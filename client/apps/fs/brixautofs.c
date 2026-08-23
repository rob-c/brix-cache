/*
 * brixautofs.c — CVMFS-brix-autofs: the /cvmfs automount umbrella daemon.
 *
 * WHAT: `brixMount autofs <etc-root|-> <mountdir>` mounts a FUSE umbrella on
 *       <mountdir> (normally /cvmfs). Resolving a valid repository FQRN
 *       fork/execs `brixMount cvmfs <fqrn> <mntbase>/<fqrn> -f -o …` as a real
 *       FUSE mount in an EXTERNAL mount farm and answers the name with a
 *       symlink to it — the first path resolution blocks until the repo is
 *       live (autofs UX), every later access follows the link straight into
 *       the mounted fs.
 * WHY:  the stock CVMFS client's autofs experience with zero dependency on
 *       autofs or systemd — the out-of-the-box answer for WSL2 and containers,
 *       and a plain daemon for everything else. One process per repo also
 *       isolates a hung stratum to that repo.
 * HOW:  children CANNOT mount over the umbrella's own virtual subdir: the
 *       kernel serializes every lookup of one name on the in-lookup dentry
 *       (d_alloc_parallel), so while our LOOKUP handler waits for the child,
 *       the child's own mount(2) path walk of the same name waits on US — a
 *       guaranteed deadlock the autofs kernel module exists to solve. A plain
 *       FUSE umbrella therefore mounts children in a farm dir it never path-
 *       walks itself (default <cachebase>/.mnt) and presents each repo as a
 *       symlink; readlink is the (blocking) mount trigger, lstat/readdir never
 *       mount. Works fully unprivileged (no bind mounts needed). Idle repos
 *       expire via umount2(MNT_EXPIRE) two-phase (root only); SIGTERM unmounts
 *       every child before the umbrella itself goes away. Honors
 *       CVMFS_REPOSITORIES / CVMFS_STRICT_MOUNT from the stock config cascade.
 *       Pure parts (FQRN gate, slot table) live in brixautofs.h and compile
 *       without libfuse for the unit test (-DBRIXAUTOFS_UNIT).
 */
#include "brixautofs.h"

#include <stdio.h>
#include <string.h>

/* ---- pure core (unit-tested; no libfuse, no I/O) ------------------------ */

/*
 * WHAT: Classify one byte permitted inside a CVMFS repository DNS label.
 * WHY:  The FQRN walker should express label structure separately from charset.
 * HOW:  Accept lowercase ASCII letters, decimal digits, and the interior hyphen.
 */
static int brixautofs_label_char(char value) {
    return (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9') || value == '-';
}

int brixautofs_valid_fqrn(const char *name) {
    if (name == NULL || name[0] == '\0') return 0;
    size_t len = strlen(name);
    if (len > BRIXAUTOFS_FQRN_MAX - 1) return 0;

    int labels = 0;
    size_t lab = 0;                     /* current label length */
    for (size_t i = 0; i <= len; i++) {
        char c = name[i];
        if (c == '.' || c == '\0') {
            if (lab == 0 || lab > 63) return 0;          /* empty/overlong label */
            if (name[i - 1] == '-') return 0;            /* label ends with '-' */
            labels++;
            lab = 0;
            continue;
        }
        if (!brixautofs_label_char(c)) return 0;          /* '/', '_', upper, meta… */
        if (lab == 0 && c == '-') return 0;              /* label starts with '-' */
        lab++;
    }
    return labels >= 2;                 /* needs an org AND a domain part */
}

int brixautofs_repo_listed(const char *list, const char *fqrn) {
    if (list == NULL || fqrn == NULL) return 0;
    size_t fl = strlen(fqrn);
    const char *p = list;
    while (*p) {
        while (*p == ',' || *p == ':' || *p == ' ' || *p == '\t') p++;
        const char *tok = p;
        while (*p && *p != ',' && *p != ':' && *p != ' ' && *p != '\t') p++;
        if ((size_t)(p - tok) == fl && strncmp(tok, fqrn, fl) == 0) return 1;
    }
    return 0;
}

void brixautofs_table_init(brixautofs_table_t *t) {
    memset(t->slot, 0, sizeof(t->slot));
    pthread_mutex_init(&t->mu, NULL);
}

int brixautofs_find_locked(brixautofs_table_t *t, const char *fqrn) {
    for (int i = 0; i < BRIXAUTOFS_MAX_REPOS; i++)
        if (t->slot[i].st != BRIXAUTOFS_FREE && strcmp(t->slot[i].fqrn, fqrn) == 0)
            return i;
    return -1;
}

int brixautofs_claim_locked(brixautofs_table_t *t, const char *fqrn) {
    for (int i = 0; i < BRIXAUTOFS_MAX_REPOS; i++) {
        if (t->slot[i].st != BRIXAUTOFS_FREE) continue;
        snprintf(t->slot[i].fqrn, sizeof(t->slot[i].fqrn), "%s", fqrn);
        t->slot[i].st  = BRIXAUTOFS_MOUNTING;
        t->slot[i].pid = 0;
        return i;
    }
    return -1;
}

void brixautofs_commit_locked(brixautofs_table_t *t, int idx, pid_t pid) {
    t->slot[idx].st  = BRIXAUTOFS_MOUNTED;
    t->slot[idx].pid = pid;
}

void brixautofs_release_locked(brixautofs_table_t *t, int idx) {
    memset(&t->slot[idx], 0, sizeof(t->slot[idx]));
}

int brixautofs_find_pid_locked(brixautofs_table_t *t, pid_t pid) {
    for (int i = 0; i < BRIXAUTOFS_MAX_REPOS; i++)
        if (t->slot[i].st != BRIXAUTOFS_FREE && t->slot[i].pid == pid)
            return i;
    return -1;
}

#ifndef BRIXAUTOFS_UNIT
/* ---- the umbrella daemon proper (libfuse3 + fork/exec of child mounts) -- */

#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include "cvmfs/config/cvmfs_conf.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "brixautofs_ext_internal.h"


autofs_state_t g_af;

void af_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "brixautofs: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* 1 iff `path` is a mount point per /proc/self/mountinfo (field 5). FQRNs
 * never contain the \040-style escapes mountinfo uses, so plain compare. */
int af_is_mounted(const char *path) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (f == NULL) return 0;
    char line[1024];
    int found = 0;
    while (!found && fgets(line, sizeof(line), f) != NULL) {
        /* fields: id parent maj:min root mountpoint … */
        char *save = NULL, *tok = strtok_r(line, " ", &save);
        for (int i = 0; tok != NULL && i < 4; i++) tok = strtok_r(NULL, " ", &save);
        if (tok != NULL && strcmp(tok, path) == 0) found = 1;
    }
    fclose(f);
    return found;
}

/* Where the child actually mounts: in the farm, NEVER under g_af.mnt (see the
 * d_alloc_parallel note in the header — mounting over our own name deadlocks). */
void af_child_path(const char *fqrn, char *out, size_t cap) {
    snprintf(out, cap, "%s/%.*s", g_af.farm, BRIXAUTOFS_FQRN_MAX - 1, fqrn);
}

/* mkdir -p (two fixed levels are enough: farm base, then the per-repo dir). */
int af_mkdir_p(const char *path) {
    char buf[768];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* Unmount `path`: umount2 when root (MNT_DETACH on EBUSY), else fusermount3
 * (-u, then lazy -uz). Best-effort; returns 0 if the mount is gone. */
int af_umount_path(const char *path) {
    if (geteuid() == 0) {
        if (umount2(path, 0) == 0) return 0;
        if (errno == EBUSY && umount2(path, MNT_DETACH) == 0) return 0;
        if (!af_is_mounted(path)) return 0;
    }
    const char *modes[] = { "-u", "-uz" };
    for (int m = 0; m < 2; m++) {
        pid_t pid = fork();
        if (pid == 0) {
            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); }
            execlp("fusermount3", "fusermount3", modes[m], path, (char *) NULL);
            _exit(127);
        }
        if (pid > 0) {
            int st = 0;
            waitpid(pid, &st, 0);
        }
        if (!af_is_mounted(path)) return 0;
    }
    return af_is_mounted(path) ? -1 : 0;
}

/* Build the child's `-o` string. `cache=` pins a per-repo cache dir (which
 * also disables brixcvmfs "clever" mode — it must never write onto the
 * mountpoint under the umbrella); nodev,nosuid harden the nested mount.
 * $BRIXAUTOFS_CHILD_OPTS appends extra tokens (tests). Must stay < 512
 * (brixcvmfs parse_opts buffer cap). */
static void af_child_opts(const char *fqrn, char *out, size_t cap) {
    const char *extra = getenv("BRIXAUTOFS_CHILD_OPTS");
    snprintf(out, cap, "cache=%s/%s,nodev,nosuid%s%s%s",
             g_af.o.cache_base, fqrn,
             g_af.o.allow_other ? ",allow_other" : "",
             extra ? "," : "", extra ? extra : "");
}

/* Fork/exec the per-repo mount (`brixMount cvmfs <fqrn> <mnt>/<fqrn> -f -o …`)
 * and poll /proc/self/mountinfo until the nested mount is live. The child runs
 * -f (no daemonize) so its pid stays ours to reap and its exit before the
 * mount lands is a definitive failure. Returns the child pid, or -1. */
static pid_t af_spawn_child(const char *fqrn) {
    char mntpath[768], opts[512], exe[512];
    af_child_path(fqrn, mntpath, sizeof(mntpath));
    af_child_opts(fqrn, opts, sizeof(opts));

    ssize_t el = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (el > 0) {
        exe[el] = '\0';
    } else {
        const char *env = getenv("BRIXMOUNT_BIN");
        if (env == NULL) { af_log("cannot resolve own binary path"); return -1; }
        snprintf(exe, sizeof(exe), "%s", env);
    }

    if (af_mkdir_p(mntpath) != 0) {
        af_log("cannot create mountpoint %s: %s", mntpath, strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) { af_log("fork: %s", strerror(errno)); return -1; }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) dup2(devnull, 0);
        execl(exe, exe, "cvmfs", fqrn, mntpath, "-f", "-o", opts, (char *) NULL);
        _exit(127);
    }

    int deadline_ms = g_af.o.spawn_timeout_s * 1000;
    for (int waited = 0; waited < deadline_ms; waited += 100) {
        if (af_is_mounted(mntpath)) return pid;
        int st = 0;
        if (waitpid(pid, &st, WNOHANG) == pid) {
            af_log("mount of %s failed (child exit %d)", fqrn,
                   WIFEXITED(st) ? WEXITSTATUS(st) : -1);
            return -1;
        }
        struct timespec ts = { 0, 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    af_log("mount of %s timed out after %ds", fqrn, g_af.o.spawn_timeout_s);
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    af_umount_path(mntpath);        /* in case it landed between poll and kill */
    return -1;
}

/* Admission gate shared by every op: is `name` a repo this umbrella may show
 * at all? (validity + strict-mount policy; never touches the slot table). */
static int af_admit(const char *name) {
    if (!brixautofs_valid_fqrn(name)) return 0;
    if (g_af.strict && !brixautofs_repo_listed(g_af.repos, name)) return 0;
    return !g_af.shutting_down;
}

/* The mount trigger: drive the slot state machine and block until the child
 * mount is live in the farm. Called from readlink only — the triggering path
 * resolution waits (autofs UX); the child's own mount(2) walk happens in the
 * farm, far away from the umbrella's dentries, so nothing re-enters us.
 * Returns 0 when <farm>/<name> is a live mount, else -ENOENT. */
static int af_ensure_repo(const char *name) {
    if (!af_admit(name)) return -ENOENT;

    pthread_mutex_lock(&g_af.tab.mu);
    int idx = brixautofs_find_locked(&g_af.tab, name);
    if (idx >= 0) {
        /* MOUNTED: done. MOUNTING: another resolution is bringing it up; its
         * kernel-side lookup already serializes ours, so just answer. */
        pthread_mutex_unlock(&g_af.tab.mu);
        return 0;
    }
    idx = brixautofs_claim_locked(&g_af.tab, name);
    pthread_mutex_unlock(&g_af.tab.mu);
    if (idx < 0) {
        af_log("repo table full (%d), refusing %s", BRIXAUTOFS_MAX_REPOS, name);
        return -ENOENT;
    }

    pid_t pid = af_spawn_child(name);   /* blocking: the autofs UX — the
                                         * triggering resolution waits */
    pthread_mutex_lock(&g_af.tab.mu);
    if (pid > 0) brixautofs_commit_locked(&g_af.tab, idx, pid);
    else         brixautofs_release_locked(&g_af.tab, idx);
    pthread_mutex_unlock(&g_af.tab.mu);
    return pid > 0 ? 0 : -ENOENT;
}

/* ---- FUSE ops (root dir + one virtual level of repo symlinks) ----------- */

static void af_fill_dir_stat(struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFDIR | 0755;
    st->st_nlink = 2;
    st->st_uid   = getuid();
    st->st_gid   = getgid();
    st->st_atime = st->st_mtime = st->st_ctime = time(NULL);
}

static void af_fill_link_stat(struct stat *st, const char *name) {
    char target[768];
    af_child_path(name, target, sizeof(target));
    memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFLNK | 0777;
    st->st_nlink = 1;
    st->st_size  = (off_t) strlen(target);
    st->st_uid   = getuid();
    st->st_gid   = getgid();
    st->st_atime = st->st_mtime = st->st_ctime = time(NULL);
}

/* getattr NEVER mounts: an admissible name is a symlink into the farm, so a
 * bare lstat / colorized ls of ghosts stays cheap. Following the link (stat,
 * open, cd) goes through readlink — that is where the mount happens. */
static int af_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void) fi;
    if (strcmp(path, "/") == 0) { af_fill_dir_stat(st); return 0; }
    const char *name = path + 1;
    if (strchr(name, '/') != NULL) return -ENOENT;   /* depth 1 only */
    if (!af_admit(name)) return -ENOENT;
    af_fill_link_stat(st, name);
    return 0;
}

/* readlink IS the mount trigger: block until the repo is live, then hand the
 * kernel the farm path to walk into. */
static int af_readlink(const char *path, char *buf, size_t cap) {
    const char *name = path + 1;
    if (strchr(name, '/') != NULL) return -ENOENT;
    int rc = af_ensure_repo(name);
    if (rc != 0) return rc;
    char target[768];
    af_child_path(name, target, sizeof(target));
    snprintf(buf, cap, "%s", target);
    return 0;
}

static int af_opendir(const char *path, struct fuse_file_info *fi) {
    (void) fi;
    /* only "/" exists as a directory here; repo names resolve via symlink */
    return strcmp(path, "/") == 0 ? 0 : -ENOENT;
}

/* readdir("/") = "." ".." ∪ mounted repos ∪ configured repos (ghost listing:
 * CVMFS_REPOSITORIES + the config.d .conf entries). NEVER spawns a mount. */
/* Copy the idx-th token of a comma/colon/space-separated repo list into out.
 * Returns 1 if that token exists, 0 once the list is exhausted. */
static int af_repos_nth_token(const char *list, int idx, char *out, size_t outsz) {
    const char *p = list;
    int tok = 0;
    while (*p) {
        while (*p == ',' || *p == ':' || *p == ' ') p++;
        const char *s = p;
        while (*p && *p != ',' && *p != ':' && *p != ' ') p++;
        if (p == s) break;
        if (tok++ == idx) {
            snprintf(out, outsz, "%.*s", (int)(p - s), s);
            return 1;
        }
    }
    return 0;
}

/* The idx-th ghost-candidate name for source src (0 = the ghost array, 1 = the
 * configured repos list).  Returns 1 with the name in out, or 0 to stop src. */
static int af_ghost_name(int src, int idx, char *out, size_t outsz) {
    if (src == 0) {
        if (idx >= g_af.nghost) return 0;
        snprintf(out, outsz, "%s", g_af.ghost[idx]);
        return 1;
    }
    return af_repos_nth_token(g_af.repos, idx, out, outsz);
}

/* 1 if name is already in the first nseen entries of seen. */
static int af_seen_has(char seen[][BRIXAUTOFS_FQRN_MAX], int nseen,
                       const char *name) {
    for (int k = 0; k < nseen; k++)
        if (strcmp(seen[k], name) == 0) return 1;
    return 0;
}

/* Emit the live-mounted repos (under the table lock), recording each in seen. */
static void af_fill_mounted(void *buf, fuse_fill_dir_t fill,
                            char seen[][BRIXAUTOFS_FQRN_MAX], int *nseen) {
    pthread_mutex_lock(&g_af.tab.mu);
    for (int i = 0; i < BRIXAUTOFS_MAX_REPOS; i++) {
        if (g_af.tab.slot[i].st == BRIXAUTOFS_FREE) continue;
        snprintf(seen[*nseen], BRIXAUTOFS_FQRN_MAX, "%s", g_af.tab.slot[i].fqrn);
        fill(buf, seen[(*nseen)++], NULL, 0, 0);
    }
    pthread_mutex_unlock(&g_af.tab.mu);
}

static int af_readdir(const char *path, void *buf, fuse_fill_dir_t fill,
                      off_t off, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags) {
    (void) off; (void) fi; (void) flags;
    fill(buf, ".",  NULL, 0, 0);
    fill(buf, "..", NULL, 0, 0);
    if (strcmp(path, "/") != 0) return 0;   /* unreachable: opendir admits "/" only */

    char seen[BRIXAUTOFS_MAX_REPOS * 2][BRIXAUTOFS_FQRN_MAX];
    int  nseen = 0;

    af_fill_mounted(buf, fill, seen, &nseen);

    /* ghost entries: configured but not (yet) mounted */
    for (int src = 0; src < 2; src++) {
        for (int i = 0; ; i++) {
            char name[BRIXAUTOFS_FQRN_MAX] = "";
            if (!af_ghost_name(src, i, name, sizeof(name))) break;
            if (af_seen_has(seen, nseen, name) || !brixautofs_valid_fqrn(name))
                continue;
            if (nseen >= (int)(sizeof(seen) / sizeof(seen[0]))) break;
            snprintf(seen[nseen], BRIXAUTOFS_FQRN_MAX, "%s", name);
            fill(buf, seen[nseen++], NULL, 0, 0);
        }
    }
    return 0;
}

const struct fuse_operations af_ops = {
    .getattr  = af_getattr,
    .readlink = af_readlink,
    .opendir  = af_opendir,
    .readdir  = af_readdir,
};

#endif /* BRIXAUTOFS_UNIT */
