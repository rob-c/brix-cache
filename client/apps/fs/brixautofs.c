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
        int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok) return 0;                               /* '/', '_', upper, meta… */
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

/* Parsed umbrella options (`-o` keys the umbrella owns; unknown tokens are
 * forwarded to the umbrella's own libfuse instance, brixcvmfs-style). */
typedef struct {
    int  idle_s;                    /* -o idle=<s>: child expiry (0 = off)   */
    int  spawn_timeout_s;           /* -o timeout=<s>: child bring-up cap    */
    int  allow_other;               /* -o allow_other: umbrella AND children */
    int  foreground;                /* -f / -d                               */
    int  debug;                     /* -d                                    */
    char cache_base[256];           /* -o cachebase=<dir>: child caches here */
    char mnt_base[256];             /* -o mntbase=<dir>: child mount farm    */
    char repos[512];                /* -o repos=a:b (overrides CVMFS_REPOSITORIES) */
    char fuse_extra[512];           /* passthrough -o tokens for the umbrella */
} autofs_opts_t;

typedef struct {
    char               mnt[512];    /* umbrella mountpoint (/cvmfs)          */
    char               farm[512];   /* child mount farm (never under mnt!)   */
    char               etc[256];    /* config root ("" = /etc/cvmfs default) */
    autofs_opts_t      o;
    int                strict;      /* CVMFS_STRICT_MOUNT                    */
    char               repos[512];  /* effective repository list (may be "") */
    char               ghost[BRIXAUTOFS_MAX_REPOS][BRIXAUTOFS_FQRN_MAX];
    int                nghost;      /* config.d repos (.conf), for readdir   */
    brixautofs_table_t tab;
    struct fuse       *fuse;
    int                sigpipe[2];  /* self-pipe: 'T'=terminate 'C'=SIGCHLD  */
    int                shutting_down;
} autofs_state_t;

static autofs_state_t g_af;

static void af_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "brixautofs: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* 1 iff `path` is a mount point per /proc/self/mountinfo (field 5). FQRNs
 * never contain the \040-style escapes mountinfo uses, so plain compare. */
static int af_is_mounted(const char *path) {
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
static void af_child_path(const char *fqrn, char *out, size_t cap) {
    snprintf(out, cap, "%s/%.*s", g_af.farm, BRIXAUTOFS_FQRN_MAX - 1, fqrn);
}

/* mkdir -p (two fixed levels are enough: farm base, then the per-repo dir). */
static int af_mkdir_p(const char *path) {
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
static int af_umount_path(const char *path) {
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
static int af_readdir(const char *path, void *buf, fuse_fill_dir_t fill,
                      off_t off, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags) {
    (void) off; (void) fi; (void) flags;
    fill(buf, ".",  NULL, 0, 0);
    fill(buf, "..", NULL, 0, 0);
    if (strcmp(path, "/") != 0) return 0;   /* unreachable: opendir admits "/" only */

    char seen[BRIXAUTOFS_MAX_REPOS * 2][BRIXAUTOFS_FQRN_MAX];
    int  nseen = 0;

    pthread_mutex_lock(&g_af.tab.mu);
    for (int i = 0; i < BRIXAUTOFS_MAX_REPOS; i++) {
        if (g_af.tab.slot[i].st == BRIXAUTOFS_FREE) continue;
        snprintf(seen[nseen], BRIXAUTOFS_FQRN_MAX, "%s", g_af.tab.slot[i].fqrn);
        fill(buf, seen[nseen++], NULL, 0, 0);
    }
    pthread_mutex_unlock(&g_af.tab.mu);

    /* ghost entries: configured but not (yet) mounted */
    for (int src = 0; src < 2; src++) {
        for (int i = 0; ; i++) {
            char name[BRIXAUTOFS_FQRN_MAX] = "";
            if (src == 0) {
                if (i >= g_af.nghost) break;
                snprintf(name, sizeof(name), "%s", g_af.ghost[i]);
            } else {
                /* i-th token of the repos list */
                const char *p = g_af.repos;
                int tok = 0, got = 0;
                while (*p && !got) {
                    while (*p == ',' || *p == ':' || *p == ' ') p++;
                    const char *s = p;
                    while (*p && *p != ',' && *p != ':' && *p != ' ') p++;
                    if (p == s) break;
                    if (tok++ == i) {
                        snprintf(name, sizeof(name), "%.*s", (int)(p - s), s);
                        got = 1;
                    }
                }
                if (!got) break;
            }
            int dup = 0;
            for (int k = 0; k < nseen && !dup; k++)
                if (strcmp(seen[k], name) == 0) dup = 1;
            if (dup || !brixautofs_valid_fqrn(name)) continue;
            if (nseen >= (int)(sizeof(seen) / sizeof(seen[0]))) break;
            snprintf(seen[nseen], BRIXAUTOFS_FQRN_MAX, "%s", name);
            fill(buf, seen[nseen++], NULL, 0, 0);
        }
    }
    return 0;
}

static const struct fuse_operations af_ops = {
    .getattr  = af_getattr,
    .readlink = af_readlink,
    .opendir  = af_opendir,
    .readdir  = af_readdir,
};

/* ---- lifecycle: signals, reaper, idle expiry, teardown ------------------ */

static void af_signal(int sig) {
    char c = sig == SIGCHLD ? 'C' : 'T';
    ssize_t ignored = write(g_af.sigpipe[1], &c, 1);
    (void) ignored;
}

/* Reap dead children; a slot whose child died gets its (possibly wedged)
 * mount detached and the slot freed so the repo can remount on next access. */
static void af_reap_children(void) {
    for (;;) {
        int st = 0;
        pid_t pid = waitpid(-1, &st, WNOHANG);
        if (pid <= 0) return;
        pthread_mutex_lock(&g_af.tab.mu);
        int idx = brixautofs_find_pid_locked(&g_af.tab, pid);
        char fqrn[BRIXAUTOFS_FQRN_MAX] = "";
        if (idx >= 0) {
            snprintf(fqrn, sizeof(fqrn), "%s", g_af.tab.slot[idx].fqrn);
            brixautofs_release_locked(&g_af.tab, idx);
        }
        pthread_mutex_unlock(&g_af.tab.mu);
        if (fqrn[0] == '\0') continue;
        char mntpath[768];
        af_child_path(fqrn, mntpath, sizeof(mntpath));
        if (af_is_mounted(mntpath)) af_umount_path(mntpath);
        if (!g_af.shutting_down) af_log("child for %s exited", fqrn);
    }
}

/* Unmount every child, then reap. Idempotent — runs from the control thread
 * on SIGTERM (while the umbrella's worker threads still serve the path walks)
 * and again after fuse_loop returns. */
static void af_teardown_children(void) {
    g_af.shutting_down = 1;
    for (int i = 0; i < BRIXAUTOFS_MAX_REPOS; i++) {
        pthread_mutex_lock(&g_af.tab.mu);
        char fqrn[BRIXAUTOFS_FQRN_MAX] = "";
        pid_t pid = 0;
        if (g_af.tab.slot[i].st != BRIXAUTOFS_FREE) {
            snprintf(fqrn, sizeof(fqrn), "%s", g_af.tab.slot[i].fqrn);
            pid = g_af.tab.slot[i].pid;
            brixautofs_release_locked(&g_af.tab, i);
        }
        pthread_mutex_unlock(&g_af.tab.mu);
        if (fqrn[0] == '\0') continue;

        char mntpath[768];
        af_child_path(fqrn, mntpath, sizeof(mntpath));
        af_umount_path(mntpath);
        if (pid > 0) {
            int st = 0;
            for (int w = 0; w < 30 && waitpid(pid, &st, WNOHANG) == 0; w++) {
                struct timespec ts = { 0, 100 * 1000 * 1000 };
                nanosleep(&ts, NULL);
            }
            if (waitpid(pid, &st, WNOHANG) == 0) {
                kill(pid, SIGTERM);
                waitpid(pid, &st, 0);
            }
        }
    }
}

/* Control thread: owns the self-pipe. 'C' → reap; 'T' → teardown children
 * (worker threads still live to serve the umount path walks), then end the
 * umbrella session; unmounting our own mountpoint makes every worker's
 * /dev/fuse read return ENODEV, so the loop exits deterministically. */
static void *af_control_thread(void *arg) {
    (void) arg;
    for (;;) {
        char c = 0;
        ssize_t n = read(g_af.sigpipe[0], &c, 1);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return NULL;
        }
        if (c == 'C') { af_reap_children(); continue; }
        af_teardown_children();
        fuse_exit(g_af.fuse);
        af_umount_path(g_af.mnt);
        return NULL;
    }
}

/* Idle expiry (root only): umount2(MNT_EXPIRE) two-phase — first call marks
 * (EAGAIN), an untouched repo expires on the next tick (0), any access in
 * between clears the mark in-kernel. The reaper frees the slot when the
 * child exits after its session ends. EPERM ⇒ no CAP_SYS_ADMIN ⇒ disable. */
static void *af_idle_thread(void *arg) {
    (void) arg;
    unsigned tick = (unsigned) g_af.o.idle_s / 2;
    if (tick == 0) tick = 1;
    for (;;) {
        sleep(tick);
        if (g_af.shutting_down) return NULL;
        char repos[BRIXAUTOFS_MAX_REPOS][BRIXAUTOFS_FQRN_MAX];
        int n = 0;
        pthread_mutex_lock(&g_af.tab.mu);
        for (int i = 0; i < BRIXAUTOFS_MAX_REPOS; i++)
            if (g_af.tab.slot[i].st == BRIXAUTOFS_MOUNTED)
                snprintf(repos[n++], BRIXAUTOFS_FQRN_MAX, "%s", g_af.tab.slot[i].fqrn);
        pthread_mutex_unlock(&g_af.tab.mu);
        for (int i = 0; i < n; i++) {
            char mntpath[768];
            af_child_path(repos[i], mntpath, sizeof(mntpath));
            if (umount2(mntpath, MNT_EXPIRE) == 0) {
                af_log("idle-expired %s", repos[i]);
            } else if (errno == EPERM) {
                af_log("idle expiry needs CAP_SYS_ADMIN — disabled");
                return NULL;
            }
            /* EAGAIN = marked for next tick; EBUSY = in use: both fine */
        }
    }
}

/* ---- option parsing / startup ------------------------------------------- */

static void af_opts_o_list(char *list, autofs_opts_t *o) {
    char *save = NULL;
    for (char *t = strtok_r(list, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        if      (strncmp(t, "idle=", 5) == 0)      o->idle_s = atoi(t + 5);
        else if (strncmp(t, "timeout=", 8) == 0)   o->spawn_timeout_s = atoi(t + 8);
        else if (strncmp(t, "cachebase=", 10) == 0)
            snprintf(o->cache_base, sizeof(o->cache_base), "%s", t + 10);
        else if (strncmp(t, "mntbase=", 8) == 0)
            snprintf(o->mnt_base, sizeof(o->mnt_base), "%s", t + 8);
        else if (strncmp(t, "repos=", 6) == 0)
            snprintf(o->repos, sizeof(o->repos), "%s", t + 6);
        else if (strcmp(t, "allow_other") == 0)    o->allow_other = 1;
        else {   /* forward to the umbrella's libfuse */
            size_t cur = strlen(o->fuse_extra);
            snprintf(o->fuse_extra + cur, sizeof(o->fuse_extra) - cur,
                     "%s%s", cur ? "," : "", t);
        }
    }
}

static void af_parse_opts(int argc, char **argv, int start, autofs_opts_t *o) {
    memset(o, 0, sizeof(*o));
    o->idle_s          = 600;
    o->spawn_timeout_s = 60;
    const char *env_cache = getenv("BRIXCVMFS_CACHE");
    snprintf(o->cache_base, sizeof(o->cache_base), "%s",
             env_cache ? env_cache : "/var/lib/brixcvmfs");
    char obuf[512];
    for (int i = start; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            snprintf(obuf, sizeof(obuf), "%s", argv[++i]);
            af_opts_o_list(obuf, o);
        } else if (strncmp(argv[i], "-o", 2) == 0 && argv[i][2] != '\0') {
            snprintf(obuf, sizeof(obuf), "%s", argv[i] + 2);
            af_opts_o_list(obuf, o);
        } else if (strcmp(argv[i], "-f") == 0) {
            o->foreground = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            o->foreground = 1;
            o->debug = 1;
        }
    }
}

/* Ghost list: config.d .conf basenames are the operator-configured repos. */
static void af_scan_configured(const char *etc_root) {
    char dd[512];
    snprintf(dd, sizeof(dd), "%s/config.d", etc_root[0] ? etc_root : "/etc/cvmfs");
    DIR *d = opendir(dd);
    if (d == NULL) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && g_af.nghost < BRIXAUTOFS_MAX_REPOS) {
        const char *dot = strrchr(e->d_name, '.');
        if (dot == NULL || strcmp(dot, ".conf") != 0) continue;
        char name[BRIXAUTOFS_FQRN_MAX];
        snprintf(name, sizeof(name), "%.*s", (int)(dot - e->d_name), e->d_name);
        if (brixautofs_valid_fqrn(name))
            snprintf(g_af.ghost[g_af.nghost++], BRIXAUTOFS_FQRN_MAX, "%s", name);
    }
    closedir(d);
}

/* brixautofs entry — dispatched by the brixMount umbrella:
 *   brixMount autofs <etc-root|-> <mountdir> [-f|-d] [-o idle=…,…] */
int brixautofs_main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
            "usage: brixMount autofs <etc-root|-> <mountdir> [-f|-d] [-o opts]\n"
            "  -o idle=<s>       unmount idle repos after <s> seconds (default 600, 0=off)\n"
            "  -o timeout=<s>    per-repo mount bring-up timeout (default 60)\n"
            "  -o cachebase=<d>  child cache dirs under <d>/<fqrn> (default /var/lib/brixcvmfs)\n"
            "  -o mntbase=<d>    child mount farm; repos appear as symlinks to <d>/<fqrn>\n"
            "                    (default <cachebase>/.mnt)\n"
            "  -o repos=a:b      restrict/ghost-list repos (overrides CVMFS_REPOSITORIES)\n"
            "  -o allow_other    let other users read the mounts (needs root or user_allow_other)\n");
        return 2;
    }

    memset(&g_af.tab, 0, sizeof(g_af.tab));
    brixautofs_table_init(&g_af.tab);
    if (strcmp(argv[1], "-") != 0)
        snprintf(g_af.etc, sizeof(g_af.etc), "%s", argv[1]);
    snprintf(g_af.mnt, sizeof(g_af.mnt), "%s", argv[2]);
    size_t ml = strlen(g_af.mnt);
    while (ml > 1 && g_af.mnt[ml - 1] == '/') g_af.mnt[--ml] = '\0';
    af_parse_opts(argc, argv, 3, &g_af.o);

    /* child mount farm: an absolute dir the umbrella never path-walks itself */
    char farm_raw[512];
    if (g_af.o.mnt_base[0])
        snprintf(farm_raw, sizeof(farm_raw), "%s", g_af.o.mnt_base);
    else
        snprintf(farm_raw, sizeof(farm_raw), "%s/.mnt", g_af.o.cache_base);
    if (af_mkdir_p(farm_raw) != 0) {
        af_log("cannot create mount farm %s: %s", farm_raw, strerror(errno));
        return 1;
    }
    char farm_rp[PATH_MAX];
    const char *farm_src =
        realpath(farm_raw, farm_rp) != NULL ? farm_rp : farm_raw;
    if (strlen(farm_src) >= sizeof(g_af.farm)) {
        af_log("mount farm path too long: %s", farm_src);
        return 1;
    }
    snprintf(g_af.farm, sizeof(g_af.farm), "%.*s",
             (int)(sizeof(g_af.farm) - 1), farm_src);
    size_t mnl = strlen(g_af.mnt);
    if (strncmp(g_af.farm, g_af.mnt, mnl) == 0
        && (g_af.farm[mnl] == '/' || g_af.farm[mnl] == '\0')) {
        af_log("mount farm %s must not live under the umbrella %s", g_af.farm, g_af.mnt);
        return 1;
    }

    /* children resolve their own repo config from the same etc root */
    if (g_af.etc[0]) setenv("BRIXCVMFS_ETC", g_af.etc, 1);

    cvmfs_conf_t cf;
    cvmfs_conf_init(&cf);
    cvmfs_conf_load_cascade(&cf, g_af.etc[0] ? g_af.etc : NULL, "");
    const char *strict = cvmfs_conf_get(&cf, "CVMFS_STRICT_MOUNT");
    g_af.strict = strict != NULL
               && (strcmp(strict, "yes") == 0 || strcmp(strict, "on") == 0
                   || strcmp(strict, "1") == 0);
    const char *repos = cvmfs_conf_get(&cf, "CVMFS_REPOSITORIES");
    snprintf(g_af.repos, sizeof(g_af.repos), "%s",
             g_af.o.repos[0] ? g_af.o.repos : (repos ? repos : ""));
    if (g_af.strict && g_af.repos[0] == '\0')
        af_log("warning: CVMFS_STRICT_MOUNT set with no CVMFS_REPOSITORIES — "
               "every mount will be refused");
    af_scan_configured(g_af.etc);

    mkdir(g_af.mnt, 0755);          /* mount(2) will fail loudly if unusable */

    /* umbrella libfuse args (mountpoint goes to fuse_mount, not the arg list) */
    char oarg[600];
    snprintf(oarg, sizeof(oarg), "fsname=brixautofs,subtype=cvmfs%s%s%s",
             g_af.o.allow_other ? ",allow_other" : "",
             g_af.o.fuse_extra[0] ? "," : "", g_af.o.fuse_extra);
    char *fargv[8];
    int fargc = 0;
    fargv[fargc++] = argv[0];
    if (g_af.o.debug) fargv[fargc++] = (char *) "-d";
    fargv[fargc++] = (char *) "-o";
    fargv[fargc++] = oarg;
    struct fuse_args fargs = FUSE_ARGS_INIT(fargc, fargv);

    g_af.fuse = fuse_new(&fargs, &af_ops, sizeof(af_ops), NULL);
    if (g_af.fuse == NULL) { af_log("fuse_new failed"); return 1; }
    if (fuse_mount(g_af.fuse, g_af.mnt) != 0) {
        af_log("cannot mount umbrella on %s", g_af.mnt);
        fuse_destroy(g_af.fuse);
        return 1;
    }
    if (fuse_daemonize(g_af.o.foreground) != 0) {
        af_log("daemonize failed");
        fuse_unmount(g_af.fuse);
        fuse_destroy(g_af.fuse);
        return 1;
    }

    /* threads AFTER daemonize (fork drops them); self-pipe carries signals */
    if (pipe(g_af.sigpipe) != 0) {
        af_log("pipe: %s", strerror(errno));
        fuse_unmount(g_af.fuse);
        fuse_destroy(g_af.fuse);
        return 1;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = af_signal;
    sa.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    pthread_t ctl, idle;
    pthread_create(&ctl, NULL, af_control_thread, NULL);
    int have_idle = g_af.o.idle_s > 0;
    if (have_idle) pthread_create(&idle, NULL, af_idle_thread, NULL);

    af_log("serving %s (etc=%s idle=%ds strict=%d)", g_af.mnt,
           g_af.etc[0] ? g_af.etc : "/etc/cvmfs", g_af.o.idle_s, g_af.strict);
    int rc = fuse_loop_mt(g_af.fuse, 0);

    /* normal exit path (external unmount): tear children down too */
    af_teardown_children();
    close(g_af.sigpipe[1]);         /* control thread read() returns 0 → exits */
    pthread_join(ctl, NULL);
    if (have_idle) { pthread_cancel(idle); pthread_join(idle, NULL); }
    fuse_unmount(g_af.fuse);
    fuse_destroy(g_af.fuse);
    return rc == 0 ? 0 : 1;
}

#endif /* BRIXAUTOFS_UNIT */
