/*
 * brixautofs_ext.c — lifecycle for the CVMFS automount umbrella: POSIX signal
 * self-pipe, child reaper, idle expiry + teardown, option/`-o` parsing, mount
 * farm + repo-config bring-up, the libfuse event loop and the entry point.
 *
 * Phase-38 split of brixautofs.c; behaviour-identical. The core TU
 * (brixautofs.c) keeps the pure FQRN validator/table state machine (also built
 * standalone under -DBRIXAUTOFS_UNIT) and the per-request FUSE handlers + ops
 * table; this TU drives them. The two share brixautofs_ext_internal.h. See
 * docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIXAUTOFS_UNIT
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include "brixautofs.h"
#include "brixautofs_ext_internal.h"

#include "cvmfs/config/cvmfs_conf.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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
/* Resolve + create the child mount farm (an absolute dir the umbrella never
 * path-walks itself) and reject a farm nested under the umbrella mountpoint.
 * Fills g_af.farm.  Returns 0 on success, 1 on error. */
static int
af_setup_mount_farm(void)
{
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
    return 0;
}


/* Load the cascaded CVMFS config for repo gating: the strict-mount flag and the
 * repo allow/ghost list (option override wins), then scan the configured set.
 * Fills g_af.{strict,repos}. */
static void
af_load_repo_config(void)
{
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
}


/* Build the umbrella libfuse args (mountpoint goes to fuse_mount, not the arg
 * list), create the session, mount it, and daemonize.  Returns 0 with g_af.fuse
 * live, or 1 after cleaning up any partial state. */
static int
af_fuse_bringup(char *argv0)
{
    char oarg[600];
    snprintf(oarg, sizeof(oarg), "fsname=brixautofs,subtype=cvmfs%s%s%s",
             g_af.o.allow_other ? ",allow_other" : "",
             g_af.o.fuse_extra[0] ? "," : "", g_af.o.fuse_extra);
    char *fargv[8];
    int fargc = 0;
    fargv[fargc++] = argv0;
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
    return 0;
}


/* Self-pipe + signal handlers, installed AFTER daemonize (fork drops threads;
 * the self-pipe carries signals to the control thread).  Returns 0, or 1 after
 * unmount/destroy if the pipe cannot be created. */
static int
af_install_signals(void)
{
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
    return 0;
}


/* Spin the control + optional idle threads, run the umbrella event loop, then
 * (on external unmount) tear the children down and join.  Returns the process
 * exit code. */
static int
af_run(void)
{
    pthread_t ctl, idle;
    pthread_create(&ctl, NULL, af_control_thread, NULL);
    int have_idle = g_af.o.idle_s > 0;
    if (have_idle) pthread_create(&idle, NULL, af_idle_thread, NULL);

    af_log("serving %s (etc=%s idle=%ds strict=%d)", g_af.mnt,
           g_af.etc[0] ? g_af.etc : "/etc/cvmfs", g_af.o.idle_s, g_af.strict);
    int rc = fuse_loop_mt(g_af.fuse, 0);

    af_teardown_children();
    close(g_af.sigpipe[1]);         /* control thread read() returns 0 → exits */
    pthread_join(ctl, NULL);
    if (have_idle) { pthread_cancel(idle); pthread_join(idle, NULL); }
    fuse_unmount(g_af.fuse);
    fuse_destroy(g_af.fuse);
    return rc == 0 ? 0 : 1;
}


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

    if (af_setup_mount_farm() != 0)
        return 1;

    /* children resolve their own repo config from the same etc root */
    if (g_af.etc[0]) setenv("BRIXCVMFS_ETC", g_af.etc, 1);

    af_load_repo_config();

    mkdir(g_af.mnt, 0755);          /* mount(2) will fail loudly if unusable */

    if (af_fuse_bringup(argv[0]) != 0)
        return 1;

    if (af_install_signals() != 0)
        return 1;

    return af_run();
}

#endif /* BRIXAUTOFS_UNIT */
