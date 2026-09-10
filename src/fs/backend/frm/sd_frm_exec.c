/*
 * sd_frm_exec.c — the "exec" MSS adapter: drives a real HSM through an
 * operator-supplied stage command ($BRIX_FRM_STAGECMD), the classic FRM model.
 * Residency/recall/migrate/purge shell out to the stage command; the online
 * buffer is a local dir.  Split out of sd_frm.c.  Reuses the frm_mkparents /
 * stub_copyfile filesystem helpers from sd_frm_stub.c (via sd_frm_mss.h).
 */

#include "sd_frm_mss.h"
#include "core/compat/subprocess.h"   /* shared SIGCHLD-safe reparented runner */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ===================== the "exec" MSS adapter (real HSM) =====================
 * The classic FRM model: an operator-supplied stage command drives the real MSS
 * (HPSS, CTA, dCache, an Enstore wrapper, ...). The local online buffer lives at
 * <base>/.online/<key>; the recall/migrate/exists verbs shell out to:
 *     $BRIX_FRM_STAGECMD <verb> <key> <online-path>
 * recall is expected to be ASYNC-SUBMIT (start the MSS recall and return promptly,
 * not block until online); the driver then parks the open and polls until the
 * online buffer appears. A `recall_poll` is the cheap local-buffer existence check,
 * so no per-poll fork. */

typedef struct {
    frm_mss_head_t  head;            /* base + invoke — the shared-op seam */
    char            stagecmd[PATH_MAX];  /* brix_frm_stagecmd / $BRIX_FRM_STAGECMD */
    ngx_msec_t      timeout_ms;      /* brix_frm_copy_timeout (0 = none)    */
    ngx_log_t      *log;
} exec_ctx_t;

/* ===================== spawn hygiene (2.0, 2026-09-08) =====================
 * The one program this adapter still spawns directly -- the `dread` listing in
 * exec_list, whose stdout must be STREAMED (see its own note) -- is an operator
 * binary executed from a worker. A bare posix_spawn hands it every descriptor the worker
 * holds (the listen sockets, which nginx opens without CLOEXEC, live client
 * connections, the epoll fd, the logs) and leaves it in the worker's process
 * group. Two consequences a release cannot ship: a child of the program keeps
 * the server's ports bound after a deadline kill or a restart, and the
 * program can reach client traffic. exec_spawn therefore closes every fd above
 * stderr in the child (after the caller's own dup2 actions) and starts it in a
 * new session, so pid == pgid and the deadline kill reaches the whole group.
 * glibc 2.34 has closefrom as a spawn action; older glibc gets one addclose
 * per descriptor the worker holds right now (the same set, via /proc). */
#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 34)
static int
exec_fa_close_inherited(posix_spawn_file_actions_t *fa)
{
    return posix_spawn_file_actions_addclosefrom_np(fa, 3);
}
#else
static int
exec_fa_close_inherited(posix_spawn_file_actions_t *fa)
{
    DIR           *d = opendir("/proc/self/fd");
    struct dirent *e;
    int            fd, rc = 0;

    if (d == NULL) {
        return errno;
    }
    while (rc == 0 && (e = readdir(d)) != NULL) {
        fd = atoi(e->d_name);          /* "." and ".." read as 0: skipped */
        if (fd >= 3 && fd != dirfd(d)) {
            rc = posix_spawn_file_actions_addclose(fa, fd);
        }
    }
    closedir(d);
    return rc;                         /* a closed-by-then fd is ignored */
}
#endif

/* posix_spawn with the hygiene above, for the streaming `dread` path only —
 * every status-dependent verb goes through brix_subprocess_run instead (see
 * exec_run). `fa` may carry the caller's dup2/close actions (NULL = none).
 * 0 ok / -1 with errno. */
int
frm_exec_spawn(pid_t *pid, const char *prog, char *const argv[],
    posix_spawn_file_actions_t *fa)
{
    posix_spawn_file_actions_t  own;
    posix_spawnattr_t           attr;
    int                         rc;

    if (fa == NULL) {
        posix_spawn_file_actions_init(&own);
        fa = &own;
    }
    rc = exec_fa_close_inherited(fa);
    if (rc == 0) {
        posix_spawnattr_init(&attr);
#ifdef POSIX_SPAWN_SETSID
        rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);
#endif
        if (rc == 0) {
            rc = posix_spawn(pid, prog, fa, &attr, argv, environ);
        }
        posix_spawnattr_destroy(&attr);
    }
    if (fa == &own) {
        posix_spawn_file_actions_destroy(&own);
    }
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    return 0;
}

/* Run "<stagecmd> <verb> <key> <online>"; returns the child's exit code (0 ok), or
 * -1 on spawn/wait failure. No shell - argv is passed directly (no injection).
 *
 * The run goes through brix_subprocess_run (2.0, 2026-09-09), NOT a child of
 * this worker: nginx's signal handler calls ngx_process_get_status() for
 * SIGCHLD in workers too, so waitpid(-1, WNOHANG) there reaps ANY direct child
 * before the feature's own wait reaches it — the adapter then saw ECHILD, lost
 * the status and reported every verb as failed (the first live run of the
 * rebuilt 2.0 binary: "unknown process NNNN exited with code 0" next to
 * "stage command failed"). The shared runner puts the command under a
 * double-forked agent the worker never had as a child, and that agent enforces
 * the brix_frm_copy_timeout deadline and the SIGKILL of the whole process
 * group. Spawn hygiene (closefrom(3) + its own session) is the runner's. */
static int
exec_run(const exec_ctx_t *c, const char *verb, const char *key,
    const char *online)
{
    char                  *argv[5];
    brix_subprocess_req_t  req;
    int                    exit_code = -1;

    argv[0] = (char *) c->stagecmd;
    argv[1] = (char *) verb;
    argv[2] = (char *) key;
    argv[3] = (char *) online;
    argv[4] = NULL;

    req.argv       = argv;
    req.out        = NULL;                    /* the verbs report by exit code */
    req.outsz      = 0;
    req.timeout_ms = (unsigned) c->timeout_ms;

    if (brix_subprocess_run(&req, NULL, &exit_code) != 0) {
        if (errno == ETIMEDOUT) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "xrootd frm: stage command \"%s %s %s\" exceeded "
                "brix_frm_copy_timeout (%M ms) and was killed",
                c->stagecmd, verb, key, c->timeout_ms);
        }
        return -1;
    }
    return exit_code;
}

/* The exec adapter's frm_mss_invoke_fn: every MSS verb is one child run of the
 * stage command. The stage protocol has no purge verb — the MSS-side purge is
 * a local no-op (the shared op already unlinked the online buffer). */
static int
exec_invoke(void *mss, const char *verb, const char *key, const char *online)
{
    if (strcmp(verb, "purge") == 0) {
        return 0;
    }
    return exec_run(mss, verb, key, online);
}

static void
exec_destroy(void *mss)
{
    free(mss);
}

/* exec_list — §3.7 MSS namespace enumeration, the stock `rsscmd dread` analog:
 * run "<stagecmd> dread <key> ''" with stdout captured; the command prints one
 * entry name per line, a trailing '/' marking a directory. Nonzero exit (or a
 * spawn failure) is -1 — the driver then reports the key as not enumerable.
 * A stagecmd that does not know the dread verb simply exits nonzero, so
 * existing recall-only stage commands keep today's ENOTSUP behaviour. */

/* Normalize one dread line in place (strip CR/LF, a trailing '/' marks a dir)
 * and hand a non-empty entry to `cb`. Returns cb's stop flag (0 to continue). */
static int
exec_emit_line(char *line, int (*cb)(void *ud, const char *name, int is_dir),
    void *ud)
{
    size_t n = strlen(line);
    int    is_dir = 0;

    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
        line[--n] = '\0';
    }
    if (n > 0 && line[n - 1] == '/') {
        line[--n] = '\0';
        is_dir = 1;
    }
    if (n == 0) {
        return 0;
    }
    return cb(ud, line, is_dir);
}

static int
exec_list(void *mss, const char *key,
    int (*cb)(void *ud, const char *name, int is_dir), void *ud)
{
    exec_ctx_t                 *c = mss;
    char                       *argv[5];
    posix_spawn_file_actions_t  fa;
    int                         pfd[2];
    pid_t                       pid;
    int                         status;
    FILE                       *out;
    char                        line[NAME_MAX + 2];

    argv[0] = (char *) c->stagecmd;
    argv[1] = (char *) "dread";
    argv[2] = (char *) key;
    argv[3] = (char *) "";
    argv[4] = NULL;

    if (pipe(pfd) != 0) {
        return -1;
    }
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pfd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, pfd[0]);
    posix_spawn_file_actions_addclose(&fa, pfd[1]);

    if (frm_exec_spawn(&pid, c->stagecmd, argv, &fa) != 0) {
        posix_spawn_file_actions_destroy(&fa);
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    posix_spawn_file_actions_destroy(&fa);
    close(pfd[1]);

    out = fdopen(pfd[0], "r");
    if (out == NULL) {
        close(pfd[0]);
        (void) waitpid(pid, &status, 0);
        return -1;
    }
    while (fgets(line, sizeof(line), out) != NULL) {
        if (exec_emit_line(line, cb, ud)) {
            break;
        }
    }
    fclose(out);   /* closes pfd[0] */

    while (waitpid(pid, &status, 0) < 0) {
        if (errno == ECHILD) {
            /* nginx's SIGCHLD handler reaps children in workers too, and this
             * is the ONE adapter path that still spawns one directly: `dread`
             * streams an unbounded listing through the pipe while the program
             * runs, which the fixed-buffer capture in brix_subprocess_run
             * cannot do without silently truncating a large directory. The
             * stolen status is survivable HERE and nowhere else: the pipe
             * reached EOF and the dread contract prints entries only on
             * success, so what was read is the answer. Every verb whose result
             * IS the exit status runs under the reparented agent (exec_run). */
            return 0;
        }
        if (errno != EINTR) {
            return -1;
        }
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* exec_mkpath — §3.7 rcreate analog: "<stagecmd> rcreate <key> ''", exit 0 = the
 * MSS created the directory (parents included). Uses exec_run's immediate
 * waitpid, which wins the nginx SIGCHLD reap race (see exec_list). A stagecmd
 * that does not know the verb exits nonzero ⇒ -1 (not creatable). */
static int
exec_mkpath(void *mss, const char *key, mode_t mode)
{
    exec_ctx_t *c = mss;

    (void) mode;   /* the MSS owns its modes; the verb carries none */
    return (exec_run(c, "rcreate", key, "") == 0) ? 0 : -1;
}

/* frm_mss_exchange — atomic swap of two ONLINE-BUFFER copies (phase-107 C6).
 * Head-generic (frm_mss_head_t), shared by the exec and lib adapters; lives
 * here because sd_frm_stub.c, home of the other frm_mss_* head ops, is at the
 * 600-line cap. Raw SYS_renameat2 (glibc's wrapper postdates 2.28); a
 * kernel/filesystem without RENAME_EXCHANGE answers ENOSYS/EINVAL, reported
 * as ENOTSUP and never degraded to two renames (§3.5). */
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1u << 1)    /* <linux/fs.h>; avoided for its struct
                                      * collisions, same as fs/path/beneath.c */
#endif

int
frm_mss_exchange(void *mss, const char *a, const char *b)
{
    frm_mss_head_t *h = mss;
    char            pa[PATH_MAX];
    char            pb[PATH_MAX];

    if (frm_online_path(h->base, a, pa, sizeof(pa)) != 0
        || frm_online_path(h->base, b, pb, sizeof(pb)) != 0)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (syscall(SYS_renameat2, AT_FDCWD, pa, AT_FDCWD, pb,
                (unsigned int) RENAME_EXCHANGE) != 0)
    {
        if (errno == ENOSYS || errno == EINVAL) {
            errno = ENOTSUP;
        }
        return -1;
    }
    return 0;
}

const brix_mss_adapter_t brix_mss_exec_adapter = {
    .name          = "exec",
    .residency     = frm_mss_residency,
    .recall_begin  = frm_mss_recall_begin,
    .recall_poll   = frm_mss_recall_poll,
    .migrate       = frm_mss_migrate,
    .purge         = frm_mss_purge,
    .on_tape       = frm_mss_on_tape,        /* phase-115 W3.2 */
    .exchange      = frm_mss_exchange,       /* phase-107 C6 */
    .list          = exec_list,
    .mkpath        = exec_mkpath,
    .open_online   = frm_mss_open_online,
    .create_online = frm_mss_create_online,
    .sync_publish  = frm_mss_sync_publish,   /* phase-107 C3 */
    .destroy       = exec_destroy,
};

/* ===================== exec adapter constructor ===================== */

/* brix_mss_exec_create — the exec/HSM adapter context (online buffer + stagecmd). */
void *
brix_mss_exec_create(const char *location, const char *stagecmd,
    ngx_msec_t timeout_ms, ngx_log_t *log)
{
    exec_ctx_t *ec = calloc(1, sizeof(*ec));

    if (ec == NULL) {
        return NULL;
    }
    ngx_cpystrn((u_char *) ec->head.base, (u_char *) location,
                sizeof(ec->head.base));
    ec->head.invoke = exec_invoke;
    ngx_cpystrn((u_char *) ec->stagecmd, (u_char *) stagecmd, sizeof(ec->stagecmd));
    ec->timeout_ms = timeout_ms;
    ec->log = log;
    return ec;
}
