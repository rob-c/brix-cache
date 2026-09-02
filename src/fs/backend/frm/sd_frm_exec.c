/*
 * sd_frm_exec.c — the "exec" MSS adapter: drives a real HSM through an
 * operator-supplied stage command ($BRIX_FRM_STAGECMD), the classic FRM model.
 * Residency/recall/migrate/purge shell out to the stage command; the online
 * buffer is a local dir.  Split out of sd_frm.c.  Reuses the frm_mkparents /
 * stub_copyfile filesystem helpers from sd_frm_stub.c (via sd_frm_mss.h).
 */

#include "sd_frm_mss.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
    char            stagecmd[PATH_MAX];  /* $BRIX_FRM_STAGECMD */
    ngx_log_t      *log;
} exec_ctx_t;

/* Run "<stagecmd> <verb> <key> <online>"; returns the child's exit code (0 ok), or
 * -1 on spawn/wait failure. No shell - argv is passed directly (no injection). */
static int
exec_run(const exec_ctx_t *c, const char *verb, const char *key,
    const char *online)
{
    char  *argv[5];
    pid_t  pid;
    int    status;

    argv[0] = (char *) c->stagecmd;
    argv[1] = (char *) verb;
    argv[2] = (char *) key;
    argv[3] = (char *) online;
    argv[4] = NULL;

    if (posix_spawn(&pid, c->stagecmd, NULL, NULL, argv, environ) != 0) {
        return -1;
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
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

    if (posix_spawn(&pid, c->stagecmd, &fa, NULL, argv, environ) != 0) {
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
            /* In a worker, nginx's SIGCHLD handler reaps children — and unlike
             * exec_run (which waits immediately and wins that race), draining
             * the pipe to EOF gives the handler time to reap first. The exit
             * status is lost, but the pipe reached EOF and the dread contract
             * prints entries only on success — accept what was read. */
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
brix_mss_exec_create(const char *location, const char *stagecmd, ngx_log_t *log)
{
    exec_ctx_t *ec = calloc(1, sizeof(*ec));

    if (ec == NULL) {
        return NULL;
    }
    ngx_cpystrn((u_char *) ec->head.base, (u_char *) location,
                sizeof(ec->head.base));
    ec->head.invoke = exec_invoke;
    ngx_cpystrn((u_char *) ec->stagecmd, (u_char *) stagecmd, sizeof(ec->stagecmd));
    ec->log = log;
    return ec;
}
