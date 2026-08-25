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

const brix_mss_adapter_t brix_mss_exec_adapter = {
    .name          = "exec",
    .residency     = frm_mss_residency,
    .recall_begin  = frm_mss_recall_begin,
    .recall_poll   = frm_mss_recall_poll,
    .migrate       = frm_mss_migrate,
    .purge         = frm_mss_purge,
    .open_online   = frm_mss_open_online,
    .create_online = frm_mss_create_online,
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
