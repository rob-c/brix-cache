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
    char       base[PATH_MAX];      /* local online-buffer root          */
    char       stagecmd[PATH_MAX];  /* $BRIX_FRM_STAGECMD              */
    ngx_log_t *log;
} exec_ctx_t;

static int
exec_online_path(const exec_ctx_t *c, const char *key, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/.online/%s", c->base,
                     (key[0] == '/') ? key + 1 : key);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

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

static int
exec_residency(void *mss, const char *key, off_t *size_out, time_t *mtime_out)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];
    struct stat sb;

    if (exec_online_path(c, key, online, sizeof(online)) == 0
        && stat(online, &sb) == 0)
    {
        if (size_out)  { *size_out = sb.st_size; }
        if (mtime_out) { *mtime_out = sb.st_mtime; }
        return BRIX_RESIDENCY_ONLINE;
    }
    /* Ask the MSS: exit 0 = on tape (offline), non-zero = absent. The size is
     * unknown until recalled; the cache fill restats the online buffer. */
    if (exec_run(c, "exists", key, "") == 0) {
        if (size_out)  { *size_out = 0; }
        if (mtime_out) { *mtime_out = time(NULL); }
        return BRIX_RESIDENCY_OFFLINE;
    }
    return BRIX_RESIDENCY_ABSENT;
}

static int
exec_recall_begin(void *mss, const char *key)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) != 0) {
        return -1;
    }
    if (access(online, F_OK) == 0) {
        return 0;                            /* already online */
    }
    frm_mkparents(online);                   /* the cmd writes the online buffer */
    return (exec_run(c, "recall", key, online) == 0) ? 0 : -1;
}

static int
exec_recall_poll(void *mss, const char *key)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) != 0) {
        return -1;
    }
    return (access(online, F_OK) == 0) ? 1 : 0;
}

static int
exec_migrate(void *mss, const char *key)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) != 0) {
        return -1;
    }
    return (exec_run(c, "migrate", key, online) == 0) ? 0 : -1;
}

static int
exec_purge(void *mss, const char *key)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) == 0) {
        (void) unlink(online);
    }
    return 0;
}

static int
exec_open_online(void *mss, const char *key)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return open(online, O_RDONLY | O_CLOEXEC);
}

static int
exec_create_online(void *mss, const char *key, mode_t mode)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    frm_mkparents(online);
    return open(online, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC,
                mode ? mode : 0644);
}

static void
exec_destroy(void *mss)
{
    free(mss);
}

const brix_mss_adapter_t brix_mss_exec_adapter = {
    .name          = "exec",
    .residency     = exec_residency,
    .recall_begin  = exec_recall_begin,
    .recall_poll   = exec_recall_poll,
    .migrate       = exec_migrate,
    .purge         = exec_purge,
    .open_online   = exec_open_online,
    .create_online = exec_create_online,
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
    ngx_cpystrn((u_char *) ec->base, (u_char *) location, sizeof(ec->base));
    ngx_cpystrn((u_char *) ec->stagecmd, (u_char *) stagecmd, sizeof(ec->stagecmd));
    ec->log = log;
    return ec;
}
