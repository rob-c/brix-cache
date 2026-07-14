/*
 * sd_frm.c - the nearline (tape/MSS) backend FS driver (SP5). See header.
 *
 * The driver is a thin residency layer over a pluggable MSS adapter. A read of an
 * offline object RECALLS it into the MSS online buffer (synchronously in this
 * increment - the stub recall is a local copy), then serves from the buffer via a
 * real fd; a staged write lands in the online buffer and is MIGRATED to tape on
 * commit. The composing registry requires a cache tier in front (G8), so the
 * recall is in practice the cache miss-fill sourced from tape.
 *
 * The built-in "stub" MSS adapter simulates tape with two local directories under
 * a base: <base>/<key> is "on tape" (offline) and <base>/.online/<key> is the
 * online buffer. It is what the SP5 tests drive; a real MSS (exec stagecmd, HPSS,
 * CTA) is another adapter selected on the tape:// store-URL.
 */
#include "sd_frm.h"
#include "sd_frm_mss.h"     /* MSS adapters (stub/exec) split out */

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

extern char **environ;


/* ===================== the sd_frm driver ===================== */

typedef struct {
    const brix_mss_adapter_t *mss;
    void                       *mss_ctx;
    ngx_log_t                  *log;
} sd_frm_state;

typedef struct {
    sd_frm_state *fst;
    int           fd;
    char          key[1024];
} sd_frm_staged_state;

#define SD_FRM_ST(inst)  ((sd_frm_state *) (inst)->state)

/* Bounded synchronous recall: ensure `key` is online in the MSS buffer. Returns 0
 * (online), or -1 (errno: ENOENT absent, EAGAIN still in-flight, EIO error). A
 * genuinely slow MSS would return EAGAIN and the cache tier would park the open on
 * the stage_engine waiter (the deferred async path); the stub completes at once. */
static int
frm_ensure_online(sd_frm_state *st, const char *key)
{
    off_t  sz = 0;
    time_t mt = 0;
    int    res = st->mss->residency(st->mss_ctx, key, &sz, &mt);

    if (res == BRIX_RESIDENCY_ONLINE) {
        return 0;
    }
    if (res == BRIX_RESIDENCY_ABSENT) {
        errno = ENOENT;
        return -1;
    }
    if (st->mss->recall_begin(st->mss_ctx, key) != 0) {
        errno = EIO;
        return -1;
    }
    /* One poll: a synchronous adapter (begin copied) is online now; an async MSS is
     * still staging, so return EAGAIN and let the HTTP plane answer 202 (the open
     * "parks" via client retry, §9.2). A later retry re-polls and completes. */
    {
        int p = st->mss->recall_poll(st->mss_ctx, key);

        if (p == 1) {
            return 0;
        }
        if (p < 0) {
            errno = EIO;
            return -1;
        }
    }
    errno = EAGAIN;
    return -1;
}

static brix_sd_obj_t *
sd_frm_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_frm_state    *st = SD_FRM_ST(inst);
    brix_sd_obj_t *o;
    int              fd;

    (void) mode;
    if ((sd_flags & BRIX_SD_O_WRITE) != 0) {
        /* writes go through the staged path (migrate); a direct write-open is not
         * supported on a nearline backend. */
        if (err_out) { *err_out = EROFS; }
        return NULL;
    }
    if (frm_ensure_online(st, path) != 0) {
        if (err_out) { *err_out = errno; }
        return NULL;
    }
    fd = st->mss->open_online(st->mss_ctx, path);
    if (fd < 0) {
        if (err_out) { *err_out = errno ? errno : EIO; }
        return NULL;
    }
    o = calloc(1, sizeof(*o));
    if (o == NULL) {
        (void) close(fd);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    o->driver     = inst->driver;
    o->inst       = inst;
    o->fd         = fd;
    o->heap_shell = 1;
    {
        struct stat sb;
        if (fstat(fd, &sb) == 0) {
            o->snap.size   = sb.st_size;
            o->snap.mtime  = sb.st_mtime;
            o->snap.mode   = sb.st_mode;
            o->snap.is_reg = 1;
        }
    }
    return o;
}

static ngx_int_t
sd_frm_close(brix_sd_obj_t *obj)
{
    if (obj == NULL) {
        return NGX_OK;
    }
    if (obj->fd >= 0) {
        (void) close(obj->fd);
        obj->fd = -1;
    }
    if (obj->heap_shell) {
        free(obj);
    }
    return NGX_OK;
}

static ssize_t
sd_frm_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    return pread(obj->fd, buf, len, off);
}

static ngx_int_t
sd_frm_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    struct stat sb;

    if (fstat(obj->fd, &sb) != 0) {
        return NGX_ERROR;
    }
    ngx_memzero(out, sizeof(*out));
    out->size   = sb.st_size;
    out->mtime  = sb.st_mtime;
    out->ctime  = sb.st_ctime;
    out->mode   = sb.st_mode;
    out->ino    = sb.st_ino;
    out->is_reg = 1;
    return NGX_OK;
}

static ngx_int_t
sd_frm_stat(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    sd_frm_state *st = SD_FRM_ST(inst);
    off_t         sz = 0;
    time_t        mt = 0;
    int           res = st->mss->residency(st->mss_ctx, path, &sz, &mt);

    if (res == BRIX_RESIDENCY_ABSENT) {
        return NGX_ERROR;            /* ENOENT - errno set by the caller's mapping */
    }
    ngx_memzero(out, sizeof(*out));
    out->size   = sz;
    out->mtime  = mt;
    out->mode   = S_IFREG | 0644;
    out->is_reg = 1;
    return NGX_OK;
}

/* Residency (the VFS residency seam, phase-64 §9) — classify `key` via the MSS
 * adapter WITHOUT initiating a recall, mapping the adapter's residency model onto
 * the SD residency enum the protocol handlers consume. ABSENT ⇒ LOST (errno ENOENT
 * so the seam can surface a missing object); ONLINE/NEARLINE/OFFLINE pass through. */
static ngx_int_t
sd_frm_residency(brix_sd_instance_t *inst, const char *key,
                 brix_sd_residency_t *out)
{
    sd_frm_state *st = SD_FRM_ST(inst);
    off_t         sz = 0;
    time_t        mt = 0;
    int           res = st->mss->residency(st->mss_ctx, key, &sz, &mt);

    switch (res) {
    case BRIX_RESIDENCY_ONLINE:   *out = BRIX_SD_RES_ONLINE;   break;
    case BRIX_RESIDENCY_NEARLINE: *out = BRIX_SD_RES_NEARLINE; break;
    case BRIX_RESIDENCY_OFFLINE:  *out = BRIX_SD_RES_OFFLINE;  break;
    default:                        errno = ENOENT; return NGX_ERROR;  /* ABSENT */
    }
    return NGX_OK;
}

static ngx_int_t
sd_frm_recall(brix_sd_instance_t *inst, const char *key, char reqid_out[40])
{
    sd_frm_state *st = SD_FRM_ST(inst);

    if (reqid_out != NULL) {
        reqid_out[0] = '\0';         /* synchronous recall: no parking handle */
    }
    if (frm_ensure_online(st, key) == 0) {
        return NGX_OK;               /* online now - the cache tier does a normal fill */
    }
    return (errno == EAGAIN) ? NGX_AGAIN : NGX_ERROR;
}

/* ---- migrate via the staged-write path (online buffer -> tape on commit) ---- */

static brix_sd_staged_t *
sd_frm_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_frm_state        *st = SD_FRM_ST(inst);
    sd_frm_staged_state *ss;
    brix_sd_staged_t  *h;
    int                  fd;

    fd = st->mss->create_online(st->mss_ctx, final_path, mode);
    if (fd < 0) {
        if (err_out) { *err_out = errno ? errno : EIO; }
        return NULL;
    }
    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        (void) close(fd);
        free(ss);
        free(h);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    ss->fst = st;
    ss->fd  = fd;
    ngx_cpystrn((u_char *) ss->key, (u_char *) final_path, sizeof(ss->key));
    h->inst  = inst;
    h->state = ss;
    return h;
}

static ssize_t
sd_frm_staged_write(brix_sd_staged_t *st, const void *buf, size_t len, off_t off)
{
    sd_frm_staged_state *ss = st->state;

    return pwrite(ss->fd, buf, len, off);
}

static ngx_int_t
sd_frm_staged_commit(brix_sd_staged_t *st, int noreplace)
{
    sd_frm_staged_state *ss = st->state;
    int                  rc;

    (void) noreplace;
    if (ss->fd >= 0) {
        (void) close(ss->fd);
        ss->fd = -1;
    }
    /* Publish: migrate the online-buffer object to tape. */
    rc = ss->fst->mss->migrate(ss->fst->mss_ctx, ss->key);
    free(ss);
    free(st);
    return (rc == 0) ? NGX_OK : NGX_ERROR;
}

static void
sd_frm_staged_abort(brix_sd_staged_t *st)
{
    sd_frm_staged_state *ss = st->state;

    if (ss->fd >= 0) {
        (void) close(ss->fd);
        ss->fd = -1;
    }
    (void) ss->fst->mss->purge(ss->fst->mss_ctx, ss->key);
    free(ss);
    free(st);
}

static const brix_sd_driver_t brix_sd_frm_driver = {
    .name = "frm",
    .caps = BRIX_SD_CAP_NEARLINE | BRIX_SD_CAP_RANGE_READ
          | BRIX_SD_CAP_RANDOM_WRITE | BRIX_SD_CAP_FD,
    .open          = sd_frm_open,
    .close         = sd_frm_close,
    .pread         = sd_frm_pread,
    .fstat         = sd_frm_fstat,
    .stat          = sd_frm_stat,
    .recall        = sd_frm_recall,
    .residency     = sd_frm_residency,
    .staged_open   = sd_frm_staged_open,
    .staged_write  = sd_frm_staged_write,
    .staged_commit = sd_frm_staged_commit,
    .staged_abort  = sd_frm_staged_abort,
};

/* ---- Select the "exec" MSS adapter when requested ----
 *
 * WHAT: If `adapter` names the "exec" HSM driver AND $BRIX_FRM_STAGECMD is set,
 * builds the exec MSS context and points `st->mss`/`st->mss_ctx` at it. Returns 0
 * whenever the caller may proceed (adapter not "exec", or missing stage command -
 * in both cases `st->mss` is left NULL so the stub fallback runs); returns -1 with
 * errno set to ENOMEM only when the exec context allocation itself fails.
 *
 * WHY: Isolates the exec-adapter decision (the classic FRM model over an external
 * stage command) so brix_sd_frm_create stays a flat orchestration below the
 * complexity cap, without changing any allocation, log line, or errno behaviour.
 *
 * HOW:
 *   1. If `adapter` is NULL or not "exec", return 0 (fall through to the stub).
 *   2. Read $BRIX_FRM_STAGECMD; if unset/empty, WARN and return 0 (stub fallback).
 *   3. Create the exec MSS context; on failure set errno=ENOMEM and return -1.
 *   4. On success, publish the exec adapter, NOTICE-log it, and return 0.
 */
static int
frm_select_exec_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log)
{
    const char *cmd;

    /* "exec" drives a real HSM via $BRIX_FRM_STAGECMD (the classic FRM model). */
    if (adapter == NULL || ngx_strcmp(adapter, "exec") != 0) {
        return 0;
    }
    cmd = getenv("BRIX_FRM_STAGECMD");
    if (cmd == NULL || cmd[0] == '\0') {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd frm: the \"exec\" MSS adapter needs $BRIX_FRM_STAGECMD "
            "(the stage command); falling back to the built-in stub");
        return 0;
    }
    st->mss_ctx = brix_mss_exec_create(location, cmd, log);
    if (st->mss_ctx == NULL) {
        errno = ENOMEM;
        return -1;
    }
    st->mss = &brix_mss_exec_adapter;
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
        "xrootd frm: exec MSS adapter (stagecmd=%s, online buffer=%s)",
        cmd, location);
    return 0;
}

/* ---- Select the built-in local-dir stub MSS adapter (default / fallback) ----
 *
 * WHAT: Builds the stub MSS context that simulates tape with local directories and
 * points `st->mss`/`st->mss_ctx` at it. Returns 0 on success, or -1 with errno set
 * to ENOMEM when the stub context allocation fails. An `adapter` name that is
 * neither empty, "stub", nor "exec" is WARN-logged as not-yet-implemented before
 * the stub is used, matching the original in-place behaviour.
 *
 * WHY: The stub is the default and the fallback for every adapter that is not a
 * working "exec"; factoring it out keeps the create orchestrator flat and under
 * the complexity cap while preserving the exact warning and errno semantics.
 *
 * HOW:
 *   1. If `adapter` is a non-empty name other than "stub"/"exec", WARN about it.
 *   2. Create the stub MSS context; on failure set errno=ENOMEM and return -1.
 *   3. Publish the stub adapter and return 0.
 */
static int
frm_select_stub_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log)
{
    if (adapter != NULL && adapter[0] != '\0'
        && ngx_strcmp(adapter, "stub") != 0
        && ngx_strcmp(adapter, "exec") != 0)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd frm: MSS adapter \"%s\" is not yet implemented "
            "(phase-64 SP5: hpss/cta); using the built-in stub", adapter);
    }
    st->mss_ctx = brix_mss_stub_create(location, log);
    if (st->mss_ctx == NULL) {
        errno = ENOMEM;
        return -1;
    }
    st->mss = &brix_mss_stub_adapter;
    return 0;
}

/* ---- Construct an sd_frm nearline backend instance ----
 *
 * WHAT: Allocates the sd_frm instance and state, selects the MSS adapter (exec if
 * requested and usable, otherwise the built-in stub), and wires the state to the
 * frm driver. Returns the instance, or NULL with errno set (EINVAL for an empty
 * location, ENOMEM for any allocation failure) after freeing partial state.
 *
 * WHY: The single public entry point for the nearline (tape/MSS) backend; the two
 * adapter choices are delegated to helpers so this stays a linear early-return
 * sequence below the complexity cap.
 *
 * HOW:
 *   1. Reject an empty `location` with EINVAL.
 *   2. Allocate inst + state; on failure free both and return ENOMEM.
 *   3. Try the exec adapter; on hard failure free both and return NULL.
 *   4. If no adapter is set yet, fall back to the stub; on failure free and return.
 *   5. Publish the driver and state onto the instance and return it.
 */
brix_sd_instance_t *
brix_sd_frm_create(const char *adapter, const char *location, ngx_log_t *log)
{
    brix_sd_instance_t *inst;
    sd_frm_state         *st;

    if (location == NULL || location[0] == '\0') {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    st   = calloc(1, sizeof(*st));
    if (inst == NULL || st == NULL) {
        free(inst);
        free(st);
        errno = ENOMEM;
        return NULL;
    }
    st->log = log;

    if (frm_select_exec_adapter(st, adapter, location, log) != 0) {
        free(inst);
        free(st);
        return NULL;
    }
    if (st->mss == NULL
        && frm_select_stub_adapter(st, adapter, location, log) != 0)
    {
        free(inst);
        free(st);
        return NULL;
    }

    inst->driver = &brix_sd_frm_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = st;
    return inst;
}

void
brix_sd_frm_destroy(brix_sd_instance_t *inst)
{
    sd_frm_state *st;

    if (inst == NULL) {
        return;
    }
    st = inst->state;
    if (st != NULL) {
        if (st->mss != NULL && st->mss->destroy != NULL) {
            st->mss->destroy(st->mss_ctx);
        }
        free(st);
    }
    free(inst);
}
