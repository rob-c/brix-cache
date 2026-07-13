/*
 * http_serve_offload.c - off-event-loop serve of a remote (socket-wire) object.
 * See http_serve_offload.h for the WHAT/WHY/HOW.
 */
#include "http_serve_offload.h"
#include "core/aio/aio.h"                          /* brix_task_bind */
#include "fs/vfs/vfs.h"                           /* brix_vfs_adopt_fd / _ctx_t */
#include "fs/vfs/vfs_internal.h"       /* brix_vfs_backend_cred (per-user cred gate) */
#include "fs/core/vfs_core.h"                 /* xvfs_drain (shared copy verb) */
#include "fs/backend/cache/sd_cache.h"        /* cache store accessor */
#include "fs/backend/stage/sd_stage.h"        /* stage source accessor */
#include "fs/backend/ucred.h"      /* BRIX_UCRED_*_MAX (cred buffer sizing) */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#if (NGX_THREADS)

/* The chunk size for the materialise copy (driver pread -> temp pwrite). */
#define BRIX_SERVE_OFFLOAD_CHUNK  (1024 * 1024)

/* Per-serve task context (lives on r->pool inside the ngx_thread_task_t). */
typedef struct {
    ngx_http_request_t           *r;
    brix_sd_instance_t         *inst;          /* composed instance to open       */
    brix_http_serve_metrics_pt  metrics_cb;
    ngx_log_t                    *log;
    off_t                         size;          /* materialised size               */
    time_t                        mtime;         /* captured object mtime           */
    int                           etag_flags;
    int                           xfer_proto;
    int                           tmp_fd;        /* O_TMPFILE / unlinked scratch    */
    int                           mret;          /* 0 ok, else errno                */
    unsigned                      compress:1;
    unsigned                      is_tls:1;
    char                          key[PATH_MAX];     /* export-relative open key    */
    char                          fs_path[PATH_MAX]; /* logical path for headers    */
    char                          op_name[24];
    char                          identity[128];
    /* Per-user backend credential (phase-2 follow-up), detached-copied at
     * submit (see brix_stage_cred_t in fs/xfer/stage_engine.h for the same
     * pattern/rationale): the worker thread outlives the request pool
     * boundary that owns the borrowed brix_sd_cred_t strings, so the raw
     * pointers cannot cross into the thread — only these fixed buffers can.
     * use_cred=0 means the gate resolved a service-credential fallback (or
     * the ctx had no cred policy bound at all); the thread then opens with a
     * NULL cred, exactly as brix_sd_open_maybe_cred's NULL-cred contract. */
    unsigned                      use_cred:1;
    char                          cred_x509_proxy[BRIX_UCRED_PATH_MAX];
    char                          cred_bearer[BRIX_UCRED_BEARER_MAX];
    char                          cred_key[BRIX_UCRED_KEY_MAX];
    char                          cred_principal[BRIX_UCRED_PRINC_MAX];
    char                          cred_dir[BRIX_UCRED_PATH_MAX];
    unsigned                      cred_fallback_deny:1;
} serve_offload_ctx;

/* The immutable serve inputs the orchestrator receives from its caller, bundled
 * so the ctx-fill helper takes them as one param. Borrowed pointers, valid for
 * the submit call only (copied into fixed task buffers by serve_offload_fill_ctx). */
typedef struct {
    brix_sd_instance_t             *inst;
    const char                     *key;
    const char                     *fs_path;
    const brix_http_serve_opts_t   *opts;
    brix_http_serve_metrics_pt      metrics_cb;
} serve_offload_args_t;

/* Resolved per-user backend credential, produced by the event-loop gate and
 * consumed by the task-ctx fill. `ustore` is the fixed backing storage the gate
 * fills; `cred` borrows into it (valid only for the submit call); `use_cred` is
 * 0 when no policy is bound or a service-credential fallback was resolved. */
typedef struct {
    brix_sd_ucred_t  ustore;
    brix_sd_cred_t   cred;
    int              use_cred;
} serve_offload_cred_t;

/* 1 iff serving `inst` reads from a socket-wire backend (one that cannot pump its
 * blocking socket on the un-pumped event loop). A cache serves from its STORE; a
 * stage decorator serves from its SOURCE; a bare driver answers by name. Today the
 * only such driver is "xroot"; in-process (rados) and curl (s3/http) block-but-
 * complete on-loop and are served inline. */
static int
serve_is_remote_socket(const brix_sd_instance_t *inst)
{
    if (inst == NULL) {
        return 0;
    }
    if (brix_sd_cache_instance_is(inst)) {
        return serve_is_remote_socket(brix_sd_cache_store_instance(inst));
    }
    if (brix_sd_stage_instance_is(inst)) {
        return serve_is_remote_socket(brix_sd_stage_source_instance(inst));
    }
    return (inst->driver != NULL && inst->driver->name != NULL
            && ngx_strcmp(inst->driver->name, "xroot") == 0) ? 1 : 0;
}

/* Open an anonymous, auto-cleaned temp file for the materialised object. Prefers
 * O_TMPFILE (no name, removed on last close); falls back to mkstemp+unlink. A
 * transient worker-owned scratch buffer, not export storage. */
static int
serve_offload_tmp_open(ngx_log_t *log)
{
    const char *dir = getenv("TMPDIR");
    int         fd;

    if (dir == NULL || dir[0] == '\0') {
        dir = "/tmp";
    }
    fd = open(dir, O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);  /* vfs-seam-allow: transient serve scratch (not export storage) */
    if (fd >= 0) {
        return fd;
    }
    {
        char tmpl[PATH_MAX];
        int  n = ngx_snprintf((u_char *) tmpl, sizeof(tmpl) - 1,
                              "%s/xrd-serve.XXXXXX", dir) - (u_char *) tmpl;

        tmpl[n] = '\0';
        fd = mkstemp(tmpl);                                /* vfs-seam-allow: transient serve scratch (not export storage) */
        if (fd >= 0) {
            (void) unlink(tmpl);                           /* vfs-seam-allow: transient serve scratch (not export storage) */
            return fd;
        }
    }
    ngx_log_error(NGX_LOG_ERR, log, errno,
        "serve offload: cannot open a temp scratch file under \"%s\"", dir);
    return -1;
}

/* Rebuild a stack brix_sd_cred_t from the task ctx's detached-copied buffers.
 *
 * WHAT: Reconstitute the per-user credential the event loop resolved, mapping
 *       each empty fixed buffer back to a NULL field.
 * WHY:  The request pool that owned the original borrowed brix_sd_cred_t
 *       strings does not outlive this worker thread call, so the credential
 *       must travel as fixed-buffer copies and be rebuilt here (see the
 *       serve_offload_ctx struct comment + http_serve_offload.h PHASE-2).
 * HOW:  Zero the out cred, then point each field at its buffer iff non-empty.
 */
static void
serve_offload_rebuild_cred(const serve_offload_ctx *t, brix_sd_cred_t *cred)
{
    ngx_memzero(cred, sizeof(*cred));
    cred->x509_proxy = (t->cred_x509_proxy[0] != '\0')
                       ? t->cred_x509_proxy : NULL;
    cred->bearer     = (t->cred_bearer[0] != '\0') ? t->cred_bearer : NULL;
    cred->key        = (t->cred_key[0] != '\0') ? t->cred_key : NULL;
    cred->principal  = (t->cred_principal[0] != '\0')
                       ? t->cred_principal : NULL;
    cred->cred_dir   = (t->cred_dir[0] != '\0') ? t->cred_dir : NULL;
    cred->fallback_deny = t->cred_fallback_deny;
}

/* Open the composed instance for the task's key with the per-user credential.
 *
 * WHAT: Open through brix_sd_open_maybe_cred so a remote-backed export sees the
 *       REQUESTING USER's credential (or a NULL cred when use_cred=0), exactly
 *       as the caller's own inline brix_vfs_open would have.
 * WHY:  use_cred=0 (no policy bound, or the gate resolved a service-credential
 *       fallback) opens with a NULL cred, unchanged from before this fix.
 * HOW:  Rebuild the stack cred iff use_cred, then delegate to the open verb;
 *       returns the opened obj or NULL (with *err set to the open errno).
 */
static brix_sd_obj_t *
serve_offload_thread_open(const serve_offload_ctx *t, int *err)
{
    if (t->use_cred) {
        brix_sd_cred_t cred;

        serve_offload_rebuild_cred(t, &cred);
        return brix_sd_open_maybe_cred(t->inst, t->key, BRIX_SD_O_READ, 0,
                                       &cred, err);
    }
    return brix_sd_open_maybe_cred(t->inst, t->key, BRIX_SD_O_READ, 0,
                                   NULL, err);
}

/* Materialise the opened object into the scratch temp fd through the driver seam.
 *
 * WHAT: Capture the object mtime, then copy every byte into the POSIX-wrapped
 *       temp fd; sets t->mtime / t->size / t->mret.
 * WHY:  Keeps the byte-pump (buffer alloc, fstat, drain) out of the thread
 *       orchestrator so the open and copy phases read as one line each.
 * HOW:  fstat for a fresh mtime snapshot, malloc the chunk, xvfs_drain owns the
 *       chunked pread->pwrite + EINTR loop; the caller still owns obj close.
 */
static void
serve_offload_thread_materialise(serve_offload_ctx *t, brix_sd_obj_t *obj)
{
    brix_sd_obj_t   dst;            /* worker-owned scratch, driver-routed */
    brix_sd_stat_t  snap;
    u_char         *buf;
    off_t           off = 0;

    snap = obj->snap;
    if (obj->driver->fstat != NULL) {
        (void) obj->driver->fstat(obj, &snap);
    }
    t->mtime = snap.mtime;

    buf = malloc(BRIX_SERVE_OFFLOAD_CHUNK);
    if (buf == NULL) {
        t->mret = ENOMEM;
        return;
    }
    /* Read from the (possibly remote/object) source obj, write to the POSIX-
     * wrapped temp. xvfs_drain owns the chunked pread->pwrite + EINTR loop. */
    brix_sd_posix_wrap(&dst, t->tmp_fd);
    t->mret = (xvfs_drain(obj, &dst, buf, BRIX_SERVE_OFFLOAD_CHUNK, &off) == 0)
              ? 0 : (errno ? errno : EIO);
    free(buf);
    if (t->mret == 0) {
        t->size = off;
    }
}

/* Worker thread: open the object through the composed driver (eager connect, cinfo
 * load, miss fill all run here) and copy it into the temp fd. Pure blocking I/O off
 * the event loop - the socket wire client opens + reads here safely. */
static void
serve_offload_thread(void *data, ngx_log_t *log)
{
    serve_offload_ctx *t = data;
    brix_sd_obj_t     *obj;
    int                err = 0;

    (void) log;
    if (t->inst->driver->open == NULL || t->inst->driver->pread == NULL) {
        t->mret = ENOSYS;
        return;
    }

    obj = serve_offload_thread_open(t, &err);
    if (obj == NULL) {
        t->mret = err ? err : EIO;
        return;
    }

    serve_offload_thread_materialise(t, obj);

    obj->driver->close(obj);
    if (obj->heap_shell) { free(obj); }
}

/* Event loop: adopt the temp fd as a POSIX handle and serve it through the shared
 * sendfile pipeline, run the protocol metrics callback, then finalise. The single
 * ngx_http_finalize_request balances the r->main->count++ taken at post. */
static void
serve_offload_done(ngx_event_t *ev)
{
    ngx_thread_task_t          *task = ev->data;
    serve_offload_ctx          *t = task->ctx;
    ngx_http_request_t         *r = t->r;
    ngx_connection_t           *c = r->connection;
    brix_vfs_ctx_t            tvctx;
    brix_vfs_file_t          *tfh = NULL;
    brix_vfs_stat_t           vst;
    brix_http_serve_opts_t    opts;
    brix_http_serve_result_t  result;
    brix_vfs_adopt_attrs_t    tattrs;
    ngx_int_t                   rc;

    if (t->mret != 0) {
        if (t->tmp_fd >= 0) {
            (void) close(t->tmp_fd);
        }
        ngx_log_error(NGX_LOG_ERR, c->log, t->mret,
            "serve offload: materialise failed for \"%s\" - returning %d",
            t->fs_path, (t->mret == ENOENT) ? 404 : 502);
        ngx_http_finalize_request(r,
            (t->mret == ENOENT) ? NGX_HTTP_NOT_FOUND : NGX_HTTP_BAD_GATEWAY);
        ngx_http_run_posted_requests(c);
        return;
    }

    /* Wrap the temp fd in a POSIX VFS handle (sd == NULL -> default driver). */
    ngx_memzero(&tvctx, sizeof(tvctx));
    tvctx.rootfd = -1;
    tvctx.pool   = r->pool;
    tvctx.log    = t->log;
    tvctx.sd     = NULL;
    tvctx.is_tls = t->is_tls;
    ngx_memzero(&tattrs, sizeof(tattrs));   /* from_cache=0, writable=0 */
    if (brix_vfs_adopt_fd(&tvctx, t->fs_path, t->tmp_fd, tattrs, &tfh)
        != NGX_OK)
    {
        (void) close(t->tmp_fd);
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno,
            "serve offload: temp adopt failed for \"%s\"", t->fs_path);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_run_posted_requests(c);
        return;
    }

    ngx_memzero(&vst, sizeof(vst));
    vst.size       = t->size;
    vst.mtime      = t->mtime;
    vst.mode       = S_IFREG | 0644;
    vst.is_regular = 1;

    ngx_memzero(&opts, sizeof(opts));
    opts.xfer_proto = t->xfer_proto;
    opts.op_name    = t->op_name;
    opts.identity   = t->identity;
    opts.etag_flags = t->etag_flags;
    opts.compress   = t->compress;
    /* The protocol pre-header hook references request-stack state that did not
     * survive the offload, so it is not run: a materialised serve omits the
     * checksum / xrdhttp / response-override headers (the bytes/range are exact). */

    rc = brix_http_serve_file_ranged(r, tfh, &vst, t->fs_path, &opts, &result);
    if (t->metrics_cb != NULL) {
        t->metrics_cb(r, &result);
    }
    ngx_http_finalize_request(r, rc);
    ngx_http_run_posted_requests(c);
}

/* Lazily resolve the export's async thread pool (the webdav/copy.c idiom). */
static ngx_thread_pool_t *
serve_offload_pool(ngx_http_brix_shared_conf_t *common)
{
    ngx_thread_pool_t *pool = common->thread_pool;

    if (pool == NULL) {
        static ngx_str_t  default_name = ngx_string("default");
        ngx_str_t        *pname = common->thread_pool_name.len > 0
                                  ? &common->thread_pool_name : &default_name;

        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
        if (pool != NULL) {
            common->thread_pool = pool;
        }
    }
    return pool;
}

/* Run the per-user backend credential gate on the event loop.
 *
 * WHAT: Resolve the requesting user's backend credential (or a service-cred
 *       fallback) for this request, writing the borrowed cred into *ucred and
 *       the use-cred flag into *use_cred.
 * WHY:  Deny mode (no cred / not authorized, fallback forbidden) must refuse
 *       the whole GET with errno EACCES BEFORE any origin connection is
 *       attempted, exactly as the inline brix_vfs_open path already does. A
 *       NULL vctx (no bound ctx / no cred policy) skips the gate — use_cred
 *       stays 0, unchanged pre-fix behaviour.
 * HOW:  Zero the out cred; when vctx is set, delegate to brix_vfs_backend_cred
 *       and on deny log + set errno EACCES. Returns NGX_OK on grant/skip,
 *       NGX_ERROR on deny. `out->ustore` is the fixed backing storage the gate
 *       fills; `out->cred` borrows into it for the caller's stack lifetime.
 */
static ngx_int_t
serve_offload_cred_gate(ngx_http_request_t *r, brix_vfs_ctx_t *vctx,
    const char *fs_path, serve_offload_cred_t *out)
{
    int gate_err = 0;

    ngx_memzero(&out->cred, sizeof(out->cred));
    out->use_cred = 0;

    if (vctx == NULL) {
        return NGX_OK;
    }
    if (brix_vfs_backend_cred(vctx, &out->ustore, &out->cred, &out->use_cred,
                              &gate_err) == NGX_OK)
    {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log,
        gate_err ? gate_err : EACCES,
        "serve offload: credential denied for \"%s\" - refusing "
        "before origin open", fs_path);
    errno = gate_err ? gate_err : EACCES;
    return NGX_ERROR;
}

/* Detached-copy the resolved credential's strings into the task ctx.
 *
 * WHAT: Copy each non-NULL borrowed credential string into its fixed task
 *       buffer (empty buffer == NULL field), and set use_cred / fallback_deny.
 * WHY:  The borrowed brix_sd_cred_t pointers are only valid for the duration of
 *       the submit call; the worker thread outlives it, so only fixed buffers
 *       (rebuilt by serve_offload_rebuild_cred) may cross the thread boundary.
 * HOW:  Pre-clear every buffer, then ngx_cpystrn each present field; a NULL/0
 *       cred (use_cred=0) leaves all buffers empty — the thread opens NULL-cred.
 */
static void
serve_offload_copy_cred(serve_offload_ctx *t, const serve_offload_cred_t *rc)
{
    const brix_sd_cred_t *ucred = &rc->cred;

    t->use_cred = rc->use_cred ? 1 : 0;
    t->cred_x509_proxy[0] = '\0';
    t->cred_bearer[0]     = '\0';
    t->cred_key[0]        = '\0';
    t->cred_principal[0]  = '\0';
    t->cred_dir[0]        = '\0';
    t->cred_fallback_deny = 0;

    if (!rc->use_cred) {
        return;
    }
    if (ucred->x509_proxy != NULL) {
        ngx_cpystrn((u_char *) t->cred_x509_proxy,
                    (u_char *) ucred->x509_proxy, sizeof(t->cred_x509_proxy));
    }
    if (ucred->bearer != NULL) {
        ngx_cpystrn((u_char *) t->cred_bearer, (u_char *) ucred->bearer,
                    sizeof(t->cred_bearer));
    }
    if (ucred->key != NULL) {
        ngx_cpystrn((u_char *) t->cred_key, (u_char *) ucred->key,
                    sizeof(t->cred_key));
    }
    if (ucred->principal != NULL) {
        ngx_cpystrn((u_char *) t->cred_principal, (u_char *) ucred->principal,
                    sizeof(t->cred_principal));
    }
    if (ucred->cred_dir != NULL) {
        ngx_cpystrn((u_char *) t->cred_dir, (u_char *) ucred->cred_dir,
                    sizeof(t->cred_dir));
    }
    t->cred_fallback_deny = ucred->fallback_deny;
}

/* Populate the per-serve task ctx from the request, opts, and resolved cred.
 *
 * WHAT: Fill every field of the freshly-allocated serve_offload_ctx: request
 *       handles, serve opts, the claimed temp fd, the detached credential, the
 *       TLS flag, and the copied path/name strings.
 * WHY:  Keeps the (long, mechanical) field-by-field population out of the
 *       orchestrator so it reads as gate -> alloc -> fill -> post.
 * HOW:  Direct assignment for scalars, serve_offload_copy_cred for the cred, and
 *       ngx_cpystrn for the fixed string buffers (never capture c->log lifetime
 *       state — t->log is the connection log pointer, valid for the request).
 */
static void
serve_offload_fill_ctx(serve_offload_ctx *t, ngx_http_request_t *r,
    const serve_offload_args_t *a, int tmp_fd, const serve_offload_cred_t *rc)
{
    const brix_http_serve_opts_t *opts = a->opts;

    t->r          = r;
    t->inst       = a->inst;
    t->metrics_cb = a->metrics_cb;
    t->log        = r->connection->log;
    t->etag_flags = opts->etag_flags;
    t->xfer_proto = opts->xfer_proto;
    t->tmp_fd     = tmp_fd;
    t->mret       = EIO;
    t->compress   = opts->compress ? 1 : 0;

    serve_offload_copy_cred(t, rc);

    t->is_tls     = 0;
#if (NGX_HTTP_SSL)
    t->is_tls     = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    ngx_cpystrn((u_char *) t->key, (u_char *) a->key, sizeof(t->key));
    ngx_cpystrn((u_char *) t->fs_path, (u_char *) a->fs_path,
                sizeof(t->fs_path));
    ngx_cpystrn((u_char *) t->op_name,
                (u_char *) (opts->op_name ? opts->op_name : ""),
                sizeof(t->op_name));
    ngx_cpystrn((u_char *) t->identity,
                (u_char *) (opts->identity ? opts->identity : ""),
                sizeof(t->identity));
}

ngx_int_t
brix_http_serve_offload_remote(ngx_http_request_t *r,
    brix_sd_instance_t *inst, const char *key, const char *fs_path,
    const brix_http_serve_opts_t *opts,
    ngx_http_brix_shared_conf_t *common,
    brix_vfs_ctx_t *vctx,
    brix_http_serve_metrics_pt metrics_cb)
{
    ngx_thread_task_t    *task;
    serve_offload_ctx    *t;
    ngx_thread_pool_t    *pool;
    int                   tmp_fd;
    serve_offload_cred_t  rc;
    serve_offload_args_t  args;

    if (r == NULL || inst == NULL || key == NULL || fs_path == NULL
        || opts == NULL || common == NULL || r->header_only
        || !serve_is_remote_socket(inst))
    {
        return NGX_DECLINED;             /* serve inline (local / in-process / HEAD) */
    }

    pool = serve_offload_pool(common);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "serve offload: \"%s\" reads from a remote socket backend but no "
            "thread pool is configured - serving inline (may stall)", fs_path);
        return NGX_DECLINED;
    }

    if (serve_offload_cred_gate(r, vctx, fs_path, &rc) != NGX_OK) {
        return NGX_ERROR;
    }

    tmp_fd = serve_offload_tmp_open(r->connection->log);
    if (tmp_fd < 0) {
        return NGX_ERROR;
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(serve_offload_ctx));
    if (task == NULL) {
        (void) close(tmp_fd);
        return NGX_ERROR;
    }
    t = task->ctx;
    args.inst       = inst;
    args.key        = key;
    args.fs_path    = fs_path;
    args.opts       = opts;
    args.metrics_cb = metrics_cb;
    serve_offload_fill_ctx(t, r, &args, tmp_fd, &rc);

    brix_task_bind(task, serve_offload_thread, serve_offload_done);
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        (void) close(tmp_fd);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "serve offload: materialising remote \"%s\" on the thread pool", fs_path);
    r->main->count++;
    return NGX_DONE;
}

#else  /* !NGX_THREADS */

ngx_int_t
brix_http_serve_offload_remote(ngx_http_request_t *r,
    brix_sd_instance_t *inst, const char *key, const char *fs_path,
    const brix_http_serve_opts_t *opts,
    ngx_http_brix_shared_conf_t *common,
    brix_vfs_ctx_t *vctx,
    brix_http_serve_metrics_pt metrics_cb)
{
    (void) r; (void) inst; (void) key; (void) fs_path;
    (void) opts; (void) common; (void) vctx; (void) metrics_cb;
    return NGX_DECLINED;
}

#endif /* NGX_THREADS */
