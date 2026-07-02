/*
 * http_serve_offload.c - off-event-loop serve of a remote (socket-wire) object.
 * See http_serve_offload.h for the WHAT/WHY/HOW.
 */
#include "http_serve_offload.h"
#include "core/aio/aio.h"                          /* xrootd_task_bind */
#include "fs/vfs.h"                           /* xrootd_vfs_adopt_fd / _ctx_t */
#include "fs/core/vfs_core.h"                 /* xvfs_drain (shared copy verb) */
#include "fs/backend/cache/sd_cache.h"        /* cache store accessor */
#include "fs/backend/stage/sd_stage.h"        /* stage source accessor */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#if (NGX_THREADS)

/* The chunk size for the materialise copy (driver pread -> temp pwrite). */
#define XROOTD_SERVE_OFFLOAD_CHUNK  (1024 * 1024)

/* Per-serve task context (lives on r->pool inside the ngx_thread_task_t). */
typedef struct {
    ngx_http_request_t           *r;
    xrootd_sd_instance_t         *inst;          /* composed instance to open       */
    xrootd_http_serve_metrics_pt  metrics_cb;
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
} serve_offload_ctx;

/* 1 iff serving `inst` reads from a socket-wire backend (one that cannot pump its
 * blocking socket on the un-pumped event loop). A cache serves from its STORE; a
 * stage decorator serves from its SOURCE; a bare driver answers by name. Today the
 * only such driver is "xroot"; in-process (rados) and curl (s3/http) block-but-
 * complete on-loop and are served inline. */
static int
serve_is_remote_socket(const xrootd_sd_instance_t *inst)
{
    if (inst == NULL) {
        return 0;
    }
    if (xrootd_sd_cache_instance_is(inst)) {
        return serve_is_remote_socket(xrootd_sd_cache_store_instance(inst));
    }
    if (xrootd_sd_stage_instance_is(inst)) {
        return serve_is_remote_socket(xrootd_sd_stage_source_instance(inst));
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

/* Worker thread: open the object through the composed driver (eager connect, cinfo
 * load, miss fill all run here) and copy it into the temp fd. Pure blocking I/O off
 * the event loop - the socket wire client opens + reads here safely. */
static void
serve_offload_thread(void *data, ngx_log_t *log)
{
    serve_offload_ctx *t = data;
    xrootd_sd_obj_t   *obj;
    xrootd_sd_obj_t    dst;            /* worker-owned scratch, driver-routed */
    xrootd_sd_stat_t   snap;
    u_char            *buf;
    off_t              off = 0;
    int                err = 0;

    (void) log;
    if (t->inst->driver->open == NULL || t->inst->driver->pread == NULL) {
        t->mret = ENOSYS;
        return;
    }
    obj = t->inst->driver->open(t->inst, t->key, XROOTD_SD_O_READ, 0, &err);
    if (obj == NULL) {
        t->mret = err ? err : EIO;
        return;
    }

    snap = obj->snap;
    if (obj->driver->fstat != NULL) {
        (void) obj->driver->fstat(obj, &snap);
    }
    t->mtime = snap.mtime;

    buf = malloc(XROOTD_SERVE_OFFLOAD_CHUNK);
    if (buf == NULL) {
        obj->driver->close(obj);
        if (obj->heap_shell) { free(obj); }
        t->mret = ENOMEM;
        return;
    }
    /* Materialise the whole object into the scratch fd through the driver seam:
     * read from the (possibly remote/object) source obj, write to the POSIX-
     * wrapped temp. xvfs_drain owns the chunked pread->pwrite + EINTR loop. */
    xrootd_sd_posix_wrap(&dst, t->tmp_fd);
    t->mret = (xvfs_drain(obj, &dst, buf, XROOTD_SERVE_OFFLOAD_CHUNK, &off) == 0)
              ? 0 : (errno ? errno : EIO);
    free(buf);
    obj->driver->close(obj);
    if (obj->heap_shell) { free(obj); }
    if (t->mret == 0) {
        t->size = off;
    }
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
    xrootd_vfs_ctx_t            tvctx;
    xrootd_vfs_file_t          *tfh = NULL;
    xrootd_vfs_stat_t           vst;
    xrootd_http_serve_opts_t    opts;
    xrootd_http_serve_result_t  result;
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
    if (xrootd_vfs_adopt_fd(&tvctx, t->fs_path, t->tmp_fd, 0, 0, &tfh) != NGX_OK) {
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

    rc = xrootd_http_serve_file_ranged(r, tfh, &vst, t->fs_path, &opts, &result);
    if (t->metrics_cb != NULL) {
        t->metrics_cb(r, &result);
    }
    ngx_http_finalize_request(r, rc);
    ngx_http_run_posted_requests(c);
}

/* Lazily resolve the export's async thread pool (the webdav/copy.c idiom). */
static ngx_thread_pool_t *
serve_offload_pool(ngx_http_xrootd_shared_conf_t *common)
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

ngx_int_t
xrootd_http_serve_offload_remote(ngx_http_request_t *r,
    xrootd_sd_instance_t *inst, const char *key, const char *fs_path,
    const xrootd_http_serve_opts_t *opts,
    ngx_http_xrootd_shared_conf_t *common,
    xrootd_http_serve_metrics_pt metrics_cb)
{
    ngx_thread_task_t *task;
    serve_offload_ctx *t;
    ngx_thread_pool_t *pool;
    int                tmp_fd;

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
    t->r          = r;
    t->inst       = inst;
    t->metrics_cb = metrics_cb;
    t->log        = r->connection->log;
    t->etag_flags = opts->etag_flags;
    t->xfer_proto = opts->xfer_proto;
    t->tmp_fd     = tmp_fd;
    t->mret       = EIO;
    t->compress   = opts->compress ? 1 : 0;
    t->is_tls     = 0;
#if (NGX_HTTP_SSL)
    t->is_tls     = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    ngx_cpystrn((u_char *) t->key, (u_char *) key, sizeof(t->key));
    ngx_cpystrn((u_char *) t->fs_path, (u_char *) fs_path, sizeof(t->fs_path));
    ngx_cpystrn((u_char *) t->op_name,
                (u_char *) (opts->op_name ? opts->op_name : ""),
                sizeof(t->op_name));
    ngx_cpystrn((u_char *) t->identity,
                (u_char *) (opts->identity ? opts->identity : ""),
                sizeof(t->identity));

    xrootd_task_bind(task, serve_offload_thread, serve_offload_done);
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
xrootd_http_serve_offload_remote(ngx_http_request_t *r,
    xrootd_sd_instance_t *inst, const char *key, const char *fs_path,
    const xrootd_http_serve_opts_t *opts,
    ngx_http_xrootd_shared_conf_t *common,
    xrootd_http_serve_metrics_pt metrics_cb)
{
    (void) r; (void) inst; (void) key; (void) fs_path;
    (void) opts; (void) common; (void) metrics_cb;
    return NGX_DECLINED;
}

#endif /* NGX_THREADS */
