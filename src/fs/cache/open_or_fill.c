#include "cache_internal.h"
#include "cache_storage.h"   /* driver-aware readiness for a backend-backed cache */
#include "fs/vfs/vfs_backend_registry.h"   /* C-1: resolve the source backend */
#include "fs/vfs/vfs_internal.h"           /* export-relative key for the composed fill */
#include "fs/backend/cache/sd_cache.h" /* composed-cache fill seam (SP2) */
#include "core/compat/error_mapping.h"      /* errno → kXR for the fill result */
#include "protocols/root/connection/shutdown_hold.h" /* active fill lifetime */

#include <errno.h>
#include <string.h>


/* brix_cache_open_or_fill — kXR_open cache entry point: by brix_cache_file_ready()
 * — 1 serve directly from cache (fast path), -1 error — else allocate a thread-pool
 * task (ngx_thread_task_alloc, since the worker thread owns the ctx: streamid,
 * options, clean_path/cache_path), post it to conf->common.thread_pool, enter
 * XRD_ST_AIO, and await brix_cache_fill_done. */
ngx_int_t
brix_cache_open_or_fill(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path,
    const char *cache_path, uint16_t options, uint16_t mode_bits)
{
    ngx_thread_task_t   *task;
    brix_cache_fill_t *t;
    int                  ready;

    ready = brix_cache_ready(conf, cache_path);
    if (ready == 1) {
        brix_open_request_t oreq = {
            .resolved  = cache_path,
            .options   = options,
            .mode_bits = mode_bits,
            .is_write  = 0,
            .codec     = 0,
        };
        return brix_open_resolved_file(ctx, c, conf, &oreq);
    }
    if (ready < 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", cache_path,
                          "cache", kXR_IOError, strerror(errno));
    }

    if (conf->common.thread_pool == NULL) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", clean_path,
                          "cache", kXR_ServerError, "cache thread pool missing");
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(brix_cache_fill_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    ngx_memzero(t, sizeof(*t));
    t->c = c;
    t->ctx = ctx;
    t->conf = conf;
    t->streamid[0] = ctx->recv.cur_streamid[0];
    t->streamid[1] = ctx->recv.cur_streamid[1];
    t->options = options;
    t->mode_bits = mode_bits;

    ngx_cpystrn((u_char *) t->clean_path, (u_char *) clean_path,
                sizeof(t->clean_path));
    ngx_cpystrn((u_char *) t->cache_path, (u_char *) cache_path,
                sizeof(t->cache_path));

    /* C-1 (phase-63): when no separate brix_cache_origin is configured but the
     * export's PRIMARY storage is a remote SOURCE backend (xroot://), the cache
     * fills FROM that registered backend. Resolve it HERE (main thread) so the
     * registry's lazy per-worker build never races on the async fill worker. */
    if (conf->cache_origin_host.len == 0) {
        brix_sd_instance_t *src =
            brix_vfs_backend_resolve(conf->common.root_canon, c->log);

        if (src != NULL
            && (ngx_strcmp(brix_sd_backend_name(src), "xroot") == 0
                || ngx_strcmp(brix_sd_backend_name(src), "http") == 0))
        {
            t->source_inst = src;
        }
    }

    if (brix_cache_append_suffix(t->part_path, sizeof(t->part_path),
                                   cache_path, BRIX_CACHE_PART_SUFFIX) != 0
        || brix_cache_append_suffix(t->lock_path, sizeof(t->lock_path),
                                      cache_path, BRIX_CACHE_LOCK_SUFFIX) != 0)
    {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", clean_path,
                          "cache", kXR_ArgTooLong, "cache path too long");
    }

    brix_task_bind(task, brix_cache_fill_thread, brix_cache_fill_done);

    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", clean_path,
                          "cache", kXR_ServerError, "cache thread post failed");
    }

    brix_shutdown_hold_sync(c, ctx, 1);
    ctx->state = XRD_ST_AIO;
    return NGX_OK;
}

/* ---- composed-cache (tier grammar) slow-tier miss offload (phase-64 SP2) ----
 *
 * A tier config (brix_storage_backend + brix_cache_store, conf->cache == 0)
 * serves reads through the registry's composed sd_cache: its open() runs a MISS
 * fill INLINE, which is a blocking wire transfer (s3/http HEAD+GET, root://
 * login+read) — a stall on the stream event loop, and a self-connect deadlock
 * when the source is served by this same worker. These three helpers are the
 * stream twin of src/shared/http_cache_fill.c: probe with the decorator's
 * non-blocking brix_sd_cache_fill_needs_offload, run the whole-file fill
 * (brix_sd_cache_fill_key) on the async thread pool with the connection
 * parked in XRD_ST_AIO, then serve the now-cached object from the done
 * callback. A COMPLETE hit, slice mode, or an all-local stack never gets here
 * (needs_offload == 0 → the caller opens inline as before). */

/* Lazily resolve the stream plane's async pool: postconfig may leave
 * common.thread_pool unset when the config only declares `thread_pool default`
 * (the http_cache_fill.c idiom). NULL when no pool exists. */
static ngx_thread_pool_t *
cache_composed_fill_pool(ngx_stream_brix_srv_conf_t *conf)
{
    ngx_thread_pool_t *pool = conf->common.thread_pool;

    if (pool == NULL) {
        static ngx_str_t  default_name = ngx_string("default");
        ngx_str_t        *pname = conf->common.thread_pool_name.len > 0
                                  ? &conf->common.thread_pool_name
                                  : &default_name;

        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
        if (pool != NULL) {
            conf->common.thread_pool = pool;
        }
    }
    return pool;
}

/* Project the fill task's carried per-user credential (populated on the main
 * thread by brix_cache_open_fill_offload) into a borrowed brix_sd_cred_t whose
 * pointers alias the task's owned buffers — valid for the duration of the fill.
 * Returns 1 when any credential field is set (so the source open forwards the
 * inbound user's delegated identity), 0 when the task carries none (anonymous /
 * service-credential fill, unchanged legacy behaviour). */
static int
cache_fill_cred_view(const brix_cache_fill_t *t, brix_sd_cred_t *out)
{
    int have = 0;

    ngx_memzero(out, sizeof(*out));
    if (t->cred_x509_proxy[0] != '\0') { out->x509_proxy = t->cred_x509_proxy; have = 1; }
    if (t->cred_bearer[0]     != '\0') { out->bearer     = t->cred_bearer;     have = 1; }
    if (t->cred_sss_keytab[0] != '\0') { out->sss_keytab = t->cred_sss_keytab; have = 1; }
    if (t->cred_krb5_ccache[0] != '\0') { out->krb5_ccache = t->cred_krb5_ccache; have = 1; }
    if (t->cred_krb5_princ[0]  != '\0') { out->krb5_princ  = t->cred_krb5_princ; }
    if (t->cred_principal[0]   != '\0') { out->principal   = t->cred_principal; }
    return have;
}

/* Copy a resolved per-user credential's strings into the fill task's owned
 * buffers so the async worker (which outlives the caller's ucred store) can
 * forward the inbound user's identity to the source origin. Mirrors the driver
 * carry (sd_xroot_copy_cred_into_task) but stays in the cache layer — no reach
 * into a backend's internals. NULL cred (no forwarded identity) is a no-op; the
 * task's cred_* fields stay empty (calloc-zeroed) → anonymous fill. */
static void
cache_fill_carry_cred(brix_cache_fill_t *t, const brix_sd_cred_t *cred)
{
    if (cred == NULL) {
        return;
    }
    if (cred->x509_proxy != NULL && cred->x509_proxy[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_x509_proxy, (u_char *) cred->x509_proxy,
                    sizeof(t->cred_x509_proxy));
    }
    if (cred->bearer != NULL && cred->bearer[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_bearer, (u_char *) cred->bearer,
                    sizeof(t->cred_bearer));
    }
    if (cred->sss_keytab != NULL && cred->sss_keytab[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_sss_keytab, (u_char *) cred->sss_keytab,
                    sizeof(t->cred_sss_keytab));
    }
    if (cred->krb5_ccache != NULL && cred->krb5_ccache[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_krb5_ccache, (u_char *) cred->krb5_ccache,
                    sizeof(t->cred_krb5_ccache));
    }
    if (cred->krb5_princ != NULL && cred->krb5_princ[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_krb5_princ, (u_char *) cred->krb5_princ,
                    sizeof(t->cred_krb5_princ));
    }
    if (cred->principal != NULL && cred->principal[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_principal, (u_char *) cred->principal,
                    sizeof(t->cred_principal));
    }
}

/* Worker thread: the blocking source → cache-store transfer, off the loop. */
static void
brix_cache_fill_composed_thread(void *data, ngx_log_t *log)
{
    brix_cache_fill_t *t = data;
    const char          *key = brix_vfs_export_relative_root(
                                   t->cache_path, t->conf->common.root_canon);
    brix_sd_cred_t       cred;
    int                  have_cred = cache_fill_cred_view(t, &cred);

    (void) log;
    errno = 0;
    t->result    = brix_sd_cache_fill_key(t->source_inst, key,
                                            have_cred ? &cred : NULL);
    t->sys_errno = errno;
}

/* Event loop: resume the parked open — serve the now-cached object (NGX_OK), or
 * open straight through the decorator for an admission-declined object
 * (NGX_DECLINED: sd_cache_open serves from the source), or report the fill
 * failure with the errno-mapped kXR code (ENOENT ⇒ the standard NotFound). */
static void
brix_cache_fill_composed_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    brix_cache_fill_t *t = task->ctx;
    brix_ctx_t        *ctx = t->ctx;
    ngx_connection_t    *c = t->c;
    ngx_int_t            rc;

    if (!brix_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->result == NGX_ERROR) {
        int      err = t->sys_errno ? t->sys_errno : EIO;
        uint16_t kxr = brix_kxr_from_errno(err);

        brix_log_access(ctx, c, "OPEN", t->clean_path, "cache-fill", 0, kxr,
                          "composed cache fill failed", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_OPEN_RD);
        brix_send_error(ctx, c, kxr,
                          (err == ENOENT) ? "file not found"
                                          : "cache fill from source failed");
        brix_aio_resume(c);
        return;
    }

    if (t->result == NGX_OK) {
        brix_log_access(ctx, c, "CACHE", t->cache_path, "fill", 1, 0, NULL, 0);

        /* The fill ran because this open MISSED; the re-open below will find
         * the just-written COMPLETE cinfo and sd_cache will call it a HIT.
         * Mark the request so the driver-adopt metric bump accounts the
         * client-visible miss instead. */
        ctx->open_fill_miss = 1;
    }

    brix_open_request_t oreq = {
        .resolved  = t->cache_path,
        .options   = t->options,
        .mode_bits = t->mode_bits,
        .is_write  = 0,
        .codec     = 0,
    };
    rc = brix_open_resolved_file(ctx, c, t->conf, &oreq);
    ctx->open_fill_miss = 0;   /* one-shot: never leak onto a later request */
    if (rc != NGX_OK && ctx->state != XRD_ST_SENDING) {
        brix_send_error(ctx, c, kXR_ServerError,
                          "open after cache fill failed");
    }

    brix_aio_resume(c);
}

/* brix_cache_open_fill_offload — post the composed-cache miss fill for
 * `full_path` (opened as `inst`, the registry's composed sd_cache) to the async
 * thread pool and park the connection in XRD_ST_AIO. Returns NGX_OK (parked; the
 * done callback responds), NGX_DECLINED (no pool — the caller must open inline,
 * accepting the stall), or a queued-error rc on a post failure. */
ngx_int_t
brix_cache_open_fill_offload(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path,
    const char *full_path, brix_sd_instance_t *inst,
    uint16_t options, uint16_t mode_bits, const brix_sd_cred_t *cred)
{
    ngx_thread_pool_t   *pool = cache_composed_fill_pool(conf);
    ngx_thread_task_t   *task;
    brix_cache_fill_t *t;

    if (pool == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
            "brix: cache miss on \"%s\" needs an async thread pool to fill a "
            "remote tier; none configured - serving inline (may stall)",
            clean_path);
        return NGX_DECLINED;
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(brix_cache_fill_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    ngx_memzero(t, sizeof(*t));
    t->c           = c;
    t->ctx         = ctx;
    t->conf        = conf;
    t->streamid[0] = ctx->recv.cur_streamid[0];
    t->streamid[1] = ctx->recv.cur_streamid[1];
    t->options     = options;
    t->mode_bits   = mode_bits;
    t->source_inst = inst;                 /* the composed sd_cache instance */
    ngx_cpystrn((u_char *) t->clean_path, (u_char *) clean_path,
                sizeof(t->clean_path));
    ngx_cpystrn((u_char *) t->cache_path, (u_char *) full_path,
                sizeof(t->cache_path));
    cache_fill_carry_cred(t, cred);   /* forward the inbound user's identity */

    brix_task_bind(task, brix_cache_fill_composed_thread,
                     brix_cache_fill_composed_done);

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", clean_path,
                          "cache", kXR_ServerError, "cache thread post failed");
    }

    brix_shutdown_hold_sync(c, ctx, 1);
    ctx->state = XRD_ST_AIO;
    return NGX_OK;
}
