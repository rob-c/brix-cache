/*
 * put_aio.c - extracted concern
 * Phase-38 split of put.c; behavior-identical.
 */
#include "s3_put_internal.h"




/*
 * s3_thread_pool — resolve (and cache) the async-I/O thread pool for this
 * location.
 *
 * WHY: the S3 postconfiguration only resolves common.thread_pool on the
 * *server-level* loc-conf, but `xrootd_s3 on` is normally inside a `location {}`
 * block whose loc-conf never gets that pointer set — so the offload below would
 * silently never engage.  Mirror the WebDAV COPY/MOVE pattern
 * (src/webdav/copy.c, move.c): resolve lazily at request time via ngx_cycle and
 * cache the result into the loc-conf for subsequent requests.
 */
ngx_thread_pool_t *
s3_thread_pool(ngx_http_s3_loc_conf_t *cf)
{
    static ngx_str_t   default_name = ngx_string("default");
    ngx_str_t         *pname;
    ngx_thread_pool_t *pool;

    if (cf->common.thread_pool != NULL) {
        return cf->common.thread_pool;
    }
    pname = cf->common.thread_pool_name.len > 0
            ? &cf->common.thread_pool_name : &default_name;
    pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
    if (pool != NULL) {
        cf->common.thread_pool = pool;   /* cache for subsequent requests */
    }
    return pool;
}


void
s3_put_aio_thread(void *data, ngx_log_t *log)
{
    s3_put_aio_t *t = data;

    (void) log;

    t->io_errno = 0;

    /*
     * Phase 31 W2 / phase-46 W1a: stream every body buf straight to the staged
     * temp fd — no full-body contiguous copy.  Memory bufs go via pwrite(2);
     * spooled bufs via kernel copy_file_range from the nginx temp file.  Both are
     * blocking syscalls, which is exactly why they run here on the thread pool
     * rather than the event loop.
     */
    /* A driver-backed (remote-stage) staged target has no kernel fd — stream the
     * body through the staged-write primitive; otherwise write straight to the temp
     * fd (memory pwrite / spooled copy_file_range). Mirrors the WebDAV PUT path. */
    if (xrootd_vfs_staged_is_driver(t->staged)
            ? xrootd_http_body_write_to_staged(t->r, t->staged) != NGX_OK
            : xrootd_http_body_write_to_fd(t->r, xrootd_vfs_staged_fd(t->staged),
                                           t->final_path, NULL) != NGX_OK)
    {
        t->io_errno = errno;
        t->nwritten = -1;
        return;
    }

    t->nwritten = (ssize_t) t->len;
}


void
s3_put_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    s3_put_aio_t       *t = task->ctx;
    ngx_http_request_t *r = t->r;
    ngx_log_t          *log = r->connection->log;

    if (t->nwritten < 0 || (size_t) t->nwritten < t->len) {
        xrootd_log_safe_path(log, NGX_LOG_ERR,
                             (ngx_uint_t) t->io_errno,
                             "s3: async write() failed for: \"%s\"",
                             t->final_path);
        xrootd_vfs_staged_abort(t->staged, 1);
        s3_put_finalize_error(r);
        return;
    }

    /* The VFS staged commit closes/promotes the temp itself — no manual close. */
    if (s3_commit_put(r, log, t->root_canon, t->staged,
                      t->final_path) != NGX_OK)
    {
        if (s3_put_commit_conflict(r)) {
            return;
        }
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "s3: async staged commit to \"%s\" failed",
                             t->final_path);
        s3_put_finalize_error(r);
        return;
    }

    /* S3 PutObject requires an ETag on the 200 response (the synchronous path
     * sets it too — keep the offload path's response identical). */
    {
        xrootd_vfs_ctx_t  fctx;
        xrootd_vfs_stat_t fst;
        char              etag_buf[48];

        xrootd_vfs_ctx_init(&fctx, r->pool, log, XROOTD_PROTO_S3, t->root_canon,
            NULL, 0 /* allow_write */, 0 /* is_tls */, NULL, t->final_path);
        if (xrootd_vfs_probe(&fctx, 1 /* no-follow */, &fst) == NGX_OK) {
            struct stat final_sb;

            ngx_memzero(&final_sb, sizeof(final_sb));
            final_sb.st_mtime = fst.mtime;
            final_sb.st_size  = fst.size;
            s3_etag(&final_sb, etag_buf, sizeof(etag_buf));
            (void) s3_set_header(r, "ETag", etag_buf);
        }
    }

    /* Full-object checksum verify (client-supplied) + echo; failures remove the
     * object and send the matching 400. */
    if (s3_put_checksum_failed(r, t->final_path, t->root_canon)) {
        return;
    }

    /* x-amz-tagging (best-effort): store the request's tag set on the object. */
    (void) s3_apply_put_tagging_header(r, t->final_path, t->root_canon);
    /* x-amz-meta-* (best-effort): store the request's user metadata set. */
    (void) s3_apply_put_user_metadata(r, t->final_path, t->root_canon);

    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) t->body_bytes);
    XROOTD_S3_METRIC_ADD(bytes_rx_total, t->body_bytes);
    if (r->connection && r->connection->sockaddr
        && r->connection->sockaddr->sa_family == AF_INET6) {
        XROOTD_S3_METRIC_ADD(bytes_rx_ipv6_total, t->body_bytes);
    } else {
        XROOTD_S3_METRIC_ADD(bytes_rx_ipv4_total, t->body_bytes);
    }
    XROOTD_S3_METRIC_INC(put_body_total[t->body_mode]);
    s3_put_finalize_empty_ok(r);
}
