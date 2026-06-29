#include "cache_internal.h"
#include "cache_storage.h"   /* driver-aware readiness for a backend-backed cache */
#include "../manager/registry.h"


#include <netinet/in.h>
#include <unistd.h>

/* xrootd_cache_fill_thread — thread-pool worker running the full fill lifecycle:
 * ensure parent dir → evict if over threshold → acquire the per-file lock → skip if
 * already ready → fetch origin → release the lock on exit. No response (the done
 * callback resumes the client). */
void
xrootd_cache_fill_thread(void *data, ngx_log_t *log)
{
    xrootd_cache_fill_t *t;
    int                 owned;

    t = data;
    owned = 0;
    (void) log;

    t->result = NGX_OK;
    t->xrd_error = 0;
    t->sys_errno = 0;
    t->err_msg[0] = '\0';

    if (xrootd_cache_ensure_parent(t->cache_path) != 0) {
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache parent mkdir failed");
        return;
    }

    xrootd_cache_evict_if_needed(t, t->cache_path, log);

    if (xrootd_cache_wait_or_lock(t, &owned) != 0) {
        return;
    }

    if (!owned) {
        return;
    }

    if (xrootd_cache_ready(t->conf, t->cache_path) == 1) {
        unlink(t->lock_path);
        return;
    }

    if (xrootd_cache_fetch_origin(t) != 0) {
        /* -1 = fill error (t->result + t->err_msg set by fetch)
         *  1 = admission declined (t->result = NGX_DECLINED)
         * Both paths: release the lock and let the done callback handle it. */
        unlink(t->lock_path);
        return;
    }

    xrootd_cache_evict_if_needed(t, t->cache_path, log);

    unlink(t->lock_path);
}

/* xrootd_cache_fill_done — completion callback (event loop) when the fill worker
 * finishes: restore the request context, then dispatch on the result — NGX_DECLINED
 * redirects to origin (admission rejected), error sends kXR_error, success opens the
 * cached file — and resume the client via ngx_stream_xrootd_recv(). */
void
xrootd_cache_fill_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task;
    xrootd_cache_fill_t *t;
    xrootd_ctx_t      *ctx;
    ngx_connection_t  *c;
    ngx_int_t          rc;

    task = ev->data;
    t = task->ctx;
    ctx = t->ctx;
    c = t->c;

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    /*
     * Admission declined: the file was too large and didn't match the include
     * regex.  Redirect the client to the origin so it fetches the file directly
     * without going through the cache layer at all.
     */
    if (t->result == NGX_DECLINED) {
        xrootd_log_access(ctx, c, "OPEN", t->clean_path, "cache-bypass",
                          0, 0,
                          "cache admission rejected; redirecting to origin", 0);
        if (t->conf->cache_origin_host.len > 0) {
            xrootd_send_redirect(ctx, c,
                                 (const char *) t->conf->cache_origin_host.data,
                                 t->conf->cache_origin_port);
        } else {
            XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
            xrootd_send_error(ctx, c, kXR_Unsupported,
                              "file too large to cache and no origin configured "
                              "for redirect");
        }
        xrootd_aio_resume(c);
        return;
    }

    if (t->result != NGX_OK) {
        int err;

        err = t->xrd_error ? t->xrd_error : kXR_ServerError;
        xrootd_log_access(ctx, c, "OPEN", t->clean_path, "cache-fill",
                          0, (uint16_t) err,
                          t->err_msg[0] ? t->err_msg : "cache fill failed",
                          0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
        xrootd_send_error(ctx, c, (uint16_t) err,
                          t->err_msg[0] ? t->err_msg : "cache fill failed");
        xrootd_aio_resume(c);
        return;
    }

    xrootd_log_access(ctx, c, "CACHE", t->cache_path, "fill",
                      1, 0, NULL, 0);

    if (t->conf->manager_mode && c->local_sockaddr != NULL) {
        u_char   addr_buf[NGX_SOCKADDR_STRLEN];
        size_t   addr_len;
        uint16_t self_port;

        addr_len = ngx_sock_ntop(c->local_sockaddr, c->local_socklen,
                                 addr_buf, sizeof(addr_buf) - 1, 0);
        addr_buf[addr_len] = '\0';
        self_port = 0;
        if (c->local_sockaddr->sa_family == AF_INET) {
            self_port = ntohs(
                ((struct sockaddr_in *) c->local_sockaddr)->sin_port);
        } else if (c->local_sockaddr->sa_family == AF_INET6) {
            self_port = ntohs(
                ((struct sockaddr_in6 *) c->local_sockaddr)->sin6_port);
        }
        xrootd_srv_register((const char *) addr_buf, self_port,
                            t->clean_path, 0, 0);
    }

    rc = xrootd_open_resolved_file(ctx, c, t->conf, t->cache_path,
                                   t->options, t->mode_bits, 0, 0);
    if (rc != NGX_OK && ctx->state != XRD_ST_SENDING) {
        xrootd_send_error(ctx, c, kXR_ServerError,
                          "cache open after fill failed");
    }

    xrootd_aio_resume(c);
}

