#include "cache_internal.h"
#include "cache_storage.h"   /* driver-aware readiness for a backend-backed cache */
#include "net/manager/registry.h"


#include <netinet/in.h>
#include <unistd.h>

/* brix_cache_fill_thread — thread-pool worker running the full fill lifecycle:
 * ensure parent dir → evict if over threshold → acquire the per-file lock → skip if
 * already ready → fetch origin → release the lock on exit. No response (the done
 * callback resumes the client). */
void
brix_cache_fill_thread(void *data, ngx_log_t *log)
{
    brix_cache_fill_t *t;
    int                 owned;

    t = data;
    owned = 0;
    (void) log;

    t->result = NGX_OK;
    t->xrd_error = 0;
    t->sys_errno = 0;
    t->err_msg[0] = '\0';

    if (brix_cache_ensure_parent(t->cache_path) != 0) {
        brix_cache_set_syserror(t, kXR_IOError,
                                  "cache parent mkdir failed");
        return;
    }

    brix_cache_evict_if_needed(t, t->cache_path, log);

    if (brix_cache_wait_or_lock(t, &owned) != 0) {
        return;
    }

    if (!owned) {
        return;
    }

    if (brix_cache_ready(t->conf, t->cache_path) == 1) {
        unlink(t->lock_path);
        return;
    }

    if (brix_cache_fetch_origin(t) != 0) {
        /* -1 = fill error (t->result + t->err_msg set by fetch)
         *  1 = admission declined (t->result = NGX_DECLINED)
         * Both paths: release the lock and let the done callback handle it. */
        unlink(t->lock_path);
        return;
    }

    brix_cache_evict_if_needed(t, t->cache_path, log);

    unlink(t->lock_path);
}

/* brix_cache_fill_done — completion callback (event loop) when the fill worker
 * finishes: restore the request context, then dispatch on the result — NGX_DECLINED
 * redirects to origin (admission rejected), error sends kXR_error, success opens the
 * cached file — and resume the client via ngx_stream_brix_recv(). */
void
brix_cache_fill_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task;
    brix_cache_fill_t *t;
    brix_ctx_t      *ctx;
    ngx_connection_t  *c;
    ngx_int_t          rc;

    task = ev->data;
    t = task->ctx;
    ctx = t->ctx;
    c = t->c;

    if (!brix_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    /*
     * Admission declined: the file was too large and didn't match the include
     * regex.  Redirect the client to the origin so it fetches the file directly
     * without going through the cache layer at all.
     */
    if (t->result == NGX_DECLINED) {
        brix_log_access(ctx, c, "OPEN", t->clean_path, "cache-bypass",
                          0, 0,
                          "cache admission rejected; redirecting to origin", 0);
        if (t->conf->cache_origin_host.len > 0) {
            brix_send_redirect(ctx, c,
                                 (const char *) t->conf->cache_origin_host.data,
                                 t->conf->cache_origin_port);
        } else {
            BRIX_OP_ERR(ctx, BRIX_OP_OPEN_RD);
            brix_send_error(ctx, c, kXR_Unsupported,
                              "file too large to cache and no origin configured "
                              "for redirect");
        }
        brix_aio_resume(c);
        return;
    }

    if (t->result != NGX_OK) {
        int err;

        err = t->xrd_error ? t->xrd_error : kXR_ServerError;
        brix_log_access(ctx, c, "OPEN", t->clean_path, "cache-fill",
                          0, (uint16_t) err,
                          t->err_msg[0] ? t->err_msg : "cache fill failed",
                          0);
        BRIX_OP_ERR(ctx, BRIX_OP_OPEN_RD);
        brix_send_error(ctx, c, (uint16_t) err,
                          t->err_msg[0] ? t->err_msg : "cache fill failed");
        brix_aio_resume(c);
        return;
    }

    brix_log_access(ctx, c, "CACHE", t->cache_path, "fill",
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
        brix_srv_register((const char *) addr_buf, self_port,
                            t->clean_path, 0, 0);
    }

    brix_open_request_t oreq = {
        .resolved  = t->cache_path,
        .options   = t->options,
        .mode_bits = t->mode_bits,
        .is_write  = 0,
        .codec     = 0,
    };
    rc = brix_open_resolved_file(ctx, c, t->conf, &oreq);
    if (rc != NGX_OK && ctx->state != XRD_ST_SENDING) {
        brix_send_error(ctx, c, kXR_ServerError,
                          "cache open after fill failed");
    }

    brix_aio_resume(c);
}

