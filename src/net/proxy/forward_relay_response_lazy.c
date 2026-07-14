#include "proxy_internal.h"
#include "protocols/root/session/registry.h"
#include "protocols/root/protocol/frame_hdr.h"   /* shared kXR_wait seconds parse (libxrdproto) */
#include "core/compat/cstr.h"
#include "forward_relay_response_internal.h"

/*
 * WHAT: Bound-secondary lazy-open relay cluster — handle the synthetic
 *       kXR_open response, translate the upstream fhandle into the reserved
 *       local slot (or free it on failure), chain any further pending lazy
 *       opens, and dispatch the saved read/readv that triggered the open.
 *
 * WHY:  A bound secondary defers its kXR_open until the first read arrives.
 *       When the upstream open completes the proxy must resolve the local↔
 *       upstream fhandle mapping, re-issue the queued request with the
 *       translated handle, and resume the client read loop — all transparently.
 *
 * HOW:  brix_proxy_relay_lazy_open() is invoked from
 *       brix_proxy_relay_to_client() (forward_relay_response.c). It records the
 *       open, releases the response body, drives brix_proxy_lazy_open_next() for
 *       any remaining reserved handles, then brix_proxy_dispatch_saved_read()
 *       to forward the deferred read with fhandle translation applied.
 */

static void
brix_proxy_lazy_release_body(brix_proxy_ctx_t *proxy)
{
    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }
}

static void
brix_proxy_lazy_open_failed(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    ngx_connection_t *c, int local_fh)
{
    if (proxy->saved_req != NULL) {
        ngx_free(proxy->saved_req);
        proxy->saved_req = NULL;
    }

    brix_proxy_lazy_release_body(proxy);
    if (local_fh >= 0 && local_fh < BRIX_MAX_FILES) {
        proxy->fh_map[local_fh].upstream_fh = BRIX_PROXY_FH_FREE;
    }

    proxy->state = XRD_PX_IDLE;
    ctx->state = XRD_ST_REQ_HEADER;
    brix_send_error(ctx, c, kXR_IOError,
                    "proxy: lazy open for bound secondary failed");
    brix_schedule_read_resume(c);
}

static void
brix_proxy_lazy_record_open(brix_proxy_ctx_t *proxy, int local_fh)
{
    int upstream_fh;

    upstream_fh = (proxy->resp_body != NULL && proxy->resp_dlen >= 1)
                  ? (int)(unsigned char) proxy->resp_body[0] : 0;
    if (local_fh >= 0 && local_fh < BRIX_MAX_FILES) {
        proxy->fh_map[local_fh].upstream_fh = upstream_fh;
        proxy->fh_map[local_fh].open_msec = ngx_current_msec;
    }
}

static int
brix_proxy_lazy_open_next(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    ngx_connection_t *c)
{
    int next_fh;
    u_char *rreq;
    size_t rlen;

    if (proxy->lazy_open_pending_count <= 0) {
        return 0;
    }

    proxy->lazy_open_pending_count--;
    next_fh = proxy->lazy_open_pending_fhs[proxy->lazy_open_pending_count];

    rreq = proxy->saved_req;
    rlen = proxy->saved_req_len;
    proxy->saved_req = NULL;
    if (brix_proxy_lazy_open(proxy, ctx, c, next_fh, rreq, rlen) != NGX_OK) {
        /* Error already handled / reported. */
    }
    return 1;
}

static int
brix_proxy_translate_saved_readv(brix_proxy_ctx_t *proxy, u_char *rreq,
    size_t rlen)
{
    u_char *pl = rreq + XRD_REQUEST_HDR_LEN;
    size_t pos = 0;
    size_t pdlen = rlen > XRD_REQUEST_HDR_LEN ? rlen - XRD_REQUEST_HDR_LEN : 0;

    while (pos + 16 <= pdlen) {
        int cfh = (int)(unsigned char) pl[pos];
        if (cfh >= 0 && cfh < BRIX_MAX_FILES
            && proxy->fh_map[cfh].upstream_fh >= 0)
        {
            pl[pos] = (u_char)(unsigned int) proxy->fh_map[cfh].upstream_fh;
        }
        pos += 16;
    }
    return -1;
}

static int
brix_proxy_translate_saved_read(brix_proxy_ctx_t *proxy, u_char *rreq,
    size_t rlen, int local_fh)
{
    uint16_t saved_rid;
    int upstream_fh;

    saved_rid = ntohs(((ClientRequestHdr *)(void *) rreq)->requestid);
    if (saved_rid == kXR_read || saved_rid == kXR_pgread) {
        upstream_fh = (local_fh >= 0 && local_fh < BRIX_MAX_FILES)
                      ? proxy->fh_map[local_fh].upstream_fh : -1;
        if (upstream_fh >= 0) {
            rreq[4] = (u_char)(unsigned int) upstream_fh;
        }
        return local_fh;
    }
    if (saved_rid == kXR_readv) {
        return brix_proxy_translate_saved_readv(proxy, rreq, rlen);
    }
    return local_fh;
}

static void
brix_proxy_prepare_saved_forward(brix_proxy_ctx_t *proxy, u_char *rreq,
    size_t rlen, int local_fh)
{
    ClientRequestHdr *hdr = (ClientRequestHdr *)(void *) rreq;

    proxy->fwd_reqid = ntohs(hdr->requestid);
    proxy->fwd_streamid[0] = hdr->streamid[0];
    proxy->fwd_streamid[1] = hdr->streamid[1];
    proxy->fwd_local_fh = local_fh;
    proxy->fwd_streaming = 0;
    proxy->fwd_payload_len = rlen > XRD_REQUEST_HDR_LEN
                             ? rlen - XRD_REQUEST_HDR_LEN : 0;
    proxy->saved_req = NULL;
}

static void
brix_proxy_save_wait_retry(brix_proxy_ctx_t *proxy, ngx_connection_t *c,
    u_char *rreq, size_t rlen)
{
    if (rlen >= 128 * 1024) {
        return;
    }

    if (proxy->wait_retry_req != NULL) {
        ngx_free(proxy->wait_retry_req);
    }
    proxy->wait_retry_req = ngx_alloc(rlen, c->log);
    if (proxy->wait_retry_req != NULL) {
        ngx_memcpy(proxy->wait_retry_req, rreq, rlen);
        proxy->wait_retry_req_len = rlen;
    } else {
        proxy->wait_retry_req_len = 0;
    }
    proxy->wait_retry_local_fh = proxy->fwd_local_fh;
    proxy->wait_retry_count = 0;
}

static int
brix_proxy_dispatch_saved_read(brix_proxy_ctx_t *proxy, ngx_connection_t *c)
{
    u_char *rreq = proxy->saved_req;
    size_t rlen = proxy->saved_req_len;
    int local_fh = proxy->saved_local_fh;

    if (rreq == NULL) {
        return 0;
    }

    local_fh = brix_proxy_translate_saved_read(proxy, rreq, rlen, local_fh);
    brix_proxy_prepare_saved_forward(proxy, rreq, rlen, local_fh);
    brix_proxy_save_wait_retry(proxy, c, rreq, rlen);

    proxy->wbuf = rreq;
    proxy->wbuf_len = rlen;
    proxy->wbuf_pos = 0;
    proxy->state = XRD_PX_FORWARDING;
    proxy->rhdr_pos = 0;
    proxy->resp_dlen = 0;
    proxy->resp_body = NULL;
    proxy->resp_body_pos = 0;

    if (brix_proxy_flush(proxy) == NGX_ERROR) {
        brix_proxy_abort(proxy,
            "proxy: send deferred read after lazy open failed");
        return 1;
    }
    if (proxy->wbuf_pos < proxy->wbuf_len) {
        return 1;
    }
    if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
        brix_proxy_abort(proxy, "proxy: read arm failed after lazy open read");
    }
    return 1;
}

/* relay upstream response to client */
/* Handle the synthetic kXR_open response for a bound-secondary lazy open:
 * translate the upstream fhandle into the reserved local slot (or free it on
 * failure) and resume the client read loop.  Returns 1 when this was a lazy-
 * open response and the caller must return; 0 otherwise. */
int
brix_proxy_relay_lazy_open(brix_proxy_ctx_t *proxy)
{
    brix_ctx_t *ctx = proxy->client_ctx;
    ngx_connection_t *c = proxy->client_conn;
    int local_fh = proxy->fwd_local_fh;

    if (!proxy->fwd_is_lazy_open) {
        return 0;
    }

    proxy->fwd_is_lazy_open = 0;

    if (proxy->resp_status != kXR_ok) {
        brix_proxy_lazy_open_failed(proxy, ctx, c, local_fh);
        return 1;
    }

    brix_proxy_lazy_record_open(proxy, local_fh);
    brix_proxy_lazy_release_body(proxy);

    if (brix_proxy_lazy_open_next(proxy, ctx, c)) {
        return 1;
    }

    if (brix_proxy_dispatch_saved_read(proxy, c)) {
        return 1;
    }

    proxy->state = XRD_PX_IDLE;
    ctx->state = XRD_ST_REQ_HEADER;
    brix_schedule_read_resume(c);
    return 1;
}
