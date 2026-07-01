/*
 * deliver.c — async SSI delivery primitive. See deliver.h.
 *
 * Builds the same [XrdSsiRRInfoAttn][metadata][data] payload a kXR_query reply
 * carries (ssi_reply), then wraps it in a kXR_attn + kXR_asynresp frame
 * (response/async.c) addressed to the submit's streamid. Event-loop only; the
 * caller owns liveness (registry generation check).
 */

#include "deliver.h"
#include "ssi.h"
#include "ssi_reply.h"
#include "ssi_rrinfo.h"     /* XROOTD_SSI_ATTN_FULL / _PEND / _ALRT */
#include "../response/response.h"
#include "../response/async.h"

/* Build the SSI reply payload (tag + meta + data) into a c->pool buffer and push
 * it as a deferred response (kXR_ok inner status). 0 on success. */
static ngx_int_t
ssi_push_reply(xrootd_ctx_t *ctx, ngx_connection_t *c, xrootd_ssi_req_t *rq,
               char tag, const unsigned char *data, size_t data_len)
{
    size_t   total = xrootd_ssi_reply_len(rq->meta_len, data_len);
    u_char  *buf   = ngx_palloc(c->pool, total);

    if (buf == NULL) {
        return NGX_ERROR;
    }
    xrootd_ssi_reply_build(tag, rq->meta, rq->meta_len, data, data_len, buf);
    return xrootd_send_attn_asynresp(ctx, c, rq->defer_streamid, kXR_ok,
                                     buf, (uint32_t) total);
}

/* Push a terminal kXR_error (err_code + err_text) for the request. */
static ngx_int_t
ssi_push_error(xrootd_ctx_t *ctx, ngx_connection_t *c, xrootd_ssi_req_t *rq)
{
    const char *text = rq->err_text[0] ? rq->err_text : "SSI error";
    size_t      tlen = ngx_strlen(text);
    uint32_t    code = htonl((uint32_t) (rq->err_code ? rq->err_code
                                                      : kXR_ServerError));
    size_t      bodylen = 4 + tlen + 1;        /* errnum(BE) + text + NUL */
    u_char     *body = ngx_palloc(c->pool, bodylen);

    if (body == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(body, &code, 4);
    ngx_memcpy(body + 4, text, tlen);
    body[4 + tlen] = '\0';
    return xrootd_send_attn_asynresp(ctx, c, rq->defer_streamid, kXR_error,
                                     body, (uint32_t) bodylen);
}

void
xrootd_ssi_deliver(xrootd_ctx_t *ctx, ngx_connection_t *c,
                   xrootd_ssi_session_t *s, uint32_t req_id,
                   xrootd_ssi_dlv_kind kind)
{
    xrootd_ssi_req_t *rq = xrootd_ssi_session_req(s, req_id, 0);
    ngx_int_t         rc = NGX_ERROR;

    if (rq == NULL) {
        return;   /* reqId slot gone (cancelled/closed) — drop the late delivery */
    }

    switch (kind) {
    case SSI_DLV_RESPONSE:
        rc = ssi_push_reply(ctx, c, rq, XROOTD_SSI_ATTN_FULL,
                            rq->resp.data, rq->resp.len);
        break;
    case SSI_DLV_PEND:
        rc = ssi_push_reply(ctx, c, rq, XROOTD_SSI_ATTN_PEND, NULL, 0);
        break;
    case SSI_DLV_ERROR:
        rc = ssi_push_error(ctx, c, rq);
        XROOTD_SRV_METRIC_INC(ctx, ssi_errors_total);
        break;
    }
    if (rc != NGX_OK) {
        XROOTD_SRV_METRIC_INC(ctx, ssi_attn_push_failures_total);
    }
}

void
xrootd_ssi_deliver_alert(xrootd_ctx_t *ctx, ngx_connection_t *c,
                         xrootd_ssi_req_t *rq,
                         const unsigned char *buf, size_t len)
{
    size_t   total = xrootd_ssi_reply_len(0, len);
    u_char  *out   = ngx_palloc(c->pool, total);

    if (out == NULL) {
        return;
    }
    /* alrtResp '!' with the alert bytes as data; no metadata. The client keeps
     * waiting for the request's actual response after handling the alert. */
    xrootd_ssi_reply_build(XROOTD_SSI_ATTN_ALRT, NULL, 0, buf, len, out);
    if (xrootd_send_attn_asynresp(ctx, c, rq->defer_streamid, kXR_ok,
                                  out, (uint32_t) total) == NGX_OK) {
        XROOTD_SRV_METRIC_INC(ctx, ssi_alerts_pushed_total);
    } else {
        XROOTD_SRV_METRIC_INC(ctx, ssi_attn_push_failures_total);
    }
}
