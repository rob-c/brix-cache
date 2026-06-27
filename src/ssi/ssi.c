/*
 * ssi.c — byte-exact XrdSsi-over-xroot engine glue (§7). See ssi.h.
 *
 * The open/write/query/read hooks are clean early-returns keyed on
 * ctx->files[idx].ssi, so the normal data path is unchanged for non-SSI handles.
 * Wire decode/encode lives in ssi_rrinfo (golden-validated) and ssi_reply; the
 * service dispatch uses the native responder interface in ssi_service.
 */

#include "../ngx_xrootd_module.h"   /* master header: ngx + tunables + config + types */
#include "ssi.h"
#include "ssi_rrinfo.h"
#include "ssi_reply.h"
#include "ssi_service.h"
#include "../connection/fd_table.h"
#include "../response/response.h"
#include "../compat/error_mapping.h"   /* xrootd_kxr_from_errno */
#include "../protocol/opcodes.h"
#include "../protocol/wire_core_requests.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int
xrootd_ssi_match(ngx_stream_xrootd_srv_conf_t *conf, const char *path,
                 const char **service, size_t *service_len)
{
    const char *svc;
    size_t      n;

    if (conf == NULL || !conf->ssi_enable || path == NULL) {
        return 0;
    }
    if (ngx_strncmp(path, XROOTD_SSI_PREFIX, XROOTD_SSI_PREFIX_LEN) != 0) {
        return 0;
    }
    svc = path + XROOTD_SSI_PREFIX_LEN;
    n = 0;
    while (svc[n] != '\0' && svc[n] != '/' && svc[n] != '?') {
        n++;
    }
    if (n == 0 || n >= 64) {
        return 0;
    }
    *service     = svc;
    *service_len = n;
    return 1;
}

/* synchronous responder: fills the session response/metadata buffers */
static void
ssi_resp_set_metadata(xrootd_ssi_responder_t *r, const unsigned char *md,
                      size_t len)
{
    xrootd_ssi_req_t *rq = r->state;

    if (len > XROOTD_SSI_META_MAX) {
        len = XROOTD_SSI_META_MAX;
    }
    if (rq->meta == NULL) {
        rq->meta = ngx_palloc(rq->pool, XROOTD_SSI_META_MAX);
        if (rq->meta == NULL) {
            return;
        }
    }
    ngx_memcpy(rq->meta, md, len);
    rq->meta_len = len;
}

static void
ssi_resp_set_response(xrootd_ssi_responder_t *r, const unsigned char *buf,
                      size_t len, int last)
{
    xrootd_ssi_req_t *rq = r->state;

    /* A non-final chunk marks the response as streamed: it is delivered to the
     * client via kXR_read pulls (pendResp) rather than inline in the reply. */
    if (!last) {
        rq->streaming = 1;
    }
    if (rq->resp == NULL) {
        rq->resp = ngx_palloc(rq->pool, XROOTD_SSI_RESP_MAX);
        if (rq->resp == NULL) {
            rq->error = 1;
            rq->err_code = kXR_NoMemory;
            return;
        }
    }
    if (rq->resp_len + len > XROOTD_SSI_RESP_MAX) {
        len = XROOTD_SSI_RESP_MAX - rq->resp_len;
    }
    if (len > 0) {
        ngx_memcpy(rq->resp + rq->resp_len, buf, len);
        rq->resp_len += len;
    }
    rq->responded = 1;
}

static void
ssi_resp_alert(xrootd_ssi_responder_t *r, const unsigned char *buf, size_t len)
{
    /* Alerts are an async/streaming feature; the synchronous core drops them. */
    (void) r;
    (void) buf;
    (void) len;
}

static void
ssi_resp_error(xrootd_ssi_responder_t *r, int code, const char *text)
{
    xrootd_ssi_req_t *rq = r->state;

    rq->error = 1;
    /* The service reports a POSIX errno (XrdSsi eNum); map it to a kXR code. */
    rq->err_code = code ? (int) xrootd_kxr_from_errno(code) : kXR_ServerError;
    if (text != NULL) {
        ngx_cpystrn((u_char *) rq->err_text, (u_char *) text,
                    sizeof(rq->err_text));
    }
    rq->responded = 1;
}

/* Run the resolved service over the accumulated request (synchronous path). */
static void
ssi_dispatch(xrootd_ssi_req_t *rq)
{
    xrootd_ssi_responder_t r;

    r.set_metadata = ssi_resp_set_metadata;
    r.set_response = ssi_resp_set_response;
    r.alert        = ssi_resp_alert;
    r.error        = ssi_resp_error;
    r.state        = rq;

    rq->dispatched = 1;
    if (rq->handler(rq->req, rq->req_len, &r) != 0 && !rq->responded) {
        rq->error = 1;
        rq->err_code = kXR_ServerError;
        rq->responded = 1;
    }
}

ngx_int_t
xrootd_ssi_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
                const char *service, size_t service_len, uint16_t options)
{
    ngx_connection_t      *conn = c;
    xrootd_ssi_req_t      *rq;
    xrootd_ssi_process_fn  handler;
    char                   svc[64];
    int                    idx, devnull;
    ServerOpenBody         body;
    size_t                 total, bodylen;
    u_char                *buf;
    char                   statbuf[128];
    int                    want_stat = (options & kXR_retstat) ? 1 : 0;

    ngx_memcpy(svc, service, service_len);
    svc[service_len] = '\0';

    handler = xrootd_ssi_service_lookup(svc);
    if (handler == NULL) {
        return xrootd_send_error(ctx, c, kXR_NotFound, "unknown SSI service");
    }

    idx = xrootd_alloc_fhandle(ctx);
    if (idx < 0) {
        return xrootd_send_error(ctx, c, kXR_ServerError, "too many open files");
    }

    /* A real (harmless) fd keeps the slot "in use" so close()/free work via the
     * normal path; all I/O is intercepted on ctx->files[idx].ssi first. */
    devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (devnull < 0) {
        xrootd_free_fhandle(ctx, idx);
        return xrootd_send_error(ctx, c, kXR_ServerError, "ssi open");
    }

    rq = ngx_pcalloc(conn->pool, sizeof(*rq));
    if (rq == NULL) {
        close(devnull);
        xrootd_free_fhandle(ctx, idx);
        return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi alloc");
    }
    ngx_memcpy(rq->service, service, service_len);
    rq->service[service_len] = '\0';
    rq->handler = handler;
    rq->pool    = conn->pool;

    ctx->files[idx].fd         = devnull;
    ctx->files[idx].ssi        = rq;
    ctx->files[idx].readable   = 1;
    ctx->files[idx].writable   = 1;
    ctx->files[idx].is_regular = 0;

    /*
     * The libXrdSsi client opens the resource with kXR_retstat and refuses the
     * reply unless a StatInfo string follows the 12-byte ServerOpenBody. For the
     * virtual SSI resource we synthesize a plausible stat: id 0, size 0,
     * read+write flags, mtime now — matching the open-path "id size flags mtime"
     * format (open_resolved_file.c).
     */
    ngx_memzero(&body, sizeof(body));
    body.fhandle[0] = (u_char) idx;
    bodylen = sizeof(ServerOpenBody);

    statbuf[0] = '\0';
    if (want_stat) {
        ngx_snprintf((u_char *) statbuf, sizeof(statbuf), "%d %d %d %T%Z",
                     0, 0, kXR_readable | kXR_writable, ngx_time());
        bodylen += ngx_strlen(statbuf) + 1;
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    buf   = ngx_palloc(conn->pool, total);
    if (buf == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi resp");
    }
    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, (uint32_t) bodylen,
                          (ServerResponseHdr *) buf);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(ServerOpenBody));
    if (want_stat) {
        size_t slen = ngx_strlen(statbuf) + 1;
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                   statbuf, slen);
    }

    return xrootd_queue_response(ctx, c, buf, total);
}

ngx_int_t
xrootd_ssi_write(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                 const unsigned char off8[8])
{
    xrootd_ssi_req_t *rq = ctx->files[idx].ssi;
    int               cmd;
    uint32_t          id, size;
    size_t            n = ctx->cur_dlen;

    xrootd_ssi_rrinfo_decode(off8, &cmd, &id, &size);

    if (cmd == XROOTD_SSI_CMD_CAN) {
        /* request-phase cancel: reset accumulation */
        rq->req_len = 0;
        rq->dispatched = 0;
        rq->responded = 0;
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    if (rq->dispatched) {
        return xrootd_send_error(ctx, c, kXR_FileLocked,
                                 "SSI request already dispatched");
    }

    if (!rq->have_size) {
        rq->req_id = id;
        rq->req_expected = size;
        rq->have_size = 1;
    }

    if (n > 0) {
        if (rq->req_len + n > XROOTD_SSI_REQ_MAX) {
            return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                     "SSI request too large");
        }
        if (rq->req == NULL) {
            rq->req = ngx_palloc(c->pool, XROOTD_SSI_REQ_MAX);
            if (rq->req == NULL) {
                return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi req buf");
            }
        }
        if (ctx->payload != NULL) {
            ngx_memcpy(rq->req + rq->req_len, ctx->payload, n);
            rq->req_len += n;
        }
    }

    /* When the client declared a total request size (req_expected > 0), dispatch
     * as soon as that many bytes have accumulated. When no size was given
     * (req_expected == 0 — the simple write-until-read protocol), DEFER dispatch
     * to the first read so several writes accumulate into one request instead of
     * the first write firing it prematurely (which then rejected every following
     * write as "already dispatched"). */
    if (rq->req_expected > 0 && rq->req_len >= rq->req_expected) {
        ssi_dispatch(rq);
    }

    return xrootd_send_ok(ctx, c, NULL, 0);
}

ngx_int_t
xrootd_ssi_query(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                 const unsigned char *body, size_t body_len)
{
    xrootd_ssi_req_t *rq = ctx->files[idx].ssi;
    int               cmd;
    uint32_t          id, size;
    u_char           *buf;
    size_t            total;

    if (body_len < XROOTD_SSI_RRINFO_LEN) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "short SSI control");
    }
    xrootd_ssi_rrinfo_decode(body, &cmd, &id, &size);

    if (cmd == XROOTD_SSI_CMD_CAN) {
        rq->req_len = 0;
        rq->resp_len = 0;
        rq->read_cursor = 0;
        rq->dispatched = 0;
        rq->responded = 0;
        rq->error = 0;
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    /* response-wait (Rwt). For the synchronous core the response is ready once
     * the request write completed; if not, treat as a protocol error. */
    if (!rq->responded) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "no SSI response pending");
    }

    if (rq->error) {
        return xrootd_send_error(ctx, c,
                                 rq->err_code ? rq->err_code : kXR_ServerError,
                                 rq->err_text[0] ? rq->err_text : "SSI error");
    }

    /*
     * Streaming response: reply pendResp with metadata only (no inline data);
     * the client pulls the body via kXR_read (GetResp maps pendResp -> isStream).
     * Unary response: reply fullResp with the data inline.
     */
    if (rq->streaming) {
        total = xrootd_ssi_reply_len(rq->meta_len, 0);
        buf = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi reply");
        }
        xrootd_ssi_reply_build(XROOTD_SSI_ATTN_PEND, rq->meta, rq->meta_len,
                               NULL, 0, buf);
        return xrootd_send_ok(ctx, c, buf, total);
    }

    total = xrootd_ssi_reply_len(rq->meta_len, rq->resp_len);
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi reply");
    }
    xrootd_ssi_reply_build(XROOTD_SSI_ATTN_FULL, rq->meta, rq->meta_len,
                           rq->resp, rq->resp_len, buf);
    return xrootd_send_ok(ctx, c, buf, total);
}

ngx_int_t
xrootd_ssi_read(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                uint64_t offset, uint32_t rlen)
{
    xrootd_ssi_req_t *rq = ctx->files[idx].ssi;
    size_t            avail, n;

    (void) offset;   /* SSI read offset carries an RRInfo, not a byte position */

    /* Write-until-read protocol: a request never given an explicit size is
     * dispatched on its first read (the writes have all accumulated by now). */
    if (!rq->dispatched) {
        ssi_dispatch(rq);
    }

    if (!rq->responded || rq->error) {
        return xrootd_send_ok(ctx, c, NULL, 0);   /* nothing to stream */
    }
    if (rq->read_cursor >= rq->resp_len) {
        return xrootd_send_ok(ctx, c, NULL, 0);   /* EOF */
    }
    avail = rq->resp_len - rq->read_cursor;
    n = (rlen < avail) ? rlen : avail;
    {
        u_char *p = rq->resp + rq->read_cursor;
        rq->read_cursor += n;
        return xrootd_send_ok(ctx, c, p, n);
    }
}
