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
#include "provider.h"
#include "session.h"
#include "registry.h"
#include "deliver.h"
#include "svc_cta/cta_service.h"
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

/*
 * Responder state. The synchronous/submit phase fills only `rq` (ctx/c NULL, so
 * alerts drop — there is no push channel yet). The completion phase (driven from
 * the deferral timer) also carries ctx/c, so alerts are pushed live.
 */
typedef struct {
    xrootd_ssi_req_t  *rq;
    xrootd_ctx_t      *ctx;   /* non-NULL only when a push channel exists */
    ngx_connection_t  *c;
} ssi_resp_state_t;

static void
ssi_resp_set_metadata(xrootd_ssi_responder_t *r, const unsigned char *md,
                      size_t len)
{
    xrootd_ssi_req_t *rq = ((ssi_resp_state_t *) r->state)->rq;

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
    xrootd_ssi_req_t *rq = ((ssi_resp_state_t *) r->state)->rq;

    /* A non-final chunk marks the response as streamed: it is delivered to the
     * client via kXR_read pulls (pendResp) rather than inline in the reply. */
    if (!last) {
        rq->streaming = 1;
    }
    {
        size_t cap = rq->response_max > 0 ? rq->response_max : XROOTD_SSI_RESP_MAX;
        if (xrootd_ssi_respbuf_append(&rq->resp, buf, len, cap) != 0) {
            rq->error = 1;
            rq->err_code = kXR_NoMemory;
            return;
        }
    }
    rq->responded = 1;
}

static void
ssi_resp_alert(xrootd_ssi_responder_t *r, const unsigned char *buf, size_t len)
{
    ssi_resp_state_t *st = r->state;

    /* Deliverable only when a push channel exists (the deferred completion phase)
     * and the client is awaiting a pushed response. The synchronous core has no
     * out-of-band channel, so it drops alerts (Phase-1 behaviour). */
    if (st->ctx != NULL && st->rq->waiting) {
        xrootd_ssi_deliver_alert(st->ctx, st->c, st->rq, buf, len);
    }
}

static void
ssi_resp_error(xrootd_ssi_responder_t *r, int code, const char *text)
{
    xrootd_ssi_req_t *rq = ((ssi_resp_state_t *) r->state)->rq;

    rq->error = 1;
    /* The service reports a POSIX errno (XrdSsi eNum); map it to a kXR code. */
    rq->err_code = code ? (int) xrootd_kxr_from_errno(code) : kXR_ServerError;
    if (text != NULL) {
        ngx_cpystrn((u_char *) rq->err_text, (u_char *) text,
                    sizeof(rq->err_text));
    }
    rq->responded = 1;
}

/* Submit-phase defer: accept the deferral (the write hook will arm the async
 * completion and reply kXR_waitresp). */
static int
ssi_resp_defer_accept(xrootd_ssi_responder_t *r)
{
    ((ssi_resp_state_t *) r->state)->rq->deferred = 1;
    return 0;
}

/* Completion-phase defer: refuse, so a re-invoked service responds inline. */
static int
ssi_resp_defer_refuse(xrootd_ssi_responder_t *r)
{
    (void) r;
    return -1;
}

static void **
ssi_resp_svc_slot(xrootd_ssi_responder_t *r)
{
    return &((ssi_resp_state_t *) r->state)->rq->svc_state;
}

static void
ssi_responder_init(xrootd_ssi_responder_t *r, ssi_resp_state_t *st,
                   int (*defer)(xrootd_ssi_responder_t *))
{
    r->set_metadata = ssi_resp_set_metadata;
    r->set_response = ssi_resp_set_response;
    r->alert        = ssi_resp_alert;
    r->error        = ssi_resp_error;
    r->defer        = defer;
    r->svc_slot     = ssi_resp_svc_slot;
    r->state        = st;
}

/* Run the resolved service over the accumulated request (submit phase). The
 * service may answer inline or call r->defer to be completed later. */
static void
ssi_dispatch(xrootd_ssi_req_t *rq, xrootd_ssi_process_fn process)
{
    xrootd_ssi_responder_t r;
    ssi_resp_state_t       st = { rq, NULL, NULL };

    ssi_responder_init(&r, &st, ssi_resp_defer_accept);

    rq->dispatched = 1;
    if (process(rq->req, rq->req_len, &r) != 0 && !rq->responded) {
        rq->error = 1;
        rq->err_code = kXR_ServerError;
        rq->responded = 1;
    }
}

/* Re-invoke a deferred service to produce its response now (completion phase):
 * defer is refused (so the service answers inline) and ctx/c are present (so the
 * service's alerts are pushed live before the terminal response). */
static void
ssi_complete_deferred(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      xrootd_ssi_session_t *sess, xrootd_ssi_req_t *rq)
{
    xrootd_ssi_responder_t r;
    ssi_resp_state_t       st = { rq, ctx, c };

    ssi_responder_init(&r, &st, ssi_resp_defer_refuse);
    if (sess->provider.process(rq->req, rq->req_len, &r) != 0 && !rq->responded) {
        rq->error = 1;
        rq->err_code = kXR_ServerError;
        rq->responded = 1;
    }
}

/* ------------------------------------------------------------------ */
/* Async deferral: an event-loop timer drives the deferred completion. */
/* ------------------------------------------------------------------ */

/*
 * The timer state is heap-allocated (NOT pool-allocated) so it has an independent
 * lifetime: handle teardown cancels it (ngx_del_timer + free) before the
 * connection pool dies, and the timer handler frees it on fire. It carries the
 * session key + generation (never a raw session pointer) so the handler resolves
 * a LIVE session through the registry — the use-after-free guard.
 */
typedef struct {
    ngx_event_t        timer;
    xrootd_ctx_t      *ctx;
    ngx_connection_t  *c;
    uintptr_t          session_key;
    uint64_t           generation;
    uint32_t           req_id;
} ssi_defer_t;

static void
ssi_defer_cancel(void *p)
{
    ssi_defer_t *d = p;

    if (d == NULL) {
        return;
    }
    if (d->timer.timer_set) {
        ngx_del_timer(&d->timer);
    }
    ngx_free(d);
}

static void
ssi_defer_timer_handler(ngx_event_t *ev)
{
    ssi_defer_t          *d = ev->data;
    xrootd_ssi_session_t *s;
    xrootd_ssi_req_t     *rq;

    /* Liveness gate: a NULL find means the session/connection is gone (teardown
     * removed it). Do not touch ctx/c in that case. */
    s = xrootd_ssi_registry_find(d->session_key, d->generation);
    if (s != NULL) {
        rq = xrootd_ssi_session_req(s, d->req_id, 0);
        if (rq != NULL && !rq->responded) {
            xrootd_ssi_dlv_kind kind;

            rq->defer_ctx = NULL;   /* consume the timer before delivering */
            ssi_complete_deferred(d->ctx, d->c, s, rq);
            /* A streamed response is signalled PEND (client pulls the body via
             * kXR_read); a unary response is pushed inline; an error is terminal. */
            kind = rq->error     ? SSI_DLV_ERROR
                 : rq->streaming ? SSI_DLV_PEND
                                 : SSI_DLV_RESPONSE;
            xrootd_ssi_deliver(d->ctx, d->c, s, d->req_id, kind);
        } else if (rq != NULL) {
            rq->defer_ctx = NULL;
        }
    }
    ngx_free(d);
}

static ngx_int_t
ssi_defer_arm(xrootd_ctx_t *ctx, ngx_connection_t *c,
              xrootd_ssi_session_t *sess, xrootd_ssi_req_t *rq)
{
    ssi_defer_t *d = ngx_alloc(sizeof(*d), c->log);

    if (d == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(&d->timer, sizeof(d->timer));
    d->timer.handler = ssi_defer_timer_handler;
    d->timer.data    = d;
    d->timer.log     = c->log;
    d->ctx           = ctx;
    d->c             = c;
    d->session_key   = sess->conn_id;
    d->generation    = sess->generation;
    d->req_id        = rq->req_id;
    rq->defer_ctx    = d;
    ngx_add_timer(&d->timer, 10);   /* 10ms — proves the push without stalling */
    return NGX_OK;
}

/*
 * Teardown hook (called from xrootd_free_fhandle before the .ssi slot is cleared,
 * on both kXR_close and connection disconnect): cancel any armed deferral timers
 * and unregister the session, so no async completion can run against freed memory.
 */
void
xrootd_ssi_handle_cleanup(void *ssi_session)
{
    xrootd_ssi_session_t *sess = ssi_session;
    int                   i;

    if (sess == NULL) {
        return;
    }
    for (i = 0; i < XROOTD_SSI_MAX_INFLIGHT; i++) {
        if (sess->rr[i].in_use && sess->rr[i].defer_ctx != NULL) {
            ssi_defer_cancel(sess->rr[i].defer_ctx);
            sess->rr[i].defer_ctx = NULL;
        }
    }
    xrootd_ssi_registry_remove(sess->conn_id);
}

ngx_int_t
xrootd_ssi_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
                const char *service, size_t service_len, uint16_t options)
{
    ngx_connection_t      *conn = c;
    xrootd_ssi_session_t  *sess;
    xrootd_ssi_provider_t  prov;
    char                   svc[64];
    int                    idx, devnull;
    ServerOpenBody         body;
    size_t                 total, bodylen;
    u_char                *buf;
    char                   statbuf[128];
    int                    want_stat = (options & kXR_retstat) ? 1 : 0;

    ngx_stream_xrootd_srv_conf_t *conf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);
    int is_cta;

    ngx_memcpy(svc, service, service_len);
    svc[service_len] = '\0';

    if (!xrootd_ssi_provider_lookup(svc, &prov)) {
        return xrootd_send_error(ctx, c, kXR_NotFound, "unknown SSI service");
    }

    /* The CTA tape service exposes a storage-control surface — gate it behind
     * `xrootd_ssi_service cta;`. When enabled, push the config down to the
     * service (journal + executor backend). */
    is_cta = (ngx_strcmp(svc, "cta") == 0);
    if (is_cta) {
        if (conf == NULL || !conf->ssi_cta_enable) {
            return xrootd_send_error(ctx, c, kXR_NotFound, "unknown SSI service");
        }
        {
            char jbuf[1024];
            size_t jlen = conf->ssi_cta_journal.len;
            if (jlen >= sizeof(jbuf)) {
                jlen = sizeof(jbuf) - 1;
            }
            ngx_memcpy(jbuf, conf->ssi_cta_journal.data, jlen);
            jbuf[jlen] = '\0';
            xrootd_ssi_cta_configure(jbuf, conf->ssi_cta_executor == 1);
        }
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

    sess = xrootd_ssi_session_create(conn->pool, service, service_len, &prov);
    if (sess == NULL) {
        close(devnull);
        xrootd_free_fhandle(ctx, idx);
        return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi alloc");
    }
    /* Key the registry by the session's own address (unique per live session)
     * so async completions resolve THIS session, not whichever handle shares the
     * connection. The generation check catches a recycled address. */
    sess->conn_id = (uintptr_t) sess;
    if (conf != NULL) {
        sess->max_inflight = (int) conf->ssi_max_inflight;
        sess->request_max  = conf->ssi_request_max;
        sess->response_max = conf->ssi_response_max;
    }
    xrootd_ssi_registry_add(sess->conn_id, sess);

    ctx->files[idx].fd         = devnull;
    ctx->files[idx].ssi        = sess;     /* now a session, not a req */
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
    xrootd_ssi_session_t *sess = ctx->files[idx].ssi;
    xrootd_ssi_req_t     *rq;
    int                   cmd;
    uint32_t              id, size;
    size_t                n = ctx->cur_dlen;

    xrootd_ssi_rrinfo_decode(off8, &cmd, &id, &size);

    if (cmd == XROOTD_SSI_CMD_CAN) {
        xrootd_ssi_session_drop(sess, id);    /* request-phase cancel */
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    rq = xrootd_ssi_session_req(sess, id, 1);
    if (rq == NULL) {
        return xrootd_send_error(ctx, c, kXR_Overloaded,
                                 "too many concurrent SSI requests");
    }
    if (rq->dispatched) {
        return xrootd_send_error(ctx, c, kXR_FileLocked,
                                 "SSI request already dispatched");
    }

    if (!rq->have_size) {
        rq->req_expected = size;
        rq->have_size = 1;
    }

    if (n > 0) {
        /* request cap: the configured limit, never above the compile-time hard
         * ceiling (the request buffer is sized to that ceiling). */
        size_t reqcap = (sess->request_max > 0 &&
                         sess->request_max < XROOTD_SSI_REQ_MAX)
                      ? sess->request_max : XROOTD_SSI_REQ_MAX;
        if (rq->req_len + n > reqcap) {
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
        ssi_dispatch(rq, sess->provider.process);
        XROOTD_SRV_METRIC_INC(ctx, ssi_requests_total);

        /* Deferred service: capture the submit streamid, arm the async
         * completion, and ack with kXR_waitresp — the response is pushed later
         * via kXR_attn (xrootd_ssi_deliver). */
        if (rq->deferred && !rq->responded) {
            ngx_memcpy(rq->defer_streamid, ctx->cur_streamid,
                       sizeof(rq->defer_streamid));
            rq->waiting = 1;
            if (ssi_defer_arm(ctx, c, sess, rq) != NGX_OK) {
                return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi defer");
            }
            return xrootd_send_waitresp(ctx, c);
        }
    }

    return xrootd_send_ok(ctx, c, NULL, 0);
}

ngx_int_t
xrootd_ssi_query(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                 const unsigned char *body, size_t body_len)
{
    xrootd_ssi_session_t *sess = ctx->files[idx].ssi;
    xrootd_ssi_req_t     *rq;
    int                   cmd;
    uint32_t              id, size;
    u_char               *buf;
    size_t                total;

    if (body_len < XROOTD_SSI_RRINFO_LEN) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "short SSI control");
    }
    xrootd_ssi_rrinfo_decode(body, &cmd, &id, &size);

    if (cmd == XROOTD_SSI_CMD_CAN) {
        xrootd_ssi_session_drop(sess, id);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    /* response-wait (Rwt). For the synchronous core the response is ready once
     * the request write completed; if the reqId is unknown or no response is
     * pending yet, treat as a protocol error. */
    rq = xrootd_ssi_session_req(sess, id, 0);
    if (rq == NULL || !rq->responded) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "no SSI response pending");
    }

    if (rq->error) {
        XROOTD_SRV_METRIC_INC(ctx, ssi_errors_total);
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

    total = xrootd_ssi_reply_len(rq->meta_len, rq->resp.len);
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi reply");
    }
    xrootd_ssi_reply_build(XROOTD_SSI_ATTN_FULL, rq->meta, rq->meta_len,
                           rq->resp.data, rq->resp.len, buf);
    return xrootd_send_ok(ctx, c, buf, total);
}

ngx_int_t
xrootd_ssi_read(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                uint64_t offset, uint32_t rlen)
{
    xrootd_ssi_session_t *sess = ctx->files[idx].ssi;
    xrootd_ssi_req_t     *rq;
    unsigned char         off8[8];
    int                   cmd;
    uint32_t              id, size;
    size_t                avail, n;

    /* The SSI read offset field is a big-endian XrdSsiRRInfo; re-serialize the
     * decoded 64-bit offset back to its 8 wire bytes and decode the reqId. */
    off8[0] = (u_char) (offset >> 56); off8[1] = (u_char) (offset >> 48);
    off8[2] = (u_char) (offset >> 40); off8[3] = (u_char) (offset >> 32);
    off8[4] = (u_char) (offset >> 24); off8[5] = (u_char) (offset >> 16);
    off8[6] = (u_char) (offset >> 8);  off8[7] = (u_char) (offset);
    xrootd_ssi_rrinfo_decode(off8, &cmd, &id, &size);

    rq = xrootd_ssi_session_req(sess, id, 0);
    if (rq == NULL) {
        return xrootd_send_ok(ctx, c, NULL, 0);   /* unknown reqId → nothing */
    }

    /* Write-until-read protocol: a request never given an explicit size is
     * dispatched on its first read (the writes have all accumulated by now). */
    if (!rq->dispatched) {
        ssi_dispatch(rq, sess->provider.process);
        XROOTD_SRV_METRIC_INC(ctx, ssi_requests_total);
    }

    if (!rq->responded || rq->error) {
        return xrootd_send_ok(ctx, c, NULL, 0);   /* nothing to stream */
    }
    if (rq->read_cursor >= rq->resp.len) {
        return xrootd_send_ok(ctx, c, NULL, 0);   /* EOF */
    }
    avail = rq->resp.len - rq->read_cursor;
    n = (rlen < avail) ? rlen : avail;
    {
        u_char *p = rq->resp.data + rq->read_cursor;
        rq->read_cursor += n;
        return xrootd_send_ok(ctx, c, p, n);
    }
}
