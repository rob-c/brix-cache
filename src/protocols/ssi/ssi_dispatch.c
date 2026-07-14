/*
 * ssi_dispatch.c — SSI request dispatch, async deferral, and the kXR_write
 * accumulation path (split from ssi.c, phase-79). See ssi.h / ssi_internal.h.
 *
 * WHAT: The write side of the byte-exact XrdSsi-over-xroot engine glue. A
 *       kXR_write accumulates a request (ssi_write_accumulate) and, once the
 *       request is complete, dispatches it through a native responder
 *       (brix_ssi_dispatch) to the resolved service. A service may answer inline
 *       or defer; deferred completions are driven off an event-loop timer
 *       (ssi_defer_*) that resolves a LIVE session through the registry before
 *       delivering the pushed response.
 * WHY:  ssi.c held both the client-facing reply side (open/query/read) and this
 *       write/dispatch side in one 725-line file. Isolating the dispatch +
 *       deferral + write machinery here keeps each half focused and under the
 *       500-line cap without changing a single byte of wire behaviour.
 * HOW:  The responder callbacks fill brix_ssi_req_t; brix_ssi_dispatch runs the
 *       submit phase (defer accepted), ssi_complete_deferred the completion phase
 *       (defer refused, alerts pushed). The heap-allocated ssi_defer_t carries a
 *       session key + generation (never a raw pointer) so a fired timer never
 *       touches freed memory. brix_ssi_write coalesces writes into one request and
 *       arms the deferral, replying kXR_waitresp for deferred services.
 */

#include "core/ngx_brix_module.h"   /* master header: ngx + tunables + config + types */
#include "ssi.h"
#include "ssi_internal.h"
#include "ssi_rrinfo.h"
#include "ssi_reply.h"
#include "ssi_service.h"
#include "provider.h"
#include "session.h"
#include "registry.h"
#include "deliver.h"
#include "protocols/ssi/svc_cta/cta_service.h"
#include "protocols/root/connection/fd_table.h"
#include "protocols/root/response/response.h"
#include "core/compat/error_mapping.h"   /* brix_kxr_from_errno */
#include "protocols/root/protocol/opcodes.h"
#include "protocols/root/protocol/wire_core_requests.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/*
 * Responder state. The synchronous/submit phase fills only `rq` (ctx/c NULL, so
 * alerts drop — there is no push channel yet). The completion phase (driven from
 * the deferral timer) also carries ctx/c, so alerts are pushed live.
 */
typedef struct {
    brix_ssi_req_t  *rq;
    brix_ctx_t      *ctx;   /* non-NULL only when a push channel exists */
    ngx_connection_t  *c;
} ssi_resp_state_t;

static void
ssi_resp_set_metadata(brix_ssi_responder_t *r, const unsigned char *md,
                      size_t len)
{
    brix_ssi_req_t *rq = ((ssi_resp_state_t *) r->state)->rq;

    if (len > BRIX_SSI_META_MAX) {
        len = BRIX_SSI_META_MAX;
    }
    if (rq->meta == NULL) {
        rq->meta = ngx_palloc(rq->pool, BRIX_SSI_META_MAX);
        if (rq->meta == NULL) {
            return;
        }
    }
    ngx_memcpy(rq->meta, md, len);
    rq->meta_len = len;
}

static void
ssi_resp_set_response(brix_ssi_responder_t *r, const unsigned char *buf,
                      size_t len, int last)
{
    brix_ssi_req_t *rq = ((ssi_resp_state_t *) r->state)->rq;

    /* A non-final chunk marks the response as streamed: it is delivered to the
     * client via kXR_read pulls (pendResp) rather than inline in the reply. */
    if (!last) {
        rq->streaming = 1;
    }
    {
        size_t cap = rq->response_max > 0 ? rq->response_max : BRIX_SSI_RESP_MAX;
        if (brix_ssi_respbuf_append(&rq->resp, buf, len, cap) != 0) {
            rq->error = 1;
            rq->err_code = kXR_NoMemory;
            return;
        }
    }
    rq->responded = 1;
}

static void
ssi_resp_alert(brix_ssi_responder_t *r, const unsigned char *buf, size_t len)
{
    ssi_resp_state_t *st = r->state;

    /* Deliverable only when a push channel exists (the deferred completion phase)
     * and the client is awaiting a pushed response. The synchronous core has no
     * out-of-band channel, so it drops alerts (Phase-1 behaviour). */
    if (st->ctx != NULL && st->rq->waiting) {
        brix_ssi_deliver_alert(st->ctx, st->c, st->rq, buf, len);
    }
}

static void
ssi_resp_error(brix_ssi_responder_t *r, int code, const char *text)
{
    brix_ssi_req_t *rq = ((ssi_resp_state_t *) r->state)->rq;

    rq->error = 1;
    /* The service reports a POSIX errno (XrdSsi eNum); map it to a kXR code. */
    rq->err_code = code ? (int) brix_kxr_from_errno(code) : kXR_ServerError;
    if (text != NULL) {
        ngx_cpystrn((u_char *) rq->err_text, (u_char *) text,
                    sizeof(rq->err_text));
    }
    rq->responded = 1;
}

/* Submit-phase defer: accept the deferral (the write hook will arm the async
 * completion and reply kXR_waitresp). */
static int
ssi_resp_defer_accept(brix_ssi_responder_t *r)
{
    ((ssi_resp_state_t *) r->state)->rq->deferred = 1;
    return 0;
}

/* Completion-phase defer: refuse, so a re-invoked service responds inline. */
static int
ssi_resp_defer_refuse(brix_ssi_responder_t *r)
{
    (void) r;
    return -1;
}

static void **
ssi_resp_svc_slot(brix_ssi_responder_t *r)
{
    return &((ssi_resp_state_t *) r->state)->rq->svc_state;
}

static void
ssi_responder_init(brix_ssi_responder_t *r, ssi_resp_state_t *st,
                   int (*defer)(brix_ssi_responder_t *))
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
void
brix_ssi_dispatch(brix_ssi_req_t *rq, brix_ssi_process_fn process)
{
    brix_ssi_responder_t r;
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
ssi_complete_deferred(brix_ctx_t *ctx, ngx_connection_t *c,
                      brix_ssi_session_t *sess, brix_ssi_req_t *rq)
{
    brix_ssi_responder_t r;
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
    brix_ctx_t      *ctx;
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
    brix_ssi_session_t *s;
    brix_ssi_req_t     *rq;

    /* Liveness gate: a NULL find means the session/connection is gone (teardown
     * removed it). Do not touch ctx/c in that case. */
    s = brix_ssi_registry_find(d->session_key, d->generation);
    if (s != NULL) {
        rq = brix_ssi_session_req(s, d->req_id, 0);
        if (rq != NULL && !rq->responded) {
            brix_ssi_dlv_kind kind;

            rq->defer_ctx = NULL;   /* consume the timer before delivering */
            ssi_complete_deferred(d->ctx, d->c, s, rq);
            /* A streamed response is signalled PEND (client pulls the body via
             * kXR_read); a unary response is pushed inline; an error is terminal. */
            kind = rq->error     ? SSI_DLV_ERROR
                 : rq->streaming ? SSI_DLV_PEND
                                 : SSI_DLV_RESPONSE;
            brix_ssi_deliver(d->ctx, d->c, s, d->req_id, kind);
        } else if (rq != NULL) {
            rq->defer_ctx = NULL;
        }
    }
    ngx_free(d);
}

static ngx_int_t
ssi_defer_arm(brix_ctx_t *ctx, ngx_connection_t *c,
              brix_ssi_session_t *sess, brix_ssi_req_t *rq)
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
 * Teardown hook (called from brix_free_fhandle before the .ssi slot is cleared,
 * on both kXR_close and connection disconnect): cancel any armed deferral timers
 * and unregister the session, so no async completion can run against freed memory.
 */
void
brix_ssi_handle_cleanup(void *ssi_session)
{
    brix_ssi_session_t *sess = ssi_session;
    int                   i;

    if (sess == NULL) {
        return;
    }
    for (i = 0; i < BRIX_SSI_MAX_INFLIGHT; i++) {
        if (sess->rr[i].in_use && sess->rr[i].defer_ctx != NULL) {
            ssi_defer_cancel(sess->rr[i].defer_ctx);
            sess->rr[i].defer_ctx = NULL;
        }
    }
    brix_ssi_registry_remove(sess->conn_id);
}

/* ---- Append this write's payload to the accumulating SSI request ----
 *
 * WHAT: Appends n bytes of the current write payload to rq->req, enforcing the
 * per-request size cap. Returns 1 when accumulation succeeded (including the n==0
 * no-op case); returns 0 after sending a kXR error (ArgTooLong or NoMemory) and
 * stashing its status in *out_rc.
 *
 * WHY: A single logical SSI request can span several writes; concentrating the
 * cap check, lazy buffer allocation, and copy in one helper keeps brix_ssi_write
 * flat and its cyclomatic complexity within budget while preserving the exact
 * accept/reject behavior clients depend on.
 *
 * HOW: 1) Skip when there is nothing to append. 2) Clamp the effective cap to the
 * configured request_max but never above the compile-time BRIX_SSI_REQ_MAX (the
 * buffer is sized to that ceiling). 3) Reject when the append would exceed the
 * cap. 4) Lazily allocate the request buffer. 5) Copy the payload when present
 * and advance req_len.
 */
static int
ssi_write_accumulate(brix_ctx_t *ctx, ngx_connection_t *c,
                     brix_ssi_session_t *sess, brix_ssi_req_t *rq,
                     size_t n, ngx_int_t *out_rc)
{
    size_t reqcap;

    if (n == 0) {
        return 1;
    }
    reqcap = (sess->request_max > 0 && sess->request_max < BRIX_SSI_REQ_MAX)
           ? sess->request_max : BRIX_SSI_REQ_MAX;
    if (rq->req_len + n > reqcap) {
        *out_rc = brix_send_error(ctx, c, kXR_ArgTooLong,
                                    "SSI request too large");
        return 0;
    }
    if (rq->req == NULL) {
        rq->req = ngx_palloc(c->pool, BRIX_SSI_REQ_MAX);
        if (rq->req == NULL) {
            *out_rc = brix_send_error(ctx, c, kXR_NoMemory, "ssi req buf");
            return 0;
        }
    }
    if (ctx->recv.payload != NULL) {
        ngx_memcpy(rq->req + rq->req_len, ctx->recv.payload, n);
        rq->req_len += n;
    }
    return 1;
}

/* ---- Dispatch the SSI request once fully accumulated ----
 *
 * WHAT: When the client declared a total request size and that many bytes have
 * arrived, dispatches the request to the provider and (for deferred services)
 * arms async completion. Returns 1 when the caller should ack with kXR_ok
 * (nothing dispatched yet, or a synchronous dispatch); returns 0 when it has
 * already produced the terminal reply (kXR_waitresp, or a kXR_NoMemory error via
 * *out_rc) for a deferred dispatch.
 *
 * WHY: With no declared size (req_expected == 0, the write-until-read protocol)
 * dispatch must be deferred to the first read so several writes coalesce into one
 * request; firing on the first write rejected every following write as "already
 * dispatched". Isolating this decision keeps the routing exact and the caller
 * within complexity budget.
 *
 * HOW: 1) Return early when fewer than req_expected bytes have accumulated (or no
 * size was declared). 2) Dispatch and count the request. 3) For a deferred,
 * not-yet-responded request: capture the submit streamid, mark it waiting, arm
 * the completion (NoMemory error on failure), and ack with kXR_waitresp — the
 * response is later pushed via kXR_attn (brix_ssi_deliver). 4) Otherwise let the
 * caller send the inline kXR_ok.
 */
static int
ssi_write_maybe_dispatch(brix_ctx_t *ctx, ngx_connection_t *c,
                         brix_ssi_session_t *sess, brix_ssi_req_t *rq,
                         ngx_int_t *out_rc)
{
    if (!(rq->req_expected > 0 && rq->req_len >= rq->req_expected)) {
        return 1;
    }
    brix_ssi_dispatch(rq, sess->provider.process);
    BRIX_SRV_METRIC_INC(ctx, ssi_requests_total);

    if (rq->deferred && !rq->responded) {
        ngx_memcpy(rq->defer_streamid, ctx->recv.cur_streamid,
                   sizeof(rq->defer_streamid));
        rq->waiting = 1;
        if (ssi_defer_arm(ctx, c, sess, rq) != NGX_OK) {
            *out_rc = brix_send_error(ctx, c, kXR_NoMemory, "ssi defer");
            return 0;
        }
        *out_rc = brix_send_waitresp(ctx, c);
        return 0;
    }
    return 1;
}

ngx_int_t
brix_ssi_write(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
                 const unsigned char off8[8])
{
    brix_ssi_session_t *sess = ctx->files[idx].ssi;
    brix_ssi_req_t     *rq;
    int                   cmd;
    uint32_t              id, size;
    size_t                n = ctx->recv.cur_dlen;
    ngx_int_t             rc = NGX_OK;

    brix_ssi_rrinfo_decode(off8, &cmd, &id, &size);

    if (cmd == BRIX_SSI_CMD_CAN) {
        brix_ssi_session_drop(sess, id);    /* request-phase cancel */
        return brix_send_ok(ctx, c, NULL, 0);
    }

    rq = brix_ssi_session_req(sess, id, 1);
    if (rq == NULL) {
        return brix_send_error(ctx, c, kXR_Overloaded,
                                 "too many concurrent SSI requests");
    }
    if (rq->dispatched) {
        return brix_send_error(ctx, c, kXR_FileLocked,
                                 "SSI request already dispatched");
    }

    if (!rq->have_size) {
        rq->req_expected = size;
        rq->have_size = 1;
    }

    if (!ssi_write_accumulate(ctx, c, sess, rq, n, &rc)) {
        return rc;
    }

    if (!ssi_write_maybe_dispatch(ctx, c, sess, rq, &rc)) {
        return rc;
    }

    return brix_send_ok(ctx, c, NULL, 0);
}
