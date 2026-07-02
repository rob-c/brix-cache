#ifndef XROOTD_SSI_DELIVER_H
#define XROOTD_SSI_DELIVER_H

/*
 * deliver.h — the single async SSI delivery primitive (server push).
 *
 * WHAT: push a request's response / alert / error to the client via an unsolicited
 *       kXR_attn frame, addressed to the streamid the client used on the submit it
 *       had acked with kXR_waitresp.
 * WHY:  real libXrdSsi clients expect the server to push a deferred response
 *       (kXR_asynresp) rather than be polled. This is the one place an async
 *       completion reaches the socket.
 * HOW:  runs ONLY in event-loop context (a timer handler or a thread-pool
 *       completion posted back via aio/resume.c), and only after the caller has
 *       resolved a LIVE session through the generation-guarded registry. It
 *       reuses xrootd_send_attn_asynresp (src/response/async.c).
 */

#include "ngx_xrootd_module.h"
#include "session.h"

typedef enum {
    SSI_DLV_RESPONSE,   /* terminal full response (metadata + data) */
    SSI_DLV_PEND,       /* response-ready, pull the body via kXR_read (streamed) */
    SSI_DLV_ERROR       /* terminal error (err_code + err_text on the slot) */
} xrootd_ssi_dlv_kind;

/*
 * Push `kind` for the request `req_id` of session `s` to connection `c`. The
 * caller MUST be on the event loop and MUST have just resolved `s` via
 * xrootd_ssi_registry_find (so the connection is live). No-op if the reqId slot
 * is gone.
 */
void xrootd_ssi_deliver(xrootd_ctx_t *ctx, ngx_connection_t *c,
                        xrootd_ssi_session_t *s, uint32_t req_id,
                        xrootd_ssi_dlv_kind kind);

/*
 * Push an out-of-band alert (alrtResp '!') carrying `buf`/`len` for an already
 * resolved live request `rq`. The client processes it as an alert and keeps
 * awaiting the request's response. Event-loop only.
 */
void xrootd_ssi_deliver_alert(xrootd_ctx_t *ctx, ngx_connection_t *c,
                              xrootd_ssi_req_t *rq,
                              const unsigned char *buf, size_t len);

#endif /* XROOTD_SSI_DELIVER_H */
