/*
 * events.c — upstream read/write event handlers for the proxy connection.
 *
 * Write handler: flushes the wbuf (bootstrap or forwarded request).
 * Read handler:  accumulates a full response (header + body), then dispatches
 *                to the bootstrap handler or to the client relay.
 */

#include "proxy_internal.h"
#include "protocols/root/connection/handler.h"
#include "auth/token/file.h"

#include <sys/socket.h>

#include "events_bootstrap_internal.h"

/* bootstrap response handling */
/*
 * WHAT: Advance the upstream login handshake one step, consuming the response
 *       that the read handler just finished accumulating (proxy->resp_status /
 *       resp_dlen / resp_body) and, where the next step requires sending,
 *       arming the write side with the next request frame.
 * WHY:  Connecting to an upstream XRootD server is a fixed conversation —
 *       hello -> kXR_protocol -> kXR_login -> (optional kXR_auth) — that must
 *       complete before any client request can be forwarded. Each leg is a
 *       separate wire round-trip, so the proxy drives it as a state machine
 *       (proxy->bs_phase) re-entered once per upstream response rather than
 *       blocking; the event loop never waits.
 * HOW:  Switch on bs_phase. Each arm validates the just-received response,
 *       optionally builds+flushes the next request, and either advances
 *       bs_phase or returns early (when it issued a send and must wait for the
 *       reply). The single fallthrough at the bottom frees the response
 *       accumulator; reaching XRD_PX_BS_DONE flips proxy->state to IDLE and
 *       releases any request queued during bootstrap.
 *
 * RE-ENTRY: this is called by brix_proxy_read_handler each time a complete
 *       upstream frame arrives. Arms that send (AUTH legs) return early and are
 *       resumed by the next read event; non-sending arms fall through to the
 *       shared reset/finish tail. The auth-send arms (FORWARD bearer, SSS,
 *       FORWARD token-file fallback, login-sec hint) are structurally identical
 *       — build frame -> free+reset resp accumulator -> set wbuf -> flush ->
 *       arm write if partial -> return — and share proxy_bs_queue_auth_frame;
 *       they differ only in how the credential is sourced.
 */
/* BS_LOGIN bootstrap phase: handle the upstream login reply — kXR_authmore
 * (forward bearer / SSS / token-file), login failure, and the token-only
 * login-sec hint (proactive P=sss / P=ztn).  Returns 1 when it has issued a
 * frame or aborted and the caller must return; 0 when the phase is complete
 * (bs_phase advanced to DONE) and the caller falls through to the shared
 * reset/finish tail. */
static int
brix_proxy_bs_login(brix_proxy_ctx_t *proxy)
{
    if (proxy->resp_status == kXR_authmore) {
        /* Upstream requests authentication — handle by configured policy.
         * Effective policy: per-upstream override if set, else global
         * conf->proxy.auth. */
        return proxy_bs_do_auth(proxy);
    }

    if (proxy->resp_status != kXR_ok) {
        proxy_bs_auth_error(proxy, 1, "upstream login failed");
        return 1;
    }

    if (proxy_bs_login_sec_hint(proxy)) {
        return 1;
    }

    proxy->bs_phase = XRD_PX_BS_DONE;

    return 0;
}

/*
 * WHAT: Validate the upstream kXR_protocol reply (BS_PROTOCOL phase).
 * WHY:  kXR_protocol reply body: [4 bytes pval][4 bytes flags][...]. The
 *       server's capability flags live at body offset 4; kXR_gotoTLS there
 *       means the server wants the connection upgraded to TLS now. We only
 *       reach this code on a cleartext connection (TLS-from-start uses a
 *       different path), so an in-band upgrade request is unsupported.
 * HOW:  Returns NGX_OK when the reply is acceptable; NGX_ERROR after
 *       aborting the proxy (bad status or gotoTLS demand).
 */
static ngx_int_t
proxy_bs_check_protocol_reply(brix_proxy_ctx_t *proxy)
{
    if (proxy->resp_status != kXR_ok) {
        brix_proxy_abort(proxy, "upstream kXR_protocol failed");
        return NGX_ERROR;
    }

    if (proxy->resp_dlen >= 8) {
        uint32_t flags_be;
        ngx_memcpy(&flags_be, proxy->resp_body + 4, sizeof(flags_be));
        if (ntohl(flags_be) & kXR_gotoTLS) {
#if (NGX_SSL)
            /* gotoTLS from upstream is only valid when proxy_upstream_tls
             * was NOT set (it's the upstream's choice to require TLS after
             * the connection was made without TLS).  Not supported yet. */
#endif
            brix_proxy_abort(proxy,
                "upstream requires TLS upgrade after connect "
                "(use brix_proxy_upstream_tls on to start with TLS)");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: Adopt the bootstrapped upstream connection into service — flip the
 *       proxy to IDLE, publish success metrics, restore failure budgets, and
 *       hand the fd over to whichever request is waiting.
 * WHY:  This is the single point where the upstream stops being "in
 *       bootstrap" and becomes usable by the client relay; keeping the
 *       transition in one helper freezes the handoff timing.
 * HOW:  Marks the upstream healthy, clears the consecutive-failure budget,
 *       refills the reconnect budget, then either forwards the request that
 *       was queued during bootstrap (dispatch_pending handles bound-secondary
 *       lazy-open) or resumes the client read loop.
 */
static void
proxy_bs_adopt_conn(brix_proxy_ctx_t *proxy)
{
    proxy->state = XRD_PX_IDLE;
    brix_proxy_up_mark_ok(proxy);
    BRIX_PROXY_METRIC_INC(proxy->client_ctx, upstream_connects_total);
    BRIX_PROXY_UP_INC(proxy, upstream_connects_total);

    /* The upstream accepted the forwarded credential — this connection is
     * healthy again, so clear the consecutive-failure budget. */
    if (proxy->client_ctx != NULL) {
        proxy->client_ctx->proxy_fail_count = 0;
    }

    /* Restore the full reconnect budget on every successful bootstrap */
    if (proxy->conf != NULL) {
        proxy->reconnect_left = (int) proxy->conf->proxy.reconnect_attempts;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                   "xrootd proxy: upstream bootstrap done");

    /* If a request was queued during bootstrap, forward it now.
     * brix_proxy_dispatch_pending handles bound-secondary lazy-open. */
    if (proxy->saved_req != NULL) {
        brix_proxy_dispatch_pending(proxy);
        return;
    }

    /* No deferred request — just resume the client read loop */
    {
        brix_ctx_t *ctx = proxy->client_ctx;
        ctx->state = XRD_ST_REQ_HEADER;
        brix_schedule_read_resume(proxy->client_conn);
    }
}

void
brix_proxy_handle_bootstrap(brix_proxy_ctx_t *proxy)
{
    /* State machine over the upstream login conversation; see bs_phase enum. */
    switch (proxy->bs_phase) {

    case XRD_PX_BS_HANDSHAKE:
        /* Server hello: the 16-byte handshake reply begins with two zero
         * 32-bit words, and the read handler parsed status from the bytes that
         * happen to fall in the zero prefix, so resp_status is normally 0 ==
         * kXR_ok. A non-zero value here means the bytes did not line up as a
         * valid hello, i.e. this is not an XRootD server speaking. */
        if (proxy->resp_status != kXR_ok) {
            brix_proxy_abort(proxy, "bad handshake from upstream");
            return;
        }
        proxy->bs_phase = XRD_PX_BS_PROTOCOL;
        break;

    case XRD_PX_BS_PROTOCOL:
        if (proxy_bs_check_protocol_reply(proxy) != NGX_OK) {
            return;
        }
        proxy->bs_phase = XRD_PX_BS_LOGIN;
        break;

    case XRD_PX_BS_LOGIN:
        if (brix_proxy_bs_login(proxy)) {
            return;
        }
        break;

    case XRD_PX_BS_AUTH:
        if (proxy->resp_status != kXR_ok) {
            proxy_bs_auth_error(proxy, 1, "upstream rejected forwarded token");
            return;
        }
        proxy->bs_phase = XRD_PX_BS_DONE;
        break;

    default:
        brix_proxy_abort(proxy, "proxy: invalid bootstrap phase");
        return;
    }

    /* Shared tail: reached only by arms that fell through (i.e. did NOT issue a
     * send and return early). Reset the accumulator for whatever comes next. */
    /* Reset response accumulator for the next bootstrap message or first req */
    proxy_bs_reset_resp(proxy);

    if (proxy->bs_phase != XRD_PX_BS_DONE) {
        return;  /* caller (read_handler) will continue the loop */
    }

    /* Bootstrap complete — transition to IDLE */
    proxy_bs_adopt_conn(proxy);
}
