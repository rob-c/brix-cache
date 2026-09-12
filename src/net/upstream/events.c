/* ---- File: events.c — Upstream connection non-blocking read/write event handlers ----
 *
 * PURPOSE:
 *   Three nginx event-loop callbacks managing outbound upstream redirector
 *   connection lifecycle: wait timer, write handler, read handler.
 *
 * HANDLERS:
 *
 * 1. brix_upstream_wait_timer_handler(ev)
 *    - Trigger: kXR_wait expiry timer callback
 *    - Action: Checks ctx validity, logs "upstream kXR_wait expired; retrying"
 *    - Calls: brix_upstream_send_request() to resend saved client request
 *    - Error: Aborts on failure
 *
 * 2. brix_upstream_write_handler(wev)
 *    - Trigger: Non-blocking upstream write event
 *    - CONNECTING state: SO_ERROR getsockopt check
 *      - Abort on TCP connect failure
 *      - Transition to XRD_UP_BOOTSTRAP with bs_phase=BS_HANDSHAKE
 *      - Reset response accumulator
 *    - Partial write: brix_upstream_flush() drain
 *      - Abort on error
 *    - Complete write: ngx_handle_read_event() to arm read
 *
 * 3. brix_upstream_read_handler(rev)
 *    - Accumulates XRD_RESPONSE_HDR_LEN bytes
 *    - Parses ServerResponseHdr → resp_status, resp_dlen (ntohs/ntohl)
 *    - Allocates resp_body from uconn->pool (cap: MAX_PATH+256)
 *    - Accumulates body bytes until full
 *    - State dispatch:
 *      - XRD_UP_BOOTSTRAP → handle_bootstrap_response()
 *      - XRD_UP_REQUEST/XRD_UP_ASYNC → forward_response()
 *      - Default → abort ("unexpected state")
 *
 * KEY DESIGN DECISIONS:
 * 1. TCP connect completion via SO_ERROR on first write event (no separate callback)
 * 2. Response body cap MAX_PATH+256 prevents unbounded allocation
 * 3. Pool allocation (uconn->pool) ties cleanup to connection lifecycle
 * 4. State-based dispatch: bootstrap → state machine, request/async → forward
 * 5. ctx->destroyed check prevents callbacks on closed connections
 *
 * ERROR HANDLING:
 * - All handlers check ctx validity/destroyed flag
 * - Timeout aborts with descriptive message
 * - Cleanup via brix_upstream_cleanup() on ctx destruction
 */
#include "upstream_internal.h"
#include "core/compat/log_diag.h"

#include <sys/socket.h>

/*
 * WHAT: Timer callback fired when a server-issued kXR_wait delay expires.
 * WHY: When the backend answers an opcode with kXR_wait it is asking us to retry the
 *      same request after N seconds; this timer is the retry trigger.
 * HOW: Validate the client session still exists, then resend the saved request via
 *      send_request(). On failure (with the upstream conn still live) abort the proxy.
 */
void
brix_upstream_wait_timer_handler(ngx_event_t *ev)
{
    brix_upstream_t *up = ev->data;
    brix_ctx_t      *ctx = up->client_ctx;

    /* Client session may have gone away while we were waiting — drop the upstream. */
    if (ctx == NULL || ctx->destroyed) {
        brix_upstream_cleanup(up);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, up->client_conn->log, 0,
                  "brix: upstream kXR_wait expired; retrying");

    if (brix_upstream_send_request(up) != NGX_OK && up->conn != NULL) {
        brix_upstream_abort(up, "upstream retry failed");
    }
}

/*
 * WHAT: Writable-event callback for the upstream socket: completes the async TCP connect
 *      and drains the pending write buffer (bootstrap bytes or a replayed request).
 * WHY: nginx has no separate connect-completion callback for non-blocking sockets — the
 *      socket simply becomes writable. So the first write event doubles as the signal
 *      that connect() finished, which we confirm via SO_ERROR.
 * HOW: While in CONNECTING, check SO_ERROR (abort on TCP failure) and transition to
 *      BOOTSTRAP/HANDSHAKE, zeroing the response accumulator. Then if wbuf still has
 *      unsent bytes, flush() and return (stay armed for the next writable event).
 *      Only once the buffer is fully drained do we arm the read side for the reply.
 */
void
brix_upstream_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *uconn = wev->data;
    brix_upstream_t *up = uconn->data;
    brix_ctx_t      *ctx = up->client_ctx;

    /* Don't act on a socket whose client session has already been torn down. */
    if (ctx == NULL || ctx->destroyed) {
        brix_upstream_cleanup(up);
        return;
    }

    if (wev->timedout) {
        brix_upstream_abort(up, "upstream connect/write timeout");
        return;
    }

    if (up->state == XRD_UP_CONNECTING) {
        int       err = 0;
        socklen_t len = sizeof(err);

        /* SO_ERROR holds the pending connect() result; a getsockopt failure or a
         * non-zero err means the async connect did not succeed. */
        if (getsockopt(uconn->fd, SOL_SOCKET, SO_ERROR,
                       (char *) &err, &len) == -1 || err)
        {
            BRIX_DIAG_ERR(up->client_conn->log,
                err ? err : ngx_socket_errno,
                "brix: cannot connect to upstream data server",
                "the upstream is down, unreachable, or refusing connections "
                "(wrong host/port, or a firewall)",
                "confirm the upstream xrootd/data server is up and reachable "
                "from this host; the OS reason is appended below");
            brix_upstream_abort(up, "upstream TCP connect failed");
            return;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, up->client_conn->log, 0,
                       "brix: upstream TCP connected");

        /* Connect succeeded — begin bootstrap and reset the read accumulator so the
         * first reply (the handshake response) parses from a clean slate. */
        up->state = XRD_UP_BOOTSTRAP;
        up->bs_phase = XRD_UP_BS_HANDSHAKE;
        up->rhdr_pos = 0;
        up->resp_dlen = 0;
        up->resp_body = NULL;
        up->resp_body_pos = 0;
    }

    /* Partial-write drain: flush() advances wbuf_pos. If bytes remain we return and
     * wait for the next writable event rather than arming the read side prematurely. */
    if (up->wbuf_pos < up->wbuf_len) {
        ngx_int_t rc = brix_upstream_flush(up);

        if (rc == NGX_ERROR) {
            brix_upstream_abort(up, "upstream write error");
        }
        return;
    }

    /* Buffer fully sent — now wait for the upstream's reply. */
    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        brix_upstream_abort(up, "upstream read arm failed in write handler");
    }
}

/*
 * WHAT: Perform a single non-blocking recv into buf[*pos..total), advancing *pos on
 *      success, and translate the three possible outcomes into a caller-return signal.
 * WHY: Both accumulation stages of the read handler (header and body) share identical
 *      recv/NGX_AGAIN/peer-closed handling — only the destination buffer and the abort
 *      messages differ. Centralising it keeps the offsets (rhdr_pos/resp_body_pos)
 *      resumable across re-entries and removes a duplicated branch ladder.
 * HOW: recv `total - *pos` bytes at buf + *pos. On NGX_AGAIN re-arm the read event
 *      (abort with again_msg if arming fails) and return NGX_DONE — the caller must
 *      return so re-entry resumes at the same offset. On <=0 abort with closed_msg and
 *      return NGX_DONE. On a real read advance *pos and return NGX_OK; the caller then
 *      decides (via the offset) whether the stage is complete or must loop for more.
 */
static ngx_int_t
brix_upstream_recv_chunk(brix_upstream_t *up, ngx_connection_t *uconn,
    ngx_event_t *rev, u_char *buf, size_t *pos, size_t total,
    const char *again_msg, const char *closed_msg)
{
    size_t  need = total - *pos;
    ssize_t n = uconn->recv(uconn, buf + *pos, need);

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            brix_upstream_abort(up, again_msg);
        }
        return NGX_DONE;
    }
    if (n <= 0) {
        brix_upstream_abort(up, closed_msg);
        return NGX_DONE;
    }

    *pos += (size_t) n;
    return NGX_OK;
}

/*
 * WHAT: Decode the just-completed response header and, when a body follows, allocate a
 *      size-capped body buffer for stage 2.
 * WHY: The 8-byte ServerResponseHdr carries the wire status and the body length that
 *      governs stage-2 accumulation. Untrusted `dlen` must be bounded before it drives
 *      an allocation, and the buffer needs a spare NUL so downstream parsers can treat
 *      the body as a C string.
 * HOW: Read status (ntohs) and dlen (ntohl) from the header in host order. With dlen==0
 *      there is no body — return NGX_OK immediately. Otherwise reject a dlen above
 *      BRIX_MAX_PATH+256 (abort, NGX_ERROR), then ngx_palloc dlen+1 from the connection
 *      pool (abort on failure), NUL-terminate at [dlen], and reset resp_body_pos.
 */
static ngx_int_t
brix_upstream_parse_header_and_alloc(brix_upstream_t *up,
    ngx_connection_t *uconn)
{
    ServerResponseHdr *hdr = (ServerResponseHdr *) (void *) up->rhdr;

    up->resp_status = ntohs(hdr->status);
    up->resp_dlen = ntohl(hdr->dlen);

    if (up->resp_dlen == 0) {
        return NGX_OK;
    }

    /* Cap untrusted body size to bound allocation — the largest legitimate
     * upstream payload here is a path plus protocol slack, except during the
     * kXR_auth exchange where a GSI kXGS_cert carries the server's X.509 chain
     * and DH parameters (phase 115 W2.4: XRD_UP_AUTH_BODY_MAX). */
    if (up->resp_dlen > ((up->state == XRD_UP_BOOTSTRAP
                          && up->bs_phase == XRD_UP_BS_AUTH)
                         ? (uint32_t) XRD_UP_AUTH_BODY_MAX
                         : (uint32_t) (BRIX_MAX_PATH + 256)))
    {
        brix_upstream_abort(up, "upstream response body too large");
        return NGX_ERROR;
    }

    /* +1 byte for a NUL terminator so the body can be treated as a C string by
     * downstream parsers; allocated from the connection pool. */
    up->resp_body = ngx_palloc(uconn->pool, up->resp_dlen + 1);
    if (up->resp_body == NULL) {
        brix_upstream_abort(up, "upstream pool alloc failed");
        return NGX_ERROR;
    }
    up->resp_body[up->resp_dlen] = '\0';
    up->resp_body_pos = 0;
    return NGX_OK;
}

/*
 * WHAT: Hand a fully-buffered header+body response to the correct consumer for the
 *      current connection state.
 * WHY: Bootstrap and live-request phases consume responses differently: bootstrap replies
 *      drive the login FSM, while request/async replies are relayed verbatim. Any other
 *      state reaching a complete frame is a logic error worth aborting on.
 * HOW: BOOTSTRAP → handle_bootstrap_response(); REQUEST/ASYNC → forward_response();
 *      anything else → abort. The handler returns unconditionally after this call.
 */
static void
brix_upstream_dispatch_response(brix_upstream_t *up)
{
    /* Bootstrap replies (handshake/protocol/TLS/login) drive the login FSM, which
     * advances bs_phase and, when DONE, replays the saved client request. */
    if (up->state == XRD_UP_BOOTSTRAP) {
        brix_upstream_handle_bootstrap_response(up);
        return;
    }

    /* Live request/async replies are relayed verbatim to the client connection. */
    if (up->state == XRD_UP_REQUEST || up->state == XRD_UP_ASYNC) {
        brix_upstream_forward_response(up);
        return;
    }

    /* No other state should ever reach the read handler with a complete frame. */
    brix_upstream_abort(up, "upstream: unexpected state in read handler");
}

/*
 * WHAT: Readable-event callback that accumulates one complete upstream response
 *      (fixed-size header + variable body) and dispatches it by connection state.
 * WHY: XRootD replies are framed as an 8-byte ServerResponseHdr followed by `dlen`
 *      body bytes. Reads can fragment arbitrarily, so we must persist partial progress
 *      (rhdr_pos / resp_body_pos) across re-entries to this handler. A single response
 *      is consumed per invocation, after which we hand off and return.
 * HOW: Two-stage accumulation inside one loop. Stage 1 fills rhdr to XRD_RESPONSE_HDR_LEN
 *      via recv_chunk() then parses status/dlen and allocates the body. Stage 2 fills the
 *      body via recv_chunk(). recv_chunk() returns NGX_DONE on NGX_AGAIN (re-armed) or
 *      peer-close (aborted) — in both cases we return so re-entry resumes at the same
 *      offset; on NGX_OK a short read loops to pull the remainder. Once both stages are
 *      complete, dispatch_response() routes the frame by connection state.
 */
void
brix_upstream_read_handler(ngx_event_t *rev)
{
    ngx_connection_t  *uconn = rev->data;
    brix_upstream_t *up = uconn->data;
    brix_ctx_t      *ctx = up->client_ctx;

    /* Stale event after the client session was destroyed: just clean up. */
    if (ctx == NULL || ctx->destroyed) {
        brix_upstream_cleanup(up);
        return;
    }

    if (rev->timedout) {
        brix_upstream_abort(up, "upstream read timeout");
        return;
    }

    for (;;) {
        /* Stage 1: accumulate the fixed-length response header. */
        if (up->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
            if (brix_upstream_recv_chunk(up, uconn, rev, up->rhdr,
                    &up->rhdr_pos, XRD_RESPONSE_HDR_LEN,
                    "upstream read arm failed (hdr)",
                    "upstream connection closed") != NGX_OK)
            {
                return;
            }
            if (up->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
                /* Short read — loop to pull the rest of the header. */
                continue;
            }
            if (brix_upstream_parse_header_and_alloc(up, uconn) != NGX_OK) {
                return;
            }
        }

        /* Stage 2: accumulate the variable-length body (skipped when dlen==0). */
        if (up->resp_body_pos < up->resp_dlen) {
            if (brix_upstream_recv_chunk(up, uconn, rev, up->resp_body,
                    &up->resp_body_pos, up->resp_dlen,
                    "upstream read arm failed (body)",
                    "upstream connection closed (body)") != NGX_OK)
            {
                return;
            }
            if (up->resp_body_pos < up->resp_dlen) {
                /* More body to come — loop. */
                continue;
            }
        }

        /* Dispatch: a full header+body is now buffered. */
        brix_upstream_dispatch_response(up);
        return;
    }
}

