#include "handshake.h"
#include "net/proxy/proxy.h"
#include "net/mirror/stream_mirror.h"
#include "net/mirror/stream_wmirror.h"
#include "net/ratelimit/ratelimit.h"
#include "auth/impersonate/lifecycle.h"

/*
 * Request routing overview
 * ========================
 *
 * brix_dispatch() tries each of the four dispatch functions in order.
 * Each returns BRIX_DISPATCH_CONTINUE if the opcode is not its own;
 * otherwise it handles the request and returns an ngx_int_t result.
 *
 *   dispatch_session.c  — protocol, login, auth, bind, endsess, ping, set
 *   proxy/forward.c     — all post-login opcodes when brix_proxy is on
 *   dispatch_read.c     — open(read), stat, statx, read, readv, pgread,
 *                         close, dirlist, locate, query, prepare
 *   dispatch_write.c    — open(write), write, pgwrite, writev, sync,
 *                         truncate, mkdir, rm, rmdir, mv, chmod, fattr,
 *                         clone, chkpoint
 *   dispatch_signing.c  — sigver (must be last; inspects every request)
 *
 * Adding a new opcode: determine its category above, add a case to the
 * matching dispatch_*.c file, then see docs/contributing.md §5 for the
 * full checklist.
 */

/* dispatch_defer_to_manager — should this opcode bypass the forwarding gate so
 * the CMS manager can (re-)select a data server for it?  (phase-115 W2.1)
 *
 * WHAT: True only for a SELECTION-pinned session (ctx->proxy set while
 *       conf->proxy.enable is off) whose upstream is quiescent.
 * WHY:  The pin is created by brix_cms_answer_selected() on the first
 *       selection.  Short-circuiting every later opcode onto that upstream —
 *       correct for a statically configured proxy — means the manager never
 *       runs again, so a path held by a *different* data server is forwarded
 *       verbatim to the wrong node, which answers kXR_error/3011.  Falling
 *       through returns the request to the normal dispatchers, whose open /
 *       stat / locate paths consult the registry and re-pin through
 *       brix_proxy_dispatch_to().
 * HOW:  conf->proxy.enable off, ctx->proxy set, and the proxy movable.  With a
 *       file open (or a request in flight) the predicate is false and the
 *       session keeps its node — the one-upstream-per-session invariant.  The
 *       auth_done half of the gate is deliberately *not* part of this
 *       predicate: falling through leads to the direct dispatchers, which
 *       enforce their own require_auth gate, and an unauthenticated session
 *       never reaches this point with a proxy anyway.
 */
static int
dispatch_defer_to_manager(const ngx_stream_brix_srv_conf_t *conf,
    const brix_ctx_t *ctx)
{
    if (conf->proxy.enable || ctx->proxy == NULL) {
        return 0;
    }
    return brix_proxy_session_may_reselect(ctx->proxy);
}

ngx_int_t
brix_dispatch(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    ngx_int_t rc;

    /* Every dispatched request resets the per-request timing origin for logging. */
    ctx->req_start = ngx_current_msec;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: dispatch reqid=%d", (int) ctx->recv.cur_reqid);

    rc = brix_verify_pending_sigver(ctx, c);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    rc = brix_signing_enforce_level(ctx, c, conf);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    /*
     * Per-capability TLS gate (brix_tls_require) — BEFORE the session opcodes
     * so the `login` capability gates kXR_login/kXR_auth themselves; the
     * classifier exempts the handshake/control opcodes so a client can always
     * reach the in-protocol TLS upgrade this policy demands.
     */
    rc = brix_tls_require_enforce(ctx, c, conf);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    rc = brix_dispatch_session_opcode(ctx, c, conf);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    /*
     * D-1: enforce the session-posture floor (brix_min_sec_level).  Placed after
     * the session opcodes are dispatched so the login/auth/protocol/bind/TLS-
     * upgrade handshake is never blocked; every opcode reaching here is a
     * data/metadata request, so a below-floor (cleartext, or anonymous under
     * intense) session is refused before it can touch the proxy or the FS.
     */
    rc = brix_min_sec_enforce(ctx, c, conf);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    /*
     * Proxy mode: all post-login file-system opcodes go to the upstream.
     *
     * SECURITY (fail-closed): gate on ctx->login.auth_done, NOT merely ctx->login.logged_in.
     * kXR_login only sets logged_in; for any configured auth (gsi/token/sss/...)
     * auth_done stays 0 until kXR_auth completes (login.c).  The session opcodes
     * (login/auth/bind/...) are already handled above, so anything reaching here
     * is a file-system opcode that MUST be authenticated before we forward it to
     * the upstream under the proxy's own bridged credentials.  Gating on
     * logged_in alone let a client send kXR_login then skip kXR_auth and still
     * reach upstream resources.  Anonymous mode (auth=none) sets auth_done=1 at
     * login, so this remains a no-op gate there.  This mirrors the require_auth
     * gate enforced on the direct (non-proxy) read/write dispatchers.
     *
     * Phase-115 W2.1: a session that a manager already pinned to a CMS-selected
     * data server (`brix_cms_response proxy`, ctx->proxy != NULL) rides that
     * upstream for every later opcode, exactly like a configured proxy — EXCEPT
     * while the pin is still movable, when the opcode is handed back to the
     * manager so a selection can name a different node.  See
     * dispatch_defer_to_manager() above for why an unconditional short-circuit
     * makes the first selection permanent.
     */
    if ((conf->proxy.enable || ctx->proxy != NULL) && ctx->login.auth_done
        && !dispatch_defer_to_manager(conf, ctx))
    {
        return brix_proxy_dispatch(ctx, c, conf);
    }

    /* Phase 25: advanced rate limiting / traffic shaping.  Gates data-plane
     * read/write opcodes; a throttled request is answered with kXR_wait and the
     * gate returns the send result (NGX_DECLINED means "proceed normally"). */
    rc = brix_rl_stream_gate(ctx, c, conf);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /*
     * Phase 40: bracket the confined-FS dispatchers with the impersonation
     * principal taken from the authenticated identity.  begin()/end() are no-ops
     * unless brix_idmap=map; when active they make the beneath helpers
     * (open/stat/mkdir/...) route to the broker as the mapped UNIX user for the
     * duration of this synchronous dispatch, then restore the worker identity.
     * The data plane (kXR_read/write on the already-open fd) and the mirror/RL
     * paths run unbracketed — they need no impersonation.
     */
    brix_imp_request_begin(ctx->identity);
    rc = brix_dispatch_read_opcode(ctx, c, conf);
    brix_imp_request_end();
    if (rc != BRIX_DISPATCH_CONTINUE) {
        /* Phase 24: fire-and-forget replay of this read to the shadow server(s).
         * No-op unless brix_mirror_url is configured; the primary
         * response has already been queued to the client above. */
        brix_stream_mirror_maybe(ctx, c, conf, rc);
        /* Phase 24 W3: kXR_close finalises a data-write mirror (open/write/close
         * is dispatched across the read+write tables). */
        brix_stream_wmirror_observe(ctx, c, conf, rc);
        return rc;
    }

    brix_imp_request_begin(ctx->identity);
    rc = brix_dispatch_write_opcode(ctx, c, conf);
    brix_imp_request_end();
    if (rc != BRIX_DISPATCH_CONTINUE) {
        /* Phase 24 write mirroring (W1): replay self-contained metadata mutations
         * (mkdir/rm/rmdir/mv/truncate/chmod) to the shadow.  No-op unless
         * brix_mirror_writes is on and the op is listed in brix_mirror_opcodes;
         * the primary response was already queued to the client above. */
        brix_stream_mirror_maybe(ctx, c, conf, rc);
        /* Phase 24 W3: accumulate kXR_write / kXR_pgwrite payloads for the
         * data-write mirror (replayed to the shadow on kXR_close). */
        brix_stream_wmirror_observe(ctx, c, conf, rc);
        return rc;
    }

    rc = brix_dispatch_signing_opcode(ctx, c);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: unsupported request %d",
                   (int) ctx->recv.cur_reqid);
    /* An unrecognized opcode is kXR_InvalidRequest ("Invalid request code"),
     * matching the stock server; kXR_Unsupported is
     * reserved for a recognized op the backend cannot perform (ENOTSUP). */
    return brix_send_error(ctx, c, kXR_InvalidRequest,
                             "Invalid request code");
}
