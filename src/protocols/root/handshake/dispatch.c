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

ngx_int_t
brix_dispatch(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    ngx_int_t rc;

    /* Every dispatched request resets the per-request timing origin for logging. */
    ctx->req_start = ngx_current_msec;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: dispatch reqid=%d", (int) ctx->cur_reqid);

    rc = brix_verify_pending_sigver(ctx, c);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    rc = brix_signing_enforce_level(ctx, c, conf);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    rc = brix_dispatch_session_opcode(ctx, c, conf);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    /*
     * Proxy mode: all post-login file-system opcodes go to the upstream.
     *
     * SECURITY (fail-closed): gate on ctx->auth_done, NOT merely ctx->logged_in.
     * kXR_login only sets logged_in; for any configured auth (gsi/token/sss/...)
     * auth_done stays 0 until kXR_auth completes (login.c).  The session opcodes
     * (login/auth/bind/...) are already handled above, so anything reaching here
     * is a file-system opcode that MUST be authenticated before we forward it to
     * the upstream under the proxy's own bridged credentials.  Gating on
     * logged_in alone let a client send kXR_login then skip kXR_auth and still
     * reach upstream resources.  Anonymous mode (auth=none) sets auth_done=1 at
     * login, so this remains a no-op gate there.  This mirrors the require_auth
     * gate enforced on the direct (non-proxy) read/write dispatchers.
     */
    if (conf->proxy_enable && ctx->auth_done) {
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
     * unless brix_impersonation=map; when active they make the beneath helpers
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
         * No-op unless brix_stream_mirror_url is configured; the primary
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
                   (int) ctx->cur_reqid);
    /* An unrecognized opcode is kXR_InvalidRequest ("Invalid request code"),
     * matching the reference (XrdXrootdProtocol.cc:608); kXR_Unsupported is
     * reserved for a recognized op the backend cannot perform (ENOTSUP). */
    return brix_send_error(ctx, c, kXR_InvalidRequest,
                             "Invalid request code");
}
