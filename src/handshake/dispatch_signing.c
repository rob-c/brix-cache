#include "handshake.h"

/* xrootd_dispatch_signing_opcode — signing dispatcher entry point (HMAC-SHA256 sigver inspection)
 * WHAT: Called from src/handshake/dispatch.c as the final routing phase. Handles only kXR_sigver requests — verifies pending HMAC-SHA256 signatures before any request is processed. Returns XROOTD_DISPATCH_CONTINUE if opcode ≠ kXR_sigver (always passes to other dispatchers for non-signing opcodes). Requires login authentication before processing sigver envelope.
 *
 * HOW: Single opcode check (ctx->cur_reqid == kXR_sigver) → login gate via xrootd_dispatch_require_login() → call xrootd_handle_sigver() to verify HMAC-SHA256 envelope; returns XROOTD_DISPATCH_CONTINUE for all other opcodes.
 */
ngx_int_t
xrootd_dispatch_signing_opcode(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_int_t rc;

    if (ctx->cur_reqid != kXR_sigver) {
        return XROOTD_DISPATCH_CONTINUE;
    }

    rc = xrootd_dispatch_require_login(ctx, c);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        return rc;
    }

    return xrootd_handle_sigver(ctx, c);
}
