#include "handshake.h"

/* brix_dispatch_signing_opcode — signing dispatcher entry point (HMAC-SHA256 sigver inspection)
 * WHAT: Called from src/handshake/dispatch.c as the final routing phase. Handles only kXR_sigver requests — verifies pending HMAC-SHA256 signatures before any request is processed. Returns BRIX_DISPATCH_CONTINUE if opcode ≠ kXR_sigver (always passes to other dispatchers for non-signing opcodes). Requires login authentication before processing sigver envelope.
 *
 * HOW: Single opcode check (ctx->cur_reqid == kXR_sigver) → login gate via brix_dispatch_require_login() → call brix_handle_sigver() to verify HMAC-SHA256 envelope; returns BRIX_DISPATCH_CONTINUE for all other opcodes.
 */
ngx_int_t
brix_dispatch_signing_opcode(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_int_t rc;

    if (ctx->cur_reqid != kXR_sigver) {
        return BRIX_DISPATCH_CONTINUE;
    }

    rc = brix_dispatch_require_login(ctx, c);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    return brix_handle_sigver(ctx, c);
}
