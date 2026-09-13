#ifndef BRIX_SESSION_H
#define BRIX_SESSION_H

#include "core/ngx_brix_module.h"

/*
 * Session lifecycle — the XRootD login sequence every client must complete:
 *
 *   Client                           Server
 *   ──────                           ──────
 *   → kXR_protocol (capabilities)   ← kXR_ok (server caps, TLS flags)
 *   → kXR_login    (username)        ← kXR_ok (session ID) or kXR_authmore
 *   → kXR_auth     (credentials)    ← kXR_ok or kXR_authmore (multi-round GSI)
 *   → kXR_open / kXR_read / …       ← responses
 *   → kXR_endsess                   ← kXR_ok (connection then closes)
 *
 * kXR_protocol must be the first request.  kXR_ping is allowed at any time.
 * All other opcodes require logged_in=1 AND auth_done=1 in brix_ctx_t.
 *
 * When brix_auth=none, auth_done is set immediately after login (no kXR_auth
 * round-trip required).  When brix_auth=gsi or token, the client must send
 * kXR_auth before any file operations.
 *
 * GSI uses multiple kXR_auth / kXR_authmore round-trips to exchange DH keys,
 * certificates, and a signed random challenge.  The steps are tracked by the
 * XrdSutBuffer step numbers in protocol/gsi.h.
 */

/* ---- Function: brix_handle_protocol() ----
 * WHAT: kXR_protocol handler — first opcode every client must send.
 *   - Advertises server capabilities (TLS, auth modes, version)
 *   - Negotiates TLS upgrade flags
 *   - Returns NGX_OK on success, NGX_ERROR if incompatible
 *   - Called immediately after TCP connect, before any other opcode */
ngx_int_t brix_handle_protocol(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* ---- Function: brix_handle_login() ----
 * WHAT: kXR_login handler — accepts client username, generates session ID.
 *   - Sets logged_in=1 in context
 *   - If auth required (gsi/token): returns kXR_authmore for credential round-trip
 *   - If auth_mode=none: sets auth_done=1 immediately
 *   - Session ID stored in shared memory for cross-worker lookup */
ngx_int_t brix_handle_login(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* ---- Function: brix_handle_ping() ----
 * WHAT: kXR_ping handler — liveness check.
 *   - No logged_in/auth_done state required
 *   - Responds with kXR_ok + empty body
 *   - Works at any session lifecycle point (including pre-login)
 *   - Clients use for health monitoring during transfers/idle */
ngx_int_t brix_handle_ping(brix_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: brix_handle_endsess() ----
 * WHAT: kXR_endsess handler — graceful session teardown.
 *   - Flushes pending I/O operations
 *   - Unregisters session from shared memory registry
 *   - Clears all published handles via brix_session_handle_unpublish_all()
 *   - Closes connection
 *   - Called by client request or after auth_done=1
 *   - Prevents stale handle references */
ngx_int_t brix_handle_endsess(brix_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: brix_handle_sigver() ----
 * WHAT: kXR_sigver handler — validates HMAC-SHA256 request signing envelope.
 *   - Required only for GSI sessions (brix_auth=gsi)
 *   - Verifies signature covers opcode+body
 *   - Uses session secret from DH exchange
 *   - Returns kXR_ok on valid, kXR_notAuthorized on invalid/missing
 *   - Prevents unauthorized opcode injection */
ngx_int_t brix_handle_sigver(brix_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: gsi_find_bucket() ----
 * WHAT: Scans XrdSutBuffer payload for bucket of given type.
 *   - Searches for kXRS_* codes (protocol/gsi.h)
 *   - Returns pointer + length into raw payload
 *   - Used by GSI certificate parsing and response building
 *   - Locates specific data buckets in multi-bucket payloads
 *   - Returns 0 on success (data_out/len_out populated), -1 if not found */
int gsi_find_bucket(const u_char *payload, size_t plen,
    uint32_t target_type, const u_char **data_out, size_t *len_out);

/* ---- Function: brix_gsi_parse_x509() ----
 * WHAT: Extracts DER-encoded certificate chain from kXRS_x509 bucket.
 *   - Returns OpenSSL STACK_OF(X509)
 *   - Caller must free with sk_X509_pop_free()
 *   - Used during GSI auth for client proxy certificates
 *   - Returns NULL if bucket not found or parsing fails
 */
STACK_OF(X509) *brix_gsi_parse_x509(brix_ctx_t *ctx,
    ngx_connection_t *c);

/* ---- Function: brix_handle_auth() ----
 * WHAT: kXR_auth handler — multi-round authentication dispatcher.
 *   - Routes to GSI or token auth based on configured mode
 *   - GSI: exchanges DH keys, certs, signed challenge
 *     - Multiple kXR_auth/kXR_authmore round-trips
 *     - Tracked by XrdSutBuffer step numbers (protocol/gsi.h)
 *   - Token: validates JWT against JWKS endpoint
 *     - Checks signature, scope, expiry, issuer
 *   - Sets auth_done=1 on success, enabling file operations
 */
ngx_int_t brix_handle_auth(brix_ctx_t *ctx, ngx_connection_t *c);

/* Phase 51 (E4): per-worker in-flight GSI-handshake admission gauge (gsi/auth.c).
 * _admit returns 1 if the new handshake is admitted under `cap` (0 = unlimited)
 * and marks ctx->login.gsi_counted; 0 if it should be shed.  _release frees the slot
 * exactly once (gated by ctx->login.gsi_counted) — called at auth completion AND from
 * the disconnect funnel so the gauge can never leak. */
ngx_int_t brix_gsi_inflight_admit(brix_ctx_t *ctx, ngx_int_t cap);
void      brix_gsi_inflight_release(brix_ctx_t *ctx);

#endif /* BRIX_SESSION_H */
