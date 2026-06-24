#ifndef XROOTD_SESSION_H
#define XROOTD_SESSION_H

#include "../ngx_xrootd_module.h"

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
 * All other opcodes require logged_in=1 AND auth_done=1 in xrootd_ctx_t.
 *
 * When xrootd_auth=none, auth_done is set immediately after login (no kXR_auth
 * round-trip required).  When xrootd_auth=gsi or token, the client must send
 * kXR_auth before any file operations.
 *
 * GSI uses multiple kXR_auth / kXR_authmore round-trips to exchange DH keys,
 * certificates, and a signed random challenge.  The steps are tracked by the
 * XrdSutBuffer step numbers in protocol/gsi.h.
 */

/* ---- Function: xrootd_handle_protocol() ----
 * WHAT: kXR_protocol handler — first opcode every client must send. Advertises server capabilities (TLS support, auth modes, version) and negotiates TLS upgrade flags. Returns NGX_OK on successful capability exchange, NGX_ERROR if protocol version incompatible or TLS negotiation fails. Called immediately after TCP connection establishment before any other opcode. */
ngx_int_t xrootd_handle_protocol(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* ---- Function: xrootd_handle_login() ----
 * WHAT: kXR_login handler — accepts client username and generates unique session ID. Sets logged_in=1 in context; if auth mode requires credentials (gsi/token), initiates auth round-trip by returning kXR_authmore prompting client to send kXR_auth. If auth_mode=none, sets auth_done=1 immediately allowing subsequent file operations without credential exchange. Session ID stored in shared memory registry for cross-worker lookup by bound stream connections. */
ngx_int_t xrootd_handle_login(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* ---- Function: xrootd_handle_ping() ----
 * WHAT: kXR_ping handler — liveness check allowing clients to verify server is still responsive without requiring logged_in/auth_done state. Responds with kXR_ok and empty body at any point in session lifecycle including before login completion. Called by clients monitoring connection health during long transfers or idle periods. */
ngx_int_t xrootd_handle_ping(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: xrootd_handle_endsess() ----
 * WHAT: kXR_endsess handler — graceful session teardown. Flushes any pending I/O operations, unregisters session from shared memory registry clearing all published handles via xrootd_session_handle_unpublish_all(), then closes connection. Called by client explicitly requesting session end or after auth_done=1 with no further requests expected. Prevents stale handle references remaining in shared table after session termination. */
ngx_int_t xrootd_handle_endsess(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: xrootd_handle_sigver() ----
 * WHAT: kXR_sigver handler — validates HMAC-SHA256 request signing envelope before routing the next opcode to its handler. Only required for GSI sessions (xrootd_auth=gsi). Verifies signature covers opcode+body using session secret derived from DH exchange; returns kXR_ok on valid signature, kXR_notAuthorized on invalid or missing signature. Prevents unauthorized opcode injection in authenticated sessions. */
ngx_int_t xrootd_handle_sigver(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: gsi_find_bucket() ----
 * WHAT: Scans an XrdSutBuffer payload for a bucket of a given type (one of the kXRS_* codes in protocol/gsi.h), returning pointer and length into the raw payload. Used by GSI certificate parsing and response building to locate specific data buckets within multi-bucket payloads. Returns 0 on success with data_out/len_out populated, -1 if target bucket not found in payload. */
int gsi_find_bucket(const u_char *payload, size_t plen,
    uint32_t target_type, const u_char **data_out, size_t *len_out);

/* ---- Function: xrootd_gsi_parse_x509() ----
 * WHAT: Extracts the DER-encoded certificate chain from a kXRS_x509 bucket within an XrdSutBuffer payload and returns it as an OpenSSL STACK_OF(X509). The caller is responsible for freeing the stack with sk_X509_pop_free(). Used during GSI authentication round-trips to parse client-provided proxy certificates. Returns NULL if no kXRS_x509 bucket found in payload or parsing fails. */
STACK_OF(X509) *xrootd_gsi_parse_x509(xrootd_ctx_t *ctx,
    ngx_connection_t *c);

/* ---- Function: xrootd_handle_auth() ----
 * WHAT: kXR_auth handler — multi-round authentication dispatcher routing to GSI or token auth based on configured auth mode. For GSI: exchanges DH keys, certificates, and signed random challenge via multiple kXR_auth/kXR_authmore round-trips tracked by XrdSutBuffer step numbers in protocol/gsi.h. For tokens: validates JWT bearer token against JWKS endpoint checking signature, scope (storage.read/storage.write), expiry, and issuer. Sets auth_done=1 upon successful authentication enabling subsequent file operations. */
ngx_int_t xrootd_handle_auth(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* Phase 51 (E4): per-worker in-flight GSI-handshake admission gauge (gsi/auth.c).
 * _admit returns 1 if the new handshake is admitted under `cap` (0 = unlimited)
 * and marks ctx->gsi_counted; 0 if it should be shed.  _release frees the slot
 * exactly once (gated by ctx->gsi_counted) — called at auth completion AND from
 * the disconnect funnel so the gauge can never leak. */
ngx_int_t xrootd_gsi_inflight_admit(xrootd_ctx_t *ctx, ngx_int_t cap);
void      xrootd_gsi_inflight_release(xrootd_ctx_t *ctx);

#endif /* XROOTD_SESSION_H */
