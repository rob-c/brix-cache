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

/* kXR_protocol — advertise server capabilities and negotiate TLS */
ngx_int_t xrootd_handle_protocol(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* kXR_login — accept username, generate session ID, start auth if required */
ngx_int_t xrootd_handle_login(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* kXR_ping — liveness check; responds kXR_ok with empty body */
ngx_int_t xrootd_handle_ping(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* kXR_endsess — graceful teardown; flushes pending I/O then closes */
ngx_int_t xrootd_handle_endsess(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* kXR_sigver — validate the HMAC envelope before routing the next request */
ngx_int_t xrootd_handle_sigver(xrootd_ctx_t *ctx, ngx_connection_t *c);

/*
 * kXR_auth — multi-round authentication dispatcher.
 * Routes to GSI or token auth based on the configured auth mode.
 *
 * gsi_find_bucket() scans an XrdSutBuffer payload for a bucket of a given
 * type (one of the kXRS_* codes in protocol/gsi.h), returning a pointer and
 * length into the raw payload.  Used by GSI cert parsing and response building.
 *
 * xrootd_gsi_parse_x509() extracts the DER-encoded certificate chain from a
 * kXRS_x509 bucket and returns it as an OpenSSL STACK_OF(X509).  The caller
 * is responsible for freeing the stack with sk_X509_pop_free().
 */
int gsi_find_bucket(const u_char *payload, size_t plen,
    uint32_t target_type, const u_char **data_out, size_t *len_out);
STACK_OF(X509) *xrootd_gsi_parse_x509(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
ngx_int_t xrootd_handle_auth(xrootd_ctx_t *ctx, ngx_connection_t *c);

#endif /* XROOTD_SESSION_H */
