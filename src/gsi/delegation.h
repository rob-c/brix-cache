#ifndef XROOTD_GSI_DELEGATION_H
#define XROOTD_GSI_DELEGATION_H

/* ---- GSI X.509 proxy delegation — inbound capture (phase-57 §F6) ----
 *
 * The destination, acting as the GSI server on the client→dest login, runs an
 * extra handshake round after a verified kXGC_cert (gated on xrootd_tpc_delegate):
 * it asks the client to delegate a proxy (kXGS_pxyreq) and captures the signed
 * result (kXGC_sigpxy), so a later TPC pull can present the user's proxy to the
 * source. Built on the verified RFC-3820 crypto in proxy_req.{c,h}. */

#include "gsi_internal.h"
#include <openssl/x509.h>

/*
 * xrootd_gsi_begin_delegation — after a verified kXGC_cert, build a proxy request
 * for `leaf` (the client's EEC/proxy), encrypt it under the persisted GSI session
 * cipher, and send it as kXGS_pxyreq (kXR_authmore). Saves the fresh request key
 * and the client chain PEM on ctx for the kXGC_sigpxy round and sets
 * ctx->gsi_deleg_await. Returns NGX_OK (request sent — auth completes later) or
 * NGX_ERROR. The caller still owns/frees `chain`.
 */
ngx_int_t xrootd_gsi_begin_delegation(xrootd_ctx_t *ctx, ngx_connection_t *c,
                                      ngx_stream_xrootd_srv_conf_t *conf,
                                      X509 *leaf, STACK_OF(X509) *chain);

/*
 * xrootd_gsi_handle_sigpxy — process the client's kXGC_sigpxy: decrypt the main
 * under the session cipher, extract the signed proxy, assemble the delegated
 * credential (signed proxy + saved request key + client chain) into
 * ctx->gsi_deleg_proxy_pem, clear the await flag and cleanse the session key.
 * Returns NGX_OK on success, NGX_ERROR on failure.
 */
ngx_int_t xrootd_gsi_handle_sigpxy(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* Release any delegation state held on the connection (at disconnect / reset). */
void xrootd_gsi_delegation_cleanup(xrootd_ctx_t *ctx);

#endif /* XROOTD_GSI_DELEGATION_H */
