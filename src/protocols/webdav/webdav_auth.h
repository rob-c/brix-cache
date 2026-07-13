/*
 * webdav/webdav_auth.h
 *
 * WebDAV authentication surface: SSL ex_data index init, CA-store build from
 * cadir/cafile/crl, the GSI/X.509 proxy-cert and Bearer-token auth gates, the
 * token write-scope check, and postconfig PKI-path validation.  Split out of
 * webdav.h so the auth surface is grouped by concern and individually
 * reviewable.  Includes webdav.h for the shared request/config types.
 */

#ifndef NGX_HTTP_BRIX_WEBDAV_AUTH_H
#define NGX_HTTP_BRIX_WEBDAV_AUTH_H

#include "webdav.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_ctx_t for webdav_vfs_bind_deleg */

/* Authentication */
/* Allocate the global SSL/SSL_SESSION ex_data indices used to cache TLS auth
 * results; call once at postconfig.  NGX_OK / NGX_ERROR. */
ngx_int_t webdav_auth_init_ssl_indices(ngx_log_t *log);
/* Build an X509_STORE from conf->cadir/cafile/crl (no proxy-cert chains for
 * plain WebDAV x509).  Returns the store (caller/postconfig owns it) or NULL;
 * *crl_count_out receives the number of CRLs loaded. */
X509_STORE *webdav_build_ca_store(ngx_log_t *log,
    ngx_http_brix_webdav_loc_conf_t *conf, int *crl_count_out);
/* Auth gate (see HELPERS): verify the peer's GSI/X.509 (proxy) cert against
 * conf->ca_store, allocating+caching the req ctx and identity.  Result is
 * memoised per TLS session.  NGX_OK; 403 (no/invalid cert or non-TLS); 500. */
ngx_int_t webdav_verify_proxy_cert(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf);
/* Auth gate (see HELPERS): validate the Bearer token (JWKS JWT or macaroon,
 * with old-secret grace-period fallback) and stash claims/scopes in the req
 * ctx.  NGX_OK; NGX_DECLINED if no token/keys configured (try other auth);
 * 401 invalid; 500. */
ngx_int_t webdav_verify_bearer_token(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf);
/* For token-authed data-access methods (read AND write), require a scope
 * covering r->uri (matched against the decoded URI path, not the filesystem
 * path).  Op class (read vs write) is derived from the HTTP method.  NGX_OK
 * if granted OR auth was not token-based; NGX_HTTP_FORBIDDEN otherwise. */
ngx_int_t webdav_check_token_scope(ngx_http_request_t *r,
    const char *method_name);
/* Postconfig-time validation of CA/CRL paths so misconfiguration fails
 * `nginx -t`.  NGX_OK / NGX_ERROR. */
ngx_int_t webdav_check_pki_consistency(ngx_log_t *log,
    ngx_http_brix_webdav_loc_conf_t *conf);

/* Phase-70 §5.1/§5.4: bind the request's captured forwardable credential
 * (raw bearer JWT and/or user-supplied full x509 proxy PEM, both lifted onto the
 * req ctx at the auth gate) onto an already-cred-bound VFS ctx, using the
 * export's resolved mode (conf->common.backend_delegation). A no-op when the
 * export is on the default SELECT path or nothing forwardable was captured.
 * Called at every WebDAV brix_vfs_ctx_bind_backend_cred site so a delegated
 * export authenticates the backend leg as the inbound user. */
void webdav_vfs_bind_deleg(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, brix_vfs_ctx_t *vctx);

#endif /* NGX_HTTP_BRIX_WEBDAV_AUTH_H */
