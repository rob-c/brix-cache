#ifndef BRIX_WEBDAV_TPC_CRED_INTERNAL_H
#define BRIX_WEBDAV_TPC_CRED_INTERNAL_H

#include "tpc_cred.h"
#include "webdav.h"

/* Maximum token length (RFC 6750: opaque tokens rarely exceed 1 KiB). */
#define TPC_CRED_MAX_TOKEN_LEN  4096

ngx_int_t tpc_cred_parse_token_response(ngx_http_request_t *r,
    const char *json, ngx_str_t *token_out);

/*
 * oidc-agent delegation fetch (tpc_cred_oidc.c) — spawns the oidc-agent
 * fork/exec pipeline and returns an access token in *token_out.
 */
ngx_int_t tpc_cred_oidc_agent_fetch(ngx_http_request_t *r,
    const char *source_url, const char *scope, ngx_str_t *token_out);

/*
 * RFC 8693 token-exchange (tpc_cred_exchange.c) — POSTs a token-exchange
 * request to the configured endpoint and returns the token in *token_out.
 */
ngx_int_t tpc_cred_rfc8693_exchange(ngx_http_request_t *r,
    const char *subject_token, const char *source_url, const char *scope,
    const char *token_endpoint, const char *client_id,
    const char *client_secret, ngx_str_t *token_out);

#endif /* BRIX_WEBDAV_TPC_CRED_INTERNAL_H */
