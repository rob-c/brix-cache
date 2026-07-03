/*
 * tpc_config.h — HTTP-TPC location configuration types
 *
 * Defines ngx_http_brix_tpc_conf_t, the per-location TPC configuration
 * block used by tpc_cred.c for OAuth2/OIDC credential delegation.
 */

#ifndef _TPC_CONFIG_H
#define _TPC_CONFIG_H 1

#include <ngx_core.h>
#include <ngx_http.h>

/* ------------------------------------------------------------------ */
/*  TPC credential-delegation configuration                           */
/* ------------------------------------------------------------------ */

typedef struct {
    /* OAuth2/OIDC token endpoint for RFC 8693 token exchange. */
    ngx_str_t  token_endpoint;

    /* OAuth2 client ID (optional, for confidential clients). */
    ngx_str_t  token_client_id;

    /* OAuth2 client secret (optional, for confidential clients). */
    ngx_str_t  token_client_secret;

    /* Scope string to request during token exchange (e.g. "storage.read"). */
    ngx_str_t  token_scope;
} ngx_http_brix_tpc_conf_t;

#endif /* _TPC_CONFIG_H */
