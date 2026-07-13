/*
 * exchange.h — RFC 8693 OAuth2 token-exchange client (public API).
 *
 * WHAT: Declares brix_token_exchange(), which trades a subject access token
 *       for a new access token scoped/audienced for a backend origin.
 * WHY:  Phase-70 full credential delegation §5.4 — when a backend audience is
 *       node-bound the cache must mint an origin-specific token rather than
 *       replay the client's token verbatim.
 * HOW:  brix_token_exchange() POSTs an RFC 8693 grant to the configured OAuth2
 *       token endpoint and returns the minted access_token allocated from the
 *       caller's pool. All parameters are ngx_str_t; nothing is logged that
 *       could leak a token or the client secret.
 */

#ifndef BRIX_AUTH_TOKEN_EXCHANGE_H
#define BRIX_AUTH_TOKEN_EXCHANGE_H

#include <ngx_core.h>

/*
 * Static configuration for a token-exchange endpoint.
 *   endpoint      — absolute https:// URL of the OAuth2 token endpoint.
 *   client_id     — OAuth2 client id (empty => no client authentication).
 *   client_secret — OAuth2 client secret (paired with client_id).
 */
typedef struct {
    ngx_str_t endpoint;
    ngx_str_t client_id;
    ngx_str_t client_secret;
} brix_token_exchange_conf_t;

/*
 * Perform an RFC 8693 token exchange.
 *
 *   pool          — allocation arena; out_token is allocated here.
 *   subject_token — the client's access token to exchange (required).
 *   audience      — target audience for the minted token (optional, may be
 *                   NULL/empty). Also sent as `resource`.
 *   scope         — requested scope (optional, may be NULL/empty).
 *   cf            — endpoint + client credentials (required, endpoint set).
 *   out_token     — on NGX_OK, receives the minted access_token (pool-copied,
 *                   NUL-terminated at out_token->data[out_token->len]).
 *   log           — error log target.
 *
 * Returns NGX_OK on success, NGX_ERROR otherwise (reason logged, never the
 * token or secret).
 */
ngx_int_t brix_token_exchange(ngx_pool_t *pool,
                              const ngx_str_t *subject_token,
                              const ngx_str_t *audience,
                              const ngx_str_t *scope,
                              const brix_token_exchange_conf_t *cf,
                              ngx_str_t *out_token,
                              ngx_log_t *log);

#endif /* BRIX_AUTH_TOKEN_EXCHANGE_H */
