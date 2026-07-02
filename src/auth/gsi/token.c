#include "gsi_internal.h"
#include "protocols/root/session/registry.h"
#include "auth/token/macaroon.h"
#include "auth/token/token_cache.h"
#include "auth/token/worker_cache.h"
#include "auth/token/issuer_registry.h"

/*
 * Bearer-token (JWT/WLCG) authentication for the "ztn" credential type.
 */
/*
 * WHAT: xrootd_handle_token_auth() — handles kXR_auth with protocol "ztn"
 *       (WLCG/SciToken bearer JWT). Extracts token from payload, validates
 *       signature against JWKS keys + issuer + audience claims.
 *
 * WHY: Single-round authentication — no DH exchange needed. The client
 *      submits a pre-signed JWT and the server verifies it against trusted
 *      public keys (RSA/ECDSA) configured via xrootd_jwks_keys directive.
 *
 * HOW: 1) Extract token from payload; 2) Parse macaroon secret if configured;
 *      3) Validate JWT signature + claims; 4) Grace-period fallback with old
 *      secret for key rotation during reload; 5) On success set ctx->auth_done,
 *      extract DN/groups/scopes from claims, track metrics, register session.
 *
 * Grace-period key rotation: if the primary macaroon secret rejects a token
 * and an old secret is configured, retry validation with the old key.
 *
 * WHY: Allows in-flight tokens to survive nginx -s reload during key rotation.
 *      Without this fallback, tokens signed by the previous secret would be
 *      rejected immediately after reload, breaking active client sessions.
 *
 * Postconditions on success:
 *
 * WHY: ctx->auth_done = 1 enables subsequent authenticated operations.
 *      ctx->bearer_token stores raw token for proxy auth-bridging to upstream.
 *      DN, vo_list, primary_vo extracted from JWT claims (sub/groups).
 *      Token scopes stored for per-path scope checks. Unique user and VO
 *      tracked in shared-memory metrics counters.
 *
 * Return values: NGX_OK on successful validation, kXR_NotAuthorized error
 * on empty payload, signature failure, or issuer/audience mismatch. */

ngx_int_t
xrootd_handle_token_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    xrootd_token_claims_t claims;
    const char           *token;
    size_t                token_len;
    int                   rc, i;

    if (ctx->payload == NULL || ctx->cur_dlen <= 4) {
        xrootd_log_access(ctx, c, "AUTH", "-", "ztn",
                          0, kXR_NotAuthorized, "empty token payload", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty bearer token");
    }

    token = (const char *) (ctx->payload + 4);
    token_len = ctx->cur_dlen - 4;

    while (token_len > 0 && token[token_len - 1] == '\0') {
        token_len--;
    }

    if (token_len == 0) {
        xrootd_log_access(ctx, c, "AUTH", "-", "ztn",
                          0, kXR_NotAuthorized, "empty token payload", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty bearer token");
    }

    u_char                secret[64];
    ssize_t               slen = 0;

    if (conf->token_macaroon_secret.len) {
        slen = xrootd_macaroon_secret_parse(
            (const char *) conf->token_macaroon_secret.data,
            conf->token_macaroon_secret.len, secret, sizeof(secret));
    }

    /*
     * Token-validation caches, consulted cheapest-first so token auth does not
     * re-run RSA/ECDSA verification on the event loop under load:
     *   L1 — always-on, per-worker, lockless (lazily created here).  A hit skips
     *        both the signature verification AND the L2 spinlock.
     *   L2 — the optional cross-worker SHM cache; an L2 hit is promoted into L1.
     * Only successfully verified claims are ever cached.
     */
    int cache_hit = 0;

    /* phase-59 W1: a registry config validates per-issuer; bypass the
     * token-keyed caches. The matched issuer is stored on the identity so the
     * per-path policy check enforces its base_path. */
    const xrootd_token_issuer_t *reg_issuer = NULL;
    int via_registry = (conf->token_registry != NULL);

    if (conf->token_l1 == NULL) {
        conf->token_l1 = xrootd_token_l1_create(ngx_cycle->pool,
                                                XROOTD_TOKEN_L1_SLOTS);
    }

    if (!via_registry
        && xrootd_token_l1_lookup(conf->token_l1, token, token_len, &claims))
    {
        rc = 0;
        cache_hit = 1;
    } else if (!via_registry && conf->token_cache_kv != NULL
               && xrootd_token_cache_lookup(conf->token_cache_kv,
                                            token, token_len, &claims))
    {
        rc = 0;
        cache_hit = 1;
        xrootd_token_l1_store(conf->token_l1, token, token_len, &claims);
    } else if (via_registry) {
        rc = xrootd_token_validate_registry_authn(c->log, token, token_len,
                conf->token_registry, slen > 0 ? secret : NULL, (size_t) slen,
                &claims, &reg_issuer);
    } else {
        rc = xrootd_token_validate(c->log, token, token_len,
                                   conf->jwks_keys, conf->jwks_key_count,
                                   (const char *) conf->token_issuer.data,
                                   (const char *) conf->token_audience.data,
                                   slen > 0 ? secret : NULL, (size_t) slen,
                                   &claims);
    }

    /* Grace-period fallback: if the primary secret rejected a macaroon token
     * and an old secret is configured, try validating with the old key.
     * This lets in-flight tokens survive nginx -s reload during key rotation. */
    if (rc != 0 && !via_registry && conf->token_macaroon_secret_old.len) {
        u_char  old_secret[64];
        ssize_t old_slen;

        old_slen = xrootd_macaroon_secret_parse(
            (const char *) conf->token_macaroon_secret_old.data,
            conf->token_macaroon_secret_old.len,
            old_secret, sizeof(old_secret));

        if (old_slen > 0) {
            rc = xrootd_token_validate(c->log, token, token_len,
                                       conf->jwks_keys, conf->jwks_key_count,
                                       (const char *) conf->token_issuer.data,
                                       (const char *) conf->token_audience.data,
                                       old_secret, (size_t) old_slen,
                                       &claims);
            if (rc == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "xrootd: macaroon accepted via old secret "
                              "(grace-period key rotation)");
            }
        }
    }

    if (rc != 0) {
        xrootd_log_access(ctx, c, "AUTH", "-", "ztn",
                          0, kXR_NotAuthorized, "token validation failed", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "bearer token validation failed");
    }

    /* Cache the freshly verified claims for subsequent presentations (L1 always,
     * L2 when a SHM zone is configured).  Registry tokens are never cached: the
     * per-path decision is not a function of the token alone. */
    if (!cache_hit && !via_registry) {
        xrootd_token_l1_store(conf->token_l1, token, token_len, &claims);
        if (conf->token_cache_kv != NULL) {
            xrootd_token_cache_store(conf->token_cache_kv, token, token_len,
                                     &claims);
        }
    }

    ctx->token_auth = 1;
    ctx->auth_done = 1;
    if (ctx->identity != NULL
        && xrootd_identity_set_token_claims(ctx->identity, c->pool, &claims)
           != NGX_OK)
    {
        return xrootd_send_error(ctx, c, kXR_NoMemory,
                                 "identity allocation failed");
    }

    /* phase-59 W1: record the matched issuer so the per-path scope check
     * (xrootd_identity_check_token_scope) enforces its base_path. */
    if (ctx->identity != NULL && reg_issuer != NULL) {
        ctx->identity->token_issuer = (void *) reg_issuer;
    }

    /* Save raw token so proxy auth-bridging can forward it to the upstream. */
    if (token_len > 0 && token_len < sizeof(ctx->bearer_token) - 1) {
        ngx_memcpy(ctx->bearer_token, token, token_len);
        ctx->bearer_token[token_len] = '\0';
    }

    ngx_cpystrn((u_char *) ctx->dn, (u_char *) claims.sub, sizeof(ctx->dn));

    if (claims.groups[0]) {
        const char *comma;
        size_t      pvo_len;

        ngx_cpystrn((u_char *) ctx->vo_list,
                    (u_char *) claims.groups,
                    sizeof(ctx->vo_list));

        comma = strchr(claims.groups, ',');
        pvo_len = comma ? (size_t) (comma - claims.groups)
                        : strlen(claims.groups);
        if (pvo_len >= sizeof(ctx->primary_vo)) {
            pvo_len = sizeof(ctx->primary_vo) - 1;
        }
        ngx_memcpy(ctx->primary_vo, claims.groups, pvo_len);
        ctx->primary_vo[pvo_len] = '\0';
    }

    /* Track unique user and VO at auth completion. */
    {
        ngx_xrootd_metrics_t *shm = xrootd_metrics_shared();
        if (shm != NULL) {
            size_t vo_len = strlen(ctx->primary_vo);
            if (vo_len > 0 && vo_len < sizeof(ctx->primary_vo)) {
                xrootd_track_vo_activity(shm, ctx->primary_vo, 0, 0);
                ngx_uint_t vi;
                for (vi = 0; vi < XROOTD_VO_MAX_TRACKED; vi++) {
                    if (ngx_strncmp(shm->vo_global.slots[vi].name, ctx->primary_vo,
                                    XROOTD_VO_NAME_LEN) == 0)
                    {
                        XROOTD_ATOMIC_INC(&shm->vo_global.slots[vi].requests_total);
                        break;
                    }
                }
            }
            xrootd_track_unique_user(shm, ctx->dn, strlen(ctx->dn));
        }
    }

    xrootd_session_register(ctx->sessid, ctx->dn, ctx->vo_list, 1);

    ctx->token_scope_count = claims.scope_count;
    for (i = 0; i < claims.scope_count && i < XROOTD_MAX_TOKEN_SCOPES; i++) {
        ctx->token_scopes[i] = claims.scopes[i];
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: token auth ok sub=\"%s\" scopes=%d groups=\"%s\"",
                  claims.sub, claims.scope_count, claims.groups);

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", claims.sub, 0);
}
