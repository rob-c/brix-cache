/*
 * webdav/auth_token_verify.c — bearer-token signature/issuer verification.
 *
 * WHAT: The four validation steps a parsed bearer token runs through once the
 *       header (or query) transport has yielded its bytes: path+op-scoped
 *       registry validation, single-issuer JWKS validation, the key-rotation
 *       grace retry, and the wt_check_issuer_keys orchestrator that picks
 *       between them.
 *
 * WHY:  Split out of auth_token.c (coding-standards §1, 600-line cap).
 *       auth_token.c keeps credential *transport* (header/query extraction,
 *       query-token redaction, no-store) and post-verification identity
 *       plumbing; the crypto/issuer decision — the part a security reviewer
 *       reads on its own — lives here.
 */


#include "webdav.h"
#include "core/http/http_headers.h"
#include "auth/token/macaroon.h"
#include "auth/token/token_cache.h"
#include "auth/token/worker_cache.h"
#include "auth/token/issuer_registry.h"

#include <string.h>
#include "auth_token_internal.h"


/*
 * wt_validate_registry — run path+op-scoped registry validation for a token.
 *
 * WHAT: Copies the request URI into a bounded NUL-terminated buffer, populates a
 * brix_token_registry_args_t from the location config + parsed macaroon secret,
 * and validates the token against the issuer registry, returning the validator
 * rc (0 = accepted) with verified claims in *claims.
 * WHY: registry authz (phase-59 W1) is path+op dependent and therefore MUST NOT
 * consult the token-keyed caches — it is split out so the orchestrator can route
 * a registry config straight here every request without cache branching.
 * HOW: bound the URI to sizeof(pathz)-1, build the args struct (secret only when
 * slen>0), derive the op class from the HTTP method, and call
 * brix_token_validate_registry() with a throwaway bucket out-param.
 */
static int
wt_validate_registry(const wt_validate_ctx_t *v)
{
    ngx_http_request_t         *r = v->r;
    char                        pathz[2048];
    size_t                      plen;
    int                         bucket = 0;
    brix_token_registry_args_t  ra;

    plen = (r->uri.len < sizeof(pathz) - 1) ? r->uri.len : sizeof(pathz) - 1;
    ngx_memcpy(pathz, r->uri.data, plen);
    pathz[plen] = '\0';

    ra.log             = r->connection->log;
    ra.token           = v->token;
    ra.token_len       = v->token_len;
    ra.reg             = v->conf->token_registry;
    ra.macaroon_secret = v->slen > 0 ? v->secret : NULL;
    ra.secret_len      = (size_t) v->slen;
    ra.clock_skew      = (int) v->conf->common.token_clock_skew;
    ra.claims          = v->claims;

    return brix_token_validate_registry(&ra, pathz,
                                        webdav_token_op_class(r), &bucket);
}

/*
 * wt_validate_jwks — validate a token against the JWKS keys + macaroon secret.
 *
 * WHAT: Builds a brix_token_validate_args_t from the location config's JWKS keys,
 * issuer/audience, clock skew, and the supplied secret, then runs the JWT/macaroon
 * validator, returning its rc (0 = accepted) with verified claims in *claims.
 * WHY: both the primary validation and the old-secret grace-period retry issue an
 * identical validate call differing only in the secret bytes; centralising the
 * args assembly keeps the two callsites byte-identical and off the orchestrator's
 * complexity budget.
 * HOW: populate the args struct (secret NULL when slen<=0), call
 * brix_token_validate(); no side effects beyond writing *claims on success.  The
 * secret/slen are taken as explicit overrides so the grace-period retry can pass
 * the old secret while reusing the same immutable context.
 */
static int
wt_validate_jwks(const wt_validate_ctx_t *v,
                 const u_char *secret, ssize_t slen)
{
    brix_token_validate_args_t  va;

    va.log               = v->r->connection->log;
    va.token             = v->token;
    va.token_len         = v->token_len;
    va.keys              = v->conf->jwks_keys;
    va.key_count         = v->conf->jwks_key_count;
    va.expected_issuer   = (const char *) v->conf->common.token_issuer.data;
    va.expected_audience = (const char *) v->conf->common.token_audience.data;
    va.macaroon_secret   = slen > 0 ? secret : NULL;
    va.secret_len        = (size_t) slen;
    va.clock_skew        = (int) v->conf->common.token_clock_skew;
    va.claims            = v->claims;

    return brix_token_validate(&va);
}

/*
 * wt_grace_retry — retry macaroon validation with the rotated-out old secret.
 *
 * WHAT: When primary validation has failed on a non-registry request and an old
 * macaroon secret is configured, parses it and re-runs JWKS/macaroon validation
 * with the old key, logging an informational note on success.  Returns the retry
 * rc, or the unchanged incoming rc when the retry is not applicable.
 * WHY: an nginx -s reload that rotates the macaroon secret would otherwise hard-
 * break every in-flight macaroon; accepting the old secret until tokens expire
 * gives graceful migration.  Registry validation has no shared-secret concept and
 * is excluded.
 * HOW: return prev_rc unchanged unless (prev_rc!=0 && !via_registry && old secret
 * present); parse the old secret, and only if it parses (>0) call wt_validate_jwks
 * with it, emitting the grace-period NGX_LOG_INFO line when it now accepts.
 */
static int
wt_grace_retry(const wt_validate_ctx_t *v, int via_registry, int prev_rc)
{
    ngx_http_brix_webdav_loc_conf_t *conf = v->conf;
    u_char                           old_secret[64];
    ssize_t                          old_slen;
    int                              rc;

    /* Grace-period fallback: if the primary secret rejected a macaroon token
     * and an old secret is configured, try validating with the old key.
     * This lets in-flight tokens survive nginx -s reload during key rotation. */
    if (prev_rc == 0 || via_registry || conf->common.token_macaroon_secret_old.len == 0) {
        return prev_rc;
    }

    old_slen = brix_macaroon_secret_parse(
        (const char *) conf->common.token_macaroon_secret_old.data,
        conf->common.token_macaroon_secret_old.len,
        old_secret, sizeof(old_secret));
    if (old_slen <= 0) {
        return prev_rc;
    }

    rc = wt_validate_jwks(v, old_secret, old_slen);
    if (rc == 0) {
        ngx_log_error(NGX_LOG_INFO, v->r->connection->log, 0,
                      "brix_webdav: macaroon accepted via old secret "
                      "(grace-period key rotation)");
    }
    return rc;
}

/*
 * wt_check_issuer_keys — resolve token validity via caches, registry or keys.
 *
 * WHAT: Determines whether the presented token is valid, filling *claims and
 * flagging *cache_hit / *via_registry for the caller's caching decision.  Returns
 * 0 when the token is accepted (from L1, L2, registry, JWKS, or the grace-period
 * old-secret retry), non-zero when rejected.
 * WHY: this is the crypto/lookup hot path — consulting the cheapest source first
 * (per-worker L1, then cross-worker L2 SHM) avoids re-running signature checks and
 * JSON parsing on the event loop under load.  Registry authz is path+op dependent
 * so it MUST bypass the token-keyed caches and re-validate every request.
 * HOW: lazily create L1; on a non-registry request probe L1 then L2 (promoting an
 * L2 hit into L1); otherwise validate via registry or JWKS; finally apply the
 * old-secret grace retry.  Only successfully validated claims are ever cached, and
 * caching itself is left to the caller.
 */
int
wt_check_issuer_keys(const wt_validate_ctx_t *v,
                     int *cache_hit, int *via_registry)
{
    ngx_http_brix_webdav_loc_conf_t *conf = v->conf;
    const char                      *token = v->token;
    size_t                           token_len = v->token_len;
    brix_token_claims_t             *claims = v->claims;
    int                              rc;

    /*
     * Token-validation caches, consulted cheapest-first so token auth does not
     * re-run crypto + JSON parsing on the event loop under load:
     *   L1 — always-on, per-worker, lockless (lazily created here).  A hit skips
     *        BOTH the signature verification AND the L2 spinlock.
     *   L2 — the optional cross-worker SHM cache.  An L2 hit is promoted into L1
     *        so the next presentation to this worker is an L1 hit.
     * Only successfully validated claims are ever cached.
     */
    *cache_hit = 0;

    /* The token-validity caches are keyed on the token alone.  Registry authz
     * (phase-59 W1) is path+op dependent, so a registry config MUST bypass the
     * caches and re-run the per-request base_path/strategy check every time. */
    *via_registry = (conf->token_registry != NULL);

    if (conf->token_l1 == NULL) {
        conf->token_l1 = brix_token_l1_create(ngx_cycle->pool,
                                                BRIX_TOKEN_L1_SLOTS);
    }

    if (!*via_registry
        && brix_token_l1_lookup(conf->token_l1, token, token_len, claims))
    {
        rc = 0;
        *cache_hit = 1;
    } else if (!*via_registry && conf->token_cache_kv != NULL
               && brix_token_cache_lookup(conf->token_cache_kv,
                                            token, token_len, claims))
    {
        rc = 0;
        *cache_hit = 1;
        brix_token_l1_store(conf->token_l1, token, token_len, claims);
    } else if (*via_registry) {
        rc = wt_validate_registry(v);
    } else {
        rc = wt_validate_jwks(v, v->secret, v->slen);
    }

    return wt_grace_retry(v, *via_registry, rc);
}

/*
 * wt_check_claims — persist verified token claims onto the request context.
 *
 * WHAT: Marks the context token-authenticated, retains the raw JWT bytes for
 * backend passthrough, records the identity claims (sub, scopes) and the DN, and
 * copies the scope list.  Returns NGX_OK, or NGX_HTTP_INTERNAL_SERVER_ERROR on an
 * allocation failure.
 * WHY: downstream scope enforcement (webdav_check_token_scope) and backend
 * credential passthrough read these fields; centralising the store keeps the
 * orchestrator a flat success path and matches the phase-70 §5.4 passthrough rule
 * that the JWT bytes be copied onto r->pool (the wire buffer may be rewritten,
 * e.g. by query-token redaction) and never logged.
 * HOW: set verified/token_auth/auth_source; pnalloc+copy the bearer bytes; call
 * brix_identity_set_token_claims(); cpystrn the subject into ctx->dn; copy up to
 * BRIX_MAX_TOKEN_SCOPES scopes; emit the token-auth-OK INFO line.
 */
