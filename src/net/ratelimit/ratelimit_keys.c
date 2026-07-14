/*
 * ratelimit_keys.c — Phase 25 key extraction.
 *
 * Two planes expose identity through different context structs, so a pair of
 * extraction functions produce the canonical "<type>:<value>" key string used
 * for the rbtree lookup.  Anonymous principals (no VO / issuer / DN) fall back
 * to the client IP so unauthenticated bulk clients are always subject to at
 * least an IP-keyed rule (Phase 25 invariant 5).
 *
 * The directive setters (zone / rate-rule / bandwidth-rule / concurrency-rule)
 * live in the sibling ratelimit_keys_parse.c (value primitives) and
 * ratelimit_keys_rules.c (shared rule builders).
 */
#include "ratelimit.h"
#include "protocols/webdav/webdav.h"      /* ngx_http_brix_webdav_req_ctx_t */
#include "ratelimit_keys_internal.h"


/* key extraction */
/*
 * Emit a "dn:<hash>" key for a (potentially long, PII-bearing) GSI subject DN.
 * WHY hash rather than embed the DN verbatim: the key string is bounded by
 * BRIX_RL_KEY_LEN and is exposed in dashboard/metrics snapshots, so we never
 * want the raw DN there.  The FNV-1a32 hash is rendered as fixed 8 hex digits
 * (%08xD = zero-padded uppercase 32-bit), giving a stable, short, collision-
 * tolerable bucket id for the same principal.
 */
static void
rl_key_dn_hash(const u_char *dn, size_t dn_len, char *out, size_t out_sz)
{
    uint32_t h = brix_rl_hash((const char *) dn, dn_len);
    ngx_snprintf((u_char *) out, out_sz, "dn:%08xD%Z", h);
}

/*
 * Stream-plane key builder: derive the "<type>:<value>" rbtree key for `rule`
 * from the connection's brix_ctx_t identity.  Each branch implements the
 * Phase 25 invariant-5 fallback: when the principal lacks the requested
 * dimension (anonymous VO/issuer/DN), fall back to keying on the client IP so
 * an unauthenticated bulk client is still subject to *some* bucket rather than
 * escaping the limiter entirely.  Returns NGX_DECLINED for a VOLUME rule whose
 * prefix does not match `path` (rule simply does not apply here).
 */
ngx_int_t
brix_rl_key_stream(brix_rl_rule_t *rule, brix_ctx_t *ctx,
    const char *path, char *out, size_t out_sz)
{
    switch (rule->key_type) {

    case BRIX_RL_KEY_VO:
        if (ctx->login.primary_vo[0] == '\0') {
            ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->login.peer_ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "vo:%s%Z", ctx->login.primary_vo);
        }
        break;

    case BRIX_RL_KEY_ISSUER:
        if (ctx->identity == NULL || ctx->identity->issuer.len == 0) {
            ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->login.peer_ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "iss:%V%Z",
                         &ctx->identity->issuer);
        }
        break;

    case BRIX_RL_KEY_IP:
        ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->login.peer_ip);
        break;

    case BRIX_RL_KEY_DN:
        if (ctx->login.dn[0] == '\0') {
            ngx_snprintf((u_char *) out, out_sz, "ip:%s%Z", ctx->login.peer_ip);
        } else {
            rl_key_dn_hash((u_char *) ctx->login.dn, ngx_strlen(ctx->login.dn),
                           out, out_sz);
        }
        break;

    case BRIX_RL_KEY_VOLUME:
        /* Prefix match: the rule limits aggregate traffic under one storage
         * path (e.g. "/store/tape").  All requests below the prefix share the
         * single "vol:<prefix>" bucket; non-matching paths decline the rule. */
        if (path == NULL || rule->key_match.len == 0
            || ngx_strncmp(path, rule->key_match.data, rule->key_match.len) != 0)
        {
            return NGX_DECLINED;   /* rule does not apply to this path */
        }
        ngx_snprintf((u_char *) out, out_sz, "vol:%V%Z", &rule->key_match);
        break;

    default:
        return NGX_ERROR;
    }

    /* ngx_snprintf does not guarantee NUL on truncation; force-terminate so the
     * key is always a valid C string for the hash/copy in the zone layer. */
    out[out_sz - 1] = '\0';
    return NGX_OK;
}

/* rl_key_req_t (the resolved-identity bundle passed to brix_rl_key_http) is
 * declared in ratelimit.h so ratelimit_http.c can build the literal directly.
 * `wctx` is void* there to keep webdav.h out of the header; the branch helpers
 * below cast it to ngx_http_brix_webdav_req_ctx_t* where they read the cert DN. */

/* ---- Derive the DN key for an HTTP request, with the two-source fallback ----
 *
 * WHAT: Writes a "dn:<hash>" (or IP fallback) key into `out`.  Prefers the
 * unified identity DN, then the cert-derived wctx->dn string, then the client IP
 * when the request is anonymous.
 *
 * WHY: DN keying carries an extra fallback step over the other dimensions; the
 * unified identity (token/SSS bridged) and the raw client-cert DN cached on wctx
 * can each independently carry the subject.  Splitting it out keeps the main
 * switch flat.
 *
 * HOW: (1) identity DN present → hash it; (2) else cert DN present → hash it;
 * (3) else fall back to the IP key.
 */
static void
rl_key_http_dn(const rl_key_req_t *req, char *out, size_t out_sz)
{
    ngx_http_brix_webdav_req_ctx_t *wctx = req->wctx;

    if (req->id != NULL && req->id->dn.len > 0) {
        rl_key_dn_hash(req->id->dn.data, req->id->dn.len, out, out_sz);
    } else if (wctx != NULL && wctx->dn[0] != '\0') {
        rl_key_dn_hash((u_char *) wctx->dn, ngx_strlen(wctx->dn),
                       out, out_sz);
    } else {
        ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", req->ip);
    }
}

/* ---- Build the "<type>:<value>" key for one HTTP rule dimension ----
 *
 * WHAT: Emits the rbtree key for `rule->key_type` into `out`.  Returns NGX_OK on
 * success, NGX_DECLINED for a VOLUME rule whose prefix does not match the path,
 * and NGX_ERROR for an unknown key type.
 *
 * WHY: Isolates the per-key-type branch logic from brix_rl_key_http()'s frozen
 * six-argument public shell so the derivation reads as one small switch over an
 * explicit, already-resolved identity struct.  Each anon branch keeps the Phase
 * 25 invariant-5 IP fallback so an unauthenticated client is still bucketed.
 *
 * HOW: switch on key_type — VO/ISSUER fall back to IP when the dimension is
 * absent; IP is unconditional; DN defers to rl_key_http_dn(); VOLUME prefix-
 * matches `path` or declines.
 */
static ngx_int_t
rl_key_http_derive(brix_rl_rule_t *rule, const rl_key_req_t *req,
    char *out, size_t out_sz)
{
    switch (rule->key_type) {

    case BRIX_RL_KEY_VO:
        if (req->id == NULL || req->id->vo_csv.len == 0) {
            ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", req->ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "vo:%V%Z", &req->id->vo_csv);
        }
        return NGX_OK;

    case BRIX_RL_KEY_ISSUER:
        if (req->id == NULL || req->id->issuer.len == 0) {
            ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", req->ip);
        } else {
            ngx_snprintf((u_char *) out, out_sz, "iss:%V%Z", &req->id->issuer);
        }
        return NGX_OK;

    case BRIX_RL_KEY_IP:
        ngx_snprintf((u_char *) out, out_sz, "ip:%V%Z", req->ip);
        return NGX_OK;

    case BRIX_RL_KEY_DN:
        rl_key_http_dn(req, out, out_sz);
        return NGX_OK;

    case BRIX_RL_KEY_VOLUME:
        if (req->path == NULL || rule->key_match.len == 0
            || ngx_strncmp(req->path, rule->key_match.data,
                           rule->key_match.len) != 0)
        {
            return NGX_DECLINED;
        }
        ngx_snprintf((u_char *) out, out_sz, "vol:%V%Z", &rule->key_match);
        return NGX_OK;

    default:
        return NGX_ERROR;
    }
}

/*
 * HTTP/WebDAV-plane key builder — the same dimension-and-fallback logic as
 * brix_rl_key_stream(), but reading identity from a caller-resolved rl_key_req_t
 * bundle instead of the WebDAV ctx and connection directly.  DN keying has an
 * extra fallback step: prefer the structured identity DN, then the cert-derived
 * wctx->dn string, then IP.  The caller (ratelimit_http.c) hoists the
 * side-effecting lookups (wctx->identity, connection addr) into `req` before the
 * call; the branch logic lives in rl_key_http_derive().
 */
ngx_int_t
brix_rl_key_http(brix_rl_rule_t *rule, const rl_key_req_t *req,
    char *out, size_t out_sz)
{
    ngx_int_t rc = rl_key_http_derive(rule, req, out, out_sz);

    if (rc != NGX_OK) {
        return rc;
    }
    out[out_sz - 1] = '\0';
    return NGX_OK;
}
