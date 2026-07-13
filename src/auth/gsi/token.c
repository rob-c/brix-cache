#include "gsi_internal.h"
#include "protocols/root/session/registry.h"
#include "auth/token/macaroon.h"
#include "auth/token/token_cache.h"
#include "auth/token/worker_cache.h"
#include "auth/token/issuer_registry.h"

/*
 * Bearer-token (JWT/WLCG) authentication for the "ztn" credential type.
 *
 * The kXR_auth "ztn" conversation is decomposed into four sequential phases,
 * each owning one nameable concern and passing state explicitly:
 *   tokenauth_extract       — locate the raw token in the auth payload
 *   tokenauth_validate      — cache lookup + signature/claim verification
 *                             (incl. grace-period old-secret fallback + caching)
 *   tokenauth_map_identity   — stamp ctx identity/login fields from claims
 *   tokenauth_bind_session   — metrics, session registry, scopes, success log
 * The orchestrator brix_handle_token_auth() reads as a flat early-return
 * sequence over these phases. Wire bytes, error codes, log strings, metric
 * calls and evaluation order are preserved 1:1 with the pre-split handler.
 */

/*
 * tokenauth_state_t — per-request state threaded between the phase helpers.
 *
 * WHAT: bundles the token slice extracted from the payload, the verified
 *       claims, and the registry issuer matched during validation (NULL for
 *       non-registry configs) so each phase takes/returns exactly what it needs.
 *
 * WHY: keeps the phase-helper signatures small (§8 explicit data flow, no new
 *      globals) — the state lives on the orchestrator's stack and is passed by
 *      pointer, never through file-scope state.
 *
 * HOW: extract fills token/token_len; validate fills claims/reg_issuer; the
 *      identity/session phases read them.
 */
typedef struct {
    const char                *token;
    size_t                     token_len;
    const u_char              *secret;      /* active macaroon secret, or NULL */
    size_t                     secret_len;  /* 0 ⇒ no secret (macaroon → NULL)  */
    brix_token_claims_t        claims;
    const brix_token_issuer_t *reg_issuer;
} tokenauth_state_t;


/* ---- Slice the raw token out of a kXR_auth "ztn" payload (both framings) ----
 *
 * WHAT: point *token / *token_len at the raw JWT inside the auth payload,
 *       handling the two ztn credential framings we accept:
 *         - stock XrdSecProtocolztn TokenResp: an 8-byte TokenHdr
 *           ("ztn\0", ver=0, opr='T', rsvd[2]), a 2-byte big-endian length, then
 *           the token followed by a trailing NUL — the token starts at offset 10.
 *         - legacy brix framing: the 4-byte credtype echo ("ztn\0") followed by
 *           the token — the token starts at offset 4.
 *       Trailing NUL padding is stripped in both cases. Returns 0 on a non-empty
 *       token, -1 on an empty/all-NUL slice.
 *
 * WHY: a stock XRootD client (and now brix's own cache-origin ztn client, which
 *      speaks the standard wire format so it interoperates with a stock origin)
 *      sends the TokenResp framing. Detecting it here — rather than in the caller
 *      — keeps the deny logic in tokenauth_extract untouched. This only widens
 *      what we parse; the token itself is still fully validated downstream, so no
 *      security check is weakened.
 *
 * HOW: identify the stock framing by its fixed header bytes (dlen big enough,
 *      id "ztn", ver byte 0 at offset 4, opr 'T' at offset 5); use the embedded
 *      length to bound the token, else fall back to the legacy payload+4 slice.
 *      Trailing NULs are stripped from whichever slice we chose.
 */
static int
tokenauth_slice_token(const u_char *payload, size_t dlen,
    const char **token, size_t *token_len)
{
    const char *tok;
    size_t      tlen;

    /* Stock XrdSecProtocolztn TokenResp: "ztn\0" ver=0 opr='T' rsvd[2] len[2] ...
     * The minimum is the 10-byte prefix + a 1-byte (NUL-only) token slot. */
    if (dlen >= 11
        && ngx_memcmp(payload, "ztn", 4) == 0
        && payload[4] == 0
        && payload[5] == 'T')
    {
        size_t claimed = ((size_t) payload[8] << 8) | (size_t) payload[9];
        size_t avail   = dlen - 10;               /* bytes after the 10B prefix */

        tlen = (claimed > 0 && claimed <= avail) ? claimed : avail;
        tok  = (const char *) (payload + 10);
    } else {
        tok  = (const char *) (payload + 4);      /* legacy "ztn\0" + token */
        tlen = dlen - 4;
    }

    while (tlen > 0 && tok[tlen - 1] == '\0') {
        tlen--;
    }
    if (tlen == 0) {
        return -1;
    }

    *token     = tok;
    *token_len = tlen;
    return 0;
}


/* ---- Locate the bearer token inside the kXR_auth payload ----
 *
 * WHAT: validates the auth payload and points st->token / st->token_len at the
 *       raw JWT (via tokenauth_slice_token, which handles both the stock
 *       XrdSecProtocolztn TokenResp framing and the legacy payload+4 framing).
 *       Returns NGX_OK on a non-empty token; on an empty payload or all-NUL
 *       token it emits the standard error triplet and returns the
 *       kXR_NotAuthorized wire response verbatim.
 *
 * WHY: an empty bearer token is a hard deny — this phase is the sole gate that
 *      rejects it, preserving the exact "empty token payload"/"empty bearer
 *      token" log+wire strings the pre-split handler emitted.
 *
 * HOW: 1) reject payload==NULL or dlen<=4; 2) slice the token (stock or legacy
 *      framing) with trailing '\0' stripped; 3) reject a now-empty token; else
 *      NGX_OK. On the deny paths *out carries the wire-response value the
 *      orchestrator must return unchanged (brix_send_error's own return can be
 *      NGX_OK, so the caller keys on NGX_DONE — not on *out — to know a response
 *      was sent).
 */
static ngx_int_t
tokenauth_extract(brix_ctx_t *ctx, ngx_connection_t *c, tokenauth_state_t *st,
    ngx_int_t *out)
{
    const char *token;
    size_t      token_len;

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen <= 4) {
        brix_log_access(ctx, c, "AUTH", "-", "ztn",
                          0, kXR_NotAuthorized, "empty token payload", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
        *out = brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty bearer token");
        return NGX_DONE;
    }

    if (tokenauth_slice_token(ctx->recv.payload, ctx->recv.cur_dlen,
                              &token, &token_len) != 0)
    {
        brix_log_access(ctx, c, "AUTH", "-", "ztn",
                          0, kXR_NotAuthorized, "empty token payload", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
        *out = brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty bearer token");
        return NGX_DONE;
    }

    st->token = token;
    st->token_len = token_len;
    return NGX_OK;
}


/* ---- Populate a JWKS brix_token_validate_args_t from the config + token ----
 *
 * WHAT: fills *va with the log, token slice, JWKS key set, expected issuer /
 *       audience, the active macaroon secret from st (NULL when st->secret_len
 *       is 0), clock skew and claims out-pointer for a brix_token_validate() call.
 *
 * WHY: the primary and grace-period paths build an identical args struct
 *      differing only in which secret they carry (in st->secret); factoring it
 *      removes the duplicated 10-field literal and keeps both callsites identical.
 *
 * HOW: copy each field from conf/st; point macaroon_secret at st->secret only
 *      when st->secret_len > 0 (matching the pre-split "slen > 0 ? secret : NULL").
 */
static void
tokenauth_fill_va(brix_token_validate_args_t *va, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, tokenauth_state_t *st)
{
    va->log               = c->log;
    va->token             = st->token;
    va->token_len         = st->token_len;
    va->keys              = conf->jwks_keys;
    va->key_count         = conf->jwks_key_count;
    va->expected_issuer   = (const char *) conf->token_issuer.data;
    va->expected_audience = (const char *) conf->token_audience.data;
    va->macaroon_secret   = st->secret_len > 0 ? st->secret : NULL;
    va->secret_len        = st->secret_len;
    va->clock_skew        = (int) conf->token_clock_skew;
    va->claims            = &st->claims;
}


/* ---- Try the cheapest-first token caches, then signature verification ----
 *
 * WHAT: attempts L1, then L2 (promoting hits into L1), then — on a miss —
 *       registry-authn (registry mode) or JWKS validation. Returns 0 when the
 *       token verified, non-zero otherwise; sets *cache_hit on a cache hit and
 *       fills st->claims / st->reg_issuer.
 *
 * WHY: isolates the "did we already verify this token?" fast path from the
 *      grace-period retry so each stays a small single-purpose step. Cheapest-
 *      first order (L1 → L2 → verify) is frozen; only verified claims are cached.
 *
 * HOW: 1) lazily create L1; 2) L1 lookup; 3) else L2 lookup (store into L1);
 *      4) else registry-authn; 5) else JWKS validate via tokenauth_fill_va.
 *      The active macaroon secret is carried on st (st->secret/secret_len).
 */
static int
tokenauth_verify_or_cache(ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, tokenauth_state_t *st,
    int via_registry, int *cache_hit)
{
    /*
     * Token-validation caches, consulted cheapest-first so token auth does not
     * re-run RSA/ECDSA verification on the event loop under load:
     *   L1 — always-on, per-worker, lockless (lazily created here).  A hit skips
     *        both the signature verification AND the L2 spinlock.
     *   L2 — the optional cross-worker SHM cache; an L2 hit is promoted into L1.
     * Only successfully verified claims are ever cached.
     */
    if (conf->token_l1 == NULL) {
        conf->token_l1 = brix_token_l1_create(ngx_cycle->pool,
                                                BRIX_TOKEN_L1_SLOTS);
    }

    if (!via_registry
        && brix_token_l1_lookup(conf->token_l1, st->token, st->token_len,
                                &st->claims))
    {
        *cache_hit = 1;
        return 0;
    }

    if (!via_registry && conf->token_cache_kv != NULL
        && brix_token_cache_lookup(conf->token_cache_kv, st->token,
                                     st->token_len, &st->claims))
    {
        *cache_hit = 1;
        brix_token_l1_store(conf->token_l1, st->token, st->token_len,
                            &st->claims);
        return 0;
    }

    if (via_registry) {
        brix_token_registry_args_t  ra;

        ra.log             = c->log;
        ra.token           = st->token;
        ra.token_len       = st->token_len;
        ra.reg             = conf->token_registry;
        ra.macaroon_secret = st->secret_len > 0 ? st->secret : NULL;
        ra.secret_len      = st->secret_len;
        ra.clock_skew      = (int) conf->token_clock_skew;
        ra.claims          = &st->claims;

        return brix_token_validate_registry_authn(&ra, &st->reg_issuer);
    }

    {
        brix_token_validate_args_t  va;

        tokenauth_fill_va(&va, c, conf, st);
        return brix_token_validate(&va);
    }
}


/* ---- Grace-period fallback: retry a rejected macaroon with the old secret ----
 *
 * WHAT: re-runs JWKS validation using the configured *old* macaroon secret.
 *       Returns 0 if the token now verifies (and logs the acceptance), the
 *       passed-in prev_rc unchanged if the old secret is absent/unparseable.
 *
 * WHY: lets in-flight tokens signed by the previous secret survive an nginx -s
 *      reload during key rotation. Only reached when the primary attempt failed
 *      and the config is non-registry — that gate stays in the caller.
 *
 * HOW: 1) parse the old secret; 2) if it parses, fill a va with it and
 *      validate; 3) on success log "accepted via old secret"; 4) return rc.
 */
static int
tokenauth_grace_retry(ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf,
    tokenauth_state_t *st, int prev_rc)
{
    u_char                      old_secret[64];
    ssize_t                     old_slen;
    brix_token_validate_args_t  va;
    int                         rc;

    old_slen = brix_macaroon_secret_parse(
        (const char *) conf->token_macaroon_secret_old.data,
        conf->token_macaroon_secret_old.len,
        old_secret, sizeof(old_secret));

    if (old_slen <= 0) {
        return prev_rc;
    }

    /* Point the shared va-builder at the old secret for this retry only. */
    st->secret     = old_secret;
    st->secret_len = (size_t) old_slen;

    tokenauth_fill_va(&va, c, conf, st);
    rc = brix_token_validate(&va);
    if (rc == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "brix: macaroon accepted via old secret "
                      "(grace-period key rotation)");
    }
    return rc;
}


/* ---- Run macaroon/JWT validation against JWKS keys or an issuer registry ----
 *
 * WHAT: verifies st->token, filling st->claims and (registry mode) st->reg_issuer.
 *       Returns 0 on a verified token (from L1/L2 cache OR fresh verification),
 *       non-zero if every validation attempt rejected it. Sets *cache_hit when
 *       the claims came from a cache (so the caller skips re-caching).
 *
 * WHY: isolates the cheapest-first cache ladder and the signature-verification
 *      dispatch (registry vs JWKS) plus the grace-period old-secret retry into
 *      one pure verification step; keeps deny logic (rc!=0) intact for the
 *      caller to act on. Order of cache/verify/fallback is frozen.
 *
 * HOW: 1) parse the primary macaroon secret if configured; 2) verify-or-cache;
 *      3) if still rejected, non-registry, and an old secret exists, grace-retry;
 *      4) on success, cache freshly verified claims (non-registry cache miss);
 *      5) return rc.
 */
static int
tokenauth_validate(ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf,
    tokenauth_state_t *st)
{
    int         via_registry = (conf->token_registry != NULL);
    int         cache_hit = 0;
    u_char      secret[64];
    ssize_t     slen = 0;
    int         rc;

    if (conf->token_macaroon_secret.len) {
        slen = brix_macaroon_secret_parse(
            (const char *) conf->token_macaroon_secret.data,
            conf->token_macaroon_secret.len, secret, sizeof(secret));
    }

    st->secret     = secret;
    st->secret_len = (size_t) (slen > 0 ? slen : 0);

    rc = tokenauth_verify_or_cache(c, conf, st, via_registry, &cache_hit);

    /* Grace-period fallback: if the primary secret rejected a macaroon token
     * and an old secret is configured, try validating with the old key. */
    if (rc != 0 && !via_registry && conf->token_macaroon_secret_old.len) {
        rc = tokenauth_grace_retry(c, conf, st, rc);
    }

    /* Cache the freshly verified claims for subsequent presentations (L1 always,
     * L2 when a SHM zone is configured).  Registry tokens are never cached: the
     * per-path decision is not a function of the token alone.  A cache hit
     * already holds the claims, so re-store only on a verified cache miss. */
    if (rc == 0 && !cache_hit && !via_registry) {
        brix_token_l1_store(conf->token_l1, st->token, st->token_len,
                            &st->claims);
        if (conf->token_cache_kv != NULL) {
            brix_token_cache_store(conf->token_cache_kv, st->token,
                                     st->token_len, &st->claims);
        }
    }

    return rc;
}


/* ---- Stamp ctx identity + login fields from the verified claims ----
 *
 * WHAT: sets ctx->token.auth / ctx->login.auth_done, populates the identity
 *       (claims + matched issuer), stashes the raw token for proxy bridging,
 *       and derives DN / vo_list / primary_vo from claims. Returns NGX_OK, or
 *       NGX_DONE (with *out set) on the kXR_NoMemory identity-allocation deny.
 *
 * WHY: concentrates the "authenticated client → ctx" mapping in one place; the
 *      only non-OK exit is the identity-allocation ENOMEM deny, preserved
 *      verbatim. (Claim caching happens in tokenauth_validate, next to the
 *      verification that produced them.)
 *
 * HOW: 1) set auth flags; 2) set identity claims (ENOMEM→deny) + issuer;
 *      3) copy raw token into ctx->bearer_token; 4) copy DN; 5) split groups
 *      into vo_list + primary_vo (first comma-delimited group). Returns NGX_OK
 *      to continue; on the ENOMEM deny returns NGX_DONE with *out set to the
 *      wire-response value (brix_send_error can itself return NGX_OK, so the
 *      caller keys on NGX_DONE, not on *out).
 */
static ngx_int_t
tokenauth_map_identity(brix_ctx_t *ctx, ngx_connection_t *c,
    tokenauth_state_t *st, ngx_int_t *out)
{
    const brix_token_claims_t *claims = &st->claims;

    ctx->token.auth = 1;
    ctx->login.auth_done = 1;
    if (ctx->identity != NULL
        && brix_identity_set_token_claims(ctx->identity, c->pool, &st->claims)
           != NGX_OK)
    {
        *out = brix_send_error(ctx, c, kXR_NoMemory,
                                 "identity allocation failed");
        return NGX_DONE;
    }

    /* phase-59 W1: record the matched issuer so the per-path scope check
     * (brix_identity_check_token_scope) enforces its base_path. */
    if (ctx->identity != NULL && st->reg_issuer != NULL) {
        ctx->identity->token_issuer = (void *) st->reg_issuer;
    }

    /* Save raw token so proxy auth-bridging can forward it to the upstream. */
    if (st->token_len > 0 && st->token_len < sizeof(ctx->bearer_token) - 1) {
        ngx_memcpy(ctx->bearer_token, st->token, st->token_len);
        ctx->bearer_token[st->token_len] = '\0';
    }

    ngx_cpystrn((u_char *) ctx->login.dn, (u_char *) claims->sub,
                sizeof(ctx->login.dn));

    if (claims->groups[0]) {
        const char *comma;
        size_t      pvo_len;

        ngx_cpystrn((u_char *) ctx->login.vo_list,
                    (u_char *) claims->groups,
                    sizeof(ctx->login.vo_list));

        comma = strchr(claims->groups, ',');
        pvo_len = comma ? (size_t) (comma - claims->groups)
                        : strlen(claims->groups);
        if (pvo_len >= sizeof(ctx->login.primary_vo)) {
            pvo_len = sizeof(ctx->login.primary_vo) - 1;
        }
        ngx_memcpy(ctx->login.primary_vo, claims->groups, pvo_len);
        ctx->login.primary_vo[pvo_len] = '\0';
    }

    return NGX_OK;
}


/* ---- Record metrics, register the session, copy scopes, log success ----
 *
 * WHAT: tracks unique-user and per-VO activity counters in shared memory,
 *       registers the authenticated session, copies the token scopes onto the
 *       ctx, and emits the success info log. Terminal side-effecting phase; no
 *       return value (the caller returns the BRIX_RETURN_OK wire response).
 *
 * WHY: separates the observability/session-registry side effects (the "edges")
 *      from the pure identity mapping; low-cardinality metric labels only.
 *
 * HOW: 1) if metrics SHM present, track VO activity + bump the VO request
 *      counter + track unique user; 2) register the session; 3) copy up to
 *      BRIX_MAX_TOKEN_SCOPES scopes; 4) log "token auth ok".
 */
static void
tokenauth_bind_session(brix_ctx_t *ctx, ngx_connection_t *c,
    tokenauth_state_t *st)
{
    const brix_token_claims_t *claims = &st->claims;
    int i;

    /* Track unique user and VO at auth completion. */
    {
        ngx_brix_metrics_t *shm = brix_metrics_shared();
        if (shm != NULL) {
            size_t vo_len = strlen(ctx->login.primary_vo);
            if (vo_len > 0 && vo_len < sizeof(ctx->login.primary_vo)) {
                brix_track_vo_activity(shm, ctx->login.primary_vo, 0, 0);
                ngx_uint_t vi;
                for (vi = 0; vi < BRIX_VO_MAX_TRACKED; vi++) {
                    if (ngx_strncmp(shm->vo_global.slots[vi].name, ctx->login.primary_vo,
                                    BRIX_VO_NAME_LEN) == 0)
                    {
                        BRIX_ATOMIC_INC(&shm->vo_global.slots[vi].requests_total);
                        break;
                    }
                }
            }
            brix_track_unique_user(shm, ctx->login.dn, strlen(ctx->login.dn));
        }
    }

    brix_session_register(ctx->login.sessid, ctx->login.dn, ctx->login.vo_list, 1);

    ctx->token.scope_count = claims->scope_count;
    for (i = 0; i < claims->scope_count && i < BRIX_MAX_TOKEN_SCOPES; i++) {
        ctx->token.scopes[i] = claims->scopes[i];
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: token auth ok sub=\"%s\" scopes=%d groups=\"%s\"",
                  claims->sub, claims->scope_count, claims->groups);
}


/*
 * WHAT: brix_handle_token_auth() — handles kXR_auth with protocol "ztn"
 *       (WLCG/SciToken bearer JWT). Extracts token from payload, validates
 *       signature against JWKS keys + issuer + audience claims.
 *
 * WHY: Single-round authentication — no DH exchange needed. The client
 *      submits a pre-signed JWT and the server verifies it against trusted
 *      public keys (RSA/ECDSA) configured via brix_jwks_keys directive.
 *
 * HOW: 1) tokenauth_extract — token from payload (empty → deny);
 *      2) tokenauth_validate — cache/verify + grace-period fallback
 *         (rejected → error triplet + kXR_NotAuthorized deny);
 *      3) tokenauth_map_identity — auth flags, identity, DN/groups/scopes
 *         (ENOMEM → deny); 4) tokenauth_bind_session — metrics + registry + log.
 *
 * Return values: NGX_OK on successful validation, kXR_NotAuthorized error
 * on empty payload, signature failure, or issuer/audience mismatch. */

ngx_int_t
brix_handle_token_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    tokenauth_state_t st;
    int               rc;
    ngx_int_t         out = NGX_OK;

    ngx_memzero(&st, sizeof(st));

    if (tokenauth_extract(ctx, c, &st, &out) == NGX_DONE) {
        return out;
    }

    rc = tokenauth_validate(c, conf, &st);
    if (rc != 0) {
        brix_log_access(ctx, c, "AUTH", "-", "ztn",
                          0, kXR_NotAuthorized, "token validation failed", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "bearer token validation failed");
    }

    if (tokenauth_map_identity(ctx, c, &st, &out) == NGX_DONE) {
        return out;
    }

    tokenauth_bind_session(ctx, c, &st);

    BRIX_RETURN_OK(ctx, c, BRIX_OP_AUTH, "AUTH", "-", st.claims.sub, 0);
}
