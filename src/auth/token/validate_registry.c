/*
 * validate_registry.c — multi-issuer registry authN/authZ for WLCG bearer tokens.
 *
 * WHAT: The issuer-registry entry points that sit above brix_token_validate():
 * brix_token_peek_iss() reads the "iss" claim WITHOUT trusting the signature so
 * the registry can pick which issuer's keys to verify against;
 * brix_token_validate_registry_authn() does the authN half (peek → registry_find
 * → validate() with that issuer's keys → multi-audience accept);
 * brix_token_authz_strategy() runs the per-path authorization ladder
 * (base_path/restricted_path gate → capability / group / mapping strategy); and
 * brix_token_validate_registry() combines authN+authZ where the request path is
 * known at validation time (WebDAV/S3).
 *
 * WHY: validate.c exceeded the ~500-line file-size guard, so the registry plane
 * — which layers issuer selection and per-path authorization on top of the core
 * signature/claims pipeline — was split out under the phase-79 guard. Stream
 * kXR_auth happens before any path is known, so issuer-keyed authentication and
 * per-path authorization are deliberately split into the authn half and the
 * strategy ladder; both are reused by the combined HTTP entry point. The peek →
 * find → verify → strategy ordering and the capability/group/mapping semantics
 * are preserved exactly from the original single-file implementation.
 *
 * HOW: peek_iss splits + b64url-decodes the payload and reads "iss" (untrusted,
 * re-derived from verified claims afterwards). The authn half hands a single
 * declared audience to brix_token_validate() for correct string-or-array
 * membership and accepts multiple issuer/global audiences best-effort. The
 * strategy ladder short-circuits ALLOW on the first satisfied strategy bit.
 * token_sanitize_for_log() (validate.c, via validate_internal.h) guards every
 * untrusted value that reaches the error log.
 */

#include "token_internal.h"
#include "validate_internal.h"
#include "issuer_registry.h"
#include "subject_map.h"
#include "b64url.h"
#include "json.h"
#include "scopes.h"

#include <string.h>

/* brix_token_peek_iss — read the "iss" claim WITHOUT trusting the signature
 * (xrdjwt_split + b64url_decode + json_get_string): the registry must pick an
 * issuer, and thus its verification keys, before it can trust anything, so this
 * read is explicitly untrusted and re-derived from verified claims afterwards. */
int
brix_token_peek_iss(const char *token, size_t token_len,
    char *out, size_t outsz)
{
    xrdjwt_seg  seg[3];
    u_char      pay[4096];
    ssize_t     n;

    out[0] = '\0';

    if (xrdjwt_split(token, token_len, seg) != 0) {
        return -1;                              /* not a compact JWS */
    }
    n = b64url_decode(seg[1].p, seg[1].n, pay, sizeof(pay) - 1);
    if (n < 0) {
        return -1;
    }
    pay[n] = '\0';
    if (json_get_string((char *) pay, (size_t) n, "iss", out, outsz) < 0) {
        return -1;
    }
    return 0;
}

/* brix_token_validate_registry_authn — registry authN with no path gate: peek
 * iss → registry_find → validate() with THAT issuer's keys → multi-audience accept.
 * Stream kXR_auth happens before any path is known, so issuer-keyed authentication
 * and per-path authorization are split; this is the authN half (also reused by the
 * combined HTTP entry point). On success returns 0, fills *claims, sets *out_issuer. */
int
brix_token_validate_registry_authn(const brix_token_registry_args_t *a,
    const brix_token_issuer_t **out_issuer)
{
    char                        iss[256];
    const brix_token_issuer_t  *is;
    const char                 *expected_aud;
    int                         i;

    *out_issuer = NULL;

    if (brix_token_peek_iss(a->token, a->token_len, iss, sizeof(iss)) != 0) {
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: cannot read iss for issuer selection");
        return -1;
    }
    is = brix_token_registry_find(a->reg, iss);
    if (is == NULL) {
        char safe[512];
        token_sanitize_for_log(iss, safe, sizeof(safe));
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: unknown issuer \"%s\"", safe);
        return -1;
    }

    /* Verify with THIS issuer's keys; validate() re-checks iss after the
     * signature is trusted. A single declared audience is handed to validate()
     * for correct string-or-array membership; multiple audiences are accepted
     * best-effort below (full multi-audience array membership = W1b). */
    expected_aud = (is->audience_count == 1) ? is->audiences[0] : NULL;

    {
        brix_token_validate_args_t  va;

        va.log               = a->log;
        va.token             = a->token;
        va.token_len         = a->token_len;
        va.keys              = is->jwks_key_count ? is->jwks_keys : NULL;
        va.key_count         = is->jwks_key_count;
        va.expected_issuer   = is->issuer;
        va.expected_audience = expected_aud;
        va.macaroon_secret   = a->macaroon_secret;
        va.secret_len        = a->secret_len;
        va.clock_skew        = a->clock_skew;
        va.claims            = a->claims;

        if (brix_token_validate(&va) != 0) {
            return -1;
        }
    }

    if (expected_aud == NULL && is->audience_count > 0) {
        int ok = 0;
        for (i = 0; i < is->audience_count && !ok; i++) {
            ok = (strcmp(a->claims->aud, is->audiences[i]) == 0);
        }
        for (i = 0; i < a->reg->global_audience_count && !ok; i++) {
            ok = (strcmp(a->claims->aud, a->reg->global_audiences[i]) == 0);
        }
        if (!ok) {
            ngx_log_error(NGX_LOG_WARN, a->log, 0,
                "brix_token: audience not accepted for issuer \"%s\"",
                is->name);
            return -1;
        }
    }

    *out_issuer = is;
    return 0;
}

/* brix_token_authz_strategy — the per-path authorization ladder: enforce the
 * issuer base_path/restricted_path gate, then run the authorization_strategy
 * (capability / group / mapping) for (req_path, op). Shared by the HTTP combined
 * path and the stream per-path identity check. Returns 1 = ALLOW, 0 = DENY. */
int
brix_token_authz_strategy(const brix_token_issuer_t *is,
    const brix_token_claims_t *claims, const char *req_path,
    brix_token_op_e op)
{
    if (!brix_token_issuer_path_ok(is, req_path)) {
        return 0;
    }

    /* capability — the token's own WLCG scopes must cover (path, op). */
    if (is->strategy & BRIX_AUTHZ_CAPABILITY) {
        int ok = (op == BRIX_TOKEN_OP_WRITE)
            ? brix_token_check_write(claims->scopes, claims->scope_count,
                                       req_path)
            : brix_token_check_read(claims->scopes, claims->scope_count,
                                      req_path);
        if (ok) {
            return 1;
        }
    }

    /* group — the issuer vouches for its base_path for any token bearing a
     * group claim; the per-VO/group ACL layer refines the actual access using
     * the identity's groups (claims->groups → identity vo_list). */
    if (is->strategy & BRIX_AUTHZ_GROUP) {
        if (claims->groups[0] != '\0') {
            return 1;
        }
    }

    /* mapping — the subject must resolve to a local user (map_subject +
     * name_mapfile, with onmissing/default policy); the per-user ACL/POSIX
     * layer then enforces that user's permissions within base_path. */
    if (is->strategy & BRIX_AUTHZ_MAPPING) {
        char user[64];

        if (!is->map_subject) {
            return 1;                       /* trust the issuer's subject as-is */
        }
        if (is->name_mapfile[0] != '\0'
            && brix_subject_mapfile_lookup(is->name_mapfile, claims->sub,
                                             user, sizeof(user)) == 0)
        {
            return 1;
        }
        if (!is->onmissing_fail && is->default_user[0] != '\0') {
            return 1;                       /* fall back to default_user */
        }
    }

    return 0;
}

/* brix_token_validate_registry — combined authN+authZ for where the request path
 * is known at validation time (WebDAV/S3): the authN half then the per-path
 * strategy ladder. */
int
brix_token_validate_registry(const brix_token_registry_args_t *a,
    const char *req_path, brix_token_op_e op, int *out_issuer_bucket)
{
    const brix_token_issuer_t *is;

    *out_issuer_bucket = -1;

    if (brix_token_validate_registry_authn(a, &is) != 0) {
        return -1;
    }
    if (!brix_token_authz_strategy(is, a->claims, req_path, op)) {
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
            "brix_token: issuer \"%s\" did not authorize path", is->name);
        return -1;
    }

    *out_issuer_bucket = is->metric_bucket;
    return 0;
}
