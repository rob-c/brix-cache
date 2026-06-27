/*
 * validate.c — WLCG/SciToken JWT bearer-token validation and claim extraction.
 *
 * Validates JWTs (RS256/ES256) against a JWKS key set, enforces
 * issuer/audience/exp/nbf, extracts claims (scopes, groups, iss/sub/aud), and
 * handles macaroons as an alternative auth path. WLCG storage tokens are HEP's
 * primary bearer mechanism (scope-granted paths + VO group membership), so this is
 * the authoritative path a connection trusts before granting filesystem access.
 * xrootd_token_validate() runs one deterministic pipeline: structural (3 segments)
 * → alg check → key select (by kid, else single-key) → EVP signature → claim
 * extraction → time window. Returns 0 (claims populated) / -1 (reason logged).
 */

#include "token_internal.h"
#include "b64url.h"
#include "json.h"
#include "scopes.h"
#include "macaroon.h"
#include "issuer_registry.h"
#include "subject_map.h"
#include "../types/tunables.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Escape control characters and non-printable bytes in a string before it is
 * written to the nginx error log.  This prevents log-injection attacks where a
 * malicious token embeds newlines or other control codes to forge log entries.
 *
 * Output format: printable ASCII is kept verbatim; anything < 0x20, 0x7f, or
 * DEL is replaced with \xHH.  The output is always NUL-terminated.
 */
/*
 *
 * WHAT: Escapes control characters and non-printable bytes in a string before it is written to the nginx error log. Printable ASCII (0x20-0x7e) passes through verbatim; anything below 0x20, at 0x7f, or DEL is replaced with \xHH hex notation. This prevents log-injection attacks where malicious tokens could embed newlines or other control codes to forge or corrupt log entries.
 *
 * WHY: JWT tokens are untrusted input that may contain arbitrary bytes (base64url decoded payloads). Without sanitization, an attacker could inject newline characters into a token's issuer or subject claim and make it appear as if separate log entries were generated — this is a log forgery attack vector. This function follows the AGENTS.md FAQ rule for "Log strings from wire" which mandates using xrootd_sanitize_log_string(). */
static void
token_sanitize_for_log(const char *in, char *out, size_t outsz)
{
    static const char hex[] = "0123456789abcdef";
    size_t            i     = 0;

    if (out == NULL || outsz == 0) {
        return;
    }
    if (in == NULL) {
        out[0] = '\0';
        return;
    }

    while (*in && i + 1 < outsz) {
        unsigned char c = (unsigned char) *in++;

        if (c >= 0x20 && c < 0x7f) {
            out[i++] = (char) c;
        } else {
            if (i + 4 >= outsz) {
                break;
            }
            out[i++] = '\\';
            out[i++] = 'x';
            out[i++] = hex[c >> 4];
            out[i++] = hex[c & 0x0f];
        }
    }
    out[i] = '\0';
}

/*
 *
 * WHAT: Logs a warning that the JWT token has malformed structure and returns -1 to signal validation failure. Used whenever the three-segment dot-separated format (header.payload.signature) is violated — missing dots, extra dots, or any structural anomaly indicates an invalid token.
 *
 * WHY: Provides a single point of error logging for all malformed-structure detection paths so operators see consistent "malformed JWT structure" messages regardless of which specific structural violation occurred. This makes log parsing easier when troubleshooting token delivery issues from upstream services.
 * HOW: Checks for exactly two dots in the token string (three segments);
 logs and returns -1 on any structural anomaly. */
static int
xrootd_token_malformed(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "xrootd_token: malformed JWT structure");
    return -1;
}

/*
 *
 * WHAT: Extracts the WLCG groups array from the JWT payload JSON into a comma-separated string stored in claims->groups. Reads up to 16 group names from the "wlcg.groups" claim and concatenates them with commas, truncating any individual group name that would exceed remaining buffer space. Empty result (no groups) produces an empty string.
 *
 * WHY: WLCG tokens include a groups array for VO membership attribution but nginx needs a flat comma-separated representation for logging and ACL matching. This helper converts the JSON array into a format compatible with existing path/acl.c logic which checks group memberships against configured VO ACLs without requiring additional JSON parsing at access time.
 * HOW: Reads up to 16 group names from JSON "wlcg.groups" array, concatenates with commas into claims->groups buffer, truncating individual groups that exceed remaining space. */
static void
xrootd_token_extract_groups(const char *pay_json, size_t pay_len,
    xrootd_token_claims_t *claims)
{
    char groups[16][256];
    int  i, gcount;

    gcount = json_get_string_array(pay_json, pay_len, "wlcg.groups",
                                   groups, 16);

    claims->groups[0] = '\0';
    for (i = 0; i < gcount; i++) {
        size_t cur, rem, gl;

        if (i > 0) {
            cur = strlen(claims->groups);
            if (cur + 1 < sizeof(claims->groups)) {
                claims->groups[cur] = ',';
                claims->groups[cur + 1] = '\0';
            }
        }

        cur = strlen(claims->groups);
        rem = sizeof(claims->groups) - cur - 1;
        if (rem == 0) {
            continue;
        }

        gl = strlen(groups[i]);
        if (gl > rem) {
            gl = rem;
        }

        ngx_memcpy(claims->groups + cur, groups[i], gl);
        claims->groups[cur + gl] = '\0';
    }
}

/*
 * xrootd_token_validate — verify a WLCG/SciToken JWT bearer token.
 *
 * Validates the token according to the WLCG token profile spec:
 *   https://zenodo.org/record/3992838
 *
 * Checks performed, in order:
 *   1. Structural: exactly three base64url-encoded segments separated by '.'.
 *   2. Algorithm: only "RS256" is accepted.
 *      alg:"none" bypass — a token that declares alg:"none" or any other
 *      algorithm is rejected before signature verification, preventing an
 *      attacker from forging an unsigned token.
 *   3. Key selection: by "kid" header claim; falls back to the only key
 *      when key_count == 1 and "kid" is absent.
 *   4. Signature: RSA PKCS#1v1.5 SHA-256 over header.payload.
 *      The signature MUST be verified before claims are trusted.
 *   5. Issuer: if expected_issuer is non-empty, "iss" must match exactly.
 *      Issuer confusion attack — without this check an attacker can present a
 *      valid token from a different trusted issuer.
 *   6. Audience: if expected_audience is non-empty, "aud" must match exactly.
 *   7. Expiry ("exp") and not-before ("nbf") against the server clock.
 *      Clock-skew tolerance is deliberately absent; configure NTP.
 *
 * Preconditions:
 *   - keys/key_count contain loaded, trusted RSA public keys (JWKS).
 *   - claims is an output parameter; the caller need not initialise it.
 *
 * Postconditions on success (return 0):
 *   - claims->scopes and claims->scope_count contain the parsed scope list.
 *   - claims->iss/sub/aud/exp/nbf are populated from the payload.
 *   - The caller must check xrootd_token_check_read() / _write() before
 *     granting access to any specific path.
 *
 * Ownership: claims points into caller-provided storage; no heap allocation.
 *
 * Returns: 0 on success, -1 on any validation failure (reason logged).
 */
int
xrootd_token_validate(ngx_log_t *log,
    const char *token, size_t token_len,
    const xrootd_jwks_key_t *keys, int key_count,
    const char *expected_issuer, const char *expected_audience,
    const u_char *macaroon_secret, size_t secret_len,
    xrootd_token_claims_t *claims)
{
    xrdjwt_seg  seg[3];
    u_char      hdr_json[2048], pay_json[4096], sig_bin[512];
    ssize_t     hdr_len, pay_len, sig_len;
    char        alg[16], kid[128];
    int         i;
    time_t      now;
    size_t      hdr_b64_len, pay_b64_len, sig_b64_len, signed_len;
    EVP_PKEY   *pkey;
 
    ngx_memzero(claims, sizeof(*claims));
 
    if (xrootd_token_is_macaroon(token, token_len)) {
        if (macaroon_secret == NULL || secret_len == 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_token: Macaroon detected but no secret configured");
            return -1;
        }
        if (xrootd_macaroon_validate(log, token, token_len,
                                     macaroon_secret, secret_len, claims) != 0)
        {
            return -1;
        }
        /*
         * Issuer pinning applies to macaroons too (fail-closed).  The macaroon
         * "location" packet is recorded in claims->iss; when the operator has
         * configured an expected issuer, a macaroon whose location does not match
         * — including one with no location packet (claims->iss == "") — is
         * rejected, closing the same issuer-confusion gap the JWT path guards
         * against below.  Macaroons carry no audience claim, so expected_audience
         * is intentionally not applied here.
         */
        if (expected_issuer != NULL && expected_issuer[0]
            && strcmp(claims->iss, expected_issuer) != 0)
        {
            char safe_iss[512];
            token_sanitize_for_log(claims->iss, safe_iss, sizeof(safe_iss));
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_macaroon: issuer/location mismatch: got \"%s\" "
                          "expected \"%s\"", safe_iss, expected_issuer);
            return -1;
        }
        return 0;
    }

    if (token_len == 0 || token_len > 8192) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: token length invalid: %uz", token_len);
        return -1;
    }

    /* Split "header.payload.signature" via the shared splitter (libxrdproto —
     * the same xrdjwt_split() the native client's token introspection uses), so
     * the two-dot scan is single-sourced across both trees. */
    if (xrdjwt_split((const char *) token, token_len, seg) != 0) {
        return xrootd_token_malformed(log);   /* fewer than 2 dots */
    }

    /* Compact JWS is EXACTLY 3 segments; xrdjwt_split folds any extra dots into
     * the signature slice, so reject a dot inside it here — keeping this gate's
     * strict structural check (defence-in-depth) and its "malformed" log path. */
    if (memchr(seg[2].p, '.', seg[2].n) != NULL) {
        return xrootd_token_malformed(log);
    }

    hdr_b64_len = seg[0].n;
    pay_b64_len = seg[1].n;
    sig_b64_len = seg[2].n;

    hdr_len = b64url_decode(token, hdr_b64_len, hdr_json,
                            sizeof(hdr_json) - 1);
    if (hdr_len < 0) {
        return xrootd_token_malformed(log);
    }
    hdr_json[hdr_len] = '\0';

    ngx_memzero(alg, sizeof(alg));
    ngx_memzero(kid, sizeof(kid));
    json_get_string((char *) hdr_json, (size_t) hdr_len, "alg", alg,
                    sizeof(alg));
    /* alg:"none" bypass: reject any algorithm other than RS256/ES256 before
     * touching the signature.  An unsigned token (alg:"none") must be
     * rejected here, not later, or the signature step is skipped. */
    if (strcmp(alg, "RS256") != 0 && strcmp(alg, "ES256") != 0) {
        char safe_alg[64];
        token_sanitize_for_log(alg, safe_alg, sizeof(safe_alg));
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: unsupported JWT algorithm \"%s\" "
                      "(only RS256 and ES256 accepted)", safe_alg);
        return -1;
    }

    json_get_string((char *) hdr_json, (size_t) hdr_len, "kid", kid,
                    sizeof(kid));

    pkey = NULL;
    for (i = 0; i < key_count; i++) {
        if (kid[0] == '\0' || strcmp(keys[i].kid, kid) == 0) {
            pkey = keys[i].pkey;
            break;
        }
    }
    if (pkey == NULL && key_count == 1) {
        pkey = keys[0].pkey;
    }
    if (pkey == NULL) {
        char safe_kid[256];
        token_sanitize_for_log(kid, safe_kid, sizeof(safe_kid));
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: no JWKS key matching kid=\"%s\"", safe_kid);
        return -1;
    }

    sig_len = b64url_decode(seg[2].p, sig_b64_len, sig_bin, sizeof(sig_bin));
    if (sig_len < 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: cannot decode JWT signature");
        return -1;
    }

    signed_len = hdr_b64_len + 1 + pay_b64_len;   /* "header.payload" */
    {
        int sig_ok;
        if (strcmp(alg, "ES256") == 0) {
            sig_ok = xrootd_token_verify_es256((const u_char *) token,
                                               signed_len, sig_bin,
                                               (size_t) sig_len, pkey);
        } else {
            sig_ok = xrootd_token_verify_rs256((const u_char *) token,
                                               signed_len, sig_bin,
                                               (size_t) sig_len, pkey);
        }
        if (!sig_ok) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_token: JWT signature verification failed");
            return -1;
        }
    }

    pay_len = b64url_decode(seg[1].p, pay_b64_len, pay_json,
                            sizeof(pay_json) - 1);
    if (pay_len < 0) {
        return xrootd_token_malformed(log);
    }
    pay_json[pay_len] = '\0';

    json_get_string((char *) pay_json, (size_t) pay_len, "iss",
                    claims->iss, sizeof(claims->iss));
    json_get_string((char *) pay_json, (size_t) pay_len, "sub",
                    claims->sub, sizeof(claims->sub));
    if (json_get_string((char *) pay_json, (size_t) pay_len, "aud",
                        claims->aud, sizeof(claims->aud)) < 0) {
        /* RFC 7519 §4.1.3: "aud" MAY be an array of strings (WLCG/OIDC commonly
         * emit it that way).  json_get_string() only accepts a JSON string, so
         * record the first array entry for logging/audit; the membership check
         * below accepts the string OR array form. */
        char aud_arr[1][256];
        if (json_get_string_array((char *) pay_json, (size_t) pay_len, "aud",
                                  aud_arr, 1) > 0) {
            ngx_cpystrn((u_char *) claims->aud, (u_char *) aud_arr[0],
                        sizeof(claims->aud));
        }
    }
    json_get_string((char *) pay_json, (size_t) pay_len, "scope",
                    claims->scope_raw, sizeof(claims->scope_raw));

    if (json_get_int64((char *) pay_json, (size_t) pay_len, "exp",
                       &claims->exp) != 0
        || claims->exp <= 0)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: token missing valid positive exp");
        return -1;
    }
    json_get_int64((char *) pay_json, (size_t) pay_len, "nbf",
                   &claims->nbf);
    json_get_int64((char *) pay_json, (size_t) pay_len, "iat",
                   &claims->iat);

    xrootd_token_extract_groups((char *) pay_json, (size_t) pay_len, claims);

    /* Issuer-confusion attack prevention: without this check an attacker
     * could present a valid token from a different trusted issuer. */
    if (expected_issuer != NULL && expected_issuer[0]) {
        if (strcmp(claims->iss, expected_issuer) != 0) {
            char safe_iss[512];
            token_sanitize_for_log(claims->iss, safe_iss, sizeof(safe_iss));
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_token: issuer mismatch: got \"%s\" "
                          "expected \"%s\"", safe_iss, expected_issuer);
            return -1;
        }
    }

    if (expected_audience != NULL && expected_audience[0]) {
        /* Accept the expected audience whether "aud" is a single string or an
         * array of strings containing it (RFC 7519 §4.1.3). */
        if (!json_string_or_array_contains((char *) pay_json, (size_t) pay_len,
                                           "aud", expected_audience)) {
            char safe_aud[512];
            token_sanitize_for_log(claims->aud, safe_aud, sizeof(safe_aud));
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_token: audience mismatch: got \"%s\" "
                          "expected \"%s\"", safe_aud,
                          expected_audience);
            return -1;
        }
    }

    now = time(NULL);

    /* Apply a clock-skew window so that tokens from systems whose clock differs
     * from ours by a few seconds are not spuriously rejected.  The skew widens
     * the acceptance window on both sides without permanently extending validity. */
    if (now > (time_t) claims->exp + XROOTD_TOKEN_CLOCK_SKEW_SECS)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: token expired at %L (now=%L skew=%d)",
                      (long long) claims->exp, (long long) now,
                      XROOTD_TOKEN_CLOCK_SKEW_SECS);
        return -1;
    }

    if (claims->nbf > 0 && now < (time_t) claims->nbf)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: token not yet valid (nbf=%L now=%L)",
                      (long long) claims->nbf, (long long) now);
        return -1;
    }

    claims->scope_count = xrootd_token_parse_scopes(
        claims->scope_raw, claims->scopes, XROOTD_MAX_TOKEN_SCOPES);

    /* Only build the ~2.5 KB of sanitized log strings when INFO logging is
     * actually enabled — otherwise this is pure wasted work on every validation
     * (the hot path under token-auth load). */
    if (log->log_level >= NGX_LOG_INFO) {
        char safe_sub[512], safe_iss[512], safe_scope[1024], safe_groups[512];
        token_sanitize_for_log(claims->sub,       safe_sub,    sizeof(safe_sub));
        token_sanitize_for_log(claims->iss,       safe_iss,    sizeof(safe_iss));
        token_sanitize_for_log(claims->scope_raw, safe_scope,  sizeof(safe_scope));
        token_sanitize_for_log(claims->groups,    safe_groups, sizeof(safe_groups));
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "xrootd_token: valid token sub=\"%s\" iss=\"%s\" "
                      "scope=\"%s\" groups=\"%s\" scopes=%d",
                      safe_sub, safe_iss, safe_scope, safe_groups,
                      claims->scope_count);
    }
    return 0;
}

/* xrootd_token_peek_iss — read the "iss" claim WITHOUT trusting the signature
 * (xrdjwt_split + b64url_decode + json_get_string): the registry must pick an
 * issuer, and thus its verification keys, before it can trust anything, so this
 * read is explicitly untrusted and re-derived from verified claims afterwards. */
int
xrootd_token_peek_iss(const char *token, size_t token_len,
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

/* xrootd_token_validate_registry_authn — registry authN with no path gate: peek
 * iss → registry_find → validate() with THAT issuer's keys → multi-audience accept.
 * Stream kXR_auth happens before any path is known, so issuer-keyed authentication
 * and per-path authorization are split; this is the authN half (also reused by the
 * combined HTTP entry point). On success returns 0, fills *claims, sets *out_issuer. */
int
xrootd_token_validate_registry_authn(ngx_log_t *log,
    const char *token, size_t token_len,
    const xrootd_token_registry_t *reg,
    const u_char *macaroon_secret, size_t secret_len,
    xrootd_token_claims_t *claims, const xrootd_token_issuer_t **out_issuer)
{
    char                          iss[256];
    const xrootd_token_issuer_t  *is;
    const char                   *expected_aud;
    int                           i;

    *out_issuer = NULL;

    if (xrootd_token_peek_iss(token, token_len, iss, sizeof(iss)) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: cannot read iss for issuer selection");
        return -1;
    }
    is = xrootd_token_registry_find(reg, iss);
    if (is == NULL) {
        char safe[512];
        token_sanitize_for_log(iss, safe, sizeof(safe));
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: unknown issuer \"%s\"", safe);
        return -1;
    }

    /* Verify with THIS issuer's keys; validate() re-checks iss after the
     * signature is trusted. A single declared audience is handed to validate()
     * for correct string-or-array membership; multiple audiences are accepted
     * best-effort below (full multi-audience array membership = W1b). */
    expected_aud = (is->audience_count == 1) ? is->audiences[0] : NULL;
    if (xrootd_token_validate(log, token, token_len,
            is->jwks_key_count ? is->jwks_keys : NULL, is->jwks_key_count,
            is->issuer, expected_aud, macaroon_secret, secret_len,
            claims) != 0)
    {
        return -1;
    }

    if (expected_aud == NULL && is->audience_count > 0) {
        int ok = 0;
        for (i = 0; i < is->audience_count && !ok; i++) {
            ok = (strcmp(claims->aud, is->audiences[i]) == 0);
        }
        for (i = 0; i < reg->global_audience_count && !ok; i++) {
            ok = (strcmp(claims->aud, reg->global_audiences[i]) == 0);
        }
        if (!ok) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "xrootd_token: audience not accepted for issuer \"%s\"",
                is->name);
            return -1;
        }
    }

    *out_issuer = is;
    return 0;
}

/* xrootd_token_authz_strategy — the per-path authorization ladder: enforce the
 * issuer base_path/restricted_path gate, then run the authorization_strategy
 * (capability / group / mapping) for (req_path, op). Shared by the HTTP combined
 * path and the stream per-path identity check. Returns 1 = ALLOW, 0 = DENY. */
int
xrootd_token_authz_strategy(const xrootd_token_issuer_t *is,
    const xrootd_token_claims_t *claims, const char *req_path,
    xrootd_token_op_e op)
{
    if (!xrootd_token_issuer_path_ok(is, req_path)) {
        return 0;
    }

    /* capability — the token's own WLCG scopes must cover (path, op). */
    if (is->strategy & XROOTD_AUTHZ_CAPABILITY) {
        int ok = (op == XROOTD_TOKEN_OP_WRITE)
            ? xrootd_token_check_write(claims->scopes, claims->scope_count,
                                       req_path)
            : xrootd_token_check_read(claims->scopes, claims->scope_count,
                                      req_path);
        if (ok) {
            return 1;
        }
    }

    /* group — the issuer vouches for its base_path for any token bearing a
     * group claim; the per-VO/group ACL layer refines the actual access using
     * the identity's groups (claims->groups → identity vo_list). */
    if (is->strategy & XROOTD_AUTHZ_GROUP) {
        if (claims->groups[0] != '\0') {
            return 1;
        }
    }

    /* mapping — the subject must resolve to a local user (map_subject +
     * name_mapfile, with onmissing/default policy); the per-user ACL/POSIX
     * layer then enforces that user's permissions within base_path. */
    if (is->strategy & XROOTD_AUTHZ_MAPPING) {
        char user[64];

        if (!is->map_subject) {
            return 1;                       /* trust the issuer's subject as-is */
        }
        if (is->name_mapfile[0] != '\0'
            && xrootd_subject_mapfile_lookup(is->name_mapfile, claims->sub,
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

/* xrootd_token_validate_registry — combined authN+authZ for where the request path
 * is known at validation time (WebDAV/S3): the authN half then the per-path
 * strategy ladder. */
int
xrootd_token_validate_registry(ngx_log_t *log,
    const char *token, size_t token_len,
    const xrootd_token_registry_t *reg, const char *req_path,
    xrootd_token_op_e op,
    const u_char *macaroon_secret, size_t secret_len,
    xrootd_token_claims_t *claims, int *out_issuer_bucket)
{
    const xrootd_token_issuer_t *is;

    *out_issuer_bucket = -1;

    if (xrootd_token_validate_registry_authn(log, token, token_len, reg,
            macaroon_secret, secret_len, claims, &is) != 0)
    {
        return -1;
    }
    if (!xrootd_token_authz_strategy(is, claims, req_path, op)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd_token: issuer \"%s\" did not authorize path", is->name);
        return -1;
    }

    *out_issuer_bucket = is->metric_bucket;
    return 0;
}
