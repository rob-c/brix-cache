/*
 * validate.c — WLCG/SciToken JWT bearer-token validation and claim extraction.
 *
 * Validates JWTs (RS256/ES256) against a JWKS key set, enforces
 * issuer/audience/exp/nbf, extracts claims (scopes, groups, iss/sub/aud), and
 * handles macaroons as an alternative auth path. WLCG storage tokens are HEP's
 * primary bearer mechanism (scope-granted paths + VO group membership), so this is
 * the authoritative path a connection trusts before granting filesystem access.
 * brix_token_validate() runs one deterministic pipeline: structural (3 segments)
 * → alg check → key select (by kid, else single-key) → EVP signature → claim
 * extraction → time window. Returns 0 (claims populated) / -1 (reason logged).
 */

#include "token_internal.h"
#include "validate_internal.h"
#include "b64url.h"
#include "json.h"
#include "scopes.h"
#include "macaroon.h"
#include "core/types/tunables.h"

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
 * WHY: JWT tokens are untrusted input that may contain arbitrary bytes (base64url decoded payloads). Without sanitization, an attacker could inject newline characters into a token's issuer or subject claim and make it appear as if separate log entries were generated — this is a log forgery attack vector. This function follows the AGENTS.md FAQ rule for "Log strings from wire" which mandates using brix_sanitize_log_string(). */
void
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
int
brix_token_malformed(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix_token: malformed JWT structure");
    return -1;
}

/*
 *
 * WHAT: Extracts the WLCG groups array from the JWT payload JSON into a comma-separated string stored in claims->groups. Reads up to 16 group names from the "wlcg.groups" claim and concatenates them with commas, truncating any individual group name that would exceed remaining buffer space. Empty result (no groups) produces an empty string.
 *
 * WHY: WLCG tokens include a groups array for VO membership attribution but nginx needs a flat comma-separated representation for logging and ACL matching. This helper converts the JSON array into a format compatible with existing path/acl.c logic which checks group memberships against configured VO ACLs without requiring additional JSON parsing at access time.
 * HOW: Reads up to 16 group names from JSON "wlcg.groups" array, concatenates with commas into claims->groups buffer, truncating individual groups that exceed remaining space. */
static void
brix_token_extract_groups(const char *pay_json, size_t pay_len,
    brix_token_claims_t *claims)
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
 * token_validate_macaroon — the macaroon alternative-auth branch.
 *
 * WHAT: Validates a detected macaroon against the configured secret, then
 *       applies issuer pinning to its "location" packet. Returns 0 on success
 *       with a->claims populated, -1 on any failure (reason logged).
 * WHY:  Macaroons are the non-JWT bearer path; keeping the whole branch in one
 *       helper preserves the original early-return ordering (secret presence →
 *       HMAC chain validation → issuer pin) while shrinking the JWT pipeline.
 * HOW:  Fails closed when no secret is configured. Issuer pinning applies to
 *       macaroons too: the macaroon "location" packet is recorded in
 *       claims->iss; when the operator has configured an expected issuer, a
 *       macaroon whose location does not match — including one with no
 *       location packet (claims->iss == "") — is rejected, closing the same
 *       issuer-confusion gap the JWT path guards against. Macaroons carry no
 *       audience claim, so expected_audience is intentionally not applied.
 */
static int
token_validate_macaroon(const brix_token_validate_args_t *a)
{
    if (a->macaroon_secret == NULL || a->secret_len == 0) {
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: Macaroon detected but no secret configured");
        return -1;
    }
    if (brix_macaroon_validate(a->log, a->token, a->token_len,
                                 a->macaroon_secret, a->secret_len,
                                 a->claims) != 0)
    {
        return -1;
    }
    if (a->expected_issuer != NULL && a->expected_issuer[0]
        && strcmp(a->claims->iss, a->expected_issuer) != 0)
    {
        char safe_iss[512];
        token_sanitize_for_log(a->claims->iss, safe_iss, sizeof(safe_iss));
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_macaroon: issuer/location mismatch: got \"%s\" "
                      "expected \"%s\"", safe_iss, a->expected_issuer);
        return -1;
    }
    return 0;
}

/*
 * token_extract_claims — pull the registered + WLCG claims from the payload.
 *
 * WHAT: Extracts iss/sub/aud (string OR first array entry), the raw scope
 *       string, exp/nbf/iat, and the wlcg.groups list into a->claims. Returns
 *       0 on success, -1 when "exp" is missing or non-positive (logged).
 * WHY:  Runs only AFTER the signature is trusted; exp is the one claim whose
 *       absence is fatal at extraction time (RFC 7519 §4.1.4 — a token with
 *       no valid expiry can never be accepted).
 * HOW:  RFC 7519 §4.1.3: "aud" MAY be an array of strings (WLCG/OIDC commonly
 *       emit it that way). json_get_string() only accepts a JSON string, so
 *       the first array entry is recorded for logging/audit; the membership
 *       check in token_check_issuer_audience() accepts string OR array form.
 */
static int
token_extract_claims(const brix_token_validate_args_t *a, const char *pay_json,
    size_t pay_len)
{
    brix_token_claims_t *claims = a->claims;

    json_get_string(pay_json, pay_len, "iss",
                    claims->iss, sizeof(claims->iss));
    json_get_string(pay_json, pay_len, "sub",
                    claims->sub, sizeof(claims->sub));
    if (json_get_string(pay_json, pay_len, "aud",
                        claims->aud, sizeof(claims->aud)) < 0) {
        /* RFC 7519 §4.1.3: "aud" MAY be an array of strings (WLCG/OIDC commonly
         * emit it that way).  json_get_string() only accepts a JSON string, so
         * record the first array entry for logging/audit; the membership check
         * below accepts the string OR array form. */
        char aud_arr[1][256];
        if (json_get_string_array(pay_json, pay_len, "aud",
                                  aud_arr, 1) > 0) {
            ngx_cpystrn((u_char *) claims->aud, (u_char *) aud_arr[0],
                        sizeof(claims->aud));
        }
    }
    json_get_string(pay_json, pay_len, "scope",
                    claims->scope_raw, sizeof(claims->scope_raw));

    if (json_get_int64(pay_json, pay_len, "exp", &claims->exp) != 0
        || claims->exp <= 0)
    {
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: token missing valid positive exp");
        return -1;
    }
    json_get_int64(pay_json, pay_len, "nbf", &claims->nbf);
    json_get_int64(pay_json, pay_len, "iat", &claims->iat);

    brix_token_extract_groups(pay_json, pay_len, a->claims);
    return 0;
}

/*
 * token_check_issuer_audience — enforce the iss/aud pins on verified claims.
 *
 * WHAT: When an expected issuer is configured, "iss" must match exactly; when
 *       an expected audience is configured, "aud" (string or array) must
 *       contain it or the WLCG wildcard audience. Returns 0 on acceptance,
 *       -1 on mismatch (logged with sanitized claim values).
 * WHY:  Issuer-confusion attack prevention — without the iss check an attacker
 *       could present a valid token from a different trusted issuer. The WLCG
 *       wildcard (rules 104/105): a token whose aud is
 *       'https://wlcg.cern.ch/jwt/v1/any' MUST be accepted by any WLCG
 *       endpoint regardless of its locally configured audience.
 * HOW:  aud membership re-reads the payload JSON via
 *       json_string_or_array_contains() so the array form is honored exactly
 *       (claims->aud holds only the first entry, for logging).
 */
static int
token_check_issuer_audience(const brix_token_validate_args_t *a,
    const char *pay_json, size_t pay_len)
{
    /* Issuer-confusion attack prevention: without this check an attacker
     * could present a valid token from a different trusted issuer. */
    if (a->expected_issuer != NULL && a->expected_issuer[0]) {
        if (strcmp(a->claims->iss, a->expected_issuer) != 0) {
            char safe_iss[512];
            token_sanitize_for_log(a->claims->iss, safe_iss, sizeof(safe_iss));
            ngx_log_error(NGX_LOG_WARN, a->log, 0,
                          "brix_token: issuer mismatch: got \"%s\" "
                          "expected \"%s\"", safe_iss, a->expected_issuer);
            return -1;
        }
    }

    if (a->expected_audience != NULL && a->expected_audience[0] != '\0') {
        /* Accept the expected audience whether "aud" is a single string or an
         * array of strings containing it (RFC 7519 §4.1.3).  Also accept the
         * WLCG-profile wildcard audience (rules 104/105): a token whose aud is
         * 'https://wlcg.cern.ch/jwt/v1/any' MUST be accepted by any WLCG
         * endpoint regardless of its locally configured audience. */
        int aud_ok =
            json_string_or_array_contains(pay_json, pay_len,
                                          "aud", a->expected_audience)
            || json_string_or_array_contains(pay_json, pay_len,
                                          "aud",
                                          "https://wlcg.cern.ch/jwt/v1/any");
        if (!aud_ok) {
            char safe_aud[512];
            token_sanitize_for_log(a->claims->aud, safe_aud, sizeof(safe_aud));
            ngx_log_error(NGX_LOG_WARN, a->log, 0,
                          "brix_token: audience mismatch: got \"%s\" "
                          "expected \"%s\"", safe_aud,
                          a->expected_audience);
            return -1;
        }
    }
    return 0;
}

/*
 * token_check_time_window — enforce exp/nbf against the server clock.
 *
 * WHAT: Rejects tokens past exp (widened by the configured clock skew, with
 *       saturating addition) or before nbf. Returns 0 when inside the window,
 *       -1 otherwise (logged with the offending times).
 * WHY:  Apply a clock-skew window so that tokens from systems whose clock
 *       differs from ours by a few seconds are not spuriously rejected. The
 *       skew widens the acceptance window without permanently extending
 *       validity.
 * HOW:  Guard against int64 overflow: json_get_int64() clamps a far-future
 *       NumericDate (e.g. 99999999999999999999) to INT64_MAX, so
 *       claims->exp + clock_skew can overflow. Use saturating addition — if
 *       the sum would overflow, the expiry is effectively infinite and the
 *       token is always valid.
 */
static int
token_check_time_window(const brix_token_validate_args_t *a)
{
    time_t   now = time(NULL);
    int64_t  exp_limit;

    if (a->clock_skew > 0
        && a->claims->exp > (int64_t) INT64_MAX - (int64_t) a->clock_skew)
    {
        exp_limit = INT64_MAX;   /* saturate: far-future, never expired */
    } else {
        exp_limit = a->claims->exp + (int64_t) a->clock_skew;
    }
    if (now > (time_t) exp_limit) {
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: token expired at %L (now=%L skew=%d)",
                      (long long) a->claims->exp, (long long) now,
                      a->clock_skew);
        return -1;
    }

    if (a->claims->nbf > 0 && now < (time_t) a->claims->nbf)
    {
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: token not yet valid (nbf=%L now=%L)",
                      (long long) a->claims->nbf, (long long) now);
        return -1;
    }
    return 0;
}

/*
 * token_log_valid — INFO-level success line for an accepted token.
 *
 * WHAT: Emits the "valid token" log line with sanitized sub/iss/scope/groups
 *       and the parsed scope count.
 * WHY:  Only build the ~2.5 KB of sanitized log strings when INFO logging is
 *       actually enabled — otherwise this is pure wasted work on every
 *       validation (the hot path under token-auth load).
 * HOW:  Level gate first, then four token_sanitize_for_log() passes feeding
 *       one ngx_log_error(NGX_LOG_INFO, ...) call.
 */
static void
token_log_valid(ngx_log_t *log, const brix_token_claims_t *claims)
{
    if (log->log_level >= NGX_LOG_INFO) {
        char safe_sub[512], safe_iss[512], safe_scope[1024], safe_groups[512];
        token_sanitize_for_log(claims->sub,       safe_sub,    sizeof(safe_sub));
        token_sanitize_for_log(claims->iss,       safe_iss,    sizeof(safe_iss));
        token_sanitize_for_log(claims->scope_raw, safe_scope,  sizeof(safe_scope));
        token_sanitize_for_log(claims->groups,    safe_groups, sizeof(safe_groups));
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "brix_token: valid token sub=\"%s\" iss=\"%s\" "
                      "scope=\"%s\" groups=\"%s\" scopes=%d",
                      safe_sub, safe_iss, safe_scope, safe_groups,
                      claims->scope_count);
    }
}


/*
 * brix_token_validate — verify a WLCG/SciToken JWT bearer token.
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
 *   3. Key selection: by "kid" header claim (exact match); when "kid" is
 *      absent all JWKS keys are tried in order (rotation grace, §3.3).
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
 *   - a->keys/key_count contain loaded, trusted RSA public keys (JWKS).
 *   - a->claims is an output parameter; the caller need not initialise it.
 *
 * Postconditions on success (return 0):
 *   - claims->scopes and claims->scope_count contain the parsed scope list.
 *   - claims->iss/sub/aud/exp/nbf are populated from the payload.
 *   - The caller must check brix_token_check_read() / _write() before
 *     granting access to any specific path.
 *
 * Ownership: a->claims points into caller-provided storage; no heap allocation.
 *
 * Returns: 0 on success, -1 on any validation failure (reason logged).
 */
int
brix_token_validate(const brix_token_validate_args_t *a)
{
    xrdjwt_seg   seg[3];
    u_char       pay_json[4096];
    ssize_t      pay_len;
    token_hdr_t  hdr;

    ngx_memzero(a->claims, sizeof(*a->claims));

    if (brix_token_is_macaroon(a->token, a->token_len)) {
        return token_validate_macaroon(a);
    }

    if (a->token_len == 0 || a->token_len > 8192) {
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: token length invalid: %uz", a->token_len);
        return -1;
    }

    /* Split "header.payload.signature" via the shared splitter (libxrdproto —
     * the same xrdjwt_split() the native client's token introspection uses), so
     * the two-dot scan is single-sourced across both trees. */
    if (xrdjwt_split((const char *) a->token, a->token_len, seg) != 0) {
        return brix_token_malformed(a->log);   /* fewer than 2 dots */
    }

    /* Compact JWS is EXACTLY 3 segments; xrdjwt_split folds any extra dots into
     * the signature slice, so reject a dot inside it here — keeping this gate's
     * strict structural check (defence-in-depth) and its "malformed" log path. */
    if (memchr(seg[2].p, '.', seg[2].n) != NULL) {
        return brix_token_malformed(a->log);
    }

    if (token_check_header(a, seg, &hdr) != 0) {
        return -1;
    }
    if (token_verify_signature(a, seg, &hdr) != 0) {
        return -1;
    }

    pay_len = b64url_decode(seg[1].p, seg[1].n, pay_json,
                            sizeof(pay_json) - 1);
    if (pay_len < 0) {
        return brix_token_malformed(a->log);
    }
    pay_json[pay_len] = '\0';

    if (token_extract_claims(a, (char *) pay_json, (size_t) pay_len) != 0) {
        return -1;
    }
    if (token_check_issuer_audience(a, (char *) pay_json,
                                    (size_t) pay_len) != 0)
    {
        return -1;
    }
    if (token_check_time_window(a) != 0) {
        return -1;
    }

    a->claims->scope_count = brix_token_parse_scopes(
        a->claims->scope_raw, a->claims->scopes, BRIX_MAX_TOKEN_SCOPES);

    token_log_valid(a->log, a->claims);
    return 0;
}
