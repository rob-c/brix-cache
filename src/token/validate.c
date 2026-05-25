/* ---- File: validate.c — WLCG/SciToken JWT bearer-token validation and claim extraction ----
 *
 * WHAT: Validates JWT tokens (RS256/ES256) against a JWKS key set, checks issuer/audience/expiry/nbf constraints, extracts claims (scopes, groups, iss/sub/aud), and handles macaroon tokens as an alternative auth path. The main exported function xrootd_token_validate() performs structural verification → algorithm check → key selection → signature verification → claim extraction → time-window enforcement in a single deterministic pipeline.
 *
 * WHY: WLCG storage tokens are the primary bearer-token mechanism for HEP data access — they encode scope-granted paths (storage.read/write/create) and VO group membership. This module provides the authoritative validation path so every nginx connection can trust token claims before granting filesystem access. Macaroon support adds a fallback path for sites that use macaroon-based auth instead of JWT.
 *
 * HOW: Structural check → 3 dot-separated segments (header.payload.signature) → decode header JSON → verify alg is RS256 or ES256 → select key by kid or single-key fallback → verify signature with OpenSSL EVP → decode payload JSON → extract standard claims + groups array → parse scope string into per-path xrootd_token_scope_t entries → check exp/nbf against server clock. Returns 0 on success (claims populated) or -1 on failure (reason logged).
 * ------------------------------------------------------------------ */

#include "token_internal.h"
#include "b64url.h"
#include "json.h"
#include "scopes.h"
#include "macaroon.h"
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
/* ---- Function: token_sanitize_for_log() ----
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

/* ---- Function: xrootd_token_malformed() ----
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

/* ---- Function: xrootd_token_extract_groups() ----
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
    const char *dot1, *dot2;
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
        return xrootd_macaroon_validate(log, token, token_len,
                                        macaroon_secret, secret_len, claims);
    }

    if (token_len == 0 || token_len > 8192) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: token length invalid: %uz", token_len);
        return -1;
    }

    dot1 = memchr(token, '.', token_len);
    if (dot1 == NULL) {
        return xrootd_token_malformed(log);
    }

    dot2 = memchr(dot1 + 1, '.', token_len - (size_t) (dot1 + 1 - token));
    if (dot2 == NULL) {
        return xrootd_token_malformed(log);
    }

    if (memchr(dot2 + 1, '.', token_len - (size_t) (dot2 + 1 - token))
        != NULL)
    {
        return xrootd_token_malformed(log);
    }

    hdr_b64_len = (size_t) (dot1 - token);
    pay_b64_len = (size_t) (dot2 - dot1 - 1);
    sig_b64_len = token_len - (size_t) (dot2 + 1 - token);

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

    sig_len = b64url_decode(dot2 + 1, sig_b64_len, sig_bin, sizeof(sig_bin));
    if (sig_len < 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: cannot decode JWT signature");
        return -1;
    }

    signed_len = (size_t) (dot2 - token);
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

    pay_len = b64url_decode(dot1 + 1, pay_b64_len, pay_json,
                            sizeof(pay_json) - 1);
    if (pay_len < 0) {
        return xrootd_token_malformed(log);
    }
    pay_json[pay_len] = '\0';

    json_get_string((char *) pay_json, (size_t) pay_len, "iss",
                    claims->iss, sizeof(claims->iss));
    json_get_string((char *) pay_json, (size_t) pay_len, "sub",
                    claims->sub, sizeof(claims->sub));
    json_get_string((char *) pay_json, (size_t) pay_len, "aud",
                    claims->aud, sizeof(claims->aud));
    json_get_string((char *) pay_json, (size_t) pay_len, "scope",
                    claims->scope_raw, sizeof(claims->scope_raw));

    json_get_int64((char *) pay_json, (size_t) pay_len, "exp",
                   &claims->exp);
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
        if (strcmp(claims->aud, expected_audience) != 0) {
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
    if (claims->exp > 0
        && now > (time_t) claims->exp + XROOTD_TOKEN_CLOCK_SKEW_SECS)
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

    {
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
