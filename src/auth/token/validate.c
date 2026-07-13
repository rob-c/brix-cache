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
#include "b64url.h"
#include "json.h"
#include "scopes.h"
#include "macaroon.h"
#include "issuer_registry.h"
#include "subject_map.h"
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
 * token_hdr_t — decoded JOSE header fields needed by the pipeline.
 *
 * WHAT: The "alg" and "kid" header claims extracted from the JWS protected
 *       header, sized to their validated maxima.
 * WHY:  token_check_header() produces them and token_verify_signature()
 *       consumes them; a tiny struct keeps both helpers under the 5-parameter
 *       gate and makes the header→signature data flow explicit.
 * HOW:  Zeroed then filled by token_check_header(); empty kid ("") means the
 *       token asserted no key id (rotation-grace multi-key path).
 */
typedef struct {
    char alg[16];
    char kid[128];
} token_hdr_t;

/*
 * token_sig_input_t — everything the algorithm-dispatched verifier needs.
 *
 * WHAT: The signing input ("header.payload" bytes + length) and the decoded
 *       binary signature, plus the accepted algorithm name.
 * WHY:  token_sig_ok() is called from both the kid-exact-match path and the
 *       kid-absent multi-key loop; passing one struct + the candidate key
 *       keeps the helper at 2 parameters (was 6).
 * HOW:  Filled once in token_verify_signature() after the signature segment is
 *       base64url-decoded; only the candidate EVP_PKEY varies per call.
 */
typedef struct {
    const char   *alg;
    const u_char *signed_data;
    size_t        signed_len;
    const u_char *sig;
    size_t        sig_len;
} token_sig_input_t;

/*
 * token_sig_ok — dispatch signature verification by algorithm.
 *
 * WHAT: Calls brix_token_verify_es256() for ES256 or brix_token_verify_rs256()
 *       for RS256 (the only two accepted algorithms at this call site).
 * WHY:  DRY helper shared by the kid-present single-key path and the kid-absent
 *       multi-key fallback loop; avoids duplicating the ES256/RS256 branch.
 * HOW:  strcmp on alg (already validated non-NULL before this point).
 *       Returns 1 on success, 0 on failure, matching the underlying verify API.
 */
static int
token_sig_ok(const token_sig_input_t *in, EVP_PKEY *pkey)
{
    if (strcmp(in->alg, "ES256") == 0) {
        return brix_token_verify_es256(in->signed_data, in->signed_len,
                                       in->sig, in->sig_len, pkey);
    }
    return brix_token_verify_rs256(in->signed_data, in->signed_len,
                                   in->sig, in->sig_len, pkey);
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
 * token_check_header — decode and police the JWS protected header (RFC 7515).
 *
 * WHAT: Base64url-decodes segment 0, extracts "alg" and "kid" into *hdr,
 *       rejects any algorithm other than RS256/ES256, and rejects any token
 *       asserting a "crit" header. Returns 0 on acceptance, -1 on rejection
 *       (reason logged).
 * WHY:  alg:"none" bypass — a token that declares alg:"none" or any other
 *       algorithm must be rejected BEFORE signature verification, preventing
 *       an attacker from forging an unsigned token. RFC 7515 §4.1.11: we
 *       implement no `crit` extension parameters, so any token asserting
 *       critical headers we do not understand MUST be rejected.
 * HOW:  Decode failure routes through brix_token_malformed() (same log line as
 *       every structural rejection); alg/kid are zeroed before extraction so
 *       an absent kid reads as "".
 */
static int
token_check_header(const brix_token_validate_args_t *a, const xrdjwt_seg *seg,
    token_hdr_t *hdr)
{
    u_char   hdr_json[2048];
    ssize_t  hdr_len;

    hdr_len = b64url_decode(seg[0].p, seg[0].n, hdr_json,
                            sizeof(hdr_json) - 1);
    if (hdr_len < 0) {
        return brix_token_malformed(a->log);
    }
    hdr_json[hdr_len] = '\0';

    ngx_memzero(hdr->alg, sizeof(hdr->alg));
    ngx_memzero(hdr->kid, sizeof(hdr->kid));
    json_get_string((char *) hdr_json, (size_t) hdr_len, "alg", hdr->alg,
                    sizeof(hdr->alg));
    /* alg:"none" bypass: reject any algorithm other than RS256/ES256 before
     * touching the signature.  An unsigned token (alg:"none") must be
     * rejected here, not later, or the signature step is skipped. */
    if (strcmp(hdr->alg, "RS256") != 0 && strcmp(hdr->alg, "ES256") != 0) {
        char safe_alg[64];
        token_sanitize_for_log(hdr->alg, safe_alg, sizeof(safe_alg));
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: unsupported JWT algorithm \"%s\" "
                      "(only RS256 and ES256 accepted)", safe_alg);
        return -1;
    }

    json_get_string((char *) hdr_json, (size_t) hdr_len, "kid", hdr->kid,
                    sizeof(hdr->kid));

    /* RFC 7515 §4.1.11: we implement no `crit` extension parameters, so any
     * token asserting critical headers we do not understand MUST be rejected. */
    if (json_has_member((char *) hdr_json, (size_t) hdr_len, "crit")) {
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: JWS 'crit' header not supported — rejecting");
        return -1;
    }
    return 0;
}

/*
 * token_select_key_by_kid — resolve the asserted "kid" to a trusted JWKS key.
 *
 * WHAT: Exact-matches hdr->kid against the loaded JWKS key ids; when no key
 *       matches but exactly one key is loaded, that key is used (legacy
 *       single-key leniency). Returns the key or NULL (mismatch logged).
 * WHY:  Key selection by kid is the RFC 7515 §4.1.4 path; the single-key
 *       fallback preserves long-standing behavior for deployments whose JWKS
 *       predates kid discipline.
 * HOW:  Linear scan (JWKS sets are tiny); the failure log sanitizes the
 *       attacker-controlled kid before it reaches the error log.
 */
static EVP_PKEY *
token_select_key_by_kid(const brix_token_validate_args_t *a, const token_hdr_t *hdr)
{
    EVP_PKEY *pkey = NULL;
    int       i;

    for (i = 0; i < a->key_count; i++) {
        if (strcmp(a->keys[i].kid, hdr->kid) == 0) {
            pkey = a->keys[i].pkey;
            break;
        }
    }
    if (pkey == NULL && a->key_count == 1) {
        pkey = a->keys[0].pkey;   /* preserve legacy single-key leniency */
    }
    if (pkey == NULL) {
        char safe_kid[256];
        token_sanitize_for_log(hdr->kid, safe_kid, sizeof(safe_kid));
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: no JWKS key matching kid=\"%s\"",
                      safe_kid);
    }
    return pkey;
}

/*
 * token_verify_signature — decode the signature and verify it against JWKS.
 *
 * WHAT: Base64url-decodes segment 2, then verifies the "header.payload"
 *       signing input: kid asserted → the kid-selected key only; kid absent →
 *       every JWKS key in order (rotation grace, WLCG profile §3.3). Returns
 *       0 on a valid signature, -1 otherwise (reason logged).
 * WHY:  The signature MUST be verified before any payload claim is trusted;
 *       isolating key selection + verification keeps that trust boundary in
 *       one auditable helper.
 * HOW:  signed_len spans "header.payload" (seg lengths + the joining dot);
 *       verification dispatches through token_sig_ok() per accepted algorithm.
 */
static int
token_verify_signature(const brix_token_validate_args_t *a, const xrdjwt_seg *seg,
    const token_hdr_t *hdr)
{
    u_char             sig_bin[512];
    ssize_t            sig_len;
    token_sig_input_t  in;
    int                sig_ok = 0;
    int                i;

    sig_len = b64url_decode(seg[2].p, seg[2].n, sig_bin, sizeof(sig_bin));
    if (sig_len < 0) {
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: cannot decode JWT signature");
        return -1;
    }

    in.alg         = hdr->alg;
    in.signed_data = (const u_char *) a->token;
    in.signed_len  = seg[0].n + 1 + seg[1].n;   /* "header.payload" */
    in.sig         = sig_bin;
    in.sig_len     = (size_t) sig_len;

    if (hdr->kid[0] != '\0') {
        /* kid asserted: exact-match the named key only. */
        EVP_PKEY *pkey = token_select_key_by_kid(a, hdr);
        if (pkey == NULL) {
            return -1;
        }
        sig_ok = token_sig_ok(&in, pkey);
    } else {
        /* kid absent: try every JWKS key in order (rotation grace, §3.3). */
        for (i = 0; i < a->key_count && !sig_ok; i++) {
            sig_ok = token_sig_ok(&in, a->keys[i].pkey);
        }
    }
    if (!sig_ok) {
        ngx_log_error(NGX_LOG_WARN, a->log, 0,
                      "brix_token: JWT signature verification failed");
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
