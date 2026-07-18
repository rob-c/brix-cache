/*
 * validate_sig.c — JWT signature plane: JOSE-header policing and JWKS
 * signature verification for WLCG/SciToken bearer tokens.
 *
 * WHAT: Owns the two trust-boundary steps that must run — and pass — before any
 * payload claim is believed: token_check_header() base64url-decodes the JWS
 * protected header, extracts "alg"/"kid", and rejects any algorithm other than
 * RS256/ES256 or any asserted "crit" header (the alg:"none" forgery defence);
 * token_verify_signature() base64url-decodes the signature segment and verifies
 * the "header.payload" signing input against the loaded JWKS keys. The kid
 * key-selection helper and the algorithm-dispatched verifier are file-local.
 *
 * WHY: validate.c exceeded the ~500-line file-size guard, so the security-
 * critical signature plane was split out under the phase-79 guard. It shares the
 * decoded-header carrier (token_hdr_t), the log sanitiser, and the malformed-log
 * helper with the main pipeline via validate_internal.h. The bytes verified, the
 * algorithm allow-list, the RFC 7515 §4.1.4 kid selection (with legacy single-
 * key leniency and rotation-grace multi-key fallback), and the EVP dispatch are
 * preserved exactly from the original single-file implementation.
 *
 * HOW: token_check_header() → b64url_decode seg[0] → json "alg"/"kid" → allow-
 * list + "crit" rejection. token_verify_signature() → b64url_decode seg[2] →
 * build the token_sig_input_t over "header.payload" → dispatch via token_sig_ok()
 * (ES256/RS256) against the kid-selected key, or every JWKS key in order when kid
 * is absent. Rejections route their untrusted inputs through token_sanitize_for_log()
 * or brix_token_malformed() (shared with validate.c) so log lines stay uniform.
 */

#include "token_internal.h"
#include "validate_internal.h"
#include "b64url.h"
#include "json.h"

#include <string.h>

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
int
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
 *       key). Returns the matched key or NULL (mismatch logged).
 * WHY:  Key selection by kid is the RFC 7515 §4.1.4 path. An asserted kid is
 *       authoritative: it MUST name a key present in the JWKS. The former
 *       single-key fallback (unmatched kid → use the sole loaded key anyway)
 *       let a self-inconsistent kid slip through, so the kid was not truly
 *       authoritative — the signature still gated, but the resolved key did
 *       not match the client's own assertion (hyper-hardening D-5). A legit
 *       single-key deployment either asserts the correct kid (exact match) or
 *       omits kid entirely (handled by the caller's rotation-grace trial), so
 *       nothing spec-faithful depends on the fallback.
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
int
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
