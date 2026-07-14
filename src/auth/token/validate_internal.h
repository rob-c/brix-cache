#pragma once

/* Internal descriptors and cross-file entry points shared by the JWT
 * validation split (validate.c / validate_sig.c).
 *
 * WHAT: Declares the decoded-JOSE-header carrier (token_hdr_t), the two
 * log-sanitising helpers used on every rejection path (token_sanitize_for_log,
 * brix_token_malformed), and the two signature-plane entry points that cross a
 * translation-unit boundary after the phase-79 file-size split
 * (token_check_header decodes+polices the protected header; token_verify_signature
 * decodes segment 2 and verifies it against the JWKS keys).
 *
 * WHY: validate.c exceeded the ~500-line file-size guard, so the JWT signature
 * plane (structural/alg/kid key-selection/EVP verify) was carved into
 * validate_sig.c. The main pipeline in validate.c still drives those two steps
 * and shares the sanitiser + malformed-log helpers with them (and with the
 * registry plane in validate_registry.c). Grouping the shared struct and the
 * crossing entry points here keeps each definition in exactly one place while
 * preserving the identical structural checks, algorithm allow-list, key
 * selection, and EVP signature verification of the original single-file
 * implementation.
 *
 * HOW: Requires token_internal.h (brix_token_validate_args_t via token.h, ngx
 * types, EVP) and b64url.h (xrdjwt_seg) before inclusion — both are included
 * here directly. token_hdr_t carries the validated "alg"/"kid" JOSE claims from
 * token_check_header() to token_verify_signature(); an empty kid ("") means the
 * token asserted no key id (the rotation-grace multi-key path). The two helper
 * decls point at definitions that live in validate.c (the shared owner). */

#include "token_internal.h"   /* ngx types, token.h: validate_args, EVP */
#include "b64url.h"           /* xrdjwt_seg */

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

/* token_sanitize_for_log — escape control bytes before an untrusted string
 * (issuer/subject/scope/kid/alg from the wire) reaches the error log; prevents
 * log-forgery via embedded newlines. Defined in validate.c, shared by the
 * signature and registry planes. */
void token_sanitize_for_log(const char *in, char *out, size_t outsz);

/* brix_token_malformed — single "malformed JWT structure" WARN + return -1,
 * used by every structural-rejection path so operators see one consistent line.
 * Defined in validate.c, shared with the header-decode path in validate_sig.c. */
int brix_token_malformed(ngx_log_t *log);

/* token_check_header — base64url-decode segment 0, extract "alg"/"kid" into
 * *hdr, reject any algorithm other than RS256/ES256 and any asserted "crit"
 * header (alg:"none" bypass defence). 0 on acceptance, -1 on rejection.
 * Defined in validate_sig.c. */
int token_check_header(const brix_token_validate_args_t *a,
    const xrdjwt_seg *seg, token_hdr_t *hdr);

/* token_verify_signature — base64url-decode segment 2 and verify the
 * "header.payload" signing input against the JWKS keys (kid-selected key when
 * asserted, else every key in rotation-grace order). 0 on a valid signature,
 * -1 otherwise. Defined in validate_sig.c. */
int token_verify_signature(const brix_token_validate_args_t *a,
    const xrdjwt_seg *seg, const token_hdr_t *hdr);
