/*
 * auth_bearer.h — WLCG bearer-token helpers for the S3 endpoint.
 *
 * WHAT: Two small functions that implement WLCG bearer-token handling for the
 *       S3 REST auth gate.  They live in their own file to keep auth_sigv4_verify.c
 *       focused on SigV4 (INVARIANT §6: S3 SigV4 and WLCG bearer are mutually
 *       exclusive per request — never blend auth logic).
 *
 * WHY:  The S3 auth gate (s3_verify_sigv4) needs to detect and validate Bearer
 *       tokens before falling through to SigV4 processing.  Keeping this as a
 *       separate compilation unit makes it independently testable and avoids
 *       entangling JWT logic with SigV4 HMAC logic.
 *
 * HOW:  s3_bearer_present() is a pure predicate — it reads the Authorization
 *       header and returns 1 if it starts with "Bearer " (case-insensitive).
 *       s3_verify_bearer() validates the token via brix_token_validate(), copies
 *       the claims into the request identity via brix_identity_set_token_claims(),
 *       and returns NGX_OK on success or an already-sent 403 XML error response.
 */

#ifndef BRIX_S3_AUTH_BEARER_H
#define BRIX_S3_AUTH_BEARER_H

#include <ngx_http.h>
#include "s3.h"

/*
 * s3_bearer_present — detect a Bearer Authorization header.
 *
 * Returns 1 if the Authorization header starts with "Bearer " (7 chars,
 * case-insensitive prefix match); 0 otherwise (absent, SigV4, or other scheme).
 */
int s3_bearer_present(ngx_http_request_t *r);

/*
 * s3_verify_bearer — validate a WLCG JWT bearer token.
 *
 * Extracts the token from the Authorization: Bearer header, calls
 * brix_token_validate() against cf->jwks_keys, and on success copies the claims
 * into *identity via brix_identity_set_token_claims().
 *
 * On validation failure, an XML S3 AccessDenied response has already been sent
 * to the client; the caller must propagate the returned status directly.
 *
 * Returns NGX_OK on accept; an HTTP error code (with response already sent) on
 * reject.
 */
ngx_int_t s3_verify_bearer(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, brix_identity_t *identity);

#endif /* BRIX_S3_AUTH_BEARER_H */
