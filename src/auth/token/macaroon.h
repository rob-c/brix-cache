#ifndef BRIX_TOKEN_MACAROON_H
#define BRIX_TOKEN_MACAROON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "token.h"

/*
 * WHAT: Public header for macaroon token validation.
 *       HMAC-SHA256 signature chaining, WLCG caveat parsing, third-party discharge verification.
 *
 * WHY: Provides API interface for callers to validate WLCG macaroon tokens
 *      (used by grid computing delegation) alongside JWTs in unified token layer.
 *      Supports single-root validation and multi-discharge bundles (up to 8 discharges per root).
 *
 * HOW: Four exported functions:
 *        - brix_token_is_macaroon(): routes token type (JWT vs macaroon)
 *        - brix_macaroon_secret_parse(): converts hex secret to binary key material
 *        - brix_macaroon_validate_bundle(): validates space-separated bundles with discharge verification
 *        - brix_macaroon_validate(): thin wrapper for single-root tokens
 */

/*
 * WHAT: Verify HMAC-chained Macaroon root token.
 *       Reconstruct signature chain from root key, parse caveats into claims.
 *
 * WHY: Single-root macaroons (no third-party discharge requirements) are simplest authorization form.
 *      Validates token integrity via HMAC chain verification.
 *      Extracts activity/path/expiry constraints for access control decisions.
 *
 * HOW: Delegates to brix_macaroon_validate_bundle() which handles both
 *      single-root and multi-discharge cases uniformly — no local logic in wrapper.
 */
int brix_macaroon_validate(ngx_log_t *log,
    const char *token, size_t token_len,
    const u_char *root_key, size_t root_key_len,
    brix_token_claims_t *claims);

/*
 * WHAT: Validate space-separated Macaroon bundle with discharge verification.
 *       Each third-party caveat requires corresponding discharge token.
 *
 * WHY: WLCG delegation requires discharges — each third-party caveat in root macaroon
 *      must be accompanied by discharge token proving authorization from that third party.
 *      Bundle validation ensures all discharges are valid and constraints intersect
 *      correctly with root claims.
 *
 * HOW: Six-step process:
 *        1. Space-tokenize bundle
 *        2. Base64url-decode root token
 *        3. parse_core() extracts third-party caveats (cid + vid)
 *        4. For each caveat: find matching discharge by identifier match
 *        5. Decrypt vid via AES-256-CBC using sig_before_cid as key
 *        6. Validate discharge and intersect expiry/paths into root claims
 */
int brix_macaroon_validate_bundle(ngx_log_t *log,
    const char *token, size_t token_len,
    const u_char *root_key, size_t root_key_len,
    brix_token_claims_t *claims);

/*
 * WHAT: Convert hex-encoded macaroon root secret string into binary bytes.
 *       Output used for HMAC computation in signature chain reconstruction.
 *
 * WHY: Macaroon secrets stored as hex strings in config files or environment variables.
 *      HMAC chain requires raw binary key material.
 *      Helper performs safe hex-to-binary conversion with bounds checking
 *      and nibble validation.
 */
ssize_t brix_macaroon_secret_parse(const char *hex, size_t hex_len,
    u_char *bin, size_t bin_max);

/*
 * WHAT: Quick heuristic to distinguish macaroon tokens from JWT tokens.
 *       Used for routing authentication logic dispatch.
 *
 * WHY: Token layer needs to dispatch authentication logic:
 *        - JWTs: use RS256 signature verification
 *        - Macaroons: use HMAC chain reconstruction
 *      Check avoids expensive parsing of non-macaroon tokens by exploiting
 *      structural difference (JWTs always have 3 dot-separated parts,
 *      macaroons don't).
 */
int brix_token_is_macaroon(const char *token, size_t token_len);

#endif /* BRIX_TOKEN_MACAROON_H */
