#ifndef XROOTD_TOKEN_MACAROON_H
#define XROOTD_TOKEN_MACAROON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "token.h"

/* WHAT: Public header for macaroon token validation — HMAC-SHA256 signature chaining, WLCG caveat parsing, and third-party discharge verification.
 * WHY: Provides the API interface for callers to validate WLCG macaroon tokens (used by grid computing delegation) alongside JWTs in the unified token layer. Supports single-root validation and multi-discharge bundles with up to 8 discharges per root.
 * HOW: xrootd_token_is_macaroon() routes token type; xrootd_macaroon_secret_parse() converts hex secret to binary key material; xrootd_macaroon_validate_bundle() validates space-separated bundles with discharge verification; xrootd_macaroon_validate() thin wrapper for single-root tokens. */

/* WHAT: Verify an HMAC-chained Macaroon root token — reconstruct signature chain from root key, parse caveats into claims.
 * WHY: Single-root macaroons (no third-party discharge requirements) are the simplest authorization form. This function validates the token's integrity via HMAC chain verification and extracts activity/path/expiry constraints for access control decisions.
 * HOW: Delegate to xrootd_macaroon_validate_bundle() which handles both single-root and multi-discharge cases uniformly — no local logic in this wrapper. */
int xrootd_macaroon_validate(ngx_log_t *log,
    const char *token, size_t token_len,
    const u_char *root_key, size_t root_key_len,
    xrootd_token_claims_t *claims);

/* WHAT: Validate a space-separated Macaroon bundle with discharge verification for each third-party caveat.
 * WHY: WLCG delegation requires discharges — each third-party caveat in the root macaroon must be accompanied by a corresponding discharge token that proves authorization from that third party. Bundle validation ensures all discharges are valid and their constraints intersect correctly with root claims.
 * HOW: Space-tokenize bundle → base64url-decode root → parse_core to extract third-party caveats (cid+vid) → for each caveat find matching discharge by identifier match → decrypt vid via AES-256-CBC using sig_before_cid as key → validate discharge → intersect discharge expiry/paths into root claims. */
int xrootd_macaroon_validate_bundle(ngx_log_t *log,
    const char *token, size_t token_len,
    const u_char *root_key, size_t root_key_len,
    xrootd_token_claims_t *claims);

/* WHAT: Convert hex-encoded macaroon root secret string into binary bytes for HMAC computation.
 * WHY: Macaroon secrets are stored as hex strings in config files or environment variables; the HMAC chain requires raw binary key material. This helper performs safe hex-to-binary conversion with bounds checking and nibble validation. */
ssize_t xrootd_macaroon_secret_parse(const char *hex, size_t hex_len,
    u_char *bin, size_t bin_max);

/* WHAT: Quick heuristic to distinguish macaroon tokens from JWT tokens for routing.
 * WHY: The token layer needs to dispatch authentication logic — JWTs use RS256 signature verification while macaroons use HMAC chain reconstruction. This check avoids expensive parsing of non-macaroon tokens by exploiting the structural difference (JWTs always have 3 dot-separated parts, macaroons don't). */
int xrootd_token_is_macaroon(const char *token, size_t token_len);

#endif /* XROOTD_TOKEN_MACAROON_H */
