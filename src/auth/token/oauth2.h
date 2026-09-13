#ifndef BRIX_TOKEN_OAUTH2_H
#define BRIX_TOKEN_OAUTH2_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * WHAT: Public header for OAuth2/OIDC token response parsing.
 *       Extracts access_token from JSON-encoded OIDC responses.
 *
 * WHY: OIDC token endpoints return JSON bodies containing access tokens.
 *      Provides API interface for callers to extract tokens without
 *      embedding jansson parsing logic directly in handlers.
 *      Used by token/validate.c and s3/auth.c.
 *
 * HOW: brix_oauth2_parse_access_token() performs six steps:
 *        1. Validates input bounds (non-NULL json, out, err)
 *        2. Loads JSON via json_loads() with JSON_REJECT_DUPLICATES
 *        3. Extracts "access_token" string field
 *        4. Checks strlen(access_token) < out_sz
 *        5. Copies with NUL termination via ngx_memcpy
 *        6. Returns NGX_OK on success, NGX_ERROR with err populated on failure
 */

/*
 * WHAT: Parse JSON-encoded OAuth2/OIDC access_token response.
 *       Output: caller-provided buffer with NUL-terminated access_token.
 *
 * WHY: OIDC token endpoints return JSON bodies containing access tokens.
 *      Provides single entry point for extracting token without requiring
 *      callers to embed jansson parsing logic.
 *
 * HOW: Six-step validation and extraction:
 *        1. Validates out/out_sz non-empty (null check + capacity > 0)
 *        2. Zeroes output buffer via memset
 *        3. Loads JSON via json_loads() with JSON_REJECT_DUPLICATES flag
 *        4. Retrieves "access_token" key, verifies string type
 *        5. Checks strlen(access_token) < out_sz (capacity check)
 *        6. Copies via ngx_memcpy including NUL terminator
 *
 * Returns: NGX_OK on success, NGX_ERROR with err buffer populated on failure
 */

ngx_int_t brix_oauth2_parse_access_token(const char *json, char *out,
    size_t out_sz, char *err, size_t err_sz);

#endif /* BRIX_TOKEN_OAUTH2_H */
