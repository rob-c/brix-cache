#ifndef BRIX_TOKEN_OAUTH2_H
#define BRIX_TOKEN_OAUTH2_H

#include <ngx_config.h>
#include <ngx_core.h>

/* WHAT: Public header for OAuth2/OIDC token response parsing — extracts access_token from JSON-encoded OIDC responses.
* WHY: OIDC token endpoints return JSON bodies containing access tokens. This provides the API interface for callers to extract tokens without embedding jansson parsing logic directly in handlers (used by token/validate.c, s3/auth.c).
* HOW: brix_oauth2_parse_access_token() validates input bounds, loads JSON via json_loads with duplicate rejection, extracts "access_token" string field, checks length against output capacity, copies with NUL termination. Returns NGX_OK on success or NGX_ERROR with error message populated in err buffer.
*/

/* WHAT: Parse JSON-encoded OAuth2/OIDC access_token response into caller-provided buffer.
* WHY: OIDC token endpoints return JSON bodies containing access tokens. This provides a single entry point for extracting the token without requiring callers to embed jansson parsing logic.
* HOW: Validates out/out_sz non-empty, zeroes output, loads JSON via json_loads() with JSON_REJECT_DUPLICATES, retrieves "access_token" key verifying string type, checks strlen < out_sz, copies via ngx_memcpy including NUL terminator. Returns NGX_OK on success or NGX_ERROR with err buffer populated.
*/

ngx_int_t brix_oauth2_parse_access_token(const char *json, char *out,
    size_t out_sz, char *err, size_t err_sz);

#endif /* BRIX_TOKEN_OAUTH2_H */
