#pragma once

#include <ngx_config.h>
#include <ngx_core.h>
#include "token.h"

/*
 * Macaroon validation.
 * Supports WLCG-style Macaroons with activity: and path: caveats.
 */

/*
 * xrootd_macaroon_validate — verify an HMAC-chained Macaroon token.
 *
 * Checks:
 *   1. Signature: re-derives the HMAC chain from the root key.
 *   2. Caveats: parses "activity", "path", and "before" (expiry).
 *
 * Map activities to scopes:
 *   - DOWNLOAD -> storage.read
 *   - LIST     -> storage.read
 *   - UPLOAD   -> storage.write
 *   - DELETE   -> storage.write
 *   - MANAGE   -> storage.modify
 *
 * Returns: 0 on success, -1 on failure.
 */
int xrootd_macaroon_validate(ngx_log_t *log,
    const char *token, size_t token_len,
    const u_char *root_key, size_t root_key_len,
    xrootd_token_claims_t *claims);

/* Helper to parse hex secret string into binary */
ssize_t xrootd_macaroon_secret_parse(const char *hex, size_t hex_len,
    u_char *bin, size_t bin_max);

/* Helper to detect if a token looks like a Macaroon (not a JWT) */
int xrootd_token_is_macaroon(const char *token, size_t token_len);
