#ifndef XROOTD_TOKEN_MACAROON_ISSUE_H
#define XROOTD_TOKEN_MACAROON_ISSUE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <time.h>

/*
 * Maximum base64url-encoded output length for an issued macaroon.
 * A macaroon with location + identifier + 3 caveats + signature
 * is at most ~512 bytes binary, producing ~700 chars base64url.
 * 1024 provides comfortable headroom.
 */
#define XROOTD_MACAROON_ISSUE_OUT_MAX  1024

/*
 * xrootd_macaroon_issue — mint a new single-root WLCG macaroon.
 *
 * Builds the binary macaroon packet sequence, computes the HMAC-SHA256
 * chain, and writes the base64url-encoded result to out_b64.
 *
 * Parameters:
 *   log          for error reporting
 *   root_key     HMAC root key bytes (obtain via xrootd_macaroon_secret_parse)
 *   root_key_len length of root_key in bytes
 *   location     URI claim for the location: packet (e.g. "https://se.example.org");
 *                NULL or empty to omit
 *   identifier   unique token identifier string; must be non-NULL and non-empty
 *   activities   comma-separated WLCG activity string for the activity: caveat
 *                (e.g. "DOWNLOAD,LIST" or "UPLOAD"); NULL to omit
 *   path         path prefix for the path: caveat (e.g. "/atlas"); NULL to omit
 *   expiry       Unix timestamp for the before: caveat; 0 to omit
 *   out_b64      output buffer for the base64url-encoded macaroon
 *   out_b64sz    size of out_b64 (must be >= XROOTD_MACAROON_ISSUE_OUT_MAX)
 *
 * Returns NGX_OK on success, NGX_ERROR on any failure.
 */
ngx_int_t xrootd_macaroon_issue(ngx_log_t *log,
    const u_char *root_key, size_t root_key_len,
    const char *location,
    const char *identifier,
    const char *activities,
    const char *path,
    time_t expiry,
    char *out_b64, size_t out_b64sz);

#endif /* XROOTD_TOKEN_MACAROON_ISSUE_H */
