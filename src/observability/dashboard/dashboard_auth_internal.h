#pragma once

/*
 * dashboard/dashboard_auth_internal.h — cross-file seam for the dashboard
 * authentication unit (phase-79 file-size split of auth.c).
 *
 * WHAT: Shared constants, the urlencoded-field output descriptor, and the
 *       entry points that the three dashboard-auth translation units call
 *       across their file boundary:
 *         - dashboard_auth_parse.c  — Cookie/form request parsing
 *         - dashboard_auth_creds.c  — user credential store + session HMAC
 *         - auth.c                  — session-cookie verification (check_auth)
 *         - dashboard_auth_login.c  — login GET form + POST verify flow
 *
 * WHY: auth.c was one 1104-line file mixing request parsing, the credential
 *      store, cookie verification, and the login flow. Splitting it by concern
 *      keeps each file focused and under the size cap; the functions that are
 *      genuinely called across the new boundary are declared here (and are the
 *      ONLY non-static symbols the split promotes). Everything else stays file-
 *      local static — behaviour is byte-for-byte unchanged from the original.
 *
 * Requires: dashboard_http.h (ngx types + ngx_http_brix_dashboard_loc_conf_t /
 *           ngx_http_brix_dashboard_user_t) before inclusion.
 */

#include "dashboard_http.h"

#define HMAC_HEX_LEN  64    /* SHA-256 = 32 bytes = 64 hex chars */
#define TIMESTAMP_MAX 20    /* enough for a Unix timestamp string */

/* Decoded-field destination for dashboard_form_value(): a caller-owned buffer
 * of `size` bytes; the decoded, NUL-terminated value length lands in `len`. */
typedef struct {
    char   *buf;
    size_t  size;
    size_t  len;
} dash_form_out_t;

/* ---- Request parsing (dashboard_auth_parse.c) ---- */

/* Find the value of a named cookie in the Cookie: header. Returns NGX_OK and
 * sets *val / *val_len on success, NGX_DECLINED if not found. */
ngx_int_t dashboard_find_cookie(ngx_http_request_t *r,
    const char *name, size_t name_len, u_char **val, size_t *val_len);

/* Extract and URL-decode one field from an application/x-www-form-urlencoded
 * request body. Returns NGX_OK on the first match (out filled), NGX_DECLINED
 * if the field is absent. */
ngx_int_t dashboard_form_value(const u_char *body, size_t body_len,
    const char *name, dash_form_out_t *out);

/* ---- Credential store + session HMAC (dashboard_auth_creds.c) ---- */

/* Non-zero when the multi-user credential mode is configured. */
ngx_uint_t dashboard_users_enabled(
    const ngx_http_brix_dashboard_loc_conf_t *conf);

/* Linear lookup of a configured user by exact username; NULL if absent or the
 * multi-user mode is not enabled. */
ngx_http_brix_dashboard_user_t *dashboard_find_user(
    const ngx_http_brix_dashboard_loc_conf_t *conf,
    const char *username, size_t username_len);

/* Verify a plaintext password against a stored user credential (crypt(3) hash
 * or legacy plaintext). Returns NGX_OK / NGX_DECLINED / NGX_ERROR. */
ngx_int_t dashboard_verify_user_password(ngx_pool_t *pool,
    ngx_http_brix_dashboard_user_t *user,
    const char *password, size_t password_len);

/* Derive the cookie signature for a session into out_hex (HMAC_HEX_LEN + 1
 * bytes). Single-user signs "<ts>"; multi-user signs "<ts>.<username>".
 * Returns NGX_OK, or NGX_DECLINED if inputs exceed the message caps. */
ngx_int_t dashboard_cookie_hmac(const ngx_str_t *key,
    const char *ts, size_t ts_len,
    const char *username, size_t username_len,
    char out_hex[HMAC_HEX_LEN + 1]);
