#include "dashboard_auth_internal.h"

#include <openssl/crypto.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

/*
 * dashboard/auth.c — session-cookie verification for the live monitor.
 *
 * This file owns the "verify a session" half of dashboard authentication; the
 * "issue a session" login flow is in dashboard_auth_login.c, the credential
 * store + session HMAC in dashboard_auth_creds.c, and the untrusted-input
 * parsing in dashboard_auth_parse.c (phase-79 split of the former 1104-line
 * auth.c — see dashboard_auth_internal.h for the cross-file seam).
 *
 * COOKIE FORMAT:  xrd_dashboard=<hex32_hmac>.<timestamp_s>
 *   - timestamp_s  is Unix time (decimal, seconds) when the cookie was issued.
 *   - hmac         is HMAC-SHA256(password, timestamp_s) as 32 lowercase hex bytes.
 *
 * VERIFICATION:
 *   1. Split on '.'; parse timestamp_s.
 *   2. Reject if now - timestamp_s > session_ttl.
 *   3. Recompute HMAC(password, timestamp_s); constant-time compare with CRYPTO_memcmp.
 *
 * SECURITY NOTE:
 *   This is a minimal, firewalled-admin-only mechanism.  The password is in
 *   nginx.conf; the cookie carries no user identity.  The module is NOT
 *   suitable for Internet-facing deployments without additional firewall rules.
 */

/* Fields recovered from a "<hex>.<ts>[.<username>]" session cookie: the
 * timestamp field length, the (multi-user only) username, and the HMAC key
 * selected for verification (per-user hash or the single configured password). */
typedef struct {
    char       username[257];
    size_t     username_len;
    size_t     ts_len;
    ngx_str_t  key;
} dash_cookie_parse_t;

/*
 * WHAT: Validate the cookie's leading HMAC field and copy it out NUL-terminated.
 * WHY:  The HMAC field must be exactly HMAC_HEX_LEN bytes ending at the first
 *       '.'; anything else (no dot, leading dot, wrong-length hex) is a
 *       malformed cookie and is rejected (fail closed) with an audit event.
 * HOW:  Locate the first '.', check the field length, copy into given_hex
 *       (HMAC_HEX_LEN + 1 bytes) and return the dot via *dot_out.
 *       Returns NGX_OK or NGX_HTTP_UNAUTHORIZED.
 */
static ngx_int_t
dash_auth_extract_hex(u_char *cookie_val, size_t cookie_val_len,
    char given_hex[HMAC_HEX_LEN + 1], u_char **dot_out)
{
    u_char  *dot = NULL;
    size_t   i;

    /* Find the '.' separator between hex and timestamp. */
    for (i = 0; i < cookie_val_len; i++) {
        if (cookie_val[i] == '.') { dot = cookie_val + i; break; }
    }

    if (dot == NULL || dot == cookie_val ||
        (size_t)(dot - cookie_val) != HMAC_HEX_LEN)
    {
        brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth malformed cookie", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Extract and null-terminate the HMAC hex. */
    ngx_memcpy(given_hex, cookie_val, HMAC_HEX_LEN);
    given_hex[HMAC_HEX_LEN] = '\0';

    *dot_out = dot;
    return NGX_OK;
}

/*
 * WHAT: Split the cookie's post-HMAC fields and select the HMAC key.
 * WHY:  In multi-user mode a SECOND '.' separates the timestamp from the
 *       username: "<hex>.<ts>.<username>"; the per-user password hash becomes
 *       the HMAC key, so the cookie is verifiable only against the same user
 *       it was issued for. In single-user mode everything after "<hex>." is
 *       the timestamp and the configured password is the key.
 * HOW:  Locate dot2 (multi-user), bound-check and copy the username, resolve
 *       the user; fill ps->{username,username_len,ts_len,key}. Structural
 *       anomalies and unknown users return NGX_HTTP_UNAUTHORIZED (audited
 *       where the original behavior audited).
 */
static ngx_int_t
dash_auth_resolve_key(const ngx_http_brix_dashboard_loc_conf_t *conf,
    u_char *cookie_val, size_t cookie_val_len, const u_char *dot,
    dash_cookie_parse_t *ps)
{
    u_char                           *dot2 = NULL;
    size_t                            i;
    ngx_http_brix_dashboard_user_t *user;

    if (!dashboard_users_enabled(conf)) {
        ps->ts_len = cookie_val_len - HMAC_HEX_LEN - 1;
        ps->key = conf->password;
        return NGX_OK;
    }

    for (i = (size_t) (dot - cookie_val) + 1; i < cookie_val_len; i++) {
        if (cookie_val[i] == '.') {
            dot2 = cookie_val + i;
            break;
        }
    }

    if (dot2 == NULL) {
        brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth missing username", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }

    ps->ts_len = (size_t) (dot2 - dot - 1);
    ps->username_len = cookie_val_len - (size_t) (dot2 - cookie_val) - 1;
    if (ps->username_len == 0 || ps->username_len >= sizeof(ps->username)) {
        return NGX_HTTP_UNAUTHORIZED;
    }
    ngx_memcpy(ps->username, dot2 + 1, ps->username_len);
    ps->username[ps->username_len] = '\0';

    user = dashboard_find_user(conf, ps->username, ps->username_len);
    if (user == NULL) {
        brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth unknown user", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }
    ps->key = user->password_hash;
    return NGX_OK;
}

/*
 * WHAT: Extract, parse, and freshness-check the cookie timestamp field.
 * WHY:  Cookies older than session_ttl are expired; cookies dated more than
 *       60s in the future (clock skew tolerance) are rejected to bound replay
 *       of a forged future timestamp.
 * HOW:  Copy [dot+1, dot+1+ts_len) into ts_str (NUL-terminated), strtol it,
 *       reject non-positive or trailing-garbage values, then apply the TTL
 *       window. Each rejection emits the same audit event as before.
 */
static ngx_int_t
dash_auth_check_timestamp(const u_char *dot, size_t ts_len,
    ngx_uint_t session_ttl, char ts_str[TIMESTAMP_MAX + 1])
{
    char    *endptr;
    long     ts;
    time_t   now;

    /* Extract and null-terminate the timestamp. */
    if (ts_len == 0 || ts_len > TIMESTAMP_MAX) {
        brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth bad timestamp", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }
    ngx_memcpy(ts_str, dot + 1, ts_len);
    ts_str[ts_len] = '\0';

    endptr = NULL;
    ts = strtol(ts_str, &endptr, 10);
    if (ts <= 0 || endptr == NULL || *endptr != '\0') {
        brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth bad timestamp", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }

    now = time(NULL);
    if ((long) now - ts > (long) session_ttl || ts > (long) now + 60) {
        brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth expired cookie", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }

    return NGX_OK;
}

/*
 * WHAT: Recompute the session HMAC over the parsed cookie fields and compare
 *       it against the presented signature.
 * WHY:  This is the actual proof of possession: only a holder of the HMAC key
 *       (configured password / per-user hash) can mint a valid signature.
 * HOW:  dashboard_cookie_hmac() re-derives expected_hex for the active auth
 *       mode; CRYPTO_memcmp never short-circuits on the first differing byte,
 *       which would leak how much of the signature an attacker has guessed.
 */
static ngx_int_t
dash_auth_verify_hmac(const dash_cookie_parse_t *ps, const char *ts_str,
    const char given_hex[HMAC_HEX_LEN + 1], ngx_uint_t multi_user)
{
    char  expected_hex[HMAC_HEX_LEN + 1];

    if (dashboard_cookie_hmac(&ps->key, ts_str, ps->ts_len,
                              multi_user ? ps->username : NULL,
                              ps->username_len, expected_hex) != NGX_OK)
    {
        return NGX_HTTP_UNAUTHORIZED;
    }

    if (CRYPTO_memcmp(expected_hex, given_hex, HMAC_HEX_LEN) != 0) {
        brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth bad signature", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }

    return NGX_OK;
}

/* Public: check auth cookie */
ngx_int_t
ngx_http_brix_dashboard_check_auth(ngx_http_request_t *r,
    const ngx_http_brix_dashboard_loc_conf_t *conf,
    ngx_uint_t suppress_missing_cookie)
{
    u_char               *cookie_val;
    size_t                cookie_val_len;
    u_char               *dot;
    char                  ts_str[TIMESTAMP_MAX + 1];
    char                  given_hex[HMAC_HEX_LEN + 1];
    ngx_int_t             rc;
    dash_cookie_parse_t   ps;

    if (conf->password.len == 0 && !dashboard_users_enabled(conf)) {
        /* No password configured — dashboard accessible without auth. */
        return NGX_OK;
    }

    /* Cookie layout (see file header): "<64-hex HMAC>.<ts>" in single-user mode,
     * "<64-hex HMAC>.<ts>.<username>" in multi-user mode. The parse below
     * locates the dot(s), validates each field, then recomputes and compares the
     * HMAC. Any structural anomaly is treated as unauthorized (fail closed). */

    if (dashboard_find_cookie(r, "xrd_dashboard", 13, &cookie_val,
                              &cookie_val_len) != NGX_OK)
    {
        /* A missing cookie is the normal case for an anonymous viewer; the
         * read-API caller passes suppress_missing_cookie=1 so anonymous polls do
         * not spam the audit ring. The config-download and other sensitive
         * callers pass 0, so unauthenticated attempts there are always audited.
         * Present-but-invalid cookies (malformed/expired/forged, above helpers)
         * are always logged regardless. */
        if (!suppress_missing_cookie) {
            brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                       NGX_HTTP_UNAUTHORIZED,
                                       "dashboard auth missing cookie", NULL);
        }
        return NGX_HTTP_UNAUTHORIZED;
    }

    rc = dash_auth_extract_hex(cookie_val, cookie_val_len, given_hex, &dot);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&ps, sizeof(ps));
    rc = dash_auth_resolve_key(conf, cookie_val, cookie_val_len, dot, &ps);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = dash_auth_check_timestamp(dot, ps.ts_len, conf->session_ttl, ts_str);
    if (rc != NGX_OK) {
        return rc;
    }

    return dash_auth_verify_hmac(&ps, ts_str, given_hex,
                                 dashboard_users_enabled(conf));
}
