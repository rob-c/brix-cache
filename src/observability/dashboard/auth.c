#include "dashboard_http.h"
#include "core/ident.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <crypt.h>
#include <ctype.h>
#include "core/compat/alloc_guard.h"

/*
 * dashboard/auth.c — single-admin-user authentication for the live monitor.
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

#define HMAC_HEX_LEN  64    /* SHA-256 = 32 bytes = 64 hex chars */
#define TIMESTAMP_MAX 20    /* enough for a Unix timestamp string */

/* Helpers */
/*
 * WHAT: Compute HMAC-SHA256(key, msg) and emit it as 64 lowercase hex chars.
 * HOW:  out_hex must hold HMAC_HEX_LEN + 1 bytes; each of the 32 digest bytes
 *       becomes two hex chars, then a trailing NUL is written.
 */
static void
hmac_sha256_hex(const u_char *key, size_t key_len,
    const char *msg, size_t msg_len,
    char out_hex[HMAC_HEX_LEN + 1])
{
    u_char  digest[32];
    u_int   digest_len = sizeof(digest);
    int     i;

    HMAC(EVP_sha256(), key, (int) key_len,
         (const u_char *) msg, msg_len, digest, &digest_len);

    /* Byte i of the digest maps to hex chars [2*i, 2*i+1]; snprintf's size-3
     * cap covers the two hex digits plus its own NUL (overwritten next loop). */
    for (i = 0; i < 32; i++) {
        snprintf(out_hex + i * 2, 3, "%02x", (unsigned int) digest[i]);
    }
    out_hex[HMAC_HEX_LEN] = '\0';
}

/*
 * WHAT: Locate the first Cookie: request header, or NULL if the request has none.
 * WHY:  nginx 1.23.0 replaced the `headers_in.cookies` array (of
 *       ngx_table_elt_t *) with a single `headers_in.cookie` linked-list head,
 *       so read whichever the build's nginx provides — keeping the module
 *       buildable on EL stock nginx (1.20.x) as well as current releases.
 * HOW:  Either way we take the first Cookie header; find_cookie() then walks
 *       the ';'-separated pairs inside its value.
 */
static ngx_table_elt_t *
dash_cookie_header(ngx_http_request_t *r)
{
#if (nginx_version >= 1023000)
    return r->headers_in.cookie;
#else
    if (r->headers_in.cookies.nelts > 0) {
        return ((ngx_table_elt_t **) r->headers_in.cookies.elts)[0];
    }
    return NULL;
#endif
}

/*
 * WHAT: Consume one ';'-delimited "name=value" pair from a Cookie header value,
 *       advancing *pp past it (including the trailing ';' if present).
 * WHY:  find_cookie() walks the whole header pair-by-pair; isolating the scan of
 *       a single pair keeps the caller a flat match loop.
 * HOW:  Skip leading whitespace, then scan to ';' (or header end) remembering
 *       the FIRST '=' so name splits from value. Only the FIRST '=' splits; any
 *       later '=' is part of the value (cookie values may contain '=').
 *       Sets *start to the pair's name start, *eq to the '=' (or NULL for a
 *       valueless token); on return *pp points at the pair terminator before it
 *       is skipped by the caller — the value runs [*eq + 1, pair end).
 */
static void
dash_cookie_next_pair(u_char **pp, u_char *end, u_char **start, u_char **eq)
{
    u_char *p = *pp;

    /* skip whitespace */
    while (p < end && (*p == ' ' || *p == '\t')) { p++; }

    *start = p;

    *eq = NULL;
    while (p < end && *p != ';') {
        if (*p == '=' && *eq == NULL) { *eq = p; }
        p++;
    }

    *pp = p;
}

/*
 * Find the value of a named cookie in the Cookie: header.
 * Returns NGX_OK and sets *val / *val_len on success, NGX_DECLINED if not found.
 */
static ngx_int_t
find_cookie(ngx_http_request_t *r, const char *name, size_t name_len,
    u_char **val, size_t *val_len)
{
    ngx_table_elt_t  *cookie_hdr;
    u_char           *p, *end, *eq, *start;

    cookie_hdr = dash_cookie_header(r);
    if (cookie_hdr == NULL) {
        return NGX_DECLINED;
    }

    p   = cookie_hdr->value.data;
    end = p + cookie_hdr->value.len;

    /* Walk the "name1=val1; name2=val2" list one pair at a time. p advances
     * across the whole header; each iteration consumes one ';'-delimited pair. */
    while (p < end) {
        dash_cookie_next_pair(&p, end, &start, &eq);

        /* Name must match exactly (length + bytes); value is everything between
         * the '=' and the pair terminator p. */
        if (eq != NULL && (size_t)(eq - start) == name_len &&
            ngx_memcmp(start, name, name_len) == 0)
        {
            *val     = eq + 1;
            *val_len = (size_t)(p - (eq + 1));
            return NGX_OK;
        }

        if (p < end) { p++; }  /* skip ';' */
    }

    return NGX_DECLINED;
}

static ngx_uint_t
dashboard_users_enabled(const ngx_http_brix_dashboard_loc_conf_t *conf)
{
    return conf->users != NULL && conf->users->nelts > 0;
}

/* Linear lookup of a configured user by exact username; NULL if absent or the
 * multi-user mode is not enabled. Used by both login and cookie verification. */
static ngx_http_brix_dashboard_user_t *
dashboard_find_user(const ngx_http_brix_dashboard_loc_conf_t *conf,
    const char *username, size_t username_len)
{
    ngx_http_brix_dashboard_user_t *users;
    ngx_uint_t                        i;

    if (!dashboard_users_enabled(conf) || username == NULL) {
        return NULL;
    }

    users = conf->users->elts;
    for (i = 0; i < conf->users->nelts; i++) {
        if (users[i].username.len == username_len
            && ngx_memcmp(users[i].username.data, username, username_len) == 0)
        {
            return &users[i];
        }
    }

    return NULL;
}

/* Copy an ngx_str_t (not NUL-terminated) into a fresh pool-allocated C string.
 * Needed because crypt()/strlen() require a NUL terminator. */
static ngx_int_t
dashboard_copy_str0(ngx_pool_t *pool, ngx_str_t *src, char **out)
{
    char *dst;

    BRIX_PNALLOC_OR_RETURN(dst, pool, src->len + 1, NGX_ERROR);

    ngx_memcpy(dst, src->data, src->len);
    dst[src->len] = '\0';
    *out = dst;
    return NGX_OK;
}

/*
 * WHAT: Verify a plaintext password against a stored user credential.
 * WHY:  htpasswd-style files may contain either a crypt(3) hash (modern, leading
 *       '$id$' marker) or — for legacy/test configs — a literal plaintext value.
 * HOW:  '$'-prefixed -> run crypt() with the stored hash as the salt and compare
 *       the re-derived hash; otherwise fall back to a direct byte comparison.
 *       Both comparisons use CRYPTO_memcmp to avoid leaking length/content via
 *       timing. Returns NGX_OK / NGX_DECLINED / NGX_ERROR (alloc failure).
 */
static ngx_int_t
dashboard_verify_user_password(ngx_pool_t *pool,
    ngx_http_brix_dashboard_user_t *user,
    const char *password, size_t password_len)
{
    char *hash;
    char *candidate;
    char *plain;

    if (user == NULL || password == NULL) {
        return NGX_DECLINED;
    }

    if (dashboard_copy_str0(pool, &user->password_hash, &hash) != NGX_OK) {
        return NGX_ERROR;
    }

    /* crypt() needs a NUL-terminated plaintext copy (the wire password is not). */
    BRIX_PNALLOC_OR_RETURN(plain, pool, password_len + 1, NGX_ERROR);
    ngx_memcpy(plain, password, password_len);
    plain[password_len] = '\0';

    /* crypt(3) hash: the stored hash doubles as the salt; crypt re-derives the
     * full hash string, which must match byte-for-byte (incl. length). */
    if (hash[0] == '$') {
        candidate = crypt(plain, hash);
        if (candidate == NULL) {
            return NGX_DECLINED;
        }
        if (strlen(candidate) == strlen(hash)
            && CRYPTO_memcmp(candidate, hash, strlen(hash)) == 0)
        {
            return NGX_OK;
        }
        return NGX_DECLINED;
    }

    /* Legacy plaintext credential: constant-time equality of raw bytes. */
    if (password_len == user->password_hash.len
        && CRYPTO_memcmp(password, user->password_hash.data, password_len) == 0)
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

/* Decoded-field destination for dashboard_form_value(): a caller-owned buffer
 * of `size` bytes; the decoded, NUL-terminated value length lands in `len`. */
typedef struct {
    char   *buf;
    size_t  size;
    size_t  len;
} dash_form_out_t;

/* One "key=value" pair delimited inside an urlencoded body: [key_start,
 * key_start + key_len) is the raw key, [val_start, val_end) the raw value. */
typedef struct {
    size_t  key_start;
    size_t  key_len;
    size_t  val_start;
    size_t  val_end;
} dash_form_pair_t;

/*
 * WHAT: Scan the next complete "key=value" pair from an urlencoded body,
 *       advancing *pos past it (and past any valueless tokens before it).
 * WHY:  dashboard_form_value() only cares about pairs that HAVE a value;
 *       centralizing the '&'-walk keeps the caller a flat match loop.
 * HOW:  Scan the key up to its '=' (skipping whole tokens with no '='), then
 *       delimit the value from just after '=' to the next '&' or body end.
 *       Returns NGX_OK with *pair filled, or NGX_DECLINED at body end.
 */
static ngx_int_t
dash_form_next_pair(const u_char *body, size_t body_len, size_t *pos,
    dash_form_pair_t *pair)
{
    size_t i = *pos;

    while (i < body_len) {
        pair->key_start = i;

        /* Scan the key up to its '=' (or '&'/end if the pair has no value). */
        while (i < body_len && body[i] != '=' && body[i] != '&') {
            i++;
        }
        pair->key_len = i - pair->key_start;

        /* No '=' for this token: skip the whole valueless pair and continue. */
        if (i >= body_len || body[i] != '=') {
            while (i < body_len && body[i] != '&') {
                i++;
            }
            if (i < body_len) {
                i++;
            }
            continue;
        }

        /* Delimit the value: from just after '=' to the next '&' or body end. */
        i++;
        pair->val_start = i;
        while (i < body_len && body[i] != '&') {
            i++;
        }
        pair->val_end = i;

        if (i < body_len) {
            i++;    /* skip '&' */
        }
        *pos = i;
        return NGX_OK;
    }

    *pos = i;
    return NGX_DECLINED;
}

/*
 * WHAT: URL-decode one raw form value [val_start, val_end) into out->buf,
 *       NUL-terminated and truncated to out->size; decoded length -> out->len.
 * WHY:  Application/x-www-form-urlencoded values escape spaces as '+' and
 *       arbitrary bytes as "%HH"; the login fields must be decoded before any
 *       credential comparison.
 * HOW:  '+' -> space, "%HH" -> the byte, anything else verbatim; k+1 < size
 *       reserves space for the trailing NUL.
 */
static void
dash_form_decode_value(const u_char *body, size_t val_start, size_t val_end,
    dash_form_out_t *out)
{
    size_t j, k;

    for (j = val_start, k = 0; j < val_end && k + 1 < out->size; j++) {
        if (body[j] == '+') {
            out->buf[k++] = ' ';
        } else if (body[j] == '%' && j + 2 < val_end
                   && isxdigit(body[j + 1])
                   && isxdigit(body[j + 2]))
        {
            /* "%HH" escape: fold each hex nibble (case-insensitive via
             * |0x20) into the decoded byte (hi<<4 | lo); skip the 2 hex
             * chars consumed. */
            unsigned int hi, lo;
            hi = body[j + 1] <= '9' ? body[j + 1] - '0'
                 : (body[j + 1] | 0x20) - 'a' + 10;
            lo = body[j + 2] <= '9' ? body[j + 2] - '0'
                 : (body[j + 2] | 0x20) - 'a' + 10;
            out->buf[k++] = (char) ((hi << 4) | lo);
            j += 2;
        } else {
            out->buf[k++] = (char) body[j];
        }
    }
    out->buf[k] = '\0';
    out->len = k;
}

/*
 * WHAT: Extract and URL-decode one field from an application/x-www-form-urlencoded
 *       request body, writing the decoded value (NUL-terminated, truncated to
 *       out->size) to out->buf and its length to out->len.
 * HOW:  Iterate "key=value" pairs separated by '&' (dash_form_next_pair); on a
 *       name match, decode the value applying form rules (dash_form_decode_value).
 *       Returns NGX_OK on the first match, NGX_DECLINED if the field is absent.
 */
static ngx_int_t
dashboard_form_value(const u_char *body, size_t body_len,
    const char *name, dash_form_out_t *out)
{
    size_t            name_len = strlen(name);
    size_t            i = 0;
    dash_form_pair_t  pair;

    if (out == NULL || out->buf == NULL || out->size == 0) {
        return NGX_DECLINED;
    }

    out->len = 0;
    out->buf[0] = '\0';

    while (dash_form_next_pair(body, body_len, &i, &pair) == NGX_OK) {
        if (pair.key_len == name_len
            && ngx_memcmp(body + pair.key_start, name, name_len) == 0)
        {
            dash_form_decode_value(body, pair.val_start, pair.val_end, out);
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

/*
 * WHAT: Derive the cookie signature for a session.
 * WHY:  The signed message MUST be identical at issue (login) and verify time or
 *       the constant-time compare fails. The two auth modes sign different msgs:
 *         single-user  -> HMAC(password,        "<ts>")
 *         multi-user    -> HMAC(user_pw_hash,    "<ts>.<username>")
 *       Binding the username into the multi-user message prevents a cookie issued
 *       for one user being replayed as another. `out_hex` must hold
 *       HMAC_HEX_LEN + 1 bytes.
 * HOW:  msg[] is sized for "<ts>.<username>" (TIMESTAMP_MAX + '.' + 256 + NUL);
 *       inputs longer than those caps are rejected to avoid overflow.
 */
static ngx_int_t
dashboard_cookie_hmac(const ngx_str_t *key, const char *ts, size_t ts_len,
    const char *username, size_t username_len,
    char out_hex[HMAC_HEX_LEN + 1])
{
    char   msg[TIMESTAMP_MAX + 1 + 256 + 1];
    size_t msg_len;

    /* Single-user mode: sign the bare timestamp only. */
    if (username == NULL) {
        hmac_sha256_hex(key->data, key->len, ts, ts_len, out_hex);
        return NGX_OK;
    }

    if (username_len > 256 || ts_len > TIMESTAMP_MAX) {
        return NGX_DECLINED;
    }

    /* Multi-user mode: sign "<ts>.<username>". */
    ngx_memcpy(msg, ts, ts_len);
    msg[ts_len] = '.';
    ngx_memcpy(msg + ts_len + 1, username, username_len);
    msg_len = ts_len + 1 + username_len;
    hmac_sha256_hex(key->data, key->len, msg, msg_len, out_hex);
    return NGX_OK;
}

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

    if (find_cookie(r, "xrd_dashboard", 13, &cookie_val, &cookie_val_len)
        != NGX_OK)
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

/* Inline HTML strings */
static const char login_form_html[] =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head><meta charset=\"utf-8\">"
    "<title>" BRIX_SERVER_NAME " Monitor — Login</title>\n"
    "<style>\n"
    "body{background:#1a1a2e;color:#e0e0e0;font-family:monospace;"
    "display:flex;justify-content:center;align-items:center;height:100vh;margin:0}\n"
    ".box{background:#16213e;padding:2em 3em;border-radius:8px;"
    "border:1px solid #0f3460;min-width:320px}\n"
    "h2{color:#e94560;margin-bottom:1.5em;text-align:center}\n"
    "input[type=text],input[type=password]{width:100%;padding:.5em;background:#0f3460;"
    "border:1px solid #e94560;color:#e0e0e0;border-radius:4px;font-size:1em;box-sizing:border-box}\n"
    "input+input{margin-top:.75em}\n"
    "button{width:100%;padding:.6em;margin-top:1em;background:#e94560;"
    "border:none;color:#fff;font-size:1em;border-radius:4px;cursor:pointer}\n"
    "button:hover{background:#c73652}\n"
    ".err{color:#e94560;font-size:.85em;margin-top:.5em}\n"
    "</style></head>\n"
    "<body><div class=\"box\">\n"
    "<h2>Transfer Monitor</h2>\n"
    "<form method=\"post\">\n"
    "<input type=\"text\" name=\"username\" placeholder=\"Username\">\n"
    "<input type=\"password\" name=\"password\" placeholder=\"Admin password\" autofocus>\n"
    "<button type=\"submit\">Sign in</button>\n"
    "</form>\n"
    "</div></body></html>\n";

static const char login_form_html_error[] =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head><meta charset=\"utf-8\">"
    "<title>" BRIX_SERVER_NAME " Monitor — Login</title>\n"
    "<style>\n"
    "body{background:#1a1a2e;color:#e0e0e0;font-family:monospace;"
    "display:flex;justify-content:center;align-items:center;height:100vh;margin:0}\n"
    ".box{background:#16213e;padding:2em 3em;border-radius:8px;"
    "border:1px solid #0f3460;min-width:320px}\n"
    "h2{color:#e94560;margin-bottom:1.5em;text-align:center}\n"
    "input[type=text],input[type=password]{width:100%;padding:.5em;background:#0f3460;"
    "border:1px solid #e94560;color:#e0e0e0;border-radius:4px;font-size:1em;box-sizing:border-box}\n"
    "input+input{margin-top:.75em}\n"
    "button{width:100%;padding:.6em;margin-top:1em;background:#e94560;"
    "border:none;color:#fff;font-size:1em;border-radius:4px;cursor:pointer}\n"
    "button:hover{background:#c73652}\n"
    ".err{color:#e94560;font-size:.85em;margin-top:.5em}\n"
    "</style></head>\n"
    "<body><div class=\"box\">\n"
    "<h2>Transfer Monitor</h2>\n"
    "<form method=\"post\">\n"
    "<input type=\"text\" name=\"username\" placeholder=\"Username\">\n"
    "<input type=\"password\" name=\"password\" placeholder=\"Admin password\" autofocus>\n"
    "<button type=\"submit\">Sign in</button>\n"
    "</form>\n"
    "<p class=\"err\">Incorrect password.</p>\n"
    "</div></body></html>\n";

/* Helpers for sending HTML responses */
/* Emit a complete text/html response from a static string. The buffer is
 * memory-backed (b->memory) pointing directly at the const literal — safe
 * because the data outlives the request and is never mutated. */
static ngx_int_t
send_html(ngx_http_request_t *r, ngx_int_t status,
    const char *html, size_t html_len)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }

    b->pos = b->last = (u_char *) html;
    b->last  += html_len;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status            = status;
    r->headers_out.content_length_n  = (off_t) html_len;
    r->headers_out.content_type      = (ngx_str_t) ngx_string("text/html; charset=utf-8");
    r->headers_out.content_type_len  = r->headers_out.content_type.len;

    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) { return rc; }

    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

/* Context for async POST body reading */
typedef struct {
    ngx_http_request_t                        *r;
    const ngx_http_brix_dashboard_loc_conf_t *conf;
} ngx_http_dashboard_login_ctx_t;

/* Credentials extracted from a login POST body plus the HMAC key selected for
 * the session cookie (per-user hash in multi-user mode, else the configured
 * password). Filled by login_verify_credentials(). */
typedef struct {
    char       username[257];
    char       password[1025];
    size_t     username_len;
    size_t     pw_len;
    ngx_str_t  hmac_key;
} login_creds_t;

/*
 * WHAT: Finalize a failed login by re-rendering the login form with the error
 *       banner (HTTP 200).
 * WHY:  Every credential-failure path responds identically so as not to reveal
 *       whether the username or password was wrong.
 * HOW:  send_html() with the static error form; its return code feeds
 *       ngx_http_finalize_request().
 */
static void
login_fail_form(ngx_http_request_t *r)
{
    ngx_http_finalize_request(r,
        send_html(r, NGX_HTTP_OK,
            login_form_html_error, sizeof(login_form_html_error) - 1));
}

/*
 * WHAT: Reassemble the (possibly multi-buffer) buffered request body into one
 *       NUL-terminated allocation.
 * WHY:  dashboard_form_value() scans a contiguous byte range; nginx delivers
 *       the body as a buffer chain.
 * HOW:  Sum the chain, enforce the 1..4096-byte bound (NGX_DECLINED -> caller
 *       re-renders the form), allocate len+1 from r->pool, copy each buffer,
 *       NUL-terminate. NGX_ERROR on alloc failure.
 */
static ngx_int_t
login_collect_body(ngx_http_request_t *r, u_char **body_out, size_t *total_out)
{
    ngx_chain_t  *cl;
    u_char       *body_buf;
    size_t        body_len = 0;
    size_t        total    = 0;
    u_char       *p;

    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        body_len += ngx_buf_size(cl->buf);
    }

    if (body_len == 0 || body_len > 4096) {
        return NGX_DECLINED;
    }

    body_buf = ngx_palloc(r->pool, body_len + 1);
    if (body_buf == NULL) {
        return NGX_ERROR;
    }

    p = body_buf;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        size_t n = ngx_buf_size(cl->buf);
        ngx_memcpy(p, cl->buf->pos, n);
        p     += n;
        total += n;
    }
    body_buf[total] = '\0';

    *body_out  = body_buf;
    *total_out = total;
    return NGX_OK;
}

/*
 * WHAT: Extract username/password from the form body and verify them per the
 *       active auth mode, selecting the session-cookie HMAC key on success.
 * WHY:  Two auth modes, mutually exclusive by config (see module.c setters):
 *         multi-user  -> look up the user, verify against their crypt/plaintext
 *                        hash; the per-user hash becomes the cookie HMAC key.
 *         single-user -> constant-time compare against the one configured
 *                        password, which is itself the HMAC key.
 * HOW:  Missing password and failed verification each emit their original audit
 *       event and return NGX_DECLINED (caller re-renders the form). NGX_OK
 *       fills creds->hmac_key (plus username/password fields).
 */
static ngx_int_t
login_verify_credentials(ngx_http_request_t *r,
    const ngx_http_brix_dashboard_loc_conf_t *conf,
    const u_char *body_buf, size_t total, login_creds_t *creds)
{
    dash_form_out_t                    pw_out;
    dash_form_out_t                    user_out;
    ngx_http_brix_dashboard_user_t  *user;

    pw_out.buf  = creds->password;
    pw_out.size = sizeof(creds->password);
    pw_out.len  = 0;

    if (dashboard_form_value(body_buf, total, "password", &pw_out) != NGX_OK
        || pw_out.len == 0)
    {
        brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard login missing password", NULL);
        return NGX_DECLINED;
    }
    creds->pw_len = pw_out.len;

    user_out.buf  = creds->username;
    user_out.size = sizeof(creds->username);
    user_out.len  = 0;
    (void) dashboard_form_value(body_buf, total, "username", &user_out);
    creds->username_len = user_out.len;

    if (dashboard_users_enabled(conf)) {
        user = dashboard_find_user(conf, creds->username, creds->username_len);
        if (dashboard_verify_user_password(r->pool, user, creds->password,
                                           creds->pw_len) != NGX_OK)
        {
            brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                       NGX_HTTP_UNAUTHORIZED,
                                       "dashboard login failed", NULL);
            return NGX_DECLINED;
        }
        creds->hmac_key = user->password_hash;
        return NGX_OK;
    }

    if (creds->pw_len != conf->password.len
        || CRYPTO_memcmp(creds->password, conf->password.data,
                         creds->pw_len) != 0)
    {
        brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard login failed", NULL);
        return NGX_DECLINED;
    }
    creds->hmac_key = conf->password;
    return NGX_OK;
}

/*
 * WHAT: Mint the session cookie value "<hmac>.<ts>[.<user>]" for verified
 *       credentials and push the Set-Cookie header.
 * WHY:  The cookie must be signed with exactly the key/message the verifier
 *       (dashboard_cookie_hmac) will recompute, and the success audit event is
 *       emitted here, between minting the value and pushing the header, to
 *       preserve the original event ordering.
 * HOW:  Timestamp = now; HMAC via dashboard_cookie_hmac(); assemble the
 *       Set-Cookie value with Path/HttpOnly/Secure/SameSite=Strict attributes.
 *       Returns NGX_OK or NGX_HTTP_INTERNAL_SERVER_ERROR (caller finalizes).
 */
static ngx_int_t
login_issue_cookie(ngx_http_request_t *r,
    const ngx_http_brix_dashboard_loc_conf_t *conf,
    const login_creds_t *creds)
{
    char              ts_str[TIMESTAMP_MAX + 1];
    char              cookie_hex[HMAC_HEX_LEN + 1];
    char              cookie_val[HMAC_HEX_LEN + TIMESTAMP_MAX + 260];
    ngx_table_elt_t  *set_cookie;
    size_t            cookie_full_len;
    u_char           *cookie_full;
    time_t            now;

    now = time(NULL);
    snprintf(ts_str, sizeof(ts_str), "%ld", (long) now);
    if (dashboard_cookie_hmac(&creds->hmac_key, ts_str, strlen(ts_str),
                              dashboard_users_enabled(conf)
                                  ? creds->username : NULL,
                              creds->username_len, cookie_hex) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (dashboard_users_enabled(conf)) {
        snprintf(cookie_val, sizeof(cookie_val), "%s.%s.%s", cookie_hex,
                 ts_str, creds->username);
    } else {
        snprintf(cookie_val, sizeof(cookie_val), "%s.%s", cookie_hex, ts_str);
    }

    brix_dashboard_event_add(BRIX_DASH_EVENT_AUTH, 0, NGX_HTTP_OK,
                               "dashboard login success",
                               dashboard_users_enabled(conf)
                                   ? creds->username : NULL);

    /* Set-Cookie: xrd_dashboard=<value>; Path=/xrootd; HttpOnly; Secure; SameSite=Strict */
    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cookie_full_len = sizeof("xrd_dashboard=; Path=; HttpOnly; Secure; SameSite=Strict") - 1
                      + strlen(cookie_val) + conf->cookie_path.len;
    cookie_full = ngx_palloc(r->pool, cookie_full_len + 1);
    if (cookie_full == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    snprintf((char *) cookie_full, cookie_full_len + 1,
             "xrd_dashboard=%s; Path=%.*s; HttpOnly; Secure; SameSite=Strict",
             cookie_val, (int) conf->cookie_path.len,
             (char *) conf->cookie_path.data);

    set_cookie->hash        = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.data  = cookie_full;
    set_cookie->value.len   = cookie_full_len;

    return NGX_OK;
}

/*
 * WHAT: Install the post-login "Location: <cookie_path>/" redirect header.
 * WHY:  Use r->headers_out.location (nginx's dedicated field) +
 *       NGX_HTTP_MOVED_TEMPORARILY so that nginx's special-response handler
 *       sends a complete response including the body flush. Calling
 *       ngx_http_send_header() alone inside a body callback leaves headers in
 *       the write buffer unflushed because there is no trailing output chain.
 * HOW:  Push the header, build "<cookie_path>/" (NUL-terminated) in r->pool.
 *       Returns NGX_OK or NGX_HTTP_INTERNAL_SERVER_ERROR (caller finalizes).
 */
static ngx_int_t
login_set_redirect(ngx_http_request_t *r,
    const ngx_http_brix_dashboard_loc_conf_t *conf)
{
    u_char  *loc;

    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.location->hash = 1;
    ngx_str_set(&r->headers_out.location->key, "Location");

    loc = ngx_pnalloc(r->pool, conf->cookie_path.len + 2);
    if (loc == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(loc, conf->cookie_path.data, conf->cookie_path.len);
    loc[conf->cookie_path.len] = '/';
    loc[conf->cookie_path.len + 1] = '\0';
    r->headers_out.location->value.data = loc;
    r->headers_out.location->value.len = conf->cookie_path.len + 1;

    return NGX_OK;
}

/*
 * WHAT: Body callback for a login POST — verifies credentials and, on success,
 *       issues the session cookie and redirects to the dashboard.
 * WHY:  This runs only after nginx has fully buffered the request body (set up
 *       by ngx_http_brix_dashboard_login_handler via
 *       ngx_http_read_client_request_body). It owns finalizing the request:
 *       every exit path calls ngx_http_finalize_request().
 * HOW:  Reassemble the (possibly multi-buffer) body (login_collect_body),
 *       extract + verify username/password (login_verify_credentials), then
 *       mint "<hmac>.<ts>[.<user>]" as Set-Cookie (login_issue_cookie) and
 *       redirect (login_set_redirect). Failures re-render the login form (200)
 *       so as not to reveal whether the username or password was wrong.
 */
static void
login_post_body_handler(ngx_http_request_t *r)
{
    ngx_http_brix_dashboard_loc_conf_t *conf;
    u_char                               *body_buf;
    size_t                                total = 0;
    ngx_int_t                             rc;
    login_creds_t                         creds;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_dashboard_module);

    rc = login_collect_body(r, &body_buf, &total);
    if (rc == NGX_DECLINED) {
        login_fail_form(r);
        return;
    }
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(&creds, sizeof(creds));
    if (login_verify_credentials(r, conf, body_buf, total, &creds) != NGX_OK) {
        login_fail_form(r);
        return;
    }

    rc = login_issue_cookie(r, conf, &creds);
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    rc = login_set_redirect(r, conf);
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    ngx_http_finalize_request(r, NGX_HTTP_MOVED_TEMPORARILY);
}

/* Public: login handler (GET form + POST verify) */
ngx_int_t
ngx_http_brix_dashboard_login_handler(ngx_http_request_t *r)
{
    if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
        return send_html(r, NGX_HTTP_OK,
                         login_form_html, sizeof(login_form_html) - 1);
    }

    if (r->method == NGX_HTTP_POST) {
        ngx_int_t rc = ngx_http_read_client_request_body(r, login_post_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) { return rc; }
        return NGX_DONE;
    }

    return NGX_HTTP_NOT_ALLOWED;
}
