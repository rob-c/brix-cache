#include "dashboard_http.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <crypt.h>
#include <ctype.h>

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

/* ---- Helpers ---- */

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

    for (i = 0; i < 32; i++) {
        snprintf(out_hex + i * 2, 3, "%02x", (unsigned int) digest[i]);
    }
    out_hex[HMAC_HEX_LEN] = '\0';
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

    cookie_hdr = r->headers_in.cookie;
    if (cookie_hdr == NULL) {
        return NGX_DECLINED;
    }

    p   = cookie_hdr->value.data;
    end = p + cookie_hdr->value.len;

    while (p < end) {
        /* skip whitespace */
        while (p < end && (*p == ' ' || *p == '\t')) { p++; }

        start = p;

        /* find '=' */
        eq = NULL;
        while (p < end && *p != ';') {
            if (*p == '=' && eq == NULL) { eq = p; }
            p++;
        }

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
dashboard_users_enabled(const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    return conf->users != NULL && conf->users->nelts > 0;
}

static ngx_http_xrootd_dashboard_user_t *
dashboard_find_user(const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    const char *username, size_t username_len)
{
    ngx_http_xrootd_dashboard_user_t *users;
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

static ngx_int_t
dashboard_copy_str0(ngx_pool_t *pool, ngx_str_t *src, char **out)
{
    char *dst;

    dst = ngx_pnalloc(pool, src->len + 1);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst, src->data, src->len);
    dst[src->len] = '\0';
    *out = dst;
    return NGX_OK;
}

static ngx_int_t
dashboard_verify_user_password(ngx_pool_t *pool,
    ngx_http_xrootd_dashboard_user_t *user,
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

    plain = ngx_pnalloc(pool, password_len + 1);
    if (plain == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(plain, password, password_len);
    plain[password_len] = '\0';

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

    if (password_len == user->password_hash.len
        && CRYPTO_memcmp(password, user->password_hash.data, password_len) == 0)
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

static ngx_int_t
dashboard_form_value(const u_char *body, size_t body_len,
    const char *name, char *out, size_t outsz, size_t *out_len)
{
    size_t name_len = strlen(name);
    size_t i;

    if (out == NULL || outsz == 0 || out_len == NULL) {
        return NGX_DECLINED;
    }

    *out_len = 0;
    out[0] = '\0';

    for (i = 0; i < body_len; ) {
        size_t key_start = i;
        size_t key_len;
        size_t val_start;
        size_t val_end;
        size_t j, k;

        while (i < body_len && body[i] != '=' && body[i] != '&') {
            i++;
        }
        key_len = i - key_start;
        if (i >= body_len || body[i] != '=') {
            while (i < body_len && body[i] != '&') {
                i++;
            }
            if (i < body_len) {
                i++;
            }
            continue;
        }

        i++;
        val_start = i;
        while (i < body_len && body[i] != '&') {
            i++;
        }
        val_end = i;

        if (key_len == name_len
            && ngx_memcmp(body + key_start, name, name_len) == 0)
        {
            for (j = val_start, k = 0; j < val_end && k + 1 < outsz; j++) {
                if (body[j] == '+') {
                    out[k++] = ' ';
                } else if (body[j] == '%' && j + 2 < val_end
                           && isxdigit(body[j + 1])
                           && isxdigit(body[j + 2]))
                {
                    unsigned int hi, lo;
                    hi = body[j + 1] <= '9' ? body[j + 1] - '0'
                         : (body[j + 1] | 0x20) - 'a' + 10;
                    lo = body[j + 2] <= '9' ? body[j + 2] - '0'
                         : (body[j + 2] | 0x20) - 'a' + 10;
                    out[k++] = (char) ((hi << 4) | lo);
                    j += 2;
                } else {
                    out[k++] = (char) body[j];
                }
            }
            out[k] = '\0';
            *out_len = k;
            return NGX_OK;
        }

        if (i < body_len) {
            i++;
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
dashboard_cookie_hmac(const ngx_str_t *key, const char *ts, size_t ts_len,
    const char *username, size_t username_len,
    char out_hex[HMAC_HEX_LEN + 1])
{
    char   msg[TIMESTAMP_MAX + 1 + 256 + 1];
    size_t msg_len;

    if (username == NULL) {
        hmac_sha256_hex(key->data, key->len, ts, ts_len, out_hex);
        return NGX_OK;
    }

    if (username_len > 256 || ts_len > TIMESTAMP_MAX) {
        return NGX_DECLINED;
    }

    ngx_memcpy(msg, ts, ts_len);
    msg[ts_len] = '.';
    ngx_memcpy(msg + ts_len + 1, username, username_len);
    msg_len = ts_len + 1 + username_len;
    hmac_sha256_hex(key->data, key->len, msg, msg_len, out_hex);
    return NGX_OK;
}

/* ---- Public: check auth cookie ---- */

ngx_int_t
ngx_http_xrootd_dashboard_check_auth(ngx_http_request_t *r,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    u_char                             *cookie_val;
    size_t                              cookie_val_len;
    u_char                             *dot;
    u_char                             *dot2;
    char                                ts_str[TIMESTAMP_MAX + 1];
    char                                username[257];
    size_t                              ts_len;
    size_t                              username_len = 0;
    char                               *endptr;
    long                                ts;
    time_t                              now;
    char                                expected_hex[HMAC_HEX_LEN + 1];
    char                                given_hex[HMAC_HEX_LEN + 1];
    ngx_str_t                           key;
    ngx_http_xrootd_dashboard_user_t   *user;

    if (conf->password.len == 0 && !dashboard_users_enabled(conf)) {
        /* No password configured — dashboard accessible without auth. */
        return NGX_OK;
    }

    if (find_cookie(r, "xrd_dashboard", 13, &cookie_val, &cookie_val_len)
        != NGX_OK)
    {
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth missing cookie", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Find the '.' separator between hex and timestamp. */
    dot = NULL;
    {
        size_t i;
        for (i = 0; i < cookie_val_len; i++) {
            if (cookie_val[i] == '.') { dot = cookie_val + i; break; }
        }
    }

    if (dot == NULL || dot == cookie_val ||
        (size_t)(dot - cookie_val) != HMAC_HEX_LEN)
    {
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth malformed cookie", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Extract and null-terminate the HMAC hex. */
    if (HMAC_HEX_LEN >= sizeof(given_hex)) {
        return NGX_HTTP_UNAUTHORIZED;
    }
    ngx_memcpy(given_hex, cookie_val, HMAC_HEX_LEN);
    given_hex[HMAC_HEX_LEN] = '\0';

    dot2 = NULL;
    if (dashboard_users_enabled(conf)) {
        size_t i;

        for (i = (size_t) (dot - cookie_val) + 1; i < cookie_val_len; i++) {
            if (cookie_val[i] == '.') {
                dot2 = cookie_val + i;
                break;
            }
        }

        if (dot2 == NULL) {
            xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                       NGX_HTTP_UNAUTHORIZED,
                                       "dashboard auth missing username", NULL);
            return NGX_HTTP_UNAUTHORIZED;
        }

        ts_len = (size_t) (dot2 - dot - 1);
        username_len = cookie_val_len - (size_t) (dot2 - cookie_val) - 1;
        if (username_len == 0 || username_len >= sizeof(username)) {
            return NGX_HTTP_UNAUTHORIZED;
        }
        ngx_memcpy(username, dot2 + 1, username_len);
        username[username_len] = '\0';

        user = dashboard_find_user(conf, username, username_len);
        if (user == NULL) {
            xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                       NGX_HTTP_UNAUTHORIZED,
                                       "dashboard auth unknown user", NULL);
            return NGX_HTTP_UNAUTHORIZED;
        }
        key = user->password_hash;
    } else {
        ts_len = cookie_val_len - HMAC_HEX_LEN - 1;
        key = conf->password;
    }

    /* Extract and null-terminate the timestamp. */
    if (ts_len == 0 || ts_len >= sizeof(ts_str)) {
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth bad timestamp", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }
    ngx_memcpy(ts_str, dot + 1, ts_len);
    ts_str[ts_len] = '\0';

    endptr = NULL;
    ts = strtol(ts_str, &endptr, 10);
    if (ts <= 0 || endptr == NULL || *endptr != '\0') {
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth bad timestamp", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Check TTL. */
    now = time(NULL);
    if ((long) now - ts > (long) conf->session_ttl || ts > (long) now + 60) {
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth expired cookie", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Recompute HMAC and constant-time compare. */
    if (dashboard_cookie_hmac(&key, ts_str, ts_len,
                              dashboard_users_enabled(conf)
                                  ? username : NULL,
                              username_len, expected_hex) != NGX_OK)
    {
        return NGX_HTTP_UNAUTHORIZED;
    }

    if (CRYPTO_memcmp(expected_hex, given_hex, HMAC_HEX_LEN) != 0) {
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard auth bad signature", NULL);
        return NGX_HTTP_UNAUTHORIZED;
    }

    return NGX_OK;
}

/* ---- Inline HTML strings ---- */

static const char login_form_html[] =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head><meta charset=\"utf-8\">"
    "<title>nginx-xrootd Monitor — Login</title>\n"
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
    "<title>nginx-xrootd Monitor — Login</title>\n"
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

/* ---- Helpers for sending HTML responses ---- */

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

/* ---- Context for async POST body reading ---- */

typedef struct {
    ngx_http_request_t                        *r;
    const ngx_http_xrootd_dashboard_loc_conf_t *conf;
} ngx_http_dashboard_login_ctx_t;

static void
login_post_body_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    ngx_chain_t                          *cl;
    u_char                               *body_buf;
    size_t                                body_len = 0;
    size_t                                total    = 0;
    u_char                               *p;
    char                                  ts_str[TIMESTAMP_MAX + 1];
    char                                  cookie_hex[HMAC_HEX_LEN + 1];
    char                                  cookie_val[HMAC_HEX_LEN + TIMESTAMP_MAX + 260];
    ngx_table_elt_t                      *set_cookie;
    char                                  username[257];
    char                                  password[1025];
    size_t                                username_len = 0;
    size_t                                pw_len = 0;
    ngx_str_t                             hmac_key;
    ngx_http_xrootd_dashboard_user_t     *user = NULL;
    time_t                                now;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);

    /* Collect body length */
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        body_len += ngx_buf_size(cl->buf);
    }

    if (body_len == 0 || body_len > 4096) {
        ngx_http_finalize_request(r,
            send_html(r, NGX_HTTP_OK,
                login_form_html_error, sizeof(login_form_html_error) - 1));
        return;
    }

    body_buf = ngx_palloc(r->pool, body_len + 1);
    if (body_buf == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    p = body_buf;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        size_t n = ngx_buf_size(cl->buf);
        ngx_memcpy(p, cl->buf->pos, n);
        p     += n;
        total += n;
    }
    body_buf[total] = '\0';

    if (dashboard_form_value(body_buf, total, "password", password,
                             sizeof(password), &pw_len) != NGX_OK
        || pw_len == 0)
    {
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                   NGX_HTTP_UNAUTHORIZED,
                                   "dashboard login missing password", NULL);
        ngx_http_finalize_request(r,
            send_html(r, NGX_HTTP_OK,
                login_form_html_error, sizeof(login_form_html_error) - 1));
        return;
    }

    (void) dashboard_form_value(body_buf, total, "username", username,
                                sizeof(username), &username_len);

    if (dashboard_users_enabled(conf)) {
        user = dashboard_find_user(conf, username, username_len);
        if (dashboard_verify_user_password(r->pool, user, password, pw_len)
            != NGX_OK)
        {
            xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                       NGX_HTTP_UNAUTHORIZED,
                                       "dashboard login failed", NULL);
            ngx_http_finalize_request(r,
                send_html(r, NGX_HTTP_OK,
                    login_form_html_error, sizeof(login_form_html_error) - 1));
            return;
        }
        hmac_key = user->password_hash;
    } else {
        if (pw_len != conf->password.len
            || CRYPTO_memcmp(password, conf->password.data, pw_len) != 0)
        {
            xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0,
                                       NGX_HTTP_UNAUTHORIZED,
                                       "dashboard login failed", NULL);
            ngx_http_finalize_request(r,
                send_html(r, NGX_HTTP_OK,
                    login_form_html_error, sizeof(login_form_html_error) - 1));
            return;
        }
        hmac_key = conf->password;
    }

    /* Issue cookie */
    now = time(NULL);
    snprintf(ts_str, sizeof(ts_str), "%ld", (long) now);
    if (dashboard_cookie_hmac(&hmac_key, ts_str, strlen(ts_str),
                              dashboard_users_enabled(conf) ? username : NULL,
                              username_len, cookie_hex) != NGX_OK)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (dashboard_users_enabled(conf)) {
        snprintf(cookie_val, sizeof(cookie_val), "%s.%s.%s", cookie_hex,
                 ts_str, username);
    } else {
        snprintf(cookie_val, sizeof(cookie_val), "%s.%s", cookie_hex, ts_str);
    }

    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_AUTH, 0, NGX_HTTP_OK,
                               "dashboard login success",
                               dashboard_users_enabled(conf) ? username : NULL);


    /* Set-Cookie: xrd_dashboard=<value>; Path=/xrootd; HttpOnly; Secure; SameSite=Strict */
    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    {
        size_t  cookie_full_len;
        u_char *cookie_full;

        cookie_full_len = sizeof("xrd_dashboard=; Path=; HttpOnly; Secure; SameSite=Strict") - 1
                          + strlen(cookie_val) + conf->cookie_path.len;
        cookie_full = ngx_palloc(r->pool, cookie_full_len + 1);
        if (cookie_full == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        snprintf((char *) cookie_full, cookie_full_len + 1,
                 "xrd_dashboard=%s; Path=%.*s; HttpOnly; Secure; SameSite=Strict",
                 cookie_val, (int) conf->cookie_path.len,
                 (char *) conf->cookie_path.data);

        set_cookie->hash        = 1;
        ngx_str_set(&set_cookie->key, "Set-Cookie");
        set_cookie->value.data  = cookie_full;
        set_cookie->value.len   = cookie_full_len;
    }

    /*
     * Redirect to dashboard.  Use r->headers_out.location (nginx's dedicated
     * field) + NGX_HTTP_MOVED_TEMPORARILY so that nginx's special-response
     * handler sends a complete response including the body flush.  Calling
     * ngx_http_send_header() alone inside a body callback leaves headers in
     * the write buffer unflushed because there is no trailing output chain.
     */
    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    r->headers_out.location->hash = 1;
    ngx_str_set(&r->headers_out.location->key, "Location");
    {
        u_char *loc;
        loc = ngx_pnalloc(r->pool, conf->cookie_path.len + 2);
        if (loc == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        ngx_memcpy(loc, conf->cookie_path.data, conf->cookie_path.len);
        loc[conf->cookie_path.len] = '/';
        loc[conf->cookie_path.len + 1] = '\0';
        r->headers_out.location->value.data = loc;
        r->headers_out.location->value.len = conf->cookie_path.len + 1;
    }

    ngx_http_finalize_request(r, NGX_HTTP_MOVED_TEMPORARILY);
}

/* ---- Public: login handler (GET form + POST verify) ---- */

ngx_int_t
ngx_http_xrootd_dashboard_login_handler(ngx_http_request_t *r)
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
