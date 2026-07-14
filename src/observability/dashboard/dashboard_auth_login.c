#include "dashboard_auth_internal.h"
#include "core/ident.h"

#include <openssl/crypto.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

/*
 * dashboard/dashboard_auth_login.c — login GET form + POST verify flow for the
 * dashboard authentication unit (split from auth.c, phase-79).
 *
 * WHAT: The interactive login surface: the static HTML forms, the HTML response
 *       emitter, and the POST pipeline that reassembles the body, verifies the
 *       submitted credentials, mints the signed session cookie, and redirects.
 *
 * WHY: This is the "issue a session" half of dashboard auth; the "verify a
 *       session" half lives in auth.c. Both lean on the shared credential store
 *       and HMAC (dashboard_auth_creds.c) and the form parser
 *       (dashboard_auth_parse.c) so the cookie they mint here is verifiable
 *       there. Behaviour, audit events, and event ordering are unchanged from
 *       the original auth.c.
 */

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
