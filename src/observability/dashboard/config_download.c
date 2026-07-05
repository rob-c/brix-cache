/*
 * dashboard/config_download.c - authenticated, secret-safe config export.
 *
 * Serves GET /xrootd/api/v1/config: the running nginx configuration
 * (ngx_cycle->conf_file) as a text/plain attachment, with EVERY secret removed.
 *
 * SECURITY MODEL (fail-closed — the whole point of this feature):
 *   The on-disk config is read verbatim, then passed through a line redactor
 *   that masks the VALUE of every directive UNLESS the directive name is
 *   recognised as safe. "Recognised safe" = a project brix_* directive that is
 *   not itself a secret, OR a name on a curated stock-nginx allowlist. Anything
 *   else - unknown directives, stock directives that may carry credentials
 *   (proxy_set_header, set, auth_basic_user_file, ...), `include`, secret
 *   directives - has its value replaced with "[redacted]". Because the default
 *   is to redact, a directive we have never heard of CANNOT leak its value: the
 *   only way a value survives is if we explicitly classified its name as safe.
 *
 *   On top of that fail-closed core:
 *     - an explicit secret denylist + a secret-name substring net always win
 *       (so even a future brix_*_secret is masked before the brix_* "safe"
 *       rule can pass it through);
 *     - `include` targets are never inlined (separate files are not read), so a
 *       secret living in an included file is never reachable here;
 *     - surviving values are additionally scrubbed of embedded URL credentials
 *       (scheme://user:pass@host and ?token=/secret=/sig= query params), the one
 *       place a secret can hide inside an otherwise-safe URL directive.
 *
 *   The whole file is read into memory and redacted BEFORE any byte is sent; a
 *   read/stat error or an oversize file yields a 5xx with NO body, never a
 *   partial or unredacted dump.
 *
 * AUTH: always required. This handler is never reached anonymously - it is a
 *   separate route from the api_handler and does not consult conf->anonymous.
 */

#include "dashboard_http.h"
#include "core/http/http_headers.h"   /* brix_http_source_offer (AGPL sec.13) */
#include "core/compat/cstr.h"         /* brix_str_cbuf */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define DASHBOARD_CONFIG_MAX_BYTES   (1 << 20)   /* 1 MiB cap (fail-safe) */
#define DASHBOARD_REDACTED           "[redacted]"

/*
 * Secret directives whose value MUST always be masked, even though some begin
 * with "brix_" (which the fail-closed core would otherwise pass through). This
 * is belt-and-suspenders: the secret-name net below also catches all of these
 * except brix_webdav_proxy_auth (whose name carries no secret keyword), so
 * that one in particular relies on this list.
 */
static const char *const dashboard_secret_directives[] = {
    "brix_dashboard_password",
    "brix_dashboard_users",
    "brix_admin_secret",
    "brix_macaroon_secret",
    "brix_macaroon_secret_old",
    "brix_webdav_macaroon_secret",
    "brix_webdav_macaroon_secret_old",
    "brix_s3_access_key",
    "brix_s3_secret_key",
    "brix_tpc_outbound_client_secret",
    "brix_tpc_outbound_bearer_file",
    "brix_webdav_tpc_token_client_secret",
    "brix_webdav_proxy_auth",
    /* brix_mirror_token is an inline bearer credential whose name carries no
     * secret keyword the substring net catches ("token" is excluded there so
     * the non-secret token_issuer/audience/endpoint stay visible) — list it
     * explicitly, like brix_webdav_proxy_auth above. */
    "brix_mirror_token",
    "brix_upstream_token_file",
    "brix_certificate_key",
    "brix_webdav_tpc_key",
    "brix_webdav_tpc_cert",
    "brix_sss_keytab",
    "brix_cms_server_sss_keytab",
    "brix_krb5_keytab",
    "brix_token_jwks",
    "brix_webdav_token_jwks",
    /* stock nginx secret-bearing directives that may share the same file */
    "ssl_certificate_key",
    "ssl_password_file",
    "ssl_session_ticket_key",
    "proxy_ssl_password_file",
    "proxy_ssl_certificate_key",
    NULL
};

/*
 * Substrings that, if present in a (lowercased) directive name, mark it secret.
 * This is the forward-looking net: a NEW secret directive added later whose name
 * follows the project convention is masked automatically, with no code change.
 */
static const char *const dashboard_secret_name_substrings[] = {
    "secret", "passwd", "password", "passphrase", "keytab", "privatekey",
    "private_key", "accesskey", "access_key", "secretkey", "secret_key",
    "apikey", "api_key", "client_secret", "credential", "bearer", "macaroon",
    "hmac", "jwks",
    NULL
};

/*
 * Names that MATCH the secret net by substring but are demonstrably NOT secret
 * (public identifiers / numbers / booleans). Listed so the export stays useful;
 * the explicit denylist always overrides this, so nothing secret can be
 * un-masked here.
 */
static const char *const dashboard_secret_exceptions[] = {
    "brix_token_issuer",
    "brix_token_audience",
    "brix_token_jwks_refresh_interval",
    "brix_token_cache",
    "brix_webdav_token_issuer",
    "brix_webdav_token_audience",
    "brix_webdav_token_introspect_ttl",
    "brix_webdav_token_introspect_loc",
    "brix_webdav_token_introspect_fail_open",
    NULL
};

/*
 * Stock (non-xrootd) nginx directives whose values are safe to show. Structural
 * keywords and common operational settings only - deliberately conservative.
 * Anything not here (and not an brix_* non-secret directive) is redacted.
 */
static const char *const dashboard_safe_stock_directives[] = {
    "user", "worker_processes", "worker_connections", "worker_rlimit_nofile",
    "pid", "daemon", "master_process", "events", "use", "multi_accept",
    "http", "stream", "server", "location", "upstream", "types", "include_off",
    "default_type", "server_name", "listen", "root", "alias", "index",
    "sendfile", "tcp_nopush", "tcp_nodelay", "keepalive_timeout",
    "keepalive_requests", "client_max_body_size", "client_body_buffer_size",
    "client_body_temp_path", "proxy_temp_path", "fastcgi_temp_path",
    "uwsgi_temp_path", "scgi_temp_path", "output_buffers", "thread_pool",
    "access_log", "error_log", "log_format", "log_not_found", "autoindex",
    "gzip", "gzip_types", "gzip_min_length", "dav_methods", "dav_ext_methods",
    "ssl_certificate", "ssl_protocols", "ssl_ciphers",
    "ssl_prefer_server_ciphers", "ssl_verify_client", "ssl_verify_depth",
    "ssl_buffer_size", "ssl_session_cache", "ssl_session_timeout",
    "ssl_conf_command", "ssl_ecdh_curve", "ssl_dhparam", "ssl_trusted_certificate",
    "ssl_client_certificate", "ssl_crl", "resolver", "resolver_timeout",
    "limit_rate", "limit_conn", "limit_req", "expires", "etag", "charset",
    "merge_slashes", "server_tokens", "reset_timedout_connection",
    "send_timeout", "proxy_connect_timeout", "proxy_read_timeout",
    "proxy_send_timeout", "proxy_buffering", "proxy_request_buffering",
    "underscores_in_headers", "large_client_header_buffers",
    NULL
};

/* lowercase one ASCII byte. */
static u_char dashboard_lc(u_char c)
{
    return (c >= 'A' && c <= 'Z') ? (u_char) (c - 'A' + 'a') : c;
}

/* Case-insensitive compare of [name,len) against a NUL-terminated literal. */
static ngx_uint_t
dashboard_name_eq(const u_char *name, size_t len, const char *lit)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (lit[i] == '\0' || dashboard_lc(name[i]) != (u_char) lit[i]) {
            return 0;
        }
    }
    return lit[len] == '\0';
}

/* Is [name,len) one of the NULL-terminated literals in `set`? */
static ngx_uint_t
dashboard_name_in(const u_char *name, size_t len, const char *const *set)
{
    size_t i;

    for (i = 0; set[i] != NULL; i++) {
        if (dashboard_name_eq(name, len, set[i])) {
            return 1;
        }
    }
    return 0;
}

/* Does the lowercased [name,len) contain `sub` (NUL-terminated, lowercase)? */
static ngx_uint_t
dashboard_name_contains(const u_char *name, size_t len, const char *sub)
{
    size_t sublen = ngx_strlen(sub);
    size_t i, j;

    if (sublen == 0 || sublen > len) {
        return 0;
    }
    for (i = 0; i + sublen <= len; i++) {
        for (j = 0; j < sublen; j++) {
            if (dashboard_lc(name[i + j]) != (u_char) sub[j]) {
                break;
            }
        }
        if (j == sublen) {
            return 1;
        }
    }
    return 0;
}

/* True when the directive name marks a secret (denylist OR name net), after
 * subtracting the explicit non-secret exceptions. */
static ngx_uint_t
dashboard_name_is_secret(const u_char *name, size_t len)
{
    size_t i;

    if (dashboard_name_in(name, len, dashboard_secret_directives)) {
        return 1;
    }
    if (dashboard_name_in(name, len, dashboard_secret_exceptions)) {
        return 0;
    }
    for (i = 0; dashboard_secret_name_substrings[i] != NULL; i++) {
        if (dashboard_name_contains(name, len, dashboard_secret_name_substrings[i])) {
            return 1;
        }
    }
    /* trailing "_key" or a bare "key" directive (e.g. ...tpc_key) */
    if (len == 3 && dashboard_name_eq(name, len, "key")) {
        return 1;
    }
    if (len >= 4 && dashboard_name_eq(name + (len - 4), 4, "_key")) {
        return 1;
    }
    return 0;
}

/*
 * Fail-closed value-keep decision for a directive name.
 * Keep (show value) ONLY when: not secret AND (a project brix_* directive OR a
 * safe stock directive). Everything else -> redact the value.
 */
static ngx_uint_t
dashboard_keep_value(const u_char *name, size_t len)
{
    if (dashboard_name_is_secret(name, len)) {
        return 0;
    }
    if (len >= 5 && dashboard_name_eq(name, 5, "brix_")) {
        return 1;
    }
    if (dashboard_name_in(name, len, dashboard_safe_stock_directives)) {
        return 1;
    }
    return 0;
}

/*
 * In-place scrub of embedded credentials in a surviving value region [p,end):
 *   scheme://user:pass@host          -> scheme://[redacted]@host
 *   ...?token=v / &secret=v / &sig=v -> ...?token=[redacted]&...
 * Returns the new end pointer (the region may shrink). Defence-in-depth for the
 * brix_*_url / upstream / origin directives that pass the keep test.
 */
static u_char *
dashboard_scrub_value_creds(u_char *p, u_char *end)
{
    static const char *const qkeys[] = {
        "token=", "access_token=", "secret=", "client_secret=", "password=",
        "passwd=", "apikey=", "api_key=", "key=", "sig=", "signature=",
        "x-amz-credential=", "x-amz-signature=", "x-amz-security-token=", NULL
    };
    u_char *s = p;

    while (s < end) {
        /* userinfo: "://" ... ':' ... '@' before the authority ends */        if (s + 3 <= end && s[0] == ':' && s[1] == '/' && s[2] == '/') {
            u_char *auth = s + 3;
            u_char *q = auth;
            u_char *at = NULL;
            u_char *colon = NULL;
            while (q < end && *q != '/' && *q != '?' && *q != '#'
                   && *q != ' ' && *q != '\t' && *q != '"' && *q != '\''
                   && *q != ';')
            {
                if (*q == ':' && colon == NULL) { colon = q; }
                if (*q == '@') { at = q; break; }
                q++;
            }
            if (at != NULL && colon != NULL && colon < at) {
                /* Fully overwrite the userinfo [auth,at). NEVER grow the buffer:
                 * write min(marker,old) bytes (a sub-marker-length secret is
                 * fully covered by a marker prefix), and only shrink (memmove the
                 * tail left) when the secret is longer than the marker. */
                size_t rep = ngx_strlen(DASHBOARD_REDACTED);
                size_t old = (size_t) (at - auth);
                size_t n   = (rep < old) ? rep : old;
                ngx_memcpy(auth, DASHBOARD_REDACTED, n);
                if (old > rep) {
                    ngx_memmove(auth + rep, at, (size_t) (end - at));
                    end -= (old - rep);
                }
                s = auth;   /* continue scanning after the rewrite */
                continue;
            }
        }

        /* query credential params: <key>=<value> up to & / delimiter */        if (*s == '?' || *s == '&') {
            u_char *kv = s + 1;
            size_t  i;
            for (i = 0; qkeys[i] != NULL; i++) {
                size_t kl = ngx_strlen(qkeys[i]);
                if (kv + kl <= end && dashboard_name_eq(kv, kl, qkeys[i])) {
                    u_char *vs = kv + kl;
                    u_char *ve = vs;
                    while (ve < end && *ve != '&' && *ve != ' ' && *ve != '\t'
                           && *ve != '"' && *ve != '\'' && *ve != ';'
                           && *ve != '#') {
                        ve++;
                    }
                    if (ve > vs) {
                        /* Fully overwrite the value; never grow (see userinfo). */
                        size_t rep = ngx_strlen(DASHBOARD_REDACTED);
                        size_t old = (size_t) (ve - vs);
                        size_t n   = (rep < old) ? rep : old;
                        ngx_memcpy(vs, DASHBOARD_REDACTED, n);
                        if (old > rep) {
                            ngx_memmove(vs + rep, ve, (size_t) (end - ve));
                            end -= (old - rep);
                        }
                    }
                    break;
                }
            }
        }
        s++;
    }
    return end;
}

/*
 * Append a directive line to *out with its value masked:
 *   "<indent><name> [redacted]<terminator>"
 * where terminator preserves a block '{' or statement ';' and a trailing '\r'.
 * If the directive has no value (e.g. "sendfile;") the line is emitted intact.
 * `line`/`line_end` exclude the '\n'.
 */
static u_char *
dashboard_emit_masked(u_char *out, const u_char *line, const u_char *line_end,
    const u_char *name, const u_char *name_end)
{
    const u_char *vs = name_end;
    const u_char *t;
    ngx_uint_t    has_value;
    ngx_uint_t    is_block = 0;
    ngx_uint_t    has_semi = 0;
    ngx_uint_t    has_cr = (line_end > line && line_end[-1] == '\r');

    while (vs < line_end && (*vs == ' ' || *vs == '\t')) { vs++; }
    for (t = vs; t < line_end; t++) {
        if (*t == '{') { is_block = 1; }
        if (*t == ';') { has_semi = 1; }
    }
    has_value = (vs < line_end && *vs != '{' && *vs != ';' && *vs != '\r');

    /* indent + name */
    ngx_memcpy(out, line, (size_t) (name_end - line));
    out += (name_end - line);

    if (has_value) {
        *out++ = ' ';
        ngx_memcpy(out, DASHBOARD_REDACTED, ngx_strlen(DASHBOARD_REDACTED));
        out += ngx_strlen(DASHBOARD_REDACTED);
    }
    if (is_block) { *out++ = ' '; *out++ = '{'; }
    else if (has_semi) { *out++ = ';'; }
    if (has_cr) { *out++ = '\r'; }
    *out++ = '\n';
    return out;
}

/*
 * Redact a whole config buffer. Allocates and fills out_buf / out_len from
 * r->pool. Returns NGX_OK or NGX_ERROR (alloc failure).
 *
 * Output sizing (must be a hard upper bound — a masked line writes a CONSTANT
 * " [redacted]" regardless of how short the original value was, so growth is
 * per-LINE, not proportional to input): a masked line emits at most
 * indent+name (<= line length) + " [redacted]" (11) + " {"/";" (2) + "\r\n" (2)
 * = line_len + 15. Kept/blank/comment lines never grow (dashboard_scrub_value_
 * creds is non-growing). So the body is bounded by in_len + 15*nlines; we
 * reserve 16*nlines + slack.
 */
static ngx_int_t
dashboard_redact_config(ngx_http_request_t *r, const u_char *in, size_t in_len,
    u_char **out_buf, size_t *out_len)
{
    static const char banner[] =
        "# nginx-xrootd running configuration (secrets redacted)\n"
        "# Values of directives not on the dashboard safe-allowlist are shown as\n"
        "# [redacted]; 'include' targets are NOT inlined. Secrets never appear.\n";
    size_t   nlines = 1, k;
    size_t   cap;
    u_char  *out;
    u_char  *w;
    const u_char *p = in;
    const u_char *end = in + in_len;

    for (k = 0; k < in_len; k++) {
        if (in[k] == '\n') { nlines++; }
    }
    cap = in_len + nlines * 16 + sizeof(banner) + 256;
    out = ngx_palloc(r->pool, cap);

    if (out == NULL) {
        return NGX_ERROR;
    }
    w = out;
    ngx_memcpy(w, banner, sizeof(banner) - 1);
    w += sizeof(banner) - 1;

    while (p < end) {
        const u_char *line = p;
        const u_char *nl = ngx_strlchr((u_char *) p, (u_char *) end, '\n');
        const u_char *line_end = (nl != NULL) ? nl : end;
        const u_char *q = line;
        const u_char *name, *name_end;

        p = (nl != NULL) ? nl + 1 : end;

        /* Defence-in-depth: the cap above is a proven upper bound, but never let
         * a write cross out+cap regardless. Worst growth for this line is
         * (line_len) + " [redacted]" (11) + " {"/";" (2) + "\r\n" (2); reserve
         * generously and fail closed (5xx, no body) rather than overflow. */
        if ((size_t) ((out + cap) - w) < (size_t) (line_end - line) + 32) {
            return NGX_ERROR;
        }

        /* leading whitespace */
        while (q < line_end && (*q == ' ' || *q == '\t')) { q++; }

        /* blank / comment / brace-only -> pass through, but scrub creds. */
        if (q >= line_end || *q == '#' || *q == '{' || *q == '}') {
            u_char *seg = w;
            ngx_memcpy(w, line, (size_t) (line_end - line));
            w += (line_end - line);
            w = dashboard_scrub_value_creds(seg, w);
            *w++ = '\n';
            continue;
        }

        /* directive name token */
        name = q;
        name_end = q;
        while (name_end < line_end && *name_end != ' ' && *name_end != '\t'
               && *name_end != ';' && *name_end != '{' && *name_end != '#') {
            name_end++;
        }

        if (dashboard_keep_value(name, (size_t) (name_end - name))) {
            u_char *seg = w;
            ngx_memcpy(w, line, (size_t) (line_end - line));
            w += (line_end - line);
            w = dashboard_scrub_value_creds(seg, w);   /* belt-and-suspenders */
            *w++ = '\n';
        } else {
            w = dashboard_emit_masked(w, line, line_end, name, name_end);
        }
    }

    *out_buf = out;
    *out_len = (size_t) (w - out);
    return NGX_OK;
}

/*
 * Read the running config file fully into a pool buffer. Returns NGX_OK with
 * buf / len set, or an NGX_HTTP_* status on failure (file missing, too large,
 * read error). Closes the fd on every path. No goto: the fd is owned here and
 * released before each return.
 */
static ngx_int_t
dashboard_read_config_file(ngx_http_request_t *r, u_char **buf, size_t *len)
{
    ngx_str_t   path = ngx_cycle->conf_file;
    char        cpath[NGX_MAX_PATH];
    int         fd;
    struct stat st;
    u_char     *b;
    ssize_t     n;
    size_t      got;

    if (path.len == 0
        || brix_str_cbuf(cpath, sizeof(cpath), &path) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    fd = open(cpath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (st.st_size <= 0 || st.st_size > DASHBOARD_CONFIG_MAX_BYTES) {
        close(fd);
        return NGX_HTTP_INSUFFICIENT_STORAGE;   /* 507: fail-safe, no body */
    }

    b = ngx_palloc(r->pool, (size_t) st.st_size);
    if (b == NULL) {
        close(fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    got = 0;
    while (got < (size_t) st.st_size) {
        n = read(fd, b + got, (size_t) st.st_size - got);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            close(fd);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (n == 0) { break; }   /* truncated since fstat — use what we have */
        got += (size_t) n;
    }
    close(fd);

    *buf = b;
    *len = got;
    return NGX_OK;
}

/* Emit the redacted config as a text/plain download. */
static ngx_int_t
dashboard_send_config(ngx_http_request_t *r, u_char *body, size_t len)
{
    ngx_buf_t       *b;
    ngx_chain_t      out;
    ngx_table_elt_t *h;
    ngx_int_t        rc;

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    b->pos = b->start = body;
    b->last = b->end  = body + len;
    b->memory   = 1;
    b->last_buf = 1;

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) len;
    r->headers_out.content_type     =
        (ngx_str_t) ngx_string("text/plain; charset=utf-8");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key,   "Content-Disposition");
        ngx_str_set(&h->value, "attachment; filename=\"nginx-xrootd.conf\"");
    }
    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key,   "Cache-Control");
        ngx_str_set(&h->value, "no-store");
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) { return rc; }

    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

ngx_int_t
ngx_http_brix_dashboard_config_download_handler(ngx_http_request_t *r)
{
    ngx_http_brix_dashboard_loc_conf_t *conf;
    ngx_int_t  rc;
    u_char    *raw, *red;
    size_t     raw_len, red_len;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_dashboard_module);

    /* ALWAYS auth — never anonymous (do NOT consult conf->anonymous). Pass
     * suppress_missing_cookie=0 so every unauthenticated config-download attempt
     * is audited, even when the read API is anonymous. */
    rc = ngx_http_brix_dashboard_check_auth(r, conf, 0);
    if (rc != NGX_OK) {
        return rc;
    }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* AGPL-3.0 sec.13: offer remote users the source. */
    brix_http_source_offer(r);

    rc = dashboard_read_config_file(r, &raw, &raw_len);
    if (rc != NGX_OK) {
        return rc;   /* 5xx, no body — never an unredacted/partial dump */
    }
    if (dashboard_redact_config(r, raw, raw_len, &red, &red_len) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return dashboard_send_config(r, red, red_len);
}
