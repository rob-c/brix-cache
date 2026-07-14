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

#include "config_download_internal.h"

#define DASHBOARD_CONFIG_MAX_BYTES   (1 << 20)   /* 1 MiB cap (fail-safe) */

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
 * Emit one line verbatim (plus '\n'), then scrub embedded URL credentials in
 * the copied bytes. Used for pass-through lines: blank/comment/brace lines
 * and directives whose value passed the fail-closed keep test
 * (belt-and-suspenders — a secret hiding inside a "safe" URL is still masked).
 * Returns the new write pointer.
 */
static u_char *
dashboard_emit_scrubbed(u_char *w, const u_char *line, const u_char *line_end)
{
    u_char *seg = w;

    ngx_memcpy(w, line, (size_t) (line_end - line));
    w += (line_end - line);
    w = dashboard_scrub_value_creds(seg, w);
    *w++ = '\n';
    return w;
}

/* End of the directive-name token starting at q (space/tab/';'/'{'/'#'). */
static const u_char *
dashboard_name_token_end(const u_char *q, const u_char *line_end)
{
    while (q < line_end && *q != ' ' && *q != '\t'
           && *q != ';' && *q != '{' && *q != '#') {
        q++;
    }
    return q;
}

/*
 * Redact a single config line [line,line_end) (excluding the '\n') into w:
 * blank/comment/brace-only lines pass through cred-scrubbed; directives on
 * the fail-closed allowlist keep their value (also cred-scrubbed); everything
 * else has its value masked. Returns the new write pointer.
 */
static u_char *
dashboard_redact_line(u_char *w, const u_char *line, const u_char *line_end)
{
    const u_char *q = line;
    const u_char *name, *name_end;

    /* leading whitespace */
    while (q < line_end && (*q == ' ' || *q == '\t')) { q++; }

    /* blank / comment / brace-only -> pass through, but scrub creds. */
    if (q >= line_end || *q == '#' || *q == '{' || *q == '}') {
        return dashboard_emit_scrubbed(w, line, line_end);
    }

    /* directive name token */
    name = q;
    name_end = dashboard_name_token_end(q, line_end);

    if (dashboard_keep_value(name, (size_t) (name_end - name))) {
        return dashboard_emit_scrubbed(w, line, line_end);
    }
    return dashboard_emit_masked(w, line, line_end, name, name_end);
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

        p = (nl != NULL) ? nl + 1 : end;

        /* Defence-in-depth: the cap above is a proven upper bound, but never let
         * a write cross out+cap regardless. Worst growth for this line is
         * (line_len) + " [redacted]" (11) + " {"/";" (2) + "\r\n" (2); reserve
         * generously and fail closed (5xx, no body) rather than overflow. */
        if ((size_t) ((out + cap) - w) < (size_t) (line_end - line) + 32) {
            return NGX_ERROR;
        }

        w = dashboard_redact_line(w, line, line_end);
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
