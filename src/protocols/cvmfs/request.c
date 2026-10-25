/* request.c — proxy-mode target extraction + allowlist.
 *
 * WHAT: for absolute-form request lines ("GET http://s1:8000/cvmfs/..."),
 *       extract the authority nginx already parsed (r->host_start/end,
 *       r->port_start/end) and check it against brix_cvmfs_upstream_allow.
 * WHY:  a CVMFS site proxy is a proxy for the site's Stratum-1s ONLY —
 *       without the allowlist it is an open HTTP proxy.
 * HOW:  no parsing of our own: nginx validates absolute-form targets during
 *       request-line parsing and r->uri already holds just the path, so the
 *       classifier and every layer below see exactly the reverse-mode shape.
 */
#include "cvmfs.h"

/* ---- Validate the absolute-form request scheme ----
 *
 * WHAT: returns NGX_OK when the absolute-form target scheme is acceptable on
 *       this listener, else NGX_HTTP_FORBIDDEN. http:// is always allowed;
 *       https:// is allowed only on a secure (scvmfs://) listener.
 *
 * WHY:  WLCG proxy traffic is plain HTTP, so an https target on a cleartext
 *       cvmfs:// listener means a misconfigured client, not a feature request.
 *       The secure (T22) listener lifts this to permit https authorities (and
 *       TLS upstream connects), gated on ctx->secure.
 *
 * HOW:  1. Fetch the per-request cvmfs ctx (carries the secure flag).
 *       2. Classify the parsed schema token as exactly "http" or "https".
 *       3. Refuse anything that is neither.
 *       4. Refuse https unless the ctx exists and is marked secure.
 */
static ngx_int_t
brix_cvmfs_proxy_scheme_check(ngx_http_request_t *r)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    size_t sl = (size_t) (r->schema_end - r->schema_start);
    int is_http  = (sl == 4
        && ngx_strncasecmp(r->schema_start, (u_char *) "http", 4) == 0);
    int is_https = (sl == 5
        && ngx_strncasecmp(r->schema_start, (u_char *) "https", 5) == 0);

    if (!is_http && !is_https) {
        return NGX_HTTP_FORBIDDEN;
    }
    if (is_https && (ctx == NULL || !ctx->secure)) {
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_OK;
}

static u_char *
brix_cvmfs_authority_host_end(u_char *start, u_char *authority_end,
    u_char **port_start)
{
    u_char *cursor;

    *port_start = NULL;
    if (*start == '[') {
        cursor = start + 1;
        while (cursor < authority_end && *cursor != ']') {
            cursor++;
        }
        if (cursor == authority_end || (cursor + 1 < authority_end
                                        && cursor[1] != ':'))
        {
            return NULL;
        }
        if (cursor + 1 < authority_end) {
            *port_start = cursor + 2;
        }
        return cursor + 1;
    }

    for (cursor = start; cursor < authority_end; cursor++) {
        if (*cursor == ':') {
            *port_start = cursor + 1;
            return cursor;
        }
    }
    return authority_end;
}

/* ---- Extract the host and port from the validated authority span ----
 *
 * WHAT: fills host and port from the absolute-form target, defaulting the port
 *       to 80. Returns NGX_OK, or NGX_HTTP_BAD_REQUEST for malformed bounds,
 *       bracket syntax, separators, or a port outside 1..65535.
 *
 * WHY:  nginx versions disagree on whether r->host_end points at the colon or
 *       after the complete host:port authority. The security allowlist is
 *       host-only, so using that unstable endpoint can reject valid packaged
 *       builds or accidentally compare the wrong authority bytes.
 *
 * HOW:  1. Bound the authority by nginx's validated host_start and uri_start.
 *       2. For bracketed IPv6, retain the brackets and find the closing one;
 *          otherwise the first colon separates the host from its port.
 *       3. Require any trailing authority bytes to be exactly :<valid-port>.
 */
static ngx_int_t
brix_cvmfs_proxy_extract_authority(ngx_http_request_t *r, ngx_str_t *host,
    in_port_t *port)
{
    u_char    *authority_end, *host_end, *port_start;
    ngx_int_t  parsed_port;

    if (r->host_start == NULL || r->uri_start == NULL
        || r->host_start >= r->uri_start)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    authority_end = r->uri_start;
    host_end = brix_cvmfs_authority_host_end(r->host_start, authority_end,
                                             &port_start);
    if (host_end == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (host_end == r->host_start) {
        return NGX_HTTP_BAD_REQUEST;
    }
    host->data = r->host_start;
    host->len = (size_t) (host_end - r->host_start);
    *port = 80;
    if (port_start != NULL) {
        if (port_start == authority_end) {
            return NGX_HTTP_BAD_REQUEST;
        }
        parsed_port = ngx_atoi(port_start,
                              (size_t) (authority_end - port_start));
        if (parsed_port < 1 || parsed_port > 65535) {
            return NGX_HTTP_BAD_REQUEST;
        }
        *port = (in_port_t) parsed_port;
    }
    return NGX_OK;
}

/* ---- Match the target host against the Stratum-1 allowlist ----
 *
 * WHAT: returns NGX_OK when host is listed in cc->upstream_allow (case-
 *       insensitive), else NGX_HTTP_FORBIDDEN.
 *
 * WHY:  the allowlist is the sole thing separating a CVMFS site proxy from an
 *       open HTTP proxy; an unset or empty allowlist means proxy mode is off,
 *       so every absolute-form target is refused.
 *
 * HOW:  1. Treat an unset/empty allowlist as proxy-off and refuse.
 *       2. Scan the entries for a length-exact, case-insensitive host match.
 *       3. Return NGX_OK on a hit, NGX_HTTP_FORBIDDEN otherwise.
 */
static ngx_int_t
brix_cvmfs_proxy_host_allowed(const brix_cvmfs_conf_t *cc, const ngx_str_t *host)
{
    ngx_str_t  *allow;
    ngx_uint_t  i;

    if (cc->upstream_allow == NULL || cc->upstream_allow->nelts == 0) {
        /* allowlist unset = proxy mode off: absolute-form always refused */
        return NGX_HTTP_FORBIDDEN;
    }
    allow = cc->upstream_allow->elts;
    for (i = 0; i < cc->upstream_allow->nelts; i++) {
        if (allow[i].len == host->len
            && ngx_strncasecmp(allow[i].data, host->data, host->len) == 0)
        {
            return NGX_OK;
        }
    }
    return NGX_HTTP_FORBIDDEN;
}

/* ---- Extract and authorize an absolute-form proxy target ----
 *
 * WHAT: for an absolute-form request line, fills host/port with the target
 *       authority and returns NGX_OK when it is an allowed Stratum-1. Returns
 *       NGX_DECLINED for origin-form (reverse mode), or an HTTP error status
 *       (FORBIDDEN/BAD_REQUEST) when the scheme, port, or host is rejected.
 *
 * WHY:  a CVMFS site proxy proxies the site's Stratum-1s ONLY; this gate keeps
 *       it from acting as an open HTTP proxy while leaving reverse-mode
 *       requests to fall through to the classifier.
 *
 * HOW:  1. Absent host_start means origin-form → NGX_DECLINED.
 *       2. Enforce the scheme policy (http always, https only when secure).
 *       3. Extract the bounded host and port independent of nginx-version
 *          host_end semantics.
 *       4. Authorize the request-target host against the Stratum-1 allowlist.
 */
ngx_int_t
brix_cvmfs_proxy_target(ngx_http_request_t *r, const brix_cvmfs_conf_t *cc,
    ngx_str_t *host, in_port_t *port)
{
    ngx_int_t rc;

    if (r->host_start == NULL) {
        return NGX_DECLINED;                    /* origin-form: reverse mode */
    }

    rc = brix_cvmfs_proxy_scheme_check(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = brix_cvmfs_proxy_extract_authority(r, host, port);
    if (rc != NGX_OK) {
        return rc;
    }

    return brix_cvmfs_proxy_host_allowed(cc, host);
}
