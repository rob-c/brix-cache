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

/* ---- Recover the target port from the raw request line ----
 *
 * WHAT: sets *port to the absolute-form target's port, defaulting to 80 when
 *       no ":port" is present. Returns NGX_OK, or NGX_HTTP_BAD_REQUEST when the
 *       port digits are out of the 1..65535 range.
 *
 * WHY:  nginx (>= 1.11) keeps no port_start/port_end for absolute-form
 *       targets, so the port must be read back from the request line between
 *       host_end (":") and uri_start ("/") — both recorded by the parser.
 *
 * HOW:  1. Default the port to 80.
 *       2. When a ':' separates host_end from uri_start, parse the digits.
 *       3. Reject an out-of-range value; otherwise publish it.
 */
static ngx_int_t
brix_cvmfs_proxy_parse_port(ngx_http_request_t *r, in_port_t *port)
{
    ngx_int_t p;

    *port = 80;
    if (r->uri_start != NULL && r->host_end != NULL
        && r->host_end < r->uri_start && *r->host_end == ':')
    {
        p = ngx_atoi(r->host_end + 1,
                     (size_t) (r->uri_start - (r->host_end + 1)));
        if (p < 1 || p > 65535) {
            return NGX_HTTP_BAD_REQUEST;
        }
        *port = (in_port_t) p;
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
 *       3. Publish the host span nginx already parsed.
 *       4. Recover the target port from the request line.
 *       5. Authorize the host against the Stratum-1 allowlist.
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

    host->data = r->host_start;
    host->len  = (size_t) (r->host_end - r->host_start);

    rc = brix_cvmfs_proxy_parse_port(r, port);
    if (rc != NGX_OK) {
        return rc;
    }

    return brix_cvmfs_proxy_host_allowed(cc, host);
}
