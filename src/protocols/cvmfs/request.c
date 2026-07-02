/* request.c — proxy-mode target extraction + allowlist.
 *
 * WHAT: for absolute-form request lines ("GET http://s1:8000/cvmfs/..."),
 *       extract the authority nginx already parsed (r->host_start/end,
 *       r->port_start/end) and check it against xrootd_cvmfs_upstream_allow.
 * WHY:  a CVMFS site proxy is a proxy for the site's Stratum-1s ONLY —
 *       without the allowlist it is an open HTTP proxy.
 * HOW:  no parsing of our own: nginx validates absolute-form targets during
 *       request-line parsing and r->uri already holds just the path, so the
 *       classifier and every layer below see exactly the reverse-mode shape.
 */
#include "cvmfs.h"

ngx_int_t
xrootd_cvmfs_proxy_target(ngx_http_request_t *r, const xrootd_cvmfs_conf_t *cc,
    ngx_str_t *host, in_port_t *port)
{
    ngx_str_t   *allow;
    ngx_uint_t   i;
    ngx_int_t    p;

    if (r->host_start == NULL) {
        return NGX_DECLINED;                    /* origin-form: reverse mode */
    }

    /* cleartext only on cvmfs://: WLCG proxy traffic is plain HTTP; an
     * https target means a misconfigured client, not a feature request.
     * (scvmfs://, T22, lifts this on secure listeners: ctx->secure allows
     * https authorities and TLS upstream connects.) */
    if (r->schema_end - r->schema_start != 4
        || ngx_strncasecmp(r->schema_start, (u_char *) "http", 4) != 0)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    host->data = r->host_start;
    host->len  = (size_t) (r->host_end - r->host_start);

    /* nginx (>= 1.11) keeps no port_start/port_end: for an absolute-form
     * target the port digits sit in the raw request line between host_end
     * (":") and uri_start ("/"), both of which the parser recorded. */
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
