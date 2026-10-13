/*
 * access_query.c - WebDAV access-phase query boundary.
 *
 * WHAT: Parses the request query exactly once, rejects ambiguous credential
 *       names, and prepares the XrdHttp compatibility context.
 * WHY: Authentication must consume one canonical request-owned parse, while
 *      native nginx log sources are scrubbed before any later error can expose
 *      a query credential.
 * HOW: Validate unique decoded names, reject encoded or repeated credential
 *      keys, then delegate XrdHttp parsing and TPC header injection.
 */

#include "access_internal.h"
#include "xrdhttp.h"

/* ---- Parse and validate the query authentication boundary ----
 *
 * WHAT: Return NGX_OK with xctx->query populated, NGX_HTTP_BAD_REQUEST for an
 *       ambiguous credential query, or NGX_HTTP_INTERNAL_SERVER_ERROR when the
 *       request context cannot be allocated.
 * WHY: Alternate encodings and duplicate credential keys must not let two
 *      consumers authenticate different interpretations of one request.
 * HOW: 1. Allocate the request context. 2. Parse and require unique names.
 *      3. Require literal credential-key spellings and at most one token key.
 *      4. Scrub query tokens on every refusal.
 */
ngx_int_t
access_parse_query_boundary(ngx_http_request_t *r)
{
    xrdhttp_req_ctx_t *xctx = xrdhttp_get_ctx(r);
    ngx_uint_t         i;
    ngx_uint_t         token_params = 0;

    if (xctx == NULL) {
        brix_http_redact_request_query_tokens(r);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (brix_http_query_parse(r->pool, r->args, &xctx->query) < 0
        || brix_http_query_unique(&xctx->query,
                                  BRIX_HTTP_QUERY_CASE_INSENSITIVE) < 0)
    {
        brix_http_redact_request_query_tokens(r);
        return NGX_HTTP_BAD_REQUEST;
    }
    for (i = 0; i < xctx->query.count; i++) {
        const brix_http_query_param_t *param = &xctx->query.params[i];
        int is_authz = param->name.len == sizeof("authz") - 1
            && ngx_strncasecmp(param->name.data, (u_char *) "authz",
                               param->name.len) == 0;
        int is_access_token =
            param->name.len == sizeof("access_token") - 1
            && ngx_strncasecmp(param->name.data, (u_char *) "access_token",
                               param->name.len) == 0;

        token_params += is_authz || is_access_token;
        if ((is_authz || is_access_token)
            && (param->raw_name.len != param->name.len
                || ngx_strncasecmp(param->raw_name.data, param->name.data,
                                   param->name.len) != 0))
        {
            brix_http_redact_request_query_tokens(r);
            return NGX_HTTP_BAD_REQUEST;
        }
    }
    if (token_params > 1) {
        brix_http_redact_request_query_tokens(r);
        return NGX_HTTP_BAD_REQUEST;
    }
    return NGX_OK;
}

/* ---- Prepare the compatibility request after authentication ----
 *
 * WHAT: Return NGX_OK after parsing XrdHttp metadata and injecting TPC
 *       headers, or the corresponding HTTP/internal error.
 * WHY: The access orchestrator needs one checked operation instead of ignoring
 *      either parser's return value.
 * HOW: Parse XrdHttp state first; only on success inject the TPC headers.
 */
ngx_int_t
access_prepare_xrdhttp(ngx_http_request_t *r)
{
    ngx_int_t rc;

    rc = xrdhttp_parse_request(r);
    if (rc != NGX_OK) {
        return rc;
    }
    return xrdhttp_inject_tpc_headers(r) == NGX_OK
           ? NGX_OK : NGX_HTTP_INTERNAL_SERVER_ERROR;
}
