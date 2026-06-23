/*
 * handler.c — HTTP content handler for the WLCG SRR endpoint.
 *
 * WHAT: ngx_http_xrootd_srr_handler() serves the storageservice JSON document
 *   for a location carrying `xrootd_srr on;`.  GET/HEAD only; request body is
 *   discarded; no request input influences the output.
 *
 * WHY: Mirrors the /metrics handler (src/metrics/handler.c) so the two
 *   read-only reporting endpoints behave identically (method gating, body
 *   discard, NGX_DECLINED when disabled so the location can be toggled without
 *   a 404).  The payload is sized to the document via the builder's two-pass
 *   json_dumpb().
 *
 * HOW: build → set status/headers (application/json) → send_header → output the
 *   single memory buffer.  HEAD stops after the header.
 */

#include "srr.h"
#include "../compat/http_headers.h"
#include "../compat/alloc_guard.h"


ngx_int_t
ngx_http_xrootd_srr_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_srr_loc_conf_t *lcf;
    ngx_int_t                       rc;
    u_char                         *buf;
    size_t                          len;
    ngx_buf_t                      *b;
    ngx_chain_t                     out;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_srr_module);
    if (!lcf->enable) {
        return NGX_DECLINED;
    }

    /* AGPL-3.0 sec.13: offer remote users the source (X-Source header). */
    xrootd_http_source_offer(r);

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_http_xrootd_srr_build_json(r, lcf, &buf, &len) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) len;

    {
        ngx_str_t ct = ngx_string("application/json");
        r->headers_out.content_type         = ct;
        r->headers_out.content_type_len     = ct.len;
        r->headers_out.content_type_lowcase = NULL;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    XROOTD_PCALLOC_OR_RETURN(b, r->pool, sizeof(*b), NGX_HTTP_INTERNAL_SERVER_ERROR);
    b->pos      = b->start = buf;
    b->last     = b->end   = buf + len;
    b->memory   = 1;
    b->last_buf = 1;

    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}
