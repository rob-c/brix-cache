/*
 * dashboard_json.c — shared JSON response serialiser for the dashboard HTTP
 * endpoints.  See dashboard_json.h.
 */
#include "dashboard_json.h"

ngx_int_t
dashboard_json_send(ngx_http_request_t *r, ngx_int_t status, json_t *root)
{
    ngx_buf_t       *b;
    ngx_chain_t      out;
    ngx_table_elt_t *cc;
    ngx_int_t        rc;
    size_t           needed;
    u_char          *buf;

    if (root == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Two-pass serialise: a NULL-buffer dump returns the exact byte count, then
     * allocate that and dump for real — sizing the response to the payload.
     * needed==0 means a dump error. */
    needed = json_dumpb(root, NULL, 0, JSON_COMPACT);
    if (needed == 0) {
        json_decref(root);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    buf = ngx_palloc(r->pool, needed);
    if (buf == NULL) {
        json_decref(root);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    json_dumpb(root, (char *) buf, needed, JSON_COMPACT);
    /* root is fully serialised into buf; release it now (we own the ref). */
    json_decref(root);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = b->start = buf;
    b->last = b->end  = buf + needed;
    b->memory   = 1;
    b->last_buf = 1;

    r->headers_out.status           = status;
    r->headers_out.content_length_n = (off_t) needed;
    r->headers_out.content_type     = (ngx_str_t) ngx_string("application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc != NULL) {
        cc->hash = 1;
        ngx_str_set(&cc->key,   "Cache-Control");
        ngx_str_set(&cc->value, "no-store");
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

#define DASHBOARD_SCHEMA_VERSION "xrootd-dashboard.v1"

void
dashboard_json_set_schema(json_t *root)
{
    if (root != NULL) {
        json_object_set_new(root, "schema",
                            json_string(DASHBOARD_SCHEMA_VERSION));
    }
}
