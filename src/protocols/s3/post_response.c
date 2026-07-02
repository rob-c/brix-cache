/*
 * post_response.c - extracted concern
 * Phase-38 split of post_object.c; behavior-identical.
 */
#include "s3_post_internal.h"


/* Send a header-only response with the given status and no body. */
ngx_int_t
s3_post_send_empty(ngx_http_request_t *r, ngx_uint_t status)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}


/*
 * WHAT: Send the 201 Created <PostResponse> XML document (Location/Bucket/Key/
 *       ETag) used when the form requested success_action_status=201.
 * HOW:  Build the Location URL (absolute if a Host header is present, else a
 *       path), then assemble the XML via the XML_APPEND* helper macros.
 */
ngx_int_t
s3_post_send_created(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, const char *etag)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;
    u_char       *xml;
    size_t        xml_capacity = 8192;
    size_t        xml_len = 0;
    ngx_int_t     rc;
    ngx_str_t     host;
    char          location[S3_MAX_KEY + 512];

    XROOTD_PNALLOC_OR_RETURN(xml, r->pool, xml_capacity, NGX_HTTP_INTERNAL_SERVER_ERROR);

    /* Absolute URL when a Host header is available; otherwise a bare path. */
    host = r->headers_in.host ? r->headers_in.host->value
                              : (ngx_str_t) ngx_null_string;
    if (host.len > 0) {
        snprintf(location, sizeof(location), "http://%.*s/%.*s/%s",
                 (int) host.len, host.data,
                 (int) cf->bucket.len, cf->bucket.data, form->key);
    } else {
        snprintf(location, sizeof(location), "/%.*s/%s",
                 (int) cf->bucket.len, cf->bucket.data, form->key);
    }

    /* Assemble the <PostResponse> body (mechanical field-by-field build). */
    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
               "<PostResponse>");
    XML_APPEND_ELEM("Location", location, strlen(location));
    XML_APPEND_ELEM("Bucket", cf->bucket.data, cf->bucket.len);
    XML_APPEND_ELEM("Key", form->key, strlen(form->key));
    XML_APPEND_ELEM("ETag", etag, strlen(etag));
    XML_APPEND("</PostResponse>");

    b = ngx_create_temp_buf(r->pool, xml_len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, xml, xml_len);
    b->last = b->pos + xml_len;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_CREATED;
    r->headers_out.content_length_n = (off_t) xml_len;
    r->headers_out.content_type.len = sizeof("application/xml") - 1;
    r->headers_out.content_type.data = (u_char *) "application/xml";
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


/*
 * WHAT: Produce the client-requested success response after a stored object.
 * WHY:  The S3 POST form controls the success shape via two optional fields,
 *       checked in precedence order:
 *         - success_action_redirect: 303 redirect to the client-supplied URL
 *           (validated for control chars first, since it becomes a Location).
 *         - success_action_status: 200 / 201 / 204 (default 204 if unset).
 *       Anything else is a client error.
 */
ngx_int_t
s3_post_send_success(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, const char *etag)
{
    /* Redirect takes precedence over success_action_status when both are set. */
    if (form->success_redirect[0] != '\0') {
        /* Reject control chars: this value is reflected into a Location header. */
        if (xrootd_http_str_has_ctl((u_char *) form->success_redirect,
                                    strlen(form->success_redirect)))
        {
            return s3_post_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                                 "success_action_redirect is invalid.");
        }
        if (s3_set_header(r, "Location", form->success_redirect) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return s3_post_send_empty(r, NGX_HTTP_SEE_OTHER);
    }

    /* Default success status is 204 No Content when unspecified. */
    if (form->success_status[0] == '\0'
        || strcmp(form->success_status, "204") == 0)
    {
        return s3_post_send_empty(r, NGX_HTTP_NO_CONTENT);
    }

    if (strcmp(form->success_status, "200") == 0) {
        return s3_post_send_empty(r, NGX_HTTP_OK);
    }

    if (strcmp(form->success_status, "201") == 0) {
        return s3_post_send_created(r, cf, form, etag);
    }

    return s3_post_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                         "success_action_status must be 200, 201, or 204.");
}
