/*
 * request.c - WebDAV LOCK request parsing helpers.
 */

#include "request.h"
#include "core/compat/xml.h"

int64_t
webdav_lock_parse_timeout(ngx_http_request_t *r,
                          ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_table_elt_t *h;
    u_char          *p, *end;
    ngx_uint_t       timeout = 3600; /* default 1 hour if not bounded */

    h = webdav_tpc_find_header(r, "Timeout", sizeof("Timeout") - 1);
    if (h == NULL) {
        timeout = 3600;
    } else {
        p = h->value.data;
        end = p + h->value.len;

        if (ngx_strncasecmp(p, (u_char *) "Second-", 7) == 0) {
            p += 7;
            timeout = ngx_atoi(p, end - p);
            if (timeout == (ngx_uint_t) NGX_ERROR) {
                timeout = 3600;
            }
        } else if (ngx_strncasecmp(p, (u_char *) "Infinite", 8) == 0) {
            timeout = conf->lock_timeout;
        }
    }

    /* Bound timeout to reasonable range [1, conf->lock_timeout]. */
    if (timeout < 1) timeout = 1;
    if (timeout > conf->lock_timeout) timeout = conf->lock_timeout;

    /* Absolute WALL-CLOCK expiry (Unix seconds). Persisted in the lock xattr, so
     * it must be reboot-stable — ngx_current_msec (monotonic) would not be. */
    return (int64_t) ngx_time() + (int64_t) timeout;
}

int
webdav_lock_if_header_matches(ngx_http_request_t *r, const char *token)
{
    ngx_table_elt_t *h;

    h = webdav_tpc_find_header(r, "If", sizeof("If") - 1);
    if (h == NULL) {
        /*
         * Some clients incorrectly use Lock-Token for refreshes; accept it
         * here to preserve compatibility with the previous handler behavior.
         */
        h = webdav_tpc_find_header(r, "Lock-Token", sizeof("Lock-Token") - 1);
        if (h == NULL) return 0;
    }

    if (ngx_strstr(h->value.data, (u_char *) token) != NULL) {
        return 1;
    }

    return 0;
}

ngx_int_t
webdav_lock_parse_depth(ngx_http_request_t *r, int *depth_infinity)
{
    ngx_table_elt_t *depth_hdr;

    *depth_infinity = 1;

    depth_hdr = webdav_tpc_find_header(r, "Depth", sizeof("Depth") - 1);
    if (depth_hdr == NULL) {
        return NGX_OK;
    }

    if (depth_hdr->value.len == 1 && depth_hdr->value.data[0] == '0') {
        *depth_infinity = 0;
        return NGX_OK;
    }

    if (ngx_strncasecmp(depth_hdr->value.data,
                        (u_char *) "infinity", 8) == 0)
    {
        return NGX_OK;
    }

    return NGX_HTTP_BAD_REQUEST;
}

void
webdav_lock_parse_body(ngx_http_request_t *r, char *owner,
                       size_t owner_len, int *exclusive)
{
    ngx_chain_t *cl;
    char        *body_data;
    size_t       blen;

    if (owner_len == 0) {
        return;
    }

    owner[0] = '\0';
    *exclusive = 1; /* default per RFC 4918 section 9.10 */

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return;
    }

    cl = r->request_body->bufs;
    if (cl->buf == NULL) {
        return;
    }

    body_data = (char *) cl->buf->pos;
    blen = cl->buf->last - cl->buf->pos;

    (void) brix_xml_parse_lockinfo(body_data, blen, owner, owner_len,
                                     exclusive);
}
