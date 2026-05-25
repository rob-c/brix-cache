#ifndef XROOTD_WEBDAV_LOCKS_REQUEST_H
#define XROOTD_WEBDAV_LOCKS_REQUEST_H

#include "../webdav.h"

ngx_msec_t webdav_lock_parse_timeout(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf);
int webdav_lock_if_header_matches(ngx_http_request_t *r, const char *token);
ngx_int_t webdav_lock_parse_depth(ngx_http_request_t *r,
    int *depth_infinity);
void webdav_lock_parse_body(ngx_http_request_t *r, char *owner,
    size_t owner_len, int *exclusive);

#endif /* XROOTD_WEBDAV_LOCKS_REQUEST_H */
