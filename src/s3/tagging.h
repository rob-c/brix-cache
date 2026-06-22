/*
 * tagging.h — S3 object tagging + canned subresource handlers (phase-43 W5).
 * See tagging.c for the design.
 */

#ifndef NGX_HTTP_S3_TAGGING_H
#define NGX_HTTP_S3_TAGGING_H

#include "s3.h"

/* GET /<key>?tagging → <Tagging><TagSet>… from the object's tag xattr. */
ngx_int_t s3_handle_get_object_tagging(ngx_http_request_t *r,
    const char *fs_path, ngx_http_s3_loc_conf_t *cf);

/* DELETE /<key>?tagging → remove the tag xattr (204). */
ngx_int_t s3_handle_delete_object_tagging(ngx_http_request_t *r,
    const char *fs_path, ngx_http_s3_loc_conf_t *cf);

/* PUT /<key>?tagging async body callback: parse the <Tagging> XML and store. */
void s3_put_object_tagging_body_handler(ngx_http_request_t *r);

/* Apply an x-amz-tagging header sent with a normal PutObject.  Returns NGX_OK
 * (stored / absent) or NGX_ERROR (malformed value or store failed). */
ngx_int_t s3_apply_put_tagging_header(ngx_http_request_t *r,
    const char *fs_path, const char *root_canon);

/* Canned probe-satisfiers. */
ngx_int_t s3_handle_get_bucket_versioning(ngx_http_request_t *r);
ngx_int_t s3_handle_get_acl(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf);
ngx_int_t s3_handle_get_cors(ngx_http_request_t *r);

#endif /* NGX_HTTP_S3_TAGGING_H */
