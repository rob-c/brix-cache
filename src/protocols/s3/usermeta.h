/*
 * usermeta.h — S3 user-defined object metadata (x-amz-meta-*). See usermeta.c.
 */

#ifndef NGX_HTTP_S3_USERMETA_H
#define NGX_HTTP_S3_USERMETA_H

#include "s3.h"

/* Apply the x-amz-meta-* headers sent with a normal PutObject: store the whole
 * set as one blob xattr beside the freshly-committed object. Returns NGX_OK
 * (stored / none present) or NGX_ERROR (store failed). */
ngx_int_t s3_apply_put_user_metadata(ngx_http_request_t *r,
    const char *fs_path, const char *root_canon);

/* Emit the stored user metadata as x-amz-meta-<name> response headers on a
 * GET/HEAD. No-op when the object carries none. */
void s3_echo_user_metadata(ngx_http_request_t *r, const char *fs_path);

/* Copy the user-metadata blob from src to dst (CopyObject, COPY directive). */
ngx_int_t s3_user_meta_copy(ngx_http_request_t *r,
    const char *src_fs_path, const char *dst_fs_path);

#endif /* NGX_HTTP_S3_USERMETA_H */
