#ifndef NGX_HTTP_BRIX_S3_OBJECT_INTERNAL_H
#define NGX_HTTP_BRIX_S3_OBJECT_INTERNAL_H

#include "protocols/shared/file_serve.h"

/*
 * Shared VFS context binding for object.c and object_meta.c.
 * The implementation lives in object_scope.c.
 *
 * Includers must already have pulled in s3.h and fs/vfs/vfs.h so that
 * ngx_http_request_t, ngx_http_s3_loc_conf_t and brix_vfs_ctx_t are visible.
 */

/*
 * s3_vfs_ctx — initialise+bind a per-request VFS ctx for an object operation
 *   (GET/HEAD/DELETE). Defined in object_scope.c.
 */
void s3_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, brix_vfs_ctx_t *vctx);

void s3_serve_metrics(ngx_http_request_t *r,
    const brix_http_serve_result_t *result);
void s3_get_compressed_done(ngx_http_request_t *r,
    const brix_http_serve_result_t *result, ngx_int_t rc);

#endif /* NGX_HTTP_BRIX_S3_OBJECT_INTERNAL_H */
