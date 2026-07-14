#ifndef NGX_HTTP_BRIX_S3_OBJECT_INTERNAL_H
#define NGX_HTTP_BRIX_S3_OBJECT_INTERNAL_H

/*
 * Internal seam for the S3 object handlers split across object.c and
 * object_meta.c (mechanical file-size split, phase-79). Declares the one
 * symbol DEFINED in object.c but REFERENCED from object_meta.c.
 *
 * Includers must already have pulled in s3.h and fs/vfs/vfs.h so that
 * ngx_http_request_t, ngx_http_s3_loc_conf_t and brix_vfs_ctx_t are visible.
 */

/*
 * s3_vfs_ctx — initialise+bind a per-request VFS ctx for an object operation
 *   (GET/HEAD/DELETE). Defined in object.c.
 */
void s3_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, brix_vfs_ctx_t *vctx);

#endif /* NGX_HTTP_BRIX_S3_OBJECT_INTERNAL_H */
