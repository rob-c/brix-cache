#ifndef BRIX_WEBDAV_COPY_ENGINE_H
#define BRIX_WEBDAV_COPY_ENGINE_H

#include "protocols/webdav/webdav.h"

ngx_int_t webdav_copy_file(const brix_vfs_export_op_ctx_t *opctx,
    const char *src, const char *dst);
ngx_int_t webdav_copy_dir_recursive(const brix_vfs_export_op_ctx_t *opctx,
    const char *src, const char *dst);

#endif /* BRIX_WEBDAV_COPY_ENGINE_H */
