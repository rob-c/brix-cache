#ifndef XROOTD_WEBDAV_COPY_ENGINE_H
#define XROOTD_WEBDAV_COPY_ENGINE_H

#include "webdav/webdav.h"

ngx_int_t webdav_copy_file(ngx_log_t *log, const char *root_canon,
    const char *src, const char *dst);
ngx_int_t webdav_copy_dir_recursive(ngx_log_t *log, const char *root_canon,
    const char *src, const char *dst);

#endif /* XROOTD_WEBDAV_COPY_ENGINE_H */
