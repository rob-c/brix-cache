#ifndef XROOTD_WEBDAV_COPY_CONDITIONALS_H
#define XROOTD_WEBDAV_COPY_CONDITIONALS_H

#include "../webdav.h"

#include <sys/stat.h>

ngx_int_t webdav_check_copy_conditionals(ngx_http_request_t *r,
    const char *dst_path, int dst_exists, const struct stat *dst_sb);

#endif /* XROOTD_WEBDAV_COPY_CONDITIONALS_H */
