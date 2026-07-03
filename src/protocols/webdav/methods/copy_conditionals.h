#ifndef BRIX_WEBDAV_COPY_CONDITIONALS_H
#define BRIX_WEBDAV_COPY_CONDITIONALS_H

#include "protocols/webdav/webdav.h"

#include <sys/stat.h>

ngx_int_t webdav_check_copy_conditionals(ngx_http_request_t *r,
    const char *dst_path, int dst_exists, const struct stat *dst_sb);

#endif /* BRIX_WEBDAV_COPY_CONDITIONALS_H */
