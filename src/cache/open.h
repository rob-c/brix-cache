#ifndef XROOTD_CACHE_OPEN_H
#define XROOTD_CACHE_OPEN_H

#include "../fs/vfs.h"

ngx_int_t xrootd_cache_open(xrootd_vfs_ctx_t *ctx, ngx_uint_t flags,
    xrootd_vfs_file_t **fh_out);
ngx_int_t xrootd_cache_record_access(const char *cache_path, size_t bytes,
    ngx_log_t *log);
ngx_int_t xrootd_cache_path_for_resolved(const char *cache_root_canon,
    const char *root_canon, const char *resolved, char *out, size_t outsz);

#endif /* XROOTD_CACHE_OPEN_H */
