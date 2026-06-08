#ifndef XROOTD_VFS_H
#define XROOTD_VFS_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "../path/unified.h"
#include "../types/identity.h"
#include "../metrics/unified.h"

#define XROOTD_VFS_O_READ        0x01
#define XROOTD_VFS_O_WRITE       0x02
#define XROOTD_VFS_O_CREATE      0x04
#define XROOTD_VFS_O_EXCL        0x08
#define XROOTD_VFS_O_TRUNC       0x10
#define XROOTD_VFS_O_APPEND      0x20
#define XROOTD_VFS_O_MKDIRPATH   0x40
#define XROOTD_VFS_O_NOCACHE     0x80

typedef struct xrootd_vfs_file_s xrootd_vfs_file_t;
typedef struct xrootd_vfs_dir_s  xrootd_vfs_dir_t;

typedef struct {
    off_t        size;
    time_t       mtime;
    time_t       ctime;
    ngx_uint_t   mode;
    ino_t        ino;
    unsigned     is_directory:1;
    unsigned     is_regular:1;
} xrootd_vfs_stat_t;

typedef struct {
    off_t        offset;
    size_t       length;
    uint32_t     crc32c;
    unsigned     from_cache:1;
    unsigned     eof:1;
} xrootd_vfs_io_result_t;

typedef struct {
    ngx_pool_t          *pool;
    ngx_log_t           *log;
    xrootd_identity_t   *identity;
    xrootd_proto_t       metrics_proto;
    const char          *root_canon;
    const char          *cache_root_canon;
    void                *cache_writethrough_cfg;
    xrootd_path_result_t resolved;
    unsigned             allow_write:1;
    unsigned             is_tls:1;
    unsigned             want_pgcrc:1;
    unsigned             cache_enabled:1;
    unsigned             cache_writethrough:1;
} xrootd_vfs_ctx_t;

xrootd_vfs_file_t *xrootd_vfs_open(xrootd_vfs_ctx_t *ctx,
    ngx_uint_t flags, int *err_out);
ngx_int_t xrootd_vfs_close(xrootd_vfs_file_t *fh, ngx_log_t *log);

ngx_fd_t xrootd_vfs_file_fd(const xrootd_vfs_file_t *fh);
const char *xrootd_vfs_file_path(const xrootd_vfs_file_t *fh);
off_t xrootd_vfs_file_size(const xrootd_vfs_file_t *fh);
time_t xrootd_vfs_file_mtime(const xrootd_vfs_file_t *fh);
ngx_uint_t xrootd_vfs_file_from_cache(const xrootd_vfs_file_t *fh);
ngx_int_t xrootd_vfs_file_stat(const xrootd_vfs_file_t *fh,
    xrootd_vfs_stat_t *stat_out);

ngx_int_t xrootd_vfs_read(xrootd_vfs_file_t *fh, off_t offset,
    size_t length, ngx_chain_t **out, xrootd_vfs_io_result_t *result);
ngx_int_t xrootd_vfs_write(xrootd_vfs_file_t *fh, off_t offset,
    ngx_chain_t *in, xrootd_vfs_io_result_t *result);

ngx_int_t xrootd_vfs_stat(xrootd_vfs_ctx_t *ctx,
    xrootd_vfs_stat_t *stat_out);

xrootd_vfs_dir_t *xrootd_vfs_opendir(xrootd_vfs_ctx_t *ctx, int *err_out);
ngx_int_t xrootd_vfs_readdir(xrootd_vfs_dir_t *dh, ngx_str_t *name_out,
    xrootd_vfs_stat_t *stat_out);
ngx_int_t xrootd_vfs_closedir(xrootd_vfs_dir_t *dh, ngx_log_t *log);

ngx_int_t xrootd_vfs_unlink(xrootd_vfs_ctx_t *ctx);
ngx_int_t xrootd_vfs_rmdir(xrootd_vfs_ctx_t *ctx, unsigned recursive);
ngx_int_t xrootd_vfs_rename(xrootd_vfs_ctx_t *ctx,
    const xrootd_path_result_t *dst);
ngx_int_t xrootd_vfs_mkdir(xrootd_vfs_ctx_t *ctx, mode_t mode,
    unsigned parents);
ngx_int_t xrootd_vfs_truncate(xrootd_vfs_file_t *fh, off_t length);
ngx_int_t xrootd_vfs_sync(xrootd_vfs_file_t *fh);

#endif /* XROOTD_VFS_H */
