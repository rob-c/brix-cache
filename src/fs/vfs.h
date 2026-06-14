/*
 * vfs.h — public API for the unified VFS (POSIX-filesystem data plane).
 *
 * WHAT: The only header protocol op handlers include to touch the export root.
 *       Declares the open flags (XROOTD_VFS_O_READ/WRITE/CREATE/EXCL/TRUNC/
 *       APPEND/MKDIRPATH/NOCACHE), the opaque handle types (xrootd_vfs_file_t,
 *       xrootd_vfs_dir_t), the per-operation request descriptor
 *       xrootd_vfs_ctx_t, the result/stat structs (xrootd_vfs_stat_t,
 *       xrootd_vfs_io_result_t), and every xrootd_vfs_* entry point —
 *       open/close, read/write, stat, opendir/readdir/closedir, and the
 *       namespace mutators unlink/rmdir/rename/mkdir plus truncate/sync.
 *
 * WHY:  All four front ends (XRootD root://, WebDAV davs://, the S3 subset, and
 *       CMS data-server I/O) funnel through this one protocol-agnostic surface
 *       so confinement, metrics, access logging, page-CRC, and cache
 *       integration are implemented once and inherited for free. Handlers must
 *       never call open/pread/rename directly — they fill an xrootd_vfs_ctx_t
 *       and call here.
 *
 * HOW:  A caller populates xrootd_vfs_ctx_t with the export root_canon (and the
 *       persistent per-worker rootfd), the already-resolved client path
 *       (xrootd_path_result_t, produced by ../path/), the caller identity,
 *       allow_write/is_tls/want_pgcrc/cache flags, and the metrics_proto, then
 *       invokes a single entry point. The handle accessors (xrootd_vfs_file_fd
 *       et al.) are the only way callers reach the underlying fd/size/mtime.
 */
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
    int                  rootfd;           /* persistent O_PATH fd, or -1 */
    void                *cache_writethrough_cfg;
    xrootd_path_result_t resolved;
    unsigned             allow_write:1;
    unsigned             is_tls:1;
    unsigned             want_pgcrc:1;
    unsigned             cache_enabled:1;
    unsigned             cache_writethrough:1;
} xrootd_vfs_ctx_t;

/* Open ctx->resolved under the confinement cascade with the given
 * XROOTD_VFS_O_* flags (translated to O_* internally). XROOTD_VFS_O_WRITE
 * requires ctx->allow_write (else EACCES); XROOTD_VFS_O_MKDIRPATH pre-creates
 * the parent dir tree; read opens may be satisfied from the read-through cache.
 * Returns a handle allocated on ctx->pool, or NULL with the syscall errno
 * written to *err_out (if non-NULL). The fd is closed by xrootd_vfs_close. */
xrootd_vfs_file_t *xrootd_vfs_open(xrootd_vfs_ctx_t *ctx,
    ngx_uint_t flags, int *err_out);
/* Close the handle's fd (idempotent; NULL/already-closed handle is NGX_OK).
 * The handle struct itself lives on the pool and is not freed here. Logs and
 * returns NGX_ERROR if the close(2) fails. */
ngx_int_t xrootd_vfs_close(xrootd_vfs_file_t *fh, ngx_log_t *log);

/* Accessors over the handle's cached metadata (captured at open via fstat) —
 * no syscalls. fd: underlying descriptor or NGX_INVALID_FILE if fh is NULL. */
ngx_fd_t xrootd_vfs_file_fd(const xrootd_vfs_file_t *fh);
/* Borrowed pointer to the handle's NUL-terminated path (owned by the pool);
 * returns "" (never NULL) when fh or its path is NULL. */
const char *xrootd_vfs_file_path(const xrootd_vfs_file_t *fh);
/* Cached file size in bytes (grows as writes extend the handle); 0 if fh NULL. */
off_t xrootd_vfs_file_size(const xrootd_vfs_file_t *fh);
/* Cached mtime captured at open; 0 if fh NULL. Not refreshed after writes. */
time_t xrootd_vfs_file_mtime(const xrootd_vfs_file_t *fh);
/* 1 if this handle was served from the read-through cache, else 0. */
ngx_uint_t xrootd_vfs_file_from_cache(const xrootd_vfs_file_t *fh);
/* Live fstat(2) of the open fd into *stat_out (unlike the cached accessors).
 * NGX_ERROR with errno set on a bad handle or fstat failure. */
ngx_int_t xrootd_vfs_file_stat(const xrootd_vfs_file_t *fh,
    xrootd_vfs_stat_t *stat_out);

/* Serve [offset, offset+length) from the handle as a freshly built ngx_chain_t
 * in *out (pool-allocated; *out=NULL on empty/past-EOF reads, which still return
 * NGX_OK). length is capped at EOF. Buffer shape depends on the handle: memory-
 * backed under TLS or want_pgcrc (and result->crc32c is filled), else file-backed
 * for sendfile. *result (if non-NULL) gets actual length/eof/from_cache. Records
 * cache access and emits read metrics. NGX_ERROR with errno set on failure. */
ngx_int_t xrootd_vfs_read(xrootd_vfs_file_t *fh, off_t offset,
    size_t length, ngx_chain_t **out, xrootd_vfs_io_result_t *result);
/* Write the input chain `in` (borrowed; file- and memory-backed bufs both
 * handled) contiguously starting at offset. Extends fh->size past the new high-
 * water mark and, when want_pgcrc, accumulates one CRC32c across the whole write
 * into result->crc32c. *result (if non-NULL) also gets bytes-written in length.
 * Emits write metrics. NGX_ERROR with errno set on partial/failed write. */
ngx_int_t xrootd_vfs_write(xrootd_vfs_file_t *fh, off_t offset,
    ngx_chain_t *in, xrootd_vfs_io_result_t *result);

/* lstat the resolved ctx path into *stat_out (symlinks reported, not followed).
 * Confined and metered as OP_STAT; NGX_ERROR with errno set on guard failure
 * (NULL stat_out / unconfined ctx -> EINVAL) or lstat error. */
ngx_int_t xrootd_vfs_stat(xrootd_vfs_ctx_t *ctx,
    xrootd_vfs_stat_t *stat_out);

/* Open the resolved ctx directory under confinement. Returns a handle on
 * ctx->pool, or NULL with the errno in *err_out (if non-NULL). The open is
 * metered as OP_DIRLIST. Release with xrootd_vfs_closedir. */
xrootd_vfs_dir_t *xrootd_vfs_opendir(xrootd_vfs_ctx_t *ctx, int *err_out);
/* Yield the next entry, one per call: name as a pool-allocated NUL-terminated
 * ngx_str_t in *name_out, plus an optional lstat of the child into *stat_out
 * (pass NULL to skip). "." and ".." are filtered out. Returns NGX_DONE at
 * end-of-stream, NGX_ERROR (errno set) on failure, NGX_OK otherwise. */
ngx_int_t xrootd_vfs_readdir(xrootd_vfs_dir_t *dh, ngx_str_t *name_out,
    xrootd_vfs_stat_t *stat_out);
/* Close the directory stream (idempotent; NULL/already-closed is NGX_OK). The
 * handle struct stays on the pool. Logs and returns NGX_ERROR on closedir(3). */
ngx_int_t xrootd_vfs_closedir(xrootd_vfs_dir_t *dh, ngx_log_t *log);

/* Remove the resolved ctx path as a regular file (non-recursive). Write-gated
 * (requires allow_write) and requires a non-NULL root_canon; metered as
 * OP_DELETE. NGX_ERROR with errno set (mapped from the namespace status). */
ngx_int_t xrootd_vfs_unlink(xrootd_vfs_ctx_t *ctx);
/* Remove the resolved ctx directory: recursively when `recursive`, otherwise
 * only if empty. Write-gated, confined; metered as OP_DELETE. NGX_ERROR with
 * errno set on failure (e.g. ENOTEMPTY for a non-empty dir when not recursive). */
ngx_int_t xrootd_vfs_rmdir(xrootd_vfs_ctx_t *ctx, unsigned recursive);
/* Move the resolved ctx (source) path to the already-resolved destination `dst`
 * (borrowed; must be is_confined with a non-empty resolved path). Write-gated;
 * both endpoints confined; metered as OP_RENAME. NGX_ERROR with errno set. */
ngx_int_t xrootd_vfs_rename(xrootd_vfs_ctx_t *ctx,
    const xrootd_path_result_t *dst);
/* Create the resolved ctx path as a directory with `mode`, creating missing
 * parent components when `parents`. Write-gated, confined; metered as OP_MKDIR.
 * NGX_ERROR with errno set (e.g. EEXIST when the target already exists). */
ngx_int_t xrootd_vfs_mkdir(xrootd_vfs_ctx_t *ctx, mode_t mode,
    unsigned parents);
/* ftruncate the open handle to `length` and update the cached fh->size so later
 * reads see the new length. Unmetered. NGX_ERROR with errno set on a bad handle,
 * negative length, or ftruncate failure. */
ngx_int_t xrootd_vfs_truncate(xrootd_vfs_file_t *fh, off_t length);
/* fsync the open handle to stable storage. Unmetered (the enclosing write op
 * records the metric). NGX_ERROR with errno set on a bad handle or fsync error. */
ngx_int_t xrootd_vfs_sync(xrootd_vfs_file_t *fh);

#endif /* XROOTD_VFS_H */
