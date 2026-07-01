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
#include "backend/sd.h"

#define XROOTD_VFS_O_READ        0x01
#define XROOTD_VFS_O_WRITE       0x02
#define XROOTD_VFS_O_CREATE      0x04
#define XROOTD_VFS_O_EXCL        0x08
#define XROOTD_VFS_O_TRUNC       0x10
#define XROOTD_VFS_O_APPEND      0x20
#define XROOTD_VFS_O_MKDIRPATH   0x40
#define XROOTD_VFS_O_NOCACHE     0x80

typedef struct xrootd_vfs_file_s   xrootd_vfs_file_t;
typedef struct xrootd_vfs_dir_s    xrootd_vfs_dir_t;
typedef struct xrootd_vfs_staged_s xrootd_vfs_staged_t;

/* Options for xrootd_vfs_copy() — mirrors xrootd_ns_copy_opts_t without pulling
 * the namespace_ops header into this public surface. */
typedef struct {
    unsigned recursive:1;
    unsigned overwrite:1;
    unsigned overwrite_dirs:1;
    unsigned preserve_xattrs:1;
    unsigned staged_commit:1;
} xrootd_vfs_copy_opts_t;

typedef struct {
    off_t        size;
    time_t       mtime;
    time_t       ctime;
    time_t       atime;      /* access time — for oss.at in kXR_Qxattr replies   */
    ngx_uint_t   mode;
    ino_t        ino;
    dev_t        dev;        /* with ino: the kXR stat id (ino<<32 | dev)       */
    uid_t        uid;        /* with gid+mode: stat readable/writable flags     */
    gid_t        gid;
    blkcnt_t     blocks;     /* st_blocks — the VFS-mode stat size (blocks*512)  */
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
    /* Bound storage-driver instance for this export, or NULL to use the default
     * POSIX backend (full-featured, sendfile-capable). Reserved for per-export
     * backend selection; today the VFS treats NULL as POSIX. */
    xrootd_sd_instance_t *sd;
    void                *cache_writethrough_cfg;
    xrootd_path_result_t resolved;
    unsigned             allow_write:1;
    unsigned             is_tls:1;
    unsigned             want_pgcrc:1;
    unsigned             cache_enabled:1;
    unsigned             cache_writethrough:1;
} xrootd_vfs_ctx_t;

/* Populate *vctx for a transient (rootfd = -1) confined open of an
 * already-resolved canonical path, filling the fields the HTTP front ends set
 * identically (pool/log/proto, export+cache roots, cache_enabled, allow_write,
 * is_tls, identity, resolved path). HTTP-agnostic: callers pass pool/log/is_tls
 * from their own request. Callers may tweak individual fields afterwards. */
void xrootd_vfs_ctx_init(xrootd_vfs_ctx_t *vctx, ngx_pool_t *pool,
    ngx_log_t *log, xrootd_proto_t proto, const char *root_canon,
    const char *cache_root_canon, int allow_write, int is_tls,
    xrootd_identity_t *identity, const char *resolved_path);

/* The export-root-relative ("logical") form of an absolute confined `path` — the
 * key an inst-keyed storage driver expects (what xrootd_vfs_open passes to the
 * driver's open slot). Returns `path` unchanged when it is not under the ctx's
 * export root. A borrowed pointer into `path` (no allocation). */
const char *xrootd_vfs_export_relative(const xrootd_vfs_ctx_t *ctx,
    const char *path);

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
/* Adopt a storage-driver object (from a driver's open slot) into a NEW VFS read
 * handle, preserving its per-open state; the object's own fstat populates the
 * handle metadata. A heap_shell object is freed once copied. Used by the cache
 * hit-serve path (src/cache/open.c). writable is 0 for a read handle. */
ngx_int_t xrootd_vfs_adopt_obj(xrootd_vfs_ctx_t *ctx, const char *path,
    xrootd_sd_obj_t *o, unsigned writable, xrootd_vfs_file_t **out);

/* Wrap an already-open kernel fd in a NEW VFS read handle (the default POSIX
 * driver), fstat'ing it into the handle metadata. The handle is sendfile-capable
 * (CAP_FD|CAP_SENDFILE). Used to serve a materialized local temp file through the
 * shared sendfile pipeline. `from_cache` tags the handle; `writable` is 0 for a
 * read handle. NGX_OK with *out set, or NGX_ERROR (errno set). */
ngx_int_t xrootd_vfs_adopt_fd(xrootd_vfs_ctx_t *ctx, const char *path,
    ngx_fd_t fd, unsigned from_cache, unsigned writable,
    xrootd_vfs_file_t **out);

/* Copy the handle's storage-driver object (driver + instance + fd) into *out.
 * Layer 3: lets a caller route whole-object I/O (e.g. checksum-at-rest) through
 * the backend driver rather than the bare block-0 fd. For a default POSIX handle
 * out->driver is the POSIX driver (equivalent to using the fd). */
void xrootd_vfs_file_sd_obj(const xrootd_vfs_file_t *fh, xrootd_sd_obj_t *out);
/* The handle's fd ONLY when the backend can back a zero-copy transfer
 * (CAP_FD|CAP_SENDFILE), else NGX_INVALID_FILE. Callers that build a sendfile /
 * file-backed (b->in_file) response MUST gate on this — a NGX_INVALID_FILE
 * return means "this backend cannot sendfile; serve memory-backed instead".
 * For the default POSIX backend this is always the real fd. */
ngx_fd_t xrootd_vfs_file_sendfile_fd(const xrootd_vfs_file_t *fh);
/* 1 iff this handle's backend supports zero-copy sendfile (CAP_FD|CAP_SENDFILE),
 * else 0. The predicate form of xrootd_vfs_file_sendfile_fd(). */
ngx_uint_t xrootd_vfs_file_can_sendfile(const xrootd_vfs_file_t *fh);

/* Read up to `len` bytes at offset `off` through the handle's storage driver, for
 * a memory-backed serve of a backend with no single sendfile fd. Bytes read
 * (0 = EOF) or -1/errno. */
ssize_t xrootd_vfs_file_pread(xrootd_vfs_file_t *fh, void *buf, size_t len,
    off_t off);
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

/* lstat the resolved ctx path into *stat_out (symlinks reported, not followed).
 * Confined and metered as OP_STAT; NGX_ERROR with errno set on guard failure
 * (NULL stat_out / unconfined ctx -> EINVAL) or lstat error. */
ngx_int_t xrootd_vfs_stat(xrootd_vfs_ctx_t *ctx,
    xrootd_vfs_stat_t *stat_out);

/* stat the resolved ctx path into *stat_out, FOLLOWING a trailing in-export
 * symlink chroot-style (RESOLVE_IN_ROOT, confined to the export). Confined and
 * metered as OP_STAT; NGX_ERROR with errno set on guard failure / stat error. */
ngx_int_t xrootd_vfs_statf(xrootd_vfs_ctx_t *ctx,
    xrootd_vfs_stat_t *stat_out);

/* Classify the resolved ctx path's nearline (tape/MSS) residency — online /
 * nearline / offline / lost — WITHOUT forcing a recall, so protocol handlers can
 * advertise tape state (the HTTP Tape REST API, S3 InvalidObjectState /
 * x-amz-storage-class, root:// stat's nearline flag). Walks any read-cache /
 * write-stage decorators down to the CAP_NEARLINE driver; an export with no
 * nearline tier always reports ONLINE. NGX_OK with *out set, or NGX_ERROR (errno)
 * on a guard failure or driver error. The phase-64 replacement for the FRM
 * residency-xattr probe (frm_residency_probe). When `nearline_export` is non-NULL
 * it is set to 1 iff the residency came from a nearline (tape/MSS) tier (0 for a
 * plain disk/object export) — so callers that need the WLCG locality vocabulary can
 * distinguish ONLINE-on-a-tape-export (ONLINE_AND_NEARLINE) from ONLINE-on-disk. */
ngx_int_t xrootd_vfs_residency(xrootd_vfs_ctx_t *ctx,
    xrootd_sd_residency_t *out, int *nearline_export);

/* Confined existence/type probe for pre-op resolution / ACL gates. Like
 * xrootd_vfs_stat but emits NO OP_STAT metric/access-log line (the caller's own
 * op accounts for the access). nofollow selects lstat vs stat semantics.
 * NGX_OK (stat_out filled) when present, NGX_DECLINED when absent (errno kept),
 * NGX_ERROR on a confinement-guard failure. */
ngx_int_t xrootd_vfs_probe(xrootd_vfs_ctx_t *ctx, int nofollow,
    xrootd_vfs_stat_t *stat_out);

/* Open the resolved ctx directory under confinement. Returns a handle on
 * ctx->pool, or NULL with the errno in *err_out (if non-NULL). The open is
 * metered as OP_DIRLIST. Release with xrootd_vfs_closedir. */
xrootd_vfs_dir_t *xrootd_vfs_opendir(xrootd_vfs_ctx_t *ctx, int *err_out);
/* Non-metered confined opendir for bulk recursive walks (S3 ListObjects, WebDAV
 * SEARCH): emits NO OP_DIRLIST metric/access-log (the enclosing protocol op
 * accounts for the whole traversal, which would otherwise log one phantom open
 * per visited subdirectory). Otherwise identical to xrootd_vfs_opendir. */
xrootd_vfs_dir_t *xrootd_vfs_opendir_quiet(xrootd_vfs_ctx_t *ctx, int *err_out);
/* Yield the next entry, one per call: name as a pool-allocated NUL-terminated
 * ngx_str_t in *name_out, plus an optional lstat of the child into *stat_out
 * (pass NULL to skip). "." and ".." are filtered out. Returns NGX_DONE at
 * end-of-stream, NGX_ERROR (errno set) on failure, NGX_OK otherwise. */
ngx_int_t xrootd_vfs_readdir(xrootd_vfs_dir_t *dh, ngx_str_t *name_out,
    xrootd_vfs_stat_t *stat_out);

/* Entry kind derived from the readdir d_type, for callers that only need to
 * classify dir-vs-file without a per-entry stat (S3 ListObjects, WebDAV SEARCH).
 * XROOTD_VFS_DT_UNKNOWN means the filesystem did not populate d_type — the caller
 * should xrootd_vfs_probe() the child to classify. OTHER covers symlinks/specials
 * (never listed or traversed). */
typedef enum {
    XROOTD_VFS_DT_UNKNOWN = 0,
    XROOTD_VFS_DT_DIR,
    XROOTD_VFS_DT_REG,
    XROOTD_VFS_DT_OTHER
} xrootd_vfs_dirent_kind_t;

/* Like xrootd_vfs_readdir but yields the entry KIND from d_type (no per-entry
 * stat — preserves the fast classification path). *kind_out (optional) is set as
 * above. "." and ".." are filtered. NGX_DONE at end-of-stream, NGX_ERROR (errno)
 * on failure, NGX_OK otherwise. */
ngx_int_t xrootd_vfs_readdir_kind(xrootd_vfs_dir_t *dh, ngx_str_t *name_out,
    xrootd_vfs_dirent_kind_t *kind_out);

/* Close the directory stream (idempotent; NULL/already-closed is NGX_OK). The
 * handle struct stays on the pool. Logs and returns NGX_ERROR on closedir(3). */
ngx_int_t xrootd_vfs_closedir(xrootd_vfs_dir_t *dh, ngx_log_t *log);

/* The open directory's fd, for a dirfd-relative entry access that must stay
 * inside the same opened (impersonation-confined) directory — e.g. a TOCTOU-safe
 * per-entry openat() for a dirlist checksum. NGX_INVALID_FILE for a NULL/closed
 * handle, or a backend with no real fd (caller then has no dirfd-relative path). */
ngx_fd_t xrootd_vfs_dir_fd(const xrootd_vfs_dir_t *dh);

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
/* Thread-safe confined rename of src→dst under root_canon (no pool alloc, no
 * metric — usable off the event loop / pool-less). `overwrite` replaces an
 * existing destination; otherwise an existing dst fails with errno==EEXIST.
 * *was_dir_out (optional) reports whether a conflicting destination was a
 * directory (kXR_mv maps EEXIST + was_dir → kXR_isDirectory vs kXR_ItExists).
 * NGX_OK, or NGX_ERROR with errno set (EEXIST/ENOTEMPTY/EACCES/ENOTDIR/ENOENT
 * from the namespace status). */
ngx_int_t xrootd_vfs_rename_path(xrootd_sd_instance_t *sd, ngx_log_t *log,
    const char *root_canon, const char *src, const char *dst,
    unsigned overwrite, int *was_dir_out);
/* Enumerate the bound backend's OWN object catalog (inventory/drift, spec
 * §E1/D2) — the driver-agnostic seam over the SD `enumerate` verb. Fires cb once
 * per stored object (xrootd_sd_catalog_ent_t); want_stat asks for per-object
 * size/mtime. Returns NGX_OK (full enumeration), the cb's non-zero abort code, or
 * NGX_DECLINED with errno==ENOTSUP when the backend has no native catalog (POSIX:
 * the namespace IS the catalog — callers fall back to a vfs_walk). Thread-safe to
 * the extent the driver's enumerate is (the Ceph verb runs on a thread worker). */
ngx_int_t xrootd_vfs_enumerate_catalog(xrootd_sd_instance_t *sd, int want_stat,
    xrootd_sd_catalog_cb cb, void *ctx);
/* Create the resolved ctx path as a directory with `mode`, creating missing
 * parent components when `parents`. Write-gated, confined; metered as OP_MKDIR.
 * NGX_ERROR with errno set (e.g. EEXIST when the target already exists). */
/* Change the resolved ctx path's permission bits. Write-gated; impersonation-
 * aware (performed by the broker as the mapped user when impersonation is on, so
 * the file's real owner can chmod even though the worker is not the owner). NGX_OK
 * / NGX_ERROR with errno set. */
ngx_int_t xrootd_vfs_chmod(xrootd_vfs_ctx_t *ctx, mode_t mode);

/* Apply kXR_setattr (timestamps and/or owner) to the resolved ctx path through
 * the VFS seam. Write-gated; routes to the backend's setattr slot for a non-POSIX
 * export (no-op success when the backend has no mutable metadata) and to the
 * impersonation-aware confined utimensat/fchownat path for the default POSIX
 * export. NGX_OK / NGX_ERROR with errno set. */
ngx_int_t xrootd_vfs_setattr(xrootd_vfs_ctx_t *ctx,
    const xrootd_sd_setattr_t *attr);

ngx_int_t xrootd_vfs_mkdir(xrootd_vfs_ctx_t *ctx, mode_t mode,
    unsigned parents);
/* ftruncate the open handle to `length` and update the cached fh->size so later
 * reads see the new length. Unmetered. NGX_ERROR with errno set on a bad handle,
 * negative length, or ftruncate failure. */
ngx_int_t xrootd_vfs_truncate(xrootd_vfs_file_t *fh, off_t length);
/* fsync the open handle to stable storage. Unmetered (the enclosing write op
 * records the metric). NGX_ERROR with errno set on a bad handle or fsync error. */
ngx_int_t xrootd_vfs_sync(xrootd_vfs_file_t *fh);

/* --- confined recursive walk (src/fs/vfs_walk.c) ---------------------------
 * A thread-safe, NON-allocating, NON-metered confined traversal for bulk/off-
 * thread consumers (checksum-scan, recursive copy/remove) that cannot use the
 * pool-allocating, metered handle API. The traversal (open/opendir/fstatat) runs
 * inside the VFS over the rootfd-relative confinement (openat2 RESOLVE_BENEATH),
 * so callers never touch a confined-helper directly; per regular file it invokes
 * a callback. Symlinks/specials are never followed or reported. */
typedef struct {
    ngx_uint_t max_depth;   /* recursion cap; 0 = the target directory only      */
    ngx_uint_t max_files;   /* cap on regular files visited; 0 = unlimited        */
    unsigned   open_files:1;/* open each regular file O_RDONLY and pass fd to cb  */
} xrootd_vfs_walk_opts_t;

typedef enum {
    XROOTD_VFS_WALK_NONE = 0,  /* target stat failed (not found)                 */
    XROOTD_VFS_WALK_FILE,      /* target is a regular file (cb fired once)       */
    XROOTD_VFS_WALK_DIR,       /* target is a directory (cb per regular child)   */
    XROOTD_VFS_WALK_OTHER      /* target is a symlink/special (cb not fired)     */
} xrootd_vfs_walk_target_t;

/* Per regular-file callback. `fd` is an open confined read-only fd when
 * opts->open_files (the walk closes it after the callback returns), else -1.
 * `logical` is the export-relative path. Return NGX_OK to continue the walk;
 * any other value aborts it and is returned to the caller. */
typedef ngx_int_t (*xrootd_vfs_walk_file_cb)(void *cookie, const char *logical,
    const xrootd_vfs_stat_t *st, int fd);

/* Walk the confined rootfd-relative `logical` target. A regular-file target
 * fires cb once; a directory target recurses (per-entry open/stat failures skip
 * that entry — bulk-scan semantics). *target_out (optional) reports the target
 * kind. Returns NGX_OK (walked; cb may have skipped entries), NGX_DECLINED
 * (target stat failed → not found), NGX_ERROR (a single-file-target open failure
 * or an opendir failure mid-walk; errmsg set), or the cb's non-OK abort code.
 * Thread-safe: no pool allocation, no metric. */
ngx_int_t xrootd_vfs_walk(ngx_log_t *log, int rootfd, const char *logical,
    const xrootd_vfs_walk_opts_t *opts, xrootd_vfs_walk_file_cb cb, void *cookie,
    xrootd_vfs_walk_target_t *target_out, char *errmsg, size_t errsz);

/* Per-entry metadata callback for xrootd_vfs_copyfile/copytree, invoked after
 * each file is copied and each directory is created, for protocol-specific extra
 * metadata (e.g. WebDAV dead properties). src/dst are the export-relative
 * logical paths; is_dir distinguishes a directory from a file. Return NGX_OK to
 * continue, anything else to abort the copy. */
typedef ngx_int_t (*xrootd_vfs_copy_meta_cb)(void *cookie, const char *src,
    const char *dst, int is_dir);

/* Copy a single confined regular file src→dst under root_canon (impersonation-
 * aware, thread-safe: no pool allocation, no metric — usable on a thread-pool
 * worker). Bytes move via copy_file_range with a read/write fallback; when
 * preserve_xattrs the user.* fattrs are copied; meta_cb (if non-NULL) then runs
 * for protocol extras. NGX_OK / NGX_ERROR with errno set. */
ngx_int_t xrootd_vfs_copyfile(ngx_log_t *log, const char *root_canon,
    const char *src, const char *dst, int preserve_xattrs,
    xrootd_vfs_copy_meta_cb meta_cb, void *cookie);

/* Recursively copy a confined directory tree src→dst under root_canon: each
 * subdirectory is mkdir'd on the dst side, each regular file copied via
 * xrootd_vfs_copyfile; symlinks/specials are skipped (never followed out of the
 * export). Impersonation-aware, thread-safe. meta_cb runs per copied file AND
 * per created directory. NGX_OK / NGX_ERROR with errno set. */
ngx_int_t xrootd_vfs_copytree(ngx_log_t *log, const char *root_canon,
    const char *src, const char *dst, int preserve_xattrs,
    xrootd_vfs_copy_meta_cb meta_cb, void *cookie);

/* --- thread-safe confined open/unlink primitives (src/fs/vfs_walk.c) -------
 * Raw-fd / path primitives (no pool allocation, no metric — safe off the event
 * loop) for bulk/off-thread consumers (multipart assembly) that cannot use the
 * pool-allocating, metered handle API but must still go through the VFS rather
 * than a confined helper directly. Impersonation-aware. */
/* Confined open beneath root_canon returning a RAW fd (caller closes it). Takes
 * raw O_* `flags` (incl. O_NOFOLLOW/O_DIRECTORY etc.; O_CLOEXEC auto-added);
 * `mode` applies with O_CREAT. Impersonation-aware. fd or -1 with errno set. */
int xrootd_vfs_open_fd(ngx_log_t *log, const char *root_canon,
    const char *logical, int flags, mode_t mode);
/* Confined open beneath a persistent O_PATH rootfd, returning a RAW fd (caller
 * closes it). Takes raw O_* `flags` (so callers needing O_DIRECTORY/O_NOCTTY/
 * O_CLOEXEC etc. that the XROOTD_VFS_O_* set does not model can pass them
 * through) — for the session handle-table / bind-reopen opens. Impersonation-
 * aware, thread-safe (no pool/metric). fd or -1 with errno set. */
int xrootd_vfs_open_fd_at(int rootfd, const char *logical, int flags,
    mode_t mode);
/* Confined remove beneath a persistent O_PATH rootfd: is_dir!=0 rmdir's, else
 * unlinks. Thread-safe (no pool/metric). 0 / -1 with errno set. */
int xrootd_vfs_unlink_at(int rootfd, const char *logical, int is_dir);
/* Confined unlink of a regular file. 0 / -1 with errno set. */
int xrootd_vfs_unlink_path(ngx_log_t *log, const char *root_canon,
    const char *logical);
/* Confined mkdir of a single directory (mode). 0 / -1 with errno set (EEXIST if
 * it already exists — caller decides whether that is benign). */
/* Recursively create `logical` (export-relative) + missing parents through a
 * NON-default backend driver's mkdir slot (EEXIST tolerated). NGX_DECLINED for a
 * default POSIX export (caller uses its own confined/group-policy mkpath); 0 on
 * success; -1/errno on failure. */
int xrootd_vfs_backend_mkpath(const char *root_canon, const char *logical,
    mode_t mode, ngx_log_t *log);
int xrootd_vfs_mkdir_path(ngx_log_t *log, const char *root_canon,
    const char *logical, mode_t mode);

/* --- raw fd full read/write primitives (src/fs/vfs_read.c) -----------------
 * EINTR-safe, short-I/O-tolerant transfers that route the byte syscall through
 * the storage-driver seam (a stack POSIX object — no allocation, so these are
 * safe to call off the event-loop thread). Use these instead of a raw
 * pread/pwrite loop or a direct xrootd_sd_posix_driver.<op> in module code. */
/* pread up to len bytes at offset into buf, looping until len is filled or EOF.
 * *nread (optional) always receives the byte count, even on error. NGX_OK on a
 * full read or clean EOF; NGX_ERROR (errno set) on a real pread error. */
ngx_int_t xrootd_vfs_pread_full(ngx_fd_t fd, u_char *buf, size_t len,
    off_t offset, size_t *nread);
/* pwrite exactly len bytes at offset from buf. NGX_OK only when all len bytes
 * are written; NGX_ERROR otherwise with errno set (a 0-byte pwrite is EIO). */
ngx_int_t xrootd_vfs_pwrite_full(ngx_fd_t fd, const u_char *buf, size_t len,
    off_t offset);

/* --- extended attributes (src/fs/vfs_xattr.c) ------------------------------
 * Confined `user.`-namespace xattr ops on ctx->resolved, each metered as
 * OP_XATTR. get/list return the byte count (bufsz==0 asks the required size;
 * -1/ERANGE when a value does not fit); set/remove return NGX_OK / NGX_ERROR
 * with errno set. set/remove are intentionally NOT allow_write-gated — the lock
 * database writes on otherwise read-only requests and the protocol layer has
 * already authorized — matching the prior direct confined-helper behaviour. */
ssize_t xrootd_vfs_getxattr(xrootd_vfs_ctx_t *ctx, const char *name,
    void *buf, size_t bufsz);
ssize_t xrootd_vfs_listxattr(xrootd_vfs_ctx_t *ctx, void *buf, size_t bufsz);
ngx_int_t xrootd_vfs_setxattr(xrootd_vfs_ctx_t *ctx, const char *name,
    const void *value, size_t len, int flags);
ngx_int_t xrootd_vfs_removexattr(xrootd_vfs_ctx_t *ctx, const char *name);

/* Open-handle (fd) xattr variants: operate on an fd the VFS already opened
 * confined (so confinement travels with the descriptor — no path to re-resolve).
 * `ctx` is optional, used only to attribute the OP_XATTR metric/access-log line
 * (may be NULL → unobserved). get/list return the byte count (bufsz==0 asks the
 * required size; -1/ERANGE when a value does not fit); set/remove return
 * NGX_OK / NGX_ERROR with errno set. */
ssize_t xrootd_vfs_fgetxattr(const xrootd_vfs_ctx_t *ctx, int fd,
    const char *name, void *buf, size_t bufsz);
ssize_t xrootd_vfs_flistxattr(const xrootd_vfs_ctx_t *ctx, int fd, void *buf,
    size_t bufsz);
ngx_int_t xrootd_vfs_fsetxattr(const xrootd_vfs_ctx_t *ctx, int fd,
    const char *name, const void *value, size_t len, int flags);
ngx_int_t xrootd_vfs_fremovexattr(const xrootd_vfs_ctx_t *ctx, int fd,
    const char *name);

/* --- single-file copy (src/fs/vfs_copy.c) ---------------------------------
 * Copy the resolved ctx (source) regular file to dst_resolved within the same
 * export root via copy_file_range (read/write fallback). Write-gated; metered
 * as OP_COPY. NGX_ERROR with errno set (EEXIST when dst exists and !overwrite,
 * EXDEV on a confinement escape). */
ngx_int_t xrootd_vfs_copy(xrootd_vfs_ctx_t *ctx, const char *dst_resolved,
    const xrootd_vfs_copy_opts_t *opts);

/* --- atomic staged write (src/fs/vfs_staged.c) ----------------------------
 * Crash-safe upload lifecycle: open a unique O_EXCL temp inside the export root
 * (final path = resolved ctx), write its fd, then commit (atomic publish onto
 * the final path) or abort (close + unlink). Write-gated at open. */
xrootd_vfs_staged_t *xrootd_vfs_staged_open(xrootd_vfs_ctx_t *ctx, mode_t mode,
    ngx_uint_t attempts, int *err_out);
/* The staged temp fd to write to, or NGX_INVALID_FILE for a NULL handle OR a
 * driver-backed staged object (which has no kernel fd — write it via
 * xrootd_vfs_staged_write). */
ngx_fd_t xrootd_vfs_staged_fd(const xrootd_vfs_staged_t *st);
/* 1 iff this staged handle is delegated to a non-POSIX storage driver (no fd; the
 * body must be written through xrootd_vfs_staged_write rather than the fd). */
ngx_uint_t xrootd_vfs_staged_is_driver(const xrootd_vfs_staged_t *st);
/* Write `len` bytes at offset `off` into the staged object — the backend-neutral
 * write primitive: a POSIX staged temp gets a pwrite to its fd; a driver-backed
 * staged object gets driver->staged_write. NGX_OK / NGX_ERROR with errno set. */
ngx_int_t xrootd_vfs_staged_write(xrootd_vfs_staged_t *st, const void *buf,
    size_t len, off_t off);
/* The staged temp path (borrowed; "" when st is NULL). */
const char *xrootd_vfs_staged_tmp_path(const xrootd_vfs_staged_t *st);
/* Atomically publish the temp onto the final path; `excl` uses RENAME_NOREPLACE
 * (errno==EEXIST if the final exists). Metered as OP_WRITE (committed size).
 * NGX_OK / NGX_ERROR with errno set. */
ngx_int_t xrootd_vfs_staged_commit(xrootd_vfs_staged_t *st, unsigned excl);
/* Close and (when remove_tmp) unlink the temp. Idempotent; NULL-safe. */
void xrootd_vfs_staged_abort(xrootd_vfs_staged_t *st, unsigned remove_tmp);

#endif /* XROOTD_VFS_H */
