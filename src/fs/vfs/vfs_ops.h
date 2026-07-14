#ifndef BRIX_VFS_OPS_H
#define BRIX_VFS_OPS_H

/*
 * vfs_ops.h — confined walk / thread-safe open-unlink / raw fd read-write /
 * xattr / single-file-copy / atomic-staged-write VFS declarations, split
 * (phase-79 file-size burndown) out of the oversized vfs.h with zero behaviour
 * change. Included at the END of vfs.h and DEPENDS on the types it defines
 * (brix_vfs_ctx_t / brix_vfs_stat_t / brix_vfs_staged_t / brix_vfs_copy_opts_t
 * and the nginx includes). Do not include directly — include "fs/vfs.h".
 */

/* --- confined recursive walk (src/fs/vfs/vfs_walk.c) ---------------------------
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
} brix_vfs_walk_opts_t;

typedef enum {
    BRIX_VFS_WALK_NONE = 0,  /* target stat failed (not found)                 */
    BRIX_VFS_WALK_FILE,      /* target is a regular file (cb fired once)       */
    BRIX_VFS_WALK_DIR,       /* target is a directory (cb per regular child)   */
    BRIX_VFS_WALK_OTHER      /* target is a symlink/special (cb not fired)     */
} brix_vfs_walk_target_t;

/* Per regular-file callback. `fd` is an open confined read-only fd when
 * opts->open_files (the walk closes it after the callback returns), else -1.
 * `logical` is the export-relative path. Return NGX_OK to continue the walk;
 * any other value aborts it and is returned to the caller. */
typedef ngx_int_t (*brix_vfs_walk_file_cb)(void *cookie, const char *logical,
    const brix_vfs_stat_t *st, int fd);

/* Walk the confined rootfd-relative `logical` target. A regular-file target
 * fires cb once; a directory target recurses (per-entry open/stat failures skip
 * that entry — bulk-scan semantics). *target_out (optional) reports the target
 * kind. Returns NGX_OK (walked; cb may have skipped entries), NGX_DECLINED
 * (target stat failed → not found), NGX_ERROR (a single-file-target open failure
 * or an opendir failure mid-walk; errmsg set), or the cb's non-OK abort code.
 * Thread-safe: no pool allocation, no metric. */
ngx_int_t brix_vfs_walk(ngx_log_t *log, int rootfd, const char *logical,
    const brix_vfs_walk_opts_t *opts, brix_vfs_walk_file_cb cb, void *cookie,
    brix_vfs_walk_target_t *target_out, char *errmsg, size_t errsz);

/* Per-entry metadata callback for brix_vfs_copyfile/copytree, invoked after
 * each file is copied and each directory is created, for protocol-specific extra
 * metadata (e.g. WebDAV dead properties). src/dst are the export-relative
 * logical paths; is_dir distinguishes a directory from a file. Return NGX_OK to
 * continue, anything else to abort the copy. */
typedef ngx_int_t (*brix_vfs_copy_meta_cb)(void *cookie, const char *src,
    const char *dst, int is_dir);

/* Copy a single confined regular file src→dst under root_canon (impersonation-
 * aware, thread-safe: no pool allocation, no metric — usable on a thread-pool
 * worker). Bytes move via copy_file_range with a read/write fallback; when
 * preserve_xattrs the user.* fattrs are copied; meta_cb (if non-NULL) then runs
 * for protocol extras. NGX_OK / NGX_ERROR with errno set. */
ngx_int_t brix_vfs_copyfile(ngx_log_t *log, const char *root_canon,
    const char *src, const char *dst, int preserve_xattrs,
    brix_vfs_copy_meta_cb meta_cb, void *cookie);

/* Recursively copy a confined directory tree src→dst under root_canon: each
 * subdirectory is mkdir'd on the dst side, each regular file copied via
 * brix_vfs_copyfile; symlinks/specials are skipped (never followed out of the
 * export). Impersonation-aware, thread-safe. meta_cb runs per copied file AND
 * per created directory. NGX_OK / NGX_ERROR with errno set. */
ngx_int_t brix_vfs_copytree(ngx_log_t *log, const char *root_canon,
    const char *src, const char *dst, int preserve_xattrs,
    brix_vfs_copy_meta_cb meta_cb, void *cookie);

/* --- thread-safe confined open/unlink primitives (src/fs/vfs/vfs_walk.c) -------
 * Raw-fd / path primitives (no pool allocation, no metric — safe off the event
 * loop) for bulk/off-thread consumers (multipart assembly) that cannot use the
 * pool-allocating, metered handle API but must still go through the VFS rather
 * than a confined helper directly. Impersonation-aware. */
/* Confined open beneath root_canon returning a RAW fd (caller closes it). Takes
 * raw O_* `flags` (incl. O_NOFOLLOW/O_DIRECTORY etc.; O_CLOEXEC auto-added);
 * `mode` applies with O_CREAT. Impersonation-aware. fd or -1 with errno set. */
int brix_vfs_open_fd(ngx_log_t *log, const char *root_canon,
    const char *logical, int flags, mode_t mode);
/* Confined open beneath a persistent O_PATH rootfd, returning a RAW fd (caller
 * closes it). Takes raw O_* `flags` (so callers needing O_DIRECTORY/O_NOCTTY/
 * O_CLOEXEC etc. that the BRIX_VFS_O_* set does not model can pass them
 * through) — for the session handle-table / bind-reopen opens. Impersonation-
 * aware, thread-safe (no pool/metric). fd or -1 with errno set. */
int brix_vfs_open_fd_at(int rootfd, const char *logical, int flags,
    mode_t mode);
/* Confined remove beneath a persistent O_PATH rootfd: is_dir!=0 rmdir's, else
 * unlinks. Thread-safe (no pool/metric). 0 / -1 with errno set. */
int brix_vfs_unlink_at(int rootfd, const char *logical, int is_dir);
/* Confined unlink of a regular file. 0 / -1 with errno set. */
int brix_vfs_unlink_path(ngx_log_t *log, const char *root_canon,
    const char *logical);
/* Confined mkdir of a single directory (mode). 0 / -1 with errno set (EEXIST if
 * it already exists — caller decides whether that is benign). */
/* Recursively create `logical` (export-relative) + missing parents through a
 * NON-default backend driver's mkdir slot (EEXIST tolerated). NGX_DECLINED for a
 * default POSIX export (caller uses its own confined/group-policy mkpath); 0 on
 * success; -1/errno on failure. */
int brix_vfs_backend_mkpath(const char *root_canon, const char *logical,
    mode_t mode, ngx_log_t *log);
int brix_vfs_mkdir_path(ngx_log_t *log, const char *root_canon,
    const char *logical, mode_t mode);

/* --- raw fd full read/write primitives (src/fs/vfs/vfs_read.c) -----------------
 * EINTR-safe, short-I/O-tolerant transfers that route the byte syscall through
 * the storage-driver seam (a stack POSIX object — no allocation, so these are
 * safe to call off the event-loop thread). Use these instead of a raw
 * pread/pwrite loop or a direct brix_sd_posix_driver.<op> in module code. */
/* pread up to len bytes at offset into buf, looping until len is filled or EOF.
 * *nread (optional) always receives the byte count, even on error. NGX_OK on a
 * full read or clean EOF; NGX_ERROR (errno set) on a real pread error. */
ngx_int_t brix_vfs_pread_full(ngx_fd_t fd, u_char *buf, size_t len,
    off_t offset, size_t *nread);
/* pwrite exactly len bytes at offset from buf. NGX_OK only when all len bytes
 * are written; NGX_ERROR otherwise with errno set (a 0-byte pwrite is EIO). */
ngx_int_t brix_vfs_pwrite_full(ngx_fd_t fd, const u_char *buf, size_t len,
    off_t offset);

/* --- extended attributes (src/fs/vfs/vfs_xattr.c) ------------------------------
 * Confined `user.`-namespace xattr ops on ctx->resolved, each metered as
 * OP_XATTR. get/list return the byte count (bufsz==0 asks the required size;
 * -1/ERANGE when a value does not fit); set/remove return NGX_OK / NGX_ERROR
 * with errno set. set/remove are intentionally NOT allow_write-gated — the lock
 * database writes on otherwise read-only requests and the protocol layer has
 * already authorized — matching the prior direct confined-helper behaviour. */
ssize_t brix_vfs_getxattr(brix_vfs_ctx_t *ctx, const char *name,
    void *buf, size_t bufsz);
ssize_t brix_vfs_listxattr(brix_vfs_ctx_t *ctx, void *buf, size_t bufsz);
ngx_int_t brix_vfs_setxattr(brix_vfs_ctx_t *ctx, const char *name,
    const void *value, size_t len, int flags);
ngx_int_t brix_vfs_removexattr(brix_vfs_ctx_t *ctx, const char *name);

/* Open-handle (fd) xattr variants: operate on an fd the VFS already opened
 * confined (so confinement travels with the descriptor — no path to re-resolve).
 * `ctx` is optional, used only to attribute the OP_XATTR metric/access-log line
 * (may be NULL → unobserved). get/list return the byte count (bufsz==0 asks the
 * required size; -1/ERANGE when a value does not fit); set/remove return
 * NGX_OK / NGX_ERROR with errno set. */
ssize_t brix_vfs_fgetxattr(const brix_vfs_ctx_t *ctx, int fd,
    const char *name, void *buf, size_t bufsz);
ssize_t brix_vfs_flistxattr(const brix_vfs_ctx_t *ctx, int fd, void *buf,
    size_t bufsz);
ngx_int_t brix_vfs_fsetxattr(const brix_vfs_ctx_t *ctx, int fd,
    const char *name, const void *value, size_t len, int flags);
ngx_int_t brix_vfs_fremovexattr(const brix_vfs_ctx_t *ctx, int fd,
    const char *name);

/* --- single-file copy (src/fs/vfs/vfs_copy.c) ---------------------------------
 * Copy the resolved ctx (source) regular file to dst_resolved within the same
 * export root via copy_file_range (read/write fallback). Write-gated; metered
 * as OP_COPY. NGX_ERROR with errno set (EEXIST when dst exists and !overwrite,
 * EXDEV on a confinement escape). */
ngx_int_t brix_vfs_copy(brix_vfs_ctx_t *ctx, const char *dst_resolved,
    const brix_vfs_copy_opts_t *opts);

/* --- atomic staged write (src/fs/vfs/vfs_staged.c) ----------------------------
 * Crash-safe upload lifecycle: open a unique O_EXCL temp inside the export root
 * (final path = resolved ctx), write its fd, then commit (atomic publish onto
 * the final path) or abort (close + unlink). Write-gated at open. */
brix_vfs_staged_t *brix_vfs_staged_open(brix_vfs_ctx_t *ctx, mode_t mode,
    ngx_uint_t attempts, int *err_out);
/* The staged temp fd to write to, or NGX_INVALID_FILE for a NULL handle OR a
 * driver-backed staged object (which has no kernel fd — write it via
 * brix_vfs_staged_write). */
ngx_fd_t brix_vfs_staged_fd(const brix_vfs_staged_t *st);
/* 1 iff this staged handle is delegated to a non-POSIX storage driver (no fd; the
 * body must be written through brix_vfs_staged_write rather than the fd). */
ngx_uint_t brix_vfs_staged_is_driver(const brix_vfs_staged_t *st);
/* Write `len` bytes at offset `off` into the staged object — the backend-neutral
 * write primitive: a POSIX staged temp gets a pwrite to its fd; a driver-backed
 * staged object gets driver->staged_write. NGX_OK / NGX_ERROR with errno set. */
ngx_int_t brix_vfs_staged_write(brix_vfs_staged_t *st, const void *buf,
    size_t len, off_t off);
/* The staged temp path (borrowed; "" when st is NULL). */
const char *brix_vfs_staged_tmp_path(const brix_vfs_staged_t *st);
/* Atomically publish the temp onto the final path; `excl` uses RENAME_NOREPLACE
 * (errno==EEXIST if the final exists). Metered as OP_WRITE (committed size).
 * NGX_OK / NGX_ERROR with errno set. */
ngx_int_t brix_vfs_staged_commit(brix_vfs_staged_t *st, unsigned excl);
/* Close and (when remove_tmp) unlink the temp. Idempotent; NULL-safe. */
void brix_vfs_staged_abort(brix_vfs_staged_t *st, unsigned remove_tmp);

#endif /* BRIX_VFS_OPS_H */
