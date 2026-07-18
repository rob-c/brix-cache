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

/* --- unified verified write session (src/fs/vfs/vfs_writer.c) ------------------
 * ONE write entry point for every backend: a protocol write path (GridFTP STOR,
 * and any future caller) opens a session, feeds extents, and commits — the
 * session picks the mechanics from the backend's capabilities and, when asked,
 * folds a self-computed CRC that is verified against a read-back on commit.
 *
 *   random-write backend (POSIX default export, pblock): an in-place
 *     O_WRITE|O_CREATE handle written with brix_vfs_file_pwrite at arbitrary
 *     offsets — REST/APPE and out-of-order (MODE E) extents are supported.
 *   staged-only backend (S3/object store, no CAP_RANDOM_WRITE): an atomic
 *     staged upload (temp → commit); extents MUST arrive sequentially from
 *     offset 0 (an object store cannot patch bytes in place), so a non-sequential
 *     write is refused.
 *
 * `verify` asserts the caller is writing a whole object from offset 0 (a fresh
 * STOR, not a REST/APPE partial); when set, every extent is CRC-32'd and, on
 * commit, the persisted object is re-read through its driver and compared. A
 * mismatch/short object unlinks the file and fails the commit. An empty object
 * (nothing written) is a complete [0,0) write and verifies trivially. */
#ifndef BRIX_VFS_WRITER_T_DECLARED
#define BRIX_VFS_WRITER_T_DECLARED
typedef struct brix_vfs_writer_s brix_vfs_writer_t;
#endif

/* Open a write session on the resolved `ctx`. The writer self-contains a deep
 * copy of `ctx` (and the resolved-path / root_canon buffers it points at), so the
 * caller's ctx may be a per-request stack frame that dies before commit.
 * `flags` honours BRIX_VFS_O_TRUNC on the random-write path (the staged path is
 * always a fresh object) and BRIX_VFS_O_ATOMIC (force the staged temp+publish path
 * even for a random-write backend, so a failed write never leaves a partial at the
 * final path — the WebDAV/S3 PUT contract). Returns NULL with *err_out (errno) set
 * on failure. */
brix_vfs_writer_t *brix_vfs_writer_open(brix_vfs_ctx_t *ctx, unsigned flags,
    int verify, int *err_out);
/* Write `len` bytes from `buf` at object offset `off`. NGX_OK / NGX_ERROR (errno
 * set; EINVAL on a non-sequential extent to a staged-only backend). */
ngx_int_t brix_vfs_writer_write(brix_vfs_writer_t *w, const void *buf,
    size_t len, off_t off);
/* Ingest `len` bytes from an already-open source fd (`src_fd` at `src_off`) onto
 * the object at `dst_off` — the fd-to-fd twin of brix_vfs_writer_write, for a
 * caller that has the body spooled to a temp fd (WebDAV/S3 PUT) rather than in a
 * memory buffer. A single-fd, sendfile-capable random backend with verify OFF is
 * moved kernel-side (copy_file_range, zero-copy); a verifying, staged/object, or
 * block backend is read into a bounce buffer and pushed through the normal write
 * engine so the CRC accumulator sees every byte and block/staged routing holds.
 * NGX_OK / NGX_ERROR (errno set). */
ngx_int_t brix_vfs_writer_write_fd(brix_vfs_writer_t *w, int src_fd,
    off_t src_off, size_t len, off_t dst_off);
/* Next offset the session expects: the sequential append cursor on the staged/
 * object path (a write at any other offset is refused EINVAL), or the high-water
 * byte count on the random path. -1 when w is NULL. Lets a caller distinguish an
 * out-of-order write (its own error mapping) from a backend I/O failure. */
off_t brix_vfs_writer_expected_off(const brix_vfs_writer_t *w);
/* Finalize: fsync/close (random) or atomically publish (staged), then — when the
 * session was opened with verify — re-read and CRC-compare the object, unlinking
 * it on mismatch. NGX_OK on success, NGX_ERROR otherwise. Consumes the session:
 * after commit the only valid follow-up is brix_vfs_writer_abort (a NULL-safe
 * no-op once finished). */
ngx_int_t brix_vfs_writer_commit(brix_vfs_writer_t *w);
/* Like brix_vfs_writer_commit, but `excl` publishes with RENAME_NOREPLACE on the
 * staged path (S3 If-None-Match exclusive create): NGX_ERROR with errno==EEXIST if
 * the final object already exists. `excl` is a no-op on the in-place random path. */
ngx_int_t brix_vfs_writer_commit_ex(brix_vfs_writer_t *w, unsigned excl);
/* Discard an un-committed session: close + remove any staged temp / created
 * object. Idempotent and NULL-safe. */
void brix_vfs_writer_abort(brix_vfs_writer_t *w);
/* The writable kernel fd behind the session — the in-place handle fd (random path)
 * or the staged temp fd (staged path). NGX_INVALID_FILE for a NULL writer or a
 * driver-backed object with no kernel fd. Callers that must write bytes outside
 * brix_vfs_writer_write (Content-Encoding decode, aws-chunked de-framing) use this;
 * an NGX_INVALID_FILE result means "no fd — that path is unsupported here". */
ngx_fd_t brix_vfs_writer_fd(const brix_vfs_writer_t *w);
/* The underlying staged handle on the staged path (NULL on the in-place random
 * path or a NULL writer) — lets legacy staged-consuming code (commit ledgers,
 * streaming de-chunkers) borrow the session's temp while the writer owns its
 * lifecycle. Do NOT commit/abort it directly; drive the session via the writer. */
brix_vfs_staged_t *brix_vfs_writer_staged(const brix_vfs_writer_t *w);

#endif /* BRIX_VFS_OPS_H */
