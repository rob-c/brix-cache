#ifndef XROOTD_NAMESPACE_OPS_H
#define XROOTD_NAMESPACE_OPS_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * xrootd_ns_status_t — neutral status codes for filesystem mutations.
 */
typedef enum {
    XROOTD_NS_OK = 0,
    XROOTD_NS_NOT_FOUND,
    XROOTD_NS_DENIED,
    XROOTD_NS_EXISTS,
    XROOTD_NS_CONFLICT,
    XROOTD_NS_NOT_EMPTY,
    XROOTD_NS_TOO_LONG,
    XROOTD_NS_NO_SPACE,
    XROOTD_NS_IO_ERROR
} xrootd_ns_status_t;

/*
 * xrootd_ns_result_t — result of a namespace mutation.
 */
typedef struct {
    xrootd_ns_status_t status;
    int                sys_errno;
    ngx_flag_t         existed;
    ngx_flag_t         created;
    ngx_flag_t         was_dir;
} xrootd_ns_result_t;

/*
 * xrootd_ns_delete_opts_t — options for xrootd_ns_delete().
 */
typedef struct {
    ngx_flag_t recursive;
    ngx_flag_t idempotent_missing;
    ngx_flag_t require_empty_dir;
    ngx_flag_t require_directory;  /* fail with ENOTDIR if target is not a dir
                                    * (kXR_rmdir semantics: directories only) */
} xrootd_ns_delete_opts_t;

/*
 * xrootd_ns_copy_opts_t — options for xrootd_ns_local_copy().
 */
typedef struct {
    ngx_flag_t recursive;
    ngx_flag_t overwrite;
    ngx_flag_t overwrite_dirs;
    ngx_flag_t preserve_xattrs;
    ngx_flag_t staged_commit;
} xrootd_ns_copy_opts_t;

/*
 * Shared namespace mutation APIs.
 *
 * These operate on already-resolved, confined paths. They do not perform
 * wire path parsing or token/ACL checks; protocol handlers do those first.
 *
 * INVARIANT: All protocol handlers implementing user-visible namespace
 * mutations (delete, mkdir, rename) MUST route through these functions.
 * Direct calls to xrootd_*_confined*() from protocol handler files
 * (src/write/, src/s3/, src/webdav/ dispatch paths) are a defect.
 * Internal staging code (TPC, multipart, copy engine, checksum) is exempt.
 */

/*
 * xrootd_ns_delete — remove a file or directory, kernel-confined under root_canon.
 *   path is the absolute path (borrowed, not freed); it is stripped to a
 *   within-root tail and all touches go through the openat2 RESOLVE_BENEATH API,
 *   so a path that escapes root_canon is refused (status DENIED, errno EXDEV)
 *   rather than acted on. opts selects: recursive tree removal, idempotent_missing
 *   (ENOENT becomes OK with .existed=0), require_empty_dir (non-empty dir =>
 *   NOT_EMPTY), require_directory (rmdir semantics: a regular file => DENIED,
 *   errno ENOTDIR). Returns a by-value result: .status is the neutral code,
 *   .sys_errno the raw errno on failure, and .existed/.was_dir describe the target
 *   pre-delete. Opens and closes its own transient rootfd; no allocation.
 */
xrootd_ns_result_t xrootd_ns_delete(ngx_log_t *log,
    const char *root_canon, const char *path,
    const xrootd_ns_delete_opts_t *opts);

/*
 * xrootd_ns_mkdir — create directory path beneath root_canon (RESOLVE_BENEATH).
 *   mode is the raw mkdir(2) mode (subject to the process umask). recursive => mkdir -p
 *   (creates each missing parent component). path borrowed, not freed. Returns a
 *   by-value result: .status OK with .created=1 on success; an existing target
 *   yields status EXISTS (errno EEXIST); a path outside root_canon yields DENIED.
 *   Opens/closes its own rootfd; no heap allocation.
 */
xrootd_ns_result_t xrootd_ns_mkdir(ngx_log_t *log,
    const char *root_canon, const char *path, mode_t mode,
    ngx_flag_t recursive);

/*
 * xrootd_ns_rename — atomically move src to dst; BOTH must be under the SAME
 *   root_canon (cross-root rename is refused with status DENIED, errno EXDEV).
 *   src and dst are borrowed absolute paths. If dst already exists and is a
 *   directory: overwrite_dirs=1 first recursively removes the dst tree (rename(2)
 *   only replaces empty dirs), overwrite_dirs=0 returns status EXISTS. An
 *   existing non-directory dst is replaced atomically by renameat. Returns a
 *   by-value result; .existed/.was_dir describe a pre-existing dst. Confinement
 *   is enforced inside the kernel rename, closing the realpath-to-rename TOCTOU.
 */
xrootd_ns_result_t xrootd_ns_rename(ngx_log_t *log,
    const char *root_canon, const char *src, const char *dst,
    ngx_flag_t overwrite_dirs);

/*
 * xrootd_ns_local_copy — copy a single regular file src to dst within root_canon
 *   via copy_file_range(2) (falls back to read/write inside xrootd_copy_range).
 *   src/dst borrowed; both must be under root_canon (else DENIED/EXDEV).
 *   Directory sources are rejected (status CONFLICT — recursive copy not handled
 *   here). dst handling: !overwrite + existing dst => EXISTS; existing dst dir
 *   without overwrite_dirs => EXISTS. opts->staged_commit writes a temp file and
 *   atomically renames it into place on success (aborted/unlinked on failure);
 *   opts->preserve_xattrs copies XRootD fattr xattrs after the data copy.
 *   Returns a by-value result: OK with .created=1 on success. Opens/closes the
 *   src/dst fds and rootfd itself.
 */
xrootd_ns_result_t xrootd_ns_local_copy(ngx_log_t *log,
    const char *root_canon, const char *src, const char *dst,
    const xrootd_ns_copy_opts_t *opts);

/*
 * xrootd_ns_copy_fattrs — copy only XRootD fattr-namespaced xattrs from src to dst.
 *   Thin wrapper over xrootd_xattr_copy_by_prefix with the XROOTD_FATTR_XKEY_PFX
 *   prefix and XROOTD_FATTR_MAX_VBUF value buffer. src/dst are borrowed paths
 *   (NOT confined here — caller must have already proven them resident under the
 *   root). Best-effort: failures are silently ignored.
 */
void xrootd_ns_copy_fattrs(ngx_log_t *log, const char *src, const char *dst);

/*
 * xrootd_xattr_copy_by_prefix — copy every xattr on src whose name begins with
 *   prefix (length prefix_len) onto dst. src/dst are borrowed paths passed
 *   straight to listxattr/getxattr/setxattr — NOT confined here, so the caller
 *   must already have proven both reside under the root. value_max is the
 *   per-attribute read buffer; any attribute value larger than it is silently
 *   skipped/truncated by getxattr. Best-effort and void: alloc failures, an
 *   empty/absent xattr list, and per-attribute getxattr/setxattr errors are all
 *   ignored with no signal to the caller. Allocates and frees its own scratch
 *   buffers (ngx_alloc/ngx_free); transfers no ownership.
 */
void xrootd_xattr_copy_by_prefix(ngx_log_t *log,
    const char *src, const char *dst,
    const char *prefix, size_t prefix_len,
    size_t value_max);

#endif /* XROOTD_NAMESPACE_OPS_H */
