#ifndef XROOTD_NAMESPACE_OPS_H
#define XROOTD_NAMESPACE_OPS_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * xrootd_ns_status_t — neutral status codes for filesystem mutations.
 * The enum now lives in ns_status.h (ngx-free) so error_mapping's Sections 1-2
 * can be compiled into the standalone libxrdproto core. namespace_ops keeps the
 * full ngx-coupled API below; the enum is single-sourced via this include.
 */
#include "ns_status.h"

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
 * mutations (delete, mkdir, rename) MUST route through the VFS layer
 * (src/fs/vfs.h: xrootd_vfs_unlink/rmdir/mkdir/rename/copy and the staged-write
 * family), which calls these functions underneath while adding the metrics +
 * access-log layer. These xrootd_ns_*() entry points remain the seam the VFS
 * delegates to; calling them directly from an EVENT-LOOP handler path is now a
 * second choice (it loses the OP metric/log) and direct xrootd_*_confined*()
 * calls from such paths are a defect.
 *
 * EXEMPT — namespace MUTATION running on a THREAD-POOL worker (off the event
 * loop): native TPC pull, async/multipart S3 PUT assembly, the collection
 * copy/move engines. The metered VFS namespace entry points allocate from an
 * nginx pool and emit metrics/log lines, none of which are thread-safe, so
 * worker-thread namespace mutation stays on this xrootd_ns_*() / confined-helper
 * / staged_file tier. Confinement is identical (RESOLVE_BENEATH); only the VFS
 * metering is skipped.
 *
 * NOTE (phase-54): this exemption is for namespace MUTATION only. Raw byte I/O
 * (read/write/readv/writev/pgread + the dirlist scan) is no longer exempt —
 * worker threads now run it through the VFS-owned thread-safe core
 * xrootd_vfs_io_execute() (src/fs/vfs_io_core.c), so that path is unified across
 * all dispatch tiers. See src/fs/README.md "Two VFS tiers".
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
