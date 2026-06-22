#include "../ngx_xrootd_module.h"
#include "path_internal.h"
#include "../impersonate/impersonate.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <linux/openat2.h>

/* Helper declarations — defined in resolve_confined_helpers.c */
extern int xrootd_open_root_fd(ngx_log_t *log, const char *root_canon);
extern char *xrootd_split_relative_parent(const char *rel, char *parent, size_t parentsz,
    char *base, size_t basesz);
extern int xrootd_open_confined_parent_fallback(int rootfd, const char *parent);
extern int xrootd_open_confined_parent_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, char *base, size_t basesz);

/* ---- Main confined file open function — defence-in-depth root confinement ----
 *
 * WHAT: Opens a file while enforcing ROOT CONFINEMENT at multiple layers (defence-in-depth).
 *       resolved must already be canonical absolute path produced by xrootd_resolve_path* functions. */

/* ---- Defence-in-depth confinement mechanism ----
 *
 * WHY: Two-layer security — first layer is CANONICAL PATH RESOLUTION (no symlinks, no "..") via caller's resolve function;
 *      second layer is KERNEL-LEVEL CONFINEMENT via openat2 RESOLVE_BENEATH or fallback O_NOFOLLOW.
 *      Even if a symlink was introduced between resolve and open, kernel-level prevention blocks escape. */

/* ---- Confinement layers (defence-in-depth) ----
 *
 * HOW: Layer 1 = xrootd_resolve_path* functions produce canonical path (no symlinks, no "..");
 *      Layer 2 = kernel RESOLVE_BENEATH (openat2 Linux 5.6+) or user-space O_NOFOLLOW fallback;
 *      Both layers must pass for file access to succeed. */

/* ---- Open confined function preconditions ----
 *
 * WHY: root_canon must be produced by xrootd_get_canonical_root() and resolved must already be within root_canon (caller verified). */

/* ---- File descriptor ownership model ----
 *
 * WHY: The returned fd is NOT pool-managed — caller MUST close it explicitly. This prevents resource leaks in confined operations. */

/* ---- Argument order reminder (flags vs mode) ----
 *
 * HOW: xrootd_open_confined_canon(..., flags, mode). flags = O_RDONLY/O_WRONLY/O_RDWR/O_CREAT/O_TRUNC etc.; 
 *      mode = 0644 permission bits (used only when O_CREAT is set). CRITICAL: Do NOT pass permission bits in flags position —
 *      0644 has the O_EXCL bit (0200) and would cause unexpected exclusive-create semantics. */

ngx_int_t
xrootd_dirlist_access_ok(ngx_log_t *log, const char *root_canon,
    const char *resolved)
{
    char rel[PATH_MAX];
    int  fd;

    if (!xrootd_imp_enabled()) {
        return NGX_OK;                   /* impersonation off — existing gate holds */
    }
    if (!xrootd_imp_client_active()) {
        /*
         * Map mode is active but this request carries no per-request principal
         * (e.g. the principal was cleared by an async body read and not yet
         * re-established, or an anonymous request reached here).  We cannot
         * determine the mapped user's DAC, so FAIL CLOSED — refuse to enumerate
         * the directory rather than list it with the privileged worker's
         * credentials (which leaked entries of dirs the mapped user cannot read).
         */
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "impersonate: dirlist access check with no principal set"
                      " — refusing to enumerate \"%s\" (fail closed)", resolved);
        return NGX_ERROR;
    }
    if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                          rel, sizeof(rel)))
    {
        return NGX_ERROR;
    }
    /* Ask the broker to open the dir for READING as the mapped user.  readdir
     * needs read permission on the directory, so a successful O_RDONLY|O_DIRECTORY
     * open means the user is entitled to list it; EACCES means they are not. */
    fd = xrootd_imp_open(rel, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        return NGX_ERROR;
    }
    close(fd);
    return NGX_OK;
}

int
xrootd_open_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int flags, mode_t mode)
{
    char rel[PATH_MAX];
    char parent[PATH_MAX];
    char base[NAME_MAX + 1];
    int  rootfd;
    int  parentfd;
    int  fd;

    if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                          rel, sizeof(rel)))
    {
        return -1;
    }

    /*
     * Phase 40: when per-request impersonation is active (map mode + a principal
     * set for this request), delegate the open to the privileged broker, which
     * performs it as the mapped UNIX user under its own rootfd.  `rel` is already
     * the export-root-relative path the broker expects.  This is the HTTP/S3
     * (legacy confined-open) counterpart to the seam in beneath.c; off-path it is
     * an inert flag check.
     */
    if (xrootd_imp_client_active()) {
        return xrootd_imp_open(rel, flags, mode);
    }

    rootfd = xrootd_open_root_fd(log, root_canon);
    if (rootfd < 0) {
        return -1;
    }

#if (XROOTD_HAVE_OPENAT2)
    fd = xrootd_openat2_confined(rootfd, rel, flags, mode);
    if (fd >= 0
        || (errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP))
    {
        close(rootfd);
        return fd;
    }
#endif

    /*
     * Root-directory case: rel="." means the target IS the export root.
     * xrootd_split_relative_parent refuses "." (no parent to navigate to),
     * so open the current directory of rootfd directly with O_NOFOLLOW.
     */
    if (rel[0] == '.' && rel[1] == '\0') {
        fd = openat(rootfd, ".", flags | O_CLOEXEC | O_NOFOLLOW, mode);
        close(rootfd);
        return fd;
    }

    if (!xrootd_split_relative_parent(rel, parent, sizeof(parent),
                                      base, sizeof(base)))
    {
        close(rootfd);
        return -1;
    }

    parentfd = xrootd_open_confined_parent_fallback(rootfd, parent);
    close(rootfd);
    if (parentfd < 0) {
        return -1;
    }

    fd = openat(parentfd, base, flags | O_CLOEXEC | O_NOFOLLOW, mode);
    close(parentfd);
    return fd;
}

int
xrootd_open_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *resolved, int flags, mode_t mode)
{
    char root_canon[PATH_MAX];

    if (!xrootd_get_canonical_root(log, root, root_canon,
                                   sizeof(root_canon))) {
        errno = EACCES;
        return -1;
    }

    return xrootd_open_confined_canon(log, root_canon, resolved, flags, mode);
}

/* ---- Confined file deletion operations — unlinkat under confinement ----
 *
 * WHAT: Deletes files or directories using unlinkat syscall while enforcing parent directory confinement via openconfined_parent_canon().
 *       xrootd_unlink_confined_canon takes pre-canonicalized root; xrootd_unlink_confined converts ngx_str_t* root to canonical form. */

/* ---- Unlink confined operation flow ----
 *
 * HOW: 1) Opens parent fd under confinement via xrootd_open_confined_parent_canon(); 
 *      2) Calls unlinkat(parentfd, base, AT_REMOVEDIR if is_dir else 0);
 *      3) Closes parent fd and returns unlinkat result. */

/* ---- Unlink confined operation invariant (confinement enforced) ----
 *
 * WHY: Deletion operations MUST happen under confinement to prevent deleting files outside the export root directory.
 *      Even if resolved path appears correct, confinement ensures deletion happens at the confined location. */

int
xrootd_unlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int is_dir)
{
    char base[NAME_MAX + 1];
    int  parentfd;
    int  rc;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_unlink(rel, is_dir);
    }

    parentfd = xrootd_open_confined_parent_canon(log, root_canon, resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }

    rc = unlinkat(parentfd, base, is_dir ? AT_REMOVEDIR : 0);
    close(parentfd);
    return rc;
}

/* ---- Confined directory creation operations — mkdirat under confinement ----
 *
 * WHAT: Creates new directories using mkdirat syscall while enforcing parent directory confinement via openconfined_parent_canon().
 *       xrootd_mkdir_confined_canon takes pre-canonicalized root; xrootd_mkdir_confined converts ngx_str_t* root to canonical form. */

/* ---- Mkdir confined operation flow ----
 *
 * HOW: 1) Opens parent fd under confinement via xrootd_open_confined_parent_canon(); 
 *      2) Calls mkdirat(parentfd, base, mode);
 *      3) Closes parent fd and returns mkdirat result. */

/* ---- Mkdir confined operation invariant (confinement enforced) ----
 *
 * WHY: Directory creation MUST happen under confinement to prevent creating directories outside the export root directory.
 *      Even if resolved path appears correct, confinement ensures creation happens at the confined location. */

int
xrootd_mkdir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode)
{
    char base[NAME_MAX + 1];
    int  parentfd;
    int  rc;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_mkdir(rel, mode);
    }

    parentfd = xrootd_open_confined_parent_canon(log, root_canon, resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }

    rc = mkdirat(parentfd, base, mode);
    close(parentfd);
    return rc;
}

/* ---- Confined rename/move operations — renameat under confinement ----
 *
 * WHAT: Moves/renames files using renameat syscall while enforcing parent directory confinement for BOTH source and destination.
 *       Requires opening TWO parent fds (src_parentfd + dst_parentfd) to ensure both sides are confined. */

/* ---- Rename confined operation flow (two-parent model) ----
 *
 * HOW: 1) Opens src parent fd under confinement via xrootd_open_confined_parent_canon(src_resolved); 
 *      2) Opens dst parent fd under confinement via xrootd_open_confined_parent_canon(dst_resolved);
 *      3) Calls renameat(src_parentfd, src_base, dst_parentfd, dst_base);
 *      4) Closes both fds and returns renameat result. */

/* ---- Rename confined operation invariant (both sides confined) ----
 *
 * WHY: RENAME/MOVE operations MUST happen under confinement on BOTH source AND destination to prevent moving files into/out of export root.
 *      Even if src/dst paths appear correct, confinement ensures move happens within the confined location boundaries. */

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1u << 0)
#endif

/* Shared body for the plain and create-if-absent confined renames.  When
 * `noreplace` is set, uses renameat2(RENAME_NOREPLACE) and falls back to a plain
 * renameat (logged once) on kernels/filesystems without the flag. */
static int
rename_confined_canon_impl(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved, int noreplace)
{
    char src_base[NAME_MAX + 1];
    char dst_base[NAME_MAX + 1];
    int  src_parentfd;
    int  dst_parentfd;
    int  rc;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (xrootd_imp_client_active()) {
        char rsrc[PATH_MAX], rdst[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, src_resolved,
                                              rsrc, sizeof(rsrc))
            || !xrootd_resolved_relative_to_root(log, root_canon, dst_resolved,
                                                 rdst, sizeof(rdst)))
        {
            return -1;
        }
        return noreplace ? xrootd_imp_rename_noreplace(rsrc, rdst)
                         : xrootd_imp_rename(rsrc, rdst);
    }

    src_parentfd = xrootd_open_confined_parent_canon(log, root_canon,
                                                     src_resolved, src_base,
                                                     sizeof(src_base));
    if (src_parentfd < 0) {
        return -1;
    }

    dst_parentfd = xrootd_open_confined_parent_canon(log, root_canon,
                                                     dst_resolved, dst_base,
                                                     sizeof(dst_base));
    if (dst_parentfd < 0) {
        close(src_parentfd);
        return -1;
    }

    if (noreplace) {
        rc = (int) syscall(SYS_renameat2, src_parentfd, src_base,
                           dst_parentfd, dst_base,
                           (unsigned int) RENAME_NOREPLACE);
        if (rc != 0 && (errno == ENOSYS || errno == EINVAL)) {
            static int warned = 0;
            if (!warned) {
                warned = 1;
                ngx_log_error(NGX_LOG_WARN, log, errno,
                              "xrootd: renameat2(RENAME_NOREPLACE) unsupported; "
                              "create-if-absent falls back to non-atomic rename");
            }
            rc = renameat(src_parentfd, src_base, dst_parentfd, dst_base);
        }
    } else {
        rc = renameat(src_parentfd, src_base, dst_parentfd, dst_base);
    }
    {
        int e = errno;
        close(src_parentfd);
        close(dst_parentfd);
        errno = e;
    }
    return rc;
}

int
xrootd_rename_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved)
{
    return rename_confined_canon_impl(log, root_canon, src_resolved,
                                      dst_resolved, 0);
}

int
xrootd_rename_confined_canon_excl(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved)
{
    return rename_confined_canon_impl(log, root_canon, src_resolved,
                                      dst_resolved, 1);
}

int
xrootd_link_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved)
{
    char src_base[NAME_MAX + 1];
    char dst_base[NAME_MAX + 1];
    int  src_parentfd;
    int  dst_parentfd;
    int  rc;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (xrootd_imp_client_active()) {
        char rsrc[PATH_MAX], rdst[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, src_resolved,
                                              rsrc, sizeof(rsrc))
            || !xrootd_resolved_relative_to_root(log, root_canon, dst_resolved,
                                                 rdst, sizeof(rdst)))
        {
            return -1;
        }
        return xrootd_imp_link(rsrc, rdst);
    }

    src_parentfd = xrootd_open_confined_parent_canon(log, root_canon,
                                                     src_resolved, src_base,
                                                     sizeof(src_base));
    if (src_parentfd < 0) {
        return -1;
    }

    dst_parentfd = xrootd_open_confined_parent_canon(log, root_canon,
                                                     dst_resolved, dst_base,
                                                     sizeof(dst_base));
    if (dst_parentfd < 0) {
        close(src_parentfd);
        return -1;
    }

    rc = linkat(src_parentfd, src_base, dst_parentfd, dst_base, 0);
    close(src_parentfd);
    close(dst_parentfd);
    return rc;
}

/* ---- Confined setattr — utimensat + fchownat under parent confinement ----
 *
 * WHAT: Apply timestamps (set_times → utimensat) and/or owner (set_owner →
 *       fchownat) to <resolved>, both *at() syscalls anchored at the confined
 *       parent fd so a symlink/parent swap cannot redirect the change outside the
 *       root. AT_SYMLINK_NOFOLLOW is used so the operation never follows a final
 *       symlink. uid/gid of (uid_t)-1 / (gid_t)-1 leave that id unchanged.
 *       kXR_chmod already covers mode, so mode is intentionally not handled here.
 *       Returns 0 on success, -1 with errno set.
 */
int
xrootd_setattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int set_times, const struct timespec times[2],
    int set_owner, uid_t uid, gid_t gid)
{
    char base[NAME_MAX + 1];
    int  parentfd;
    int  rc = 0;
    int  saved_errno;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_setattr(rel, set_times, times, set_owner, uid, gid);
    }

    parentfd = xrootd_open_confined_parent_canon(log, root_canon, resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }
    if (set_times && utimensat(parentfd, base, times, AT_SYMLINK_NOFOLLOW) != 0) {
        rc = -1;
    }
    if (rc == 0 && set_owner
        && fchownat(parentfd, base, uid, gid, AT_SYMLINK_NOFOLLOW) != 0) {
        rc = -1;
    }
    saved_errno = errno;
    close(parentfd);
    errno = saved_errno;
    return rc;
}

/* ---- Confined chmod — broker-routed under impersonation ----
 *
 * WHAT: Apply <mode> (low 12 bits) to <resolved>.  Under impersonation routes
 *       through the broker so the chmod runs AS THE MAPPED USER (a chmod requires
 *       being the file's owner; the unprivileged worker is not, so a worker-local
 *       chmod of a user-owned file would EPERM — even for the file's real owner).
 *       Off impersonation, fchmodat anchored at the confined parent fd (so a
 *       symlink/parent swap cannot redirect the change outside the root).
 *       Returns 0 on success, -1 with errno set.
 */
int
xrootd_chmod_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode)
{
    char base[NAME_MAX + 1];
    int  parentfd;
    int  rc;
    int  saved_errno;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_chmod(rel, mode & 07777);
    }

    parentfd = xrootd_open_confined_parent_canon(log, root_canon, resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }
    rc = fchmodat(parentfd, base, mode & 07777, 0) == 0 ? 0 : -1;
    saved_errno = errno;
    close(parentfd);
    errno = saved_errno;
    return rc;
}

/* ---- Confined symlink creation — symlinkat under parent confinement ----
 *
 * WHAT: Create a symlink at <link_resolved> with literal contents <target>. Only
 *       the LINK location is confined (symlinkat anchored at the confined parent);
 *       the target string is stored verbatim — traversal safety for any later
 *       access THROUGH the link is enforced by the confined-open (RESOLVE_BENEATH),
 *       so a target that points outside the root simply cannot be followed.
 *       Returns 0 on success, -1 with errno set.
 */
int
xrootd_symlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *target, const char *link_resolved)
{
    char base[NAME_MAX + 1];
    int  parentfd;
    int  rc;
    int  saved_errno;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, link_resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_symlink(target, rel);
    }

    parentfd = xrootd_open_confined_parent_canon(log, root_canon, link_resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }
    rc = symlinkat(target, parentfd, base);
    saved_errno = errno;
    close(parentfd);
    errno = saved_errno;
    return rc;
}

/* ---- Confined readlink — readlinkat under parent confinement ----
 *
 * WHAT: Read the target of the symlink at <resolved> into <buf> (NOT
 *       NUL-terminated by readlinkat — the caller terminates). The parent is
 *       opened under confinement and readlinkat does not follow the final symlink.
 *       Returns the number of bytes placed in buf, or -1 with errno set.
 */
ssize_t
xrootd_readlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, char *buf, size_t bufsz)
{
    char    base[NAME_MAX + 1];
    int     parentfd;
    ssize_t n;
    int     saved_errno;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_readlink(rel, buf, bufsz);
    }

    parentfd = xrootd_open_confined_parent_canon(log, root_canon, resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }
    n = readlinkat(parentfd, base, buf, bufsz);
    saved_errno = errno;
    close(parentfd);
    errno = saved_errno;
    return n;
}

/* ---- Confined hard link creation operations — linkat under confinement ----
 *
 * WHAT: Creates hard links using linkat syscall while enforcing parent directory confinement for BOTH source and destination.
 *       Requires opening TWO parent fds (src_parentfd + dst_parentfd) to ensure both sides are confined. */

/* ---- Link confined operation flow (two-parent model) ----
 *
 * HOW: 1) Opens src parent fd under confinement via xrootd_open_confined_parent_canon(src_resolved); 
 *      2) Opens dst parent fd under confinement via xrootd_open_confined_parent_canon(dst_resolved);
 *      3) Calls linkat(src_parentfd, src_base, dst_parentfd, dst_base, 0);
 *      4) Closes both fds and returns linkat result. */

/* ---- Link confined operation invariant (both sides confined) ----
 *
 * WHY: LINK creation MUST happen under confinement on BOTH source AND destination to prevent creating links outside the export root.
 *      Even if src/dst paths appear correct, confinement ensures link is created within the confined location boundaries. */

/* ---- Function: xrootd_open_confined_canon() ----
 *
 * WHAT: Opens a file while enforcing ROOT CONFINEMENT at multiple layers (defence-in-depth). Takes pre-canonicalized root_canon and resolved path, converts to relative form, opens root fd via O_PATH, then uses openat2 RESOLVE_BENEATH (Linux 5.6+) or fallback O_NOFOLLOW to open the target file under confinement.
 *
 * WHY: Two-layer security — first layer is CANONICAL PATH RESOLUTION (no symlinks, no "..") via caller's resolve function; second layer is KERNEL-LEVEL CONFINEMENT via openat2 RESOLVE_BENEATH or fallback O_NOFOLLOW. Even if a symlink was introduced between resolve and open, kernel-level prevention blocks escape. Returns fd that is NOT pool-managed — caller MUST close it explicitly.
 *
 * HOW: 1) Call xrootd_resolved_relative_to_root(root_canon, resolved) to get relative path rel; 2) Open root fd via O_PATH mode (xrootd_open_root_fd); 3) Try openat2 confined syscall (xrootd_openat2_confined); if it fails with ENOSYS/EINVAL/EOPNOTSUPP, fall through; 4) If rel == '.' (target IS the root), openat(rootfd, '.', flags|O_CLOEXEC|O_NOFOLLOW); 5) Otherwise split rel into parent/base via xrootd_split_relative_parent, open parent fd via fallback, then openat(parentfd, base, flags|O_CLOEXEC|O_NOFOLLOW). Returns fd on success, -1 on failure. Thread safety: uses local stack buffers — safe for concurrent use. */

/* ---- Function: xrootd_open_confined() ----
 *
 * WHAT: Thin wrapper that converts ngx_str_t root argument to canonical form via xrootd_get_canonical_root(), then delegates to xrootd_open_confined_canon(). Provides the non-canonical API variant for callers holding ngx_str_t root configuration.
 *
 * WHY: Many callers (WebDAV dispatch, native XRootD handler) hold root as ngx_str_t from location config. This wrapper bridges between the nginx string type and the canonical char* form required by xrootd_open_confined_canon(). Sets errno = EACCES on canonical_root failure.
 *
 * HOW: 1) Call xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon)); 2) On success, delegate to xrootd_open_confined_canon(log, root_canon, resolved, flags, mode); 3) Return delegated result. Returns fd on success, -1 on failure. Thread safety: uses local stack buffer — safe for concurrent use. */

/* ---- Function: xrootd_unlink_confined_canon() ----
 *
 * WHAT: Deletes files or directories using unlinkat syscall while enforcing parent directory confinement via openconfined_parent_canon(). Takes pre-canonicalized root_canon and resolved path. is_dir parameter controls AT_REMOVEDIR flag.
 *
 * WHY: Deletion operations MUST happen under confinement to prevent deleting files outside the export root directory. Even if resolved path appears correct, confinement ensures deletion happens at the confined location by opening parent fd via xrootd_open_confined_parent_canon() then calling unlinkat(parentfd, base, AT_REMOVEDIR|0).
 *
 * HOW: 1) Call xrootd_open_confined_parent_canon(log, root_canon, resolved, base, sizeof(base)) to get parent fd and extract base name; 2) If parentfd < 0, return -1; 3) Call unlinkat(parentfd, base, is_dir ? AT_REMOVEDIR : 0); 4) Close parent fd; 5) Return unlinkat result. Returns 0 on success, -1 on failure. Thread safety: uses local stack buffer — safe for concurrent use. */

/* ---- Function: xrootd_mkdir_confined_canon() ----
 *
 * WHAT: Creates new directories using mkdirat syscall while enforcing parent directory confinement via openconfined_parent_canon(). Takes pre-canonicalized root_canon and resolved path, creates at mode_t permission bits.
 *
 * WHY: Directory creation MUST happen under confinement to prevent creating directories outside the export root directory. Even if resolved path appears correct, confinement ensures creation happens at the confined location by opening parent fd via xrootd_open_confined_parent_canon() then calling mkdirat(parentfd, base, mode).
 *
 * HOW: 1) Call xrootd_open_confined_parent_canon(log, root_canon, resolved, base, sizeof(base)) to get parent fd and extract base name; 2) If parentfd < 0, return -1; 3) Call mkdirat(parentfd, base, mode); 4) Close parent fd; 5) Return mkdirat result. Returns 0 on success, -1 on failure. Thread safety: uses local stack buffer — safe for concurrent use. */


/* ---- Function: xrootd_rename_confined_canon() ----
 *
 * WHAT: Moves/renames files using renameat syscall while enforcing parent directory confinement for BOTH source and destination. Takes pre-canonicalized root_canon, src_resolved and dst_resolved paths; opens TWO parent fds to ensure both sides are confined.
 *
 * WHY: RENAME/MOVE operations MUST happen under confinement on BOTH source AND destination to prevent moving files into/out of export root. Even if src/dst paths appear correct, confinement ensures move happens within the confined location boundaries by opening src_parentfd and dst_parentfd via xrootd_open_confined_parent_canon() then calling renameat(src_parentfd, src_base, dst_parentfd, dst_base).
 *
 * HOW: 1) Call xrootd_open_confined_parent_canon(log, root_canon, src_resolved, src_base, sizeof(src_base)) to get src_parentfd; 2) If src_parentfd < 0, return -1; 3) Call xrootd_open_confined_parent_canon(log, root_canon, dst_resolved, dst_base, sizeof(dst_base)) to get dst_parentfd; 4) If dst_parentfd < 0, close src_parentfd and return -1; 5) Call renameat(src_parentfd, src_base, dst_parentfd, dst_base); 6) Close both fds; 7) Return renameat result. Returns 0 on success, -1 on failure. Thread safety: uses local stack buffers — safe for concurrent use. */

/* ---- Function: xrootd_link_confined_canon() ----
 *
 * WHAT: Creates hard links using linkat syscall while enforcing parent directory confinement for BOTH source and destination. Takes pre-canonicalized root_canon, src_resolved and dst_resolved paths; opens TWO parent fds to ensure both sides are confined.
 *
 * WHY: LINK creation MUST happen under confinement on BOTH source AND destination to prevent creating links outside the export root. Even if src/dst paths appear correct, confinement ensures link is created within the confined location boundaries by opening src_parentfd and dst_parentfd via xrootd_open_confined_parent_canon() then calling linkat(src_parentfd, src_base, dst_parentfd, dst_base, 0).
 *
 * HOW: 1) Call xrootd_open_confined_parent_canon(log, root_canon, src_resolved, src_base, sizeof(src_base)) to get src_parentfd; 2) If src_parentfd < 0, return -1; 3) Call xrootd_open_confined_parent_canon(log, root_canon, dst_resolved, dst_base, sizeof(dst_base)) to get dst_parentfd; 4) If dst_parentfd < 0, close src_parentfd and return -1; 5) Call linkat(src_parentfd, src_base, dst_parentfd, dst_base, 0); 6) Close both fds; 7) Return linkat result. Returns 0 on success, -1 on failure. Thread safety: uses local stack buffers — safe for concurrent use. */


/* ---- Confined extended-attribute ops — broker-routed under impersonation ----
 *
 * WHAT: set/get/remove/list extended attributes on a resolved (already
 *       lexically-confined) path.  When impersonation map mode is active the op
 *       is routed to the privileged broker, which re-confines under its own
 *       export rootfd (openat2 RESOLVE_BENEATH) and performs the f*xattr as the
 *       mapped user — so the lock/dead-property xattr lands with, and is
 *       DAC-checked for, the real user (not the unprivileged worker).  When
 *       impersonation is off the behaviour is byte-for-byte the prior raw
 *       path-based syscall, so the non-impersonated path is unchanged.
 *
 * WHY: WebDAV LOCK tokens and PROPPATCH dead-properties are stored as `user.*`
 *       xattrs on the resource.  Without broker routing the worker (svc) would
 *       attempt setxattr on a file owned 0644 by the mapped user and fail EACCES
 *       — i.e. LOCK/PROPPATCH were broken under impersonation.  Routing fixes
 *       that and keeps the on-disk metadata owned by the right identity.
 *
 * Return values mirror the POSIX *xattr contract (get/list: byte count, or the
 * size when bufsz==0; -1/ERANGE when the caller buffer is too small).
 */
int
xrootd_setxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name, const void *value, size_t len,
    int flags)
{
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_setxattr(rel, name, value, len, flags);
    }
    return setxattr(resolved, name, value, len, flags);
}

ssize_t
xrootd_getxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name, void *buf, size_t bufsz)
{
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_getxattr(rel, name, buf, bufsz);
    }
    return getxattr(resolved, name, buf, bufsz);
}

int
xrootd_removexattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name)
{
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_removexattr(rel, name);
    }
    return removexattr(resolved, name);
}

ssize_t
xrootd_listxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, void *buf, size_t bufsz)
{
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_listxattr(rel, buf, bufsz);
    }
    return listxattr(resolved, buf, bufsz);
}

/* ---- Confined directory open — broker-routed fd + fdopendir under impersonation
 *
 * WHAT: open <resolved> as a directory stream that, under impersonation map mode,
 *       is opened BY THE BROKER as the mapped user (O_RDONLY|O_DIRECTORY via
 *       RESOLVE_BENEATH) and handed back as an fd that we fdopendir().  readdir on
 *       that stream then enumerates the directory with the mapped user's read
 *       permission — so a worker that cannot itself opendir a user-private dir
 *       (e.g. a 0700 multipart staging dir owned by the mapped user) can still
 *       list it on the user's behalf.  Off impersonation it is a plain opendir().
 *
 * WHY: S3 multipart ListParts / AbortMultipartUpload (and the staging-dir cleanup)
 *      enumerate a staging directory created+owned by the mapped user.  Done as a
 *      raw worker-side opendir() they fail EACCES under impersonation; routing the
 *      open through the broker fixes that while keeping per-entry removal on the
 *      already-brokered xrootd_unlink_confined_canon path.  Returns a DIR* (caller
 *      closedir()s it) or NULL (errno set). */
DIR *
xrootd_opendir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved)
{
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];
        int  fd;
        DIR *d;

        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return NULL;
        }
        fd = xrootd_imp_open(rel, O_RDONLY | O_DIRECTORY, 0);  /* as mapped user */
        if (fd < 0) {
            return NULL;
        }
        d = fdopendir(fd);
        if (d == NULL) {
            close(fd);
        }
        return d;                          /* closedir() closes the fd */
    }
    return opendir(resolved);
}

/* xrootd_lstat_confined_canon — lstat()/stat() a path *as the mapped user* under
 * impersonation, else a bare lstat/stat.  WHY: recursive walks (COPY/MOVE
 * collections, S3 multipart, remove-tree) lstat children of a directory owned
 * 0700 by the mapped user; a raw worker lstat would EACCES on the parent's
 * search bit.  Routes through the broker (which stat()s as the mapped user) so
 * the walk sees what that user can see.  nofollow!=0 → lstat semantics (do not
 * follow a trailing symlink — confinement: never resolve a link out of the
 * export).  Returns 0 on success, -1 on error (errno set). */
int
xrootd_lstat_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, struct stat *st, int nofollow)
{
    if (xrootd_imp_client_active()) {
        char rel[PATH_MAX];

        if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return xrootd_imp_stat(rel, st, nofollow);    /* as mapped user */
    }
    return nofollow ? lstat(resolved, st) : stat(resolved, st);
}
