#include "../ngx_xrootd_module.h"
#include "path_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
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

int
xrootd_rename_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved)
{
    char src_base[NAME_MAX + 1];
    char dst_base[NAME_MAX + 1];
    int  src_parentfd;
    int  dst_parentfd;
    int  rc;

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

    rc = renameat(src_parentfd, src_base, dst_parentfd, dst_base);
    close(src_parentfd);
    close(dst_parentfd);
    return rc;
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

