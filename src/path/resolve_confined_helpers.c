/*
 * resolve_confined_helpers.c — building blocks for absolute-path confined opens.
 *
 * WHAT: Lower-level helpers used by the resolve-then-confine stack (the callers
 *       in resolve_confined_ops.c). Covers: sanitized path-violation logging
 *       (xrootd_log_path_warning), export-root boundary checking
 *       (xrootd_path_within_root), absolute→root-relative conversion
 *       (xrootd_resolved_relative_to_root), opening the root anchor fd
 *       (xrootd_open_root_fd), the openat2(2) confined-open wrapper plus a
 *       runtime capability probe (xrootd_openat2_runtime_available), the
 *       O_NOFOLLOW segment-by-segment fallback for pre-5.6 kernels
 *       (xrootd_open_confined_parent_fallback), parent/base splitting
 *       (xrootd_split_relative_parent), and the combined confined-parent opener
 *       (xrootd_open_confined_parent_canon).
 *
 * WHY:  This is the legacy confinement path that takes an already-canonical
 *       absolute 'resolved' string (from realpath-style resolution) and reopens
 *       it safely under the export root. Unlike the newer beneath.c API — which
 *       confines a raw client reqpath directly via RESOLVE_BENEATH — these
 *       helpers must first strip the root prefix and guard against prefix
 *       attacks ("/export" must never match "/exportdata"), because user-space
 *       string comparison is the only boundary before the syscall runs.
 *
 * HOW:  When the kernel supports openat2(2) (XROOTD_HAVE_OPENAT2 compiled AND
 *       the runtime probe passes) confinement is kernel-enforced via
 *       RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS. On older kernels
 *       (ENOSYS/EINVAL/EOPNOTSUPP) it degrades to walking the parent path one
 *       component at a time with openat(O_PATH|O_DIRECTORY|O_NOFOLLOW), rejecting
 *       forbidden ("." / "..") components at each step so no intermediate symlink
 *       can escape.
 */
#include "ngx_xrootd_module.h"

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

#include "path_internal.h"

#if defined(__has_include)
#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#define XROOTD_HAVE_LINUX_OPENAT2_H 1
#endif
#endif

#if defined(__linux__) && defined(SYS_openat2) && defined(XROOTD_HAVE_LINUX_OPENAT2_H)
#define XROOTD_HAVE_OPENAT2 1
#endif

#ifndef O_PATH
#define O_PATH O_RDONLY
#endif

/*
 * xrootd_log_path_warning — log a path-related warning with the path sanitized
 * (control bytes/quotes/non-ASCII → hex via xrootd_sanitize_log_string) so a
 * hostile client path cannot inject forged entries into the log.
 */
void
xrootd_log_path_warning(ngx_log_t *log, const char *prefix, const char *path)
{
    char safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));
    ngx_log_error(NGX_LOG_WARN, log, 0, "%s: %s", prefix, safe_path);
}

/*
 * xrootd_path_within_root — 1 iff canonical path_canon is exactly root_canon or
 * a descendant of it. The boundary-char check (the byte after the prefix must be
 * '/' or '\0') defeats prefix attacks ("/export" must not match "/exportdata").
 * Both args must be canonical absolute paths, no trailing slash (except "/").
 */
int
xrootd_path_within_root(const char *root_canon, const char *path_canon)
{
    size_t root_len = strlen(root_canon);

    if (root_len == 1 && root_canon[0] == '/') {
        return path_canon[0] == '/';
    }

    if (strncmp(path_canon, root_canon, root_len) != 0) {
        return 0;
    }

    /* path-prefix attack: "/export" must not match "/exportdata" */
    return path_canon[root_len] == '\0' || path_canon[root_len] == '/';
}

/*
 * xrootd_resolved_relative_to_root — strip root_canon from the canonical
 * `resolved` to yield the root-relative `rel` the confined *at() openers need
 * (the export root itself maps to "."). Validates containment first: on escape
 * it logs and sets EXDEV (return 0); ENAMETOOLONG (return 0) on overflow; else 1.
 */
int
xrootd_resolved_relative_to_root(ngx_log_t *log, const char *root_canon,
    const char *resolved, char *rel, size_t relsz)
{
    const char *src;
    size_t      root_len;
    size_t      rel_len;

    if (!xrootd_path_within_root(root_canon, resolved)) {
        xrootd_log_path_warning(log, "xrootd: confined path escaped root",
                                resolved);
        errno = EXDEV;
        return 0;
    }

    root_len = strlen(root_canon);

    if (root_len == 1 && root_canon[0] == '/') {
        src = resolved + 1;
    } else if (resolved[root_len] == '\0') {
        src = ".";
    } else {
        src = resolved + root_len + 1;
    }

    if (*src == '\0') {
        src = ".";
    }

    rel_len = strlen(src);
    if (rel_len == 0 || rel_len >= relsz) {
        errno = ENAMETOOLONG;
        return 0;
    }

    ngx_memcpy(rel, src, rel_len + 1);
    return 1;
}

/*
 * xrootd_open_root_fd — open the export root as an O_PATH|O_DIRECTORY|O_CLOEXEC
 * anchor fd for subsequent confined openat2/openat calls (caller closes it).
 * Returns the fd, or -1 with a WARN log on failure.
 */
int
xrootd_open_root_fd(ngx_log_t *log, const char *root_canon)
{
    int fd;

    fd = open(root_canon, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "xrootd: unable to open export root for confined syscall");
    }

    return fd;
}

#if (XROOTD_HAVE_OPENAT2)
/*
 * xrootd_openat2_confined — openat2(2) with kernel-enforced confinement:
 * RESOLVE_BENEATH (refuse any escape of rootfd's tree, incl. out-pointing
 * symlinks) | RESOLVE_NO_MAGICLINKS (block /proc/<pid>/fd magic links). Mode is
 * applied only when O_CREAT is set. Harder than user-space checks — the kernel
 * enforces containment; the segment-walk fallback runs only when this is
 * unsupported (ENOSYS/EINVAL/EOPNOTSUPP).
 */
static int
xrootd_openat2_confined(int rootfd, const char *rel, int flags, mode_t mode)
{
    struct open_how how;

    ngx_memzero(&how, sizeof(how));
    how.flags = (uint64_t) (flags | O_CLOEXEC);
    if (flags & O_CREAT) {
        how.mode = (uint64_t) mode;
    }
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;

    return (int) syscall(SYS_openat2, rootfd, rel, &how, sizeof(how));
}
#endif

/*
 * xrootd_openat2_runtime_available — probe whether the running kernel
 * supports openat2(2).  Returns 1 if available, 0 if not.
 *
 * Called once at worker init.  Even when compiled with XROOTD_HAVE_OPENAT2,
 * the syscall may return ENOSYS on older kernels (e.g. RHEL8 / 4.18).
 */
int
xrootd_openat2_runtime_available(void)
{
#if (XROOTD_HAVE_OPENAT2)
    struct open_how how;
    int             fd;

    ngx_memzero(&how, sizeof(how));
    how.flags = O_PATH | O_CLOEXEC;
    fd = (int) syscall(SYS_openat2, AT_FDCWD, ".", &how, sizeof(how));
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return (errno != ENOSYS) ? 1 : 0;
#else
    return 0;
#endif
}

/*
 * xrootd_open_dir_no_symlink — openat one directory component with
 * O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW so the segment-by-segment fallback
 * cannot traverse a symlink at any step.
 */
static int
xrootd_open_dir_no_symlink(int parentfd, const char *name)
{
    return openat(parentfd, name,
                  O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

/*
 * xrootd_open_confined_parent_fallback — pre-openat2 confinement: walk `parent`
 * one component at a time, opening each with O_NOFOLLOW and rejecting forbidden
 * ("."/"..") components (EACCES), so no intermediate symlink can escape the
 * export root. Returns a parent fd (a dup of rootfd for an empty/"." parent),
 * or -1.
 */
int
xrootd_open_confined_parent_fallback(int rootfd, const char *parent)
{
    char        scratch[PATH_MAX];
    char       *seg;
    char       *slash;
    int         curfd;
    size_t      len;

    if (parent[0] == '\0' || strcmp(parent, ".") == 0) {
        return dup(rootfd);
    }

    len = strlen(parent);
    if (len >= sizeof(scratch)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    ngx_memcpy(scratch, parent, len + 1);
    curfd = dup(rootfd);
    if (curfd < 0) {
        return -1;
    }

    seg = scratch;
    while (*seg != '\0') {
        int nextfd;

        slash = strchr(seg, '/');
        if (slash != NULL) {
            *slash = '\0';
        }

        if (seg[0] == '\0'
            || xrootd_path_component_forbidden(seg, strlen(seg)))
        {
            close(curfd);
            errno = EACCES;
            return -1;
        }

        nextfd = xrootd_open_dir_no_symlink(curfd, seg);
        close(curfd);
        if (nextfd < 0) {
            return -1;
        }

        curfd = nextfd;
        if (slash == NULL) {
            break;
        }
        seg = slash + 1;
    }

    return curfd;
}

/*
 *
 * WHAT: Splits a root-relative path `rel` into its parent directory (`parent`)
 *       and final component (`base`). A path with no '/' (e.g. "file") yields
 *       parent="." and base="file". Returns 1 on success, 0 on error.
 *
 * WHY:  The confined-parent openers operate on a parent fd plus a base name, so
 *       a relative path produced by xrootd_resolved_relative_to_root() must be
 *       decomposed before openat2()/fallback can open the parent and then act on
 *       the leaf name only — the same parent-then-leaf discipline that keeps an
 *       intermediate symlink from escaping the export root.
 *
 * HOW:  Rejects NULL/empty/"." inputs (EINVAL). strrchr() finds the last '/';
 *       with none, copies "." into parent and the whole string into base. With
 *       one, copies the prefix into parent and the suffix into base, bounds-
 *       checking both against parentsz/basesz (ENAMETOOLONG on overflow). */
int
xrootd_split_relative_parent(const char *rel, char *parent, size_t parentsz,
    char *base, size_t basesz)
{
    const char *slash;
    size_t      parent_len;
    size_t      base_len;

    if (rel == NULL || rel[0] == '\0' || strcmp(rel, ".") == 0) {
        errno = EINVAL;
        return 0;
    }

    slash = strrchr(rel, '/');
    if (slash == NULL) {
        parent_len = 1;
        if (parentsz <= parent_len) {
            errno = ENAMETOOLONG;
            return 0;
        }
        ngx_memcpy(parent, ".", 2);
        base_len = strlen(rel);
        if (base_len == 0 || base_len >= basesz) {
            errno = ENAMETOOLONG;
            return 0;
        }
        ngx_memcpy(base, rel, base_len + 1);
        return 1;
    }

    parent_len = (size_t) (slash - rel);
    base_len = strlen(slash + 1);
    if (parent_len == 0 || parent_len >= parentsz
        || base_len == 0 || base_len >= basesz)
    {
        errno = ENAMETOOLONG;
        return 0;
    }

    ngx_memcpy(parent, rel, parent_len);
    parent[parent_len] = '\0';
    ngx_memcpy(base, slash + 1, base_len + 1);
    return 1;
}

/*
 * xrootd_open_confined_parent_canon — resolve `resolved` to a root-relative
 * path, split it into parent + base, then open the parent directory confined
 * (openat2, else the segment-walk fallback). Returns the parent fd (the caller
 * acts on `base` then closes it) or -1.
 */
int
xrootd_open_confined_parent_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, char *base, size_t basesz)
{
    char rel[PATH_MAX];
    char parent[PATH_MAX];
    int  rootfd;
    int  parentfd;

    if (!xrootd_resolved_relative_to_root(log, root_canon, resolved,
                                          rel, sizeof(rel))
        || !xrootd_split_relative_parent(rel, parent, sizeof(parent),
                                         base, basesz))
    {
        return -1;
    }

    rootfd = xrootd_open_root_fd(log, root_canon);
    if (rootfd < 0) {
        return -1;
    }

#if (XROOTD_HAVE_OPENAT2)
    parentfd = xrootd_openat2_confined(rootfd, parent,
                                       O_PATH | O_DIRECTORY, 0);
    if (parentfd < 0
        && errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP)
    {
        close(rootfd);
        return -1;
    }
    if (parentfd < 0) {
        parentfd = xrootd_open_confined_parent_fallback(rootfd, parent);
    }
#else
    parentfd = xrootd_open_confined_parent_fallback(rootfd, parent);
#endif

    close(rootfd);
    return parentfd;
}

