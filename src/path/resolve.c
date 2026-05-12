#include "../ngx_xrootd_module.h"

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

static void
xrootd_log_path_warning(ngx_log_t *log, const char *prefix, const char *path)
{
    char safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));
    ngx_log_error(NGX_LOG_WARN, log, 0, "%s: %s", prefix, safe_path);
}

/*
 * xrootd_path_within_root — enforce the export root boundary.
 *
 * Returns 1 if path_canon is the root itself or a direct descendant of it;
 * 0 otherwise.
 *
 * Path-prefix attack prevention: "/export" must not match "/exportdata".
 * The boundary character check (path_canon[root_len] == '/' or '\0') is
 * what makes this safe against such attacks.
 *
 * Both arguments must be canonicalised absolute paths (no trailing slash
 * except when root_canon is exactly "/").
 */
static int
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

static int
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

static int
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
 * Wrapper around the openat2(2) syscall (Linux 5.6+).  RESOLVE_BENEATH
 * instructs the kernel to refuse any path that escapes rootfd's directory
 * tree, including symlinks that point outside it.  RESOLVE_NO_MAGICLINKS
 * blocks /proc/<pid>/fd and similar kernel-magic symlinks that could be
 * used to escape the confinement.
 *
 * This is the preferred confinement method.  The fallback
 * (xrootd_open_confined_parent_fallback) is used only when the kernel
 * does not support openat2 (i.e. ENOSYS / EINVAL / EOPNOTSUPP).
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

static int
xrootd_open_dir_no_symlink(int parentfd, const char *name)
{
    return openat(parentfd, name,
                  O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

static int
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

static int
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

static int
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

/*
 * xrootd_open_confined_canon — open a file while enforcing root confinement.
 *
 * resolved must already be a canonical absolute path (no symlinks, no ".."),
 * produced by one of the xrootd_resolve_path* functions.  The confinement is
 * a defence-in-depth check: even if a symlink was introduced between resolve
 * and open, the kernel-level RESOLVE_BENEATH (openat2) or O_NOFOLLOW
 * (fallback) prevents escape.
 *
 * Preconditions:
 *   - root_canon is the export root, produced by xrootd_get_canonical_root().
 *   - resolved is within root_canon (caller must verify).
 *
 * Ownership: the returned fd must be closed by the caller.  It is not
 *   pool-managed.
 *
 * Returns: a valid file descriptor on success, -1 with errno set on failure.
 *
 * ngx_open_file argument order reminder:
 *   xrootd_open_confined_canon(..., flags, mode)
 *   flags  = O_RDONLY / O_WRONLY / O_RDWR / O_CREAT / O_TRUNC etc.
 *   mode   = 0644 permission bits (used only when O_CREAT is set)
 * Do NOT pass permission bits in flags position — 0644 has the O_EXCL bit
 * set (0200) and would cause unexpected exclusive-create semantics.
 */
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

int
xrootd_unlink_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *resolved, int is_dir)
{
    char root_canon[PATH_MAX];

    if (!xrootd_get_canonical_root(log, root, root_canon,
                                   sizeof(root_canon))) {
        errno = EACCES;
        return -1;
    }

    return xrootd_unlink_confined_canon(log, root_canon, resolved, is_dir);
}

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

int
xrootd_mkdir_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *resolved, mode_t mode)
{
    char root_canon[PATH_MAX];

    if (!xrootd_get_canonical_root(log, root, root_canon,
                                   sizeof(root_canon))) {
        errno = EACCES;
        return -1;
    }

    return xrootd_mkdir_confined_canon(log, root_canon, resolved, mode);
}

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

int
xrootd_rename_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *src_resolved, const char *dst_resolved)
{
    char root_canon[PATH_MAX];

    if (!xrootd_get_canonical_root(log, root, root_canon,
                                   sizeof(root_canon))) {
        errno = EACCES;
        return -1;
    }

    return xrootd_rename_confined_canon(log, root_canon,
                                        src_resolved, dst_resolved);
}

/*
 * xrootd_resolve_path_noexist — resolve a path where zero or more trailing
 * components may not yet exist (used for kXR_mkdir with kXR_mkdirpath).
 *
 * Walks reqpath segment by segment: for components that exist, advances the
 * canonical prefix via realpath(3); for components that don't exist (ENOENT),
 * appends them literally after checking for ".." traversal.  After each
 * realpath call, the result is checked against root to detect symlink escapes.
 *
 * Unlike xrootd_resolve_path_write, this function tolerates an arbitrary
 * number of non-existent tail components, making it suitable for deep mkdir.
 *
 * Returns: 1 on success, 0 on failure.
 */
int
xrootd_resolve_path_noexist(ngx_log_t *log, const ngx_str_t *root,
                            const char *reqpath, char *resolved,
                            size_t resolvsz)
{
    char        root_canon[PATH_MAX];
    char        current[PATH_MAX];
    char        candidate[PATH_MAX];
    struct stat st;
    const char *p;
    int         n;

    while (*reqpath == '/') {
        reqpath++;
    }

    if (*reqpath == '\0') {
        return 0;
    }

    if (!xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return 0;
    }

    ngx_cpystrn((u_char *) current, (u_char *) root_canon, sizeof(current));

    p = reqpath;
    while (*p) {
        const char *seg_end;
        size_t      seg_len;

        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        seg_end = strchr(p, '/');
        seg_len = seg_end ? (size_t) (seg_end - p) : strlen(p);

        if (xrootd_path_component_forbidden(p, seg_len)) {
            xrootd_log_path_warning(log, "xrootd: path traversal attempt", reqpath);
            return 0;
        }

        n = snprintf(candidate, sizeof(candidate), "%s/%.*s",
                     current, (int) seg_len, p);
        if (n < 0 || (size_t) n >= sizeof(candidate)) {
            ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
            return 0;
        }

        if (lstat(candidate, &st) == 0) {
            if (realpath(candidate, current) == NULL) {
                return 0;
            }
            if (!xrootd_path_within_root(root_canon, current)) {
                xrootd_log_path_warning(log, "xrootd: path traversal attempt", current);
                return 0;
            }
        } else if (errno == ENOENT) {
            ngx_cpystrn((u_char *) current, (u_char *) candidate, sizeof(current));
        } else {
            return 0;
        }

        if (seg_end == NULL) {
            break;
        }
        p = seg_end + 1;
    }

    n = snprintf(resolved, resolvsz, "%s", current);
    if (n < 0 || (size_t) n >= resolvsz) {
        return 0;
    }

    return 1;
}

/*
 * xrootd_resolve_path — resolve an existing path within the export root.
 *
 * reqpath is the client-supplied path (may start with '/').  All ".." and
 * "." components are rejected before calling realpath(3).
 *
 * realpath(3) requires existence: every component of reqpath must exist on
 * disk.  Use xrootd_resolve_path_write() for paths that may not exist yet
 * (e.g. PUT destinations).
 *
 * Preconditions: root->data is a valid export root directive value.
 * Postconditions on success: resolved[0..n] is a NUL-terminated canonical
 *   absolute path within root, with n < resolvsz.
 * Returns: 1 on success, 0 on any error (path traversal, nonexistent, too long).
 */
int
xrootd_resolve_path(ngx_log_t *log, const ngx_str_t *root,
                    const char *reqpath, char *resolved, size_t resolvsz)
{
    char        combined[PATH_MAX * 2];
    char        canonical[PATH_MAX];
    char        root_canon[PATH_MAX];
    const char *p = reqpath;
    int         n;

    if (!xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return 0;
    }

    while (*p == '/') {
        p++;
    }

    if (*p == '\0') {
        n = snprintf(resolved, resolvsz, "%s", root_canon);
        return (n >= 0 && (size_t) n < resolvsz);
    }

    {
        const char *scan = p;

        while (*scan) {
            const char *seg_end = strchr(scan, '/');
            size_t      seg_len = seg_end ? (size_t) (seg_end - scan)
                                          : strlen(scan);

            if (xrootd_path_component_forbidden(scan, seg_len)) {
                xrootd_log_path_warning(log, "xrootd: path traversal attempt", reqpath);
                return 0;
            }

            if (seg_end == NULL) {
                break;
            }

            scan = seg_end + 1;
        }
    }

    n = snprintf(combined, sizeof(combined), "%s/%s", root_canon, p);
    if (n < 0 || (size_t) n >= sizeof(combined)) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
        return 0;
    }

    if (realpath(combined, canonical) == NULL) {
        return 0;
    }

    if (!xrootd_path_within_root(root_canon, canonical)) {
        xrootd_log_path_warning(log, "xrootd: path traversal attempt", canonical);
        return 0;
    }

    n = snprintf(resolved, resolvsz, "%s", canonical);
    if (n < 0 || (size_t) n >= resolvsz) {
        return 0;
    }

    return 1;
}

/*
 * xrootd_resolve_path_write — resolve a write-destination path where the
 * final component need not exist yet (e.g. PUT, kXR_open for write).
 *
 * realpath(3) requires existence of every path component, including the
 * final one.  This function works around that by canonicalising the parent
 * directory with realpath(3) (which must exist), then appending the
 * filename component only after the parent is confirmed to be within root.
 *
 * Preconditions:
 *   - reqpath must not be empty and must name a file, not a directory.
 *   - The parent directory of reqpath must already exist.
 *
 * Returns: 1 on success, 0 on failure.
 */
int
xrootd_resolve_path_write(ngx_log_t *log, const ngx_str_t *root,
                          const char *reqpath, char *resolved, size_t resolvsz)
{
    char        root_canon[PATH_MAX];
    char        combined[PATH_MAX * 2];
    char        parent_buf[PATH_MAX * 2];
    char        parent_canon[PATH_MAX];
    char       *slash;
    const char *base;
    size_t      base_len;
    int         n;

    if (!xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return 0;
    }

    while (*reqpath == '/') {
        reqpath++;
    }

    if (*reqpath == '\0') {
        return 0;
    }

    n = snprintf(combined, sizeof(combined), "%s/%s", root_canon, reqpath);
    if (n < 0 || (size_t) n >= sizeof(combined)) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
        return 0;
    }

    ngx_cpystrn((u_char *) parent_buf, (u_char *) combined, sizeof(parent_buf));
    slash = strrchr(parent_buf, '/');
    if (slash == NULL || slash == parent_buf) {
        return 0;
    }
    base = slash + 1;
    *slash = '\0';

    if (*base == '\0') {
        return 0;
    }

    base_len = strlen(base);
    if (xrootd_path_component_forbidden(base, base_len)) {
        xrootd_log_path_warning(log, "xrootd: path traversal attempt", reqpath);
        return 0;
    }

    if (realpath(parent_buf, parent_canon) == NULL) {
        return 0;
    }

    if (!xrootd_path_within_root(root_canon, parent_canon)) {
        xrootd_log_path_warning(log, "xrootd: path traversal attempt in write",
                                parent_canon);
        return 0;
    }

    n = snprintf(resolved, resolvsz, "%s/%s", parent_canon, base);
    if (n < 0 || (size_t) n >= resolvsz) {
        return 0;
    }

    return 1;
}
