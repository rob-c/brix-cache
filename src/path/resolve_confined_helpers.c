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

/* ---- Function: xrootd_log_path_warning() ----
 *
 * WHAT: Logs a security/warning message about a problematic path using sanitized output. Escapes control bytes, quotes, backslashes, non-ASCII characters via xrootd_sanitize_log_string() to prevent log injection attacks when logging suspicious paths.
 *
 * WHY: XRootD clients can send arbitrary byte sequences in path payloads — unsanitized paths containing newline, carriage return, or quote could inject fake log entries into access logs, enabling log injection attacks. Sanitization converts dangerous bytes to hex escapes before logging.
 *
 * HOW: Copies path into safe_path[512] via xrootd_sanitize_log_string(), then calls ngx_log_error(NGX_LOG_WARN) with prefix + sanitized path. Returns void (fire-and-forget log). Thread safety: uses local stack buffer — safe for concurrent use. */

/* ---- Path warning logger helper — sanitize and log path violations ----
 *
 * WHAT: Logs a security/warning message about a problematic path using sanitized output.
 *       Escapes control bytes, quotes, backslashes, non-ASCII characters via xrootd_sanitize_log_string()
 *       to prevent log injection attacks when logging suspicious paths. */

void
xrootd_log_path_warning(ngx_log_t *log, const char *prefix, const char *path)
{
    char safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));
    ngx_log_error(NGX_LOG_WARN, log, 0, "%s: %s", prefix, safe_path);
}

/* ---- Export root boundary enforcement — path-prefix attack prevention ----
 *
 * WHAT: Enforces that a canonicalized path stays within the configured export root directory.
 *       Returns 1 (true) if path_canon is exactly the root OR a direct descendant; returns 0 (false) otherwise.
 *
 * WHY: CRITICAL SECURITY — prevents `/export` from matching `/exportdata` or similar prefix attacks.
 *      The boundary character check ensures exact containment: only `/export/anything` matches `/export`, never `/exportdata`. */

/* ---- Path-prefix attack prevention mechanism ----
 *
 * WHAT: After checking string prefix match, validates that the next byte is either '/' (subdirectory) or '\0' (exact root).
 *       This prevents "/export" matching "/exportdata", "/atlas" matching "/atlasdata", etc. */

/* ---- Boundary character validation invariant ----
 *
 * WHY: Both arguments must be canonicalized absolute paths with no trailing slash (except when root is exactly "/"). */

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

/* ---- Function: xrootd_resolved_relative_to_root() ----
 *
 * WHAT: Converts an absolute resolved path into a relative form under root_canon, returning 0 (false) if resolved escapes root and -1 on buffer overflow. Sets errno = EXDEV when path escapes root, ENAMETOOLONG when relative portion exceeds relsz.
 *
 * WHY: Confined operations (openat2/openat/unlinkat/mkdirat/renameat/linkat) require a relative path under the parent fd — this helper strips the root prefix from the absolute resolved path to produce that relative form. Also validates confinement by checking xrootd_path_within_root() before stripping.
 *
 * HOW: 1) Check xrootd_path_within_root(root_canon, resolved); if false, log warning + set EXDEV + return 0; 2) Compute root_len = strlen(root_canon); 3) Determine src pointer: if root is / (len==1), src = resolved+1; if resolved equals root exactly, src = .; else src = resolved+root_len+1; 4) If *src == null after stripping, set src = . (target IS the root); 5) Compute rel_len = strlen(src), check rel_len < relsz; 6) Copy src into rel via ngx_memcpy with null terminator. Returns 1 on success. Thread safety: uses local stack buffer — safe for concurrent use. */

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

/* ---- Function: xrootd_open_root_fd() ----
 *
 * WHAT: Opens the export root directory using O_PATH flag — a non-access fd that can be used for subsequent openat2/openat calls. O_PATH | O_DIRECTORY ensures we get a directory handle without actually reading content; O_CLOEXEC prevents fd leakage on fork.
 *
 * WHY: Confined operations need an anchor fd pointing to the export root. O_PATH is a lightweight fd that only allows directory traversal (openat, fstat) without opening the file actual data — this minimizes resource usage and avoids locking issues when the root is actively accessed by other processes. The fd is returned to callers who must close it explicitly after use.
 *
 * HOW: Calls open(root_canon, O_PATH | O_DIRECTORY | O_CLOEXEC). On failure (fd < 0), logs warning with errno via ngx_log_error(NGX_LOG_WARN) and returns -1. Returns the fd on success. Thread safety: single syscall — safe for concurrent use. */

/* ---- Root file descriptor opening helper (O_PATH mode) ----
 *
 * WHAT: Opens the export root directory using O_PATH flag — a non-access fd that can be used for subsequent openat2/openat calls.
 *       O_PATH | O_DIRECTORY ensures we get a directory handle without actually reading content; O_CLOEXEC prevents fd leakage on fork. */

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
/* ---- openat2 kernel-level confinement — preferred Linux 5.6+ method ----
 *
 * WHAT: Wrapper around openat2(2) syscall that provides KERNEL-LEVEL path confinement via RESOLVE_BENEATH flag.
 *       The kernel itself refuses any path escaping rootfd's directory tree, including symlinks pointing outside it. */

/* ---- Kernel-level confinement mechanism (RESOLVE_BENEATH) ----
 *
 * WHAT: Instructs the Linux kernel to refuse ANY path that escapes rootfd's directory tree — including symlinks pointing outside.
 *       This is HARDER security than user-space checking because the kernel itself enforces containment, not nginx code. */

/* ---- Magic link blocking (RESOLVE_NO_MAGICLINKS) ----
 *
 * WHAT: Blocks /proc/<pid>/fd and similar kernel-magic symlinks that could be used to escape confinement via proc filesystem.
 *       These are special kernel-created symlinks that point to real objects — without this flag they could bypass containment. */

/* ---- Confinement method hierarchy (openat2 vs fallback) ----
 *
 * WHY: openat2 is the preferred/conferred method because it's KERNEL-ENFORCED (hard security).
 *      The fallback xrootd_open_confined_parent_fallback is used only when kernel doesn't support openat2 (ENOSYS/EINVAL/EOPNOTSUPP). */

/* ---- Confinement flag configuration for openat2 ----
 *
 * HOW: how.flags = flags | O_CLOEXEC; how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS.
 *      Mode bits only set when O_CREAT is requested in the original flags. syscall(SYS_openat2, rootfd, rel, &how, sizeof(how)). */

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

/* ---- Function: xrootd_openat2_runtime_available() ----
 *
 * WHAT: Probes whether the running kernel supports openat2(2). Returns 1 if available, 0 if not. Called once at worker init to determine whether to use kernel-level confinement (openat2) or user-space fallback (O_NOFOLLOW segment-by-segment).
 *
 * WHY: Even when compiled with XROOTD_HAVE_OPENAT2 (kernel headers present), the syscall may return ENOSYS on older kernels (e.g. RHEL8 / 4.18). Runtime probing ensures we do not attempt openat2 on kernels that genuinely lack support, avoiding unnecessary error logging from failed syscalls.
 *
 * HOW: If XROOTD_HAVE_OPENAT2 is defined, calls syscall(SYS_openat2, AT_FDCWD, ., how, sizeof(how)) with how.flags = O_PATH | O_CLOEXEC; if fd >= 0, closes it and returns 1; if fd < 0 and errno != ENOSYS (e.g. EPERM), returns 1 assuming kernel supports it but this specific call failed; if errno == ENOSYS, returns 0. If XROOTD_HAVE_OPENAT2 is not defined, returns 0. Thread safety: single syscall — safe for concurrent use. */

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

/* ---- Function: xrootd_open_dir_no_symlink() (static) ----
 *
 * WHAT: Opens a directory using O_NOFOLLOW flag to prevent symlink traversal during parent-directory navigation. Used in the fallback confinement method when openat2 is unavailable — follows each path segment step-by-step.
 *
 * WHY: The fallback confinement method opens each path segment individually with openat(). Without O_NOFOLLOW, a single symlink could escape the export root boundary (e.g., /data/atlas -> /outside). O_NOFOLLOW ensures each segment must be a real directory, preventing any symlink-based escape.
 *
 * HOW: Calls openat(parentfd, name, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW). Returns fd on success, -1 on failure. Thread safety: single syscall — safe for concurrent use. */

/* ---- No-symlink directory opening helper (O_NOFOLLOW mode) ----
 *
 * WHAT: Opens a directory using O_NOFOLLOW flag to prevent symlink traversal during parent-directory navigation.
 *       Used in the fallback confinement method when openat2 is unavailable — follows each path segment step-by-step. */

static int
xrootd_open_dir_no_symlink(int parentfd, const char *name)
{
    return openat(parentfd, name,
                  O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

/* ---- Function: xrootd_open_confined_parent_fallback() ----
 *
 * WHAT: Fallback confinement method when openat2 syscall is unavailable (ENOSYS/EINVAL/EOPNOTSUPP on older kernels). Navigates parent path segment-by-segment, opening each directory with O_NOFOLLOW to prevent symlink escapes. Returns a parent fd for subsequent operations.
 *
 * WHY: When kernel does not support openat2 RESOLVE_BENEATH, we must manually follow each path segment using openat + O_NOFOLLOW. This provides equivalent security (no symlink escape) but requires traversing every intermediate directory instead of the kernel doing it atomically via openat2.
 *
 * HOW: 1) If parent is empty or dot, dup(rootfd) and return; 2) Copy parent into scratch[PATH_MAX], check len < sizeof(scratch); 3) Dup rootfd to curfd (own copy for traversal); 4) Iterate through scratch splitting at each slash — null-terminate segment, call xrootd_path_component_forbidden(seg) on each component, call xrootd_open_dir_no_symlink(curfd, seg); 5) Close old fd, set curfd = new fd; 6) Continue until last segment (slash == NULL). Returns final curfd. Thread safety: uses local stack buffer — safe for concurrent use. */

/* ---- Parent directory fallback confinement — segment-by-segment navigation ----
 *
 * WHAT: Fallback confinement method when openat2 syscall is unavailable (ENOSYS/EINVAL/EOPNOTSUPP on older kernels).
 *       Navigates parent path segment-by-segment, opening each directory with O_NOFOLLOW to prevent symlink escapes. */

/* ---- Fallback confinement mechanism (segment-by-segment) ----
 *
 * WHY: When kernel doesn't support openat2 RESOLVE_BENEATH, we must manually follow each path segment using openat + O_NOFOLLOW.
 *      Each segment is opened with O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW — preventing symlink traversal at every step. */

/* ---- Fallback forbidden component check (xrootd_path_component_forbidden) ----
 *
 * WHAT: Before opening each path segment, checks if the component name is forbidden (e.g., "..", special names).
 *       Returns EACCES error if a forbidden component would allow traversal escape or unauthorized access. */

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

/* ---- Confined parent canonicalization helper — opens parent directory under confinement ----
 *
 * WHAT: Helper that converts a resolved path to relative form, splits into parent/base components, then opens parent directory using kernel-level confinement (openat2 or fallback).
 *       Returns a parent fd for subsequent operations on the file's base name. */

/* ---- Confined parent helper flow ----
 *
 * HOW: 1) xrootd_resolved_relative_to_root converts absolute path to relative; 
 *      2) xrootd_split_relative_parent splits rel into parent/base components;
 *      3) Opens root fd via O_PATH mode; uses openat2 or fallback for parent directory. */

