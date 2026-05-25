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

/* Helper declaration — defined in resolve_confined_helpers.c */
extern void xrootd_log_path_warning(ngx_log_t *log, const char *prefix, const char *path);

/*---- xrootd_resolve_path_noexist function — resolve path with non-existent trailing components ----
 *
 * WHAT: Resolve a path where zero or more trailing components may not yet exist (used for kXR_mkdir with kXR_mkdirpath).
 *       Walks reqpath segment by segment: existing components advance via realpath(3); non-existent ones appended literally. */

/*---- Path resolution mechanism for partial paths ----
 *
 * HOW: For each path segment: if lstat succeeds → call realpath() to canonicalize and check root boundary; 
 *      if ENOENT → append component literally after checking ".." traversal via xrootd_path_component_forbidden(). */

/*---- Path resolution security invariant (symlink escape detection) ----
 *
 * WHY: After each realpath(3) call, the result is checked against root via xrootd_path_within_root() to detect symlink escapes.
 *      This provides defence-in-depth — even if a symlink was introduced between segment traversal and realpath(), boundary check blocks it. */

/*---- Path resolution error handling ----
 *
 * WHAT: Returns 0 (failure) on path traversal attempt (forbidden component), nonexistent components beyond ENOENT, 
 *      too-long paths, or root boundary violation after realpath(). Logs NGX_LOG_WARN for traversal attempts via xrootd_log_path_warning(). */

/*---- Path resolution success postconditions ----
 *
 * WHY: Returns 1 (success) with resolved[0..n] being a NUL-terminated canonical absolute path within root where n < resolvsz. */

/*---- Path resolution function entry point ----
 *
 * WHAT: Called from src/read/open.c for mkdir operations when kXR_mkdirpath flag indicates deep directory creation is needed. Returns 1/0 success/failure. */

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

    /* Guard: reject paths with excessive component count before filesystem ops. */
    if (xrootd_count_path_depth(reqpath) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path depth exceeds limit");
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

/*---- xrootd_resolve_path function — standard existing path canonicalization ----
 *
 * WHAT: Resolve an EXISTING path within the export root using realpath(3) canonicalization. 
 *       reqpath is client-supplied (may start with '/'); all ".." and "." components rejected before realpath call. */

/*---- Existing path resolution mechanism ----
 *
 * HOW: 1) Strip leading '/' from reqpath; 2) Check each segment for forbidden components via xrootd_path_component_forbidden();
 *      3) Combine root_canon + reqpath → call realpath() to canonicalize and resolve symlinks; 
 *      4) Verify result within root boundary via xrootd_path_within_root(). */

/*---- Existing path resolution precondition ----
 *
 * WHY: All components of reqpath must EXIST on disk — realpath(3) requires existence. Use this for read operations where file already exists,
 *      NOT for write/PUT destinations (use xrootd_resolve_path_write() instead). */

/*---- Existing path resolution security invariant ----
 *
 * WHY: After realpath(3) call verifies canonicalization and symlink resolution, xrootd_path_within_root() ensures the result stays within export root.
 *      This provides defence-in-depth against symlink escapes that could redirect to unauthorized locations. */

/*---- Existing path resolution error handling ----
 *
 * WHAT: Returns 0 (failure) on any error — realpath NULL return, too-long paths, forbidden components, or root boundary violation.
 *      Logs NGX_LOG_WARN for traversal attempts via xrootd_log_path_warning(). */

/*---- Existing path resolution success postconditions ----
 *
 * WHY: Returns 1 (success) with resolved[0..n] being a NUL-terminated canonical absolute path within root where n < resolvsz. */

/*---- Existing path resolution function entry point ----
 *
 * WHAT: Called from src/read/open.c for standard file access operations where path must exist. Returns 1/0 success/failure. */

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

    /* Guard: reject paths with excessive component count before filesystem ops. */
    if (xrootd_count_path_depth(p) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path depth exceeds limit");
        return 0;
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

/*---- xrootd_resolve_path_write function — resolve write destination with non-existent final component ----
 *
 * WHAT: Resolve a write-destination path where the final component need not exist yet (e.g. PUT, kXR_open for write).
 *       Works around realpath(3) existence requirement by canonicalising parent directory then appending filename only after root check. */

/*---- Write destination resolution mechanism ----
 *
 * HOW: 1) Split reqpath into parent + filename components; 
 *      2) Call realpath() on parent directory (which must exist); verify parent within root boundary;
 *      3) Append filename component to canonicalized parent path without realpath call. */

/*---- Write destination resolution precondition ----
 *
 * WHY: reqpath must not be empty and must name a file, not a directory; the PARENT directory of reqpath must already exist.
 *      This is specifically for PUT/POST/write operations where the target file may not yet be created. */

/*---- Write destination resolution security invariant ----
 *
 * WHY: After realpath() canonicalizes parent directory and verifies it within root boundary, filename component is appended only after confirmation.
 *      This prevents symlink escapes that could redirect a write operation to unauthorized locations. */

/*---- Write destination resolution error handling ----
 *
 * WHAT: Returns 0 (failure) on any error — realpath NULL return for parent, too-long paths, forbidden components, or root boundary violation.
 *      Logs NGX_LOG_WARN for traversal attempts via xrootd_log_path_warning(). */

/*---- Write destination resolution success postconditions ----
 *
 * WHY: Returns 1 (success) with resolved[0..n] being a NUL-terminated path within root where n < resolvsz — parent canonicalized + filename appended. */

/*---- Write destination resolution function entry point ----
 *
 * WHAT: Called from src/read/open.c for kXR_open write mode operations when target file may not exist yet. Returns 1/0 success/failure. */

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

    /* Guard: reject paths with excessive component count before filesystem ops. */
    if (xrootd_count_path_depth(reqpath) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path depth exceeds limit");
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
