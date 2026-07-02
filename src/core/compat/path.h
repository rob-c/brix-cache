/*
 * path.h — shared path constants and URI-to-filesystem path resolver.
 *
 * Pure C, no nginx headers.
 */

#ifndef XROOTD_COMPAT_PATH_H
#define XROOTD_COMPAT_PATH_H

#include <stddef.h>

/*
 * XROOTD_PATH_MAX — maximum filesystem path length accepted from any client.
 *
 * Both the XRootD stream protocol and the HTTP (WebDAV/S3) protocol layers
 * enforce this limit before expensive syscalls (realpath, open).  Setting it
 * equal to the Linux PATH_MAX (4096) ensures buffers declared as
 * char buf[XROOTD_PATH_MAX] can always hold a NUL-terminated kernel path.
 *
 * Protocol-specific aliases XROOTD_MAX_PATH (stream) and WEBDAV_MAX_PATH
 * (HTTP) are defined in their respective headers as macros that expand to
 * this value so a single change here propagates everywhere.
 */
#define XROOTD_PATH_MAX  4096

/*
 * XROOTD_PATH_MIN — minimum valid path length (inclusive).
 *
 * An absolute path must contain at least one character ("/").  The stream
 * path extractor and HTTP path resolver both reject zero-length paths;
 * this constant makes that threshold explicit and searchable.
 */
#define XROOTD_PATH_MIN  1

/*
 * WHAT: Resolve a pre-decoded URI path within root_canon into a confined filesystem path.
 *       Returns 0 on success; an HTTP status code on failure (see below).
 *
 * WHY: WebDAV and S3 PUT handlers both need canonicalization, dot/dotdot rejection,
 *      root confinement verification, and ENOENT-parent handling for new-file paths.
 *      Centralising this logic ensures consistent behaviour across protocols.
 *
 * HOW: Reject "." or ".." components → 403. Build candidate = root_canon + decoded_path.
 *       Call realpath() to canonicalize. If realpath succeeds, verify confinement under
 *       root_canon (strncmp + boundary check). If realpath fails with ENOENT, walk up
 *       the path finding the deepest existing ancestor within root_canon and append the
 *       non-existent suffix. Copy resolved into out buffer after size check.
 *
 * Input constraints: decoded_path must be percent-decoded and start with '/'.
 * Trailing slashes should be stripped by the caller before calling here.
 *
 * Return codes on failure:
 *   400  malformed input (empty filename, no slash in candidate)
 *   403  path traversal detected or resolved path outside root
 *   404  parent directory cannot be resolved (target does not exist)
 *   414  path too long (candidate/resolved exceeds PATH_MAX or outsz)
 *   500  realpath(3) failed for an unexpected reason (not ENOENT)
 *
 * The caller must map 400/404 to the appropriate protocol-level status;
 * for WebDAV COPY/MOVE destinations, 404 should be returned as 409 Conflict.
 */
int xrootd_http_resolve_path(const char *root_canon, const char *decoded_path,
    char *out, size_t outsz);

#endif /* XROOTD_COMPAT_PATH_H */
