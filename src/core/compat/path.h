/*
 * path.h — shared path constants and URI-to-filesystem path resolver.
 *
 * Pure C, no nginx headers.
 */

#ifndef BRIX_COMPAT_PATH_H
#define BRIX_COMPAT_PATH_H

#include <stddef.h>

/*
 * BRIX_PATH_MAX — maximum filesystem path length accepted from any client.
 *
 * Both the XRootD stream protocol and the HTTP (WebDAV/S3) protocol layers
 * enforce this limit before expensive syscalls (realpath, open).  Setting it
 * equal to the Linux PATH_MAX (4096) ensures buffers declared as
 * char buf[BRIX_PATH_MAX] can always hold a NUL-terminated kernel path.
 *
 * Protocol-specific aliases BRIX_MAX_PATH (stream) and WEBDAV_MAX_PATH
 * (HTTP) are defined in their respective headers as macros that expand to
 * this value so a single change here propagates everywhere.
 */
#define BRIX_PATH_MAX  4096

/*
 * BRIX_PATH_MIN — minimum valid path length (inclusive).
 *
 * An absolute path must contain at least one character ("/").  The stream
 * path extractor and HTTP path resolver both reject zero-length paths;
 * this constant makes that threshold explicit and searchable.
 */
#define BRIX_PATH_MIN  1

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
 *
 * This is a thin wrapper over brix_http_resolve_path_ex() with allow_internal=0
 * — the default-deny behaviour every normal client surface requires.
 */
int brix_http_resolve_path(const char *root_canon, const char *decoded_path,
    char *out, size_t outsz);

/*
 * WHAT: Same as brix_http_resolve_path(), plus an allow_internal switch. When
 *       allow_internal is non-zero the internal-name → 404 guard is skipped so a
 *       reserved sidecar/staging name (<key>.cinfo, .meta, stage markers, upload
 *       temps) resolves normally; all other validation (NULL→403, depth/dotdot→403,
 *       overflow→414) is identical and still runs. Returns 0 or an HTTP status.
 *
 * WHY:  A remote WebDAV/S3 cache-STORE endpoint legitimately PUTs and later GETs a
 *       <key>.cinfo sidecar over the same HTTP surface, so on a location explicitly
 *       configured as a trusted store (brix_cache_store_endpoint on) the reserved
 *       name must be a valid target — while every normal client location keeps
 *       allow_internal=0 and the reserved name stays invisible (404). The switch is
 *       an explicit per-location opt-in, so default-deny is preserved everywhere.
 *
 * HOW:  Runs the NULL/depth/forbidden-component checks, then the internal-name
 *       check ONLY when allow_internal is zero, then the lexical confined join.
 */
int brix_http_resolve_path_ex(const char *root_canon, const char *decoded_path,
    char *out, size_t outsz, unsigned allow_internal);

#endif /* BRIX_COMPAT_PATH_H */
