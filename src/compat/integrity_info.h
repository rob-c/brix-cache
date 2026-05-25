#ifndef XROOTD_INTEGRITY_INFO_H
#define XROOTD_INTEGRITY_INFO_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "checksum.h"

/*
 * xrootd_integrity_info_t — result of a checksum lookup or computation.
 *
 *   alg        parsed algorithm enum
 *   alg_name   canonical lowercase algorithm name (e.g. "adler32", "crc32c")
 *   hex        lowercase hex-encoded checksum value, NUL-terminated
 *   from_cache 1 when the value was read from the xattr cache
 */
typedef struct {
    xrootd_checksum_alg_t alg;
    char                  alg_name[16];
    char                  hex[129];
    ngx_flag_t            from_cache;
} xrootd_integrity_info_t;

/*
 * xrootd_integrity_opts_t — caller-supplied policy for integrity lookup.
 *
 *   allow_xattr_cache    1 → try reading a cached checksum from xattr first
 *   update_xattr_cache   1 → write computed checksum back to xattr on cache miss
 *   require_regular_file 1 → fail with NGX_DECLINED if fd is not a regular file
 */
typedef struct {
    ngx_flag_t allow_xattr_cache;
    ngx_flag_t update_xattr_cache;
    ngx_flag_t require_regular_file;
} xrootd_integrity_opts_t;

/*
 * xrootd_integrity_get_fd — retrieve a checksum for an open file descriptor.
 *
 * If opts->allow_xattr_cache is set, tries reading a cached value from a
 * "user.XrdCks.<alg>" extended attribute before computing.  On a cache miss,
 * computes the checksum and, when opts->update_xattr_cache is also set, writes
 * the result back to the xattr for future lookups.
 *
 * When opts->require_regular_file is set the function calls fstat(2) on fd and
 * returns NGX_DECLINED immediately if the file is not a regular file.
 *
 * Returns NGX_OK and fills *out on success.
 * Returns NGX_DECLINED when the file is not regular and require_regular_file=1.
 * Returns NGX_ERROR on algorithm parse failure or I/O error.
 *
 * opts may be NULL; NULL is treated as {allow_xattr_cache=1, update_xattr_cache=1,
 * require_regular_file=0}.
 */
ngx_int_t xrootd_integrity_get_fd(ngx_log_t *log, int fd,
    const char *path, const char *alg_name,
    const xrootd_integrity_opts_t *opts,
    xrootd_integrity_info_t *out);

/*
 * xrootd_integrity_format_http_digest — format a Digest header value.
 *
 * Writes "alg_name=hexvalue" into out[0..outsz), suitable for the HTTP Digest
 * response header (RFC 3230 / XrdHttp want-digest convention).
 *
 * Returns NGX_OK on success, NGX_ERROR if the buffer is too small.
 */
ngx_int_t xrootd_integrity_format_http_digest(
    const xrootd_integrity_info_t *info,
    char *out, size_t outsz);

/*
 * xrootd_integrity_invalidate_fd — remove all cached checksums for an fd.
 *
 * Removes "user.XrdCks.<alg>" xattrs for every supported algorithm.  Should
 * be called after any write, truncate, or rename that changes file content.
 * Ignores errors (the cache is advisory).
 */
void xrootd_integrity_invalidate_fd(ngx_log_t *log, int fd);

/*
 * xrootd_integrity_invalidate_path — remove all cached checksums by path.
 *
 * Path-based variant of xrootd_integrity_invalidate_fd for callers that have
 * a path but not an open fd (e.g. after a rename or local copy commit).
 */
void xrootd_integrity_invalidate_path(ngx_log_t *log, const char *path);

#endif /* XROOTD_INTEGRITY_INFO_H */
