#ifndef BRIX_INTEGRITY_INFO_H
#define BRIX_INTEGRITY_INFO_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "checksum.h"
#include "fs/vfs/vfs_policy.h"   /* brix_vfs_mutation_policy_t (phase-105) */

/*
 * brix_integrity_info_t — result of a checksum lookup or computation.
 *
 *   alg        parsed algorithm enum
 *   alg_name   canonical lowercase algorithm name (e.g. "adler32", "crc32c")
 *   hex        lowercase hex-encoded checksum value, NUL-terminated
 *   from_cache 1 when the value was read from the xattr cache
 */
typedef struct {
    brix_checksum_alg_t alg;
    char                  alg_name[16];
    char                  hex[129];
    ngx_flag_t            from_cache;
} brix_integrity_info_t;

/*
 * brix_integrity_opts_t — caller-supplied policy for integrity lookup.
 *
 *   allow_xattr_cache    1 → try reading a cached checksum from xattr first
 *   update_xattr_cache   1 → write computed checksum back to xattr on cache miss
 *   require_regular_file 1 → fail with NGX_DECLINED if fd is not a regular file
 *   no_compute           1 → cache-only: return NGX_DECLINED on a cache miss
 *                            instead of computing (avoids a full-file read on a
 *                            latency-sensitive path, e.g. S3 GET/HEAD echo)
 *   mutation_policy      the ENDPOINT's phase-105 write posture. Persisting a
 *                        computed checksum writes an xattr (or a §8.2 record)
 *                        ONTO THE EXPORT OBJECT, so it is a mutation like any
 *                        other and is refused on a read-only export — the
 *                        request still gets its checksum, it is just recomputed
 *                        next time. This unit has no request context (it is
 *                        reached from thread-pool workers and the scanner), so
 *                        the caller carries the policy here as a value.
 *                        ZERO IS READ_ONLY: a caller that forgets it loses the
 *                        cache write, never the other way round.
 *   proto                protocol label for the refusal metric only.
 */
typedef struct {
    ngx_flag_t                 allow_xattr_cache;
    ngx_flag_t                 update_xattr_cache;
    ngx_flag_t                 require_regular_file;
    ngx_flag_t                 no_compute;
    brix_vfs_mutation_policy_t mutation_policy;
    brix_proto_t               proto;
} brix_integrity_opts_t;

/*
 * brix_integrity_get_fd — retrieve a checksum for an open file descriptor.
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
 * require_regular_file=0, mutation_policy=READ_ONLY} — a caller that supplies no
 * policy gets the cache READ but not the cache WRITE (phase-105 fail-closed).
 *
 * Layer 3: `obj` is the open file's storage-driver object, or NULL. When non-NULL
 * and obj->driver != NULL the checksum is COMPUTED by reading the whole logical
 * object through the driver (block-striped / object backend) instead of the bare
 * fd (which exposes only block 0). NULL keeps the default POSIX-fd compute. The
 * xattr/sidecar cache layer is unchanged (keyed on fd/path).
 */
ngx_int_t brix_integrity_get_fd(ngx_log_t *log, int fd,
    brix_sd_obj_t *obj, const char *path, const char *alg_name,
    const brix_integrity_opts_t *opts,
    brix_integrity_info_t *out);

/*
 * brix_integrity_seed_fd — record an ALREADY-PROVEN digest without reading a byte.
 *
 * The producer side of the cache layer brix_integrity_get_fd consults first. A
 * caller that has just verified `hex` over exactly the bytes behind `fd` (a cache
 * fill comparing the origin's advertised checksum against the recomputed part) can
 * hand the value over here instead of leaving the first kXR_Qcksum / Want-Digest
 * request on the cached copy to re-read the whole file.
 *
 * `alg_name` is canonicalised the same way get_fd canonicalises it, so a seed
 * written as "SHA256" is found by a lookup for "sha256", and one written as
 * "crc64xz" by a lookup for "crc64". (The same parser also REJECTS a spelling
 * that is not purely alphanumeric, "sha-256" among them.) `hex` is validated as
 * non-empty pure hex and lowercased before it is stored: this API records an
 * assertion about file content, so a malformed or over-long value is REFUSED
 * (NGX_ERROR) rather than truncated into a digest nobody can verify. `path` is the
 * file's local path for the §8.2 record fallback on filesystems without user
 * xattrs, or NULL to attempt the xattr only.
 *
 * Best-effort by contract: NGX_OK means the value was accepted and the write was
 * attempted, never that a particular cache layer holds it. A lost seed costs a
 * recompute, never a wrong answer.
 */
ngx_int_t brix_integrity_seed_fd(int fd, const char *path,
    const char *alg_name, const char *hex);

/*
 * brix_integrity_format_http_digest — format a Digest header value.
 *
 * Writes "alg_name=hexvalue" into out[0..outsz), suitable for the HTTP Digest
 * response header (RFC 3230 / XrdHttp want-digest convention).
 *
 * Returns NGX_OK on success, NGX_ERROR if the buffer is too small.
 */
ngx_int_t brix_integrity_format_http_digest(
    const brix_integrity_info_t *info,
    char *out, size_t outsz);

/*
 * brix_integrity_invalidate_fd — remove all cached checksums for an fd.
 *
 * Removes "user.XrdCks.<alg>" xattrs for every supported algorithm.  Should
 * be called after any write, truncate, or rename that changes file content.
 * Ignores errors (the cache is advisory).
 */
void brix_integrity_invalidate_fd(ngx_log_t *log, int fd);

/*
 * brix_integrity_invalidate_path — remove all cached checksums by path.
 *
 * Path-based variant of brix_integrity_invalidate_fd for callers that have
 * a path but not an open fd (e.g. after a rename or local copy commit). The
 * removal is routed through the VFS xattr seam, so root_canon (the export root
 * the path is confined to) is required.
 */
void brix_integrity_invalidate_path(ngx_log_t *log, const char *root_canon,
    const char *path);

/*
 * brix_cksdata_encode / brix_cksdata_decode — official XrdCks/XrdCksData binary
 * codec (§8.1 interop), host byte order (ADR-4). encode writes
 * sizeof(struct xrd_cks_data) bytes (88 on x86-64) from in->alg_name/in->hex +
 * fmtime, returning the record size (0 on bad hex). decode parses a record,
 * validating fmTime against cur_mtime (pass 0 to skip the staleness check);
 * returns 1 with *out filled, or 0 if the buffer is the wrong size / stale /
 * malformed. Used by the xattr reader (read stock checksums) and reusable by the
 * .cks sidecar and cache cinfo (§9).
 */
size_t brix_cksdata_encode(const brix_integrity_info_t *in, time_t fmtime,
    unsigned char *out88);
int brix_cksdata_decode(const unsigned char *buf, size_t len, time_t cur_mtime,
    brix_integrity_info_t *out);

/*
 * §8.x checksum xattr WRITE format (process-global, set at config time). The
 * reader always accepts either form; this only chooses what we WRITE to
 * "user.XrdCks.<alg>". One value per key, so "both" is not representable —
 * `xrdcks` is the stock-interoperable choice. Default TEXT (no behaviour change).
 */
#define BRIX_CKS_FMT_TEXT    0   /* "<hex> <mtime_sec> <mtime_nsec> <size>" */
#define BRIX_CKS_FMT_XRDCKS  1   /* binary XrdCksData (read by stock xrdfs/OSS) */
void brix_integrity_set_xattr_format(ngx_uint_t fmt);

#endif /* BRIX_INTEGRITY_INFO_H */
