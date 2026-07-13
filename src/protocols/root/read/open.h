#ifndef BRIX_READ_OPEN_H
#define BRIX_READ_OPEN_H
/*
 * kXR_open (3012) — file handle lifecycle initiation.

 * Exported:
 *   brix_handle_open()       — Implements the open opcode: parses ClientOpenRequest
 *     from wire, resolves path via brix_resolve_path(), checks VO ACL and token scope,
 *     detects write-mode vs read-mode, opens file with appropriate flags, allocates fhandle
 *     slot in fd_table.c, returns retstat body.

 *   brix_open_resolved_file() — Opens a pre-resolved path: allocates fhandle via
 *     brix_alloc_fhandle(), open(2) with write-mode detection and TPC flag check,
 *     sends retstat response. Flags=0 for cache reads, flags=1 for write opens.

 *   brix_open_cached_read()  — Cache-aware read-open: resolves against auth root for ACL
 *     check, then tries cache root (hit → direct serve) or triggers background origin fill
 *     on miss via brix_cache_open_or_fill(). Implements XCache-style caching.

 * See also: src/read/open.c (full implementation), src/read/README.md (read module overview).
 */

#include "core/ngx_brix_module.h"

/*
 * kXR_open dispatch entry point. Parses ClientOpenRequest from ctx->recv.hdr_buf,
 * derives read/write mode from option flags, strips CGI/opaque, detects TPC
 * roles, resolves+confines the path, runs VO ACL + token-scope auth gates, then
 * either redirects (manager_mode / manager_map / upstream), delegates to the
 * cache path, or calls brix_open_resolved_file(). Always emits exactly one
 * wire response (open body or error); returns that send's result (NGX_OK on
 * queued reply, NGX_ERROR on fatal connection error) — on auth/path failures it
 * returns ctx->write_rc from the queued error frame, never a bare errno.
 */
ngx_int_t brix_handle_open(brix_ctx_t *ctx, ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf);
/*
 * Perform the POSIX open(2) for an already-resolved absolute path and reply.
 * The open intent (path/options/mode/write-classification/codec) arrives as a
 * borrowed brix_open_request_t (fields documented on the struct below).
 * Translates options/mode_bits to oflags+create mode, stages a POSC temp file
 * when kXR_posc is set on a write, opens confined (non-cache) or O_CLOEXEC
 * (cache), allocates an fd_table slot (0-255) and seeds per-handle bookkeeping,
 * then queues the ServerOpenBody (+retstat if kXR_retstat). Returns the wire
 * send result (NGX_OK / NGX_ERROR); fd-table exhaustion or open failure is
 * reported as a kXR error frame, not a return code.
 */
/*
 * brix_open_request_t — the caller-supplied kXR_open intent for
 * brix_open_resolved_file() (phase-73 parameter consolidation).
 *
 * resolved:  borrowed NUL-terminated canonical absolute path (not owned; safe
 *            to free after return).
 * options:   raw kXR_open option bits from the wire request.
 * mode_bits: XRootD create-mode bits (Unix permission bits in the low 9 bits;
 *            0 defaults to 0644 on a creating open).
 * is_write:  caller's read/write classification — also used as the
 *            cache-source flag when 0 (callers pass 0 for cache-served reads).
 * codec (phase-42 W4/W5): negotiated inline-compression codec ordinal
 *   (brix_codec_id_t cast to uint8_t).  0 = no compression (the default, byte-
 *   identical path).  Non-zero is honoured only for a regular file and stored in
 *   the direction-appropriate handle slot — read_codec on a read open (W4,
 *   compress kXR_read responses), write_codec on a write open (W5, decompress
 *   kXR_write payloads) — and signalled to the client via the kXR_open reply
 *   cpsize/cptype.  Cache-served reads pass 0.
 */
typedef struct {
    const char  *resolved;
    uint16_t     options;
    uint16_t     mode_bits;
    ngx_flag_t   is_write;
    uint8_t      codec;
} brix_open_request_t;
ngx_int_t brix_open_resolved_file(brix_ctx_t *ctx, ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf, const brix_open_request_t *req);
/*
 * Cache-aware read-open (XCache style). clean_path: borrowed root-relative
 * logical path (CGI already stripped). Checks the VO ACL against the auth root
 * first; on cache hit (stat of cache_root path succeeds) serves directly via
 * brix_open_resolved_file(); on miss triggers a background origin fill via
 * brix_cache_open_or_fill(); with slice caching configured serves through the
 * unified sd_cache partial decorator (§6.5). Returns the chosen path's result
 * (NGX_OK / NGX_ERROR); ACL denial and path-length errors become kXR error
 * frames.
 */
ngx_int_t brix_open_cached_read(brix_ctx_t *ctx, ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf, const char *clean_path, uint16_t options, uint16_t mode_bits);

#endif // BRIX_READ_OPEN_H
