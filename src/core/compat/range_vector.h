/*
 * range_vector.h — shared byte-range parsing, validation, and coalescing.
 *
 * Unifies range handling across:
 *   - XrdHttp multipart/byteranges GET   (src/webdav/xrdhttp_multipart.c)
 *   - HTTP single-range responses        (src/compat/range.c)
 *   - Native kXR_readv coalescing        (src/read/readv.c)
 *
 * Serialisation (multipart MIME boundaries, wire headers, ngx_chain_t
 * construction) stays protocol-specific; this layer handles only:
 *   1. Parsing comma-separated HTTP byte ranges.
 *   2. Summing and validating total response size.
 *   3. Finding runs of contiguous ranges for I/O coalescing.
 */

#ifndef BRIX_RANGE_VECTOR_H
#define BRIX_RANGE_VECTOR_H

#include <ngx_http.h>

/*
 * brix_byte_range_t — a normalised, inclusive byte interval.
 *
 * start, end:  byte offsets, both inclusive.  Always start ≤ end after
 *              successful parse; end < file_size.
 * fd:          optional open file descriptor for I/O planning (-1 if unused)
 * handle:      optional native kXR_readv file handle (0 if unused)
 */
typedef struct {
    off_t      start;
    off_t      end;
    int        fd;
    ngx_uint_t handle;
} brix_byte_range_t;

/*
 * brix_range_vector_opts_t — caller-supplied policy for the parser.
 *
 * max_ranges:          hard cap on number of entries stored (extra silently dropped)
 * max_total_bytes:     0 → no limit; non-zero → reject vectors exceeding this
 * allow_suffix:        1 → accept "-N" suffix ranges
 * allow_open_ended:    1 → accept "A-" ranges (end mapped to file_size−1)
 * drop_unsatisfiable:  1 → silently skip bad ranges; 0 → return NGX_ERROR
 */
typedef struct {
    ngx_uint_t max_ranges;
    off_t      max_total_bytes;
    ngx_flag_t allow_suffix;
    ngx_flag_t allow_open_ended;
    ngx_flag_t drop_unsatisfiable;
} brix_range_vector_opts_t;

/*
 * brix_http_parse_range_vector — parse a HTTP byte-ranges header value.
 *
 * data/len:  the header value WITHOUT the leading "bytes=" prefix.
 *            Callers must skip past "bytes=" before calling.
 * file_size: the resource length; used to normalise suffix and open-ended
 *            ranges and to drop unsatisfiable ones.
 * opts:      parsing policy (see brix_range_vector_opts_t above).
 * ranges:    caller-supplied array of at least opts->max_ranges entries.
 * nranges:   set to the number of valid ranges stored.
 *
 * Returns NGX_OK on success (nranges may be 0 if all ranges were dropped).
 * Returns NGX_ERROR if opts->drop_unsatisfiable is 0 and a bad range is seen.
 */
ngx_int_t brix_http_parse_range_vector(const u_char *data, size_t len,
    off_t file_size, const brix_range_vector_opts_t *opts,
    brix_byte_range_t *ranges, ngx_uint_t *nranges);

/*
 * brix_range_vector_validate_total — sum total response bytes, check cap.
 *
 * Returns NGX_OK and sets *total_out to the aggregate byte count.
 * Returns NGX_ERROR on overflow or if the sum exceeds max_total_bytes.
 */
ngx_int_t brix_range_vector_validate_total(
    const brix_byte_range_t *ranges, ngx_uint_t nranges,
    off_t max_total_bytes, off_t *total_out);

/*
 * brix_range_vector_next_coalesced_run — find a run of contiguous ranges.
 *
 * Starting at ranges[start_index], returns the count of entries that form a
 * contiguous run (i.e. ranges[i].end + 1 == ranges[i+1].start and the same
 * fd when fd != -1), capped at max_iov entries.  Returns at least 1.
 */
ngx_uint_t brix_range_vector_next_coalesced_run(
    const brix_byte_range_t *ranges, ngx_uint_t nranges,
    ngx_uint_t start_index, ngx_uint_t max_iov);

#endif /* BRIX_RANGE_VECTOR_H */
