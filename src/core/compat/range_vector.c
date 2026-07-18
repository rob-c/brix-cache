/*
 * range_vector.c — shared byte-range parsing, validation, and coalescing.
 *
 * See range_vector.h for the public API.
 */

#include "range_vector.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ---- range_vector_reject — map a rejected component to its return code. ----
 *
 * WHAT: Returns NGX_DECLINED when opts->drop_unsatisfiable is set (skip the
 *       component and continue), otherwise NGX_ERROR (abort the whole header).
 *
 * WHY: A malformed or unsatisfiable component is rejected identically from a
 *      dozen sites in the parser. Centralising the policy branch keeps every
 *      call site a single early-return and holds the accept/reject contract in
 *      exactly one place, so it cannot drift between the suffix and explicit
 *      paths.
 *
 * HOW:
 *      1. Branch on opts->drop_unsatisfiable and return the matching code.
 */
static ngx_int_t
range_vector_reject(const brix_range_vector_opts_t *opts)
{
    return opts->drop_unsatisfiable ? NGX_DECLINED : NGX_ERROR;
}

/* ---- range_vector_parse_suffix — parse a suffix component "-N". ----
 *
 * WHAT: Interprets "-N" as the last N bytes of the file and writes the
 *       normalised [*start_out, *last_out] window. Returns NGX_OK on success,
 *       or range_vector_reject(opts) when suffix ranges are disallowed or N is
 *       non-positive/unparseable.
 *
 * WHY: The suffix form has offset semantics distinct from an explicit range —
 *      N counts back from EOF — so isolating it keeps that arithmetic (and its
 *      clamp) out of the explicit path.
 *
 * HOW:
 *      1. Reject when opts->allow_suffix is unset.
 *      2. Parse N from just past the dash; reject when N <= 0 (also covers the
 *         ngx_atoof -1 parse-failure sentinel).
 *      3. Clamp N to file_size so a suffix larger than the file spans it whole.
 *      4. Emit last = file_size - 1 and start = file_size - N.
 */
static ngx_int_t
range_vector_parse_suffix(const u_char *dash, const u_char *comma,
    off_t file_size, const brix_range_vector_opts_t *opts,
    off_t *start_out, off_t *last_out)
{
    off_t start;

    if (!opts->allow_suffix) {
        return range_vector_reject(opts);
    }

    start = (off_t) ngx_atoof((u_char *)(dash + 1), comma - (dash + 1));
    if (start < 0) {   /* covers the ngx_atoof -1 parse-failure sentinel */
        return range_vector_reject(opts);
    }

    /* A well-formed zero-length suffix ("-0") is grammatically valid but
     * unsatisfiable; let it flow through as start = file_size so the final
     * bounds gate in range_vector_parse_one classifies it as unsatisfiable
     * (not a malformed grammar error). */
    if (start > file_size) {
        start = file_size;
    }

    *last_out  = file_size - 1;
    *start_out = file_size - start;
    return NGX_OK;
}

/* ---- range_vector_parse_explicit — parse an explicit component "A-" or "A-B". ----
 *
 * WHAT: Parses the start offset A and either an open-ended end (to EOF) or an
 *       explicit end B, writing [*start_out, *last_out]. Returns NGX_OK on
 *       success, or range_vector_reject(opts) when A or B is unparseable or the
 *       open-ended form is disallowed.
 *
 * WHY: Separated from the suffix path because start is always the literal A
 *      here (no EOF-relative arithmetic), and the open-ended vs. bounded end is
 *      a self-contained sub-decision.
 *
 * HOW:
 *      1. Parse A from [p, dash); reject when negative (covers the ngx_atoof
 *         -1 parse-failure sentinel).
 *      2. If the dash is the last byte ("A-"): reject when open-ended ranges
 *         are disallowed, else set last = file_size - 1.
 *      3. Otherwise parse B; reject when negative, then clamp B to the last
 *         valid byte when it runs past EOF.
 *      4. Emit start = A and last = the resolved end.
 */
static ngx_int_t
range_vector_parse_explicit(const u_char *p, const u_char *dash,
    const u_char *comma, off_t file_size,
    const brix_range_vector_opts_t *opts,
    off_t *start_out, off_t *last_out)
{
    off_t start, last;

    start = (off_t) ngx_atoof((u_char *) p, dash - p);
    if (start < 0) {   /* covers the NGX_ERROR (-1) parse-failure sentinel */
        return range_vector_reject(opts);
    }

    if (dash + 1 == comma) {
        /* Open-ended range: "A-" means from A to EOF. */
        if (!opts->allow_open_ended) {
            return range_vector_reject(opts);
        }
        last = file_size - 1;
    } else {
        last = (off_t) ngx_atoof((u_char *)(dash + 1), comma - (dash + 1));
        if (last < 0) {   /* covers the NGX_ERROR (-1) parse-failure sentinel */
            return range_vector_reject(opts);
        }
        if (last >= file_size) {
            last = file_size - 1;
        }
    }

    *start_out = start;
    *last_out  = last;
    return NGX_OK;
}

/* ---- range_vector_parse_one — parse a single byte-range component [p, comma). ----
 *
 * WHAT: Splits the component by '-' (suffix "-N", open-ended "A-", or "A-B"),
 *       normalises the offsets against file_size, and on a satisfiable range
 *       fills *out. Returns NGX_OK when a range was stored, NGX_DECLINED to
 *       skip a malformed/unsatisfiable component (when opts->drop_unsatisfiable
 *       is set), or NGX_ERROR for the same conditions when dropping is disabled.
 *
 * WHY: One place resolves a raw component into a validated byte range so both
 *      the suffix and explicit forms share the same final satisfiability gate
 *      and the same reject policy.
 *
 * HOW:
 *      1. Locate the '-' separator; reject when the component has none.
 *      2. Dispatch to the suffix helper when the dash is leading, else the
 *         explicit helper; propagate any non-OK return unchanged (grammar
 *         error -> *fail = MALFORMED).
 *      3. Reject a well-formed range that falls out of the file bounds
 *         (start >= file_size) as *fail = UNSATISFIABLE; a reversed span
 *         (start > last) is a malformed byte-range-spec (RFC 9110 §14.1.2).
 *      4. Fill *out (fd/handle cleared) and return NGX_OK.
 */
static ngx_int_t
range_vector_parse_one(const u_char *p, const u_char *comma, off_t file_size,
    const brix_range_vector_opts_t *opts, brix_byte_range_t *out,
    brix_range_fail_e *fail)
{
    const u_char *dash;
    off_t         start = 0, last = 0;
    ngx_int_t     rc;

    *fail = BRIX_RANGE_FAIL_MALFORMED;

    /* Find dash within this range component. */
    dash = ngx_strlchr((u_char *) p, (u_char *) comma, '-');
    if (dash == NULL) {
        return range_vector_reject(opts);
    }

    if (p == dash) {
        rc = range_vector_parse_suffix(dash, comma, file_size, opts,
            &start, &last);
    } else {
        rc = range_vector_parse_explicit(p, dash, comma, file_size, opts,
            &start, &last);
    }
    if (rc != NGX_OK) {
        return rc;
    }

    /* A well-formed range that begins past EOF is unsatisfiable (416); a
     * reversed span (start > last) is a malformed specifier (ignore -> 200). */
    if (start >= file_size) {
        *fail = BRIX_RANGE_FAIL_UNSATISFIABLE;
        return range_vector_reject(opts);
    }
    if (start < 0 || start > last) {
        return range_vector_reject(opts);
    }

    *fail = BRIX_RANGE_FAIL_NONE;
    out->start  = start;
    out->end    = last;
    out->fd     = -1;
    out->handle = 0;
    return NGX_OK;
}

/*
 * brix_http_parse_range_vector — parse a HTTP byte-ranges header value.
 *
 * WHAT: Parses a comma-separated list of byte ranges (e.g. "0-499, -500, 9500-")
 *       and normalises them against file_size. Handles suffix and open-ended
 *       ranges according to opts policy.
 * WHY: Both XrdHttp (multipart) and single-range HTTP responses need the same
 *      range validation and overflow detection. Centralising this avoids
 *      divergent behavior between protocol surfaces.
 * HOW: Iterates through comma-separated tokens. For each token:
 *      1. Splits by '-'.
 *      2. Handles suffix ranges (no start digit).
 *      3. Handles open-ended ranges (no end digit).
 *      4. Normalises offsets against file_size.
 *      5. Detects unsatisfiable ranges (start >= file_size or start > end).
 */
ngx_int_t
brix_http_parse_range_vector(const u_char *data, size_t len,
    off_t file_size, const brix_range_vector_opts_t *opts,
    brix_byte_range_t *ranges, ngx_uint_t *nranges, brix_range_fail_e *fail)
{
    const u_char     *p, *end, *comma;
    ngx_uint_t        n = 0;
    brix_range_fail_e why = BRIX_RANGE_FAIL_NONE;

    p   = data;
    end = data + len;

    while (p < end && n < opts->max_ranges) {
        ngx_int_t rc;

        /* Skip leading whitespace. */
        while (p < end && *p == ' ') p++;
        if (p >= end) break;

        /* Find next comma. */
        comma = ngx_strlchr((u_char *) p, (u_char *) end, ',');
        if (comma == NULL) {
            comma = end;
        }

        rc = range_vector_parse_one(p, comma, file_size, opts, &ranges[n],
                                    &why);
        if (rc == NGX_ERROR) {
            if (fail != NULL) {
                *fail = why;
            }
            return NGX_ERROR;
        }
        if (rc == NGX_OK) {
            n++;
        }
        /* NGX_DECLINED → unsatisfiable component dropped; just advance. */

        p = comma + 1;
    }

    if (fail != NULL) {
        *fail = BRIX_RANGE_FAIL_NONE;
    }
    *nranges = n;
    return NGX_OK;
}

ngx_int_t
brix_range_vector_validate_total(
    const brix_byte_range_t *ranges, ngx_uint_t nranges,
    off_t max_total_bytes, off_t *total_out)
{
    off_t      total = 0;
    ngx_uint_t i;

    for (i = 0; i < nranges; i++) {
        off_t len = ranges[i].end - ranges[i].start + 1;

        /* Check for integer overflow in sum. */
        if (len < 0 || (total > 0 && len > (off_t) (NGX_MAX_OFF_T_VALUE - total))) {
            return NGX_ERROR;
        }
        total += len;
    }

    if (max_total_bytes > 0 && total > max_total_bytes) {
        return NGX_ERROR;
    }

    if (total_out) {
        *total_out = total;
    }
    return NGX_OK;
}

ngx_uint_t
brix_range_vector_next_coalesced_run(
    const brix_byte_range_t *ranges, ngx_uint_t nranges,
    ngx_uint_t start_index, ngx_uint_t max_iov)
{
    ngx_uint_t i;
    ngx_uint_t count = 1;

    if (start_index >= nranges) return 0;
    if (max_iov == 0) return 0;

    for (i = start_index + 1; i < nranges && count < max_iov; i++) {
        /* A run is contiguous if ranges[i].start follows ranges[i-1].end
         * and both refer to the same open file (fd match). */
        if (ranges[i].start == ranges[i-1].end + 1
            && ranges[i].fd == ranges[i-1].fd)
        {
            count++;
        } else {
            break;
        }
    }

    return count;
}
