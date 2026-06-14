/*
 * range_vector.c — shared byte-range parsing, validation, and coalescing.
 *
 * See range_vector.h for the public API.
 */

#include "range_vector.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*
 * range_vector_parse_one — parse a single byte-range component [p, comma).
 *
 * Splits the component by '-' (suffix "-N", open-ended "A-", or "A-B"),
 * normalises the offsets against file_size, and on a satisfiable range fills
 * *out. Returns NGX_OK when a range was stored, NGX_DECLINED to skip a
 * malformed/unsatisfiable component (when opts->drop_unsatisfiable is set), or
 * NGX_ERROR for the same conditions when dropping is disabled.
 */
static ngx_int_t
range_vector_parse_one(const u_char *p, const u_char *comma, off_t file_size,
    const xrootd_range_vector_opts_t *opts, xrootd_byte_range_t *out)
{
    const u_char *dash;
    off_t         start, last;

    /* Find dash within this range component. */
    dash = ngx_strlchr((u_char *) p, (u_char *) comma, '-');
    if (dash == NULL) {
        return opts->drop_unsatisfiable ? NGX_DECLINED : NGX_ERROR;
    }

    /* 1. Parse start offset (if present). */
    if (p == dash) {
        /* Suffix range: "-N" means the last N bytes. */
        if (!opts->allow_suffix) {
            return opts->drop_unsatisfiable ? NGX_DECLINED : NGX_ERROR;
        }

        start = (off_t) ngx_atoof((u_char *)(dash + 1), comma - (dash + 1));
        if (start <= 0) {
            return opts->drop_unsatisfiable ? NGX_DECLINED : NGX_ERROR;
        }

        if (start > file_size) {
            start = file_size;
        }
        last  = file_size - 1;
        start = file_size - start;

    } else {
        start = (off_t) ngx_atoof((u_char *) p, dash - p);
        if (start == (off_t) NGX_ERROR || start < 0) {
            return opts->drop_unsatisfiable ? NGX_DECLINED : NGX_ERROR;
        }

        /* 2. Parse end offset (if present). */
        if (dash + 1 == comma) {
            /* Open-ended range: "A-" means from A to EOF. */
            if (!opts->allow_open_ended) {
                return opts->drop_unsatisfiable ? NGX_DECLINED : NGX_ERROR;
            }
            last = file_size - 1;
        } else {
            last = (off_t) ngx_atoof((u_char *)(dash + 1), comma - (dash + 1));
            if (last == (off_t) NGX_ERROR || last < 0) {
                return opts->drop_unsatisfiable ? NGX_DECLINED : NGX_ERROR;
            }
            if (last >= file_size) {
                last = file_size - 1;
            }
        }
    }

    /* 3. Validate unsatisfiable ranges. */
    if (start < 0 || start >= file_size || start > last) {
        return opts->drop_unsatisfiable ? NGX_DECLINED : NGX_ERROR;
    }

    out->start  = start;
    out->end    = last;
    out->fd     = -1;
    out->handle = 0;
    return NGX_OK;
}

/*
 * xrootd_http_parse_range_vector — parse a HTTP byte-ranges header value.
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
xrootd_http_parse_range_vector(const u_char *data, size_t len,
    off_t file_size, const xrootd_range_vector_opts_t *opts,
    xrootd_byte_range_t *ranges, ngx_uint_t *nranges)
{
    const u_char *p, *end, *comma;
    ngx_uint_t    n = 0;

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

        rc = range_vector_parse_one(p, comma, file_size, opts, &ranges[n]);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }
        if (rc == NGX_OK) {
            n++;
        }
        /* NGX_DECLINED → unsatisfiable component dropped; just advance. */

        p = comma + 1;
    }

    *nranges = n;
    return NGX_OK;
}

ngx_int_t
xrootd_range_vector_validate_total(
    const xrootd_byte_range_t *ranges, ngx_uint_t nranges,
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
xrootd_range_vector_next_coalesced_run(
    const xrootd_byte_range_t *ranges, ngx_uint_t nranges,
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
