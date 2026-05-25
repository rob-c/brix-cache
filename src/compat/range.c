/*
 * range.c — HTTP Range header parser shared by WebDAV and S3.
 *
 * WHAT: Parses an RFC 7233 "bytes=" Range header into a single byte-range
 *       (start, end). Used by the WebDAV GET handler for partial content
 *       responses and the S3 GET handler for Range requests.
 *
 * WHY: Both protocols need to handle three range forms — bytes=start-end,
 *      bytes=-suffix (last N bytes), bytes=start- (from start to EOF) — plus
 *      unsatisfiable ranges when the requested range exceeds file size. Centralising
 *      parsing here avoids duplication between WebDAV and S3 code.
 *
 * HOW: Defaults to full-file range. Checks header starts with "bytes=" prefix.
 *       Delegates to xrootd_http_parse_range_vector() for actual parsing (single-range mode).
 *       If vector parser returns NGX_OK → extract single range into out. If it fails →
 *       mark present=1, satisfiable=0 (unsatisfiable range). Returns no status code —
 *       caller checks out->present and out->satisfiable fields.
 */

/*
 * WHAT: Parses an RFC 7233 "bytes=" Range header into a single byte-range.
 *
 * HOW: Set defaults to full-file (start=0, end=file_size-1). Reject headers that are NULL,
 *       shorter than 7 bytes, or don't start with "bytes=". Zero opts struct — max_ranges=1,
 *       allow_suffix=1, allow_open_ended=1. Call xrootd_http_parse_range_vector() on the
 *       suffix after "bytes=" to parse the range spec. If vector parser succeeds and nranges==1,
 *       copy range.start/range.end into out->start/out->end and set present=1. If vector parser
 *       fails or returns multiple ranges (not expected with max_ranges=1), set present=1,
 *       satisfiable=0.
 *
 * WHY: WebDAV GET and S3 GET handlers both need to honour HTTP Range headers for partial content.
 *      Delegates complex parsing logic to range_vector.c while providing a simple single-range API.
 */

#include "range.h"
#include "range_vector.h"
#include <string.h>

void
xrootd_http_parse_range(const unsigned char *hdr_val, size_t hdr_len,
    off_t file_size, xrootd_http_range_t *out)
{
    xrootd_byte_range_t       range;
    xrootd_range_vector_opts_t opts;
    ngx_uint_t                nranges;

    /* Defaults: full file, no range. */
    out->start       = 0;
    out->end         = (file_size > 0) ? file_size - 1 : 0;
    out->present     = 0;
    out->satisfiable = 1;

    if (hdr_val == NULL || hdr_len < 7 || memcmp(hdr_val, "bytes=", 6) != 0) {
        return;
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.max_ranges         = 1;
    opts.allow_suffix       = 1;
    opts.allow_open_ended   = 1;
    opts.drop_unsatisfiable = 0;

    if (xrootd_http_parse_range_vector(hdr_val + 6, hdr_len - 6,
                                       file_size, &opts,
                                       &range, &nranges) != NGX_OK)
    {
        out->present     = 1;
        out->satisfiable = 0;
        return;
    }

    if (nranges == 1) {
        out->present = 1;
        out->start   = range.start;
        out->end     = range.end;
    }
}
