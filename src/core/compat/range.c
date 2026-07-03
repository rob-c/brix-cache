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
 *       Delegates to brix_http_parse_range_vector() for actual parsing (single-range mode).
 *       If vector parser returns NGX_OK → extract single range into out. If it fails →
 *       mark present=1, satisfiable=0 (unsatisfiable range). Returns no status code —
 *       caller checks out->present and out->satisfiable fields.
 */

/*
 * WHAT: Parses an RFC 7233 "bytes=" Range header into a single byte-range.
 *
 * HOW: Set defaults to full-file (start=0, end=file_size-1). Reject headers that are NULL,
 *       shorter than 7 bytes, or don't start with "bytes=". Zero opts struct — max_ranges=1,
 *       allow_suffix=1, allow_open_ended=1. Call brix_http_parse_range_vector() on the
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
brix_http_parse_range(const unsigned char *hdr_val, size_t hdr_len,
    off_t file_size, brix_http_range_t *out)
{
    brix_byte_range_t       range;
    brix_range_vector_opts_t opts;
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

    if (brix_http_parse_range_vector(hdr_val + 6, hdr_len - 6,
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

/* Parse one run of decimal digits at *p (bounded by end) into *val; advance *p.
 * Returns 1 if at least one digit was consumed (no overflow), else 0. */
static int
cr_parse_u64(const unsigned char **p, const unsigned char *end, off_t *val)
{
    const unsigned char *s = *p;
    unsigned long long   v = 0;

    if (s >= end || *s < '0' || *s > '9') {
        return 0;
    }
    for (; s < end && *s >= '0' && *s <= '9'; s++) {
        if (v > (0x7fffffffffffffffULL - 9) / 10) {
            return 0;   /* overflow guard */
        }
        v = v * 10 + (unsigned long long) (*s - '0');
    }
    *val = (off_t) v;
    *p = s;
    return 1;
}

void
brix_http_parse_content_range(const unsigned char *hdr_val, size_t hdr_len,
    brix_http_content_range_t *out)
{
    const unsigned char *p, *end;

    out->start = out->end = 0;
    out->total = -1;
    out->present = 0;

    if (hdr_val == NULL || hdr_len == 0) {
        return;
    }
    p = hdr_val;
    end = hdr_val + hdr_len;

    /* optional "bytes " unit prefix */
    if ((size_t) (end - p) >= 6 && memcmp(p, "bytes ", 6) == 0) {
        p += 6;
    }
    while (p < end && *p == ' ') {
        p++;
    }

    if (!cr_parse_u64(&p, end, &out->start)) {
        return;
    }
    if (p >= end || *p != '-') {
        return;
    }
    p++;
    if (!cr_parse_u64(&p, end, &out->end)) {
        return;
    }
    if (p >= end || *p != '/') {
        return;
    }
    p++;
    if (p < end && *p == '*') {
        out->total = -1;
        p++;
    } else if (!cr_parse_u64(&p, end, &out->total)) {
        return;
    }
    if (out->end < out->start) {
        return;   /* malformed: end before start */
    }
    /* trailing whitespace tolerated; anything else is malformed */
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }
    if (p != end) {
        return;
    }
    out->present = 1;
}
