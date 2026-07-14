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

/* ---- Skip the optional "bytes " unit token and leading spaces ----
 *
 * WHAT: Advances *cursor past an optional "bytes " unit prefix (RFC 7233
 *       Content-Range grammar) followed by any run of single spaces, up to end.
 *
 * WHY: The unit token is optional in the values we accept, and callers must land
 *      on the first digit of the range regardless of whether it was present; this
 *      keeps that positioning quirk in one named step instead of inline in the
 *      orchestrator.
 *
 * HOW: 1. If at least 6 bytes remain and they equal "bytes ", advance 6.
 *      2. Skip any following spaces one at a time until end or a non-space byte.
 */
static void
cr_skip_unit_prefix(const unsigned char **cursor, const unsigned char *end)
{
    if ((size_t) (end - *cursor) >= 6 && memcmp(*cursor, "bytes ", 6) == 0) {
        *cursor += 6;
    }
    while (*cursor < end && **cursor == ' ') {
        (*cursor)++;
    }
}

/* ---- Parse the "start-end" byte span into out->start / out->end ----
 *
 * WHAT: Parses "<start>-<end>" at *cursor, writing out->start and out->end and
 *       advancing *cursor. Returns 1 on a well-formed span, 0 otherwise.
 *
 * WHY: The start/end pair is the core of a Content-Range value; isolating its
 *      three-token grammar (number, literal '-', number) keeps the total-length
 *      and validation steps independent and separately testable.
 *
 * HOW: 1. Parse the start decimal; fail if absent.
 *      2. Require a literal '-' separator; fail otherwise, then consume it.
 *      3. Parse the end decimal; fail if absent.
 */
static int
cr_parse_span(const unsigned char **cursor, const unsigned char *end,
    brix_http_content_range_t *out)
{
    if (!cr_parse_u64(cursor, end, &out->start)) {
        return 0;
    }
    if (*cursor >= end || **cursor != '-') {
        return 0;
    }
    (*cursor)++;
    if (!cr_parse_u64(cursor, end, &out->end)) {
        return 0;
    }
    return 1;
}

/* ---- Parse the "/total" length component into out->total ----
 *
 * WHAT: Parses the "/<total>" or "/" + "*" form at *cursor, writing out->total
 *       (-1 for the "*" unknown-length form) and advancing *cursor. Returns 1 on success,
 *       0 on a missing '/' or malformed total.
 *
 * WHY: RFC 7233 allows the instance length to be an explicit number or "*"
 *      (unknown); expressing that choice as a single helper keeps the "*" → -1
 *      sentinel convention in one place shared with the default init value.
 *
 * HOW: 1. Require a literal '/' separator; fail otherwise, then consume it.
 *      2. If the next byte is '*', record total = -1, consume it, succeed.
 *      3. Otherwise parse a decimal total into out->total.
 */
static int
cr_parse_total(const unsigned char **cursor, const unsigned char *end,
    brix_http_content_range_t *out)
{
    if (*cursor >= end || **cursor != '/') {
        return 0;
    }
    (*cursor)++;
    if (*cursor < end && **cursor == '*') {
        out->total = -1;
        (*cursor)++;
        return 1;
    }
    return cr_parse_u64(cursor, end, &out->total);
}

/* ---- Confirm only tolerated trailing whitespace remains ----
 *
 * WHAT: Returns 1 if the bytes from cursor to end are entirely spaces/tabs (or
 *       empty), 0 if any other byte is present.
 *
 * WHY: A Content-Range value may carry trailing whitespace, but any other stray
 *      byte means the header is malformed and must be rejected; this makes the
 *      "consumed everything meaningful" check explicit at the end of the parse.
 *
 * HOW: 1. Skip a run of ' ' or '\t' bytes.
 *      2. Report whether the cursor reached end.
 */
static int
cr_only_trailing_ws(const unsigned char *cursor, const unsigned char *end)
{
    while (cursor < end && (*cursor == ' ' || *cursor == '\t')) {
        cursor++;
    }
    return cursor == end;
}

/* ---- Parse an RFC 7233 Content-Range header into a byte span + total ----
 *
 * WHAT: Parses "[bytes ]start-end/total" (total may be "*") from hdr_val,
 *       populating out. Sets out->present=1 only on a fully well-formed value;
 *       leaves present=0 (and out unusable) on any malformation. No return value.
 *
 * WHY: WebDAV/S3 upload and TPC paths need the server-reported byte span and
 *      instance length; a single tolerant-but-strict parser keeps acceptance and
 *      rejection identical across those callers.
 *
 * HOW: 1. Initialise defaults (empty span, total=-1, present=0); bail on empty input.
 *      2. Skip the optional unit prefix and leading spaces.
 *      3. Parse the start-end span, then the /total component.
 *      4. Reject an end-before-start span (malformed ordering).
 *      5. Require nothing but tolerated trailing whitespace, then mark present.
 */
void
brix_http_parse_content_range(const unsigned char *hdr_val, size_t hdr_len,
    brix_http_content_range_t *out)
{
    const unsigned char *cursor, *end;

    out->start = out->end = 0;
    out->total = -1;
    out->present = 0;

    if (hdr_val == NULL || hdr_len == 0) {
        return;
    }
    cursor = hdr_val;
    end = hdr_val + hdr_len;

    cr_skip_unit_prefix(&cursor, end);

    if (!cr_parse_span(&cursor, end, out)) {
        return;
    }
    if (!cr_parse_total(&cursor, end, out)) {
        return;
    }
    if (out->end < out->start) {
        return;   /* malformed: end before start */
    }
    if (!cr_only_trailing_ws(cursor, end)) {
        return;
    }
    out->present = 1;
}
