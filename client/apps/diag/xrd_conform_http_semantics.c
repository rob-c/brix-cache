/*
 * Phase-118 HTTP multipart, framing, validator-mutation and digest probes.
 *
 * WHAT: Completes HTR-010/011/016/017/021 against an adopted byte oracle.
 * WHY: A whole-body GET cannot detect malformed multipart assembly, unstable
 *      validators, broken chunk framing, or dishonest integrity metadata.
 * HOW: Parse bounded response metadata, compare every represented byte against
 *      the adopted body, and use one scratch-confined PUT for mutable ETags.
 */
#include "xrd_conform_probe_helpers.h"

#include <strings.h>



/* ---- Compare a response with the adopted whole object ----
 *
 * WHAT: Returns one only for HTTP 200 with byte-identical complete content.
 * WHY: RFC range handling may legitimately ignore a range and send the whole.
 * HOW: Check status, length, then compare the bounded response body.
 */
static int
whole_matches(const brix_http_resp *response,
    const brix_http_resp *baseline)
{
    return response->status == 200
        && response->body_len == baseline->body_len
        && (response->body_len == 0
            || memcmp(response->body, baseline->body,
                response->body_len) == 0);
}

/* ---- Validate and copy a multipart boundary parameter ----
 *
 * WHAT: Returns zero with a bounded boundary token, or -1 for bad media type.
 * WHY: A response-controlled delimiter must not cause over-read or ambiguity.
 * HOW: Require multipart/byteranges, find boundary=, unquote, validate ASCII.
 */
static int
copy_boundary_token(const char *start, const char *end, char *boundary,
    size_t capacity)
{
    const char *cursor;
    size_t length = (size_t) (end - start);

    if (length == 0 || length > 70 || length >= capacity
        || start[length - 1] == ' ') return -1;
    for (cursor = start; cursor < end; cursor++) {
        unsigned char byte = (unsigned char) *cursor;

        if (byte < 0x20 || byte > 0x7e || byte == '"' || byte == '\\')
            return -1;
    }
    memcpy(boundary, start, length);
    boundary[length] = '\0';
    return 0;
}

static int
parse_boundary_value(const char *cursor, char *boundary, size_t capacity)
{
    const char *start;
    const char *end;
    int quoted;

    while (*cursor == ' ' || *cursor == '\t') cursor++;
    if (*cursor != '=') return -1;
    cursor++;
    while (*cursor == ' ' || *cursor == '\t') cursor++;
    quoted = *cursor == '"';
    if (quoted) cursor++;
    start = cursor;
    if (quoted) {
        while (*cursor != '\0' && *cursor != '"') cursor++;
        if (*cursor != '"') return -1;
        end = cursor;
    } else {
        while (*cursor != '\0' && *cursor != ';'
            && *cursor != ' ' && *cursor != '\t') cursor++;
        end = cursor;
    }
    return copy_boundary_token(start, end, boundary, capacity);
}

static int
multipart_boundary(const char *content_type, char *boundary, size_t capacity)
{
    const char *cursor;

    if (content_type == NULL
        || strncasecmp(content_type, "multipart/byteranges", 20) != 0)
        return -1;
    cursor = content_type + 20;
    while (*cursor != '\0') {
        while (*cursor == ';' || *cursor == ' ' || *cursor == '\t') cursor++;
        if (strncasecmp(cursor, "boundary", 8) != 0) {
            while (*cursor != '\0' && *cursor != ';') cursor++;
            continue;
        }
        cursor += 8;
        return parse_boundary_value(cursor, boundary, capacity);
    }
    return -1;
}

typedef struct {
    const char *cursor;
    const char *limit;
    const char *next_marker;
    size_t marker_length;
    size_t next_length;
    uint64_t coverage;
    unsigned parts;
} multipart_cursor;

static int part_range(const char *headers, size_t header_length,
    uint64_t *start, uint64_t *end, uint64_t *total);
static uint64_t range_mask(uint64_t start, uint64_t end);

static int
multipart_finish(multipart_cursor *part, uint64_t required_mask)
{
    if ((size_t) (part->limit - part->cursor) < 2
        || memcmp(part->cursor, "--", 2) != 0) return 0;
    part->cursor += 2;
    if ((size_t) (part->limit - part->cursor) == 2
        && memcmp(part->cursor, "\r\n", 2) == 0)
        part->cursor += 2;
    return part->cursor == part->limit && part->parts > 0
        && (part->coverage & required_mask) == required_mask;
}

static int
multipart_consume_part(multipart_cursor *part,
    const brix_http_resp *baseline)
{
    const char *header_end;
    const char *delimiter;
    uint64_t start;
    uint64_t end;
    uint64_t total;
    uint64_t part_length;

    if ((size_t) (part->limit - part->cursor) < 2
        || memcmp(part->cursor, "\r\n", 2) != 0) return -1;
    part->cursor += 2;
    header_end = memmem(part->cursor,
        (size_t) (part->limit - part->cursor), "\r\n\r\n", 4);
    if (header_end == NULL || (size_t) (header_end - part->cursor) > 4096
        || part_range(part->cursor, (size_t) (header_end - part->cursor),
            &start, &end, &total) != 0 || total != baseline->body_len
        || end >= baseline->body_len) return -1;
    part->cursor = header_end + 4;
    delimiter = memmem(part->cursor,
        (size_t) (part->limit - part->cursor), part->next_marker,
        part->next_length);
    if (delimiter == NULL) return -1;
    part_length = end - start + 1;
    if (part_length != (uint64_t) (delimiter - part->cursor)
        || memcmp(part->cursor, baseline->body + start,
            (size_t) part_length) != 0) return -1;
    part->coverage |= range_mask(start, end);
    part->parts++;
    part->cursor = delimiter + 2 + part->marker_length;
    return 0;
}

/* ---- Parse one Content-Range field from a MIME part ----
 *
 * WHAT: Returns zero with start/end/total for one strict bytes range.
 * WHY: Part bytes have no oracle until their absolute object offsets are known.
 * HOW: Walk CRLF-delimited fields, copy the value, parse complete unsigneds.
 */
static int
part_range(const char *headers, size_t header_length, uint64_t *start,
    uint64_t *end, uint64_t *total)
{
    const char *cursor = headers;
    const char *limit = headers + header_length;

    while (cursor < limit) {
        const char *line_end = memmem(cursor, (size_t) (limit - cursor),
            "\r\n", 2);
        const char *value;
        char field[160];
        char trailing;
        unsigned long long first;
        unsigned long long last;
        unsigned long long size;
        size_t value_length;

        if (line_end == NULL) line_end = limit;
        if ((size_t) (line_end - cursor) > 14
            && strncasecmp(cursor, "Content-Range:", 14) == 0) {
            value = cursor + 14;
            while (value < line_end && (*value == ' ' || *value == '\t'))
                value++;
            value_length = (size_t) (line_end - value);
            if (value_length == 0 || value_length >= sizeof(field)) return -1;
            memcpy(field, value, value_length);
            field[value_length] = '\0';
            if (sscanf(field, "bytes %llu-%llu/%llu%c", &first, &last,
                    &size, &trailing) != 3 || first > last) return -1;
            *start = first;
            *end = last;
            *total = size;
            return 0;
        }
        cursor = line_end == limit ? limit : line_end + 2;
    }
    return -1;
}

/* ---- Convert one verified range to a small-object coverage mask ----
 *
 * WHAT: Returns its inclusive bit mask, or zero when outside the first 64 bytes.
 * WHY: The fixed HTR fixtures need exact requested-byte coverage without a
 *      baseline-sized allocation.
 * HOW: Bound both offsets and set each represented bit.
 */
static uint64_t
range_mask(uint64_t start, uint64_t end)
{
    uint64_t mask = 0;
    uint64_t offset;

    if (start >= 64 || end >= 64) return 0;
    for (offset = start; offset <= end; offset++)
        mask |= UINT64_C(1) << offset;
    return mask;
}

/* ---- Parse and verify a multipart/byteranges body ----
 *
 * WHAT: Returns one only when syntax, offsets, lengths, bytes and coverage hold.
 * WHY: A plausible 206 can omit, duplicate incorrectly, or misplace object data.
 * HOW: Walk delimiters, parse each Content-Range, compare its body, accumulate
 *      coverage, and require a clean closing delimiter.
 */
static int
multipart_matches(const brix_http_resp *response,
    const brix_http_resp *baseline, uint64_t required_mask)
{
    char content_type[256];
    char boundary[72];
    char marker[76];
    char next_marker[80];
    size_t marker_length;
    size_t next_length;
    multipart_cursor part;

    if (response->status != 206
        || !brix_http_header(response, "Content-Type", content_type,
            sizeof(content_type))
        || multipart_boundary(content_type, boundary, sizeof(boundary)) != 0)
        return 0;
    snprintf(marker, sizeof(marker), "--%s", boundary);
    snprintf(next_marker, sizeof(next_marker), "\r\n--%s", boundary);
    marker_length = strlen(marker);
    next_length = strlen(next_marker);
    memset(&part, 0, sizeof(part));
    part.cursor = response->body;
    part.limit = response->body + response->body_len;
    part.next_marker = next_marker;
    part.marker_length = marker_length;
    part.next_length = next_length;
    if ((size_t) (part.limit - part.cursor) < marker_length + 2
        || memcmp(part.cursor, marker, marker_length) != 0) return 0;
    part.cursor += marker_length;
    while (part.cursor < part.limit) {
        if ((size_t) (part.limit - part.cursor) >= 2
            && memcmp(part.cursor, "--", 2) == 0)
            return multipart_finish(&part, required_mask);
        if (multipart_consume_part(&part, baseline) != 0) return 0;
    }
    return 0;
}

/* ---- Verify a coalesced single-range response ----
 *
 * WHAT: Returns one when one 206 part is byte-exact and covers required bytes.
 * WHY: Overlapping ranges may legally coalesce without MIME multipart overhead.
 * HOW: Parse Content-Range, validate total/body/bytes, then test its bit mask.
 */
static int
single_range_matches(const brix_http_resp *response,
    const brix_http_resp *baseline, uint64_t required_mask)
{
    char value[160];
    char trailing;
    unsigned long long start;
    unsigned long long end;
    unsigned long long total;

    if (response->status != 206
        || !brix_http_header(response, "Content-Range", value, sizeof(value))
        || sscanf(value, "bytes %llu-%llu/%llu%c", &start, &end, &total,
            &trailing) != 3 || start > end || end >= baseline->body_len
        || total != baseline->body_len || end - start + 1 != response->body_len)
        return 0;
    return memcmp(response->body, baseline->body + start,
            response->body_len) == 0
        && (range_mask(start, end) & required_mask) == required_mask;
}

static int
multirange_response_matches(const brix_http_resp *response,
    const brix_http_resp *baseline, uint64_t mask, size_t index)
{
    if (whole_matches(response, baseline)
        || multipart_matches(response, baseline, mask)) return 1;
    if (index != 1) return 0;
    return single_range_matches(response, baseline, mask)
        || response->status == 416;
}

/* ---- Exercise ordinary and overlapping multi-range semantics ----
 *
 * WHAT: Grades HTR-010/011 from byte-verified whole, multipart or coalesced data.
 * WHY: Multi-range errors often return convincing status and incorrect slices.
 * HOW: Send two fixed range sets and require all represented bytes to match.
 */
static void
probe_multirange(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, const brix_http_resp *baseline)
{
    const char *ids[] = { "HTR-010", "HTR-011" };
    const char *fields[] = {
        "Range: bytes=0-0,2-3\r\n",
        "Range: bytes=0-3,2-5,7-6\r\n"
    };
    const uint64_t masks[] = { UINT64_C(0x0d), UINT64_C(0x3f) };
    size_t index;

    if (baseline->body_len < 6) {
        for (index = 0; index < 2; index++) {
            if (xrd_conform_row_active(execution, ids[index]))
                xrd_conform_result_set(execution, ids[index],
                    BRIX_CONFORM_VERDICT_SKIPPED,
                    "fixture-absent:object-smaller-than-six-bytes", NULL, NULL);
        }
        return;
    }
    for (index = 0; index < 2; index++) {
        brix_http_resp response;
        brix_status status;
        int rc;
        int pass;

        if (!xrd_conform_row_active(execution, ids[index])) continue;
        memset(&response, 0, sizeof(response));
        brix_status_clear(&status);
        rc = xrd_conform_http_request_fields(execution, url, "GET", token,
            fields[index], baseline->body_len + 4096, &response, &status);
        pass = rc == 0 && multirange_response_matches(&response, baseline,
            masks[index], index);
        xrd_conform_grade_received(execution, ids[index], pass,
            index == 0 ? "multi-range-body-byte-exact"
                       : "overlap-and-descending-ranges-defined-and-exact",
            index == 0 ? "multi-range-body-invalid"
                       : "overlap-or-descending-range-body-invalid",
            rc == 0 ? response.reason : status.msg);
        if (rc == 0) brix_http_resp_free(&response);
    }
}

/* ---- Grade observed chunked-transfer framing ----
 *
 * WHAT: Marks HTR-016 conformant for a valid, byte-exact chunked baseline.
 * WHY: The shared HTTP decoder records whether its zero-chunk grammar was valid.
 * HOW: Inspect Transfer-Encoding and the decoder's framing-valid flag.
 */
static void
probe_chunked(xrd_conform_execution *execution,
    const brix_http_resp *baseline)
{
    char transfer_encoding[128];
    int chunked;

    if (!xrd_conform_row_active(execution, "HTR-016")) return;
    chunked = brix_http_header(baseline, "Transfer-Encoding",
        transfer_encoding, sizeof(transfer_encoding))
        && strcasestr(transfer_encoding, "chunked") != NULL;
    if (!chunked) {
        xrd_conform_result_set(execution, "HTR-016",
            BRIX_CONFORM_VERDICT_SKIPPED, "response-not-observed:chunked",
            NULL, NULL);
        return;
    }
    xrd_conform_grade_received(execution, "HTR-016", baseline->framing_valid,
        "chunked-body-reassembled-with-zero-terminator",
        "chunked-body-framing-invalid", transfer_encoding);
}

/* ---- Parse and verify the selected HTTP digest ----
 *
 * WHAT: Returns one for canonical sha256=<64 lowercase/uppercase hex> matching.
 * WHY: A digest header is evidence only when both its name and value are bound.
 * HOW: Split the first pair, require the ROOT checksum spelling, recompute SHA256.
 */
static int
digest_matches(const char *value, const brix_http_resp *baseline)
{
    char expected[65];
    const char *equals;
    const char *end;
    size_t name_length;
    size_t digest_length;

    equals = strchr(value, '=');
    if (equals == NULL) return 0;
    end = strchr(equals + 1, ',');
    if (end == NULL) end = value + strlen(value);
    name_length = (size_t) (equals - value);
    digest_length = (size_t) (end - equals - 1);
    while (name_length > 0 && value[name_length - 1] == ' ') name_length--;
    if (name_length != 6 || strncasecmp(value, "sha256", 6) != 0
        || digest_length != 64) return 0;
    brix_s3_sha256_hex(baseline->body, baseline->body_len, expected);
    return strncasecmp(equals + 1, expected, 64) == 0;
}

/* ---- Request and recompute HTTP integrity metadata ----
 *
 * WHAT: Grades HTR-021 or skips when the endpoint does not offer Want-Digest.
 * WHY: Optional absence is not divergence, but a supplied digest must be true.
 * HOW: Ask for sha256, require a byte-exact body, parse Digest, recompute locally.
 */
static void
probe_digest(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, const brix_http_resp *baseline)
{
    brix_http_resp response;
    brix_status status;
    char digest[256];
    int rc;
    int have_digest;
    int pass;

    if (!xrd_conform_row_active(execution, "HTR-021")) return;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "GET", token,
        "Want-Digest: sha256\r\n", baseline->body_len, &response, &status);
    have_digest = rc == 0 && brix_http_header(&response, "Digest", digest,
        sizeof(digest));
    if (rc == 0 && !have_digest && whole_matches(&response, baseline)) {
        xrd_conform_result_set(execution, "HTR-021",
            BRIX_CONFORM_VERDICT_SKIPPED,
            "claim-absent:Want-Digest-sha256", NULL, NULL);
        brix_http_resp_free(&response);
        return;
    }
    pass = rc == 0 && whole_matches(&response, baseline) && have_digest
        && digest_matches(digest, baseline);
    if (!url->is_s3 && rc == 0 && whole_matches(&response, baseline)
        && have_digest)
        xrd_conform_observe_http_checksum(execution, baseline, pass);
    xrd_conform_grade_received(execution, "HTR-021", pass, "http-digest-name-and-value-match",
        "http-digest-name-or-value-mismatch", rc == 0 ? digest : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

/* ---- Build one HTTP path beneath mutation authority ----
 *
 * WHAT: Returns zero with a scratch-confined Web URL path for HTR-017.
 * WHY: The ETag mutation probe must never overwrite the adopted target object.
 * HOW: Use the common capability builder, then copy its bounded path into URL.
 */
static int
etag_scratch_url(xrd_conform_execution *execution, const brix_weburl *base,
    brix_weburl *scratch)
{
    char path[XRDC_PATH_MAX];

    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-http-etag", path, sizeof(path)) != 0)
        return -1;
    *scratch = *base;
    return (size_t) snprintf(scratch->path, sizeof(scratch->path), "%s", path)
        < sizeof(scratch->path) ? 0 : -1;
}

/* ---- Fetch one safe ETag from a complete GET ----
 *
 * WHAT: Returns zero with a visible, injection-safe ETag or -1.
 * WHY: Validator comparison must never reflect or compare truncated controls.
 * HOW: GET, require success, extract ETag, reject controls and excessive length.
 */
static int
fetch_etag(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, char *etag, size_t capacity, brix_status *status)
{
    brix_http_resp response;
    const unsigned char *cursor;
    int rc;

    memset(&response, 0, sizeof(response));
    rc = xrd_conform_http_request_fields(execution, url, "GET", token, NULL,
        64, &response, status);
    if (rc != 0 || response.status < 200 || response.status >= 300
        || !brix_http_header(&response, "ETag", etag, capacity)) {
        if (rc == 0) brix_http_resp_free(&response);
        return -1;
    }
    for (cursor = (const unsigned char *) etag; *cursor != '\0'; cursor++) {
        if (*cursor < 0x21 || *cursor > 0x7e) {
            brix_http_resp_free(&response);
            return -1;
        }
    }
    brix_http_resp_free(&response);
    return 0;
}

/* ---- Prove stable and mutation-sensitive ETags ----
 *
 * WHAT: Creates one scratch object, compares two ETags, mutates, compares again.
 * WHY: A validator that changes spuriously or survives a write breaks caches.
 * HOW: PUT A, GET twice, PUT B, GET once, require stable-then-changed, DELETE.
 */
static void
probe_etag_mutation(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token)
{
    brix_weburl scratch;
    brix_http_resp response;
    brix_status status;
    char first[1025];
    char second[1025];
    char changed[1025];
    int rc;
    int pass = 0;

    if (!xrd_conform_row_active(execution, "HTR-017")) return;
    if (url->is_s3 || etag_scratch_url(execution, url, &scratch) != 0) {
        xrd_conform_result_set(execution, "HTR-017",
            BRIX_CONFORM_VERDICT_SKIPPED,
            "fixture-absent:mutable-http-scratch", NULL, NULL);
        return;
    }
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, &scratch, "PUT", token,
        NULL, "etag-a", 6, 0, &response, &status);
    if (rc == 0) brix_http_resp_free(&response);
    if (rc == 0 && fetch_etag(execution, &scratch, token, first,
            sizeof(first), &status) == 0
        && fetch_etag(execution, &scratch, token, second,
            sizeof(second), &status) == 0) {
        memset(&response, 0, sizeof(response));
        rc = xrd_conform_http_request_body(execution, &scratch, "PUT", token,
            NULL, "etag-b-different", 16, 0, &response, &status);
        if (rc == 0) brix_http_resp_free(&response);
        pass = rc == 0 && strcmp(first, second) == 0
            && fetch_etag(execution, &scratch, token, changed,
                sizeof(changed), &status) == 0
            && strcmp(first, changed) != 0;
    }
    xrd_conform_grade_received(execution, "HTR-017", pass, "etag-stable-then-changed-after-put",
        "etag-unstable-or-unchanged-after-put", rc == 0 ? NULL : status.msg);
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    if (xrd_conform_http_request_fields(execution, &scratch, "DELETE", token,
            NULL, 0, &response, &status) == 0)
        brix_http_resp_free(&response);
}

/* ---- Execute the remaining HTTP read and validator semantics ----
 *
 * WHAT: Runs every HTR semantic probe owned by this focused module.
 * WHY: The main HTTP runner should retain baseline transport ownership only.
 * HOW: Invoke independent range, framing, digest and mutation probes in order.
 */
void
xrd_conform_probe_http_semantics(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *baseline)
{
    probe_multirange(execution, url, token, baseline);
    probe_chunked(execution, baseline);
    probe_digest(execution, url, token, baseline);
    probe_etag_mutation(execution, url, token);
}
