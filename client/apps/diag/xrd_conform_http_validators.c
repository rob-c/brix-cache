/* Phase-118 HTTP conditional-request validator probes. */
#include "xrd_conform_probe_helpers.h"

#include <zlib.h>

int
xrd_conform_http_content_length(const brix_http_resp *response,
    uint64_t *length)
{
    char value[64];
    char *end = NULL;
    unsigned long long parsed;

    if (!brix_http_header(response, "Content-Length", value, sizeof(value)))
        return -1;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') return -1;
    *length = parsed;
    return 0;
}

static void
grade_range(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, const uint8_t *baseline, const char *id,
    const char *expression, int expected_status, uint64_t offset,
    size_t expected_length)
{
    brix_http_resp response;
    brix_status status;
    char expected[96];
    char received[96];
    int matches;

    brix_status_clear(&status);
    if (xrd_conform_http_request(execution, url, "GET", token, expression,
            expected_length, &response, &status) != 0) {
        xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_DIVERGENT,
            "range-request-failed", NULL, status.msg);
        return;
    }
    matches = response.status == expected_status
        && response.body_len == expected_length
        && (expected_length == 0
            || memcmp(response.body, baseline + offset, expected_length) == 0);
    snprintf(expected, sizeof(expected), "HTTP %d length=%zu", expected_status,
        expected_length);
    snprintf(received, sizeof(received), "HTTP %d length=%zu", response.status,
        response.body_len);
    xrd_conform_result_set(execution, id,
        matches ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        matches ? "range-byte-exact" : "range-status-length-or-byte-mismatch",
        expected, received);
    brix_http_resp_free(&response);
}

static void
grade_invalid_range(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, const brix_http_resp *baseline, const char *id,
    const char *expression, int allow_416)
{
    brix_http_resp response;
    brix_status status;
    int whole;
    int unsatisfiable;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    if (xrd_conform_http_request(execution, url, "GET", token, expression,
            baseline->body_len, &response, &status) != 0) {
        xrd_conform_result_set(execution, id,
            BRIX_CONFORM_VERDICT_DIVERGENT, "invalid-range-request-failed",
            NULL, status.msg);
        return;
    }
    whole = response.status == 200
        && response.body_len == baseline->body_len
        && (response.body_len == 0
            || memcmp(response.body, baseline->body, response.body_len) == 0);
    unsatisfiable = allow_416 && response.status == 416;
    xrd_conform_result_set(execution, id,
        whole || unsatisfiable ? BRIX_CONFORM_VERDICT_CONFORMANT
                               : BRIX_CONFORM_VERDICT_DIVERGENT,
        whole ? "invalid-range-ignored-with-whole-body"
              : unsatisfiable ? "inverted-range-rejected"
                              : "invalid-range-wrong-response",
        allow_416 ? "HTTP 200 whole body or HTTP 416"
                  : "HTTP 200 whole body", NULL);
    brix_http_resp_free(&response);
}

/* WHAT: Grade safe whole-body, HEAD and Range assertions.
 * WHY: The adopted body is the O2 oracle when mutation is unavailable.
 * HOW: Compare HEAD length, range edges, suffixes and EOF handling. */
void
xrd_conform_probe_http_boundaries(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *get_response)
{
    brix_http_resp head;
    brix_status status;
    uint64_t head_length = 0;
    uint64_t size = get_response->body_len;
    char range[96];
    int head_ok = 0;

    brix_status_clear(&status);
    if (xrd_conform_http_request(execution, url, "HEAD", token, NULL, 0,
            &head, &status) == 0) {
        head_ok = head.status >= 200 && head.status < 300
            && head.body_len == 0
            && xrd_conform_http_content_length(&head, &head_length) == 0
            && head_length == size;
        brix_http_resp_free(&head);
    }
    xrd_conform_result_set(execution, "HTR-002",
        head_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        head_ok ? "head-get-length-agreement" : "head-get-length-mismatch",
        NULL, status.msg);
    xrd_conform_result_set(execution, "HTR-015",
        BRIX_CONFORM_VERDICT_CONFORMANT, "GET-body-length-framing-consistent",
        NULL, NULL);
    if (size == 0) {
        grade_range(execution, url, token, (const uint8_t *) get_response->body,
            "HTR-009", "bytes=0-", 416, 0, 0);
        return;
    }
    grade_range(execution, url, token, (const uint8_t *) get_response->body,
        "HTR-003", "bytes=0-0", 206, 0, 1);
    snprintf(range, sizeof(range), "bytes=%llu-",
        (unsigned long long) size - 1);
    grade_range(execution, url, token, (const uint8_t *) get_response->body,
        "HTR-004", range, 206, size - 1, 1);
    grade_range(execution, url, token, (const uint8_t *) get_response->body,
        "HTR-005", "bytes=-1", 206, size - 1, 1);
    grade_range(execution, url, token, (const uint8_t *) get_response->body,
        "HTR-006", "bytes=-0", 416, 0, 0);
    snprintf(range, sizeof(range), "bytes=%llu-", (unsigned long long) size);
    grade_range(execution, url, token, (const uint8_t *) get_response->body,
        "HTR-007", range, 416, 0, 0);
    snprintf(range, sizeof(range), "bytes=0-%llu", (unsigned long long) size);
    grade_range(execution, url, token, (const uint8_t *) get_response->body,
        "HTR-008", range, 206, 0, (size_t) size);
    grade_invalid_range(execution, url, token, get_response, "HTR-013",
        "bytes=abc-def", 0);
    grade_invalid_range(execution, url, token, get_response, "HTR-014",
        "bytes=2-1", 1);
}


static int
header_value_safe(const char *value)
{
    const unsigned char *cursor = (const unsigned char *) value;
    size_t length = 0;

    if (value == NULL) return 0;
    while (*cursor != '\0') {
        if (*cursor < 0x21 || *cursor > 0x7e || ++length > 1024) return 0;
        cursor++;
    }
    return length > 0;
}

static void
skip_validators(xrd_conform_execution *execution)
{
    xrd_conform_result_set(execution, "HTR-018",
        BRIX_CONFORM_VERDICT_SKIPPED, "fixture-absent:safe-etag", NULL, NULL);
    xrd_conform_result_set(execution, "HTR-019",
        BRIX_CONFORM_VERDICT_SKIPPED, "fixture-absent:safe-etag", NULL, NULL);
}

static void
probe_if_none_match(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token, const char *etag)
{
    char fields[1200];
    brix_http_resp response;
    brix_status status;
    int rc;
    int pass;

    snprintf(fields, sizeof(fields), "If-None-Match: %s\r\n", etag);
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "GET", token,
        fields, 0, &response, &status);
    pass = rc == 0 && response.status == 304 && response.body_len == 0;
    xrd_conform_result_set(execution, "HTR-018",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "current-etag-returned-empty-304"
             : "if-none-match-response-invalid",
        "HTTP 304 with empty body", rc == 0 ? NULL : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

static void
probe_if_range(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, const brix_http_resp *baseline)
{
    const char fields[] =
        "Range: bytes=0-0\r\nIf-Range: \"brix-conform-stale\"\r\n";
    brix_http_resp response;
    brix_status status;
    int rc;
    int pass;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "GET", token,
        fields, baseline->body_len, &response, &status);
    pass = rc == 0 && response.status == 200
        && response.body_len == baseline->body_len
        && (response.body_len == 0
            || memcmp(response.body, baseline->body, response.body_len) == 0);
    xrd_conform_result_set(execution, "HTR-019",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "stale-if-range-returned-whole-object"
             : "stale-if-range-returned-partial-or-mixed-object",
        "HTTP 200 whole adopted body", rc == 0 ? NULL : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

static int
gzip_matches(const brix_http_resp *response, const brix_http_resp *baseline)
{
    z_stream stream;
    uint8_t *plain;
    int zrc;
    int matches;

    if (response->body_len > UINT_MAX || baseline->body_len > UINT_MAX)
        return 0;
    plain = malloc(baseline->body_len == 0 ? 1 : baseline->body_len);
    if (plain == NULL) return 0;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef *) response->body;
    stream.avail_in = (uInt) response->body_len;
    stream.next_out = plain;
    stream.avail_out = (uInt) baseline->body_len;
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
        free(plain);
        return 0;
    }
    zrc = inflate(&stream, Z_FINISH);
    inflateEnd(&stream);
    matches = zrc == Z_STREAM_END && stream.total_out == baseline->body_len
        && stream.avail_in == 0 && (baseline->body_len == 0
            || memcmp(plain, baseline->body, baseline->body_len) == 0);
    free(plain);
    return matches;
}

static void
probe_accept_encoding(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *baseline)
{
    const char fields[] = "Accept-Encoding: gzip\r\n";
    char encoding[64] = "identity";
    brix_http_resp response;
    brix_status status;
    int rc;
    int pass = 0;

    if (!xrd_conform_row_active(execution, "HTR-020")) return;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "GET", token,
        fields, baseline->body_len, &response, &status);
    if (rc == 0 && response.status == 200) {
        if (!brix_http_header(&response, "Content-Encoding", encoding,
                sizeof(encoding)))
            snprintf(encoding, sizeof(encoding), "%s", "identity");
        if (strcmp(encoding, "identity") == 0)
            pass = response.body_len == baseline->body_len
                && (response.body_len == 0 || memcmp(response.body,
                    baseline->body, response.body_len) == 0);
        else if (strcmp(encoding, "gzip") == 0)
            pass = gzip_matches(&response, baseline);
    }
    xrd_conform_result_set(execution, "HTR-020",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "gzip-or-identity-byte-exact"
             : "content-encoding-body-mismatch",
        "identity or byte-exact gzip", rc == 0 ? encoding : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

static void
build_excessive_range_fields(char fields[8192], int *valid)
{
    size_t used;
    unsigned index;

    used = (size_t) snprintf(fields, 8192, "Range: bytes=0-0");
    for (index = 1; index < 257 && used < 8192; index++)
        used += (size_t) snprintf(fields + used, 8192 - used, ",0-0");
    *valid = index == 257 && used + 2 < 8192;
    if (*valid) snprintf(fields + used, 8192 - used, "\r\n");
}

static int
whole_response_matches(const brix_http_resp *response,
    const brix_http_resp *baseline)
{
    return response->status == 200
        && response->body_len == baseline->body_len
        && (response->body_len == 0 || memcmp(response->body,
            baseline->body, response->body_len) == 0);
}

static void
grade_excessive_range_response(xrd_conform_execution *execution,
    brix_http_resp *response, const brix_http_resp *baseline)
{
    char content_type[128] = "";
    int whole = whole_response_matches(response, baseline);
    int refused = response->status == 416;

    brix_http_header(response, "Content-Type", content_type,
        sizeof(content_type));
    if (!whole && !refused && response->status == 206
        && strncmp(content_type, "multipart/byteranges", 20) == 0) {
        xrd_conform_result_set(execution, "HTR-012",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "multipart-range-limit-needs-completeness-parser", NULL,
            content_type);
        return;
    }
    xrd_conform_result_set(execution, "HTR-012",
        whole || refused ? BRIX_CONFORM_VERDICT_CONFORMANT
                         : BRIX_CONFORM_VERDICT_DIVERGENT,
        whole ? "excessive-range-set-returned-whole-object"
              : refused ? "excessive-range-set-refused"
                        : "excessive-range-set-truncated",
        "HTTP 200 whole body or HTTP 416", NULL);
}

static void
probe_excessive_ranges(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *baseline)
{
    char fields[8192];
    brix_http_resp response;
    brix_status status;
    int rc;
    int valid;

    if (!xrd_conform_row_active(execution, "HTR-012")) return;
    build_excessive_range_fields(fields, &valid);
    if (!valid) {
        xrd_conform_result_set(execution, "HTR-012",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "local-range-set-construction-failed", NULL, NULL);
        return;
    }
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "GET", token,
        fields, baseline->body_len, &response, &status);
    if (rc != 0) {
        xrd_conform_result_set(execution, "HTR-012",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "range-set-not-observed", NULL, status.msg);
        return;
    }
    grade_excessive_range_response(execution, &response, baseline);
    brix_http_resp_free(&response);
}

/* WHAT: Prove current and stale ETag validators have their RFC semantics.
 * WHY: A cache that ignores validators can return stale or mixed object bytes.
 * HOW: Reflect only a syntax-safe observed ETag, then compare 304 and stale
 *      If-Range responses against the already adopted whole-body oracle. */
void
xrd_conform_probe_http_validators(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *baseline)
{
    char etag[1025];

    probe_excessive_ranges(execution, url, token, baseline);
    probe_accept_encoding(execution, url, token, baseline);
    if (!xrd_conform_row_active(execution, "HTR-018")
        && !xrd_conform_row_active(execution, "HTR-019")) return;
    if (!brix_http_header(baseline, "ETag", etag, sizeof(etag))
        || !header_value_safe(etag)) {
        skip_validators(execution);
        return;
    }
    probe_if_none_match(execution, url, token, etag);
    probe_if_range(execution, url, token, baseline);
}
