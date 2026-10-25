/* Phase-118 bounded kXR_pgread geometry and structural probes. */
#include "xrd_conform_probe_helpers.h"

#include <arpa/inet.h>

typedef struct {
    int attempted;
    int passed;
    int stopped;
} pg_grid_result;


static void
set_named_case(xrd_conform_execution *execution, const char *id, int matches,
    const brix_status *status)
{
    if (id == NULL) return;
    xrd_conform_result_set(execution, id,
        matches ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        matches ? "page-geometry-and-crc-validated" : "pgread-shape-failed",
        NULL, matches ? NULL : status->msg);
}

static void
mark_status_structure(xrd_conform_execution *execution)
{
    static const struct { const char *id; const char *reason; } rows[] = {
        { "PGR-001", "typed-parser-required-kXR_status" },
        { "PGR-002", "status-body-length-validated" },
        { "PGR-003", "pgread-request-id-validated" },
        { "PGR-004", "body-stream-id-validated" },
        { "PGR-005", "status-crc32c-validated" },
        { "PGR-007", "frame-offset-progression-validated" },
        { "PGR-031", "reserved-bytes-zero" },
        { "PGR-032", "response-type-domain-validated" },
    };
    size_t index;

    for (index = 0; index < sizeof(rows) / sizeof(rows[0]); index++)
        xrd_conform_result_set(execution, rows[index].id,
            BRIX_CONFORM_VERDICT_CONFORMANT, rows[index].reason, NULL, NULL);
}

/* Grade the owning structural clause when the strict native parser rejects a
 * hostile status frame.  Aggregate page/grid rows also fail, but must never be
 * the only red evidence for a malformed field with its own ledger clause. */
static void
mark_status_failure(xrd_conform_execution *execution,
    const brix_status *status)
{
    const char *id = NULL;

    if (strstr(status->msg, "expected kXR_status") != NULL) id = "PGR-001";
    else if (strstr(status->msg, "bad kXR_status body length") != NULL)
        id = "PGR-002";
    else if (strstr(status->msg, "request id mismatch") != NULL)
        id = "PGR-003";
    else if (strstr(status->msg, "body stream id") != NULL)
        id = "PGR-004";
    else if (strstr(status->msg, "kXR_status header CRC mismatch") != NULL)
        id = "PGR-005";
    else if (strstr(status->msg, "frame offset mismatch") != NULL)
        id = "PGR-007";
    else if (strstr(status->msg, "reserved bytes") != NULL)
        id = "PGR-031";
    else if (strstr(status->msg, "response type") != NULL) {
        id = "PGR-032";
        xrd_conform_result_set(execution, "PGR-006",
            BRIX_CONFORM_VERDICT_DIVERGENT,
            "hostile-result-sequence-rejected", NULL, status->msg);
    }
    if (id != NULL) xrd_conform_result_set(execution, id,
        BRIX_CONFORM_VERDICT_DIVERGENT, "hostile-status-field-rejected",
        NULL, status->msg);
}

static void
grade_pgread_match(xrd_conform_execution *execution, const char *id,
    int matches, ssize_t got, unsigned partial_frames,
    const brix_status *status)
{
    if (!matches && status->kxr == XRDC_EINTEGRITY)
        xrd_conform_result_set(execution, "PGR-021",
            BRIX_CONFORM_VERDICT_CONFORMANT,
            "injected-page-corruption-detected", NULL, status->msg);
    else if (!matches && got >= 0)
        xrd_conform_result_set(execution, "PGR-021",
            BRIX_CONFORM_VERDICT_DIVERGENT,
            "corrupt-bytes-carried-valid-page-crc", NULL, status->msg);
    if (matches) {
        mark_status_structure(execution);
        xrd_conform_result_set(execution, "PGR-006",
            BRIX_CONFORM_VERDICT_CONFORMANT,
            partial_frames == 0 ? "single-frame-final-result"
                                : "partial-frames-then-final-result",
            NULL, NULL);
    } else {
        mark_status_failure(execution, status);
    }
    set_named_case(execution, id, matches, status);
}

static int
pgread_matches(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size, uint64_t offset,
    size_t length, const char *id)
{
    uint8_t *buffer;
    brix_status status;
    char reason[64];
    ssize_t got;
    int matches;
    unsigned partial_frames = 0;

    if (offset > size || (uint64_t) length > size - offset) {
        if (id != NULL) xrd_conform_result_set(execution, id,
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "object-too-small", NULL, NULL);
        return 2;
    }
    if (!xrd_conform_reserve(execution, length, reason, sizeof(reason))) {
        if (id != NULL) xrd_conform_result_set(execution, id,
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL, NULL);
        return -1;
    }
    buffer = malloc(length == 0 ? 1 : length);
    if (buffer == NULL) {
        if (id != NULL) xrd_conform_result_set(execution, id,
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "local-allocation-failed",
            NULL, NULL);
        return -1;
    }
    brix_status_clear(&status);
    got = brix_file_pgread_profile(connection, file, (int64_t) offset, buffer,
        length, &partial_frames, &status);
    matches = xrd_conform_bytes_match(got, length, buffer, baseline + offset);
    free(buffer);
    grade_pgread_match(execution, id, matches, got, partial_frames, &status);
    return matches ? 1 : 0;
}

static pg_grid_result
run_generated_grid(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size)
{
    brix_conform_page_case *cases;
    pg_grid_result result = { 0, 1, 0 };
    size_t count = brix_conform_page_cases(execution->run->config.budget,
        NULL, 0);
    size_t index;

    cases = calloc(count == 0 ? 1 : count, sizeof(*cases));
    if (cases == NULL) {
        result.stopped = 1;
        return result;
    }
    brix_conform_page_cases(execution->run->config.budget, cases, count);
    for (index = 0; index < count; index++) {
        int outcome;

        if (cases[index].offset > size
            || cases[index].length > size - cases[index].offset) continue;
        outcome = pgread_matches(execution, connection, file, baseline, size,
            cases[index].offset, (size_t) cases[index].length, NULL);
        if (outcome < 0) {
            result.stopped = 1;
            break;
        }
        result.attempted++;
        if (outcome == 0) result.passed = 0;
    }
    free(cases);
    return result;
}

static void
grade_grid_summary(xrd_conform_execution *execution, pg_grid_result grid)
{
    brix_conform_verdict verdict;
    const char *reason;

    if (grid.stopped || grid.attempted == 0) {
        verdict = BRIX_CONFORM_VERDICT_INCONCLUSIVE;
        reason = grid.stopped ? "page-grid-resource-ceiling"
                              : "no-page-grid-case-fits-object";
    } else if (!grid.passed) {
        verdict = BRIX_CONFORM_VERDICT_DIVERGENT;
        reason = "page-grid-mismatch";
    } else {
        verdict = BRIX_CONFORM_VERDICT_CONFORMANT;
        reason = "all-bounded-page-grid-cases-matched";
    }
    xrd_conform_result_set(execution, "PGR-014", verdict, reason, NULL, NULL);
    xrd_conform_result_set(execution, "PGR-019", verdict, reason, NULL, NULL);
    xrd_conform_result_set(execution, "PGR-020", verdict,
        verdict == BRIX_CONFORM_VERDICT_CONFORMANT
            ? "all-bounded-page-crcs-validated" : reason, NULL, NULL);
}

static int
pgread_args_match(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size,
    const uint8_t *args, uint32_t args_len)
{
    uint8_t buffer[64];
    brix_status status;
    char reason[64];
    size_t length = size < sizeof(buffer) ? (size_t) size : sizeof(buffer);
    ssize_t got;

    if (!xrd_conform_reserve(execution, length, reason, sizeof(reason)))
        return -1;
    brix_status_clear(&status);
    got = brix_file_pgread_args(connection, file, 0, buffer, length, args,
        args_len, &status);
    return got == (ssize_t) length
        && (length == 0 || memcmp(buffer, baseline, length) == 0);
}

static void
probe_request_args(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size)
{
    uint8_t retry[2] = { 0, kXR_pgRetry };
    uint8_t path_only[1] = { 0 };
    uint8_t canonical[2] = { 0, 0 };
    uint8_t trailing[3] = { 0, 0x80, 0xa5 };
    uint8_t any_path[1] = { kXR_AnyPath };
    int retry_ok = pgread_args_match(execution, connection, file, baseline,
        size, retry, sizeof(retry));
    int shapes_ok = pgread_args_match(execution, connection, file, baseline,
        size, path_only, sizeof(path_only));
    int any_ok;

    if (shapes_ok > 0) shapes_ok = pgread_args_match(execution, connection,
        file, baseline, size, canonical, sizeof(canonical));
    if (shapes_ok > 0) shapes_ok = pgread_args_match(execution, connection,
        file, baseline, size, trailing, sizeof(trailing));
    any_ok = pgread_args_match(execution, connection, file, baseline, size,
        any_path, sizeof(any_path));
    xrd_conform_result_set(execution, "PGR-022",
        retry_ok > 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                     : retry_ok < 0 ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                                    : BRIX_CONFORM_VERDICT_DIVERGENT,
        retry_ok > 0 ? "pgRetry-returned-same-bytes" : "pgRetry-failed",
        NULL, NULL);
    xrd_conform_result_set(execution, "PGR-023",
        shapes_ok > 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                      : shapes_ok < 0 ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                                      : BRIX_CONFORM_VERDICT_DIVERGENT,
        shapes_ok > 0 ? "stock-calibrated-argument-shapes-tolerated"
                      : "pgread-argument-shape-diverged",
        NULL, NULL);
    xrd_conform_result_set(execution, "PGR-024",
        any_ok > 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                   : any_ok < 0 ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                                : BRIX_CONFORM_VERDICT_DIVERGENT,
        any_ok > 0 ? "any-path-served-on-valid-stream" : "any-path-refused",
        NULL, NULL);
}

static int
negative_pgread_refused(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, int64_t offset, int32_t length)
{
    ClientPgReadRequest request;
    xrdw_pgread_req_t fields = { .offset = offset, .rlen = length };
    uint16_t sid, wire_status = 0;
    uint8_t *body = NULL;
    uint32_t body_len = 0;
    brix_resp_out response = { &wire_status, &body, &body_len };
    brix_status status;
    char reason[64];
    int rc;

    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return -1;
    memcpy(fields.fhandle, file->fhandle, sizeof(fields.fhandle));
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_pgread);
    xrdw_pgread_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(&status);
    rc = brix_send(connection, &request, NULL, &sid, &status);
    if (rc == 0) rc = brix_recv(connection, sid, &response, &status);
    free(body);
    return rc != 0 && status.kxr == kXR_ArgInvalid;
}

static void
probe_negative_requests(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file)
{
    int offset_ok = negative_pgread_refused(execution, connection, file, -1, 1);
    int length_ok = offset_ok > 0
        ? negative_pgread_refused(execution, connection, file, 0, -1) : 0;
    int ok = offset_ok > 0 && length_ok > 0;

    xrd_conform_result_set(execution, "PGR-030",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : offset_ok < 0 || length_ok < 0
                ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "negative-offset-and-length-refused"
           : "negative-pgread-wrong-answer", "kXR_ArgInvalid", NULL);
    if (!ok && offset_ok >= 0 && length_ok >= 0)
        xrd_conform_result_set(execution, "PGR-020",
            BRIX_CONFORM_VERDICT_DIVERGENT,
            "unexpected-success-left-pgread-stream-unsafe", NULL, NULL);
}

void
xrd_conform_probe_pgread(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size)
{
    pg_grid_result grid;
    int first;

    first = pgread_matches(execution, connection, file, baseline, size, 0,
        8192, "PGR-008");
    if (first == 0) {
        xrd_conform_result_set(execution, "PGR-019",
            BRIX_CONFORM_VERDICT_DIVERGENT, "pgread-grid-first-case-failed",
            NULL, NULL);
        xrd_conform_result_set(execution, "PGR-020",
            BRIX_CONFORM_VERDICT_DIVERGENT, "pgread-crc-or-frame-failed",
            NULL, NULL);
        return;
    }
    pgread_matches(execution, connection, file, baseline, size, 1, 4095,
        "PGR-009");
    pgread_matches(execution, connection, file, baseline, size, 0, 4097,
        "PGR-010");
    pgread_matches(execution, connection, file, baseline, size, 1, 4096,
        "PGR-011");
    pgread_matches(execution, connection, file, baseline, size, 17, 31,
        "PGR-012");
    pgread_matches(execution, connection, file, baseline, size, 4095, 2,
        "PGR-013");
    if (size > 0) pgread_matches(execution, connection, file, baseline, size,
        size - 1, 1, "PGR-015");
    else xrd_conform_result_set(execution, "PGR-015",
        BRIX_CONFORM_VERDICT_INCONCLUSIVE, "empty-object", NULL, NULL);
    if (size == 4095) pgread_matches(execution, connection, file, baseline,
        size, 0, 4095, "PGR-016");
    else xrd_conform_result_set(execution, "PGR-016",
        BRIX_CONFORM_VERDICT_INCONCLUSIVE, "requires-standard-object-P0",
        NULL, NULL);
    if (size == 0) pgread_matches(execution, connection, file, baseline, size,
        0, 0, "PGR-017");
    else xrd_conform_result_set(execution, "PGR-017",
        BRIX_CONFORM_VERDICT_INCONCLUSIVE, "requires-standard-object-Z",
        NULL, NULL);
    pgread_matches(execution, connection, file, baseline, size, 0, 0,
        "PGR-018");
    grid = run_generated_grid(execution, connection, file, baseline, size);
    grade_grid_summary(execution, grid);
    probe_request_args(execution, connection, file, baseline, size);
    probe_negative_requests(execution, connection, file);
}

/* WHAT: Exercise clauses that require the exact Z or P0 standard object.
 * WHY: An adopted arbitrary target cannot prove empty-object or 4095-byte
 * geometry; mutation mode plants those objects under the authorized prefix.
 * HOW: Issue only the extent named by the clause, preserving the main Q-grid
 * verdicts while using the same strict status/CRC parser. */
void
xrd_conform_probe_pgread_standard(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size)
{
    if (size == 0) {
        pgread_matches(execution, connection, file, baseline, size, 0, 0,
            "PGR-017");
    } else if (size == 4095) {
        pgread_matches(execution, connection, file, baseline, size, 0, 4095,
            "PGR-016");
    }
}

static int
probe_chunked_read(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint8_t *buffer, size_t size)
{
    brix_status status;
    char reason[64];
    unsigned partials = 0;
    ssize_t got;
    int exact;
    int passed;

    if (!xrd_conform_reserve(execution, size, reason, sizeof(reason))) return 0;
    brix_status_clear(&status);
    got = brix_file_read_profile(connection, file, 0, buffer, size, &partials,
        &status);
    exact = got == (ssize_t) size && memcmp(buffer, baseline, size) == 0;
    passed = exact && partials > 0;
    xrd_conform_result_set(execution, "RD-009",
        passed ? BRIX_CONFORM_VERDICT_CONFORMANT
               : BRIX_CONFORM_VERDICT_DIVERGENT,
        passed ? "oksofar-frames-then-byte-exact-final"
               : "large-read-framing-mismatch", NULL,
        status.msg);
    xrd_conform_result_set(execution, "CHU-001",
        passed ? BRIX_CONFORM_VERDICT_CONFORMANT
               : BRIX_CONFORM_VERDICT_DIVERGENT,
        passed ? "partials-followed-by-one-terminal"
               : "partial-terminal-sequence-invalid",
        NULL, status.msg);
    xrd_conform_result_set(execution, "CHU-002",
        passed ? BRIX_CONFORM_VERDICT_CONFORMANT
               : BRIX_CONFORM_VERDICT_DIVERGENT,
        passed ? "every-partial-kept-request-streamid"
               : "partial-streamid-or-body-mismatch",
        NULL, status.msg);
    return passed;
}

static void
probe_chunk_boundary(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint8_t *buffer, size_t size, int large_chunked)
{
    const size_t small_size = 4096;
    brix_status status;
    char reason[64];
    unsigned partials = 0;
    ssize_t got;
    int exact;

    if (size < small_size) {
        xrd_conform_result_set(execution, "CHU-003",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "object-too-small", NULL, NULL);
        return;
    }
    if (!xrd_conform_reserve(execution, small_size, reason, sizeof(reason))) {
        xrd_conform_result_set(execution, "CHU-003",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL, NULL);
        return;
    }
    brix_status_clear(&status);
    got = brix_file_read_profile(connection, file, 0, buffer, small_size,
        &partials, &status);
    exact = got == (ssize_t) small_size
        && memcmp(buffer, baseline, small_size) == 0;
    xrd_conform_result_set(execution, "CHU-003",
        exact && partials == 0 && large_chunked
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        exact && partials == 0 && large_chunked
            ? "small-unsplit-large-split-and-exact"
            : "chunk-size-transition-or-bytes-invalid",
        NULL, status.msg);
}

static void
probe_chunked_pgread(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint8_t *buffer, size_t size)
{
    brix_status status;
    char reason[64];
    unsigned partials = 0;
    ssize_t got;
    int exact;

    if (!xrd_conform_reserve(execution, size, reason, sizeof(reason))) return;
    brix_status_clear(&status);
    got = brix_file_pgread_profile(connection, file, 0, buffer, size,
        &partials, &status);
    exact = got == (ssize_t) size && memcmp(buffer, baseline, size) == 0;
    xrd_conform_result_set(execution, "PGR-025",
        exact && partials > 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                              : BRIX_CONFORM_VERDICT_DIVERGENT,
        exact && partials > 0 ? "partial-page-frames-reassembled-byte-exact"
                              : "large-pgread-framing-mismatch", NULL,
        status.msg);
    xrd_conform_result_set(execution, "PGR-026",
        exact && partials > 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                              : BRIX_CONFORM_VERDICT_DIVERGENT,
        exact && partials > 0 ? "every-partial-frame-held-whole-page-units"
                              : "chunked-page-unit-boundary-mismatch", NULL,
        status.msg);
    if (exact && partials > 0)
        xrd_conform_result_set(execution, "PGR-006",
            BRIX_CONFORM_VERDICT_CONFORMANT,
            "partial-frames-then-final-result", NULL, NULL);
}

static int
send_chunked_read(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, int64_t offset, size_t length, uint16_t *stream_id,
    brix_status *status)
{
    ClientReadRequest request;
    xrdw_read_req_t fields = { .offset = offset, .rlen = (int32_t) length };
    char reason[64];

    if (!xrd_conform_reserve(execution, length, reason, sizeof(reason))) return -1;
    memcpy(fields.fhandle, file->fhandle, sizeof(fields.fhandle));
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_read);
    xrdw_read_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(status);
    return brix_send(connection, &request, NULL, stream_id, status);
}

static int
recv_chunked_read(brix_conn *connection, uint16_t stream_id,
    const uint8_t *expected, uint8_t *buffer, size_t length,
    brix_status *status)
{
    size_t total = 0;
    unsigned partials = 0;

    for (;;) {
        uint16_t wire_status = 0;
        uint8_t *body = NULL;
        uint32_t body_length = 0;
        brix_resp_out response = { &wire_status, &body, &body_length };

        if (brix_recv(connection, stream_id, &response, status) != 0) {
            free(body);
            return 0;
        }
        if (body_length > length - total) {
            free(body);
            return 0;
        }
        memcpy(buffer + total, body, body_length);
        total += body_length;
        free(body);
        if (wire_status == kXR_ok) break;
        if (wire_status != kXR_oksofar) return 0;
        partials++;
    }
    return partials > 0 && total == length
        && memcmp(buffer, expected, length) == 0;
}

static void
probe_concurrent_chunked(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint8_t *buffer, size_t size)
{
    uint16_t first_id;
    uint16_t second_id;
    brix_status status;
    size_t length = size - 1;
    int sent;
    int first_ok = 0;
    int second_ok = 0;

    brix_status_clear(&status);
    sent = send_chunked_read(execution, connection, file, 0, length,
        &first_id, &status) == 0
        && send_chunked_read(execution, connection, file, 1, length,
            &second_id, &status) == 0;
    if (sent) {
        first_ok = recv_chunked_read(connection, first_id, baseline, buffer,
            length, &status);
        second_ok = recv_chunked_read(connection, second_id, baseline + 1,
            buffer, length, &status);
    }
    xrd_conform_result_set(execution, "CHU-004",
        sent && first_ok && second_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                                     : BRIX_CONFORM_VERDICT_DIVERGENT,
        sent && first_ok && second_ok
            ? "two-inflight-streamids-reassembled-exactly"
            : "concurrent-chunked-streams-cross-contaminated",
        NULL, status.msg);
}

/* WHAT: Prove ordinary and paged framing above the 16 MiB response boundary.
 * WHY: Successful transparent reassembly alone cannot establish that the wire
 * used the mandated partial-frame sequence.
 * HOW: Count validated intermediate frames and compare reconstructed bytes. */
void
xrd_conform_probe_chunked_reads(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    size_t size)
{
    uint8_t *buffer = malloc(size);
    int large_chunked;

    if (buffer == NULL) return;
    large_chunked = probe_chunked_read(execution, connection, file, baseline,
        buffer, size);
    probe_chunk_boundary(execution, connection, file, baseline, buffer, size,
        large_chunked);
    probe_chunked_pgread(execution, connection, file, baseline, buffer, size);
    probe_concurrent_chunked(execution, connection, file, baseline, buffer,
        size);
    free(buffer);
}
