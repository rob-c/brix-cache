/* Phase-118 ROOT vector-read limits and hostile-shape probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/readv_seg.h"

#include <arpa/inet.h>
#include <errno.h>

/* WHAT: Send an exact readv payload outside the typed client's safety checks.
 * WHY: Over-limit and malformed vectors must reach the remote implementation.
 * HOW: Use the repository wire codec and the shared bounded exchange seam. */
static int
raw_readv(xrd_conform_execution *execution, brix_conn *connection,
    const void *payload_data, uint32_t payload_length, size_t expected_bytes,
    uint16_t *wire_status, uint8_t **body, uint32_t *body_length,
    brix_status *status)
{
    ClientRequestHdr request;
    brix_payload payload = { payload_data, payload_length };
    brix_resp_out response = { wire_status, body, body_length };
    uint16_t stream_id;
    char reason[64];

    if (!xrd_conform_reserve(execution, expected_bytes, reason,
            sizeof(reason))) {
        brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
        return -1;
    }
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_readv);
    xrdw_empty_req_pack(request.body);
    brix_status_clear(status);
    if (brix_send(connection, &request, &payload, &stream_id, status) != 0)
        return -1;
    return brix_recv(connection, stream_id, &response, status);
}

/* WHAT: Inspect one successful response segment without typed normalization.
 * WHY: RDV-002 requires evidence that rlen, offset and handle are echoed.
 * HOW: Send one byte and parse the exact 16-byte response descriptor. */
static void
probe_echoed_descriptor(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size)
{
    uint8_t request_segment[BRIX_READV_SEGSIZE];
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    uint16_t wire_status = 0;
    brix_status status;
    uint64_t offset = size > 1 ? 1 : 0;
    int rc, ok;

    if (size == 0) return;
    brix_readv_seg_pack(request_segment, file->fhandle, 1, offset);
    rc = raw_readv(execution, connection, request_segment,
        sizeof(request_segment), 1, &wire_status, &body, &body_length,
        &status);
    ok = rc == 0 && wire_status == kXR_ok
        && body_length == BRIX_READV_SEGSIZE + 1
        && memcmp(body, file->fhandle, XRDC_FHANDLE_LEN) == 0
        && brix_readv_seg_rlen(body) == 1
        && xrd_get_u64_be(body + 8) == offset
        && body[BRIX_READV_SEGSIZE] == baseline[offset];
    xrd_conform_result_set(execution, "RDV-002",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "response-descriptor-echoed-exactly"
           : "response-descriptor-mismatch",
        "same handle, rlen and offset", ok ? NULL : status.msg);
    xrd_conform_result_set(execution, "RDV-004",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "vector-payload-byte-exact" : "vector-payload-mismatch",
        "baseline byte", ok ? NULL : status.msg);
    free(body);
}

/* WHAT: Exercise the 1024/1025 segment boundary and scatter correctness.
 * WHY: Count-limit bugs can truncate, alias, or overrun segment state.
 * HOW: Verify 1024 typed one-byte extents, then raw-send 1025 descriptors. */
static void
probe_segment_limit(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size)
{
    brix_readv_seg *segments;
    uint8_t *bytes, *payload, *body = NULL;
    uint32_t body_length = 0;
    uint16_t wire_status = 0;
    brix_status status;
    ssize_t got;
    size_t index;
    int scatter_ok = 1, refused;
    char reason[64];

    if (size == 0) return;
    segments = calloc(XRDC_VEC_MAXSEGS, sizeof(*segments));
    bytes = malloc(XRDC_VEC_MAXSEGS);
    payload = malloc((XRDC_VEC_MAXSEGS + 1U) * BRIX_READV_SEGSIZE);
    if (segments == NULL || bytes == NULL || payload == NULL) {
        xrd_conform_result_set(execution, "RDV-011",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "local-allocation-failed",
            NULL, NULL);
        free(segments); free(bytes); free(payload);
        return;
    }
    for (index = 0; index < XRDC_VEC_MAXSEGS; index++) {
        segments[index].offset = (int64_t) (index % size);
        segments[index].len = 1;
        segments[index].buf = bytes + index;
    }
    if (!xrd_conform_reserve(execution, XRDC_VEC_MAXSEGS, reason,
            sizeof(reason))) {
        xrd_conform_result_set(execution, "RDV-011",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL, NULL);
        free(segments); free(bytes); free(payload);
        return;
    }
    brix_status_clear(&status);
    got = brix_file_readv(connection, file, segments, XRDC_VEC_MAXSEGS,
        &status);
    for (index = 0; index < XRDC_VEC_MAXSEGS && scatter_ok; index++)
        scatter_ok = segments[index].got == 1
            && bytes[index] == baseline[index % size];
    for (index = 0; index <= XRDC_VEC_MAXSEGS; index++)
        brix_readv_seg_pack(payload + index * BRIX_READV_SEGSIZE,
            file->fhandle, 1, index % size);
    refused = raw_readv(execution, connection, payload,
        (XRDC_VEC_MAXSEGS + 1U) * BRIX_READV_SEGSIZE, 0, &wire_status,
        &body, &body_length, &status) != 0
        && (status.kxr == kXR_ArgTooLong || status.kxr == kXR_ArgInvalid);
    xrd_conform_result_set(execution, "RDV-011",
        got == XRDC_VEC_MAXSEGS && scatter_ok && refused
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        got == XRDC_VEC_MAXSEGS && scatter_ok && refused
            ? "segment-count-boundary-enforced"
            : "segment-count-boundary-mismatch",
        "1024 exact; 1025 refused", status.msg);
    xrd_conform_result_set(execution, "RDV-020",
        got == XRDC_VEC_MAXSEGS && scatter_ok
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        got == XRDC_VEC_MAXSEGS && scatter_ok
            ? "1024-scattered-bytes-exact"
            : "scatter-correctness-mismatch",
        "1024 exact one-byte extents", NULL);
    free(body); free(payload); free(bytes); free(segments);
}

/* WHAT: Prove malformed and signed-negative descriptors fail closed.
 * WHY: Descriptor arithmetic must not widen into unintended file access.
 * HOW: Raw-send negative offset/length spellings and a 17-byte payload. */
static void
probe_malformed(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file)
{
    uint8_t payload[BRIX_READV_SEGSIZE + 1] = { 0 };
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    uint16_t wire_status = 0;
    brix_status status;
    int negative_ok, length_ok;

    brix_readv_seg_pack(payload, file->fhandle, UINT32_MAX, UINT64_MAX);
    negative_ok = raw_readv(execution, connection, payload,
        BRIX_READV_SEGSIZE, 0, &wire_status, &body, &body_length, &status) != 0
        && status.kxr == kXR_ArgInvalid;
    free(body); body = NULL;
    xrd_conform_result_set(execution, "RDV-016",
        negative_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                    : BRIX_CONFORM_VERDICT_DIVERGENT,
        negative_ok ? "negative-vector-fields-refused"
                    : "negative-vector-fields-wrong-answer",
        "kXR_ArgInvalid", status.msg);
    length_ok = raw_readv(execution, connection, payload, sizeof(payload), 0,
        &wire_status, &body, &body_length, &status) != 0
        && status.kxr == kXR_ArgInvalid;
    xrd_conform_result_set(execution, "RDV-017",
        length_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
        length_ok ? "partial-descriptor-refused"
                  : "partial-descriptor-wrong-answer",
        "kXR_ArgInvalid", status.msg);
    free(body);
}

/* WHAT: Exercise multiple and then stale file handles in one vector.
 * WHY: A server must never substitute another live handle for a stale one.
 * HOW: Open the path twice, verify mixed handles, close one, and retry. */
static void
probe_handle_mix(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const char *path, const uint8_t *baseline, uint64_t size)
{
    uint8_t bytes[2];
    brix_readv_seg segments[2] = { 0 };
    brix_file second, *files[2] = { file, &second };
    brix_status status;
    ssize_t got;
    int opened, mixed_ok, stale_ok;
    char reason[64];

    if (size < 2) return;
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    brix_status_clear(&status);
    opened = brix_file_open_read(connection, path, &second, &status) == 0;
    if (!opened) return;
    segments[0].len = 1; segments[0].buf = bytes;
    segments[1].offset = 1; segments[1].len = 1; segments[1].buf = bytes + 1;
    if (!xrd_conform_reserve(execution, 2, reason, sizeof(reason))) {
        brix_file_close(connection, &second, &status);
        return;
    }
    got = brix_file_readv_multi(connection, files, segments, 2, &status);
    mixed_ok = got == 2 && segments[0].got == 1 && segments[1].got == 1
        && bytes[0] == baseline[0] && bytes[1] == baseline[1];
    xrd_conform_result_set(execution, "RDV-014",
        mixed_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                 : BRIX_CONFORM_VERDICT_DIVERGENT,
        mixed_ok ? "multiple-handles-served-exactly"
                 : "multiple-handle-vector-mismatch",
        "two exact extents", status.msg);
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    brix_file_close(connection, &second, &status);
    segments[0].got = segments[1].got = 0;
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    got = brix_file_readv_multi(connection, files, segments, 2, &status);
    stale_ok = got < 0 && status.kxr == kXR_FileNotOpen
        && segments[0].got == 0 && segments[1].got == 0;
    xrd_conform_result_set(execution, "RDV-015",
        stale_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                 : BRIX_CONFORM_VERDICT_DIVERGENT,
        stale_ok ? "closed-vector-handle-refused-wholesale"
                 : "closed-vector-handle-wrong-answer",
        "kXR_FileNotOpen and no bytes", status.msg);
}

/* WHAT: Read one positive decimal Qconfig limit under the run ceiling.
 * WHY: RDV-019 compares advertised caps with the exact exercised boundaries.
 * HOW: Query one key and reject suffixes, zero, overflow and empty replies. */
static int
query_limit(xrd_conform_execution *execution, brix_conn *connection,
    const char *key, size_t *limit)
{
    char value[64], reason[64], *end;
    unsigned long long parsed;
    brix_status status;

    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return 0;
    brix_status_clear(&status);
    if (brix_query(connection, kXR_Qconfig, key, value, sizeof(value),
            &status) != 0) return 0;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    while (*end == '\r' || *end == '\n' || *end == ' ' || *end == '\t') end++;
    if (errno != 0 || end == value || *end != '\0' || parsed == 0
        || parsed > SIZE_MAX) return 0;
    *limit = (size_t) parsed;
    return 1;
}

/* WHAT: Issue a bounded typed readv and require every returned byte.
 * WHY: Cap tests must distinguish exact transfer from silent truncation.
 * HOW: Reserve aggregate bytes, call the API, then compare each segment. */
static int
readv_exact(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, brix_readv_seg segments[2], size_t count,
    const uint8_t *baseline, brix_status *status)
{
    size_t index, total = 0;
    char reason[64];
    ssize_t got;

    for (index = 0; index < count; index++) total += segments[index].len;
    if (!xrd_conform_reserve(execution, total, reason, sizeof(reason))) return 0;
    brix_status_clear(status);
    got = brix_file_readv(connection, file, segments, count, status);
    if (got != (ssize_t) total) return 0;
    for (index = 0; index < count; index++) {
        if (segments[index].got != segments[index].len
            || memcmp(segments[index].buf,
                baseline + (size_t) segments[index].offset,
                segments[index].len) != 0) return 0;
    }
    return 1;
}

/* WHAT: Reconcile per-element and vector-total Qconfig limits with behavior.
 * WHY: RDV-012/013/019 are claims checks, not hard-coded implementation facts.
 * HOW: Probe exact/+1 totals, exact/+1 element sizes and the count cap. */
static void
probe_transfer_limits(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size)
{
    brix_readv_seg segments[2] = { 0 };
    brix_status status;
    uint8_t *buffer;
    size_t byte_cap, count_cap, first;
    ssize_t got;
    int total_ok, element_ok, advertised_ok;
    char reason[64];

    if (!query_limit(execution, connection, "readv_ior_max", &byte_cap)
        || !query_limit(execution, connection, "readv_iov_max", &count_cap)
        || byte_cap > 64U * 1024U * 1024U || size <= byte_cap + 1U) return;
    buffer = malloc(byte_cap + 1U);
    if (buffer == NULL) return;
    first = byte_cap / 2U;
    segments[0].len = first; segments[0].buf = buffer;
    segments[1].offset = (int64_t) first;
    segments[1].len = byte_cap - first; segments[1].buf = buffer + first;
    total_ok = readv_exact(execution, connection, file, segments, 2,
        baseline, &status);
    segments[1].len++;
    total_ok = total_ok && readv_exact(execution, connection, file, segments,
        2, baseline, &status);
    xrd_conform_result_set(execution, "RDV-012",
        total_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                 : BRIX_CONFORM_VERDICT_DIVERGENT,
        total_ok ? "aggregate-exceeds-element-cap-exactly"
                 : "per-element-cap-misapplied-to-vector-total",
        "cap and cap+1 totals exact", status.msg);

    memset(segments, 0, sizeof(segments));
    segments[0].len = byte_cap; segments[0].buf = buffer;
    element_ok = readv_exact(execution, connection, file, segments, 1,
        baseline, &status);
    segments[0].len = byte_cap + 1U; segments[0].got = 0;
    if (!xrd_conform_reserve(execution, byte_cap + 1U, reason,
            sizeof(reason))) element_ok = 0;
    else {
        brix_status_clear(&status);
        got = brix_file_readv(connection, file, segments, 1, &status);
        element_ok = element_ok && (got < 0
            || (got == (ssize_t) byte_cap && segments[0].got == byte_cap
                && memcmp(buffer, baseline, byte_cap) == 0));
    }
    xrd_conform_result_set(execution, "RDV-013",
        element_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                   : BRIX_CONFORM_VERDICT_DIVERGENT,
        element_ok ? "advertised-element-cap-enforced"
                   : "advertised-element-cap-mismatch",
        "cap exact; cap+1 refused or explicitly short", status.msg);
    advertised_ok = element_ok && count_cap == XRDC_VEC_MAXSEGS;
    xrd_conform_result_set(execution, "RDV-019",
        advertised_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                      : BRIX_CONFORM_VERDICT_DIVERGENT,
        advertised_ok ? "advertised-readv-limits-observed"
                      : "advertised-readv-limits-mismatch",
        "readv_ior_max observed; readv_iov_max=1024", NULL);
    free(buffer);
}

void
xrd_conform_probe_readv_limits(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path,
    const uint8_t *baseline, uint64_t size)
{
    probe_echoed_descriptor(execution, connection, file, baseline, size);
    probe_segment_limit(execution, connection, file, baseline, size);
    probe_transfer_limits(execution, connection, file, baseline, size);
    probe_malformed(execution, connection, file);
    probe_handle_mix(execution, connection, file, path, baseline, size);
}
