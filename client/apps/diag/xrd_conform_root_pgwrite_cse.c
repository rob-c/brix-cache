/* Phase-118 raw pgwrite checksum-error and correction probes. */
#include "xrd_conform_probe_helpers.h"
#include "core/compat/crc32c.h"
#include "core/compat/pgio.h"
#include "protocols/root/protocol/codec/wire_codec.h"
#include "protocols/root/protocol/frame_hdr.h"

typedef struct {
    uint16_t status;
    uint8_t body[24];
    uint32_t body_length;
    uint8_t *trailer;
    uint32_t trailer_length;
} pgw_reply;



static int
send_pgwrite(brix_conn *connection, brix_file *file, int64_t offset,
    uint8_t flags, const uint8_t *payload, size_t length, uint16_t *stream_id,
    brix_status *status)
{
    ClientPgWriteRequest request;
    xrdw_pgwrite_req_t fields = {
        .offset = offset, .pathid = 0, .reqflags = flags
    };
    brix_payload body = { payload, (uint32_t) length };

    memcpy(fields.fhandle, file->fhandle, sizeof(fields.fhandle));
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_pgwrite);
    xrdw_pgwrite_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    return brix_send(connection, &request, &body, stream_id, status);
}

/* ---- Drain an unexpected bounded response body ----
 *
 * WHAT: Consumes length bytes and returns zero, or -1 on transport failure.
 * WHY: A hostile pgwrite status is evidence for the selected clause, but its
 *      body must not remain queued and corrupt the following cleanup frame.
 * HOW: Read fixed-size chunks through the shared exact-read helper until the
 *      complete advertised body has been discarded.
 */
static int
discard_reply_body(brix_conn *connection, uint32_t length,
    brix_status *status)
{
    uint8_t chunk[256];

    while (length > 0) {
        size_t take = length < sizeof(chunk) ? length : sizeof(chunk);

        if (brix_read_full(&connection->io, chunk, take, status) != 0)
            return -1;
        length -= (uint32_t) take;
    }
    return 0;
}

static int
read_pgwrite_reply(brix_conn *connection, uint16_t want_stream,
    pgw_reply *reply, brix_status *status)
{
    uint8_t header[XRD_RESPONSE_HDR_LEN];
    uint16_t stream_id;
    uint32_t length;

    memset(reply, 0, sizeof(*reply));
    if (brix_read_full(&connection->io, header, sizeof(header), status) != 0)
        return -1;
    xrd_resp_hdr_unpack(header, &stream_id, &reply->status, &length);
    if (stream_id != want_stream || reply->status != kXR_status
        || length != sizeof(reply->body)) {
        discard_reply_body(connection, length, status);
        return -1;
    }
    if (brix_read_full(&connection->io, reply->body, length, status) != 0)
        return -1;
    reply->body_length = length;
    reply->trailer_length = xrd_get_u32_be(reply->body + 12);
    if (reply->trailer_length > 4096) return -1;
    if (reply->trailer_length > 0) {
        reply->trailer = malloc(reply->trailer_length);
        if (reply->trailer == NULL
            || brix_read_full(&connection->io, reply->trailer,
                reply->trailer_length, status) != 0) {
            free(reply->trailer);
            reply->trailer = NULL;
            return -1;
        }
    }
    return 0;
}

static int
fixed_status_valid(const pgw_reply *reply, uint16_t stream_id,
    int64_t offset)
{
    return reply->body_length == 24
        && xrd_get_u32_be(reply->body) == brix_crc32c_value(reply->body + 4, 20)
        && xrd_get_u16_be(reply->body + 4) == stream_id
        && reply->body[6] == kXR_pgwrite - kXR_1stRequest
        && reply->body[7] == kXR_FinalResult
        && reply->body[8] == 0 && reply->body[9] == 0
        && reply->body[10] == 0 && reply->body[11] == 0
        && (int64_t) xrdw_get_u64(reply->body + 16) == offset;
}

static int
cse_valid(const pgw_reply *reply)
{
    if (reply->trailer_length != 16 || reply->trailer == NULL) return 0;
    return xrd_get_u32_be(reply->trailer)
            == brix_crc32c_value(reply->trailer + 4, 12)
        && xrd_get_u16_be(reply->trailer + 4) == 4096
        && xrd_get_u16_be(reply->trailer + 6) == 4096
        && (int64_t) xrdw_get_u64(reply->trailer + 8) == 0;
}

static uint8_t *
bad_pages_payload(xrd_conform_execution *execution, int64_t offset,
    size_t pages, size_t *payload_length)
{
    size_t data_length = pages * (size_t) kXR_pgPageSZ;
    uint8_t *data = malloc(data_length);
    uint8_t *payload = malloc(pages * (size_t) kXR_pgUnitSZ);
    size_t index;

    if (data == NULL || payload == NULL) {
        free(data);
        free(payload);
        return NULL;
    }
    brix_conform_fill(&execution->run->key, (uint64_t) offset, data,
        data_length);
    *payload_length = xrdp_pg_encode(data, data_length, offset, payload);
    free(data);
    for (index = 0; index < pages; index++)
        payload[index * (size_t) kXR_pgUnitSZ] ^= 0x80;
    return payload;
}

static int
send_bad_pages(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, int64_t offset, size_t pages, pgw_reply *reply,
    brix_status *status)
{
    uint8_t *payload;
    uint16_t stream_id;
    size_t payload_length;
    int rc = -1;

    payload = bad_pages_payload(execution, offset, pages, &payload_length);
    if (payload != NULL && xrd_conform_reserve_probe(execution, payload_length)
        && send_pgwrite(connection, file, offset, 0, payload, payload_length,
            &stream_id, status) == 0
        && read_pgwrite_reply(connection, stream_id, reply, status) == 0)
        rc = 0;
    free(payload);
    return rc;
}

static int
read_too_many_errors(brix_conn *connection, uint16_t want_stream,
    brix_status *status)
{
    uint8_t header[XRD_RESPONSE_HDR_LEN];
    uint8_t *body;
    uint16_t stream_id;
    uint16_t wire_status;
    uint32_t length;
    int matched;

    if (brix_read_full(&connection->io, header, sizeof(header), status) != 0)
        return 0;
    xrd_resp_hdr_unpack(header, &stream_id, &wire_status, &length);
    if (stream_id != want_stream || length > 4096) return 0;
    body = length == 0 ? NULL : malloc(length);
    if (length > 0 && (body == NULL
        || brix_read_full(&connection->io, body, length, status) != 0)) {
        free(body);
        return 0;
    }
    matched = wire_status == kXR_error && length >= 4
        && xrdw_get_u32(body) == kXR_TooManyErrs;
    free(body);
    return matched;
}

static int
correct_outstanding_pages(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, size_t pages, brix_status *status)
{
    uint8_t data[kXR_pgPageSZ];
    uint8_t payload[kXR_pgUnitSZ];
    pgw_reply reply;
    uint16_t stream_id;
    size_t index;
    size_t payload_length;

    for (index = 0; index < pages; index++) {
        int64_t offset = (int64_t) index * kXR_pgPageSZ;

        brix_conform_fill(&execution->run->key, (uint64_t) offset, data,
            sizeof(data));
        payload_length = xrdp_pg_encode(data, sizeof(data), offset, payload);
        if (!xrd_conform_reserve_probe(execution, payload_length)
            || send_pgwrite(connection, file, offset, kXR_pgRetry, payload,
                payload_length, &stream_id, status) != 0
            || read_pgwrite_reply(connection, stream_id, &reply, status) != 0)
            return 0;
        free(reply.trailer);
        if (!fixed_status_valid(&reply, stream_id, offset)
            || reply.trailer_length != 0) return 0;
    }
    return 1;
}

static void
send_outstanding_batches(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, pgw_reply *first,
    pgw_reply *second, int *first_ok, int *second_ok, brix_status *status)
{
    const size_t pages = kXR_pgMaxEpr;
    const int64_t second_offset = (int64_t) pages * kXR_pgPageSZ;

    if (send_bad_pages(execution, connection, file, 0, pages, first,
            status) == 0) {
        *first_ok = first->trailer_length == 8 + pages * 8;
        free(first->trailer);
    }
    if (*first_ok && send_bad_pages(execution, connection, file,
            second_offset, pages, second, status) == 0) {
        *second_ok = second->trailer_length == 8 + pages * 8;
        free(second->trailer);
    }
}

static int
probe_terminal_error(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, int64_t offset,
    brix_status *status)
{
    uint8_t *payload;
    uint16_t stream_id;
    size_t payload_length;
    int matched = 0;

    payload = bad_pages_payload(execution, offset, 1, &payload_length);
    if (payload != NULL && xrd_conform_reserve_probe(execution, payload_length)
        && send_pgwrite(connection, file, offset, 0, payload, payload_length,
            &stream_id, status) == 0)
        matched = read_too_many_errors(connection, stream_id, status);
    free(payload);
    return matched;
}

static void
probe_outstanding_limit(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object)
{
    const size_t batch_pages = kXR_pgMaxEpr;
    const int64_t second_offset = (int64_t) batch_pages * kXR_pgPageSZ;
    const int64_t terminal_offset = 2 * second_offset;
    pgw_reply first;
    pgw_reply second;
    brix_file file;
    brix_status status;
    int first_ok = 0;
    int second_ok = 0;
    int terminal = 0;
    int corrected = 0;

    if (execution->requests > execution->run->config.request_limit
        || execution->run->config.request_limit - execution->requests < 261
        || execution->bytes > execution->run->config.byte_limit
        || execution->run->config.byte_limit - execution->bytes < 2200000) {
        xrd_conform_result_set(execution, "PGW-010",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "budget-insufficient-for-clean-cse-limit-probe",
            "261 requests and 2.2 MiB remaining", NULL);
        return;
    }

    brix_status_clear(&status);
    if (!xrd_conform_reserve_probe(execution, 0)
        || brix_file_open_write(connection, object->path, 1, 0, &file,
            &status) != 0) return;
    send_outstanding_batches(execution, connection, &file, &first, &second,
        &first_ok, &second_ok, &status);
    if (second_ok)
        terminal = probe_terminal_error(execution, connection, &file,
            terminal_offset, &status);
    if (terminal)
        corrected = correct_outstanding_pages(execution, connection, &file,
            2 * batch_pages, &status);
    if (corrected && xrd_conform_reserve_probe(execution, 0))
        corrected = brix_file_close(connection, &file, &status) == 0;
    xrd_conform_grade_status(execution, "PGW-010", first_ok && second_ok && terminal && corrected,
        "outstanding-cse-cap-enforced", "outstanding-cse-cap-not-enforced",
        &status);
}

static int
retry_page(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *data, brix_status *status)
{
    uint8_t payload[4100];
    pgw_reply reply;
    uint16_t stream_id;
    size_t payload_length = xrdp_pg_encode(data, 4096, 0, payload);
    int passed = 0;

    if (xrd_conform_reserve_probe(execution, payload_length)
        && send_pgwrite(connection, file, 0, kXR_pgRetry, payload,
            payload_length, &stream_id, status) == 0
        && read_pgwrite_reply(connection, stream_id, &reply, status) == 0) {
        passed = fixed_status_valid(&reply, stream_id, 0)
            && reply.trailer_length == 0;
        free(reply.trailer);
    }
    return passed && xrd_conform_reserve_probe(execution, 0)
        && brix_file_close(connection, file, status) == 0;
}

static int
readback_page(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, const uint8_t *expected,
    brix_status *status)
{
    uint8_t actual[4096];
    brix_file file;
    int passed = 0;

    if (xrd_conform_reserve_probe(execution, 0)
        && brix_file_open_read(connection, object->path, &file, status) == 0) {
        if (xrd_conform_reserve_probe(execution, sizeof(actual)))
            passed = brix_file_read(connection, &file, 0, actual,
                sizeof(actual), status) == (ssize_t) sizeof(actual)
                && memcmp(actual, expected, sizeof(actual)) == 0;
        if (xrd_conform_reserve_probe(execution, 0))
            brix_file_close(connection, &file, status);
    }
    return passed;
}

void
xrd_conform_probe_pgwrite_cse(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object)
{
    uint8_t data[4096];
    uint8_t payload[4100];
    brix_file file;
    brix_status status;
    pgw_reply bad_reply;
    uint16_t stream_id;
    size_t payload_length;
    int bad_ok = 0;
    int retry_ok = 0;
    int close_gated = 0;
    int readback_ok = 0;

    brix_conform_fill(&execution->run->key, 8192, data, sizeof(data));
    brix_status_clear(&status);
    if (!xrd_conform_reserve_probe(execution, 0)
        || brix_file_open_write(connection, object->path, 1, 0, &file,
            &status) != 0) return;
    payload_length = xrdp_pg_encode(data, sizeof(data), 0, payload);
    payload[0] ^= 0x80;
    if (xrd_conform_reserve_probe(execution, payload_length)
        && send_pgwrite(connection, &file, 0, 0, payload, payload_length,
            &stream_id, &status) == 0
        && read_pgwrite_reply(connection, stream_id, &bad_reply, &status) == 0) {
        bad_ok = fixed_status_valid(&bad_reply, stream_id, 0)
            && cse_valid(&bad_reply);
        free(bad_reply.trailer);
    }
    xrd_conform_grade_status(execution, "PGW-005", bad_ok, "bad-crc-reported-in-cse",
        "bad-crc-not-reported", &status);
    xrd_conform_grade_status(execution, "PGW-007", bad_ok, "cse-lengths-and-offset-list-valid",
        "cse-structure-invalid", &status);
    xrd_conform_grade_status(execution, "PGW-008", bad_ok, "cse-crc32c-valid",
        "cse-crc32c-invalid", &status);

    if (bad_ok && xrd_conform_reserve_probe(execution, 0))
        close_gated = brix_file_close(connection, &file, &status) != 0
            && status.kxr == kXR_ChkSumErr;
    xrd_conform_grade_status(execution, "PGW-006", close_gated,
        "uncorrected-page-gated-close", "uncorrected-page-finalized", &status);

    if (close_gated)
        retry_ok = retry_page(execution, connection, &file, data, &status);
    if (retry_ok)
        readback_ok = readback_page(execution, connection, object, data,
            &status);
    xrd_conform_grade_status(execution, "PGW-009", retry_ok && readback_ok,
        "rejected-page-retry-corrected-object", "pgwrite-retry-failed", &status);
    if (xrd_conform_row_active(execution, "PGW-010"))
        probe_outstanding_limit(execution, connection, object);
}
