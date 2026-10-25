/* Phase-118 read-only kXR_open option, lifetime, and hostile-path probes. */
#include "xrd_conform_probe_helpers.h"
#include "protocols/root/protocol/frame_hdr.h"
#include "xrd_conform_reply.h"
#include "core/compat/codec_core.h"
#include "protocols/root/protocol/codec/wire_codec.h"

#include <arpa/inet.h>




static void
grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const brix_status *status)
{
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : "unexpected-open-answer", NULL,
        pass || status == NULL ? NULL : status->msg);
}


/* Send an exact open payload so option and malformed-path rows share framing. */
static int
raw_open(xrd_conform_execution *execution, brix_conn *connection,
    uint16_t options, const void *path, uint32_t path_length,
    xrd_conform_wire_reply *reply, brix_status *status)
{
    ClientOpenRequest request;
    xrdw_open_req_t fields = { .mode = 0, .options = options, .optiont = 0 };
    brix_payload payload = { path, path_length };
    uint16_t wire_status = 0;
    brix_resp_out response = { &wire_status, &reply->body, &reply->length };

    memset(reply, 0, sizeof(*reply));
    if (!xrd_conform_reserve_probe(execution, sizeof(request) + path_length)) return -1;
    xrd_creq_begin(&request, sizeof(request), 0, kXR_open);
    xrdw_open_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(status);
    return brix_roundtrip(connection, &request, &payload, &response, status);
}

static int
close_reply(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_wire_reply *reply, brix_status *status)
{
    brix_file file;

    if (reply->length < XRD_FHANDLE_LEN || !xrd_conform_reserve_probe(execution, 0)) return -1;
    memset(&file, 0, sizeof(file));
    memcpy(file.fhandle, reply->body, XRD_FHANDLE_LEN);
    brix_status_clear(status);
    return brix_file_close(connection, &file, status);
}

static int
raw_stat(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, uint8_t **body, uint32_t *length, brix_status *status)
{
    ClientStatRequest request;
    xrdw_stat_req_t fields = { .options = 0, .wants = 0 };
    brix_payload payload = { path, (uint32_t) strlen(path) };
    uint16_t wire_status = 0;
    brix_resp_out response = { &wire_status, body, length };

    if (!xrd_conform_reserve_probe(execution, sizeof(request) + payload.len)) return -1;
    xrd_creq_begin(&request, sizeof(request), 0, kXR_stat);
    xrdw_stat_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(status);
    return brix_roundtrip(connection, &request, &payload, &response, status);
}

static void
grade_retstat_match(xrd_conform_execution *execution,
    const xrd_conform_wire_reply *stat_open, int stat_ok, const uint8_t *stat_body,
    uint32_t stat_length, int wire_stat_ok)
{
    int matches = stat_ok && wire_stat_ok
        && stat_open->length == sizeof(ServerOpenBody) + stat_length
        && memcmp(stat_open->body + sizeof(ServerOpenBody), stat_body,
            stat_length) == 0;
    char received[160];

    snprintf(received, sizeof(received),
        "open_len=%u stat_len=%u open_stat=%.48s path_stat=%.48s",
        stat_open->length, stat_length,
        stat_ok && stat_open->length > sizeof(ServerOpenBody)
            ? (char *) stat_open->body + sizeof(ServerOpenBody) : "-",
        wire_stat_ok ? (char *) stat_body : "-");
    xrd_conform_result_set(execution, "OPN-006",
        matches ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        matches ? "retstat-body-matches-path-stat"
                : "retstat-body-differs-from-path-stat",
        NULL, matches ? NULL : received);
}

static void
probe_compression_shape(xrd_conform_execution *execution,
    brix_conn *connection, const char *path, xrd_conform_wire_reply *compressed,
    brix_status *status)
{
    int compressed_ok;
    uint32_t cpsize;
    uint8_t codec;
    int tuple_ok;
    char received[96];

    if (!xrd_conform_row_active(execution, "OPN-007")) return;
    compressed_ok = raw_open(execution, connection,
        kXR_open_read | kXR_compress, path, (uint32_t) strlen(path),
        compressed, status) == 0;
    cpsize = compressed_ok && compressed->length >= sizeof(ServerOpenBody)
        ? xrdw_get_u32(compressed->body + 4) : UINT32_MAX;
    codec = compressed_ok && compressed->length >= sizeof(ServerOpenBody)
        ? compressed->body[8] : 0;
    tuple_ok = compressed_ok && compressed->length >= sizeof(ServerOpenBody)
        && (cpsize == 0 || (cpsize == BRIX_INLINE_CMP_MAGIC
            && codec > BRIX_CODEC_IDENTITY && codec < BRIX_CODEC_MAX
            && brix_codec_available(codec)));
    snprintf(received, sizeof(received), "length=%u cpsize=%u codec=%u",
        compressed->length, cpsize, (unsigned) codec);
    xrd_conform_result_set(execution, "OPN-007",
        tuple_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                 : BRIX_CONFORM_VERDICT_DIVERGENT,
        tuple_ok ? "compression-tuple-is-plaintext-or-supported-codec"
                 : "invalid-compression-tuple",
        NULL, tuple_ok ? NULL : received);
}

static void
probe_response_shapes(xrd_conform_execution *execution, brix_conn *connection,
    const char *path)
{
    xrd_conform_wire_reply plain = { 0 }, stat_open = { 0 }, compressed = { 0 };
    uint8_t *stat_body = NULL;
    uint32_t stat_length = 0;
    brix_status status;
    int plain_ok = raw_open(execution, connection, kXR_open_read, path,
        (uint32_t) strlen(path), &plain, &status) == 0;
    int stat_ok = raw_open(execution, connection,
        kXR_open_read | kXR_retstat, path, (uint32_t) strlen(path),
        &stat_open, &status) == 0;

    if (xrd_conform_row_active(execution, "OPN-005"))
        grade(execution, "OPN-005", plain_ok && stat_ok
            && plain.length == XRD_FHANDLE_LEN
            && stat_open.length > sizeof(ServerOpenBody),
            "retstat-controls-inline-stat-body", &status);
    if (xrd_conform_row_active(execution, "OPN-006")) {
        int wire_stat_ok = raw_stat(execution, connection, path, &stat_body,
            &stat_length, &status) == 0;

        grade_retstat_match(execution, &stat_open, stat_ok, stat_body,
            stat_length, wire_stat_ok);
    }
    probe_compression_shape(execution, connection, path, &compressed, &status);
    if (plain_ok) close_reply(execution, connection, &plain, &status);
    if (stat_ok) close_reply(execution, connection, &stat_open, &status);
    if (compressed.body != NULL)
        close_reply(execution, connection, &compressed, &status);
    free(plain.body);
    free(stat_open.body);
    free(compressed.body);
    free(stat_body);
}

static void
probe_closed_handle(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *primary, const char *path)
{
    brix_file file;
    brix_status status;
    uint8_t byte;
    int opened;
    int distinct;
    int closed;
    int read_refused;
    int second_refused;

    if (!xrd_conform_reserve_probe(execution, 0)) return;
    brix_status_clear(&status);
    opened = brix_file_open_read(connection, path, &file, &status) == 0;
    distinct = opened && memcmp(primary->fhandle, file.fhandle,
        XRD_FHANDLE_LEN) != 0;
    closed = opened && xrd_conform_reserve_probe(execution, 0)
        && brix_file_close(connection, &file, &status) == 0;
    brix_status_clear(&status);
    read_refused = closed && xrd_conform_reserve_probe(execution, 1)
        && brix_file_read(connection, &file, 0, &byte, 1, &status) < 0
        && status.kxr == kXR_FileNotOpen;
    grade(execution, "OPN-003", distinct && read_refused,
        "closed-handle-refused-until-reissued", &status);
    brix_status_clear(&status);
    second_refused = closed && xrd_conform_reserve_probe(execution, 0)
        && brix_file_close(connection, &file, &status) != 0
        && status.kxr == kXR_FileNotOpen;
    grade(execution, "OPN-030", closed && second_refused,
        "valid-close-succeeded-and-double-close-refused", &status);
}

static int
send_reserved_close(xrd_conform_execution *execution, brix_conn *connection,
    const brix_file *file, int *close_rc, brix_status *status)
{
    ClientCloseRequest request;
    xrdw_close_req_t fields;
    uint16_t wire_status = 0;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_resp_out response = { &wire_status, &body, &body_length };
    int close_kxr;
    int defined;

    memset(&request, 0, sizeof(request));
    memset(&fields, 0, sizeof(fields));
    memcpy(fields.fhandle, file->fhandle, XRD_FHANDLE_LEN);
    request.requestid = htons(kXR_close);
    xrdw_close_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    memset(((ClientRequestHdr *) &request)->body + XRD_FHANDLE_LEN, 0xa5,
        XRDW_BODY_LEN - XRD_FHANDLE_LEN);
    brix_status_clear(status);
    *close_rc = xrd_conform_reserve_probe(execution, 0)
        ? brix_roundtrip(connection, &request, NULL, &response, status) : -1;
    close_kxr = status->kxr;
    defined = (*close_rc == 0 && wire_status == kXR_ok && body_length == 0)
        || (*close_rc != 0 && close_kxr == kXR_ArgInvalid);
    free(body);
    return defined;
}

static int
reopen_first_byte(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, const uint8_t *baseline, brix_file *file,
    brix_status *status)
{
    uint8_t byte = 0;
    int read_ok;

    if (!xrd_conform_reserve_probe(execution, 0)
        || brix_file_open_read(connection, path, file, status) != 0) return 0;
    read_ok = xrd_conform_reserve_probe(execution, 1)
        && brix_file_read(connection, file, 0, &byte, 1, status) == 1
        && byte == baseline[0];
    if (xrd_conform_reserve_probe(execution, 0))
        brix_file_close(connection, file, status);
    return read_ok;
}

/* WHAT: Exercise the twelve reserved bytes in the authoritative close body.
 * WHY: The wire has no client-supplied size; treating reserved bytes as one
 * invents a destructive contract that the protocol does not define.
 * HOW: Close a read handle with a non-zero reserved region. Accept either an
 * atomic ArgInvalid refusal or a successful ignored-reserved close, then
 * reopen and require the original first byte. */
static void
probe_close_reserved(xrd_conform_execution *execution,
    brix_conn *connection, const char *path, const uint8_t *baseline,
    uint64_t size)
{
    brix_file file;
    brix_status status;
    int close_rc;
    int close_defined;
    int read_ok = 0;

    if (!xrd_conform_row_active(execution, "OPN-031")) return;
    brix_status_clear(&status);
    if (size == 0 || !xrd_conform_reserve_probe(execution, 0)
        || brix_file_open_read(connection, path, &file, &status) != 0) {
        xrd_conform_result_set(execution, "OPN-031",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "close-target-unavailable",
            NULL, status.msg);
        return;
    }
    close_defined = send_reserved_close(execution, connection, &file,
        &close_rc, &status);
    if (close_rc != 0 && xrd_conform_reserve_probe(execution, 0))
        brix_file_close(connection, &file, &status);
    if (close_defined)
        read_ok = reopen_first_byte(execution, connection, path, baseline,
            &file, &status);
    grade(execution, "OPN-031", close_defined && read_ok,
        close_rc == 0 ? "reserved-close-bytes-ignored-safely"
                      : "reserved-close-bytes-refused-atomically",
        &status);
}

/* WHAT: Fill the session handle table, preserve an existing capability, then
 * prove the table accepts a new open after every temporary handle is closed.
 * WHY: Exhaustion must be a bounded per-session error, not corruption or a
 * permanent denial of service for the connection.
 * HOW: Hold read handles until NoMemory, read through the caller's original
 * handle at the limit, release all held handles, and perform one recovery open. */
static void
probe_handle_exhaustion(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *primary, const char *path,
    const uint8_t *baseline, uint64_t size)
{
    brix_file held[255];
    brix_file recovered;
    brix_status status;
    uint8_t byte = 0;
    size_t count = 0;
    int refused = 0;
    int original_ok = 0;
    int recovered_ok = 0;

    if (!xrd_conform_row_active(execution, "OPN-032")) return;
    while (count < sizeof(held) / sizeof(held[0])
        && xrd_conform_reserve_probe(execution, 0)) {
        brix_status_clear(&status);
        if (brix_file_open_read(connection, path, &held[count], &status) != 0) {
            refused = status.kxr == kXR_NoMemory;
            break;
        }
        count++;
    }
    if (size > 0 && xrd_conform_reserve_probe(execution, 1)) {
        brix_status_clear(&status);
        original_ok = brix_file_read(connection, primary, 0, &byte, 1,
            &status) == 1 && byte == baseline[0];
    }
    while (count > 0) {
        count--;
        if (xrd_conform_reserve_probe(execution, 0))
            brix_file_close(connection, &held[count], &status);
    }
    if (xrd_conform_reserve_probe(execution, 0)
        && brix_file_open_read(connection, path, &recovered, &status) == 0) {
        recovered_ok = 1;
        if (xrd_conform_reserve_probe(execution, 0))
            brix_file_close(connection, &recovered, &status);
    }
    grade(execution, "OPN-032", refused && original_ok && recovered_ok,
        "handle-limit-refused-and-session-recovered", &status);
}

static void
probe_advisory_option(xrd_conform_execution *execution,
    brix_conn *connection, const char *path, uint16_t option, const char *id,
    const uint8_t *baseline, uint64_t size)
{
    xrd_conform_wire_reply reply = { 0 };
    brix_file file;
    brix_status status;
    uint8_t byte = 0;
    int opened;
    int read_ok = 0;

    if (!xrd_conform_row_active(execution, id)) return;
    if (size == 0) {
        xrd_conform_result_set(execution, id,
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "object-is-empty", NULL, NULL);
        return;
    }
    opened = raw_open(execution, connection, kXR_open_read | option, path,
        (uint32_t) strlen(path), &reply, &status) == 0
        && reply.length >= XRD_FHANDLE_LEN;
    if (opened) {
        memset(&file, 0, sizeof(file));
        memcpy(file.fhandle, reply.body, XRD_FHANDLE_LEN);
        read_ok = xrd_conform_reserve_probe(execution, 1)
            && brix_file_read(connection, &file, 0, &byte, 1, &status) == 1
            && byte == baseline[0];
        if (xrd_conform_reserve_probe(execution, 0))
            brix_file_close(connection, &file, &status);
    }
    grade(execution, id, opened && read_ok,
        "advisory-open-preserved-read-bytes", &status);
    free(reply.body);
}

static int
path_open_refused(xrd_conform_execution *execution, brix_conn *connection,
    const void *path, uint32_t length, int expected, brix_status *status)
{
    xrd_conform_wire_reply reply = { 0 };
    int rc = raw_open(execution, connection, kXR_open_read, path, length,
        &reply, status);

    if (rc == 0) close_reply(execution, connection, &reply, status);
    free(reply.body);
    return rc != 0 && (expected == 0 || status->kxr == expected);
}

static void
probe_path_limits(xrd_conform_execution *execution, brix_conn *connection)
{
    uint8_t long_path[4096];
    static const uint8_t nul_path[] = "/../brix\0-tail";
    static const char *const traversal[] = {
        "/../../../../brix-conform-escape",
        "/%2e%2e%2f%2e%2e%2fbrix-conform-escape",
        "/..//..//brix-conform-escape",
        "/\\..\\..\\brix-conform-escape",
        "/\xc0\xae\xc0\xae/brix-conform-escape",
    };
    brix_status status;
    size_t index;
    int traversal_ok = 1;

    if (xrd_conform_row_active(execution, "OPN-027")) {
        memset(long_path, 'a', sizeof(long_path));
        long_path[0] = '/';
        grade(execution, "OPN-027", path_open_refused(execution, connection,
            long_path, sizeof(long_path), kXR_ArgTooLong, &status),
            "overlong-path-returned-arg-too-long", &status);
    }
    if (xrd_conform_row_active(execution, "OPN-028"))
        grade(execution, "OPN-028", path_open_refused(execution, connection,
            NULL, 0, kXR_ArgMissing, &status),
            "empty-path-returned-arg-missing", &status);
    if (!xrd_conform_row_active(execution, "OPN-029")) return;
    for (index = 0; traversal_ok
        && index < sizeof(traversal) / sizeof(traversal[0]); index++)
        traversal_ok = path_open_refused(execution, connection,
            traversal[index], (uint32_t) strlen(traversal[index]), 0, &status);
    if (traversal_ok)
        traversal_ok = path_open_refused(execution, connection, nul_path,
            sizeof(nul_path) - 1, 0, &status);
    grade(execution, "OPN-029", traversal_ok,
        "traversal-forms-remained-confined", &status);
}

void
xrd_conform_probe_root_open(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *primary, const char *path,
    const uint8_t *baseline, uint64_t size)
{
    if (xrd_conform_row_active(execution, "OPN-003")
        || xrd_conform_row_active(execution, "OPN-030"))
        probe_closed_handle(execution, connection, primary, path);
    probe_close_reserved(execution, connection, path, baseline, size);
    probe_handle_exhaustion(execution, connection, primary, path, baseline,
        size);
    if (xrd_conform_row_active(execution, "OPN-005")
        || xrd_conform_row_active(execution, "OPN-006")
        || xrd_conform_row_active(execution, "OPN-007"))
        probe_response_shapes(execution, connection, path);
    probe_advisory_option(execution, connection, path, kXR_seqio, "OPN-018",
        baseline, size);
    probe_advisory_option(execution, connection, path, kXR_async, "OPN-019",
        baseline, size);
    probe_path_limits(execution, connection);
}
