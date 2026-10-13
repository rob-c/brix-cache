/* Phase-118 raw ROOT read argument and handle probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/readv_seg.h"

#include <arpa/inet.h>

/* ---- Issue one deliberately shaped kXR_read ----
 *
 * WHAT: Returns the raw operation result and optional owned response body.
 * WHY: Typed reads cannot express negative lengths, bad handles or read args.
 * HOW: Pack the in-repo codec, reserve the bounded exchange, send and receive.
 */
int
xrd_conform_root_raw_read(xrd_conform_execution *execution,
    brix_conn *connection,
    const uint8_t handle[XRDC_FHANDLE_LEN], int64_t offset, int32_t length,
    const void *args, uint32_t args_length, size_t expected_bytes,
    uint16_t *wire_status,
    uint8_t **body, uint32_t *body_length, brix_status *status)
{
    ClientReadRequest request;
    xrdw_read_req_t fields = { .offset = offset, .rlen = length };
    brix_payload payload = { args, args_length };
    brix_resp_out response = { wire_status, body, body_length };
    uint16_t stream_id;
    char reason[64];

    if (!xrd_conform_reserve(execution, expected_bytes,
            reason, sizeof(reason))) {
        brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
        return -1;
    }
    memcpy(fields.fhandle, handle, sizeof(fields.fhandle));
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_read);
    xrdw_read_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(status);
    if (brix_send(connection, &request,
            args_length == 0 ? NULL : &payload, &stream_id, status) != 0)
        return -1;
    return brix_recv(connection, stream_id, &response, status);
}

/* ---- Grade one expected read refusal ----
 *
 * WHAT: Records whether a shaped read failed with the required kXR error.
 * WHY: Security-negative read rows must distinguish safe refusal from faults.
 * HOW: Execute, free any body, and compare the typed status code exactly.
 */
static void
grade_refusal(xrd_conform_execution *execution, brix_conn *connection,
    const char *id, const uint8_t handle[XRDC_FHANDLE_LEN], int64_t offset,
    int32_t length, const void *args, uint32_t args_length, int expected_kxr,
    const char *pass_reason)
{
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    uint16_t wire_status = 0;
    brix_status status;
    int rc;

    rc = xrd_conform_root_raw_read(execution, connection, handle, offset,
        length, args,
        args_length, 0, &wire_status, &body, &body_length, &status);
    free(body);
    xrd_conform_result_set(execution, id,
        rc != 0 && status.kxr == expected_kxr
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        rc != 0 && status.kxr == expected_kxr
            ? pass_reason : "raw-read-wrong-answer",
        brix_kxr_name(expected_kxr), status.msg);
}

/* ---- Grade primary and invalid path-id request arguments ----
 *
 * WHAT: Exercises RD-020 and RD-021 with one-byte reads carrying read_args.
 * WHY: A path id must select only a bound transport, never arbitrary state.
 * HOW: Compare pathid zero bytes, then require refusal of an unbound id.
 */
static void
probe_path_ids(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size)
{
    uint8_t primary[BRIX_READ_ARGS_LEN] = { 0 };
    uint8_t invalid[BRIX_READ_ARGS_LEN] = { 0xfe };
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    uint16_t wire_status = 0;
    brix_status status;
    int rc;
    int ok;

    if (size == 0) return;
    rc = xrd_conform_root_raw_read(execution, connection, file->fhandle, 0, 1,
        primary, sizeof(primary), 1,
        &wire_status, &body, &body_length, &status);
    ok = rc == 0 && wire_status == kXR_ok && body_length == 1
        && body != NULL && body[0] == baseline[0];
    xrd_conform_result_set(execution, "RD-020",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "primary-pathid-returned-primary-bytes"
           : "primary-pathid-wrong-answer",
        "one byte on primary stream", ok ? NULL : status.msg);
    free(body);
    grade_refusal(execution, connection, "RD-021", file->fhandle, 0, 1,
        invalid, sizeof(invalid), kXR_ArgInvalid, "unbound-pathid-refused");
}

/* WHAT: Reads one byte at the maximum signed protocol offset.
 * WHY: offset+rlen overflow must never wrap around to accessible data.
 * HOW: Accept only an empty success or the specified argument error. */
static void
probe_max_offset(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file)
{
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    uint16_t wire_status = 0;
    brix_status status;
    int rc;
    int ok;

    rc = xrd_conform_root_raw_read(execution, connection, file->fhandle,
        INT64_MAX, 1,
        NULL, 0, 0, &wire_status, &body, &body_length, &status);
    ok = (rc == 0 && wire_status == kXR_ok && body_length == 0)
        || (rc != 0 && status.kxr == kXR_ArgInvalid);
    xrd_conform_result_set(execution, "RD-012",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "max-offset-bounded" : "max-offset-wrong-answer",
        "zero bytes or ArgInvalid", ok ? NULL : status.msg);
    free(body);
}

/* WHAT: Requests INT32_MAX bytes from a bounded object.
 * WHY: Signed-length widening must not provoke an allocation failure.
 * HOW: Reserve only the known object size and require exact remaining bytes. */
static void
probe_max_length(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size)
{
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    uint16_t wire_status = 0;
    brix_status status;
    int rc;
    int ok;

    if (size > UINT32_MAX) return;
    rc = xrd_conform_root_raw_read(execution, connection, file->fhandle, 0,
        INT32_MAX,
        NULL, 0, (size_t) size, &wire_status, &body, &body_length, &status);
    ok = rc == 0 && wire_status == kXR_ok && body_length == (uint32_t) size
        && (size == 0 || memcmp(body, baseline, (size_t) size) == 0);
    xrd_conform_result_set(execution, "RD-013",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "max-length-clamped-to-object" : "max-length-wrong-answer",
        "remaining object bytes", ok ? NULL : status.msg);
    free(body);
}

/* WHAT: Appends one valid readahead_list after read_args.
 * WHY: Optional readahead must not alter the primary read's bytes.
 * HOW: Pack through the shared codec and compare the one-byte response. */
static void
probe_readahead(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size)
{
    uint8_t args[BRIX_READ_ARGS_LEN + BRIX_READV_SEGSIZE] = { 0 };
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    uint16_t wire_status = 0;
    brix_status status;
    int rc;
    int ok;

    if (size == 0) return;
    brix_readv_seg_pack(args + BRIX_READ_ARGS_LEN, file->fhandle, 1, 0);
    rc = xrd_conform_root_raw_read(execution, connection, file->fhandle, 0, 1,
        args, sizeof(args), 1, &wire_status, &body, &body_length, &status);
    ok = rc == 0 && wire_status == kXR_ok && body_length == 1
        && body != NULL && body[0] == baseline[0];
    xrd_conform_result_set(execution, "RD-022",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "readahead-preserved-primary-read"
           : "readahead-changed-primary-read",
        "primary byte unchanged", ok ? NULL : status.msg);
    free(body);
}

/* WHAT: Dispatches the three independent large-value/read-args probes.
 * WHY: Keeping clause checks separate preserves the CCN ceiling.
 * HOW: Run each bounded helper once against the same open handle. */
static void
probe_boundaries(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size)
{
    probe_max_offset(execution, connection, file);
    probe_max_length(execution, connection, file, baseline, size);
    probe_readahead(execution, connection, file, baseline, size);
}

/* ---- Run malformed and authority-negative read probes ----
 *
 * WHAT: Exercises bad handles, malformed args and signed numeric boundaries.
 * WHY: These inputs must produce one deterministic client error, never data.
 * HOW: Use the raw request seam while keeping every payload fully framed.
 */
void
xrd_conform_probe_read_raw(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size)
{
    uint8_t unknown_handle[XRDC_FHANDLE_LEN];
    uint8_t malformed_args[3] = { 0, 0, 0 };

    memset(unknown_handle, 0xff, sizeof(unknown_handle));
    grade_refusal(execution, connection, "RD-019", unknown_handle, 0, 1,
        NULL, 0, kXR_FileNotOpen, "unknown-handle-refused");
    probe_path_ids(execution, connection, file, baseline, size);
    probe_boundaries(execution, connection, file, baseline, size);
    grade_refusal(execution, connection, "RD-023", file->fhandle, 0, 1,
        malformed_args, sizeof(malformed_args), kXR_ArgInvalid,
        "malformed-read-args-refused");
    grade_refusal(execution, connection, "RD-031", file->fhandle, 0, -1,
        NULL, 0, kXR_ArgInvalid, "negative-length-refused");
    grade_refusal(execution, connection, "RD-033", file->fhandle, -1, -1,
        NULL, 0, kXR_ArgInvalid, "negative-offset-and-length-refused-once");
}
