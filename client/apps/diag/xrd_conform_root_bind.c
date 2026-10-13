/* Phase-118 ROOT bound-data-channel probes. */
#include "xrd_conform_internal.h"

#include <arpa/inet.h>

/* WHAT: Request a read on the primary and receive its body on a bound path.
 * WHY: Merely issuing requests directly on BriX extension streams does not
 * prove the protocol's pathid-directed response behavior.
 * HOW: Put the assigned pathid in read_args, send on primary, recv on bound. */
static int
bound_read(xrd_conform_execution *execution, brix_conn *primary,
    brix_conn *secondary, brix_file *file, size_t length,
    uint8_t **body, uint32_t *body_length, brix_status *status)
{
    ClientReadRequest request;
    xrdw_read_req_t fields = { .offset = 0, .rlen = (int32_t) length };
    uint8_t args[BRIX_READ_ARGS_LEN] = { 0 };
    brix_payload payload = { args, sizeof(args) };
    uint16_t wire_status = 0;
    uint16_t stream_id;
    brix_resp_out response = { &wire_status, body, body_length };
    char reason[64];

    if (!xrd_conform_reserve(execution, length, reason, sizeof(reason))) {
        brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
        return -1;
    }
    memcpy(fields.fhandle, file->fhandle, sizeof(fields.fhandle));
    args[0] = secondary->bound_pathid;
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_read);
    xrdw_read_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(status);
    if (brix_send(primary, &request, &payload, &stream_id, status) != 0)
        return -1;
    if (brix_recv(secondary, stream_id, &response, status) != 0) return -1;
    return wire_status == kXR_ok ? 0 : -1;
}

/* WHAT: Round-trip one primary-stream ping after a secondary closes.
 * WHY: The close and subsequent request arrive on different sockets; a ping
 * gives the owning event loop a bounded synchronization turn before BND-005.
 * HOW: Send the empty typed header and require an empty successful response. */
static int
primary_ping(xrd_conform_execution *execution, brix_conn *connection)
{
    ClientRequestHdr request;
    uint16_t wire_status = 0;
    uint16_t stream_id;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_resp_out response = { &wire_status, &body, &body_length };
    brix_status status;
    char reason[64];
    int rc;

    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return -1;
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_ping);
    xrdw_empty_req_pack(request.body);
    brix_status_clear(&status);
    rc = brix_send(connection, &request, NULL, &stream_id, &status);
    if (rc == 0) rc = brix_recv(connection, stream_id, &response, &status);
    free(body);
    return rc == 0 && wire_status == kXR_ok && body_length == 0 ? 0 : -1;
}

/* WHAT: Require a closed secondary's former pathid to fail on the primary.
 * WHY: Reusing stale routing authority could disclose bytes to another stream.
 * HOW: Synchronize closure, issue one pathid-tagged read, require ArgInvalid. */
static void
probe_closed_pathid(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, uint8_t pathid)
{
    ClientReadRequest request;
    xrdw_read_req_t fields = { .offset = 0, .rlen = 1 };
    uint8_t args[BRIX_READ_ARGS_LEN] = { 0 };
    brix_payload payload = { args, sizeof(args) };
    uint16_t wire_status = 0;
    uint16_t stream_id;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_resp_out response = { &wire_status, &body, &body_length };
    brix_status status;
    char reason[64];
    int rc = -1;

    if (primary_ping(execution, connection) != 0
        || primary_ping(execution, connection) != 0
        || !xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        xrd_conform_result_set(execution, "BND-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "close-synchronization-unavailable", NULL, NULL);
        return;
    }
    memcpy(fields.fhandle, file->fhandle, sizeof(fields.fhandle));
    args[0] = pathid;
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_read);
    xrdw_read_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(&status);
    if (brix_send(connection, &request, &payload, &stream_id, &status) == 0)
        rc = brix_recv(connection, stream_id, &response, &status);
    free(body);
    xrd_conform_result_set(execution, "BND-005",
        rc != 0 && status.kxr == kXR_ArgInvalid
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        rc != 0 && status.kxr == kXR_ArgInvalid
            ? "closed-pathid-refused" : "closed-pathid-remained-usable",
        "kXR_ArgInvalid", status.msg);
}

/* WHAT: Bind exactly the advertised number of secondary streams plus one.
 * WHY: BND-004 must observe the remote enforcement boundary; a config claim
 * alone cannot establish that excess substreams are refused.
 * HOW: Parse bind_max, keep every admitted stream live, and require the next
 * bind to return the server's defined count-limit error. */
static void
probe_bind_limit(xrd_conform_execution *execution, brix_conn *connection)
{
    brix_streamset streams;
    brix_conn overflow;
    brix_status status;
    char reply[64];
    char reason[64];
    char *end = NULL;
    unsigned long advertised;
    int all_bound = 1;
    int refused = 0;

    memset(&streams, 0, sizeof(streams));
    memset(&overflow, 0, sizeof(overflow));
    brix_status_clear(&status);
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))
        || brix_query(connection, kXR_Qconfig, "bind_max", reply,
            sizeof(reply), &status) != 0)
    {
        xrd_conform_result_set(execution, "BND-004",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "bind-limit-query-failed",
            "advertised live streams then kXR_ArgTooLong", status.msg);
        return;
    }
    errno = 0;
    advertised = strtoul(reply, &end, 10);
    if (errno != 0 || end == reply
        || (*end != '\0' && *end != '\n')
        || advertised == 0 || advertised > XRDC_MAX_STREAMS - 1)
    {
        xrd_conform_result_set(execution, "BND-004",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "bind-limit-not-probeable",
            "bind_max in range 1..15", reply);
        return;
    }
    while (streams.n < (int) advertised) {
        brix_status_clear(&status);
        if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))
            || brix_bind(&streams.sec[streams.n], connection, &status) != 0)
        {
            all_bound = 0;
            break;
        }
        streams.n++;
    }
    if (all_bound
        && xrd_conform_reserve(execution, 0, reason, sizeof(reason)))
    {
        brix_status_clear(&status);
        refused = brix_bind(&overflow, connection, &status) != 0
            && status.kxr == kXR_ArgTooLong;
    }
    brix_streams_close(&streams);
    xrd_conform_result_set(execution, "BND-004",
        all_bound && refused ? BRIX_CONFORM_VERDICT_CONFORMANT
                             : BRIX_CONFORM_VERDICT_DIVERGENT,
        all_bound && refused ? "advertised-bind-limit-enforced"
                             : "bind-limit-mismatch",
        "bind_max successes then kXR_ArgTooLong",
        all_bound && refused ? NULL : status.msg);
}

void
xrd_conform_probe_bind(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size)
{
    brix_streamset streams;
    brix_status status;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    char reason[64];
    size_t length = size < 4096 ? (size_t) size : 4096;
    uint8_t pathid = 0;
    int bound;
    int read_ok = 0;

    if (length == 0) {
        xrd_conform_result_set(execution, "BND-001",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "target-empty", NULL, NULL);
        return;
    }
    memset(&streams, 0, sizeof(streams));
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    brix_status_clear(&status);
    bound = brix_bind(&streams.sec[0], connection, &status) == 0;
    if (bound) {
        streams.n = 1;
        pathid = streams.sec[0].bound_pathid;
    }
    xrd_conform_result_set(execution, "BND-001",
        bound && streams.sec[0].bound_pathid != 0
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : status.kxr == kXR_Unsupported
                ? BRIX_CONFORM_VERDICT_SKIPPED
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        bound ? "bind-returned-usable-pathid"
              : status.kxr == kXR_Unsupported
                    ? "claim-absent:data-substreams"
                    : "bind-pathid-invalid",
        "one-byte pathid in range 1..253", status.msg);
    if (bound) read_ok = bound_read(execution, connection, &streams.sec[0],
        file, length, &body, &body_length, &status) == 0;
    xrd_conform_result_set(execution, "BND-002",
        read_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                : bound ? BRIX_CONFORM_VERDICT_DIVERGENT
                        : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        read_ok ? "pathid-read-arrived-on-bound-stream"
                : bound ? "pathid-read-did-not-arrive-on-bound-stream"
                        : "bind-unavailable",
        "response on bound connection", status.msg);
    xrd_conform_result_set(execution, "BND-003",
        read_ok && body_length == length
            && memcmp(body, baseline, length) == 0
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : read_ok ? BRIX_CONFORM_VERDICT_DIVERGENT
                          : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        read_ok && body_length == length
            && memcmp(body, baseline, length) == 0
                ? "bound-stream-bytes-match-primary"
                : read_ok ? "bound-stream-byte-mismatch"
                          : "bound-read-unavailable",
        "byte-identical response", status.msg);
    free(body);
    brix_streams_close(&streams);
    if (bound) probe_closed_pathid(execution, connection, file, pathid);
    probe_bind_limit(execution, connection);
}

/* WHAT: Ping the primary while a pathid-directed read is awaiting collection.
 * WHY: ENV-002 requires same-session control traffic not to corrupt another
 * stream's pending data response.
 * HOW: Bind, send read on primary, ping primary, then receive exact data on
 * the secondary. The request is bounded to the first 4096 adopted bytes. */
void
xrd_conform_probe_env_flow(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size)
{
    brix_streamset streams;
    ClientReadRequest request;
    xrdw_read_req_t fields;
    uint8_t args[BRIX_READ_ARGS_LEN] = { 0 };
    brix_payload payload = { args, sizeof(args) };
    uint16_t wire_status = 0;
    uint16_t stream_id;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_resp_out response = { &wire_status, &body, &body_length };
    brix_status status;
    char reason[64];
    size_t length = size < 4096 ? (size_t) size : 4096;
    int rc = -1;

    if (length == 0) {
        xrd_conform_result_set(execution, "ENV-002",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "target-empty", NULL, NULL);
        return;
    }
    memset(&streams, 0, sizeof(streams));
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    brix_status_clear(&status);
    if (brix_bind(&streams.sec[0], connection, &status) != 0) {
        xrd_conform_result_set(execution, "ENV-002",
            status.kxr == kXR_Unsupported ? BRIX_CONFORM_VERDICT_SKIPPED
                                          : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            status.kxr == kXR_Unsupported
                ? "claim-absent:data-substreams" : "bind-unavailable",
            NULL, status.msg);
        return;
    }
    streams.n = 1;
    memset(&fields, 0, sizeof(fields));
    fields.rlen = (int32_t) length;
    memcpy(fields.fhandle, file->fhandle, sizeof(fields.fhandle));
    args[0] = streams.sec[0].bound_pathid;
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_read);
    xrdw_read_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    if (xrd_conform_reserve(execution, length, reason, sizeof(reason))) {
        brix_status_clear(&status);
        rc = brix_send(connection, &request, &payload, &stream_id, &status);
        if (rc == 0) rc = primary_ping(execution, connection);
        if (rc == 0) rc = brix_recv(&streams.sec[0], stream_id, &response,
            &status);
    }
    xrd_conform_result_set(execution, "ENV-002",
        rc == 0 && wire_status == kXR_ok && body_length == length
            && memcmp(body, baseline, length) == 0
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        rc == 0 && wire_status == kXR_ok && body_length == length
            && memcmp(body, baseline, length) == 0
                ? "ping-preserved-inflight-bound-read"
                : "ping-disturbed-inflight-bound-read",
        "byte-identical bound read after primary ping", status.msg);
    free(body);
    brix_streams_close(&streams);
}
