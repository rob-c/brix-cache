/* Phase-118 isolated hostile ROOT framing and length probes. */
#include "xrd_conform_probe_helpers.h"
#include "protocols/root/protocol/bootstrap_pack.h"
#include "protocols/root/protocol/codec/wire_codec.h"
#include "protocols/root/protocol/frame_hdr.h"

#include <unistd.h>

typedef struct {
    uint16_t sid;
    uint16_t status;
    uint32_t length;
    uint8_t body[512];
} hostile_reply;


static int
aux_connect(xrd_conform_execution *execution, const brix_url *url,
    brix_conn *connection, brix_status *status)
{
    brix_opts opts = execution->run->opts;

    opts.capture = NULL;
    brix_status_clear(status);
    return brix_connect(connection, url, &opts, status);
}

static int
read_reply(brix_conn *connection, hostile_reply *reply, brix_status *status)
{
    uint8_t header[XRD_RESPONSE_HDR_LEN];

    memset(reply, 0, sizeof(*reply));
    if (brix_read_full(&connection->io, header, sizeof(header), status) != 0)
        return -1;
    xrd_resp_hdr_unpack(header, &reply->sid, &reply->status, &reply->length);
    if (reply->length > sizeof(reply->body)) return -1;
    if (reply->length > 0 && brix_read_full(&connection->io, reply->body,
            reply->length, status) != 0) return -1;
    return 0;
}


static void
make_request(ClientRequestHdr *request, uint16_t sid, uint16_t opcode,
    uint32_t declared_length)
{
    memset(request, 0, sizeof(*request));
    xrd_put_u16_be(request->streamid, sid);
    request->requestid = htons(opcode);
    xrd_put_u32_be(((uint8_t *) request) + 20, declared_length);
}

static int
exchange(brix_conn *connection, const ClientRequestHdr *request,
    const void *payload, size_t sent_length, hostile_reply *reply,
    brix_status *status)
{
    return brix_write_full(&connection->io, request, sizeof(*request), status)
            == 0
        && (sent_length == 0 || brix_write_full(&connection->io, payload,
            sent_length, status) == 0)
        && read_reply(connection, reply, status) == 0 ? 0 : -1;
}

static int
reply_error(const hostile_reply *reply, int error)
{
    return reply->status == kXR_error && reply->length >= 4
        && (int) xrd_get_u32_be(reply->body) == error;
}

static void
probe_path_shape(xrd_conform_execution *execution, const brix_url *url,
    const char *id, uint16_t opcode, const uint8_t *payload, size_t length,
    int expected_error)
{
    brix_conn connection;
    brix_status status;
    ClientRequestHdr request;
    hostile_reply reply;
    int exchanged;
    int pass;

    if (!xrd_conform_reserve_probe(execution, sizeof(request) + length)
        || aux_connect(execution, url, &connection, &status) != 0) return;
    make_request(&request, 0x3100, opcode, (uint32_t) length);
    exchanged = exchange(&connection, &request, payload, length, &reply,
        &status) == 0;
    pass = expected_error == 0 ? exchanged && reply.status == kXR_ok
        : expected_error == -2 ? exchanged
            && (reply.status != kXR_error || reply.length < 4
                || (xrd_get_u32_be(reply.body) != kXR_ArgInvalid
                    && xrd_get_u32_be(reply.body) != kXR_ArgMissing))
        : exchanged && (expected_error < 0 ? reply.status == kXR_error
                                           : reply_error(&reply, expected_error));
    xrd_conform_grade(execution, id, pass, "path-frame-shape-enforced",
        "path-frame-shape-misparsed");
    brix_close(&connection);
}

static void
probe_path_nuls(xrd_conform_execution *execution, const brix_url *url)
{
    uint8_t payload[XRDC_PATH_MAX + 8];
    size_t length = strlen(url->path);

    if (length + 6 >= sizeof(payload)) return;
    memcpy(payload, url->path, length);
    payload[length] = '\0';
    if (xrd_conform_row_active(execution, "FRM-008"))
        probe_path_shape(execution, url, "FRM-008", kXR_stat, payload,
            length + 1, -2);
    memcpy(payload + length + 1, "evil", 4);
    if (xrd_conform_row_active(execution, "FRM-009"))
        probe_path_shape(execution, url, "FRM-009", kXR_stat, payload,
            length + 5, -1);
    payload[length + 1] = '\0';
    if (xrd_conform_row_active(execution, "FRM-010"))
        probe_path_shape(execution, url, "FRM-010", kXR_stat, payload,
            length + 2, -1);
    if (xrd_conform_row_active(execution, "FRM-011"))
        probe_path_shape(execution, url, "FRM-011", kXR_dirlist, payload, 0,
            kXR_ArgMissing);
}

static int
fresh_connection_works(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn check;
    brix_status status;

    if (aux_connect(execution, url, &check, &status) != 0) return 0;
    brix_close(&check);
    return 1;
}

static void
probe_short_payload(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn connection;
    brix_status status;
    ClientRequestHdr request;
    const uint8_t partial[] = { '/', 'x' };
    int sent = 0;

    if (xrd_conform_reserve_probe(execution, sizeof(request) + sizeof(partial))
        && aux_connect(execution, url, &connection, &status) == 0) {
        make_request(&request, 0x3200, kXR_stat, 8);
        sent = brix_write_full(&connection.io, &request, sizeof(request),
                &status) == 0
            && brix_write_full(&connection.io, partial, sizeof(partial),
                &status) == 0;
        brix_close(&connection);
    }
    xrd_conform_grade(execution, "FRM-012", sent
        && fresh_connection_works(execution, url),
        "truncated-payload-left-no-state", "truncated-payload-wedged-server");
}

static void
probe_surplus_as_next_request(xrd_conform_execution *execution,
    const brix_url *url)
{
    brix_conn connection;
    brix_status status;
    ClientRequestHdr stat_request, ping_request;
    hostile_reply first, second;
    uint8_t wire[XRD_REQUEST_HDR_LEN * 2 + XRDC_PATH_MAX];
    size_t path_length = strlen(url->path);
    size_t total;
    int pass = 0;

    if (path_length >= XRDC_PATH_MAX
        || !xrd_conform_reserve_probe(execution, sizeof(stat_request) + sizeof(ping_request)
            + path_length)
        || aux_connect(execution, url, &connection, &status) != 0) return;
    make_request(&stat_request, 0x3300, kXR_stat, (uint32_t) path_length);
    make_request(&ping_request, 0x3301, kXR_ping, 0);
    memcpy(wire, &stat_request, sizeof(stat_request));
    memcpy(wire + sizeof(stat_request), url->path, path_length);
    memcpy(wire + sizeof(stat_request) + path_length, &ping_request,
        sizeof(ping_request));
    total = sizeof(stat_request) + path_length + sizeof(ping_request);
    if (brix_write_full(&connection.io, wire, total, &status) == 0
        && read_reply(&connection, &first, &status) == 0
        && read_reply(&connection, &second, &status) == 0)
        pass = first.sid == 0x3300 && second.sid == 0x3301;
    xrd_conform_grade(execution, "FRM-013", pass, "surplus-parsed-as-next-frame",
        "surplus-silently-consumed");
    brix_close(&connection);
}

static void
probe_extreme_length(xrd_conform_execution *execution, const brix_url *url,
    const char *id, uint32_t declared)
{
    brix_conn connection;
    brix_status status;
    ClientRequestHdr request;
    hostile_reply reply;
    int pass = 0;

    if (!xrd_conform_reserve_probe(execution, sizeof(request))
        || aux_connect(execution, url, &connection, &status) != 0) return;
    make_request(&request, 0x3400, kXR_stat, declared);
    if (brix_write_full(&connection.io, &request, sizeof(request), &status) == 0)
        pass = read_reply(&connection, &reply, &status) != 0
            || reply.status == kXR_error;
    xrd_conform_grade(execution, id, pass, "extreme-length-refused",
        "extreme-length-not-refused");
    brix_close(&connection);
}

static void
probe_duplicate_outstanding(xrd_conform_execution *execution,
    const brix_url *url)
{
    brix_conn connection;
    brix_status status;
    ClientProtocolRequest requests[2];
    const uint8_t sid[2] = { 0x35, 0x00 };
    hostile_reply first, second;
    int pass = 0;

    if (!xrd_conform_reserve_probe(execution, sizeof(requests))
        || aux_connect(execution, url, &connection, &status) != 0) return;
    xrd_pack_protocol_request(&requests[0], sid, 0);
    requests[1] = requests[0];
    if (brix_write_full(&connection.io, requests, sizeof(requests), &status) == 0
        && read_reply(&connection, &first, &status) == 0
        && read_reply(&connection, &second, &status) == 0)
        pass = first.sid == 0x3500 && second.sid == 0x3500;
    xrd_conform_grade(execution, "FRM-007", pass, "streamid-reuse-produced-two-replies",
        "streamid-reuse-silently-dropped-reply");
    brix_close(&connection);
}

static void
probe_bytewise(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn connection;
    brix_status status;
    ClientProtocolRequest request;
    const uint8_t sid[2] = { 0x36, 0x00 };
    hostile_reply reply;
    size_t index;
    int pass = 0;

    if (!xrd_conform_reserve_probe(execution, sizeof(request))
        || aux_connect(execution, url, &connection, &status) != 0) return;
    xrd_pack_protocol_request(&request, sid, 0);
    for (index = 0; index < sizeof(request); index++)
        if (brix_write_full(&connection.io, ((uint8_t *) &request) + index, 1,
                &status) != 0) break;
    if (index == sizeof(request) && read_reply(&connection, &reply, &status) == 0)
        pass = reply.sid == 0x3600 && reply.status == kXR_ok;
    xrd_conform_grade(execution, "FRM-020", pass, "all-header-splits-reassembled",
        "bytewise-header-not-reassembled");
    brix_close(&connection);
}

static void
probe_slow_payload(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn connection;
    brix_status status;
    ClientRequestHdr request;
    hostile_reply reply;
    const uint8_t payload = '/';
    int pass = 0;

    if (!xrd_conform_reserve_probe(execution, sizeof(request) + 1)
        || aux_connect(execution, url, &connection, &status) != 0) return;
    make_request(&request, 0x3700, kXR_stat, 1);
    if (brix_write_full(&connection.io, &request, sizeof(request), &status) == 0) {
        sleep(1);
        if (brix_write_full(&connection.io, &payload, 1, &status) == 0
            && read_reply(&connection, &reply, &status) == 0)
            pass = reply.status == kXR_ok || reply.status == kXR_error;
    }
    xrd_conform_grade(execution, "FRM-021", pass, "slow-payload-terminated",
        "slow-payload-left-slot-unresolved");
    brix_close(&connection);
}

static int
sigver_answer_defined(xrd_conform_execution *execution, const brix_url *url,
    char *received, size_t received_size)
{
    brix_conn connection;
    brix_status status;
    ClientRequestHdr requests[2];
    hostile_reply reply;
    xrdw_sigver_req_t sigver = { .expectrid = kXR_ping, .seqno = 1,
        .crypto = kXR_rsaKey_sig };
    int defined = 0;

    if (!xrd_conform_reserve_probe(execution, sizeof(requests))
        || aux_connect(execution, url, &connection, &status) != 0) {
        snprintf(received, received_size,
            "opcode=%u connect-or-budget-failed", (unsigned) kXR_sigver);
        return 0;
    }
    make_request(&requests[0], 0x4bd5, kXR_sigver, 0);
    xrdw_sigver_req_pack(&sigver, requests[0].body);
    make_request(&requests[1], 0x4bd5, kXR_ping, 0);
    if (brix_write_full(&connection.io, requests, sizeof(requests), &status) == 0
        && read_reply(&connection, &reply, &status) == 0) {
        defined = reply.sid == 0x4bd5 && reply.status == kXR_ok;
        if (!defined)
            snprintf(received, received_size, "opcode=%u status=%u sid=%u",
                (unsigned) kXR_sigver, (unsigned) reply.status,
                (unsigned) reply.sid);
    } else {
        snprintf(received, received_size, "opcode=%u disconnected",
            (unsigned) kXR_sigver);
    }
    brix_close(&connection);
    return defined;
}

static int
opcode_answer_defined(xrd_conform_execution *execution, const brix_url *url,
    uint16_t opcode, char *received, size_t received_size)
{
    brix_conn connection;
    brix_status status;
    ClientRequestHdr request;
    hostile_reply reply;
    int defined = 0;

    if (opcode == kXR_sigver)
        return sigver_answer_defined(execution, url, received, received_size);
    if (!xrd_conform_reserve_probe(execution, sizeof(request))
        || aux_connect(execution, url, &connection, &status) != 0) {
        snprintf(received, received_size, "opcode=%u connect-or-budget-failed",
            (unsigned) opcode);
        return 0;
    }
    make_request(&request, (uint16_t) (0x4000 + opcode - kXR_1stRequest),
        opcode, 0);
    if (exchange(&connection, &request, NULL, 0, &reply, &status) == 0) {
        defined = reply.status != kXR_error
            || (reply.length >= 4
                && xrd_get_u32_be(reply.body) != kXR_ServerError
                && xrd_get_u32_be(reply.body) != kXR_FSError);
        if (!defined)
            snprintf(received, received_size, "opcode=%u status=%u error=%u",
                (unsigned) opcode, (unsigned) reply.status,
                (unsigned) xrd_get_u32_be(reply.body));
    } else {
        snprintf(received, received_size, "opcode=%u disconnected",
            (unsigned) opcode);
    }
    brix_close(&connection);
    return defined;
}

static void
probe_opcode_range(xrd_conform_execution *execution, const brix_url *url)
{
    uint16_t opcode;
    char received[96] = "";
    int pass = 1;

    for (opcode = kXR_1stRequest; pass && opcode < kXR_REQFENCE; opcode++)
        pass = opcode_answer_defined(execution, url, opcode, received,
            sizeof(received));
    xrd_conform_result_set(execution, "FRM-019",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "all-valid-opcodes-defined"
             : "valid-opcode-server-error-or-disconnect",
        NULL, pass ? NULL : received);
}

void
xrd_conform_probe_framing_hostile(xrd_conform_execution *execution,
    const brix_url *url)
{
    if (xrd_conform_row_active(execution, "FRM-007"))
        probe_duplicate_outstanding(execution, url);
    if (xrd_conform_row_active(execution, "FRM-008")
        || xrd_conform_row_active(execution, "FRM-009")
        || xrd_conform_row_active(execution, "FRM-010")
        || xrd_conform_row_active(execution, "FRM-011"))
        probe_path_nuls(execution, url);
    if (xrd_conform_row_active(execution, "FRM-012"))
        probe_short_payload(execution, url);
    if (xrd_conform_row_active(execution, "FRM-013"))
        probe_surplus_as_next_request(execution, url);
    if (xrd_conform_row_active(execution, "FRM-014"))
        probe_extreme_length(execution, url, "FRM-014", UINT32_MAX);
    if (xrd_conform_row_active(execution, "FRM-015"))
        probe_extreme_length(execution, url, "FRM-015", INT32_MAX);
    if (xrd_conform_row_active(execution, "FRM-019"))
        probe_opcode_range(execution, url);
    if (xrd_conform_row_active(execution, "FRM-020"))
        probe_bytewise(execution, url);
    if (xrd_conform_row_active(execution, "FRM-021"))
        probe_slow_payload(execution, url);
}
