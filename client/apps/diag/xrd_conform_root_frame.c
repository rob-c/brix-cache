/* Phase-118 isolated ROOT handshake-negative probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"
#include "protocols/root/protocol/frame_hdr.h"

#include <unistd.h>

#define XRDC_CONFORM_RAW_TIMEOUT_MS 3000

static int
handshake_family_active(xrd_conform_execution *execution)
{
    brix_conform_result *row = xrd_conform_result_find(execution, "HSK-004");

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static int
raw_open(const brix_url *url, brix_io *io, brix_status *status)
{
    memset(io, 0, sizeof(*io));
    io->fd = -1;
    io->timeout_ms = XRDC_CONFORM_RAW_TIMEOUT_MS;
    io->stall_deadline_ms = XRDC_CONFORM_RAW_TIMEOUT_MS;
    io->fd = brix_tcp_connect(url->host, url->port, io->timeout_ms, status);
    return io->fd < 0 ? -1 : 0;
}

static void
raw_close(brix_io *io)
{
    if (io->fd >= 0) close(io->fd);
    io->fd = -1;
}

static int
raw_reply_status(brix_io *io, uint16_t *wire_status, brix_status *status)
{
    uint8_t header[XRD_RESPONSE_HDR_LEN];
    uint16_t streamid;
    uint32_t length;

    if (brix_read_full(io, header, sizeof(header), status) != 0) return -1;
    xrd_resp_hdr_unpack(header, &streamid, wire_status, &length);
    return 0;
}

static void
grade_rejected(xrd_conform_execution *execution, const char *id,
    int accepted, const brix_status *status)
{
    xrd_conform_result_set(execution, id,
        accepted ? BRIX_CONFORM_VERDICT_DIVERGENT
                 : BRIX_CONFORM_VERDICT_CONFORMANT,
        accepted ? "malformed-bootstrap-served" : "malformed-bootstrap-refused",
        "error-or-disconnect", status == NULL ? NULL : status->msg);
}

static void
probe_short_handshake(xrd_conform_execution *execution, const brix_url *url)
{
    ClientInitHandShake hello;
    brix_io io;
    brix_conn check;
    brix_status status;
    char reason[64];
    int recovered = 0;
    brix_opts opts = execution->run->opts;

    brix_status_clear(&status);
    opts.capture = NULL;
    xrd_pack_handshake(&hello);
    if (xrd_conform_reserve(execution, 19, reason, sizeof(reason))
        && raw_open(url, &io, &status) == 0) {
        (void) brix_write_full(&io, &hello, 19, &status);
        raw_close(&io);
        brix_status_clear(&status);
        if (brix_connect(&check, url, &opts, &status) == 0) {
            recovered = 1;
            brix_close(&check);
        }
    }
    xrd_conform_result_set(execution, "HSK-004",
        recovered ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
        recovered ? "short-handshake-left-no-state"
                  : "short-handshake-poisoned-endpoint",
        "subsequent-full-connection-succeeds", status.msg);
}

static void
probe_altered_handshake(xrd_conform_execution *execution, const brix_url *url)
{
    ClientInitHandShake hello;
    ClientProtocolRequest protocol;
    uint8_t segment[XRD_HANDSHAKE_LEN + XRD_REQUEST_HDR_LEN];
    const uint8_t streamid[2] = { 0, 1 };
    brix_io io;
    brix_status status;
    uint16_t wire_status = kXR_ok;
    char reason[64];
    int accepted = 0;

    brix_status_clear(&status);
    xrd_pack_handshake(&hello);
    hello.fourth = htonl(5);
    xrd_pack_protocol_request(&protocol, streamid, kXR_secreqs);
    memcpy(segment, &hello, sizeof(hello));
    memcpy(segment + sizeof(hello), &protocol, sizeof(protocol));
    if (xrd_conform_reserve(execution, sizeof(segment), reason, sizeof(reason))
        && raw_open(url, &io, &status) == 0) {
        accepted = brix_write_full(&io, segment, sizeof(segment), &status) == 0
            && raw_reply_status(&io, &wire_status, &status) == 0
            && wire_status == kXR_ok;
        raw_close(&io);
    }
    grade_rejected(execution, "HSK-005", accepted, &status);
}

static void
probe_second_handshake(xrd_conform_execution *execution, const brix_url *url)
{
    ClientInitHandShake hello;
    uint8_t segment[XRD_REQUEST_HDR_LEN];
    brix_conn connection;
    brix_status status;
    uint16_t wire_status = kXR_ok;
    char reason[64];
    int accepted = 0;
    brix_opts opts = execution->run->opts;

    brix_status_clear(&status);
    opts.capture = NULL;
    xrd_pack_handshake(&hello);
    memset(segment, 0, sizeof(segment));
    memcpy(segment, &hello, sizeof(hello));
    if (xrd_conform_reserve(execution, sizeof(segment), reason, sizeof(reason))
        && brix_connect(&connection, url, &opts, &status) == 0) {
        accepted = brix_write_full(&connection.io, segment, sizeof(segment),
                &status) == 0
            && raw_reply_status(&connection.io, &wire_status, &status) == 0
            && wire_status == kXR_ok;
        brix_close(&connection);
    }
    grade_rejected(execution, "HSK-006", accepted, &status);
}

static void
probe_request_before_handshake(xrd_conform_execution *execution,
    const brix_url *url)
{
    ClientRequestHdr request;
    uint8_t segment[XRD_REQUEST_HDR_LEN + XRD_HANDSHAKE_LEN];
    brix_io io;
    brix_status status;
    uint16_t wire_status = kXR_ok;
    char reason[64];
    int accepted = 0;

    brix_status_clear(&status);
    memset(&request, 0, sizeof(request));
    request.streamid[0] = 0x12;
    request.streamid[1] = 0x34;
    request.requestid = htons(kXR_ping);
    memset(segment, 0, sizeof(segment));
    memcpy(segment, &request, sizeof(request));
    if (xrd_conform_reserve(execution, sizeof(segment), reason, sizeof(reason))
        && raw_open(url, &io, &status) == 0) {
        accepted = brix_write_full(&io, segment, sizeof(segment), &status) == 0
            && raw_reply_status(&io, &wire_status, &status) == 0
            && wire_status == kXR_ok;
        raw_close(&io);
    }
    grade_rejected(execution, "HSK-007", accepted, &status);
}

void
xrd_conform_probe_handshake_negatives(xrd_conform_execution *execution,
    const brix_url *url)
{
    if (!handshake_family_active(execution)) return;
    probe_short_handshake(execution, url);
    probe_altered_handshake(execution, url);
    probe_second_handshake(execution, url);
    probe_request_before_handshake(execution, url);
}
