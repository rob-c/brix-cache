/* Phase-118 post-login ROOT request/response framing probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"
#include "protocols/root/protocol/frame_hdr.h"

typedef struct {
    uint16_t sid;
    uint16_t status;
    uint32_t length;
    uint8_t body[256];
} framing_reply;

int
xrd_conform_root_object_needed(xrd_conform_execution *execution)
{
    const char *const families[] = {
        "FRM", "OPN", "RD", "PGR", "PGW", "WRT", "WVC", "SYN",
        "TRN", "CKP", "STA", "DIR", "MKD", "MV", "RM", "CHM",
        "LOC", "FAT", "PRP", "QRY", "RDV",
        "CHU", "BND", "ENV", "ERR", "CMS", "CAC", "TPC", "XPR", "ADV",
        "CLM", "TLS", "DAV"
    };
    size_t index;

    for (index = 0; index < sizeof(families) / sizeof(families[0]); index++)
        if (xrd_conform_family_active(execution, families[index])) return 1;
    return 0;
}

static int
basic_family_active(xrd_conform_execution *execution)
{
    return xrd_conform_family_active(execution, "OPN")
        || xrd_conform_family_active(execution, "STA")
        || xrd_conform_family_active(execution, "DIR")
        || xrd_conform_family_active(execution, "LOC")
        || xrd_conform_family_active(execution, "QRY")
        || xrd_conform_family_active(execution, "ERR");
}

/* A rejected malformed pgread status frame leaves the transport deliberately
 * unusable.  Treat that as owned hostile evidence, not as a later close
 * failure of the otherwise successful conformance run. */
static int
pgread_structure_poisoned(xrd_conform_execution *execution)
{
    static const char *const ids[] = {
        "PGR-001", "PGR-002", "PGR-003", "PGR-004", "PGR-005",
        "PGR-006", "PGR-007", "PGR-031", "PGR-032"
    };
    size_t index;

    for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++) {
        const brix_conform_result *result =
            xrd_conform_result_find(execution, ids[index]);

        if (result != NULL
            && result->verdict == BRIX_CONFORM_VERDICT_DIVERGENT) return 1;
    }
    return 0;
}

int
xrd_conform_probe_selected_object(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path,
    const uint8_t *baseline, uint64_t size)
{
    brix_conform_result *pgr_result;

    if (xrd_conform_family_active(execution, "RD"))
        xrd_conform_run_rd(execution, connection, file, baseline, size);
    if (xrd_conform_family_active(execution, "PGR"))
        xrd_conform_run_pgr(execution, connection, file, baseline, size);
    pgr_result = xrd_conform_result_find(execution, "PGR-020");
    if (pgr_result != NULL
        && pgr_result->verdict == BRIX_CONFORM_VERDICT_DIVERGENT) return 1;
    if (pgread_structure_poisoned(execution)) return 1;
    if (xrd_conform_family_active(execution, "STA"))
        xrd_conform_probe_stat(execution, connection, file, path, size);
    if (xrd_conform_family_active(execution, "RDV"))
        xrd_conform_probe_readv(execution, connection, file, path, baseline,
            size);
    if (xrd_conform_family_active(execution, "RDV")
        && size == XRDC_CONFORM_CHUNKED_SIZE)
        xrd_conform_probe_readv_chunked(execution, connection, file, baseline,
            (size_t) size);
    {
        const brix_conform_result *rdv =
            xrd_conform_result_find(execution, "RDV-018");

        if (rdv != NULL
            && rdv->verdict == BRIX_CONFORM_VERDICT_DIVERGENT) return 1;
    }
    if (xrd_conform_family_active(execution, "BND"))
        xrd_conform_probe_bind(execution, connection, file, baseline, size);
    if (xrd_conform_family_active(execution, "ENV"))
        xrd_conform_probe_env_flow(execution, connection, file, baseline,
            size);
    if (xrd_conform_family_active(execution, "RD"))
        xrd_conform_probe_read_raw(execution, connection, file, baseline, size);
    execution->root_size = size;
    brix_s3_sha256_hex(baseline, (size_t) size, execution->root_digest);
    execution->have_root = 1;
    if (xrd_conform_family_active(execution, "XPR"))
        xrd_conform_probe_root_traversal(execution, connection, path);
    if (xrd_conform_family_active(execution, "XPR"))
        xrd_conform_probe_root_case(execution, connection, path);
    {
        const brix_conform_result *dav = xrd_conform_result_find(execution,
            "DAV-002");

        if (xrd_conform_family_active(execution, "XPR")
            || (dav != NULL
                && dav->verdict != BRIX_CONFORM_VERDICT_SKIPPED))
            xrd_conform_probe_root_namespace(execution, connection, path);
    }
    if (xrd_conform_family_active(execution, "XPR"))
        xrd_conform_probe_root_filenames(execution, connection, path);
    if (basic_family_active(execution))
        xrd_conform_probe_root_basic(execution, connection, file, path);
    if (xrd_conform_family_active(execution, "OPN"))
        xrd_conform_probe_root_open(execution, connection, file, path,
            baseline, size);
    if (xrd_conform_family_active(execution, "QRY")
        || xrd_conform_family_active(execution, "ENV")
        || xrd_conform_family_active(execution, "CLM"))
        xrd_conform_probe_root_control(execution, connection, file, path);
    if (xrd_conform_family_active(execution, "QRY")
        || xrd_conform_family_active(execution, "CLM"))
        xrd_conform_probe_query_claims(execution, connection, file, path,
            baseline, size);
    if (xrd_conform_family_active(execution, "FAT"))
        xrd_conform_probe_fattr_support(execution, connection, path);
    return 0;
}

static void
grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const char *failure)
{
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : failure, NULL, NULL);
}

static int
row_active(xrd_conform_execution *execution, const char *id)
{
    brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static void
make_protocol(ClientProtocolRequest *request, uint16_t sid, int padded)
{
    const uint8_t streamid[2] = {
        (uint8_t) (sid >> 8), (uint8_t) sid
    };

    xrd_pack_protocol_request(request, streamid, 0);
    if (padded) memset(((uint8_t *) request) + 10, 0xff, 10);
}

static int
read_reply(brix_conn *connection, framing_reply *reply, brix_status *status)
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

static int
send_protocol(xrd_conform_execution *execution, brix_conn *connection,
    uint16_t sid, int padded, framing_reply *reply, brix_status *status)
{
    ClientProtocolRequest request;
    char reason[64];

    if (!xrd_conform_reserve(execution, sizeof(request), reason,
            sizeof(reason))) return -1;
    make_protocol(&request, sid, padded);
    return brix_write_full(&connection->io, &request, sizeof(request), status)
            == 0
        && read_reply(connection, reply, status) == 0 ? 0 : -1;
}

static void
probe_sequential(xrd_conform_execution *execution, brix_conn *connection,
    brix_status *status)
{
    framing_reply first, second;
    int first_ok = send_protocol(execution, connection, 0, 0, &first,
        status) == 0;
    int second_ok = first_ok
        && send_protocol(execution, connection, 0, 0, &second, status) == 0;
    int body_ok = first_ok && first.status == kXR_ok
        && first.length >= sizeof(ServerProtocolBody);

    grade(execution, "FRM-001", body_ok, "zero-payload-request-accepted",
        "zero-payload-request-refused");
    grade(execution, "FRM-002", first_ok, "eight-byte-response-header-read",
        "response-header-not-eight-bytes");
    grade(execution, "FRM-003", first_ok && first.sid == 0,
        "streamid-echoed", "streamid-not-echoed");
    grade(execution, "FRM-005", first_ok && first.sid == 0,
        "zero-streamid-echoed", "zero-streamid-refused");
    grade(execution, "FRM-006", second_ok && second.sid == 0
        && second.status == kXR_ok, "completed-streamid-reused",
        "completed-streamid-reuse-refused");
}

static void
probe_pipeline(xrd_conform_execution *execution, brix_conn *connection,
    brix_status *status)
{
    ClientProtocolRequest requests[2];
    framing_reply first, second;
    int wrote;
    int read_ok;
    int identities;
    char reason[64];

    make_protocol(&requests[0], 0x1234, 0);
    make_protocol(&requests[1], 0x5678, 0);
    wrote = xrd_conform_reserve(execution, sizeof(requests[0]), reason,
            sizeof(reason))
        && xrd_conform_reserve(execution, sizeof(requests[1]), reason,
            sizeof(reason))
        && brix_write_full(&connection->io, requests, sizeof(requests), status)
            == 0;
    read_ok = wrote && read_reply(connection, &first, status) == 0
        && read_reply(connection, &second, status) == 0;
    identities = read_ok
        && ((first.sid == 0x1234 && second.sid == 0x5678)
            || (first.sid == 0x5678 && second.sid == 0x1234));
    grade(execution, "FRM-004", identities,
        "inflight-streamids-preserved", "inflight-streamids-confused");
    grade(execution, "FRM-022", read_ok,
        "pipelined-requests-served", "pipelined-request-lost");
    grade(execution, "FRM-023", read_ok,
        "same-connection-pipeline-served", "response-wait-required");
}

static void
probe_padding(xrd_conform_execution *execution, brix_conn *connection,
    brix_status *status)
{
    framing_reply plain, padded;
    int ok = send_protocol(execution, connection, 0x2200, 0, &plain,
            status) == 0
        && send_protocol(execution, connection, 0x2201, 1, &padded,
            status) == 0;

    ok = ok && plain.status == padded.status && plain.length == padded.length
        && memcmp(plain.body, padded.body, plain.length) == 0;
    grade(execution, "FRM-016", ok, "reserved-padding-ignored",
        "reserved-padding-changed-answer");
}

static void
probe_invalid_opcode(xrd_conform_execution *execution, brix_conn *connection,
    uint16_t opcode, const char *id)
{
    ClientRequestHdr request;
    uint16_t sid;
    uint16_t status = 0;
    uint8_t *body = NULL;
    uint32_t length = 0;
    brix_resp_out output = { &status, &body, &length };
    brix_status error;
    int refused;
    char reason[64];

    memset(&request, 0, sizeof(request));
    request.requestid = htons(opcode);
    brix_status_clear(&error);
    refused = xrd_conform_reserve(execution, sizeof(request), reason,
            sizeof(reason))
        && brix_send(connection, &request, NULL, &sid, &error) == 0
        && brix_recv(connection, sid, &output, &error) != 0
        && error.kxr == kXR_InvalidRequest;
    grade(execution, id, refused, "invalid-opcode-defined-error",
        "invalid-opcode-not-mapped");
    free(body);
}

void
xrd_conform_probe_framing(xrd_conform_execution *execution,
    const brix_url *url)
{
    brix_opts opts = execution->run->opts;
    brix_conn connection;
    brix_status status;

    if (!xrd_conform_family_active(execution, "FRM")) return;
    opts.capture = NULL;
    brix_status_clear(&status);
    if (brix_connect(&connection, url, &opts, &status) != 0) return;
    if (row_active(execution, "FRM-001")
        || row_active(execution, "FRM-002")
        || row_active(execution, "FRM-003")
        || row_active(execution, "FRM-005")
        || row_active(execution, "FRM-006"))
        probe_sequential(execution, &connection, &status);
    if (row_active(execution, "FRM-004")
        || row_active(execution, "FRM-022")
        || row_active(execution, "FRM-023"))
        probe_pipeline(execution, &connection, &status);
    if (row_active(execution, "FRM-016"))
        probe_padding(execution, &connection, &status);
    if (row_active(execution, "FRM-017"))
        probe_invalid_opcode(execution, &connection, kXR_REQFENCE, "FRM-017");
    if (row_active(execution, "FRM-018"))
        probe_invalid_opcode(execution, &connection, kXR_1stRequest - 1,
            "FRM-018");
    brix_close(&connection);
}
