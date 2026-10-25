/* Phase-118 read-only ROOT open, directory and locate probes. */
#include "xrd_conform_internal.h"
#include "posix/posix_map.h"
#include "protocols/root/protocol/bootstrap_pack.h"
#include "protocols/root/protocol/frame_hdr.h"

#include <arpa/inet.h>
#include <unistd.h>

#define grade xrd_conform_basic_grade
#define reserve_request xrd_conform_basic_reserve

static void probe_bootstrap_shape(xrd_conform_execution *execution,
    brix_conn *connection);
static void probe_protocol_repeats(xrd_conform_execution *execution,
    brix_conn *connection);
static void probe_protocol_expectations(xrd_conform_execution *execution,
    brix_conn *connection);
static void probe_protocol_bootstrap(xrd_conform_execution *execution,
    const brix_url *url);

typedef struct {
    int handshake_answered;
    int handshake_v5;
    int handshake_version_ok;
    int protocol_answered;
    int protocol_body_long_enough;
} bootstrap_observation;

static void
grade_clause(xrd_conform_execution *execution, const char *id, int pass,
    const char *pass_reason, const char *fail_reason, const char *received)
{
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? pass_reason : fail_reason, NULL, received);
}

int
reserve_request(xrd_conform_execution *execution, char reason[64])
{
    return xrd_conform_reserve(execution, 0, reason, 64);
}

void
xrd_conform_probe_protocol_claims(xrd_conform_execution *execution,
    const brix_url *url, brix_conn *connection)
{
    uint32_t flags = connection->server_flags;
    unsigned roles = flags & (kXR_isServer | kXR_isManager);
    unsigned tls_without_capability = flags
        & (kXR_gotoTLS | kXR_tlsAny | kXR_tlsGPFA);

    xrd_conform_result_set(execution, "PROT-003",
        roles == kXR_isServer || roles == kXR_isManager
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        roles == kXR_isServer || roles == kXR_isManager
            ? "exactly-one-server-role-bit"
            : "invalid-server-role-bit-combination",
        "exactly one of kXR_isServer/kXR_isManager", NULL);
    if ((flags & kXR_haveTLS) == 0)
        xrd_conform_result_set(execution, "PROT-014",
            tls_without_capability == 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                                        : BRIX_CONFORM_VERDICT_DIVERGENT,
            tls_without_capability == 0
                ? "tls-dependent-bits-clear-without-haveTLS"
                : "tls-dependent-bit-set-without-haveTLS",
            "no TLS-dependent bits when kXR_haveTLS is clear", NULL);
    probe_bootstrap_shape(execution, connection);
    probe_protocol_repeats(execution, connection);
    probe_protocol_expectations(execution, connection);
    probe_protocol_bootstrap(execution, url);
}

/* WHAT: Observe the pre-login protocol response on an isolated connection.
 * WHY: A malformed first response prevents brix_connect from returning a
 *      connection, so the ordinary post-connect shape audit cannot retain the
 *      owning PROT-001/002 evidence.
 * HOW: Exchange only the canonical handshake and protocol request, bound every
 *      read, and keep the malformed fixture out of the primary session. */
static void
read_bootstrap_observation(const brix_url *url, brix_io *io,
    brix_status *status, bootstrap_observation *observed)
{
    ClientInitHandShake handshake;
    ClientProtocolRequest protocol;
    const uint8_t streamid[2] = { 0, 1 };
    uint8_t handshake_header[XRD_RESPONSE_HDR_LEN];
    uint8_t handshake_body[sizeof(ServerProtocolBody)];
    uint8_t response_header[XRD_RESPONSE_HDR_LEN];
    uint16_t response_sid = 0, response_status = 0;
    uint32_t response_length = 0;
    uint16_t handshake_sid = 0, handshake_status = 0;
    uint32_t handshake_length = 0;
    memset(observed, 0, sizeof(*observed));
    xrd_pack_handshake(&handshake);
    xrd_pack_protocol_request(&protocol, streamid, kXR_secreqs);
    io->fd = brix_tcp_connect(url->host, url->port, io->timeout_ms, status);
    if (io->fd >= 0
        && brix_write_full(io, &handshake, sizeof(handshake), status) == 0
        && brix_read_full(io, handshake_header, sizeof(handshake_header),
            status) == 0) {
        xrd_resp_hdr_unpack(handshake_header, &handshake_sid,
            &handshake_status, &handshake_length);
        observed->handshake_answered = 1;
        observed->handshake_v5 = handshake_sid == 0 && handshake_status == 0
            && handshake_length == sizeof(handshake_body)
            && brix_read_full(io, handshake_body, sizeof(handshake_body),
                status) == 0;
        observed->handshake_version_ok = observed->handshake_v5
            && xrd_get_u32_be(handshake_body) >= 0x300
            && xrd_get_u32_be(handshake_body) <= kXR_PROTOCOLVERSION;
        if (observed->handshake_v5
            && brix_write_full(io, &protocol, sizeof(protocol), status) == 0
            && brix_read_full(io, response_header, sizeof(response_header),
                status) == 0) {
            xrd_resp_hdr_unpack(response_header, &response_sid,
                &response_status, &response_length);
            observed->protocol_answered = response_sid == 1
                && response_status == kXR_ok;
            observed->protocol_body_long_enough = observed->protocol_answered
                && response_length >= sizeof(ServerProtocolBody);
        }
    }
}

static void
grade_bootstrap_observation(xrd_conform_execution *execution,
    const bootstrap_observation *observed, const brix_status *status)
{
    if (xrd_conform_family_active(execution, "HSK")) {
        grade_clause(execution, "HSK-001", observed->handshake_answered,
            "canonical-handshake-answered", "handshake-reply-missing",
            status->msg);
        grade_clause(execution, "HSK-002", observed->handshake_v5,
            "v5-eight-byte-handshake-body", "non-v5-handshake-body",
            status->msg);
        grade_clause(execution, "HSK-003", observed->handshake_version_ok,
            "protocol-version-in-supported-range",
            "protocol-version-out-of-range", status->msg);
    }
    if (xrd_conform_family_active(execution, "PROT")) {
        grade_clause(execution, "PROT-001", observed->protocol_answered,
            "pre-login-protocol-answered", "pre-login-protocol-missing",
            status->msg);
        grade_clause(execution, "PROT-002",
            observed->protocol_body_long_enough,
            "short-protocol-body-present", "protocol-body-too-short",
            status->msg);
    }
}

static void
probe_protocol_bootstrap(xrd_conform_execution *execution,
    const brix_url *url)
{
    bootstrap_observation observed;
    brix_io io;
    brix_status status;
    char reason[64];

    if ((!xrd_conform_family_active(execution, "PROT")
            && !xrd_conform_family_active(execution, "HSK"))
        || url->scheme != XRDC_SCHEME_ROOT
        || !xrd_conform_reserve(execution,
            sizeof(ClientInitHandShake) + sizeof(ClientProtocolRequest),
            reason, sizeof(reason))) return;
    memset(&io, 0, sizeof(io));
    io.fd = -1;
    io.timeout_ms = 3000;
    io.stall_deadline_ms = 3000;
    brix_status_clear(&status);
    read_bootstrap_observation(url, &io, &status, &observed);
    if (io.fd >= 0) close(io.fd);
    grade_bootstrap_observation(execution, &observed, &status);
}

static void
probe_bootstrap_shape(xrd_conform_execution *execution, brix_conn *connection)
{
    const uint8_t *body = connection->protocol_body;
    uint32_t length = connection->protocol_body_len;
    int have_sec = length >= 14 && body[8] == 'S';
    int sec_level_ok = have_sec ? body[12] <= 4 : 0;
    int sec_size_ok = have_sec
        ? length == 14U + (uint32_t) body[13] * 2U : 0;
    size_t index;
    int secvec_ok = sec_size_ok;

    for (index = 0; secvec_ok && index < body[13]; index++)
        if (body[15 + index * 2] > 2) secvec_ok = 0;
    grade_clause(execution, "HSK-001", connection->handshake_body_len > 0,
        "canonical-handshake-answered", "handshake-reply-missing", NULL);
    grade_clause(execution, "HSK-002", connection->handshake_body_len == 8,
        "v5-eight-byte-handshake-body", "non-v5-handshake-body", NULL);
    grade_clause(execution, "HSK-003",
        connection->server_protocol >= 0x300
            && connection->server_protocol <= kXR_PROTOCOLVERSION,
        "protocol-version-in-supported-range", "protocol-version-out-of-range",
        NULL);
    grade_clause(execution, "PROT-001",
        length >= sizeof(ServerProtocolBody), "pre-login-protocol-answered",
        "pre-login-protocol-missing", NULL);
    grade_clause(execution, "PROT-002",
        length >= sizeof(ServerProtocolBody), "short-protocol-body-present",
        "protocol-body-too-short", NULL);
    grade_clause(execution, "PROT-004", have_sec,
        "secreqs-returned-S-trailer", "secreqs-trailer-missing", NULL);
    grade_clause(execution, "PROT-006", sec_level_ok,
        "security-level-in-domain", "security-level-out-of-domain", NULL);
    grade_clause(execution, "PROT-007", secvec_ok,
        "security-vector-requirements-in-domain",
        "security-vector-requirement-invalid", NULL);
    grade_clause(execution, "PROT-008", sec_size_ok,
        "security-vector-size-matches-body", "security-vector-size-mismatch",
        NULL);
}

static int
protocol_exchange(xrd_conform_execution *execution, brix_conn *connection,
    int32_t version, uint8_t flags, uint8_t expect, uint8_t **body,
    uint32_t *body_length, brix_status *status)
{
    ClientProtocolRequest request;
    xrdw_protocol_req_t fields = {
        .clientpv = version, .flags = flags, .expect = expect
    };
    uint16_t sid, wire_status = 0;
    brix_resp_out response = { &wire_status, body, body_length };
    char reason[64];

    if (!reserve_request(execution, reason)) return -1;
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_protocol);
    xrdw_protocol_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(status);
    if (brix_send(connection, &request, NULL, &sid, status) != 0) return -1;
    return brix_recv(connection, sid, &response, status);
}

static void
probe_protocol_repeats(xrd_conform_execution *execution,
    brix_conn *connection)
{
    uint8_t *plain = NULL;
    uint8_t *repeat = NULL;
    uint8_t *legacy = NULL;
    uint32_t plain_len = 0, repeat_len = 0, legacy_len = 0;
    brix_status status;
    int plain_ok;
    int repeat_ok;
    int legacy_ok;
    uint8_t repeat_flags = kXR_secreqs | kXR_ableTLS;

    if (connection->want_tls) repeat_flags |= kXR_wantTLS;

    plain_ok = protocol_exchange(execution, connection, 0x300, 0,
        kXR_ExpLogin, &plain, &plain_len, &status) == 0;
    plain_ok = plain_ok && plain_len == sizeof(ServerProtocolBody)
        && connection->protocol_body_len >= 14
        && connection->protocol_body[8] == 'S';
    grade_clause(execution, "PROT-004", plain_ok,
        "S-trailer-only-when-requested",
        "unrequested-security-trailer-present", status.msg);
    repeat_ok = protocol_exchange(execution, connection, kXR_PROTOCOLVERSION,
        repeat_flags, kXR_ExpLogin, &repeat, &repeat_len,
        &status) == 0;
    repeat_ok = repeat_ok
        && repeat_len == connection->protocol_body_len
        && memcmp(repeat, connection->protocol_body, repeat_len) == 0;
    grade_clause(execution, "PROT-009", repeat_ok,
        "repeated-protocol-body-identical", "repeated-protocol-body-changed",
        status.msg);
    grade_clause(execution, "PROT-010", repeat_ok,
        "pre-and-post-login-capabilities-identical",
        "capabilities-depend-on-login", status.msg);
    legacy_ok = protocol_exchange(execution, connection, 0x100, 0,
        kXR_ExpLogin, &legacy, &legacy_len, &status) == 0
        && legacy_len >= sizeof(ServerProtocolBody);
    grade_clause(execution, "PROT-011", legacy_ok,
        "below-floor-version-answered", "below-floor-version-refused",
        status.msg);
    free(plain);
    free(repeat);
    free(legacy);
}

static int
protocol_flags_match(const uint8_t *body, uint32_t length,
    const brix_conn *connection)
{
    return length >= sizeof(ServerProtocolBody)
        && xrd_get_u32_be(body + 4) == connection->server_flags;
}

static void
probe_protocol_expectations(xrd_conform_execution *execution,
    brix_conn *connection)
{
    uint8_t *bif = NULL;
    uint8_t *tpc = NULL;
    uint8_t *unknown = NULL;
    uint32_t bif_len = 0, tpc_len = 0, unknown_len = 0;
    brix_status status;
    int bif_ok;
    int tpc_ok;
    int unknown_ok;

    bif_ok = protocol_exchange(execution, connection, kXR_PROTOCOLVERSION,
        kXR_bifreqs, kXR_ExpLogin, &bif, &bif_len, &status) == 0;
    bif_ok = bif_ok && (bif_len == sizeof(ServerProtocolBody)
        || (bif_len > sizeof(ServerProtocolBody) && bif[8] == 'B'
            && (bif_len & 7U) == 0));
    grade_clause(execution, "PROT-005", bif_ok,
        "bind-preference-omitted-or-aligned",
        "malformed-bind-preference-trailer", status.msg);
    tpc_ok = protocol_exchange(execution, connection, kXR_PROTOCOLVERSION, 0,
        kXR_ExpTPC, &tpc, &tpc_len, &status) == 0;
    tpc_ok = tpc_ok && protocol_flags_match(tpc, tpc_len, connection);
    grade_clause(execution, "PROT-012", tpc_ok,
        "tpc-expect-preserved-capability-flags",
        "tpc-expect-changed-capability-flags", status.msg);
    unknown_ok = protocol_exchange(execution, connection, kXR_PROTOCOLVERSION,
        0, (uint8_t) (kXR_ExpMask + 1), &unknown, &unknown_len, &status) == 0;
    unknown_ok = unknown_ok
        && protocol_flags_match(unknown, unknown_len, connection);
    grade_clause(execution, "PROT-013", unknown_ok,
        "unknown-expect-ignored", "unknown-expect-rejected", status.msg);
    free(bif);
    free(tpc);
    free(unknown);
}

void
grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *pass_reason, const brix_status *status)
{
    char received[96];

    snprintf(received, sizeof(received), "kxr=%d message=%.60s",
        status == NULL ? 0 : status->kxr,
        status == NULL ? "" : status->msg);
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? pass_reason : "unexpected-root-answer", NULL, received);
}

static int
split_path(const char *path, char parent[XRDC_PATH_MAX], const char **name)
{
    const char *slash = strrchr(path, '/');
    size_t length;

    if (slash == NULL || slash[1] == '\0') return -1;
    *name = slash + 1;
    length = slash == path ? 1U : (size_t) (slash - path);
    if (length >= XRDC_PATH_MAX) return -1;
    memcpy(parent, path, length);
    parent[length] = '\0';
    return 0;
}

static void
probe_open_handles(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *first, const char *path)
{
    brix_file second;
    brix_status status;
    char reason[64];
    int opened;

    xrd_conform_result_set(execution, "OPN-001",
        BRIX_CONFORM_VERDICT_CONFORMANT, "read-open-returned-handle", NULL,
        NULL);
    if (!reserve_request(execution, reason)) return;
    brix_status_clear(&status);
    opened = brix_file_open_read(connection, path, &second, &status) == 0;
    grade(execution, "OPN-002", opened
        && memcmp(first->fhandle, second.fhandle, XRDC_FHANDLE_LEN) != 0,
        "simultaneous-handles-distinct", &status);
    if (opened) {
        if (reserve_request(execution, reason))
            brix_file_close(connection, &second, &status);
    }
}

static void
probe_cross_session_handle(xrd_conform_execution *execution, brix_file *file)
{
    brix_url url;
    brix_conn other;
    brix_status status;
    uint8_t byte;
    char reason[64];
    ssize_t got;
    brix_opts opts = execution->run->opts;

    brix_status_clear(&status);
    opts.capture = NULL;
    if (!reserve_request(execution, reason)
        || brix_endpoint_parse(execution->target, &url, &status) != 0
        || brix_connect(&other, &url, &opts, &status) != 0) {
        xrd_conform_result_set(execution, "OPN-004",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "second-session-unavailable",
            NULL, status.msg);
        return;
    }
    if (!reserve_request(execution, reason)) {
        brix_close(&other);
        return;
    }
    brix_status_clear(&status);
    got = brix_file_read(&other, file, 0, &byte, 1, &status);
    grade(execution, "OPN-004", got < 0 && status.kxr == kXR_FileNotOpen,
        "cross-session-handle-refused", &status);
    grade(execution, "ERR-016", got < 0 && status.kxr == kXR_FileNotOpen,
        "bad-handle-mapped-to-file-not-open", &status);
    brix_close(&other);
}

static void
probe_directory_open(xrd_conform_execution *execution, brix_conn *connection,
    const char *parent)
{
    brix_file directory;
    brix_status status;
    char reason[64];
    int rc;

    if (!reserve_request(execution, reason)) return;
    brix_status_clear(&status);
    rc = brix_file_open_read(connection, parent, &directory, &status);
    grade(execution, "OPN-013", rc != 0 && status.kxr == kXR_isDirectory,
        "directory-open-returned-is-directory", &status);
    grade(execution, "ERR-008", rc != 0 && status.kxr == kXR_isDirectory,
        "isdir-mapped-to-is-directory", &status);
    if (rc == 0 && reserve_request(execution, reason))
        brix_file_close(connection, &directory, &status);
}

static size_t
probe_plain_directory(xrd_conform_execution *execution,
    brix_conn *connection, const char *parent, const char *name)
{
    brix_dirent *entries = NULL;
    brix_status status;
    char reason[64];
    size_t count = 0;
    size_t index;
    int found = 0;

    brix_status_clear(&status);
    if (!reserve_request(execution, reason)
        || brix_dirlist(connection, parent, 0, &entries, &count,
            &status) != 0) return 0;
    for (index = 0; index < count; index++)
        if (strcmp(entries[index].name, name) == 0) found = 1;
    xrd_conform_result_set(execution, "DIR-001",
        BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        found ? "target-present-but-directory-not-exclusive"
              : "target-absent-from-parent-listing",
        "exclusive planted-directory fixture", NULL);
    free(entries);
    return count;
}

static void
probe_dstat_directory(xrd_conform_execution *execution,
    brix_conn *connection, const char *parent, size_t plain_count)
{
    brix_dirent *entries = NULL;
    brix_status status;
    char reason[64];
    size_t count = 0;
    size_t index;
    int all_stat = 1;

    brix_status_clear(&status);
    if (!reserve_request(execution, reason)
        || brix_dirlist(connection, parent, 1, &entries, &count,
            &status) != 0) return;
    for (index = 0; index < count; index++)
        if (!entries[index].have_stat) all_stat = 0;
    grade(execution, "DIR-002", count == plain_count && all_stat,
        "dstat-count-matches-plain", &status);
    grade(execution, "DIR-003", count == plain_count && all_stat,
        "exact-dstat-sentinel-recognized", &status);
    free(entries);
}

static void
probe_invalid_directories(xrd_conform_execution *execution,
    brix_conn *connection, const char *parent, const char *path)
{
    brix_dirent *entries = NULL;
    brix_status status;
    char reason[64];
    char escape[XRDC_PATH_MAX];
    size_t count = 0;

    brix_status_clear(&status);
    if (reserve_request(execution, reason))
        grade(execution, "DIR-006",
            brix_dirlist(connection, path, 0, &entries, &count, &status) != 0,
            "file-path-refused-as-directory", &status);
    free(entries);
    if ((size_t) snprintf(escape, sizeof(escape), "%s/..", parent)
        >= sizeof(escape) || !reserve_request(execution, reason)) return;
    entries = NULL;
    count = 0;
    brix_status_clear(&status);
    grade(execution, "DIR-009",
        brix_dirlist(connection, escape, 0, &entries, &count, &status) != 0,
        "parent-traversal-list-refused", &status);
    free(entries);
}

static void
probe_directory(xrd_conform_execution *execution, brix_conn *connection,
    const char *path)
{
    char parent[XRDC_PATH_MAX];
    const char *name;
    brix_statinfo info;
    brix_status status;
    size_t plain_count;
    char reason[64];

    if (split_path(path, parent, &name) != 0) return;
    probe_directory_open(execution, connection, parent);
    brix_status_clear(&status);
    if (reserve_request(execution, reason)
        && brix_stat(connection, parent, &info, &status) == 0)
        grade(execution, "STA-004", (info.flags & kXR_isDir) != 0,
            "parent-stat-identifies-directory", &status);
    plain_count = probe_plain_directory(execution, connection, parent, name);
    probe_dstat_directory(execution, connection, parent, plain_count);
    probe_invalid_directories(execution, connection, parent, path);
}

void
xrd_conform_probe_root_basic(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path)
{
    probe_open_handles(execution, connection, file, path);
    probe_cross_session_handle(execution, file);
    probe_directory(execution, connection, path);
    xrd_conform_probe_root_locate_query(execution, connection, path);
}
