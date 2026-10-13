/* Phase-118 ROOT TLS claim, verification and cross-transport probes. */
#include "xrd_conform_internal.h"
#include "platform/platform_api.h"

#include <openssl/ssl.h>

/* WHAT: Return whether one selected row still needs a probe result.
 * WHY: Multi-target runs revisit this module and must preserve earlier evidence.
 * HOW: Accept only an existing, non-skipped, provisional row. */
static int
pending(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict == BRIX_CONFORM_VERDICT_INCONCLUSIVE
        && strcmp(row->reason, "probe-not-executed") == 0;
}

/* WHAT: Record a capability- or fixture-specific safety skip.
 * WHY: An absent prerequisite is not evidence for or against conformance.
 * HOW: Replace only the untouched provisional result. */
static void
skip_pending(xrd_conform_execution *execution, const char *id,
    const char *reason)
{
    if (!pending(execution, id)) return;
    xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_SKIPPED,
        reason, NULL, NULL);
}

/* WHAT: Grade the mandatory gotoTLS transition on the live connection.
 * WHY: Advertising an upgrade while continuing in cleartext is a downgrade.
 * HOW: Compare kXR_gotoTLS with the transport state exposed by libbrix. */
static void
probe_upgrade(xrd_conform_execution *execution, const brix_conn *connection,
    int tls_active, const char *version)
{
    if ((connection->server_flags & kXR_gotoTLS) == 0) return;
    execution->root_tls_goto_seen = 1;
    if (!pending(execution, "TLS-001")) return;
    xrd_conform_result_set(execution, "TLS-001",
        tls_active ? BRIX_CONFORM_VERDICT_CONFORMANT
                   : BRIX_CONFORM_VERDICT_DIVERGENT,
        tls_active ? "gototls-upgrade-completed"
                   : "gototls-downgraded-to-cleartext",
        "active TLS after kXR_gotoTLS", version);
}

/* WHAT: Verify the endpoint again with chain and hostname checks forced on.
 * WHY: A run using an insecure inspection option must not make TLS-007 green.
 * HOW: Use an isolated no-capture connection with secure verification options.
 */
static void
probe_certificate(xrd_conform_execution *execution, const brix_url *url,
    int tls_active)
{
    brix_opts options = execution->run->opts;
    brix_conn checked;
    brix_status status;
    int connected;

    if (!tls_active || !pending(execution, "TLS-007")) return;
    options.capture = NULL;
    options.insecure_tls = 0;
    options.verify_host = 1;
    brix_status_clear(&status);
    connected = brix_connect_no_login(&checked, url, &options, &status) == 0;
    if (connected) brix_close(&checked);
    xrd_conform_result_set(execution, "TLS-007",
        connected ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
        connected ? "certificate-chain-and-hostname-verified"
                  : "certificate-verification-failed",
        "trusted chain and matching hostname", status.msg);
}

/* WHAT: Attempt bounded TLS-1.2 and TLS-1.1-only upgrades to the same target.
 * WHY: A local library floor alone cannot prove the server rejects legacy
 *      ClientHello messages; the endpoint must make that decision on the wire.
 * HOW: Require a TLS-1.2 control connection, then lower only an isolated
 *      diagnostic connection's maximum and require its handshake to fail. */
static void
probe_protocol_floor(xrd_conform_execution *execution, const brix_url *url)
{
    brix_opts options = execution->run->opts;
    brix_conn connection;
    brix_status status;
    int control;
    int legacy;

    if (!pending(execution, "TLS-006")) return;
    options.capture = NULL;
    options.no_retry = 1;
    options.insecure_tls = 1;
    options.verify_host = 0;
    options.tls_max_version = TLS1_2_VERSION;
    brix_status_clear(&status);
    control = brix_connect_no_login(&connection, url, &options, &status) == 0;
    if (control) brix_close(&connection);
    if (!control) {
        xrd_conform_result_set(execution, "TLS-006",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "tls12-control-handshake-unavailable", NULL, status.msg);
        return;
    }
    options.tls_max_version = TLS1_1_VERSION;
    brix_status_clear(&status);
    legacy = brix_connect_no_login(&connection, url, &options, &status) == 0;
    if (legacy) brix_close(&connection);
    xrd_conform_result_set(execution, "TLS-006",
        legacy ? BRIX_CONFORM_VERDICT_DIVERGENT
               : BRIX_CONFORM_VERDICT_CONFORMANT,
        legacy ? "legacy-tls-clienthello-accepted"
               : "legacy-tls-clienthello-refused",
        "TLS 1.0/1.1 refused after TLS 1.2 control", status.msg);
}

/* WHAT: Ask a TLS-1.2 session to renegotiate and observe the peer decision.
 * WHY: Negotiating TLS 1.3 does not prove the same endpoint's TLS-1.2 path has
 *      disabled client-initiated renegotiation.
 * HOW: Constrain an isolated control to 1.2, then drive OpenSSL's renegotiation
 *      state machine under the ordinary connection timeout. */
static void
probe_renegotiation(xrd_conform_execution *execution, const brix_url *url)
{
    brix_opts options = execution->run->opts;
    brix_conn connection;
    brix_status status;
    int connected;
    int result;

    if (!pending(execution, "TLS-008")) return;
    options.capture = NULL;
    options.no_retry = 1;
    options.insecure_tls = 1;
    options.verify_host = 0;
    options.tls_max_version = TLS1_2_VERSION;
    brix_status_clear(&status);
    connected = brix_connect_no_login(&connection, url, &options, &status) == 0;
    if (!connected) {
        xrd_conform_result_set(execution, "TLS-008",
            execution->root_tls13_seen ? BRIX_CONFORM_VERDICT_CONFORMANT
                                       : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            execution->root_tls13_seen ? "endpoint-is-tls13-only"
                                       : "tls12-control-handshake-unavailable",
            NULL, status.msg);
        return;
    }
    result = brix_tls_probe_renegotiate(&connection, &status);
    brix_close(&connection);
    xrd_conform_result_set(execution, "TLS-008",
        result == 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                    : result > 0 ? BRIX_CONFORM_VERDICT_DIVERGENT
                                 : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        result == 0 ? "tls12-renegotiation-refused"
                    : result > 0 ? "tls12-renegotiation-accepted"
                                 : "tls12-renegotiation-indeterminate",
        "client-initiated renegotiation refused", status.msg);
}

/* WHAT: Resume an authenticated TLS session while suppressing application auth.
 * WHY: TLS resumption may restore transport parameters, never ROOT identity or
 *      authorization state from the connection that minted the ticket.
 * HOW: Prove the authenticated baseline, retain an OpenSSL session reference,
 *      reconnect with force_anon, require confirmed resumption, then demand an
 *      exact authorization refusal for the protected object. */
static void
probe_resumed_identity(xrd_conform_execution *execution, const brix_url *url,
    const brix_conn *authenticated)
{
    brix_opts options = execution->run->opts;
    brix_conn baseline_connection = { 0 };
    brix_conn resumed;
    brix_statinfo info;
    brix_status status;
    void *session;
    char reason[64];
    int baseline;
    int connected;
    int denied;

    if (!pending(execution, "TLS-009")
        || authenticated->sec_list[0] == '\0') return;
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        xrd_conform_result_set(execution, "TLS-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "request-ceiling-before-resumption-baseline", NULL, NULL);
        return;
    }
    options.capture = NULL;
    options.no_retry = 1;
    options.tls_resume_session = NULL;
    baseline_connection.io.fd = -1;
    brix_status_clear(&status);
    connected = brix_connect(&baseline_connection, url, &options, &status) == 0;
    baseline = connected;
    if (connected) {
        baseline = brix_stat(&baseline_connection, url->path, &info,
            &status) == 0;
    }
    session = baseline ? brix_tls_session_get(&baseline_connection) : NULL;
    if (connected) brix_close(&baseline_connection);
    if (session == NULL) {
        xrd_conform_result_set(execution, "TLS-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            baseline ? "tls-session-ticket-unavailable"
                     : "authenticated-baseline-unavailable",
            NULL, status.msg);
        return;
    }
    options.force_anon = 1;
    options.tls_resume_session = session;
    brix_status_clear(&status);
    if (brix_connect(&resumed, url, &options, &status) != 0) {
        brix_tls_session_free(session);
        xrd_conform_result_set(execution, "TLS-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "resumed-anonymous-connection-unavailable", NULL, status.msg);
        return;
    }
    brix_tls_session_free(session);
    if (!resumed.tls_session_reused) {
        brix_close(&resumed);
        xrd_conform_result_set(execution, "TLS-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "server-did-not-resume-session", NULL, NULL);
        return;
    }
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        brix_close(&resumed);
        xrd_conform_result_set(execution, "TLS-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "request-ceiling-before-resumed-stat", NULL, NULL);
        return;
    }
    brix_status_clear(&status);
    denied = brix_stat(&resumed, url->path, &info, &status) != 0
        && (status.kxr == kXR_NotAuthorized || status.kxr == kXR_AuthFailed);
    brix_close(&resumed);
    xrd_conform_result_set(execution, "TLS-009",
        denied ? BRIX_CONFORM_VERDICT_CONFORMANT
               : BRIX_CONFORM_VERDICT_DIVERGENT,
        denied ? "resumed-session-did-not-carry-authorization"
               : "resumed-session-inherited-authorization",
        "authorization refusal after confirmed TLS resumption", status.msg);
}

/* WHAT: Record which ROOT transport produced the adopted-object digest.
 * WHY: TLS-005 requires independent cleartext and TLS byte oracles.
 * HOW: Retain the first digest per transport and grade when both exist. */
static void
probe_transport_bytes(xrd_conform_execution *execution, int tls_active)
{
    if (tls_active) {
        snprintf(execution->root_tls_digest,
            sizeof(execution->root_tls_digest), "%s", execution->root_digest);
        execution->have_root_tls = 1;
    } else {
        snprintf(execution->root_clear_digest,
            sizeof(execution->root_clear_digest), "%s", execution->root_digest);
        execution->have_root_clear = 1;
    }
    if (execution->have_root_tls && execution->have_root_clear
        && pending(execution, "TLS-005")) {
        int equal = strcmp(execution->root_tls_digest,
            execution->root_clear_digest) == 0;

        xrd_conform_result_set(execution, "TLS-005",
            equal ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
            equal ? "cleartext-and-tls-bytes-identical"
                  : "cleartext-and-tls-bytes-differ",
            execution->root_clear_digest, execution->root_tls_digest);
    }
}

/* WHAT: Grade observations that require a successfully adopted ROOT object.
 * WHY: TLS response framing and cross-transport equality need actual data bytes.
 * HOW: Use the completed baseline read and retain transport-specific digests. */
static void
probe_object_tls(xrd_conform_execution *execution, int tls_active,
    uint32_t required)
{
    if (tls_active && pending(execution, "TLS-004"))
        xrd_conform_result_set(execution, "TLS-004",
            BRIX_CONFORM_VERDICT_CONFORMANT,
            "tls-data-framing-byte-exact", "encrypted framed object",
            execution->root_digest);
    if (!tls_active && required == 0 && pending(execution, "TLS-003"))
        xrd_conform_result_set(execution, "TLS-003",
            BRIX_CONFORM_VERDICT_CONFORMANT,
            "unflagged-data-served-in-cleartext", "cleartext data response",
            execution->root_digest);
    probe_transport_bytes(execution, tls_active);
}

/* WHAT: Collect live TLS evidence from one ROOT plane.
 * WHY: A paired --also run may need observations from two distinct listeners.
 * HOW: Accumulate claims and grade rows supported by this particular session. */
void
xrd_conform_probe_tls(xrd_conform_execution *execution, const brix_url *url,
    const brix_conn *connection, int object_observed)
{
    const char *version = NULL;
    const char *cipher = NULL;
    int tls_active;
    uint32_t required;

    if (!xrd_conform_family_active(execution, "TLS")) return;
    tls_active = brix_tls_info(connection, &version, &cipher);
    required = connection->server_flags & (kXR_tlsAny | kXR_tlsGPFA);
    execution->root_tls_active_seen |= tls_active;
    execution->root_tls_auth_seen |= connection->sec_list[0] != '\0';
    execution->root_tls_required_seen |= required;
    execution->root_tls13_seen |= version != NULL
        && strcmp(version, "TLSv1.3") == 0;
    probe_upgrade(execution, connection, tls_active, version);
    probe_certificate(execution, url, tls_active);
    if (tls_active) probe_protocol_floor(execution, url);
    if (tls_active) probe_renegotiation(execution, url);
    if (tls_active) probe_resumed_identity(execution, url, connection);
    if (object_observed) probe_object_tls(execution, tls_active, required);
    (void) cipher;
}

static uint32_t
tls_fixture_bit(const char *request_class)
{
    if (strcmp(request_class, "login") == 0) return kXR_tlsLogin;
    if (strcmp(request_class, "data") == 0) return kXR_tlsData;
    if (strcmp(request_class, "gpf") == 0) return kXR_tlsGPF;
    if (strcmp(request_class, "session") == 0) return kXR_tlsSess;
    return strcmp(request_class, "tpc") == 0 ? kXR_tlsTPC : 0;
}

static int
tls_required(const brix_status *status)
{
    return status->kxr == kXR_TLSRequired;
}

static int
probe_gpf_cleartext(brix_conn *connection, brix_status *status)
{
    ClientRequestHdr request;
    uint16_t wire_status;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_payload payload = { NULL, 0 };
    brix_resp_out response = { &wire_status, &body, &body_length };
    int rc;

    memset(&request, 0, sizeof(request));
    request.requestid = brix_plat_htobe16(kXR_gpfile);
    rc = brix_roundtrip(connection, &request, &payload, &response, status);
    free(body);
    return rc != 0 && tls_required(status);
}

static int
probe_data_cleartext(brix_conn *connection, const char *path,
    brix_status *status)
{
    brix_file file;
    uint8_t byte;
    ssize_t got;

    if (brix_file_open_read(connection, path, &file, status) != 0) return 0;
    got = brix_file_read(connection, &file, 0, &byte, 1, status);
    if (got >= 0) (void) brix_file_close(connection, &file, status);
    return got < 0 && tls_required(status);
}

static int
probe_session_cleartext(brix_conn *connection, const char *path,
    brix_status *status)
{
    brix_statinfo info;

    return brix_stat(connection, path, &info, status) != 0
        && tls_required(status);
}

static int
probe_tpc_cleartext(brix_conn *connection, const char *path,
    brix_status *status)
{
    brix_file file;

    return brix_file_open_opaque(connection, path,
        "tpc.key=phase118&tpc.dst=127.0.0.1&tpc.stage=copy",
        0, 0, 0, &file, status) != 0 && tls_required(status);
}

static int
probe_cleartext_class(brix_conn *connection, const brix_url *url,
    const char *request_class, brix_status *status)
{
    if (strcmp(request_class, "session") == 0)
        return probe_session_cleartext(connection, url->path, status);
    if (strcmp(request_class, "data") == 0)
        return probe_data_cleartext(connection, url->path, status);
    if (strcmp(request_class, "gpf") == 0)
        return probe_gpf_cleartext(connection, status);
    return probe_tpc_cleartext(connection, url->path, status);
}

/* WHAT: Exercise each operator-supplied incapable-client TLS fixture.
 * WHY: An ordinary client upgrades automatically and therefore cannot prove a
 *      server refuses the corresponding request class on cleartext.
 * HOW: Force anonymous credential selection, suppress only the test upgrade,
 *      require the advertised class bit, and accept only kXR_TLSRequired. */
void
xrd_conform_probe_tls_fixtures(xrd_conform_execution *execution)
{
    size_t index;

    if (!xrd_conform_family_active(execution, "TLS")) return;
    for (index = 0; index < execution->run->tls_fixture_count; index++) {
        const xrd_conform_tls_fixture *fixture =
            &execution->run->tls_fixtures[index];
        brix_opts options = execution->run->opts;
        brix_url url;
        brix_conn connection = { 0 };
        brix_status status;
        uint32_t bit = tls_fixture_bit(fixture->request_class);
        char reason[64];
        int connected;
        int refused = 0;

        execution->root_tls_fixture_attempted = 1;
        if (bit == 0 || brix_endpoint_parse(fixture->target, &url, &status) != 0
            || url.scheme != XRDC_SCHEME_ROOT
            || !xrd_conform_reserve(execution, 0, reason, sizeof(reason)))
            continue;
        options.capture = NULL;
        options.no_retry = 1;
        options.force_anon = 1;
        options.auth_force = NULL;
        options.diagnostic_no_tls_upgrade = 1;
        brix_status_clear(&status);
        connected = brix_connect(&connection, &url, &options, &status) == 0;
        execution->root_tls_required_seen |= connection.server_flags
            & (kXR_tlsAny | kXR_tlsGPFA);
        if ((connection.server_flags & bit) == 0) {
            if (connected) brix_close(&connection);
            continue;
        }
        execution->root_tls_cleartext_tested |= bit;
        if (strcmp(fixture->request_class, "login") == 0) {
            refused = !connected && tls_required(&status);
        } else if (connected) {
            refused = probe_cleartext_class(&connection, &url,
                fixture->request_class, &status);
        }
        if (connected) brix_close(&connection);
        if (refused) execution->root_tls_cleartext_refused |= bit;
    }
}

/* WHAT: Resolve TLS rows that need the complete multi-target observation set.
 * WHY: Finalizing after --also avoids prematurely skipping a later TLS plane.
 * HOW: Name each absent claim or dedicated negative fixture explicitly. */
void
xrd_conform_finalize_tls(xrd_conform_execution *execution)
{
    uint32_t required;

    if (!xrd_conform_family_active(execution, "TLS")) return;
    if (!execution->root_tls_goto_seen)
        skip_pending(execution, "TLS-001", "claim-absent:kXR_gotoTLS");
    required = execution->root_tls_required_seen & kXR_tlsAny;
    if (required == 0) {
        skip_pending(execution, "TLS-002",
            execution->root_tls_fixture_attempted
                ? "fixture-did-not-advertise-requested-tls-class"
                : "claim-absent:per-class-tls-requirement");
    } else if (pending(execution, "TLS-002")) {
        int complete = (execution->root_tls_cleartext_tested & required)
            == required;
        int refused = (execution->root_tls_cleartext_refused & required)
            == required;

        xrd_conform_result_set(execution, "TLS-002",
            !complete ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                : refused ? BRIX_CONFORM_VERDICT_CONFORMANT
                          : BRIX_CONFORM_VERDICT_DIVERGENT,
            !complete ? "fixture-required:untested-cleartext-tls-class"
                : refused ? "all-advertised-tls-classes-refused-cleartext"
                          : "advertised-tls-class-accepted-cleartext",
            "exact kXR_TLSRequired for every advertised class", NULL);
    }
    if (pending(execution, "TLS-003"))
        skip_pending(execution, "TLS-003",
            execution->have_root_clear
                ? "claim-absent:unflagged-cleartext-class"
                : "fixture-required:cleartext-endpoint");
    if (!execution->root_tls_active_seen) {
        skip_pending(execution, "TLS-004", "claim-absent:active-tls");
        skip_pending(execution, "TLS-006", "claim-absent:active-tls");
        skip_pending(execution, "TLS-007", "claim-absent:active-tls");
        skip_pending(execution, "TLS-008", "claim-absent:active-tls");
    } else {
        skip_pending(execution, "TLS-004", "fixture-required:tls-data-object");
        skip_pending(execution, "TLS-006",
            "fixture-unavailable:legacy-clienthello");
        skip_pending(execution, "TLS-008",
            "fixture-unavailable:tls12-renegotiation");
    }
    skip_pending(execution, "TLS-005",
        "fixture-required:paired-cleartext-tls-endpoints");
    skip_pending(execution, "TLS-009",
        execution->root_tls_auth_seen
            ? "fixture-unavailable:session-resumption-identity"
            : "claim-absent:authenticated-authorization");
}
