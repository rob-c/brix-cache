/* Phase-118 per-security-protocol authentication-failure classification. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"
#include "protocols/root/protocol/codec/wire_codec.h"
#include "protocols/root/protocol/sec_protocol.h"

static int
auth_exchange(xrd_conform_execution *execution, brix_conn *connection,
    ClientRequestHdr *request, const void *payload, uint16_t *wire_status,
    uint8_t **body, uint32_t *body_length, brix_status *status)
{
    brix_resp_out output = { wire_status, body, body_length };
    uint16_t sid;
    char reason[64];

    if (!xrd_conform_reserve(execution, sizeof(*request), reason,
            sizeof(reason))) return -2;
    brix_status_clear(status);
    if (brix_send(connection, request, payload, &sid, status) != 0) return -1;
    return brix_recv(connection, sid, &output, status);
}

/* WHAT: Login without invoking a client authentication module.
 * WHY: The negative must send intentionally invalid material even when the host
 *      has no real credential for the advertised security protocol.
 * HOW: Handshake only, then issue the standard anonymous login and retain its
 *      bounded &P= security list for an exact offered-protocol check. */
static int
auth_fixture_login(xrd_conform_execution *execution, const brix_url *url,
    brix_conn *connection, char security[256], brix_status *status)
{
    ClientLoginRequest login;
    brix_opts options = execution->run->opts;
    const uint8_t zero_sid[2] = { 0, 0 };
    uint16_t wire_status = kXR_error;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    size_t security_length;
    int rc;

    options.capture = NULL;
    if (brix_connect_no_login(connection, url, &options, status) != 0) return -1;
    xrd_pack_login_request(&login, zero_sid, 1, "conform",
        (uint8_t) (kXR_ver005 | kXR_asyncap));
    rc = auth_exchange(execution, connection, (ClientRequestHdr *) &login,
        NULL, &wire_status, &body, &body_length, status);
    if (rc != 0 || wire_status != kXR_ok
        || body_length <= BRIX_SESSION_ID_LEN) {
        free(body);
        return -1;
    }
    security_length = body_length - BRIX_SESSION_ID_LEN;
    if (security_length >= 256) security_length = 255;
    memcpy(security, body + BRIX_SESSION_ID_LEN, security_length);
    security[security_length] = '\0';
    free(body);
    return 0;
}

static int
auth_fixture_named(const xrd_conform_run *run, const char *name, size_t length)
{
    size_t index;

    for (index = 0; index < run->auth_fixture_count; index++)
        if (strlen(run->auth_fixtures[index].protocol) == length
            && memcmp(run->auth_fixtures[index].protocol, name, length) == 0)
            return 1;
    return 0;
}

/* WHAT: Require a labelled probe for every protocol any fixture advertises.
 * WHY: Omitting a difficult mechanism must not turn "every enabled protocol"
 *      into a vacuous pass over an operator-selected subset.
 * HOW: Parse each anchored &P=name entry with the shared grammar boundaries and
 *      require its exact name to exist in the complete fixture vector. */
int
xrd_conform_auth_fixtures_cover(const xrd_conform_run *run,
    const char *security)
{
    const char *entry = security;
    size_t count = 0;

    while ((entry = strstr(entry, "&P=")) != NULL) {
        const char *name = entry + 3;
        const char *end = name;

        while (*end != '\0' && *end != ',' && *end != '&') end++;
        if (end == name || !auth_fixture_named(run, name,
                (size_t) (end - name))) return 0;
        count++;
        entry = end;
    }
    return count != 0;
}

/* WHAT: Send malformed credentials for one explicitly advertised protocol.
 * WHY: ERR-047 tests the server's wire classification, not local credential
 *      discovery or the client's ability to complete a successful login.
 * HOW: Build a raw kXR_auth with the real credtype and an invalid bounded blob;
 *      accept only AuthFailed or NotAuthorized from the resulting error frame. */
static int
auth_failure_matches(xrd_conform_execution *execution,
    const xrd_conform_auth_fixture *fixture)
{
    static const uint8_t invalid[] = "brix-conform-invalid-credential";
    brix_url url;
    brix_conn connection;
    brix_status status;
    ClientAuthRequest auth;
    xrdw_auth_req_t body;
    brix_payload payload = { invalid, sizeof(invalid) - 1 };
    char security[256];
    uint16_t wire_status = kXR_error;
    uint8_t *reply = NULL;
    uint32_t reply_length = 0;
    int rc;
    int matched = 0;
    size_t protocol_length;

    brix_status_clear(&status);
    if (brix_endpoint_parse(fixture->target, &url, &status) != 0
        || (url.scheme != XRDC_SCHEME_ROOT && url.scheme != XRDC_SCHEME_ROOTS)
        || auth_fixture_login(execution, &url, &connection, security,
            &status) != 0) return 0;
    if (!brix_sec_proto_advertised(security, fixture->protocol, NULL, 0)
        || !xrd_conform_auth_fixtures_cover(execution->run, security)) {
        brix_close(&connection);
        return 0;
    }
    memset(&auth, 0, sizeof(auth));
    auth.requestid = htons(kXR_auth);
    memset(&body, 0, sizeof(body));
    protocol_length = strlen(fixture->protocol);
    if (protocol_length > sizeof(body.credtype))
        protocol_length = sizeof(body.credtype);
    memcpy(body.credtype, fixture->protocol, protocol_length);
    xrdw_auth_req_pack(&body, ((ClientRequestHdr *) &auth)->body);
    rc = auth_exchange(execution, &connection, (ClientRequestHdr *) &auth,
        &payload, &wire_status, &reply, &reply_length, &status);
    if (rc != 0)
        matched = status.kxr == kXR_AuthFailed
            || status.kxr == kXR_NotAuthorized;
    free(reply);
    brix_close(&connection);
    return matched;
}

/* WHAT: Grade invalid credentials for every explicitly enabled protocol.
 * WHY: A generic FSError hides an authentication failure and defeats clients'
 *      security-aware retry and diagnostic behavior.
 * HOW: Require every labelled fixture to advertise its label and return one of
 *      the two permitted authentication-class wire codes. */
void
xrd_conform_probe_auth_fixtures(xrd_conform_execution *execution)
{
    const brix_conform_result *row;
    size_t index;
    size_t matched = 0;
    char received[80];

    row = xrd_conform_result_find(execution, "ERR-047");
    if (row == NULL || row->verdict == BRIX_CONFORM_VERDICT_SKIPPED
        || execution->run->auth_fixture_count == 0) return;
    for (index = 0; index < execution->run->auth_fixture_count; index++)
        if (auth_failure_matches(execution,
                &execution->run->auth_fixtures[index])) matched++;
    snprintf(received, sizeof(received), "protocols=%zu exact=%zu",
        execution->run->auth_fixture_count, matched);
    xrd_conform_result_set(execution, "ERR-047",
        matched == execution->run->auth_fixture_count
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        matched == execution->run->auth_fixture_count
            ? "all-supplied-auth-protocols-use-auth-class-errors"
            : "auth-protocol-returned-non-auth-class-error",
        "each enabled protocol returns kXR_AuthFailed or kXR_NotAuthorized",
        received);
}
