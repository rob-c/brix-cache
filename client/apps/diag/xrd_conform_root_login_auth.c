/* Phase-118 raw authentication rejection and continuation probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"
#include "protocols/root/protocol/codec/wire_codec.h"

#define CONFORM_AUTH_ROUND_LIMIT 10

typedef struct {
    int      classified;
    int      accepted;
    int      terminal;
    uint32_t kxr;
} conform_auth_observation;

static int
active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static void
grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const char *failure)
{
    if (!active(execution, id)) return;
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : failure, NULL, NULL);
}

static void
inconclusive(xrd_conform_execution *execution, const char *id,
    const char *reason)
{
    if (!active(execution, id)) return;
    xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        reason, NULL, NULL);
}

static int
reserve_request(xrd_conform_execution *execution, size_t bytes)
{
    char reason[64];

    return xrd_conform_reserve(execution, bytes, reason, sizeof(reason));
}

static int
raw_login_name(xrd_conform_execution *execution, const brix_url *url,
    const char *username, brix_conn *connection, char security[256])
{
    brix_opts options = execution->run->opts;
    brix_status status;
    ClientLoginRequest login;
    const uint8_t zero_sid[2] = { 0, 0 };
    uint16_t wire_status = kXR_error;
    uint16_t sid;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_resp_out output = { &wire_status, &body, &body_length };
    size_t security_length;
    int pass;

    options.capture = NULL;
    options.no_retry = 1;
    brix_status_clear(&status);
    if (brix_connect_no_login(connection, url, &options, &status) != 0)
        return -1;
    xrd_pack_login_request(&login, zero_sid, 1, username,
        (uint8_t) (kXR_ver005 | kXR_asyncap));
    pass = reserve_request(execution, sizeof(login))
        && brix_send(connection, &login, NULL, &sid, &status) == 0
        && brix_recv(connection, sid, &output, &status) == 0
        && wire_status == kXR_ok && body_length > BRIX_SESSION_ID_LEN;
    if (!pass) {
        free(body);
        brix_close(connection);
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
raw_login(xrd_conform_execution *execution, const brix_url *url,
    brix_conn *connection, char security[256])
{
    return raw_login_name(execution, url, "conform", connection, security);
}

static int
first_protocol(const char *security, char protocol[5])
{
    const char *name = strstr(security, "&P=");
    const char *end;
    size_t length;

    if (name == NULL) return -1;
    name += 3;
    end = name;
    while (*end != '\0' && *end != ',' && *end != '&') end++;
    length = (size_t) (end - name);
    if (length == 0 || length > 4) return -1;
    memcpy(protocol, name, length);
    protocol[length] = '\0';
    return 0;
}

static int
send_auth(xrd_conform_execution *execution, brix_conn *connection,
    const char *protocol, conform_auth_observation *observation)
{
    static const uint8_t invalid[] = "brix-conform-garbage";
    ClientAuthRequest auth;
    xrdw_auth_req_t body_fields;
    brix_payload payload = { invalid, sizeof(invalid) - 1 };
    brix_status status;
    uint16_t wire_status = kXR_error;
    uint16_t sid;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_resp_out output = { &wire_status, &body, &body_length };
    int round;

    memset(observation, 0, sizeof(*observation));
    for (round = 0; round < CONFORM_AUTH_ROUND_LIMIT; round++) {
        memset(&auth, 0, sizeof(auth));
        auth.requestid = htons(kXR_auth);
        memset(&body_fields, 0, sizeof(body_fields));
        memcpy(body_fields.credtype, protocol, strlen(protocol));
        xrdw_auth_req_pack(&body_fields, ((ClientRequestHdr *) &auth)->body);
        if (!reserve_request(execution, sizeof(auth) + payload.len)) return -1;
        brix_status_clear(&status);
        if (brix_send(connection, &auth, &payload, &sid, &status) != 0)
            return -1;
        wire_status = kXR_error;
        body = NULL;
        body_length = 0;
        if (brix_recv(connection, sid, &output, &status) != 0) {
            free(body);
            observation->classified = status.kxr != 0;
            observation->terminal = 1;
            observation->kxr = status.kxr;
            return 0;
        }
        free(body);
        if (wire_status == kXR_ok) {
            observation->classified = 1;
            observation->accepted = 1;
            observation->terminal = 1;
            return 0;
        }
        if (wire_status != kXR_authmore) return -1;
    }
    observation->classified = 1;
    return 0;
}

static void
probe_unadvertised(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn connection;
    conform_auth_observation observation;
    char security[256];

    if (!active(execution, "LOG-006")) return;
    if (raw_login(execution, url, &connection, security) != 0) {
        inconclusive(execution, "LOG-006",
            "fixture-unavailable:unadvertised-auth");
        return;
    }
    if (send_auth(execution, &connection, "zzz", &observation) != 0) {
        brix_close(&connection);
        inconclusive(execution, "LOG-006",
            "fixture-unavailable:unadvertised-auth");
        return;
    }
    brix_close(&connection);
    if (!observation.classified) {
        inconclusive(execution, "LOG-006",
            "fixture-unavailable:unadvertised-auth");
        return;
    }
    grade(execution, "LOG-006", observation.terminal
        && !observation.accepted, "unadvertised-auth-mechanism-refused",
        "unadvertised-auth-mechanism-accepted");
}

static void
probe_bad_continuation(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn connection;
    conform_auth_observation observation;
    brix_statinfo info;
    brix_status status;
    char security[256];
    char protocol[5];
    int stat_rc;

    if (!active(execution, "LOG-015") && !active(execution, "LOG-016")
        && !active(execution, "LOG-017")) return;
    if (raw_login(execution, url, &connection, security) != 0) {
        inconclusive(execution, "LOG-015",
            "fixture-unavailable:auth-continuation");
        inconclusive(execution, "LOG-016",
            "fixture-unavailable:auth-continuation");
        inconclusive(execution, "LOG-017",
            "fixture-unavailable:failed-auth-session");
        return;
    }
    if (first_protocol(security, protocol) != 0
        || send_auth(execution, &connection, protocol, &observation) != 0
        || !observation.classified) {
        brix_close(&connection);
        inconclusive(execution, "LOG-015",
            "fixture-unavailable:auth-continuation");
        inconclusive(execution, "LOG-016",
            "fixture-unavailable:auth-continuation");
        inconclusive(execution, "LOG-017",
            "fixture-unavailable:failed-auth-session");
        return;
    }
    grade(execution, "LOG-015", observation.terminal,
        "auth-continuation-terminated-within-bound",
        "auth-continuation-exceeded-round-bound");
    grade(execution, "LOG-016", observation.terminal
        && !observation.accepted && observation.kxr == kXR_AuthFailed,
        "garbage-auth-continuation-returned-AuthFailed",
        "garbage-auth-continuation-wrong-result");
    brix_status_clear(&status);
    stat_rc = observation.terminal && !observation.accepted
        ? brix_stat(&connection, url->path, &info, &status) : 0;
    grade(execution, "LOG-017", observation.terminal
        && !observation.accepted && stat_rc != 0,
        "failed-auth-session-retained-no-privilege",
        "failed-auth-session-retained-privilege");
    brix_close(&connection);
}

static void
probe_nul_identity(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn connection;
    brix_statinfo info;
    brix_status status;
    char security[256];
    int rc;

    if (!active(execution, "LOG-008")) return;
    if (raw_login_name(execution, url, "", &connection, security) != 0) {
        inconclusive(execution, "LOG-008",
            "fixture-unavailable:nul-username-identity");
        return;
    }
    brix_status_clear(&status);
    rc = brix_stat(&connection, url->path, &info, &status);
    brix_close(&connection);
    grade(execution, "LOG-008", rc != 0
        && (status.kxr == kXR_NotAuthorized
            || status.kxr == kXR_AuthFailed),
        "nul-username-retained-no-default-identity",
        rc == 0 ? "nul-username-inherited-default-identity"
                : "nul-username-returned-unclassified-error");
}

void
xrd_conform_probe_login_auth_negatives(xrd_conform_execution *execution,
    const brix_url *url)
{
    probe_nul_identity(execution, url);
    probe_unadvertised(execution, url);
    probe_bad_continuation(execution, url);
}

static int
redirect_host_is_ipv6(const uint8_t *body, uint32_t length, int *valid)
{
    size_t index;
    size_t colons = 0;
    size_t host_length = 0;

    *valid = 0;
    if (length <= 4) return 0;
    for (index = 4; index < length; index++) {
        if (body[index] == '\0' || body[index] == '?') break;
        if (body[index] == ':') colons++;
        host_length++;
    }
    if (host_length == 0 || index == length) return 0;
    *valid = 1;
    return body[4] == '[' || colons > 1;
}

/* WHAT: Send login with both ability bytes zero and inspect its first answer.
 * WHY: Following a redirect would hide a server that invented IPv6 ability
 *      the client never advertised and strand IPv4-only callers.
 * HOW: Stop after brix_recv surfaces the raw status; accept login, a defined
 *      refusal, or a non-IPv6 redirect, and reject malformed/IPv6-only hops. */
void
xrd_conform_probe_login_abilities(xrd_conform_execution *execution,
    const brix_url *url)
{
    brix_opts options = execution->run->opts;
    brix_conn connection;
    brix_status status;
    ClientLoginRequest login;
    const uint8_t zero_sid[2] = { 0, 0 };
    uint16_t wire_status = kXR_error;
    uint16_t sid;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_resp_out output = { &wire_status, &body, &body_length };
    int rc;
    int valid = 0;
    int ipv6 = 0;

    if (!active(execution, "LOG-025")) return;
    options.capture = NULL;
    brix_status_clear(&status);
    if (brix_connect_no_login(&connection, url, &options, &status) != 0) {
        inconclusive(execution, "LOG-025",
            "fixture-unavailable:zero-ability-login");
        return;
    }
    xrd_pack_login_request(&login, zero_sid, 1, "conform", kXR_ver005);
    if (!reserve_request(execution, sizeof(login))
        || brix_send(&connection, &login, NULL, &sid, &status) != 0) {
        brix_close(&connection);
        inconclusive(execution, "LOG-025",
            "fixture-unavailable:zero-ability-login");
        return;
    }
    rc = brix_recv(&connection, sid, &output, &status);
    if (rc == 0 && wire_status == kXR_redirect)
        ipv6 = redirect_host_is_ipv6(body, body_length, &valid);
    free(body);
    brix_close(&connection);
    if (rc != 0 && status.kxr <= 0) {
        inconclusive(execution, "LOG-025",
            "fixture-unavailable:zero-ability-login");
        return;
    }
    grade(execution, "LOG-025",
        (rc != 0 && status.kxr > 0) || wire_status == kXR_ok
            || (wire_status == kXR_redirect && valid && !ipv6),
        "zero-ability-login-received-no-ipv6-only-redirect",
        wire_status == kXR_redirect && ipv6
            ? "zero-ability-login-received-ipv6-only-redirect"
            : "zero-ability-login-received-malformed-response");
}
