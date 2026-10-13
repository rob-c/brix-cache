/* Phase-118 WLCG token claim-negative fixtures. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"
#include "protocols/root/protocol/sec_protocol.h"

typedef struct {
    int available;
    int accepted;
    int kxr;
} token_observation;

static const xrd_conform_token_fixture *
fixture_for(const xrd_conform_run *run, const char *kind)
{
    size_t index;

    for (index = 0; index < run->token_fixture_count; index++)
        if (strcmp(run->token_fixtures[index].kind, kind) == 0)
            return &run->token_fixtures[index];
    return NULL;
}

static int
advertises_ztn(xrd_conform_execution *execution, const brix_url *url)
{
    brix_opts options = execution->run->opts;
    brix_conn connection;
    brix_status status;
    ClientLoginRequest login;
    const uint8_t zero_sid[2] = { 0, 0 };
    uint16_t wire_status = kXR_error;
    uint16_t sid;
    uint8_t *body = NULL;
    uint32_t length = 0;
    brix_resp_out output = { &wire_status, &body, &length };
    char security[256];
    size_t security_length;
    int advertised = 0;

    options.capture = NULL;
    options.no_retry = 1;
    brix_status_clear(&status);
    if (brix_connect_no_login(&connection, url, &options, &status) != 0)
        return 0;
    xrd_pack_login_request(&login, zero_sid, 1, "conform", kXR_ver005);
    if (brix_send(&connection, &login, NULL, &sid, &status) == 0
        && brix_recv(&connection, sid, &output, &status) == 0
        && wire_status == kXR_ok && length > BRIX_SESSION_ID_LEN) {
        security_length = length - BRIX_SESSION_ID_LEN;
        if (security_length >= sizeof(security))
            security_length = sizeof(security) - 1;
        memcpy(security, body + BRIX_SESSION_ID_LEN, security_length);
        security[security_length] = '\0';
        advertised = brix_sec_proto_advertised(security, "ztn", NULL, 0);
    }
    free(body);
    brix_close(&connection);
    return advertised;
}

static token_observation
observe_fixture(xrd_conform_execution *execution,
    const xrd_conform_token_fixture *fixture)
{
    token_observation observation = { 0, 0, 0 };
    brix_opts options = execution->run->opts;
    brix_url url;
    brix_conn connection;
    brix_status status;

    brix_status_clear(&status);
    if (brix_endpoint_parse(fixture->target, &url, &status) != 0
        || (url.scheme != XRDC_SCHEME_ROOT
            && url.scheme != XRDC_SCHEME_ROOTS)
        || !advertises_ztn(execution, &url)) return observation;
    options.capture = NULL;
    options.no_retry = 1;
    options.auth_force = "ztn";
    if (brix_connect(&connection, &url, &options, &status) == 0) {
        observation.available = 1;
        observation.accepted = 1;
        brix_close(&connection);
        return observation;
    }
    observation.available = status.kxr > 0;
    observation.kxr = status.kxr;
    return observation;
}

static void
grade_one(xrd_conform_execution *execution, const char *id,
    const char *kind)
{
    const xrd_conform_token_fixture *fixture = fixture_for(execution->run,
        kind);
    token_observation observation;

    if (fixture == NULL) return;
    observation = observe_fixture(execution, fixture);
    if (!observation.available) {
        xrd_conform_result_set(execution, id,
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-unavailable:token-claim-negative", NULL, kind);
        return;
    }
    xrd_conform_result_set(execution, id,
        !observation.accepted && observation.kxr == kXR_AuthFailed
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        !observation.accepted && observation.kxr == kXR_AuthFailed
            ? "invalid-token-claim-returned-AuthFailed"
            : "invalid-token-claim-was-accepted-or-misclassified",
        "kXR_AuthFailed", kind);
}

static void
grade_time_pair(xrd_conform_execution *execution)
{
    const xrd_conform_token_fixture *expired = fixture_for(execution->run,
        "expired");
    const xrd_conform_token_fixture *future = fixture_for(execution->run,
        "not-yet-valid");
    token_observation left, right;

    if (expired == NULL || future == NULL) return;
    left = observe_fixture(execution, expired);
    right = observe_fixture(execution, future);
    if (!left.available || !right.available) {
        xrd_conform_result_set(execution, "LOG-023",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-unavailable:token-time-negatives", NULL, NULL);
        return;
    }
    xrd_conform_result_set(execution, "LOG-023",
        !left.accepted && !right.accepted
            && left.kxr == kXR_AuthFailed && right.kxr == kXR_AuthFailed
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        !left.accepted && !right.accepted
            && left.kxr == kXR_AuthFailed && right.kxr == kXR_AuthFailed
            ? "expired-and-future-tokens-returned-AuthFailed"
            : "token-time-bound-was-accepted-or-misclassified",
        "expired=AuthFailed not-yet-valid=AuthFailed", NULL);
}

void
xrd_conform_probe_token_fixtures(xrd_conform_execution *execution)
{
    grade_one(execution, "LOG-022", "audience");
    grade_time_pair(execution);
    grade_one(execution, "LOG-024", "issuer");
}
