/* Phase-118 ROOT login, session-id quality and lifecycle probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"
#include "protocols/root/protocol/codec/wire_codec.h"
#include "protocols/root/protocol/sec_protocol.h"

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
active(xrd_conform_execution *execution, const char *id)
{
    brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static void
grade_active(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const char *failure)
{
    if (!active(execution, id)) return;
    grade(execution, id, pass, success, failure);
}

static int
connect_aux(xrd_conform_execution *execution, const brix_url *url,
    brix_conn *connection, brix_status *status)
{
    brix_opts opts = execution->run->opts;

    opts.capture = NULL;
    brix_status_clear(status);
    return brix_connect(connection, url, &opts, status);
}

static int
connect_no_login(xrd_conform_execution *execution, const brix_url *url,
    brix_conn *connection, brix_status *status)
{
    brix_opts opts = execution->run->opts;

    opts.capture = NULL;
    brix_status_clear(status);
    return brix_connect_no_login(connection, url, &opts, status);
}

static int
request(xrd_conform_execution *execution, brix_conn *connection,
    ClientRequestHdr *header, const void *payload, uint16_t *wire_status,
    brix_status *status)
{
    uint16_t sid;
    uint8_t *body = NULL;
    uint32_t length = 0;
    brix_resp_out output = { wire_status, &body, &length };
    char reason[64];
    int rc;

    if (!xrd_conform_reserve(execution, sizeof(*header), reason,
            sizeof(reason))) return -2;
    brix_status_clear(status);
    if (brix_send(connection, header, payload, &sid, status) != 0) return -1;
    rc = brix_recv(connection, sid, &output, status);
    free(body);
    return rc;
}

static int
login_with_name(xrd_conform_execution *execution, const brix_url *url,
    const char *username)
{
    brix_conn connection;
    brix_status status;
    ClientLoginRequest login;
    const uint8_t sid[2] = { 0, 0 };
    uint16_t wire_status = kXR_error;
    int pass = 0;

    if (connect_no_login(execution, url, &connection, &status) != 0) return 0;
    xrd_pack_login_request(&login, sid, 1, username,
        (uint8_t) (kXR_ver005 | kXR_asyncap));
    if (request(execution, &connection, (ClientRequestHdr *) &login, NULL,
            &wire_status, &status) == 0)
        pass = wire_status == kXR_ok;
    brix_close(&connection);
    return pass;
}

static int
session_ids_unique(const uint8_t ids[64][BRIX_SESSION_ID_LEN], size_t count)
{
    size_t left;
    size_t right;

    for (left = 0; left < count; left++)
        for (right = left + 1; right < count; right++)
            if (memcmp(ids[left], ids[right], BRIX_SESSION_ID_LEN) == 0)
                return 0;
    return 1;
}

static void
probe_session_ids(xrd_conform_execution *execution, const brix_url *url,
    const brix_conn *primary)
{
    uint8_t ids[64][BRIX_SESSION_ID_LEN];
    brix_conn connection;
    brix_status status;
    size_t count = 0;
    size_t index;
    int unique;
    int increasing = 1;
    int decreasing = 1;
    int shared_prefix = 1;
    int malformed_length = primary->login_body_len < BRIX_SESSION_ID_LEN;

    memcpy(ids[count++], primary->sessid, BRIX_SESSION_ID_LEN);
    while (count < 64 && connect_aux(execution, url, &connection, &status) == 0) {
        memcpy(ids[count++], connection.sessid, BRIX_SESSION_ID_LEN);
        brix_close(&connection);
    }
    if (strstr(status.msg, "login reply too short") != NULL)
        malformed_length = 1;
    for (index = 1; index < count; index++) {
        int order = memcmp(ids[index - 1], ids[index], BRIX_SESSION_ID_LEN);

        if (order >= 0) increasing = 0;
        if (order <= 0) decreasing = 0;
        if (memcmp(ids[0], ids[index], 8) != 0) shared_prefix = 0;
    }
    unique = session_ids_unique(ids, count);
    grade(execution, "LOG-001", count > 0 && !malformed_length,
        "session-id-is-16-bytes",
        "session-id-missing");
    grade(execution, "LOG-002", count >= 2 && unique,
        "independent-session-ids-differ", "duplicate-session-id");
    grade(execution, "LOG-003", count == 64 && unique && !increasing
        && !decreasing && !shared_prefix, "session-ids-pass-quality-checks",
        count == 64 ? "predictable-or-low-entropy-session-ids"
                    : "session-id-sample-incomplete");
}

static void
probe_login_shapes(xrd_conform_execution *execution, const brix_url *url)
{
    int short_name = login_with_name(execution, url, "a");
    int full_name = login_with_name(execution, url, "12345678");

    grade(execution, "LOG-007", short_name && full_name,
        "short-and-full-usernames-accepted", "username-shape-refused");
}

static void
probe_prelogin_auth(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn connection;
    brix_status status;
    ClientAuthRequest auth;
    uint16_t wire_status = kXR_ok;
    int rc = -2;

    if (connect_no_login(execution, url, &connection, &status) == 0) {
        memset(&auth, 0, sizeof(auth));
        auth.requestid = htons(kXR_auth);
        memcpy(auth.credtype, "bad", 3);
        rc = request(execution, &connection, (ClientRequestHdr *) &auth, NULL,
            &wire_status, &status);
        brix_close(&connection);
    }
    grade(execution, "LOG-013", rc == -1,
        "prelogin-auth-refused", "prelogin-auth-accepted");
}

static void
probe_second_login(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn connection;
    brix_status status;
    ClientLoginRequest login;
    const uint8_t sid[2] = { 0, 0 };
    uint16_t wire_status = kXR_ok;
    int rc = -2;

    if (connect_aux(execution, url, &connection, &status) == 0) {
        xrd_pack_login_request(&login, sid, 2, "again", kXR_ver005);
        rc = request(execution, &connection, (ClientRequestHdr *) &login, NULL,
            &wire_status, &status);
        brix_close(&connection);
    }
    grade(execution, "LOG-014", rc == -1,
        "second-login-refused", "second-login-reidentified-session");
}

static int
send_endsess(xrd_conform_execution *execution, brix_conn *connection,
    const uint8_t sessid[BRIX_SESSION_ID_LEN])
{
    ClientEndsessRequest endsess;
    uint16_t wire_status = kXR_error;
    brix_status status;

    memset(&endsess, 0, sizeof(endsess));
    endsess.requestid = htons(kXR_endsess);
    memcpy(endsess.sessid, sessid, BRIX_SESSION_ID_LEN);
    return request(execution, connection, (ClientRequestHdr *) &endsess, NULL,
        &wire_status, &status) == 0 && wire_status == kXR_ok;
}

static int
session_can_stat(brix_conn *connection, const char *path)
{
    brix_statinfo info;
    brix_status status;

    brix_status_clear(&status);
    if (brix_stat(connection, path, &info, &status) == 0) return 1;
    return status.kxr != kXR_NotAuthorized;
}

static void
probe_endsess(xrd_conform_execution *execution, const brix_url *url)
{
    brix_conn first, second;
    brix_status status;
    uint8_t unknown[BRIX_SESSION_ID_LEN];
    int current = 0;
    int foreign = 0;
    int random_noop = 0;

    memset(unknown, 0xa5, sizeof(unknown));
    if (connect_aux(execution, url, &first, &status) == 0) {
        current = send_endsess(execution, &first, first.sessid)
            && !session_can_stat(&first, url->path);
        brix_close(&first);
    }
    if (connect_aux(execution, url, &first, &status) == 0
        && connect_aux(execution, url, &second, &status) == 0) {
        foreign = send_endsess(execution, &first, second.sessid)
            && session_can_stat(&first, url->path);
        random_noop = send_endsess(execution, &first, unknown)
            && session_can_stat(&first, url->path);
        brix_close(&second);
        brix_close(&first);
    }
    grade_active(execution, "LOG-018", current, "current-session-ended",
        "current-session-survived-endsess");
    grade_active(execution, "ENV-003", current, "current-session-ended",
        "current-session-survived-endsess");
    grade_active(execution, "LOG-019", foreign,
        "foreign-cleanup-preserved-carrier",
        "foreign-cleanup-deauthenticated-carrier");
    grade_active(execution, "ENV-004", foreign,
        "foreign-cleanup-preserved-carrier",
        "foreign-cleanup-deauthenticated-carrier");
    grade_active(execution, "LOG-020", random_noop, "unknown-session-was-noop",
        "unknown-session-acted-as-wildcard");
}

static void
skip_absent_security(xrd_conform_execution *execution,
    const brix_conn *primary)
{
    static const char *const ids[] = {
        "LOG-004", "LOG-005", "LOG-006", "LOG-009", "LOG-010", "LOG-011",
        "LOG-012", "LOG-015", "LOG-016", "LOG-017", "LOG-021", "LOG-022",
        "LOG-023", "LOG-024"
    };
    size_t index;

    if (primary->sec_list[0] != '\0') return;
    for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++)
        xrd_conform_result_set(execution, ids[index],
            BRIX_CONFORM_VERDICT_SKIPPED, "claim-absent:security-mechanism",
            NULL, NULL);
    for (index = 1; index <= 10; index++) {
        char id[16];

        snprintf(id, sizeof(id), "SIG-%03zu", index);
        xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_SKIPPED,
            "claim-absent:request-signing", NULL, NULL);
    }
}

static int
auth_fixture_completes(xrd_conform_execution *execution,
    const xrd_conform_auth_fixture *fixture)
{
    brix_opts opts = execution->run->opts;
    brix_url url;
    brix_conn connection;
    brix_status status;
    int complete = 0;

    brix_status_clear(&status);
    if (brix_endpoint_parse(fixture->target, &url, &status) != 0
        || (url.scheme != XRDC_SCHEME_ROOT && url.scheme != XRDC_SCHEME_ROOTS))
        return 0;
    opts.capture = NULL;
    opts.auth_force = fixture->protocol;
    if (brix_connect(&connection, &url, &opts, &status) == 0) {
        complete = connection.diag.chosen_auth != NULL
            && strcmp(connection.diag.chosen_auth, fixture->protocol) == 0
            && brix_sec_proto_advertised(connection.sec_list,
                fixture->protocol, NULL, 0);
        brix_close(&connection);
    }
    return complete;
}

/* WHAT: Reconcile the login security list with explicit working endpoints.
 * WHY: Advertising a mechanism that no client can complete is a false claim;
 *      silently probing only the preferred mechanism would miss that defect.
 * HOW: Grade the primary list shape, require an explicit fixture for every
 *      advertised name, force that protocol on its fixture, and verify the
 *      authentication driver records the same completed mechanism. */
static void
probe_security_claims(xrd_conform_execution *execution,
    const brix_conn *primary)
{
    size_t index;
    size_t complete = 0;
    char received[96];
    int covered;

    grade_active(execution, "LOG-004", strstr(primary->sec_list, "&P=") != NULL,
        "security-continuation-names-mechanism",
        "security-continuation-names-no-mechanism");
    if (!active(execution, "LOG-005")) return;
    if (execution->run->auth_fixture_count == 0) {
        xrd_conform_result_set(execution, "LOG-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:advertised-auth-protocols", NULL, NULL);
        return;
    }
    covered = xrd_conform_auth_fixtures_cover(execution->run,
        primary->sec_list);
    for (index = 0; index < execution->run->auth_fixture_count; index++)
        if (auth_fixture_completes(execution,
                &execution->run->auth_fixtures[index])) complete++;
    snprintf(received, sizeof(received), "protocols=%zu complete=%zu covered=%d",
        execution->run->auth_fixture_count, complete, covered);
    xrd_conform_result_set(execution, "LOG-005",
        covered && complete == execution->run->auth_fixture_count
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        covered && complete == execution->run->auth_fixture_count
            ? "all-advertised-auth-protocols-complete"
            : "advertised-auth-protocol-false-or-uncovered",
        "every advertised protocol has a forced successful fixture", received);
}

/* WHAT: Decide whether the protocol trailer claims request signing is needed.
 * WHY: A security mechanism can be advertised while every signing requirement
 *      remains disabled; that endpoint must claim-skip SIG, not leave ten
 *      misleading probe-not-executed rows.
 * HOW: Accept either a non-zero global level or a non-ignore secvec entry,
 *      after bounding the trailer against the captured protocol body. */
static int
signing_claimed(const brix_conn *primary)
{
    const uint8_t *body = primary->protocol_body;
    size_t count;
    size_t index;

    if (primary->protocol_body_len < 14 || body[8] != 'S') return 0;
    if (body[12] != 0) return 1;
    count = body[13];
    if (count > (primary->protocol_body_len - 14U) / 2U) return 0;
    for (index = 0; index < count; index++)
        if (body[15U + index * 2U] != 0) return 1;
    return 0;
}

static void
set_signature_family(xrd_conform_execution *execution,
    brix_conform_verdict verdict, const char *reason)
{
    size_t index;

    for (index = 1; index <= 10; index++) {
        char id[16];

        snprintf(id, sizeof(id), "SIG-%03zu", index);
        xrd_conform_result_set(execution, id, verdict, reason, NULL, NULL);
    }
}

static void
set_if_pending(xrd_conform_execution *execution, const char *id,
    brix_conform_verdict verdict, const char *reason)
{
    brix_conform_result *row = xrd_conform_result_find(execution, id);

    if (row == NULL || row->verdict != BRIX_CONFORM_VERDICT_INCONCLUSIVE
        || strcmp(row->reason, "probe-not-executed") != 0) return;
    xrd_conform_result_set(execution, id, verdict, reason, NULL, NULL);
}

static void
finalize_mechanism_specific_rows(xrd_conform_execution *execution,
    const brix_conn *primary)
{
    static const char *const gsi_ids[] = {
        "LOG-009", "LOG-010", "LOG-011", "LOG-012"
    };
    static const char *const token_ids[] = {
        "LOG-022", "LOG-023", "LOG-024"
    };
    int have_gsi = brix_sec_proto_advertised(primary->sec_list, "gsi",
        NULL, 0);
    int have_ztn = brix_sec_proto_advertised(primary->sec_list, "ztn",
        NULL, 0);
    int have_ztn_fixture = 0;
    int working_ztn_fixture = 0;
    size_t index;

    for (index = 0; index < sizeof(gsi_ids) / sizeof(gsi_ids[0]); index++)
        set_if_pending(execution, gsi_ids[index],
            have_gsi ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                     : BRIX_CONFORM_VERDICT_SKIPPED,
            have_gsi ? "fixture-required:gsi-auth-transcript"
                     : "claim-absent:gsi");
    for (index = 0; index < execution->run->auth_fixture_count; index++) {
        const xrd_conform_auth_fixture *fixture =
            &execution->run->auth_fixtures[index];

        if (strcmp(fixture->protocol, "ztn") != 0) continue;
        have_ztn_fixture = 1;
        working_ztn_fixture = auth_fixture_completes(execution, fixture);
    }
    if (have_ztn)
        grade_active(execution, "LOG-021", 1,
            "bearer-auth-advertised-as-ztn", NULL);
    else if (have_ztn_fixture && working_ztn_fixture)
        grade_active(execution, "LOG-021", 0,
            "bearer-auth-advertised-as-ztn",
            "working-bearer-fixture-not-advertised-as-ztn");
    else if (have_ztn_fixture)
        set_if_pending(execution, "LOG-021", BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "ztn-fixture-did-not-complete");
    else
        set_if_pending(execution, "LOG-021", BRIX_CONFORM_VERDICT_SKIPPED,
            "claim-absent:ztn");
    for (index = 0; index < sizeof(token_ids) / sizeof(token_ids[0]); index++)
        set_if_pending(execution, token_ids[index],
            have_ztn ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                     : BRIX_CONFORM_VERDICT_SKIPPED,
            have_ztn ? "fixture-required:token-claim-negative"
                     : "claim-absent:ztn");
}

/* WHAT: Complete one legacy GSI exchange and grade its captured transcript.
 * WHY: LOG-009..012 describe the pre-signed-DH wire variant and cannot be
 *      inferred from source or from a modern signed-DH session.
 * HOW: Force only this isolated connection to version 10300, then consume the
 *      credential-free diagnostic facts recorded by the native GSI driver. */
static void
probe_gsi_transcript(xrd_conform_execution *execution, const brix_url *url)
{
    static const char *const ids[] = {
        "LOG-009", "LOG-010", "LOG-011", "LOG-012"
    };
    brix_opts options = execution->run->opts;
    brix_conn connection;
    brix_status status;
    size_t index;

    options.capture = NULL;
    options.auth_force = "gsi";
    options.gsi_version = 10300;
    brix_status_clear(&status);
    if (brix_connect(&connection, url, &options, &status) != 0) {
        for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++)
            set_if_pending(execution, ids[index],
                BRIX_CONFORM_VERDICT_INCONCLUSIVE,
                "gsi-legacy-transcript-unavailable");
        return;
    }
    grade_active(execution, "LOG-009", connection.gsi_login_challenge_text,
        "gsi-login-challenge-is-plain-text",
        "gsi-login-challenge-is-binary");
    grade_active(execution, "LOG-010", connection.gsi_server_dh_plain,
        "gsi-puk-carried-dh-public",
        "gsi-puk-did-not-carry-dh-public");
    grade_active(execution, "LOG-011", connection.gsi_unpadded_secret,
        "legacy-gsi-derived-unpadded-secret",
        "legacy-gsi-padding-rule-diverged");
    grade_active(execution, "LOG-012", connection.gsi_server_key_persisted,
        "server-dh-key-survived-auth-round-trips",
        "server-dh-key-continuity-unproven");
    brix_close(&connection);
}

/* WHAT: Exercise the signed success and unsigned-refusal sides of the policy.
 * WHY: SIG-001/002 are observable with the production client once GSI retained
 *      a session cipher; accepting an unsigned request would defeat the claim.
 * HOW: Use isolated authenticated sessions.  The positive keeps automatic
 *      signing enabled; the negative disables only the client-side prefix and
 *      requires the protocol's signature-verification error spelling. */
static void
probe_signature_baseline(xrd_conform_execution *execution,
    const brix_url *url)
{
    brix_conn connection;
    brix_statinfo info;
    brix_status status;
    int positive = 0;
    int negative = 0;

    if (connect_aux(execution, url, &connection, &status) == 0) {
        if (connection.signing_active)
            positive = brix_stat(&connection, url->path, &info, &status) == 0;
        brix_close(&connection);
    }
    if (connect_aux(execution, url, &connection, &status) == 0) {
        if (connection.signing_active) {
            connection.signing_active = 0;
            brix_status_clear(&status);
            negative = brix_stat(&connection, url->path, &info, &status) != 0
                && status.kxr == kXR_SigVerErr;
        }
        brix_close(&connection);
    }
    grade_active(execution, "SIG-001", negative,
        "unsigned-required-request-returned-sigver-error",
        "unsigned-required-request-not-classified-as-sigver-error");
    grade_active(execution, "SIG-002", positive,
        "correctly-signed-request-served",
        "correctly-signed-request-refused");
}

void
xrd_conform_probe_login(xrd_conform_execution *execution, const brix_url *url,
    const brix_conn *primary)
{
    int login_active = xrd_conform_family_active(execution, "LOG");
    int signature_active = xrd_conform_family_active(execution, "SIG");
    int envelope_active = xrd_conform_family_active(execution, "ENV");

    if (!login_active && !signature_active && !envelope_active) return;
    if (login_active || signature_active) skip_absent_security(execution, primary);
    if (signature_active && primary->sec_list[0] != '\0'
        && !signing_claimed(primary))
        set_signature_family(execution, BRIX_CONFORM_VERDICT_SKIPPED,
            "claim-absent:request-signing");
    else if (signature_active && signing_claimed(primary)) {
        if (primary->signing_active) {
            probe_signature_baseline(execution, url);
            xrd_conform_probe_sigver_active(execution, url);
            xrd_conform_probe_sigver_bound(execution, url);
            if (primary->protocol_body_len < 14
                || primary->protocol_body[8] != 'S'
                || !(primary->protocol_body[11] & kXR_secOFrce))
            {
                xrd_conform_result_set(execution, "SIG-010",
                    BRIX_CONFORM_VERDICT_SKIPPED,
                    "claim-absent:secOFrce", NULL, NULL);
            } else {
                xrd_conform_probe_sigver_unencrypted(execution, url);
            }
        } else {
            set_signature_family(execution, BRIX_CONFORM_VERDICT_INCONCLUSIVE,
                "signing-claim-present:no-session-signing-key");
        }
    }
    if (!login_active && !envelope_active) return;
    if (login_active && (active(execution, "LOG-004")
            || active(execution, "LOG-005")))
        probe_security_claims(execution, primary);
    if (login_active && primary->sec_list[0] != '\0')
        xrd_conform_probe_login_auth_negatives(execution, url);
    if (login_active && brix_sec_proto_advertised(primary->sec_list, "gsi",
            NULL, 0))
        probe_gsi_transcript(execution, url);
    if (login_active) xrd_conform_probe_login_abilities(execution, url);
    if (active(execution, "LOG-001") || active(execution, "LOG-002")
        || active(execution, "LOG-003"))
        probe_session_ids(execution, url, primary);
    if (active(execution, "LOG-007")) probe_login_shapes(execution, url);
    if (active(execution, "LOG-013")) probe_prelogin_auth(execution, url);
    if (active(execution, "LOG-014")) probe_second_login(execution, url);
    if (active(execution, "LOG-018") || active(execution, "LOG-019")
        || active(execution, "LOG-020") || active(execution, "ENV-003")
        || active(execution, "ENV-004")) probe_endsess(execution, url);
    if (!login_active) return;
    finalize_mechanism_specific_rows(execution, primary);
    set_if_pending(execution, "LOG-008", BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        "fixture-required:identity-oracle");
}
