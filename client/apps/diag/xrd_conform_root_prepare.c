/* Phase-118 scratch-safe kXR_prepare and kXR_QPrep probes. */
#include "xrd_conform_probe_helpers.h"




static void
trim_request_id(char *request_id)
{
    size_t length = strlen(request_id);

    while (length > 0 && (request_id[length - 1] == '\n'
            || request_id[length - 1] == '\r'))
        request_id[--length] = '\0';
}

static int
qprep_status_valid(const char *reply, const char *path)
{
    const char *cursor = reply;

    while (cursor != NULL && *cursor != '\0') {
        const char *end = strchr(cursor, '\n');
        size_t length = end == NULL ? strlen(cursor) : (size_t) (end - cursor);

        if (length >= 3 && strchr("AMqsf", cursor[0]) != NULL
            && cursor[1] == ' ' && strlen(path) == length - 2
            && memcmp(cursor + 2, path, length - 2) == 0) return 1;
        cursor = end == NULL ? NULL : end + 1;
    }
    return 0;
}

/* WHAT: Ensure a QPrep id is useful only in the session that created it.
 * WHY: Durable staging ids must not become a cross-session namespace oracle.
 * HOW: Query the id on a fresh connection and reject any disclosure of path. */
static int
request_id_is_session_scoped(xrd_conform_execution *execution,
    const char *request_id, const char *path, brix_status *status)
{
    char reply[1024] = "";
    brix_url url;
    brix_conn auxiliary;
    brix_opts options = execution->run->opts;
    int safe = 0;

    options.capture = NULL;
    if (!xrd_conform_reserve_zero_status(execution, status)
        || brix_endpoint_parse(execution->target, &url, status) != 0
        || brix_connect(&auxiliary, &url, &options, status) != 0)
        return 0;
    if (xrd_conform_reserve_zero_status(execution, status)) {
        brix_status_clear(status);
        safe = brix_query(&auxiliary, kXR_QPrep, request_id, reply,
                sizeof(reply), status) != 0 || strstr(reply, path) == NULL;
    }
    brix_close(&auxiliary);
    return safe;
}

/* WHAT: Compare cancellation of a foreign live id with an absent id.
 * WHY: Different wire results disclose request existence or ownership.
 * HOW: Issue both cancels in one fresh session and compare result classes. */
static int
cancel_is_non_enumerating(xrd_conform_execution *execution,
    const char *request_id, brix_status *status)
{
    static const char absent_id[] = "brix-conform-absent-request-id";
    const char *real[] = { request_id };
    const char *absent[] = { absent_id };
    char reply[256];
    brix_status real_status;
    brix_status absent_status;
    brix_url url;
    brix_conn auxiliary;
    brix_opts options = execution->run->opts;
    int real_rc;
    int absent_rc;

    options.capture = NULL;
    if (!xrd_conform_reserve_zero_status(execution, status)
        || brix_endpoint_parse(execution->target, &url, status) != 0
        || brix_connect(&auxiliary, &url, &options, status) != 0)
        return 0;
    brix_status_clear(&real_status);
    real_rc = xrd_conform_reserve_zero_status(execution, &real_status)
        ? brix_prepare(&auxiliary, real, 1, kXR_cancel, 0, 0,
            reply, sizeof(reply), &real_status) : -1;
    brix_status_clear(&absent_status);
    absent_rc = xrd_conform_reserve_zero_status(execution, &absent_status)
        ? brix_prepare(&auxiliary, absent, 1, kXR_cancel, 0, 0,
            reply, sizeof(reply), &absent_status) : -1;
    brix_close(&auxiliary);
    if (real_rc == absent_rc
        && (real_rc == 0 || real_status.kxr == absent_status.kxr)) return 1;
    brix_status_set(status, XRDC_EPROTO, real_status.kxr,
        "foreign cancel rc=%d/kxr=%d differs from absent rc=%d/kxr=%d",
        real_rc, real_status.kxr, absent_rc, absent_status.kxr);
    return 0;
}

static int
cancel_twice(xrd_conform_execution *execution, brix_conn *connection,
    const char *request_id, brix_status *status)
{
    const char *paths[] = { request_id };
    char reply[256];
    int first_ok;
    int second_ok;

    brix_status_clear(status);
    first_ok = xrd_conform_reserve_zero_status(execution, status)
        && brix_prepare(connection, paths, 1, kXR_cancel, 0, 0,
            reply, sizeof(reply), status) == 0;
    brix_status_clear(status);
    second_ok = xrd_conform_reserve_zero_status(execution, status)
        && brix_prepare(connection, paths, 1, kXR_cancel, 0, 0,
            reply, sizeof(reply), status) == 0;
    return first_ok && second_ok;
}

static void
grade_qprep(xrd_conform_execution *execution, brix_conn *connection,
    const char *request_id, const char *path, brix_status *status)
{
    char reply[2048] = "";
    int query_ok = 0;
    int session_scoped;

    if (!xrd_conform_row_active(execution, "QRY-011")) return;
    if (xrd_conform_reserve_zero_status(execution, status)) {
        brix_status_clear(status);
        query_ok = brix_query(connection, kXR_QPrep, request_id, reply,
                sizeof(reply), status) == 0
            && qprep_status_valid(reply, path);
    }
    session_scoped = request_id_is_session_scoped(execution, request_id,
        path, status);
    xrd_conform_grade_wire_status(execution, "QRY-011", query_ok && session_scoped,
        "qprep-status-agreed-and-session-scoped",
        query_ok ? "qprep-request-id-cross-session-visible"
                 : "qprep-status-disagreed-with-prepare", status);
}

static void
grade_prepare_cancel(xrd_conform_execution *execution,
    brix_conn *connection, const char *request_id, brix_status *status)
{
    int cancel_ok;
    int cancel_scoped;

    if (!xrd_conform_row_active(execution, "PRP-002")) return;
    cancel_ok = cancel_twice(execution, connection, request_id, status);
    cancel_scoped = cancel_is_non_enumerating(execution, request_id, status);
    xrd_conform_grade_wire_status(execution, "PRP-002", cancel_ok && cancel_scoped,
        "cancel-accepted-idempotent-and-non-enumerating",
        cancel_ok ? "cancel-discloses-foreign-request-existence"
                  : "cancel-not-idempotent", status);
}

static void
probe_live_prepare(xrd_conform_execution *execution, brix_conn *connection,
    const char *path)
{
    const char *paths[] = { path };
    char request_id[256] = "";
    brix_status status;
    int prepare_ok;

    if (!xrd_conform_row_active(execution, "PRP-001")
        && !xrd_conform_row_active(execution, "PRP-002")
        && !xrd_conform_row_active(execution, "QRY-011")) return;
    brix_status_clear(&status);
    prepare_ok = xrd_conform_reserve_zero_status(execution, &status)
        && brix_prepare(connection, paths, 1, kXR_stage, 0, 0,
            request_id, sizeof(request_id), &status) == 0;
    trim_request_id(request_id);
    if (xrd_conform_row_active(execution, "PRP-001"))
        xrd_conform_grade_wire_status(execution, "PRP-001", prepare_ok && request_id[0] != '\0',
            "prepare-returned-request-id", "prepare-id-missing", &status);
    if (!prepare_ok || request_id[0] == '\0') return;
    grade_qprep(execution, connection, request_id, path, &status);
    grade_prepare_cancel(execution, connection, request_id, &status);
}

static void
probe_missing_prepare(xrd_conform_execution *execution, brix_conn *connection,
    const char *path)
{
    char missing[XRDC_PATH_MAX];
    char reply[256];
    const char *paths[] = { missing };
    brix_status status;
    int rc;

    if (!xrd_conform_row_active(execution, "PRP-005")
        || (size_t) snprintf(missing, sizeof(missing), "%s.__prepare_missing__",
            path) >= sizeof(missing)) return;
    brix_status_clear(&status);
    rc = xrd_conform_reserve_zero_status(execution, &status)
        ? brix_prepare(connection, paths, 1, kXR_stage, 0, 0, reply,
            sizeof(reply), &status) : -1;
    xrd_conform_grade_wire_status(execution, "PRP-005", rc != 0,
        "missing-prepare-refused-at-request-time",
        "missing-prepare-silently-accepted", &status);
}

/* WHAT: Aim a TCP notification at the reserved, unreachable port one.
 * WHY: A callback failure must not hold the prepare response or poison the
 *      session used by later requests.
 * HOW: Request notification for a resident scratch object, then prove the
 *      same connection remains synchronized with an immediate stat. */
static void
probe_unreachable_notify(xrd_conform_execution *execution,
    brix_conn *connection, const char *path)
{
    const char *paths[] = { path };
    char reply[256] = "";
    brix_statinfo info;
    brix_status status;
    int prepare_ok;
    int stat_ok = 0;

    if (!xrd_conform_row_active(execution, "PRP-006")) return;
    brix_status_clear(&status);
    prepare_ok = xrd_conform_reserve_zero_status(execution, &status)
        && brix_prepare_port(connection, paths, 1,
            kXR_stage | kXR_notify | kXR_usetcp, 0, 0, 1,
            reply, sizeof(reply), &status) == 0;
    memset(&info, 0, sizeof(info));
    if (prepare_ok && xrd_conform_reserve_zero_status(execution, &status)) {
        brix_status_clear(&status);
        stat_ok = brix_stat(connection, path, &info, &status) == 0;
    }
    xrd_conform_grade_wire_status(execution, "PRP-006", prepare_ok && stat_ok,
        "unreachable-notify-completed-and-session-reusable",
        prepare_ok ? "notify-poisoned-session" : "notify-request-did-not-complete",
        &status);
}

void
xrd_conform_probe_prepare(xrd_conform_execution *execution,
    brix_conn *connection, const char *path)
{
    if (!xrd_conform_family_active(execution, "PRP")
        && !xrd_conform_family_active(execution, "QRY")) return;
    probe_live_prepare(execution, connection, path);
    probe_missing_prepare(execution, connection, path);
    probe_unreachable_notify(execution, connection, path);
}
