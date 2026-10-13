/* Phase-118 read-only ROOT query and environment control probes. */
#include "xrd_conform_internal.h"

#include <arpa/inet.h>

void
xrd_conform_probe_fattr_support(xrd_conform_execution *execution,
    brix_conn *connection, const char *path)
{
    char names[4096];
    char reason[64];
    size_t names_len = 0;
    brix_status status;
    int rc;

    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    brix_status_clear(&status);
    rc = brix_fattr_list(connection, path, names, sizeof(names), &names_len,
        &status);
    xrd_conform_result_set(execution, "FAT-008",
        rc == 0 || status.kxr == kXR_Unsupported
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        rc == 0 ? "fattr-implemented"
                : status.kxr == kXR_Unsupported
                    ? "fattr-defined-unsupported"
                    : status.kxr == kXR_ServerError
                        ? "fattr-collapsed-to-server-error"
                        : "fattr-refused-before-capability-known",
        "implemented or kXR_Unsupported", status.msg);
}

/* ---- Reserve one control-plane exchange ----
 *
 * WHAT: Returns one when another request is within the configured ceiling.
 * WHY: Query/control probes must share the runner's hard resource envelope.
 * HOW: Charge a request with no response-body estimate through the common gate.
 */
static int
reserve_request(xrd_conform_execution *execution)
{
    char reason[64];

    return xrd_conform_reserve(execution, 0, reason, sizeof(reason));
}

/* ---- Remove terminal line separators from a query value ----
 *
 * WHAT: Returns the length after stripping trailing CR/LF bytes in place.
 * WHY: Servers differ only in whether the final Qconfig line has a newline.
 * HOW: Walk backward over CR/LF and terminate at the first content boundary.
 */
static size_t
trim_lines(char *value)
{
    size_t length = strlen(value);

    while (length > 0
        && (value[length - 1] == '\n' || value[length - 1] == '\r')) length--;
    value[length] = '\0';
    return length;
}

/* ---- Query one Qconfig value under the request ceiling ----
 *
 * WHAT: Returns zero with a normalized value, or -1 on ceiling/wire failure.
 * WHY: Multi-key ordering is compared against independently observed values.
 * HOW: Reserve, issue the typed query, then remove terminal line separators.
 */
static int
query_config(xrd_conform_execution *execution, brix_conn *connection,
    const char *keys, char *reply, size_t reply_size, brix_status *status)
{
    if (!reserve_request(execution)) return -1;
    brix_status_clear(status);
    if (brix_query(connection, kXR_Qconfig, keys, reply, reply_size, status)
        != 0) return -1;
    trim_lines(reply);
    return 0;
}

/* ---- Preserve the first unexpected optional-query result ----
 *
 * WHAT: Records one compact infotype, kXR code and bounded server message.
 * WHY: Later successful probes must not erase the operation that diverged.
 * HOW: Format only while the group is still passing and return false.
 */
static int
optional_failed(char failure[256], const char *name,
    const brix_status *status)
{
    snprintf(failure, 256, "%s: kXR=%d: %.200s", name, status->kxr,
        status->msg);
    return 0;
}

/* ---- Grade ordered multi-key Qconfig output ----
 *
 * WHAT: Exercises QRY-001 and QRY-014 with independently learned line values.
 * WHY: Counting lines alone cannot prove request order or unknown-key continuity.
 * HOW: Query each key alone, query the pair, and compare the exact composition.
 */
static void
probe_qconfig_order(xrd_conform_execution *execution, brix_conn *connection)
{
    char first[256], second[256], combined[512], expected[512];
    brix_status status;
    int ok;

    ok = query_config(execution, connection, "tpc", first, sizeof(first),
            &status) == 0
        && query_config(execution, connection, "role", second, sizeof(second),
            &status) == 0
        && query_config(execution, connection, "tpc role", combined,
            sizeof(combined), &status) == 0;
    if (ok) ok = (size_t) snprintf(expected, sizeof(expected), "%s\n%s",
        first, second) < sizeof(expected) && strcmp(combined, expected) == 0;
    xrd_conform_result_set(execution, "QRY-001",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "qconfig-lines-preserve-request-order"
           : "qconfig-line-order-or-count-mismatch",
        ok ? expected : NULL, ok ? combined : status.msg);
}

/* WHAT: Proves an unknown Qconfig key does not suppress a following known key.
 * WHY: Per-line errors must preserve the rest of a multi-key response.
 * HOW: Compare the combined response with two independent single-key replies. */
static void
probe_qconfig_unknown(xrd_conform_execution *execution, brix_conn *connection)
{
    char first[256], second[256], combined[512], expected[512];
    brix_status status;
    int ok;

    ok = query_config(execution, connection, "brix-conform-unknown", first,
            sizeof(first), &status) == 0
        && query_config(execution, connection, "role", second, sizeof(second),
            &status) == 0
        && query_config(execution, connection, "brix-conform-unknown role",
            combined, sizeof(combined), &status) == 0;
    if (ok) ok = first[0] != '\0'
        && (size_t) snprintf(expected, sizeof(expected), "%s\n%s", first,
            second) < sizeof(expected) && strcmp(combined, expected) == 0;
    xrd_conform_result_set(execution, "QRY-014",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "unknown-qconfig-key-preserves-known-lines"
           : "unknown-qconfig-key-disrupted-response",
        ok ? expected : NULL, ok ? combined : status.msg);
}

/* WHAT: Runs the two independent ordered Qconfig assertions.
 * WHY: Separate clause helpers keep the control runner below the CCN ceiling.
 * HOW: Invoke known-key ordering, then unknown-key continuity. */
static void
probe_qconfig_lines(xrd_conform_execution *execution, brix_conn *connection)
{
    probe_qconfig_order(execution, connection);
    probe_qconfig_unknown(execution, connection);
}

/* WHAT: Executes one path/string optional query.
 * WHY: All optional infotypes share the same success-or-unsupported contract.
 * HOW: Reserve, issue, and preserve the first unexpected failure. */
static int
optional_plain(xrd_conform_execution *execution, brix_conn *connection,
    uint16_t infotype, const char *argument, const char *name,
    char failure[256])
{
    char reply[512];
    brix_status status;
    int rc;

    if (!reserve_request(execution)) return -1;
    brix_status_clear(&status);
    rc = brix_query(connection, infotype, argument, reply, sizeof(reply),
        &status);
    if (rc == 0 || status.kxr == kXR_Unsupported) return 1;
    if (failure[0] != '\0') return 0;
    return optional_failed(failure, name, &status);
}

/* WHAT: Executes one handle-bound optional query.
 * WHY: Qvisa/Qopaqug require the handle request shape, not a path payload.
 * HOW: Reserve, issue through brix_query_file, and grade the common contract. */
static int
optional_file(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, uint16_t infotype, const char *name, char failure[256])
{
    char reply[512];
    brix_status status;
    int rc;

    if (!reserve_request(execution)) return -1;
    brix_status_clear(&status);
    rc = brix_query_file(connection, file, infotype, NULL, 0, reply,
        sizeof(reply), &status);
    if (rc == 0 || status.kxr == kXR_Unsupported) return 1;
    if (failure[0] != '\0') return 0;
    return optional_failed(failure, name, &status);
}

/* ---- Grade the optional extended query group ----
 *
 * WHAT: Exercises QRY-010 for visa and the three opaque query infotypes.
 * WHY: Optional operations must fail explicitly rather than as server faults.
 * HOW: Issue each typed query and accept success or kXR_Unsupported only.
 */
static void
probe_optional_queries(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const char *path)
{
    char failure[256] = "";
    int ok = 1;
    int rc;

    rc = optional_file(execution, connection, file, kXR_Qvisa, "Qvisa",
        failure);
    if (rc < 0) return;
    if (rc == 0) ok = 0;
    rc = optional_plain(execution, connection, kXR_Qopaque, "brix.conform",
        "Qopaque", failure);
    if (rc < 0) return;
    if (rc == 0 && ok) ok = 0;
    rc = optional_plain(execution, connection, kXR_Qopaquf, path, "Qopaquf",
        failure);
    if (rc < 0) return;
    if (rc == 0 && ok) ok = 0;
    rc = optional_file(execution, connection, file, kXR_Qopaqug, "Qopaqug",
        failure);
    if (rc < 0) return;
    if (rc == 0 && ok) ok = 0;
    xrd_conform_result_set(execution, "QRY-010",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "optional-queries-served-or-unsupported"
           : "optional-query-returned-unexpected-error",
        "success or kXR_Unsupported", ok ? NULL : failure);
}

/* ---- Grade unknown kXR_set handling ----
 *
 * WHAT: Exercises ENV-001 and records whether an unknown advisory key succeeds.
 * WHY: The stock protocol treats set as best-effort environmental advice.
 * HOW: Send a namespaced unknown command and require a successful typed reply.
 */
static void
probe_set_unknown(xrd_conform_execution *execution, brix_conn *connection)
{
    char reply[256];
    brix_status status;
    int ok;

    if (!reserve_request(execution)) return;
    brix_status_clear(&status);
    ok = brix_set_cmd(connection, "brix.conform.unknown=1", reply,
        sizeof(reply), &status) == 0;
    xrd_conform_result_set(execution, "ENV-001",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "unknown-set-key-accepted" : "unknown-set-key-refused",
        "kXR_ok", ok ? reply : status.msg);
}

/* WHAT: Exercise the retired gpfile opcode's defined compatibility answer.
 * WHY: Optional legacy verbs must not collapse into an internal server fault.
 * HOW: Send its zero-body request and accept service or kXR_Unsupported only. */
static void
probe_gpfile(xrd_conform_execution *execution, brix_conn *connection)
{
    ClientRequestHdr request;
    uint16_t wire_status = 0;
    uint16_t stream_id;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_resp_out response = { &wire_status, &body, &body_length };
    brix_status status;
    int rc;

    if (!reserve_request(execution)) return;
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_gpfile);
    xrdw_empty_req_pack(request.body);
    brix_status_clear(&status);
    rc = brix_send(connection, &request, NULL, &stream_id, &status);
    if (rc == 0) rc = brix_recv(connection, stream_id, &response, &status);
    free(body);
    execution->gpfile_state = rc == 0 ? 2
        : status.kxr == kXR_Unsupported ? 1 : -1;
    xrd_conform_result_set(execution, "ENV-005",
        rc == 0 || status.kxr == kXR_Unsupported
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : status.kxr == kXR_ServerError
                ? BRIX_CONFORM_VERDICT_DIVERGENT
                : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        rc == 0 ? "gpfile-implemented"
                : status.kxr == kXR_Unsupported
                    ? "gpfile-defined-unsupported"
                    : "gpfile-wrong-defined-error",
        "success or kXR_Unsupported", status.msg);
}

/* ---- Grade the safe metadata-query group ----
 *
 * WHAT: Exercises checksum-scan, xattr, stats and unknown-infotype semantics.
 * WHY: These query rows are remotely observable without changing target state.
 * HOW: Require stable response grammar and the specified unknown-type error.
 */
static void
probe_checksum_scan(xrd_conform_execution *execution,
    brix_conn *connection, const char *path)
{
    char reply[8192];
    brix_status status;
    int ok;

    if (!reserve_request(execution)) return;
    brix_status_clear(&status);
    ok = brix_query(connection, kXR_Qckscan, path, reply, sizeof(reply),
            &status) == 0
        && reply[0] != '\0' && strstr(reply, path) != NULL;
    xrd_conform_result_set(execution, "QRY-007",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "qckscan-returned-path-state" : "qckscan-response-invalid",
        "nonempty scan state naming target", ok ? reply : status.msg);
}

/* WHAT: Grades the target's returned xattr metadata grammar.
 * WHY: Qxattr success without the required fields is not useful evidence.
 * HOW: Require both stable file metadata keys in the typed response. */
static void
probe_query_xattr(xrd_conform_execution *execution, brix_conn *connection,
    const char *path)
{
    char reply[8192];
    brix_status status;
    int ok;

    if (!reserve_request(execution)) return;
    brix_status_clear(&status);
    ok = brix_query(connection, kXR_Qxattr, path, reply, sizeof(reply),
            &status) == 0
        && strstr(reply, "oss.type=") != NULL
        && strstr(reply, "oss.used=") != NULL;
    xrd_conform_result_set(execution, "QRY-009",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "qxattr-returned-file-metadata" : "qxattr-response-invalid",
        "oss.type and oss.used", ok ? reply : status.msg);
}

/* WHAT: Grades QStats as one complete statistics document.
 * WHY: A successful but truncated response must be reported divergent.
 * HOW: Require the documented opening and closing elements. */
static void
probe_query_stats(xrd_conform_execution *execution, brix_conn *connection)
{
    char reply[8192];
    brix_status status;
    int ok;

    if (!reserve_request(execution)) return;
    brix_status_clear(&status);
    ok = brix_query(connection, kXR_QStats, "a", reply, sizeof(reply),
            &status) == 0
        && strncmp(reply, "<statistics ", 12) == 0
        && strstr(reply, "</statistics>") != NULL;
    xrd_conform_result_set(execution, "QRY-012",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "qstats-document-framing-valid" : "qstats-response-invalid",
        "<statistics ...>...</statistics>", ok ? NULL : status.msg);
}

/* WHAT: Grades an unknown query infotype's exact refusal.
 * WHY: Defaulting an unknown type can expose unrelated query data.
 * HOW: Send UINT16_MAX and require kXR_ArgInvalid. */
static void
probe_unknown_query(xrd_conform_execution *execution, brix_conn *connection)
{
    char reply[8192];
    brix_status status;
    int ok;

    if (!reserve_request(execution)) return;
    brix_status_clear(&status);
    ok = brix_query(connection, UINT16_MAX, "", reply, sizeof(reply),
            &status) != 0
        && status.kxr == kXR_ArgInvalid;
    xrd_conform_result_set(execution, "QRY-013",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "unknown-query-type-refused" : "unknown-query-wrong-error",
        "kXR_ArgInvalid", status.msg);
}

/* WHAT: Runs the four independent non-mutating metadata queries.
 * WHY: Clause-local helpers keep each response grammar independently auditable.
 * HOW: Invoke scan, xattr, stats, then the unknown-type negative. */
static void
probe_metadata_queries(xrd_conform_execution *execution,
    brix_conn *connection, const char *path)
{
    probe_checksum_scan(execution, connection, path);
    probe_query_xattr(execution, connection, path);
    probe_query_stats(execution, connection);
    probe_unknown_query(execution, connection);
}

/* ---- Run safe ROOT control/query probes ----
 *
 * WHAT: Executes the non-mutating Qconfig, optional-query and set assertions.
 * WHY: Keeping control-plane work separate prevents the object probe growing.
 * HOW: Invoke the three independent bounded probe groups in ledger order.
 */
void
xrd_conform_probe_root_control(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path)
{
    probe_qconfig_lines(execution, connection);
    probe_optional_queries(execution, connection, file, path);
    probe_metadata_queries(execution, connection, path);
    probe_set_unknown(execution, connection);
    probe_gpfile(execution, connection);
}
