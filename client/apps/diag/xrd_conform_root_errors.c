/* Phase-118 externally observed errno-to-kXR fixture probes. */
#include "xrd_conform_internal.h"

typedef struct {
    const char *name;
    const char *clause;
    uint16_t    expected;
} error_fixture_spec;

typedef struct {
    int         present;
    int         failed;
    int         deterministic;
    int         readable;
    int         safe;
    uint16_t    code;
    char        message[128];
} error_fixture_observation;

/* WHAT: Return the immutable errno-fixture vocabulary and its row count.
 * WHY: The hard no-new-globals rule keeps even read-only tables owned by a
 *      function, while every parser/probe still shares one authoritative list.
 * HOW: Initialize one function-local constant array and return its base. */
static const error_fixture_spec *
error_specs(size_t *count)
{
    static const error_fixture_spec specs[] = {
        { "ENOENT", "ERR-001", kXR_NotFound },
    { "EINVAL", "ERR-002", kXR_ArgInvalid },
    { "EPERM", "ERR-003", kXR_NotAuthorized },
    { "EACCES", "ERR-004", kXR_NotAuthorized },
    { "EROFS", "ERR-005", kXR_fsReadOnly },
    { "EEXIST", "ERR-006", kXR_ItExists },
    { "ENOTEMPTY", "ERR-007", kXR_ItExists },
    { "EISDIR", "ERR-008", kXR_isDirectory },
    { "ENAMETOOLONG", "ERR-009", kXR_ArgTooLong },
    { "EIO", "ERR-010", kXR_IOError },
    { "ENOMEM", "ERR-011", kXR_NoMemory },
    { "ENOBUFS", "ERR-012", kXR_NoMemory },
    { "ENOSPC", "ERR-013", kXR_NoSpace },
    { "EDQUOT", "ERR-014", kXR_overQuota },
    { "ENOTSUP", "ERR-015", kXR_Unsupported },
    { "EBADF", "ERR-016", kXR_FileNotOpen },
    { "ETIMEDOUT", "ERR-017", kXR_ReqTimedOut },
    { "ETIME", "ERR-018", kXR_TimerExpired },
    { "ECANCELED", "ERR-019", kXR_Cancelled },
    { "ETXTBSY", "ERR-020", kXR_inProgress },
    { "EBADRQC", "ERR-021", kXR_InvalidRequest },
    { "ENOTBLK", "ERR-022", kXR_NotFile },
    { "ENODEV", "ERR-023", kXR_FSError },
    { "EFAULT", "ERR-024", kXR_ServerError },
    { "EDOM", "ERR-025", kXR_ChkSumErr },
    { "EILSEQ", "ERR-026", kXR_SigVerErr },
    { "ERANGE", "ERR-027", kXR_DecryptErr },
    { "EUSERS", "ERR-028", kXR_Overloaded },
    { "ENOATTR", "ERR-029", kXR_AttrNotFound },
    { "EPROTOTYPE", "ERR-030", kXR_TLSRequired },
    { "EADDRNOTAVAIL", "ERR-031", kXR_noReplicas },
    { "EAUTH", "ERR-032", kXR_AuthFailed },
    { "EIDRM", "ERR-033", kXR_Impossible },
    { "ENOTTY", "ERR-034", kXR_Conflict },
    { "ETOOMANYREFS", "ERR-035", kXR_TooManyErrs },
    { "ENETUNREACH", "ERR-036", kXR_noserver },
    { "EHOSTUNREACH", "ERR-036", kXR_noserver },
    { "ECONNREFUSED", "ERR-036", kXR_noserver },
        { "DEFAULT", "ERR-037", kXR_FSError },
    };

    *count = sizeof(specs) / sizeof(specs[0]);
    return specs;
}

/* WHAT: Locate the immutable fixture descriptor for one exact errno label.
 * WHY: CLI parsing and execution must accept the same closed vocabulary.
 * HOW: Compare bounded input against each literal without requiring a NUL. */
static const error_fixture_spec *
find_spec(const char *name, size_t length)
{
    const error_fixture_spec *specs;
    size_t count;
    size_t index;

    specs = error_specs(&count);
    for (index = 0; index < count; index++)
        if (strlen(specs[index].name) == length
            && memcmp(specs[index].name, name, length) == 0)
            return &specs[index];
    return NULL;
}

/* WHAT: Validate one --error-fixture errno spelling.
 * WHY: A typo must fail before any network operation rather than leave a row
 *      silently inconclusive.
 * HOW: Delegate to the single immutable descriptor table. */
int
xrd_conform_error_fixture_name_valid(const char *name, size_t length)
{
    return name != NULL && find_spec(name, length) != NULL;
}

/* WHAT: Report whether labelled fixtures replace the ordinary object probe.
 * WHY: A deliberately failing target cannot supply the readable baseline used
 *      by the normal battery.
 * HOW: Require at least one fixture and an exact ERR or HTE matrix selector. */
int
xrd_conform_error_fixture_exact_selected(
    const xrd_conform_execution *execution)
{
    const char *only;

    if (execution == NULL || execution->run == NULL) return 0;
    only = execution->run->config.only;
    if (only == NULL) return 0;
    if (strcmp(only, "HTE-001") == 0)
        return execution->run->error_fixture_count != 0;
    if (strcmp(only, "HTC-002") == 0)
        return execution->run->error_fixture_count != 0;
    if (strncmp(only, "ERR-", 4) != 0) return 0;
    if (execution->run->error_fixture_count != 0) return 1;
    if (strcmp(only, "ERR-044") == 0)
        return execution->run->readonly_fixture_count != 0;
    if (strcmp(only, "ERR-047") == 0)
        return execution->run->auth_fixture_count != 0;
    return 0;
}

/* WHAT: Decide whether an error message is non-empty printable text.
 * WHY: Wire errors must not hide binary/control data inside their dlen.
 * HOW: Permit horizontal tabs and visible bytes, rejecting every other control. */
static int
message_readable(const char *message)
{
    const unsigned char *cursor = (const unsigned char *) message;

    if (cursor == NULL || *cursor == '\0') return 0;
    while (*cursor != '\0') {
        if ((*cursor < 0x20 && *cursor != '\t') || *cursor == 0x7f) return 0;
        cursor++;
    }
    return 1;
}

/* WHAT: Reject obvious host-path and credential disclosure in an error string.
 * WHY: A correct status code is still unsafe when its explanation leaks local
 *      topology or reusable authentication material.
 * HOW: Match only high-confidence path roots and credential markers. */
static int
message_safe(const char *message)
{
    static const char *const forbidden[] = {
        "/etc/", "/home/", "/Users/", "/var/", "/srv/", "/tmp/",
        "Authorization:", "Bearer ", "BEGIN PRIVATE KEY",
        "AWS4-HMAC-SHA256 Credential="
    };
    size_t index;

    if (message == NULL) return 0;
    for (index = 0; index < sizeof(forbidden) / sizeof(forbidden[0]); index++)
        if (strstr(message, forbidden[index]) != NULL) return 0;
    return 1;
}

/* WHAT: Execute one labelled fault fixture and capture its first wire error.
 * WHY: mapError conformance is external only when an actual server response is
 *      observed; compiling the mapping table is necessary but insufficient.
 * HOW: Connect, read-open, then read one byte; accept failure at open or read,
 *      closing every successfully opened handle and connection. */
int
xrd_conform_observe_root_error(xrd_conform_execution *execution,
    const char *target,
    uint16_t *code, char message[128])
{
    brix_url url;
    brix_conn connection;
    brix_file file;
    brix_status status;
    brix_status close_status;
    unsigned char byte;
    char reason[64];
    int opened = 0;
    int failed = 0;

    brix_status_clear(&status);
    if (brix_endpoint_parse(target, &url, &status) != 0
        || (url.scheme != XRDC_SCHEME_ROOT && url.scheme != XRDC_SCHEME_ROOTS)
        || brix_connect(&connection, &url, &execution->run->opts, &status) != 0)
        return -1;
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        brix_close(&connection);
        return -1;
    }
    if (brix_file_open_read(&connection, url.path, &file, &status) != 0) {
        failed = 1;
    } else {
        opened = 1;
        if (!xrd_conform_reserve(execution, 1, reason, sizeof(reason))) {
            brix_status_clear(&close_status);
            brix_file_close(&connection, &file, &close_status);
            brix_close(&connection);
            return -1;
        }
        failed = brix_file_read(&connection, &file, 0, &byte, 1, &status) < 0;
    }
    *code = failed ? (uint16_t) status.kxr : 0;
    snprintf(message, 128, "%.127s", failed
        ? status.wire_message_len > 0 && status.wire_message_terminated
            ? status.msg : ""
        : "request-succeeded");
    if (opened) {
        brix_status_clear(&close_status);
        brix_file_close(&connection, &file, &close_status);
    }
    brix_close(&connection);
    return failed ? 0 : 1;
}

/* WHAT: Observe a fixture twice and derive its per-fixture safety facts.
 * WHY: One request proves neither deterministic classification nor stable text.
 * HOW: Run two fresh sessions and compare exact code/message pairs. */
static error_fixture_observation
observe_fixture(xrd_conform_execution *execution, const char *target)
{
    error_fixture_observation observation;
    uint16_t repeat_code = 0;
    char repeat_message[128] = "";
    int first_rc;
    int repeat_rc;

    memset(&observation, 0, sizeof(observation));
    observation.present = 1;
    first_rc = xrd_conform_observe_root_error(execution, target,
        &observation.code,
        observation.message);
    repeat_rc = xrd_conform_observe_root_error(execution, target,
        &repeat_code, repeat_message);
    observation.failed = first_rc == 0 && repeat_rc == 0;
    observation.deterministic = observation.failed
        && observation.code == repeat_code
        && strcmp(observation.message, repeat_message) == 0;
    observation.readable = observation.failed
        && message_readable(observation.message);
    observation.safe = observation.readable && message_safe(observation.message);
    return observation;
}

/* WHAT: Grade one mapping row after collecting all of its required fixtures.
 * WHY: ERR-036 is conformant only after all three network errnos were observed.
 * HOW: Count descriptor requirements, present observations and exact matches. */
static void
grade_mapping(xrd_conform_execution *execution, const char *clause,
    const error_fixture_observation observations[])
{
    const error_fixture_spec *specs;
    size_t count;
    size_t index;
    size_t required = 0;
    size_t present = 0;
    size_t matched = 0;
    char received[96];

    specs = error_specs(&count);
    for (index = 0; index < count; index++) {
        if (strcmp(specs[index].clause, clause) != 0) continue;
        required++;
        if (!observations[index].present) continue;
        present++;
        if (observations[index].failed
            && observations[index].code == specs[index].expected)
            matched++;
    }
    if (present == 0) return;
    snprintf(received, sizeof(received),
        "fixtures=%zu/%zu exact=%zu/%zu", present, required, matched, required);
    xrd_conform_result_set(execution, clause,
        present == required && matched == required
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        present == required && matched == required
            ? "all-labelled-errno-fixtures-mapped-exactly"
            : "missing-or-mismapped-errno-fixture",
        "every required labelled fixture returns its exact kXR code", received);
}

/* WHAT: Grade cross-cutting envelope, disclosure and determinism assertions.
 * WHY: These properties apply to every observed mapping, not one errno row.
 * HOW: Fold only present observations and require all of them to satisfy each. */
static void
grade_common(xrd_conform_execution *execution,
    const error_fixture_observation observations[])
{
    const error_fixture_spec *specs;
    size_t count;
    size_t index;
    size_t efault = 0;
    size_t unexpected_server_error = 0;
    size_t present = 0;
    size_t readable = 0;
    size_t safe = 0;
    size_t deterministic = 0;
    size_t in_range = 0;
    char received[96];

    specs = error_specs(&count);
    for (index = 0; index < count; index++) {
        if (!observations[index].present) continue;
        present++;
        readable += observations[index].readable ? 1U : 0U;
        safe += observations[index].safe ? 1U : 0U;
        deterministic += observations[index].deterministic ? 1U : 0U;
        in_range += observations[index].failed
            && observations[index].code >= kXR_ArgInvalid
            && observations[index].code < kXR_ERRFENCE ? 1U : 0U;
        if (strcmp(specs[index].name, "EFAULT") == 0
            && observations[index].code == kXR_ServerError) efault++;
        if (strcmp(specs[index].name, "EFAULT") != 0
            && observations[index].code == kXR_ServerError)
            unexpected_server_error++;
    }
    if (present == 0) return;
    snprintf(received, sizeof(received), "fixtures=%zu readable=%zu safe=%zu",
        present, readable, safe);
    xrd_conform_result_set(execution, "ERR-039",
        readable == present ? BRIX_CONFORM_VERDICT_CONFORMANT
                            : BRIX_CONFORM_VERDICT_DIVERGENT,
        readable == present ? "all-error-messages-readable"
                            : "unreadable-error-message",
        "non-empty printable NUL-terminated message", received);
    xrd_conform_result_set(execution, "ERR-040",
        safe == present ? BRIX_CONFORM_VERDICT_CONFORMANT
                        : BRIX_CONFORM_VERDICT_DIVERGENT,
        safe == present ? "no-high-confidence-disclosure-marker"
                        : "error-message-disclosure-marker",
        "no host filesystem path or credential marker", received);
    xrd_conform_result_set(execution, "ERR-041",
        deterministic == present ? BRIX_CONFORM_VERDICT_CONFORMANT
                                 : BRIX_CONFORM_VERDICT_DIVERGENT,
        deterministic == present ? "all-fixtures-deterministic"
                                 : "fixture-answer-changed",
        "two fresh sessions return the same code and message", received);
    xrd_conform_result_set(execution, "ERR-045",
        in_range == present ? BRIX_CONFORM_VERDICT_CONFORMANT
                            : BRIX_CONFORM_VERDICT_DIVERGENT,
        in_range == present ? "all-error-codes-inside-fence"
                            : "error-code-outside-fence",
        "3000 <= code < kXR_ERRFENCE", received);
    if (efault != 0 || unexpected_server_error != 0)
        xrd_conform_result_set(execution, "ERR-038",
            efault != 0 && unexpected_server_error == 0
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
            efault != 0 && unexpected_server_error == 0
                ? "server-error-confined-to-efault-fixture"
                : "server-error-observed-outside-efault-fixture",
            "only the labelled EFAULT fixture returns kXR_ServerError",
            received);
}

/* WHAT: Grade the two deliberate many-to-one mapping groups.
 * WHY: Reverse conversion is representative, not an inverse, and the report
 *      must record these collapses without calling them ambiguity defects.
 * HOW: Require both authorization errnos and all three network errnos with
 *      their shared exact wire codes. */
static void
grade_collapses(xrd_conform_execution *execution,
    const error_fixture_observation observations[])
{
    const error_fixture_spec *specs;
    size_t count;
    size_t index;
    size_t required = 0;
    size_t matched = 0;
    char received[96];

    specs = error_specs(&count);
    for (index = 0; index < count; index++) {
        int member = strcmp(specs[index].name, "EPERM") == 0
            || strcmp(specs[index].name, "EACCES") == 0
            || strcmp(specs[index].name, "ENETUNREACH") == 0
            || strcmp(specs[index].name, "EHOSTUNREACH") == 0
            || strcmp(specs[index].name, "ECONNREFUSED") == 0;

        if (!member) continue;
        required++;
        if (observations[index].present && observations[index].failed
            && observations[index].code == specs[index].expected) matched++;
    }
    if (matched == 0) return;
    snprintf(received, sizeof(received), "collapse-members=%zu/%zu", matched,
        required);
    xrd_conform_result_set(execution, "ERR-046",
        matched == required ? BRIX_CONFORM_VERDICT_CONFORMANT
                            : BRIX_CONFORM_VERDICT_DIVERGENT,
        matched == required ? "documented-collapses-observed"
                            : "collapse-fixture-set-incomplete-or-wrong",
        "EPERM/EACCES and three network errnos collapse as documented",
        received);
}

/* WHAT: Exercise open, stat and query against one policy-denied path.
 * WHY: ERR-042 requires a remotely observed cross-verb answer, not three
 *      independent source-level mappings.
 * HOW: Reuse one authenticated connection and require each typed operation to
 *      fail with the exact same NotAuthorized code. */
static void
grade_cross_verb(xrd_conform_execution *execution, const char *target)
{
    brix_url url;
    brix_conn connection;
    brix_file file;
    brix_statinfo info;
    brix_status status;
    char reply[64];
    char reason[64];
    int open_code = 0;
    int stat_code = 0;
    int query_code = 0;
    int connected;
    char received[96];

    if (xrd_conform_result_find(execution, "ERR-042")->verdict
        == BRIX_CONFORM_VERDICT_SKIPPED) return;
    brix_status_clear(&status);
    connected = brix_endpoint_parse(target, &url, &status) == 0
        && brix_connect(&connection, &url, &execution->run->opts, &status) == 0;
    if (connected && xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        brix_status_clear(&status);
        if (brix_file_open_read(&connection, url.path, &file, &status) != 0)
            open_code = status.kxr;
        else brix_file_close(&connection, &file, &status);
    }
    if (connected && xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        brix_status_clear(&status);
        if (brix_stat(&connection, url.path, &info, &status) != 0)
            stat_code = status.kxr;
    }
    if (connected && xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        brix_status_clear(&status);
        if (brix_query(&connection, kXR_Qopaquf, url.path, reply,
                sizeof(reply), &status) != 0) query_code = status.kxr;
    }
    if (connected) brix_close(&connection);
    snprintf(received, sizeof(received), "open=%d stat=%d query=%d",
        open_code, stat_code, query_code);
    xrd_conform_result_set(execution, "ERR-042",
        open_code == kXR_NotAuthorized && stat_code == open_code
            && query_code == open_code ? BRIX_CONFORM_VERDICT_CONFORMANT
                                      : BRIX_CONFORM_VERDICT_DIVERGENT,
        open_code == kXR_NotAuthorized && stat_code == open_code
            && query_code == open_code ? "cross-verb-policy-code-agrees"
                                      : "cross-verb-policy-code-diverged",
        "open/stat/query all return kXR_NotAuthorized", received);
}

/* WHAT: Observe open classification for a target path and an absent sibling.
 * WHY: ERR-048 needs paired present/missing evidence under one identity.
 * HOW: Connect once, open the URL path then a keyed missing suffix, returning
 *      zero for success or each exact kXR error code. */
static int
open_pair(xrd_conform_execution *execution, const char *target,
    int *present_code, int *missing_code)
{
    brix_url url;
    brix_conn connection;
    brix_file file;
    brix_status status;
    char missing[XRDC_PATH_MAX];
    char reason[64];

    *present_code = *missing_code = -1;
    brix_status_clear(&status);
    if (brix_endpoint_parse(target, &url, &status) != 0
        || brix_connect(&connection, &url, &execution->run->opts, &status) != 0
        || (size_t) snprintf(missing, sizeof(missing), "%s.brix-missing",
            url.path) >= sizeof(missing)) return -1;
    if (xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        brix_status_clear(&status);
        if (brix_file_open_read(&connection, url.path, &file, &status) == 0) {
            *present_code = 0;
            brix_file_close(&connection, &file, &status);
        } else {
            *present_code = status.kxr;
        }
    }
    if (xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        brix_status_clear(&status);
        if (brix_file_open_read(&connection, missing, &file, &status) == 0) {
            *missing_code = 0;
            brix_file_close(&connection, &file, &status);
        } else {
            *missing_code = status.kxr;
        }
    }
    brix_close(&connection);
    return 0;
}

/* WHAT: Grade policy refusal versus namespace absence without an existence leak.
 * WHY: Authorized users need NotFound while a denied identity must receive the
 *      same policy answer for present and absent paths.
 * HOW: Compare the primary authorized target with the labelled EACCES fixture. */
static void
grade_policy_missing(xrd_conform_execution *execution, const char *denied)
{
    int allowed_present = -1;
    int allowed_missing = -1;
    int denied_present = -1;
    int denied_missing = -1;
    int pass;
    char received[120];

    if (xrd_conform_result_find(execution, "ERR-048")->verdict
        == BRIX_CONFORM_VERDICT_SKIPPED) return;
    pass = open_pair(execution, execution->target, &allowed_present,
        &allowed_missing) == 0
        && open_pair(execution, denied, &denied_present, &denied_missing) == 0
        && allowed_present == 0 && allowed_missing == kXR_NotFound
        && denied_present == kXR_NotAuthorized
        && denied_missing == kXR_NotAuthorized;
    snprintf(received, sizeof(received),
        "allowed=%d/%d denied=%d/%d", allowed_present, allowed_missing,
        denied_present, denied_missing);
    xrd_conform_result_set(execution, "ERR-048",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "policy-and-absence-distinct-without-denied-oracle"
             : "policy-versus-absence-contract-failed",
        "allowed: success/NotFound; denied: identical NotAuthorized", received);
}

/* WHAT: Run all explicitly supplied errno fixtures and grade their ERR rows.
 * WHY: Arbitrary native failures cannot be safely manufactured on a production
 *      export; labelled dedicated endpoints make the precondition explicit.
 * HOW: Match labels to the closed ledger, observe each twice, then grade mapping
 *      rows and cross-cutting properties from the collected wire evidence. */
void
xrd_conform_probe_error_fixtures(xrd_conform_execution *execution)
{
    const error_fixture_spec *specs;
    error_fixture_observation observations[XRDC_CONFORM_ERROR_FIXTURE_MAX];
    size_t spec_count;
    size_t fixture_index;
    size_t spec_index;
    const char *denied_target = NULL;

    specs = error_specs(&spec_count);
    memset(observations, 0, sizeof(observations));
    for (fixture_index = 0;
            fixture_index < execution->run->error_fixture_count;
            fixture_index++) {
        const xrd_conform_error_fixture *fixture =
            &execution->run->error_fixtures[fixture_index];
        const error_fixture_spec *spec = find_spec(fixture->errno_name,
            strlen(fixture->errno_name));

        if (spec == NULL || fixture->is_http) continue;
        spec_index = (size_t) (spec - specs);
        observations[spec_index] = observe_fixture(execution, fixture->target);
        if (strcmp(fixture->errno_name, "EACCES") == 0)
            denied_target = fixture->target;
    }
    for (spec_index = 0; spec_index < spec_count; spec_index++) {
        size_t earlier;

        for (earlier = 0; earlier < spec_index; earlier++)
            if (strcmp(specs[earlier].clause,
                    specs[spec_index].clause) == 0) break;
        if (earlier == spec_index)
            grade_mapping(execution, specs[spec_index].clause,
                observations);
    }
    grade_common(execution, observations);
    grade_collapses(execution, observations);
    if (denied_target != NULL) {
        grade_cross_verb(execution, denied_target);
        grade_policy_missing(execution, denied_target);
    }
}
