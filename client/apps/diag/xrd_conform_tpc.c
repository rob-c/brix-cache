/* Phase-118 scratch-confined native third-party-copy probes. */
#include "xrd_conform_internal.h"
#include "core/compat/host_format.h"

#define TPC_PAYLOAD_SIZE 8192U
#define TPC_RESERVED_REQUESTS 24U
#define TPC_URL_SIZE (XRDC_PATH_MAX + 320U)

static int
row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

int
xrd_conform_tpc_exact_selected(const xrd_conform_execution *execution)
{
    const char *only;

    if (execution == NULL || execution->run == NULL) return 0;
    only = execution->run->config.only;
    return only != NULL
        && (strcmp(only, "TPC-001") == 0 || strcmp(only, "TPC-002") == 0
            || strcmp(only, "TPC-003") == 0 || strcmp(only, "TPC-004") == 0
            || strcmp(only, "TPC-005") == 0 || strcmp(only, "TPC-006") == 0
            || strcmp(only, "TPC-007") == 0
            || strcmp(only, "TPC-008") == 0 || strcmp(only, "TPC-009") == 0);
}

static int
reserve_probe(xrd_conform_execution *execution, brix_status *status)
{
    char reason[64];
    unsigned index;

    for (index = 0; index < TPC_RESERVED_REQUESTS; index++) {
        size_t bytes = index == 0 ? TPC_PAYLOAD_SIZE * 3U : 0;

        if (!xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) {
            brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
            return -1;
        }
    }
    return 0;
}

static int
parse_pair(xrd_conform_execution *execution, brix_url *source,
    brix_url *destination, brix_status *status)
{
    if (execution->run->also_count == 0
        || brix_endpoint_parse(execution->run->config.target, source,
            status) != 0
        || brix_endpoint_parse(execution->run->also[0], destination,
            status) != 0) return -1;
    if ((source->scheme != XRDC_SCHEME_ROOT
            && source->scheme != XRDC_SCHEME_ROOTS)
        || (destination->scheme != XRDC_SCHEME_ROOT
            && destination->scheme != XRDC_SCHEME_ROOTS)) return -1;
    return 0;
}

static int
strict_unsigned(const char *value, unsigned long long *number)
{
    char *end = NULL;
    unsigned long long parsed;

    while (isspace((unsigned char) *value)) value++;
    if (!isdigit((unsigned char) *value)) return 0;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value) return 0;
    while (isspace((unsigned char) *end)) end++;
    if (*end != '\0') return 0;
    *number = parsed;
    return 1;
}

static int
query_tpc(brix_conn *connection, unsigned long long *value,
    brix_status *status)
{
    char reply[128];

    if (brix_query(connection, kXR_Qconfig, "tpc", reply, sizeof(reply),
            status) != 0) return -1;
    return strict_unsigned(reply, value) ? 0 : -1;
}

int
xrd_conform_tpc_root_url(const brix_url *endpoint, const char *path, char *out,
    size_t out_size)
{
    char authority[XRDC_HOSTPORT_MAX];
    const char *scheme = endpoint->scheme == XRDC_SCHEME_ROOTS
        ? "roots" : "root";

    brix_format_host_port(endpoint->host, (uint16_t) endpoint->port,
        authority, sizeof(authority));
    return (size_t) snprintf(out, out_size, "%s://%s/%s", scheme,
        authority, path) < out_size ? 0 : -1;
}

static int
write_source(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object,
    uint8_t payload[TPC_PAYLOAD_SIZE], brix_status *status)
{
    brix_file file;

    brix_conform_fill(&execution->run->key, 0, payload, TPC_PAYLOAD_SIZE);
    if (brix_file_open_write(connection, object->path, 1, 0, &file,
            status) != 0)
        return -1;
    if (brix_file_write(connection, &file, 0, payload,
            TPC_PAYLOAD_SIZE, status) != 0) {
        brix_status close_status;

        brix_status_clear(&close_status);
        brix_file_close(connection, &file, &close_status);
        return -1;
    }
    return brix_file_close(connection, &file, status);
}

int
xrd_conform_tpc_destination_exact(brix_conn *connection, const char *path,
    const uint8_t *expected, size_t expected_length, brix_status *status)
{
    uint8_t received[TPC_PAYLOAD_SIZE];
    brix_statinfo info;
    brix_file file;
    ssize_t length;

    if (brix_stat(connection, path, &info, status) != 0
        || expected_length > sizeof(received)
        || info.size != (long long) expected_length
        || brix_file_open_read(connection, path, &file, status) != 0)
        return 0;
    length = brix_file_read(connection, &file, 0, received,
        sizeof(received), status);
    if (brix_file_close(connection, &file, status) != 0) return 0;
    return length == (ssize_t) expected_length
        && memcmp(received, expected, expected_length) == 0;
}

static void
cleanup_pair(brix_conn *source, brix_conn *destination,
    const xrd_conform_scratch_object *source_object,
    const xrd_conform_scratch_object *destination_object)
{
    brix_status status;

    brix_status_clear(&status);
    brix_rm(destination, destination_object->path, &status);
    brix_status_clear(&status);
    brix_rm(source, source_object->path, &status);
}

static void
grade_failure(xrd_conform_execution *execution, const char *reason,
    const brix_status *status)
{
    if (row_active(execution, "TPC-001"))
        xrd_conform_result_set(execution, "TPC-001",
            BRIX_CONFORM_VERDICT_DIVERGENT, reason,
            "TPC-only transfer lands byte-exact", status->msg);
}

static void
grade_required_tpc_fixtures(xrd_conform_execution *execution)
{
    const char *kind = execution->run->tpc_fixture_kind;

    if (row_active(execution, "TPC-003")
        && (kind == NULL || strcmp(kind, "source-denied") != 0))
        xrd_conform_result_set(execution, "TPC-003",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:tpc-source-auth-refusal", NULL, NULL);
    if (row_active(execution, "TPC-004")
        && (kind == NULL || strcmp(kind, "destination-abort") != 0))
        xrd_conform_result_set(execution, "TPC-004",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:tpc-destination-abort", NULL, NULL);
    if (row_active(execution, "TPC-005")
        && (kind == NULL || strcmp(kind, "scoped-delegation") != 0))
        xrd_conform_result_set(execution, "TPC-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:scoped-delegated-credential", NULL, NULL);
    if (row_active(execution, "TPC-006")
        && (kind == NULL || strcmp(kind, "native-and-webdav") != 0))
        xrd_conform_result_set(execution, "TPC-006",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:native-and-webdav-tpc", NULL, NULL);
    if (row_active(execution, "TPC-009")
        && (kind == NULL || strcmp(kind, "egress-blocked") != 0))
        xrd_conform_result_set(execution, "TPC-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:egress-blocked-destination", NULL, NULL);
}

int
xrd_conform_tpc_destination_absent(brix_conn *destination, const char *path)
{
    brix_statinfo info;
    brix_status status;
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 50000000L };
    unsigned attempt;

    for (attempt = 0; attempt < 20; attempt++) {
        brix_status_clear(&status);
        if (brix_stat(destination, path, &info, &status) != 0
            && (status.kxr == kXR_NotFound || status.kxr == XRDC_ENOENT))
            return 1;
        nanosleep(&pause, NULL);
    }
    return 0;
}

static int
prepare_destination(brix_conn *destination,
    const xrd_conform_scratch_object *object,
    brix_status *status)
{
    brix_status_clear(status);
    if (brix_rm(destination, object->path, status) != 0
        && status->kxr != kXR_NotFound && status->kxr != XRDC_ENOENT)
        return 0;
    return xrd_conform_tpc_destination_absent(destination, object->path);
}

static void
grade_destination_setup(xrd_conform_execution *execution,
    const brix_status *status)
{
    static const char *const rows[] = {
        "TPC-001", "TPC-003", "TPC-004", "TPC-008", "TPC-009"
    };
    unsigned index;

    for (index = 0; index < sizeof(rows) / sizeof(rows[0]); index++) {
        if (row_active(execution, rows[index]))
            xrd_conform_result_set(execution, rows[index],
                BRIX_CONFORM_VERDICT_INCONCLUSIVE,
                "fixture-setup:tpc-destination-not-empty", NULL,
                status->msg);
    }
}

static void
grade_abort_fixture(xrd_conform_execution *execution, int copy_ok,
    int absent, time_t elapsed, const brix_status *status)
{
    const char *kind = execution->run->tpc_fixture_kind;
    char received[192];

    snprintf(received, sizeof(received),
        "copy_ok=%d absent=%d elapsed=%lld kXR=%d message=%.96s", copy_ok,
        absent, (long long) elapsed, status->kxr, status->msg);

    if (kind == NULL) return;
    if (strcmp(kind, "source-denied") == 0
        && row_active(execution, "TPC-003")) {
        int terminal = !copy_ok && status->kxr == kXR_NotAuthorized
            && absent && elapsed < (time_t) execution->run->config.wall_seconds;

        xrd_conform_result_set(execution, "TPC-003",
            terminal ? BRIX_CONFORM_VERDICT_CONFORMANT
                     : BRIX_CONFORM_VERDICT_DIVERGENT,
            terminal ? "tpc-source-auth-refusal-terminal-no-partial"
                     : "tpc-source-refusal-retried-misclassified-or-partial",
            "kXR_NotAuthorized, bounded terminal failure, no destination",
            received);
    }
    if (strcmp(kind, "destination-abort") == 0
        && row_active(execution, "TPC-004")) {
        int discarded = !copy_ok && absent;

        xrd_conform_result_set(execution, "TPC-004",
            discarded ? BRIX_CONFORM_VERDICT_CONFORMANT
                      : BRIX_CONFORM_VERDICT_DIVERGENT,
            discarded ? "tpc-posc-abort-left-no-destination"
                      : "tpc-posc-abort-left-partial-or-succeeded",
            "failed destination transfer leaves no POSC object", received);
    }
}

static void
grade_egress_fixture(xrd_conform_execution *execution, int copy_ok, int absent,
    int attempts_known, unsigned long long attempts, const brix_status *status)
{
    char received[224];
    int refused;

    if (execution->run->tpc_fixture_kind == NULL
        || strcmp(execution->run->tpc_fixture_kind, "egress-blocked") != 0
        || !row_active(execution, "TPC-009")) return;
    refused = !copy_ok && absent && attempts_known && attempts == 0
        && status->kxr == kXR_NotAuthorized
        && strstr(status->msg, "TPC source host not permitted") != NULL;
    snprintf(received, sizeof(received),
        "copy_ok=%d absent=%d attempts=%s%llu kXR=%d message=%.120s", copy_ok,
        absent, attempts_known ? "" : "unknown:", attempts, status->kxr,
        status->msg);
    xrd_conform_result_set(execution, "TPC-009",
        refused ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        refused ? "tpc-egress-guard-refused-before-source-contact"
                : "tpc-egress-guard-bypassed-or-source-contacted",
        "kXR_NotAuthorized naming refusal, zero source attempts, no destination",
        received);
}

static int
open_read_opaque(brix_conn *connection, const char *path, const char *opaque,
    brix_file *file, brix_status *status)
{
    brix_status_clear(status);
    return brix_file_open_opaque(connection, path, opaque, 0, 0, 0, file,
        status);
}

/* WHAT: Exercise source-side key registration, one-shot consume, and replay.
 * WHY: TPC authorization is a bearer rendezvous; accepting it twice is replay.
 * HOW: Register with tpc.dst, consume with tpc.org, verify one source byte,
 * then repeat the consume and require the exact authorization refusal. */
static void
probe_key_semantics(xrd_conform_execution *execution, brix_conn *source,
    const brix_url *source_url, const xrd_conform_scratch_object *object,
    const uint8_t payload[TPC_PAYLOAD_SIZE])
{
    char key[64];
    char register_opaque[512];
    char consume_opaque[512];
    brix_file registration;
    brix_file consumption;
    brix_file replay;
    brix_status status;
    uint8_t observed = 0;
    int registered;
    int consumed = 0;
    int replay_refused = 0;

    if (!row_active(execution, "TPC-002")
        && !row_active(execution, "TPC-007")) return;
    snprintf(key, sizeof(key), "phase118-%.32s", execution->run->key_hex);
    snprintf(register_opaque, sizeof(register_opaque),
        "tpc.key=%s&tpc.dst=%s&tpc.stage=copy"
        "&tpc.phase118_unknown=must-be-ignored",
        key, source_url->host);
    snprintf(consume_opaque, sizeof(consume_opaque),
        "tpc.key=%s&tpc.org=phase118&tpc.stage=copy"
        "&tpc.phase118_unknown=must-be-ignored", key);
    registered = open_read_opaque(source, object->path, register_opaque,
        &registration, &status) == 0;
    if (registered) {
        brix_status close_status;

        brix_status_clear(&close_status);
        brix_file_close(source, &registration, &close_status);
        consumed = open_read_opaque(source, object->path, consume_opaque,
            &consumption, &status) == 0;
    }
    if (consumed) {
        ssize_t got = brix_file_read(source, &consumption, 0, &observed, 1,
            &status);
        brix_status close_status;

        consumed = got == 1 && observed == payload[0];
        brix_status_clear(&close_status);
        brix_file_close(source, &consumption, &close_status);
        if (open_read_opaque(source, object->path, consume_opaque, &replay,
                &status) == 0) {
            brix_status_clear(&close_status);
            brix_file_close(source, &replay, &close_status);
        } else {
            replay_refused = status.kxr == kXR_NotAuthorized;
        }
    }
    if (row_active(execution, "TPC-002"))
        xrd_conform_result_set(execution, "TPC-002",
            registered && consumed && replay_refused
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
            registered && consumed && replay_refused
                ? "tpc-rendezvous-key-consumed-once"
                : !registered ? "tpc-key-registration-failed"
                : !consumed ? "tpc-key-first-consume-failed"
                            : "tpc-key-replay-accepted-or-misclassified",
            "first consume succeeds; replay returns kXR_NotAuthorized",
            status.msg);
    if (row_active(execution, "TPC-007"))
        xrd_conform_result_set(execution, "TPC-007",
            registered && consumed ? BRIX_CONFORM_VERDICT_CONFORMANT
                                   : BRIX_CONFORM_VERDICT_DIVERGENT,
            registered && consumed
                ? "unknown-tpc-cgi-ignored-with-byte-exact-source"
                : "unknown-tpc-cgi-altered-or-refused-valid-operation",
            "unknown tpc.* field has no effect on selected path or bytes",
            registered && consumed ? NULL : status.msg);
}

/* WHAT: Execute a native TPC-only transfer between two explicit ROOT endpoints.
 * WHY: A capability claim is meaningful only when reconciled with exact bytes.
 * HOW: Plant PRF bytes under scratch, query both claims, hard-fail TPC copy,
 * reread the destination independently, grade behavior/claim agreement, clean. */
void
xrd_conform_probe_tpc_pair(xrd_conform_execution *execution)
{
    brix_url source_url;
    brix_url destination_url;
    brix_conn source;
    brix_conn destination;
    brix_copy_opts copy = { 0 };
    brix_opts opts = execution->run->opts;
    brix_status status;
    uint8_t payload[TPC_PAYLOAD_SIZE];
    xrd_conform_scratch_object source_object;
    xrd_conform_scratch_object destination_object;
    char source_text[TPC_URL_SIZE];
    char destination_text[TPC_URL_SIZE];
    unsigned long long source_claim = 0;
    unsigned long long destination_claim = 0;
    unsigned long long source_attempts = 0;
    int destination_connected = 0;
    int claims_ok;
    int planted = 0;
    int copy_needed;
    int copy_ok = 0;
    int exact = 0;
    int absent = 0;
    int attempts_known = 0;
    int destination_ready = 0;
    time_t copy_started = 0;
    time_t copy_elapsed;

    if (!xrd_conform_family_active(execution, "TPC")
        && !row_active(execution, "CLM-009")) return;
    if (execution->run->tpc_fixture_kind != NULL
        && strcmp(execution->run->tpc_fixture_kind,
            "scoped-delegation") == 0) {
        xrd_conform_probe_tpc_scoped(execution);
        return;
    }
    copy_elapsed = (time_t) execution->run->config.wall_seconds;
    grade_required_tpc_fixtures(execution);
    brix_status_clear(&status);
    if (parse_pair(execution, &source_url, &destination_url, &status) != 0) {
        grade_failure(execution, "fixture-required:paired-tpc-endpoints",
            &status);
        if (row_active(execution, "TPC-008"))
            xrd_conform_result_set(execution, "TPC-008",
                BRIX_CONFORM_VERDICT_INCONCLUSIVE,
                "fixture-required:paired-tpc-endpoints", NULL, status.msg);
        return;
    }
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-tpc-source", source_object.path,
            sizeof(source_object.path)) != 0
        || brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-tpc-destination", destination_object.path,
            sizeof(destination_object.path)) != 0
        || xrd_conform_tpc_root_url(&source_url, source_object.path, source_text,
            sizeof(source_text)) != 0
        || xrd_conform_tpc_root_url(&destination_url, destination_object.path,
            destination_text,
            sizeof(destination_text)) != 0
        || reserve_probe(execution, &status) != 0) {
        grade_failure(execution, "tpc-probe-setup-failed", &status);
        return;
    }
    opts.capture = NULL;
    if (brix_connect(&source, &source_url, &opts, &status) != 0) {
        grade_failure(execution, "tpc-source-unavailable", &status);
        return;
    }
    if (brix_connect(&destination, &destination_url, &opts, &status) != 0) {
        grade_failure(execution, "tpc-destination-unavailable", &status);
    } else {
        destination_connected = 1;
    }
    if (!destination_connected) {
        brix_close(&source);
        return;
    }
    claims_ok = query_tpc(&source, &source_claim, &status) == 0
        && query_tpc(&destination, &destination_claim, &status) == 0;
    planted = write_source(execution, &source, &source_object, payload,
        &status) == 0;
    if (planted) {
        if (execution->run->tpc_fixture_kind == NULL)
            probe_key_semantics(execution, &source, &source_url,
                &source_object, payload);
        copy_needed = row_active(execution, "TPC-001")
            || row_active(execution, "TPC-008")
            || row_active(execution, "CLM-009")
            || execution->run->tpc_fixture_kind != NULL;
        destination_ready = prepare_destination(&destination,
            &destination_object, &status);
        if (!destination_ready) {
            grade_destination_setup(execution, &status);
        } else if (copy_needed) {
            copy.tpc_mode = XRDC_TPC_ONLY;
            copy.force = 1;
            copy.posc = 1;
            copy.silent = 1;
            copy_started = time(NULL);
            copy_ok = brix_copy(source_text, destination_text, &copy, &opts,
                &status) == 0;
            if (copy_started != (time_t) -1) {
                time_t finished = time(NULL);

                if (finished != (time_t) -1) copy_elapsed = finished - copy_started;
            }
            if (copy_ok)
                exact = xrd_conform_tpc_destination_exact(&destination,
                    destination_object.path, payload, sizeof(payload), &status);
            else
                absent = xrd_conform_tpc_destination_absent(&destination,
                    destination_object.path);
            if (execution->run->tpc_fixture_kind != NULL
                && strcmp(execution->run->tpc_fixture_kind,
                    "egress-blocked") == 0) {
                brix_status attempt_status;
                char reply[64];

                brix_status_clear(&attempt_status);
                attempts_known = brix_query(&source, kXR_Qconfig,
                    "phase118.tpc_attempts", reply, sizeof(reply),
                    &attempt_status) == 0
                    && strict_unsigned(reply, &source_attempts);
            }
        }
    } else {
        grade_failure(execution, "tpc-source-plant-failed", &status);
    }
    if (destination_ready)
        grade_abort_fixture(execution, copy_ok, absent, copy_elapsed, &status);
    if (destination_ready)
        grade_egress_fixture(execution, copy_ok, absent, attempts_known,
            source_attempts, &status);
    if (destination_ready)
        xrd_conform_probe_tpc_webdav(execution, payload, sizeof(payload),
            copy_ok && exact);
    if (planted && destination_ready
        && execution->run->tpc_fixture_kind == NULL
        && row_active(execution, "TPC-001"))
        xrd_conform_result_set(execution, "TPC-001",
            copy_ok && exact ? BRIX_CONFORM_VERDICT_CONFORMANT
                             : BRIX_CONFORM_VERDICT_DIVERGENT,
            copy_ok && exact ? "native-tpc-byte-exact"
                             : copy_ok ? "native-tpc-byte-mismatch"
                                       : "native-tpc-failed",
            "TPC-only transfer lands byte-exact", copy_ok ? NULL : status.msg);
    if (destination_ready && execution->run->tpc_fixture_kind == NULL
        && (row_active(execution, "TPC-008")
            || row_active(execution, "CLM-009"))) {
        int advertised = claims_ok && source_claim != 0
            && destination_claim != 0;
        int agrees = planted && claims_ok
            && advertised == (copy_ok && exact);

        execution->tpc_claim_behavior_state = !planted ? 0
            : claims_ok && agrees ? 1 : -1;
    }
    if (destination_ready && execution->run->tpc_fixture_kind == NULL
        && row_active(execution, "TPC-008")) {
        int agrees = execution->tpc_claim_behavior_state > 0;

        xrd_conform_result_set(execution, "TPC-008",
            !planted ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                : agrees ? BRIX_CONFORM_VERDICT_CONFORMANT
                         : BRIX_CONFORM_VERDICT_DIVERGENT,
            !planted ? "tpc-source-plant-failed"
                : !claims_ok ? "qconfig-tpc-not-numeric"
                : agrees ? "qconfig-tpc-agrees-with-observed-transfer"
                         : "qconfig-tpc-claim-behavior-mismatch",
            "both numeric TPC claims agree with byte-exact behavior", NULL);
    }
    cleanup_pair(&source, &destination, &source_object, &destination_object);
    brix_close(&destination);
    brix_close(&source);
}
