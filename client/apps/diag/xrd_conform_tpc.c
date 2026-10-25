/* Phase-118 scratch-confined native third-party-copy probes. */
#include "xrd_conform_probe_helpers.h"
#include "xrd_conform_tpc_helpers.h"

#define TPC_PAYLOAD_SIZE 8192U
#define TPC_RESERVED_REQUESTS 24U
#define TPC_URL_SIZE (XRDC_PATH_MAX + 320U)



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
    if (xrd_conform_row_active(execution, "TPC-001"))
        xrd_conform_result_set(execution, "TPC-001",
            BRIX_CONFORM_VERDICT_DIVERGENT, reason,
            "TPC-only transfer lands byte-exact", status->msg);
}

static void
grade_required_tpc_fixtures(xrd_conform_execution *execution)
{
    static const struct {
        const char *id;
        const char *kind;
        const char *reason;
    } requirements[] = {
        { "TPC-003", "source-denied", "fixture-required:tpc-source-auth-refusal" },
        { "TPC-004", "destination-abort", "fixture-required:tpc-destination-abort" },
        { "TPC-005", "scoped-delegation", "fixture-required:scoped-delegated-credential" },
        { "TPC-006", "native-and-webdav", "fixture-required:native-and-webdav-tpc" },
        { "TPC-009", "egress-blocked", "fixture-required:egress-blocked-destination" }
    };
    const char *kind = execution->run->tpc_fixture_kind;
    size_t index;

    for (index = 0; index < sizeof(requirements) / sizeof(requirements[0]);
         index++) {
        if (xrd_conform_row_active(execution, requirements[index].id)
            && (kind == NULL || strcmp(kind, requirements[index].kind) != 0))
            xrd_conform_result_set(execution, requirements[index].id,
                BRIX_CONFORM_VERDICT_INCONCLUSIVE, requirements[index].reason,
                NULL, NULL);
    }
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
        if (xrd_conform_row_active(execution, rows[index]))
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
        && xrd_conform_row_active(execution, "TPC-003")) {
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
        && xrd_conform_row_active(execution, "TPC-004")) {
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
        || !xrd_conform_row_active(execution, "TPC-009")) return;
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
grade_key_replay(xrd_conform_execution *execution, int registered,
    int consumed, int replay_refused, const brix_status *status)
{
    if (xrd_conform_row_active(execution, "TPC-002"))
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
            status->msg);
}

static void
grade_key_unknown_field(xrd_conform_execution *execution, int registered,
    int consumed, const brix_status *status)
{
    if (xrd_conform_row_active(execution, "TPC-007"))
        xrd_conform_result_set(execution, "TPC-007",
            registered && consumed ? BRIX_CONFORM_VERDICT_CONFORMANT
                                   : BRIX_CONFORM_VERDICT_DIVERGENT,
            registered && consumed
                ? "unknown-tpc-cgi-ignored-with-byte-exact-source"
                : "unknown-tpc-cgi-altered-or-refused-valid-operation",
            "unknown tpc.* field has no effect on selected path or bytes",
            registered && consumed ? NULL : status->msg);
}

static int
consume_key_once(brix_conn *source, const xrd_conform_scratch_object *object,
    const char *opaque, uint8_t expected, brix_status *status)
{
    brix_file consumption;
    brix_status close_status;
    uint8_t observed = 0;
    ssize_t got;

    if (open_read_opaque(source, object->path, opaque, &consumption,
            status) != 0) return 0;
    got = brix_file_read(source, &consumption, 0, &observed, 1, status);
    brix_status_clear(&close_status);
    brix_file_close(source, &consumption, &close_status);
    return got == 1 && observed == expected;
}

static void
probe_key_semantics(xrd_conform_execution *execution, brix_conn *source,
    const brix_url *source_url, const xrd_conform_scratch_object *object,
    const uint8_t payload[TPC_PAYLOAD_SIZE])
{
    char key[64];
    char register_opaque[512];
    char consume_opaque[512];
    brix_file registration;
    brix_file replay;
    brix_status status;
    int registered;
    int consumed = 0;
    int replay_refused = 0;

    if (!xrd_conform_row_active(execution, "TPC-002")
        && !xrd_conform_row_active(execution, "TPC-007")) return;
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
        consumed = consume_key_once(source, object, consume_opaque,
            payload[0], &status);
    }
    if (consumed) {
        brix_status close_status;

        if (open_read_opaque(source, object->path, consume_opaque, &replay,
                &status) == 0) {
            brix_status_clear(&close_status);
            brix_file_close(source, &replay, &close_status);
        } else {
            replay_refused = status.kxr == kXR_NotAuthorized;
        }
    }
    grade_key_replay(execution, registered, consumed, replay_refused, &status);
    grade_key_unknown_field(execution, registered, consumed, &status);
}

typedef struct {
    brix_url source_url;
    brix_url destination_url;
    brix_conn source;
    brix_conn destination;
    brix_opts opts;
    brix_status status;
    uint8_t payload[TPC_PAYLOAD_SIZE];
    xrd_conform_scratch_object source_object;
    xrd_conform_scratch_object destination_object;
    char source_text[TPC_URL_SIZE];
    char destination_text[TPC_URL_SIZE];
    unsigned long long source_claim;
    unsigned long long destination_claim;
    unsigned long long source_attempts;
    int claims_ok;
    int planted;
    int copy_ok;
    int exact;
    int absent;
    int attempts_known;
    int destination_ready;
    time_t copy_elapsed;
} tpc_probe_state;

static int
setup_tpc_pair(xrd_conform_execution *execution, tpc_probe_state *state)
{
    memset(state, 0, sizeof(*state));
    state->opts = execution->run->opts;
    state->opts.capture = NULL;
    state->copy_elapsed = (time_t) execution->run->config.wall_seconds;
    brix_status_clear(&state->status);
    if (parse_pair(execution, &state->source_url, &state->destination_url,
            &state->status) != 0) return -1;
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-tpc-source", state->source_object.path,
            sizeof(state->source_object.path)) != 0
        || brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-tpc-destination", state->destination_object.path,
            sizeof(state->destination_object.path)) != 0
        || xrd_conform_tpc_root_url(&state->source_url,
            state->source_object.path, state->source_text,
            sizeof(state->source_text)) != 0
        || xrd_conform_tpc_root_url(&state->destination_url,
            state->destination_object.path, state->destination_text,
            sizeof(state->destination_text)) != 0
        || reserve_probe(execution, &state->status) != 0) return -2;
    return 0;
}

static int
connect_tpc_pair(xrd_conform_execution *execution, tpc_probe_state *state)
{
    if (brix_connect(&state->source, &state->source_url, &state->opts,
            &state->status) != 0) {
        grade_failure(execution, "tpc-source-unavailable", &state->status);
        return -1;
    }
    if (brix_connect(&state->destination, &state->destination_url,
            &state->opts, &state->status) != 0) {
        grade_failure(execution, "tpc-destination-unavailable", &state->status);
        brix_close(&state->source);
        return -1;
    }
    return 0;
}

static void
query_source_attempts(tpc_probe_state *state)
{
    brix_status attempt_status;
    char reply[64];

    brix_status_clear(&attempt_status);
    state->attempts_known = brix_query(&state->source, kXR_Qconfig,
        "phase118.tpc_attempts", reply, sizeof(reply), &attempt_status) == 0
        && xrd_conform_tpc_unsigned(reply, &state->source_attempts);
}

static void
perform_tpc_copy(xrd_conform_execution *execution, tpc_probe_state *state)
{
    brix_copy_opts copy = { 0 };
    int copy_needed;
    time_t started;

    state->claims_ok = xrd_conform_tpc_query(&state->source, &state->source_claim,
        &state->status) == 0
        && xrd_conform_tpc_query(&state->destination, &state->destination_claim,
            &state->status) == 0;
    state->planted = write_source(execution, &state->source,
        &state->source_object, state->payload, &state->status) == 0;
    if (!state->planted) {
        grade_failure(execution, "tpc-source-plant-failed", &state->status);
        return;
    }
    if (execution->run->tpc_fixture_kind == NULL)
        probe_key_semantics(execution, &state->source, &state->source_url,
            &state->source_object, state->payload);
    copy_needed = xrd_conform_row_active(execution, "TPC-001")
        || xrd_conform_row_active(execution, "TPC-008")
        || xrd_conform_row_active(execution, "CLM-009")
        || execution->run->tpc_fixture_kind != NULL;
    state->destination_ready = prepare_destination(&state->destination,
        &state->destination_object, &state->status);
    if (!state->destination_ready) {
        grade_destination_setup(execution, &state->status);
        return;
    }
    if (!copy_needed) return;
    copy.tpc_mode = XRDC_TPC_ONLY;
    copy.force = 1;
    copy.posc = 1;
    copy.silent = 1;
    started = time(NULL);
    state->copy_ok = brix_copy(state->source_text, state->destination_text,
        &copy, &state->opts, &state->status) == 0;
    if (started != (time_t) -1) {
        time_t finished = time(NULL);

        if (finished != (time_t) -1) state->copy_elapsed = finished - started;
    }
    if (state->copy_ok)
        state->exact = xrd_conform_tpc_destination_exact(&state->destination,
            state->destination_object.path, state->payload,
            sizeof(state->payload), &state->status);
    else
        state->absent = xrd_conform_tpc_destination_absent(&state->destination,
            state->destination_object.path);
    if (execution->run->tpc_fixture_kind != NULL
        && strcmp(execution->run->tpc_fixture_kind, "egress-blocked") == 0)
        query_source_attempts(state);
}

static void
record_tpc_claim_state(xrd_conform_execution *execution,
    const tpc_probe_state *state, int agrees)
{
    if (xrd_conform_row_active(execution, "TPC-008") || xrd_conform_row_active(execution, "CLM-009"))
        execution->tpc_claim_behavior_state = !state->planted ? 0
            : state->claims_ok && agrees ? 1 : -1;
}

static void
grade_tpc_claim(xrd_conform_execution *execution,
    const tpc_probe_state *state)
{
    int advertised;
    int agrees;

    if (!state->destination_ready
        || execution->run->tpc_fixture_kind != NULL) return;
    advertised = state->claims_ok && state->source_claim != 0
        && state->destination_claim != 0;
    agrees = state->planted && state->claims_ok
        && advertised == (state->copy_ok && state->exact);
    record_tpc_claim_state(execution, state, agrees);
    if (!xrd_conform_row_active(execution, "TPC-008")) return;
    xrd_conform_result_set(execution, "TPC-008",
        !state->planted ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
            : agrees ? BRIX_CONFORM_VERDICT_CONFORMANT
                     : BRIX_CONFORM_VERDICT_DIVERGENT,
        !state->planted ? "tpc-source-plant-failed"
            : !state->claims_ok ? "qconfig-tpc-not-numeric"
            : agrees ? "qconfig-tpc-agrees-with-observed-transfer"
                     : "qconfig-tpc-claim-behavior-mismatch",
        "both numeric TPC claims agree with byte-exact behavior", NULL);
}

static void
grade_tpc_pair(xrd_conform_execution *execution, tpc_probe_state *state)
{
    if (!state->destination_ready) return;
    grade_abort_fixture(execution, state->copy_ok, state->absent,
        state->copy_elapsed, &state->status);
    grade_egress_fixture(execution, state->copy_ok, state->absent,
        state->attempts_known, state->source_attempts, &state->status);
    xrd_conform_probe_tpc_webdav(execution, state->payload,
        sizeof(state->payload), state->copy_ok && state->exact);
    if (state->planted && execution->run->tpc_fixture_kind == NULL
        && xrd_conform_row_active(execution, "TPC-001"))
        xrd_conform_result_set(execution, "TPC-001",
            state->copy_ok && state->exact ? BRIX_CONFORM_VERDICT_CONFORMANT
                                          : BRIX_CONFORM_VERDICT_DIVERGENT,
            state->copy_ok && state->exact ? "native-tpc-byte-exact"
                : state->copy_ok ? "native-tpc-byte-mismatch"
                                 : "native-tpc-failed",
            "TPC-only transfer lands byte-exact",
            state->copy_ok ? NULL : state->status.msg);
    grade_tpc_claim(execution, state);
}

/* WHAT: Execute a native TPC-only transfer between two explicit ROOT endpoints.
 * WHY: A capability claim is meaningful only when reconciled with exact bytes.
 * HOW: Plant PRF bytes under scratch, query both claims, hard-fail TPC copy,
 * reread the destination independently, grade behavior/claim agreement, clean. */
void
xrd_conform_probe_tpc_pair(xrd_conform_execution *execution)
{
    tpc_probe_state state;
    int setup;

    if (!xrd_conform_family_active(execution, "TPC")
        && !xrd_conform_row_active(execution, "CLM-009")) return;
    if (execution->run->tpc_fixture_kind != NULL
        && strcmp(execution->run->tpc_fixture_kind,
            "scoped-delegation") == 0) {
        xrd_conform_probe_tpc_scoped(execution);
        return;
    }
    grade_required_tpc_fixtures(execution);
    setup = setup_tpc_pair(execution, &state);
    if (setup == -1) {
        grade_failure(execution, "fixture-required:paired-tpc-endpoints",
            &state.status);
        if (xrd_conform_row_active(execution, "TPC-008"))
            xrd_conform_result_set(execution, "TPC-008",
                BRIX_CONFORM_VERDICT_INCONCLUSIVE,
                "fixture-required:paired-tpc-endpoints", NULL,
                state.status.msg);
        return;
    }
    if (setup != 0) {
        grade_failure(execution, "tpc-probe-setup-failed", &state.status);
        return;
    }
    if (connect_tpc_pair(execution, &state) != 0) return;
    perform_tpc_copy(execution, &state);
    grade_tpc_pair(execution, &state);
    cleanup_pair(&state.source, &state.destination, &state.source_object,
        &state.destination_object);
    brix_close(&state.destination);
    brix_close(&state.source);
}
