/*
 * Phase-118 remote conformance execution and result ownership.
 *
 * WHAT: Initializes every ledger row, dispatches a protocol runner and reports.
 * WHY: A complete ledger must never omit or accidentally green an unrun clause.
 * HOW: Start selected rows inconclusive, excluded rows skipped, then let probes
 *      replace only results for assertions they actually establish.
 */
#include "xrd_conform_internal.h"
#include "core/compat/crypto.h"
#include "core/version.h"

#include <limits.h>
#include <time.h>

/* ---- Create a private raw-capture staging path ----
 *
 * WHAT: Makes an owner-only temporary directory and names its session capture.
 * WHY: Root auth frames may exist briefly but must never enter published output.
 * HOW: mkdtemp creates mode 0700; brix capture creates the only child on connect.
 */
static int
capture_staging(char directory[64], char path[96])
{
    snprintf(directory, 64, "/tmp/brix-conform-capture.XXXXXX");
    if (mkdtemp(directory) == NULL) return -1;
    if ((size_t) snprintf(path, 96, "%s/session.raw.xrdcap", directory) >= 96) {
        rmdir(directory);
        return -1;
    }
    return 0;
}

/* ---- Remove the private raw-capture staging area ----
 *
 * WHAT: Deletes only the fixed child of this run's freshly-created directory.
 * WHY: Unscrubbed connection frames must not survive after artifact publication.
 * HOW: Unlink the explicit path, then remove its now-empty private directory.
 */
static void
capture_staging_remove(const char *directory, const char *path)
{
    if (path != NULL && path[0] != '\0') unlink(path);
    if (directory != NULL && directory[0] != '\0') rmdir(directory);
}

/* ---- Return a stable run-shape name ----
 *
 * WHAT: Maps the typed run shape to its report spelling.
 * WHY: All report formats must carry the same frozen vocabulary.
 * HOW: Exhaustively switch over the enum and fail closed to unknown.
 */
static const char *
shape_name(brix_conform_run_shape shape)
{
    if (shape == BRIX_CONFORM_RUN_ACCEPT) return "accept";
    if (shape == BRIX_CONFORM_RUN_FULL) return "full";
    if (shape == BRIX_CONFORM_RUN_WATCH) return "watch";
    return "unknown";
}

/* ---- Return a stable reference-mode name ----
 *
 * WHAT: Maps reference policy to its CLI/report spelling.
 * WHY: Reports are reproducibility records, so policy cannot be implicit.
 * HOW: Exhaustively test known values and fail closed to unknown.
 */
static const char *
reference_name(brix_conform_reference_mode mode)
{
    if (mode == BRIX_CONFORM_REFERENCE_ECOSYSTEM) return "ecosystem";
    if (mode == BRIX_CONFORM_REFERENCE_STRICT) return "strict";
    if (mode == BRIX_CONFORM_REFERENCE_BOTH) return "both";
    return "unknown";
}

/* ---- Locate a mutable result by clause id ----
 *
 * WHAT: Returns the result corresponding to an immutable catalogue id.
 * WHY: Probe modules grade named assertions without depending on row order.
 * HOW: Walk the bounded 527-row vector and compare exact ids.
 */
brix_conform_result *
xrd_conform_result_find(xrd_conform_execution *execution, const char *id)
{
    size_t index;

    if (execution == NULL || id == NULL) return NULL;
    for (index = 0; index < execution->results.count; index++) {
        brix_conform_result *result = &execution->results.results[index];

        if (strcmp(result->clause->id, id) == 0) return result;
    }
    return NULL;
}

int
xrd_conform_family_active(xrd_conform_execution *execution,
    const char *family)
{
    size_t index;

    if (execution == NULL || family == NULL) return 0;
    for (index = 0; index < execution->results.count; index++) {
        brix_conform_result *result = &execution->results.results[index];

        if (strcmp(result->clause->family, family) == 0
            && result->verdict != BRIX_CONFORM_VERDICT_SKIPPED) return 1;
    }
    return 0;
}

/* ---- Grade one assertion with bounded evidence ----
 *
 * WHAT: Replaces an in-scope row's provisional verdict and evidence.
 * WHY: Probe code needs one consistent, truncation-safe result-writing seam.
 * HOW: Refuse skipped rows, copy optional strings with snprintf.
 */
void
xrd_conform_result_set(xrd_conform_execution *execution, const char *id,
    brix_conform_verdict verdict, const char *reason, const char *expected,
    const char *received)
{
    brix_conform_result *result = xrd_conform_result_find(execution, id);

    if (result == NULL || result->verdict == BRIX_CONFORM_VERDICT_SKIPPED) return;
    result->verdict = verdict;
    snprintf(result->reason, sizeof(result->reason), "%s",
        reason == NULL ? "" : reason);
    snprintf(result->expected, sizeof(result->expected), "%s",
        expected == NULL ? "" : expected);
    snprintf(result->received, sizeof(result->received), "%s",
        received == NULL ? "" : received);
}

/* ---- Enforce run resource ceilings before an operation ----
 *
 * WHAT: Reserves one request and bytes, or returns zero with a stable reason.
 * WHY: Remote assessment must remain bounded even against hostile endpoints.
 * HOW: Check wall time and overflow-safe request/byte ceilings before charging.
 */
int
xrd_conform_reserve(xrd_conform_execution *execution, size_t bytes,
    char *reason, size_t reason_size)
{
    time_t now;

    if (execution == NULL) return 0;
    now = time(NULL);
    if (now == (time_t) -1 || now - execution->started
        >= (time_t) execution->run->config.wall_seconds) {
        snprintf(reason, reason_size, "ceiling:wall-seconds");
        return 0;
    }
    if (execution->requests >= execution->run->config.request_limit) {
        snprintf(reason, reason_size, "ceiling:request-limit");
        return 0;
    }
    if ((unsigned long long) bytes > execution->run->config.byte_limit
        || execution->bytes > execution->run->config.byte_limit
            - (unsigned long long) bytes) {
        snprintf(reason, reason_size, "ceiling:byte-limit");
        return 0;
    }
    execution->requests++;
    execution->bytes += (unsigned long long) bytes;
    return 1;
}

/* ---- Seed the explicit result ledger ----
 *
 * WHAT: Allocates one result for every immutable clause and applies scope gates.
 * WHY: Filtered and unauthorized clauses must appear as skips, never disappear.
 * HOW: Copy catalogue pointers and ask the common scope resolver for each row.
 */
static int
results_init(xrd_conform_execution *execution)
{
    const brix_conform_clause *clauses;
    size_t count;
    size_t index;

    clauses = brix_conform_clauses(&count);
    execution->results.results = calloc(count, sizeof(*execution->results.results));
    if (execution->results.results == NULL) return -1;
    execution->results.count = count;
    for (index = 0; index < count; index++) {
        brix_conform_result *result = &execution->results.results[index];

        result->clause = &clauses[index];
        result->changed = 1;
        if (brix_conform_clause_selected(&clauses[index],
                &execution->run->config, result->reason,
                sizeof(result->reason))) {
            result->verdict = BRIX_CONFORM_VERDICT_INCONCLUSIVE;
            snprintf(result->reason, sizeof(result->reason),
                "probe-not-executed");
        } else {
            result->verdict = BRIX_CONFORM_VERDICT_SKIPPED;
        }
    }
    return 0;
}

/* ---- Grade the safety property established by result selection ----
 *
 * WHAT: Marks ADV-010 conformant when the adversarial family survived scope.
 * WHY: The family-wide selector now requires both mutation and disruption
 *      authority, so an active row is direct evidence of the asserted gate.
 * HOW: Replace only an active provisional row after the common scope pass.
 */
static void
grade_scope_safety(xrd_conform_execution *execution)
{
    brix_conform_result *row = xrd_conform_result_find(execution, "ADV-010");
    int injected = execution->run->adv_fixture_kind != NULL
        && strcmp(execution->run->adv_fixture_kind, "authority-bypass") == 0;

    if (row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED)
        xrd_conform_result_set(execution, "ADV-010",
            injected ? BRIX_CONFORM_VERDICT_DIVERGENT
                     : BRIX_CONFORM_VERDICT_CONFORMANT,
            injected ? "adversarial-corpus-authority-gate-bypassed"
                     : "adversarial-corpus-authority-gates-satisfied",
            "--allow-mutate, scratch, --allow-disrupt and exact confirmation",
            NULL);
}

/* ---- Infer a safe single-target web profile ----
 *
 * WHAT: Selects http/s3 scope when the operator omitted --profile.
 * WHY: The default is discovery, not an assertion that every family applies.
 * HOW: Narrow only one-target web runs; ROOT role discovery happens post-login.
 */
static void
infer_web_profile(xrd_conform_run *run)
{
    brix_weburl url;

    if (run->profile_explicit || run->also_count != 0
        || !brix_is_web_url(run->config.target)) return;
    if (brix_weburl_parse(run->config.target, &url) == 0)
        run->config.profile = url.is_s3 ? "s3" : "http";
}

/* ---- Verify declared hostile fixtures produced their promised red rows ----
 *
 * WHAT: Requires every --verify-negative row to have the emitted divergent verdict.
 * WHY: A named fixture is not §40 evidence unless its owning clause actually fails.
 * HOW: Resolve each stable ID after reference projection and fail closed otherwise.
 */
static int
negative_verification_passes(xrd_conform_execution *execution,
    int run_complete)
{
    size_t index;
    int passed = 1;

    if (!run_complete) {
        if (execution->run->negative_verify_count > 0)
            BRIX_CLIENT_LOG("ERROR",
                "xrd conform: negative fixture evidence rejected because the run is incomplete\n");
        return 0;
    }
    for (index = 0; index < execution->run->negative_verify_count; index++) {
        const char *id = execution->run->negative_verify[index];
        brix_conform_result *row = xrd_conform_result_find(execution, id);

        if (row != NULL && row->verdict == BRIX_CONFORM_VERDICT_DIVERGENT)
            continue;
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: negative fixture did not make %s divergent%s%s\n",
            id, row == NULL ? "" : ": ",
            row == NULL ? "row absent" : brix_conform_verdict_name(row->verdict));
        passed = 0;
    }
    return passed;
}

/* ---- Build an RFC3339 UTC timestamp ----
 *
 * WHAT: Writes the report timestamp, returning zero on success.
 * WHY: Artifact metadata must state when endpoint claims were observed.
 * HOW: Read wall clock, convert with gmtime_r and format a fixed UTC shape.
 */
static int
timestamp_now(char out[32])
{
    struct tm utc;
    time_t now = time(NULL);

    if (now == (time_t) -1 || gmtime_r(&now, &utc) == NULL) return -1;
    return strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0 ? -1 : 0;
}

/* ---- Run one explicitly named protocol plane ----
 *
 * WHAT: Dispatches one target URL and returns its completion status.
 * WHY: Primary and repeatable --also targets share identical runner semantics.
 * HOW: Bind the current target then choose web or root by shared URL detection.
 */
static int
run_target(xrd_conform_execution *execution, const char *target,
    int *used_root)
{
    execution->target = target;
    if (brix_is_web_url(target)) return xrd_conform_run_http(execution);
    if (brix_is_ftp_url(target)) return xrd_conform_run_ftp(execution);
    if (strncmp(target, "oci://", 6) == 0
        || strncmp(target, "oci+http://", 11) == 0)
        return xrd_conform_run_oci(execution);
    *used_root = 1;
    return xrd_conform_run_root(execution);
}

/* ---- Execute and report one remote conformance run ----
 *
 * WHAT: Returns the frozen Phase-118 exit code for a complete bounded run.
 * WHY: Network, ledger, artifact and verdict failures have distinct semantics.
 * HOW: Initialize, dispatch by URL plane, count, render, write bundle, decide.
 */
static int
execute_once(xrd_conform_run *run)
{
    xrd_conform_execution execution;
    brix_conform_report_meta meta;
    char timestamp[32];
    char report_error[256];
    char capture_directory[64] = "";
    char raw_capture[96] = "";
    int capture_enabled = 0;
    int negative_verified;
    int runner_rc = 0;
    int rc;
    size_t target_index;
    size_t repro_index;
    brix_conform_reproducer_frame
        repro_frames[XRDC_CONFORM_ADV_REPRO_MAX];

    memset(&execution, 0, sizeof(execution));
    execution.run = run;
    infer_web_profile(run);
    execution.started = time(NULL);
    if (execution.started == (time_t) -1 || results_init(&execution) != 0
        || timestamp_now(timestamp) != 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: cannot initialize run state\n");
        free(execution.results.results);
        return 3;
    }
    /* A conformance observation is one wire answer, not a resilient client
     * transaction. Retrying a hostile kXR_ServerError can both hide the answer
     * being assessed and exceed the run-level wall ceiling inside one reserved
     * request, because library resilience has its own stall window. */
    run->opts.no_retry = 1;
    grade_scope_safety(&execution);
    if (capture_staging(capture_directory, raw_capture) != 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: cannot create private capture staging\n");
        free(execution.results.results);
        return 3;
    }
    run->opts.capture = raw_capture;
    xrd_conform_probe_cache_pair(&execution);
    xrd_conform_probe_tpc_pair(&execution);
    if (!xrd_conform_tpc_exact_selected(&execution)
        && (run->cache_fixture_kind == NULL || run->config.only == NULL
            || (strcmp(run->config.only, "CAC-003") != 0
                && strcmp(run->config.only, "CAC-004") != 0
                && strcmp(run->config.only, "CAC-005") != 0
                && strcmp(run->config.only, "CAC-009") != 0))) {
        if (run_target(&execution, run->config.target, &capture_enabled) != 0)
            runner_rc = 3;
        for (target_index = 0; target_index < run->also_count; target_index++) {
            if (run_target(&execution, run->also[target_index],
                    &capture_enabled) != 0) runner_rc = 3;
        }
    }
    xrd_conform_probe_tls_fixtures(&execution);
    xrd_conform_finalize_tls(&execution);
    xrd_conform_finalize_s3_auth(&execution);
    xrd_conform_finalize_s3_readonly(&execution);
    xrd_conform_probe_readonly_fixtures(&execution);
    xrd_conform_probe_auth_fixtures(&execution);
    xrd_conform_probe_token_fixtures(&execution);
    xrd_conform_probe_denied_fixtures(&execution);
    xrd_conform_probe_mutation_fixtures(&execution);
    xrd_conform_probe_open_fixtures(&execution);
    xrd_conform_probe_cross_export_move(&execution);
    run->opts.capture = NULL;
    xrd_conform_grade_cross_plane(&execution);
    xrd_conform_finalize_checksums(&execution);
    xrd_conform_finalize_traversal(&execution);
    xrd_conform_finalize_case(&execution);
    xrd_conform_finalize_namespace(&execution);
    xrd_conform_finalize_filenames(&execution);
    xrd_conform_finalize_claim_audit(&execution);
    xrd_conform_finalize_fixture_gates(&execution);
    brix_conform_apply_reference_mode(&run->config, &execution.results);
    if (run->config.baseline != NULL
        && brix_conform_apply_baseline(run->config.baseline,
            &execution.results, report_error, sizeof(report_error)) != 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: baseline rejected: %s\n", report_error);
        runner_rc = 3;
    }
    negative_verified = negative_verification_passes(&execution,
        runner_rc == 0);
    if (!negative_verified) runner_rc = 3;
    brix_conform_run_results_count(&execution.results);
    memset(&meta, 0, sizeof(meta));
    meta.target = run->config.target;
    meta.also_targets = run->also;
    meta.also_target_count = run->also_count;
    meta.profile = run->config.profile;
    meta.shape = shape_name(run->config.shape);
    meta.budget = brix_conform_budget_name(run->config.budget);
    meta.reference = reference_name(run->config.reference_mode);
    meta.run_key = run->config.run_key;
    meta.timestamp = timestamp;
    meta.tool_version = brix_client_version();
    meta.negative_verify = run->negative_verify;
    meta.negative_verify_count = run->negative_verify_count;
    meta.negative_verify_passed = negative_verified;
    meta.requests = execution.requests;
    meta.bytes = execution.bytes;
    meta.request_limit = run->config.request_limit;
    meta.byte_limit = run->config.byte_limit;
    meta.wall_seconds = run->config.wall_seconds;
    brix_conform_report_terminal(stdout, &meta, &execution.results);
    if (brix_conform_report_bundle(run->config.out_dir, &meta,
            &execution.results, report_error, sizeof(report_error)) != 0) {
        BRIX_CLIENT_LOG("ERROR", "xrd conform: %s\n", report_error);
        runner_rc = 3;
    } else {
        for (repro_index = 0;
             repro_index < execution.adv_reproducer_count; repro_index++) {
            repro_frames[repro_index].sid =
                execution.adv_reproducers[repro_index].sid;
            repro_frames[repro_index].code =
                execution.adv_reproducers[repro_index].code;
            repro_frames[repro_index].wire =
                execution.adv_reproducers[repro_index].wire;
            repro_frames[repro_index].wire_length =
                execution.adv_reproducers[repro_index].wire_length;
        }
        if (execution.adv_reproducer_count > 0
            && brix_conform_capture_reproducer(run->config.out_dir,
                "ADV-008", repro_frames, execution.adv_reproducer_count,
                report_error, sizeof(report_error)) != 0) {
            BRIX_CLIENT_LOG("ERROR", "xrd conform: %s\n", report_error);
            runner_rc = 3;
        }
        if (capture_enabled && access(raw_capture, R_OK) == 0
            && brix_conform_capture_artifacts(run->config.out_dir, raw_capture,
                &execution.results, report_error, sizeof(report_error)) != 0) {
            BRIX_CLIENT_LOG("ERROR", "xrd conform: %s\n", report_error);
            runner_rc = 3;
        }
    }
    /* Recount at the exit boundary so renderer activity can never leave the
     * process status out of step with the verdicts in the durable bundle. */
    brix_conform_run_results_count(&execution.results);
    rc = runner_rc == 0
        ? brix_conform_run_exit_code(&run->config, &execution.results)
        : runner_rc;
    free(execution.results.results);
    capture_staging_remove(capture_directory, raw_capture);
    return rc;
}

/* ---- Keep one hostile network wait inside the run wall budget ----
 *
 * WHAT: Clamps connect/handshake and steady-state idle waits to half the
 *       configured conformance wall ceiling.
 * WHY: The run ceiling is checked between probes, so a peer that accepts TCP
 *      and then black-holes TLS could otherwise spend the default 15-second
 *      bring-up timeout inside a ten-second assessment.
 * HOW: Preserve stricter operator/library settings and lower only longer waits;
 *      reserve the other half for result classification and report emission.
 */
static void
bound_network_waits(const xrd_conform_run *run)
{
    unsigned long long half_ms = (unsigned long long) run->config.wall_seconds
        * 1000ULL / 2ULL;
    int limit;

    if (half_ms == 0) half_ms = 1;
    limit = half_ms > (unsigned long long) INT_MAX ? INT_MAX : (int) half_ms;
    if (brix_tmo_connect_ms() > limit) brix_tmo_set_connect_ms(limit);
    if (brix_tmo_io_ms() > limit) brix_tmo_set_io_ms(limit);
}

/* ---- Sleep between watch duty-cycle samples ----
 *
 * WHAT: Waits the configured interval, resuming after signal interruptions.
 * WHY: Watch must state and enforce its steady-state duty cycle.
 * HOW: Repeat nanosleep with the returned remainder until fully elapsed.
 */
static void
watch_sleep(unsigned seconds)
{
    struct timespec delay;
    struct timespec remaining;

    delay.tv_sec = (time_t) seconds;
    delay.tv_nsec = 0;
    while (nanosleep(&delay, &remaining) != 0 && errno == EINTR)
        delay = remaining;
}

/* ---- Execute one-shot or continuous conformance shapes ----
 *
 * WHAT: Runs accept/full once and watch on a fixed sampling duty cycle.
 * WHY: A one-shot command labelled watch is operationally dishonest.
 * HOW: Reinitialize each sample, publish current artifacts, sleep, repeat;
 *      finite --watch-cycles exists for supervision and deterministic tests.
 */
static int
execute_watch(xrd_conform_run *run)
{
    unsigned cycle = 0;
    int aggregate = 0;

    if (run->config.shape != BRIX_CONFORM_RUN_WATCH)
        return execute_once(run);
    for (;;) {
        int rc = execute_once(run);

        if (rc == 3 || rc == 4) return rc;
        if (rc == 1) aggregate = 1;
        else if (rc == 2 && aggregate == 0) aggregate = 2;
        cycle++;
        if (run->config.watch_cycles != 0
            && cycle >= run->config.watch_cycles) return aggregate;
        fflush(stdout);
        watch_sleep(run->config.watch_interval_seconds);
    }
}

int
xrd_conform_execute(xrd_conform_run *run)
{
    int rc;

    bound_network_waits(run);
    if (!brix_crypto_init()) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: cannot initialize cryptographic primitives\n");
        return 3;
    }
    rc = run->config.shape == BRIX_CONFORM_RUN_WATCH
        ? execute_watch(run) : execute_once(run);
    brix_crypto_cleanup();
    return rc;
}
