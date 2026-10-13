/* Phase-118 typed root:// object, byte-read and CRC-checked page probes. */
#include "xrd_conform_internal.h"

#include <stdint.h>

#define CONFORM_READ_CHUNK 65536U
#define CONFORM_PLANTED_SIZE 65536U

/* ---- Narrow an implicit ROOT profile from authenticated protocol claims ----
 *
 * WHAT: Reclassifies untouched ledger rows using the observed server role.
 * WHY: Default scope must follow discovery rather than assume every family.
 * HOW: Prefer cache/proxy attributes, then manager/data role bits; preserve
 *      explicit profiles and multi-plane unions, and never widen prior scope.
 */
static void
apply_discovered_profile(xrd_conform_execution *execution, uint32_t flags)
{
    const char *profile = "full";
    size_t index;

    if (execution->run->profile_explicit
        || execution->run->also_count != 0) return;
    if ((flags & kXR_attrCache) != 0) profile = "cache";
    else if ((flags & kXR_attrProxy) != 0) profile = "proxy";
    else if ((flags & kXR_isManager) != 0
        && (flags & kXR_isServer) == 0) profile = "manager";
    else if ((flags & kXR_isServer) != 0
        && (flags & kXR_isManager) == 0) profile = "data";
    execution->run->config.profile = profile;
    for (index = 0; index < execution->results.count; index++) {
        brix_conform_result *result = &execution->results.results[index];

        if (result->verdict != BRIX_CONFORM_VERDICT_INCONCLUSIVE) continue;
        if (!brix_conform_clause_selected(result->clause,
                &execution->run->config, result->reason,
                sizeof(result->reason)))
            result->verdict = BRIX_CONFORM_VERDICT_SKIPPED;
    }
}

/* ---- Mark every selected row in a family with one verdict ----
 *
 * WHAT: Applies an explicit family-wide result to rows not filtered from scope.
 * WHY: A missing advertised capability has one mandated skip reason per row.
 * HOW: Walk results, match family, preserve already-skipped scope decisions.
 */
static void
family_result(xrd_conform_execution *execution, const char *family,
    brix_conform_verdict verdict, const char *reason)
{
    size_t index;

    for (index = 0; index < execution->results.count; index++) {
        brix_conform_result *result = &execution->results.results[index];

        if (strcmp(result->clause->family, family) != 0
            || result->verdict == BRIX_CONFORM_VERDICT_SKIPPED) continue;
        result->verdict = verdict;
        snprintf(result->reason, sizeof(result->reason), "%s", reason);
    }
}

/* ---- Plant one bounded deterministic remote object ----
 *
 * WHAT: Creates/truncates path and writes PRF bytes through the typed API.
 * WHY: A planted object gives read probes an independent content oracle.
 * HOW: Generate and write 64 KiB chunks, under the prior scratch path gate.
 */
int
xrd_conform_plant_object(xrd_conform_execution *execution,
    brix_conn *connection,
    const xrd_conform_scratch_object *object, uint64_t size,
    brix_status *status)
{
    uint8_t buffer[CONFORM_READ_CHUNK];
    brix_file file;
    uint64_t offset = 0;
    char reason[64];

    if (brix_file_open_write(connection, object->path, 1, 0, &file, status) != 0)
        return -1;
    while (offset < size) {
        size_t length = size - offset < sizeof(buffer)
            ? (size_t) (size - offset) : sizeof(buffer);

        if (!xrd_conform_reserve(execution, length, reason, sizeof(reason))) {
            brix_file_close(connection, &file, status);
            brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
            return -1;
        }
        brix_conform_fill(&execution->run->key, offset, buffer, length);
        if (brix_file_write(connection, &file, (int64_t) offset, buffer,
                length, status) != 0) {
            brix_file_close(connection, &file, status);
            return -1;
        }
        offset += length;
    }
    return brix_file_close(connection, &file, status);
}

/* ---- Read an entire object under configured ceilings ----
 *
 * WHAT: Returns an owned byte oracle for the remote object.
 * WHY: Read-only degraded mode must learn content before grading fragments.
 * HOW: Allocate the stat size, read sequential chunks and reject short data.
 */
uint8_t *
xrd_conform_read_baseline(xrd_conform_execution *execution,
    brix_conn *connection,
    brix_file *file, uint64_t size, brix_status *status)
{
    uint8_t *bytes;
    uint64_t offset = 0;
    char reason[64];

    if (size > SIZE_MAX || size > execution->run->config.byte_limit) {
        brix_status_set(status, XRDC_EUSAGE, 0, "object exceeds byte ceiling");
        return NULL;
    }
    bytes = malloc(size == 0 ? 1 : (size_t) size);
    if (bytes == NULL) {
        brix_status_set(status, XRDC_EIO, errno, "baseline allocation failed");
        return NULL;
    }
    while (offset < size) {
        size_t length = size - offset < CONFORM_READ_CHUNK
            ? (size_t) (size - offset) : CONFORM_READ_CHUNK;
        ssize_t got;

        if (!xrd_conform_reserve(execution, length, reason, sizeof(reason))) {
            brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
            free(bytes);
            return NULL;
        }
        got = brix_file_read(connection, file, (int64_t) offset,
            bytes + offset, length, status);
        if (got != (ssize_t) length) {
            if (got >= 0) brix_status_set(status, XRDC_EPROTO, 0,
                "short baseline read at %llu", (unsigned long long) offset);
            free(bytes);
            return NULL;
        }
        offset += length;
    }
    return bytes;
}

/* ---- Grade one ordinary read against learned bytes ----
 *
 * WHAT: Issues a bounded read and records exact length/content conformance.
 * WHY: RD boundary clauses require direct evidence at their named extent.
 * HOW: Reserve resources, call typed read, compare return and optional bytes.
 */
void
xrd_conform_grade_read(xrd_conform_execution *execution,
    brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size, const char *id,
    int64_t offset, size_t requested)
{
    uint8_t *buffer;
    uint64_t available;
    size_t expected;
    ssize_t got;
    brix_status status;
    char reason[64];
    char expected_text[64];
    char received_text[96];

    if (offset < 0) available = 0;
    else available = (uint64_t) offset < size ? size - (uint64_t) offset : 0;
    expected = available < requested ? (size_t) available : requested;
    buffer = malloc(requested == 0 ? 1 : requested);
    if (buffer == NULL) {
        xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "local-allocation-failed", NULL, NULL);
        return;
    }
    if (!xrd_conform_reserve(execution, requested, reason, sizeof(reason))) {
        xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            reason, NULL, NULL);
        free(buffer);
        return;
    }
    brix_status_clear(&status);
    got = brix_file_read(connection, file, offset, buffer, requested, &status);
    snprintf(expected_text, sizeof(expected_text), "length=%zu byte-exact", expected);
    snprintf(received_text, sizeof(received_text), "length=%lld kxr=%d",
        (long long) got, status.kxr);
    if (got == (ssize_t) expected
        && (expected == 0 || memcmp(buffer, baseline + (size_t) offset,
                expected) == 0)) {
        xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_CONFORMANT,
            "typed-read-byte-exact", expected_text, received_text);
    } else {
        xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_DIVERGENT,
            got < 0 ? "typed-read-error" : "read-length-or-content-mismatch",
            expected_text, received_text);
    }
    free(buffer);
}

/* WHAT: Prove that a negative signed offset is rejected as an argument error.
 * WHY: Unsigned reinterpretation can expose unrelated data or provoke huge I/O.
 * HOW: Send a one-byte typed read and require kXR_ArgInvalid with no payload. */
static void
grade_invalid_offset(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *id, int64_t offset)
{
    uint8_t byte;
    brix_status status;
    char reason[64];
    ssize_t got;

    if (!xrd_conform_reserve(execution, 1, reason, sizeof(reason))) {
        xrd_conform_result_set(execution, id,
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL, NULL);
        return;
    }
    brix_status_clear(&status);
    got = brix_file_read(connection, file, offset, &byte, 1, &status);
    xrd_conform_result_set(execution, id,
        got < 0 && status.kxr == kXR_ArgInvalid
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        got < 0 && status.kxr == kXR_ArgInvalid
            ? "negative-offset-rejected" : "negative-offset-wrong-answer",
        "kXR_ArgInvalid", status.msg);
    xrd_conform_result_set(execution, "ERR-002",
        got < 0 && status.kxr == kXR_ArgInvalid
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        got < 0 && status.kxr == kXR_ArgInvalid
            ? "einval-mapped-to-arg-invalid" : "einval-mapping-mismatch",
        "kXR_ArgInvalid", status.msg);
}

/* ---- Grade selected RD assertions with a byte oracle ----
 *
 * WHAT: Runs the safe boundary/idempotence subset of the RD ledger.
 * WHY: These assertions are fully observable through the typed read API.
 * HOW: Exercise exact named offsets, then separately test negative offset.
 */
void
xrd_conform_run_rd(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size)
{
    uint64_t offset;

    if (size <= SIZE_MAX) xrd_conform_grade_read(execution, connection, file, baseline,
        size, "RD-001", 0, (size_t) size);
    xrd_conform_grade_read(execution, connection, file, baseline, size, "RD-002", 0, 0);
    if (size <= INT64_MAX) {
        xrd_conform_grade_read(execution, connection, file, baseline, size, "RD-003",
            (int64_t) size, 1);
        if (size < INT64_MAX) xrd_conform_grade_read(execution, connection, file, baseline,
            size, "RD-004", (int64_t) size + 1, 1);
    }
    if (size > 0) {
        xrd_conform_grade_read(execution, connection, file, baseline, size, "RD-005",
            (int64_t) size - 1, 2);
        xrd_conform_grade_read(execution, connection, file, baseline, size, "RD-006", 0, 1);
        xrd_conform_grade_read(execution, connection, file, baseline, size, "RD-007",
            (int64_t) size - 1, 1);
    }
    for (offset = 4095; offset <= 4097; offset++) {
        if (offset < size) xrd_conform_grade_read(execution, connection, file, baseline,
            size, "RD-008", (int64_t) offset, 1);
    }
    if (size == 0) xrd_conform_grade_read(execution, connection, file, baseline, size,
        "RD-010", 0, 1);
    if (size > 0) {
        xrd_conform_grade_read(execution, connection, file, baseline, size, "RD-015", 0,
            size < 4096 ? (size_t) size : 4096);
        xrd_conform_grade_read(execution, connection, file, baseline, size, "RD-015", 0,
            size < 4096 ? (size_t) size : 4096);
    }
    grade_invalid_offset(execution, connection, file, "RD-030", -1);
    grade_invalid_offset(execution, connection, file, "RD-032", INT64_MIN);
    xrd_conform_probe_read_partitions(execution, connection, file, baseline,
        size);
    xrd_conform_probe_read_substreams(execution, connection, file, baseline,
        size);
}

/* WHAT: Grade use-after-close and double-close refusal on the retained handle.
 * WHY: Stale handles must never alias another file or silently succeed.
 * HOW: Issue one read and one second close, requiring kXR_FileNotOpen. */
static void
probe_closed_handle(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file)
{
    uint8_t byte;
    brix_status status;
    char reason[64];
    ssize_t got;

    if (xrd_conform_reserve(execution, 1, reason, sizeof(reason))) {
        brix_status_clear(&status);
        got = brix_file_read(connection, file, 0, &byte, 1, &status);
        xrd_conform_result_set(execution, "RD-018",
            got < 0 && status.kxr == kXR_FileNotOpen
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
            got < 0 && status.kxr == kXR_FileNotOpen
                ? "closed-handle-refused" : "closed-handle-wrong-answer",
            "kXR_FileNotOpen", status.msg);
    }
    if (xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        brix_status_clear(&status);
        xrd_conform_result_set(execution, "OPN-030",
            brix_file_close(connection, file, &status) != 0
                && status.kxr == kXR_FileNotOpen
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
            status.kxr == kXR_FileNotOpen
                ? "double-close-refused" : "double-close-wrong-answer",
            "kXR_FileNotOpen", status.msg);
    }
}

/* ---- Grade typed pgread byte and CRC properties ----
 *
 * WHAT: Compares one fractional pgread to ordinary bytes and CRC validation.
 * WHY: The typed API exposes byte equality and fails on every bad page CRC.
 * HOW: Skip on absent claim; otherwise request a cross-page fractional extent.
 */
void
xrd_conform_run_pgr(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size)
{
    if ((connection->server_flags & kXR_suppgrw) == 0) {
        family_result(execution, "PGR", BRIX_CONFORM_VERDICT_SKIPPED,
            "claim-absent:kXR_suppgrw");
        return;
    }
    xrd_conform_probe_pgread(execution, connection, file, baseline, size);
}

/* ---- Select or plant the root object path ----
 *
 * WHAT: Returns the adopted URL path or a builder-bound planted scratch path.
 * WHY: Mutation authority and path confinement must be resolved before probing.
 * HOW: Use URL path read-only; with authority build and plant the fixed Q object.
 */
static int
prepare_root_path(xrd_conform_execution *execution, brix_conn *connection,
    const brix_url *url, xrd_conform_scratch_object *scratch_object,
    const char **path, int *planted, brix_status *status)
{
    *path = url->path;
    *planted = 0;
    if (!execution->run->config.allow_mutate) return 0;
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-Q", scratch_object->path,
            sizeof(scratch_object->path)) != 0) return -1;
    if (xrd_conform_plant_object(execution, connection, scratch_object,
            CONFORM_PLANTED_SIZE, status) != 0)
        return -1;
    *path = scratch_object->path;
    *planted = 1;
    return 0;
}

/* ---- Probe one open root object ----
 *
 * WHAT: Learns the baseline, runs RD/PGR and records cross-plane digest facts.
 * WHY: Object/read ownership should be independent from connection cleanup.
 * HOW: Stat, open, slurp under ceilings, grade, close on every open path.
 */
static int
probe_root_object(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, brix_status *status)
{
    brix_statinfo statinfo;
    brix_file file;
    uint8_t *baseline;
    brix_status close_status;
    int connection_poisoned = 0;
    int rc = -1;

    brix_status_clear(status);
    if (brix_stat(connection, path, &statinfo, status) != 0
        || statinfo.size < 0 || (statinfo.flags & kXR_isDir) != 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: target object is not readable: %s\n",
            status->msg);
        return -1;
    }
    if (brix_file_open_read(connection, path, &file, status) != 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: target object open failed: %s\n",
            status->msg);
        return -1;
    }
    baseline = xrd_conform_read_baseline(execution, connection, &file,
        (uint64_t) statinfo.size, status);
    if (baseline == NULL) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: baseline read failed: %s\n", status->msg);
    } else {
        connection_poisoned = xrd_conform_probe_selected_object(execution,
            connection, &file, path, baseline, (uint64_t) statinfo.size);
        rc = 0;
    }
    free(baseline);
    if (connection_poisoned) return rc;
    brix_status_clear(&close_status);
    if (brix_file_close(connection, &file, &close_status) != 0) rc = -1;
    else probe_closed_handle(execution, connection, &file);
    return rc;
}

/* ---- Remove an authorized planted object ----
 *
 * WHAT: Returns zero for no plant or successful typed remote removal.
 * WHY: A conformance run must not leave its scratch corpus behind silently.
 * HOW: Call brix_rm only with the prefix-bound capability member.
 */
static int
cleanup_root_path(brix_conn *connection,
    const xrd_conform_scratch_object *scratch_object, int planted)
{
    brix_status status;

    if (!planted) return 0;
    brix_status_clear(&status);
    if (brix_rm(connection, scratch_object->path, &status) == 0) return 0;
    BRIX_CLIENT_LOG("ERROR",
        "xrd conform: scratch cleanup failed for %s: %s\n",
        scratch_object->path, status.msg);
    return -1;
}

/* ---- Run the root read-plane assessment ----
 *
 * WHAT: Returns zero after usable endpoint evidence, or run-incomplete code 3.
 * WHY: Parse/connect/stat/open failures prevent any protocol conclusion.
 * HOW: Optionally plant beneath scratch, learn a baseline, probe and clean up.
 */
int
xrd_conform_run_root(xrd_conform_execution *execution)
{
    brix_url url;
    brix_conn connection;
    brix_status status;
    xrd_conform_scratch_object scratch_object;
    const char *path;
    int planted = 0;
    int rc = 3;

    brix_status_clear(&status);
    if (brix_endpoint_parse(execution->target, &url, &status) != 0
        || (url.scheme != XRDC_SCHEME_ROOT && url.scheme != XRDC_SCHEME_ROOTS)) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: target is not a valid root:// URL: %s\n",
            status.msg);
        return 3;
    }
    if (brix_connect(&connection, &url, &execution->run->opts, &status) != 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: target connection failed: %s\n", status.msg);
        if (execution->run->config.only != NULL
            && strcmp(execution->run->config.only, "LOG-004") == 0
            && strstr(status.msg, "no usable auth protocol") != NULL) {
            xrd_conform_result_set(execution, "LOG-004",
                BRIX_CONFORM_VERDICT_DIVERGENT,
                "security-continuation-names-no-mechanism",
                "at least one &P= mechanism", status.msg);
            return 0;
        }
        if (execution->run->config.only != NULL
            && strcmp(execution->run->config.only, "TLS-001") == 0
            && (strstr(status.msg, "TLS") != NULL
                || strstr(status.msg, "SSL") != NULL)) {
            xrd_conform_result_set(execution, "TLS-001",
                BRIX_CONFORM_VERDICT_DIVERGENT,
                "gototls-upgrade-failed", "working TLS upgrade", status.msg);
            return 0;
        }
        return 3;
    }
    apply_discovered_profile(execution, connection.server_flags);
    xrd_conform_probe_protocol_claims(execution, &url, &connection);
    xrd_conform_probe_cms_manager(execution, &connection, url.path);
    xrd_conform_probe_handshake_negatives(execution, &url);
    xrd_conform_probe_framing(execution, &url);
    xrd_conform_probe_framing_hostile(execution, &url);
    xrd_conform_probe_login(execution, &url, &connection);
    xrd_conform_probe_tls(execution, &url, &connection, 0);
    xrd_conform_probe_flow(execution, &url);
    if (xrd_conform_readonly_exact_selected(execution)) {
        xrd_conform_probe_readonly_exact(execution, &connection);
        rc = 0;
    } else if (xrd_conform_error_fixture_exact_selected(execution)
        || xrd_conform_cms_outage_exact_selected(execution)
        || !xrd_conform_root_object_needed(execution)) {
        rc = 0;
    } else if (prepare_root_path(execution, &connection, &url, &scratch_object, &path,
            &planted, &status) != 0)
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: cannot plant scratch object: %s\n",
            status.msg);
    else if (probe_root_object(execution, &connection, path, &status) == 0) {
        rc = 0;
        xrd_conform_probe_tls(execution, &url, &connection, 1);
        xrd_conform_probe_claim_audit(execution, &url, &connection);
        xrd_conform_probe_adversarial(execution, &url, &connection, path);
        if (planted && xrd_conform_standard_corpus_needed(execution)
            && (xrd_conform_family_active(execution, "RD")
                || xrd_conform_family_active(execution, "PGR")
                || xrd_conform_family_active(execution, "RDV")
                || xrd_conform_family_active(execution, "CHU"))
            && xrd_conform_probe_standard_corpus(execution, &connection) != 0)
            rc = 3;
        if (planted && xrd_conform_large_offset_needed(execution)
            && (xrd_conform_family_active(execution, "RD")
                || xrd_conform_family_active(execution, "PGR"))
            && xrd_conform_probe_large_offset(execution,
                &connection) != 0) rc = 3;
        if (planted && xrd_conform_write_only_needed(execution)
            && (xrd_conform_family_active(execution, "RD")
                || xrd_conform_family_active(execution, "PGR"))
            && xrd_conform_probe_write_only(execution,
                &connection) != 0) rc = 3;
        if (planted)
            xrd_conform_probe_namespace_mutations(execution, &connection);
        if (planted)
            xrd_conform_probe_open_mutations(execution, &connection);
        if (planted)
            xrd_conform_probe_checkpoints(execution, &connection);
        if (planted)
            xrd_conform_probe_prepare(execution, &connection, path);
        if (planted)
            xrd_conform_probe_write_mutations(execution, &connection);
    } else if (execution->run->config.only != NULL
        && strcmp(execution->run->config.only, "OPN-001") == 0) {
        xrd_conform_result_set(execution, "OPN-001",
            BRIX_CONFORM_VERDICT_DIVERGENT,
            "read-open-did-not-return-handle", "4-byte fhandle", status.msg);
        rc = 0;
    } else if (execution->run->config.only != NULL
        && strcmp(execution->run->config.only, "TLS-003") == 0
        && connection.io.ssl == NULL && status.kxr == kXR_TLSRequired) {
        xrd_conform_result_set(execution, "TLS-003",
            BRIX_CONFORM_VERDICT_DIVERGENT,
            "unflagged-data-over-enforced-as-tls",
            "cleartext data response", status.msg);
        rc = 0;
    } else if (execution->run->config.only != NULL
        && strcmp(execution->run->config.only, "TLS-004") == 0
        && connection.io.ssl != NULL) {
        xrd_conform_result_set(execution, "TLS-004",
            BRIX_CONFORM_VERDICT_DIVERGENT,
            "tls-data-framing-invalid", "encrypted framed object",
            status.msg);
        rc = 0;
    }
    xrd_conform_probe_error_fixtures(execution);
    xrd_conform_probe_http_error_fixtures(execution);
    if (cleanup_root_path(&connection, &scratch_object, planted) != 0) rc = 3;
    brix_close(&connection);
    return rc;
}
