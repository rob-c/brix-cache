/* Phase-118 scratch-confined ROOT write-plane probes. */
#include "xrd_conform_probe_helpers.h"
#include "protocols/root/protocol/frame_hdr.h"





static int
open_write(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, int force, brix_file *file,
    brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_file_open_write(connection, object->path, force, 0, file, status);
}

static int
close_file(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_file_close(connection, file, status);
}

static int
write_file(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, int64_t offset, const void *data, size_t length,
    brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, length, status)) return -1;
    return brix_file_write(connection, file, offset, data, length, status);
}

static int
read_exact(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, int64_t offset, void *data,
    size_t length, brix_status *status)
{
    brix_file file;
    ssize_t got;
    int rc = -1;

    if (!xrd_conform_reserve_status(execution, 0, status)
        || brix_file_open_read(connection, object->path, &file, status) != 0)
        return -1;
    if (xrd_conform_reserve_status(execution, length, status)) {
        got = brix_file_read(connection, &file, offset, data, length, status);
        rc = got == (ssize_t) length ? 0 : -1;
    }
    if (close_file(execution, connection, &file, status) != 0) rc = -1;
    return rc;
}

static int
stat_object(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_statinfo *info,
    brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_stat(connection, object->path, info, status);
}

static int
truncate_object(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, int64_t size,
    brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_truncate(connection, object->path, size, status);
}

static int
truncate_handle(xrd_conform_execution *execution, brix_conn *connection,
    const brix_file *file, int64_t size, brix_status *status)
{
    ClientTruncateRequest request;
    xrdw_truncate_req_t fields = { .offset = size };
    uint16_t wire_status = 0;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_resp_out response = { &wire_status, &body, &body_length };
    int rc;

    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    memcpy(fields.fhandle, file->fhandle, sizeof(fields.fhandle));
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_truncate);
    xrdw_truncate_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    rc = brix_roundtrip(connection, &request, NULL, &response, status);
    free(body);
    return rc == 0 && wire_status == kXR_ok && body_length == 0 ? 0 : -1;
}

static int
remove_object(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_rm(connection, object->path, status);
}

static int
probe_initial_write(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    static const uint8_t initial[] = { 'a', 'b', 'c' };
    uint8_t actual[sizeof(initial)];
    brix_file file;
    int rc = open_write(execution, connection, object, 1, &file, status);

    if (rc == 0) rc = write_file(execution, connection, &file, 0, initial,
        sizeof(initial), status);
    if (rc == 0) rc = close_file(execution, connection, &file, status);
    if (rc == 0) rc = read_exact(execution, connection, object, 0, actual,
        sizeof(actual), status);
    xrd_conform_grade_status(execution, "WRT-001", rc == 0
        && memcmp(actual, initial, sizeof(initial)) == 0,
        "write-at-eof-extended-exactly", "write-at-eof-mismatch", status);
    return rc;
}

static int
probe_sparse_write(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, uint8_t *actual,
    brix_status *status)
{
    brix_file file;
    size_t index;
    int rc = -1;
    int hole_ok;

    if (open_write(execution, connection, object, 2, &file, status) == 0) {
        rc = write_file(execution, connection, &file, 8192, "Z", 1, status);
        close_file(execution, connection, &file, status);
    }
    memset(actual, 0xff, 8193);
    if (rc == 0)
        rc = read_exact(execution, connection, object, 0, actual, 8193, status);
    hole_ok = rc == 0 && actual[0] == 'a' && actual[1] == 'b'
        && actual[2] == 'c' && actual[8192] == 'Z';
    for (index = 3; hole_ok && index < 8192; index++)
        hole_ok = actual[index] == 0;
    xrd_conform_grade_status(execution, "WRT-002", hole_ok,
        "beyond-eof-write-created-zero-hole", "sparse-hole-mismatch", status);
    return rc;
}

static void
probe_zero_and_overlap(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object,
    uint8_t *actual, brix_status *status)
{
    static const uint8_t overlap[] = { 'X', 'Y' };
    brix_statinfo info;
    brix_file file;
    int rc = -1;

    stat_object(execution, connection, object, &info, status);
    if (open_write(execution, connection, object, 2, &file, status) == 0) {
        rc = write_file(execution, connection, &file, 0, actual, 0, status);
        close_file(execution, connection, &file, status);
    }
    xrd_conform_grade_status(execution, "WRT-003", rc == 0
        && stat_object(execution, connection, object, &info, status) == 0
        && info.size == 8193, "zero-write-preserved-size",
        "zero-write-changed-size", status);
    if (!xrd_conform_row_active(execution, "WRT-004")) return;
    if (open_write(execution, connection, object, 2, &file, status) == 0) {
        rc = write_file(execution, connection, &file, 1, overlap,
            sizeof(overlap), status);
        close_file(execution, connection, &file, status);
    }
    if (rc == 0)
        rc = read_exact(execution, connection, object, 0, actual, 3, status);
    xrd_conform_grade_status(execution, "WRT-004", rc == 0 && memcmp(actual, "aXY", 3) == 0,
        "overlap-last-write-won", "overlap-write-mismatch", status);
}

static void
probe_invalid_writes(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object,
    brix_status *status)
{
    brix_file file;
    int rc = -1;
    int negative_kxr;

    if (xrd_conform_row_active(execution, "WRT-005")) {
        if (xrd_conform_reserve_status(execution, 0, status)
            && brix_file_open_read(connection, object->path, &file,
                status) == 0) {
            rc = write_file(execution, connection, &file, 0, "Q", 1, status);
            close_file(execution, connection, &file, status);
        }
        xrd_conform_grade_status(execution, "WRT-005", rc != 0, "read-only-handle-write-refused",
            "read-only-handle-writable", status);
    }
    if (!xrd_conform_row_active(execution, "WRT-009")) return;
    if (open_write(execution, connection, object, 2, &file, status) == 0) {
        rc = write_file(execution, connection, &file, -1, "Q", 1, status);
        negative_kxr = status->kxr;
        close_file(execution, connection, &file, status);
    } else {
        negative_kxr = status->kxr;
    }
    xrd_conform_grade_status(execution, "WRT-009", rc != 0 && negative_kxr == kXR_ArgInvalid,
        "negative-write-offset-refused", "negative-write-offset-wrong-answer",
        status);
}

static void
probe_write(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object)
{
    uint8_t actual[8193];
    brix_status status;

    brix_status_clear(&status);
    probe_initial_write(execution, connection, object, &status);
    if (!xrd_conform_row_active(execution, "WRT-002")
        && !xrd_conform_row_active(execution, "WRT-003")
        && !xrd_conform_row_active(execution, "WRT-004")
        && !xrd_conform_row_active(execution, "WRT-005")
        && !xrd_conform_row_active(execution, "WRT-009")) return;

    probe_sparse_write(execution, connection, object, actual, &status);
    if (!xrd_conform_row_active(execution, "WRT-003")
        && !xrd_conform_row_active(execution, "WRT-004")
        && !xrd_conform_row_active(execution, "WRT-005")
        && !xrd_conform_row_active(execution, "WRT-009")) return;

    probe_zero_and_overlap(execution, connection, object, actual, &status);
    if (!xrd_conform_row_active(execution, "WRT-004")
        && !xrd_conform_row_active(execution, "WRT-005")
        && !xrd_conform_row_active(execution, "WRT-009")) return;

    probe_invalid_writes(execution, connection, object, &status);
}

static void
grade_writev_absent(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object,
    brix_file *file, brix_status *status)
{
    brix_statinfo info;
    int rc;

    if (xrd_conform_reserve_status(execution, 0, status)) {
        brix_status_clear(status);
        rc = brix_file_sync(connection, file, status);
        xrd_conform_grade_status(execution, "SYN-001", rc == 0, "sync-completed",
            "sync-failed", status);
    }
    close_file(execution, connection, file, status);
    rc = stat_object(execution, connection, object, &info, status);
    xrd_conform_grade_status(execution, "WVC-005", rc == 0 && info.size == 0,
        "unsupported-writev-left-object-unmodified",
        "unsupported-writev-partially-modified-object", status);
    xrd_conform_result_set(execution, "WVC-001",
        BRIX_CONFORM_VERDICT_SKIPPED, "capability-absent:writev", NULL, NULL);
    xrd_conform_result_set(execution, "WVC-003",
        BRIX_CONFORM_VERDICT_SKIPPED, "capability-absent:writev", NULL, NULL);
    xrd_conform_result_set(execution, "WVC-004",
        BRIX_CONFORM_VERDICT_SKIPPED, "capability-absent:writev", NULL, NULL);
}

static void
probe_read_sync(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    brix_file file;
    int rc;

    if (xrd_conform_reserve_status(execution, 0, status)
        && brix_file_open_read(connection, object->path, &file, status) == 0) {
        if (xrd_conform_reserve_status(execution, 0, status)) {
            rc = brix_file_sync(connection, &file, status);
            xrd_conform_grade_status(execution, "SYN-002", rc == 0 || status->kxr != kXR_ServerError,
                "read-handle-sync-defined", "read-handle-sync-server-error",
                status);
        }
        close_file(execution, connection, &file, status);
    }
}

static void
grade_writev_readback(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object,
    const uint8_t *left, size_t left_size, const uint8_t *right,
    size_t right_size, brix_status *status)
{
    uint8_t actual[14] = { 0 };
    int exact = 0;

    if (read_exact(execution, connection, object, 0, actual, sizeof(actual),
            status) == 0)
        exact = memcmp(actual, left, left_size) == 0
            && actual[6] == 0 && actual[7] == 0
            && memcmp(actual + 8, right, right_size) == 0;
    xrd_conform_grade_status(execution, "WVC-001", exact,
        "writev-readback-byte-exact", "writev-readback-mismatch", status);
    xrd_conform_grade_status(execution, "WVC-003", exact, "writev-doSync-durable",
        "writev-doSync-data-missing", status);
    xrd_conform_grade_status(execution, "WVC-004", exact, "zero-element-was-noop",
        "zero-element-altered-writev", status);
}

static void
probe_writev_sync(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object)
{
    static const uint8_t left[] = "left";
    static const uint8_t right[] = "right";
    brix_writev_seg segments[3] = {
        { 0, sizeof(left), left },
        { 6, 0, left },
        { 8, sizeof(right), right },
    };
    brix_file file;
    brix_status status;
    int rc;

    brix_status_clear(&status);
    if (open_write(execution, connection, object, 1, &file, &status) != 0) return;
    if (!xrd_conform_reserve_status(execution, sizeof(left) + sizeof(right), &status)) {
        close_file(execution, connection, &file, &status);
        return;
    }
    rc = brix_file_writev(connection, &file, segments, 3, 1, &status);
    if (rc != 0 && status.kxr == kXR_Unsupported) {
        grade_writev_absent(execution, connection, object, &file, &status);
        probe_read_sync(execution, connection, object, &status);
        return;
    }
    xrd_conform_result_set(execution, "WVC-005",
        rc == 0 ? BRIX_CONFORM_VERDICT_SKIPPED
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        rc == 0 ? "capability-present:writev"
                : "unsupported-writev-returned-wrong-error",
        "kXR_Unsupported or implemented writev", status.msg);
    xrd_conform_grade_status(execution, "WVC-001", rc == 0, "writev-elements-landed",
        "writev-refused", &status);
    xrd_conform_grade_status(execution, "WVC-003", rc == 0, "writev-doSync-completed",
        "writev-doSync-failed", &status);
    xrd_conform_grade_status(execution, "WVC-004", rc == 0, "zero-element-was-noop",
        "zero-element-broke-writev", &status);
    if (xrd_conform_reserve_status(execution, 0, &status)) {
        rc = brix_file_sync(connection, &file, &status);
        xrd_conform_grade_status(execution, "SYN-001", rc == 0, "sync-completed",
            "sync-failed", &status);
    }
    close_file(execution, connection, &file, &status);
    grade_writev_readback(execution, connection, object, left, sizeof(left),
        right, sizeof(right), &status);
    probe_read_sync(execution, connection, object, &status);
}

static void
probe_truncate(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object)
{
    uint8_t actual[16];
    brix_statinfo info;
    brix_file file;
    brix_status status;
    int rc;
    int zero = 1;

    if (open_write(execution, connection, object, 1, &file, &status) == 0)
        close_file(execution, connection, &file, &status);

    rc = truncate_object(execution, connection, object, 4, &status);
    xrd_conform_grade_status(execution, "TRN-001", rc == 0
        && stat_object(execution, connection, object, &info, &status) == 0
        && info.size == 4, "truncate-shrank-object", "truncate-shrink-failed",
        &status);
    if (open_write(execution, connection, object, 2, &file, &status) == 0) {
        rc = truncate_handle(execution, connection, &file, 8, &status);
        close_file(execution, connection, &file, &status);
    }
    xrd_conform_grade_status(execution, "TRN-007", rc == 0
        && stat_object(execution, connection, object, &info, &status) == 0
        && info.size == 8, "handle-and-path-truncate-agree",
        "handle-truncate-differs-from-path", &status);
    rc = truncate_object(execution, connection, object, 16, &status);
    memset(actual, 0xff, sizeof(actual));
    if (rc == 0) rc = read_exact(execution, connection, object, 4, actual, 12,
        &status);
    for (size_t index = 0; zero && index < 12; index++) zero = actual[index] == 0;
    xrd_conform_grade_status(execution, "TRN-002", rc == 0 && zero,
        "truncate-zero-extended", "truncate-extension-not-zero", &status);
    rc = truncate_object(execution, connection, object, 16, &status);
    xrd_conform_grade_status(execution, "TRN-004", rc == 0, "same-size-truncate-noop",
        "same-size-truncate-failed", &status);
    rc = truncate_object(execution, connection, object, -1, &status);
    xrd_conform_grade_status(execution, "TRN-005", rc != 0 && status.kxr == kXR_ArgInvalid,
        "negative-truncate-refused", "negative-truncate-wrong-answer", &status);
    rc = truncate_object(execution, connection, object, 0, &status);
    xrd_conform_grade_status(execution, "TRN-003", rc == 0
        && stat_object(execution, connection, object, &info, &status) == 0
        && info.size == 0, "truncate-zero-kept-object",
        "truncate-zero-failed", &status);
}

static void
skip_pgwrite_absent(xrd_conform_execution *execution)
{
    size_t index;

    for (index = 1; index <= 13; index++) {
        char id[16];

        snprintf(id, sizeof(id), "PGW-%03zu", index);
        xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_SKIPPED,
            "claim-absent:kXR_suppgrw", NULL, NULL);
    }
}

/* ---- Verify that an unadvertised pgwrite capability stays unavailable ----
 *
 * WHAT: Grades PGW-014 conformant only when a valid pgwrite is refused.
 * WHY: Capability absence is itself a wire promise; skipping the row when the
 *      bit is clear would make acceptance of an unadvertised mutation invisible.
 * HOW: Open one scratch writer, issue a valid zero-length pgwrite, close the
 *      handle, and distinguish refusal from an incorrectly accepted request.
 */
static void
probe_pgwrite_absent(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object)
{
    uint8_t byte = 0;
    brix_file file;
    brix_status status;
    int rc = -1;

    if (!xrd_conform_row_active(execution, "PGW-014")) return;
    brix_status_clear(&status);
    if (open_write(execution, connection, object, 1, &file, &status) == 0) {
        if (xrd_conform_reserve_status(execution, 1, &status))
            rc = brix_file_pgwrite(connection, &file, 0, &byte, 1, &status);
        close_file(execution, connection, &file, &status);
    }
    xrd_conform_grade_status(execution, "PGW-014", rc != 0,
        "unadvertised-pgwrite-refused", "unadvertised-pgwrite-accepted",
        &status);
}

static void
probe_pgwrite(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object)
{
    uint8_t expected[8192];
    uint8_t actual[8192];
    brix_file file;
    brix_status status;
    ssize_t got;
    int rc;

    if ((connection->server_flags & kXR_suppgrw) == 0) {
        skip_pgwrite_absent(execution);
        probe_pgwrite_absent(execution, connection, object);
        return;
    }
    xrd_conform_result_set(execution, "PGW-014",
        BRIX_CONFORM_VERDICT_SKIPPED, "claim-present:kXR_suppgrw", NULL, NULL);
    brix_status_clear(&status);
    brix_conform_fill(&execution->run->key, 0, expected, sizeof(expected));
    if (open_write(execution, connection, object, 1, &file, &status) != 0) return;
    if (!xrd_conform_reserve_status(execution, sizeof(expected), &status)) {
        close_file(execution, connection, &file, &status);
        return;
    }
    rc = brix_file_pgwrite(connection, &file, 0, expected, sizeof(expected),
        &status);
    xrd_conform_grade_status(execution, "PGW-001", rc == 0, "typed-status-response-validated",
        "pgwrite-status-invalid", &status);
    xrd_conform_grade_status(execution, "PGW-002", rc == 0, "crc-first-pages-accepted",
        "crc-first-pages-refused", &status);
    xrd_conform_grade_status(execution, "PGW-003", rc == 0, "status-offset-validated",
        "status-offset-mismatch", &status);
    if (rc == 0 && xrd_conform_reserve_status(execution, sizeof(actual), &status)) {
        got = brix_file_pgread(connection, &file, 0, actual, sizeof(actual),
            &status);
        xrd_conform_grade_status(execution, "PGW-004", got == (ssize_t) sizeof(actual)
            && memcmp(actual, expected, sizeof(actual)) == 0,
            "pgwrite-pgread-byte-exact", "pgwrite-readback-mismatch", &status);
    }
    if (xrd_conform_reserve_status(execution, 17, &status)) {
        rc = brix_file_pgwrite(connection, &file, 1, expected + 1, 17, &status);
        xrd_conform_grade_status(execution, "PGW-011", rc == 0 || status.kxr == kXR_ArgInvalid,
            rc == 0 ? "fractional-pgwrite-honoured"
                    : "fractional-pgwrite-defined-refusal",
            "fractional-pgwrite-silently-realigned", &status);
    }
    if (xrd_conform_reserve_status(execution, 0, &status)) {
        rc = brix_file_pgwrite(connection, &file, 0, expected, 0, &status);
        xrd_conform_grade_status(execution, "PGW-012", rc == 0, "zero-pgwrite-noop",
            "zero-pgwrite-failed", &status);
    }
    close_file(execution, connection, &file, &status);
}

static int
write_family_active(xrd_conform_execution *execution)
{
    static const char *const families[] = {
        "WRT", "WVC", "SYN", "TRN", "PGW", "FAT"
    };
    size_t index;

    for (index = 0; index < sizeof(families) / sizeof(families[0]); index++)
        if (xrd_conform_family_active(execution, families[index])) return 1;
    return 0;
}

static void
run_write_probes(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object)
{
    static const char *const ids[] = {
        "WRT-001", "WRT-002", "WRT-003", "WRT-004", "WRT-005", "WRT-009"
    };

    if (xrd_conform_any_row_active(execution, ids, sizeof(ids) / sizeof(ids[0])))
        probe_write(execution, connection, object);
    if (xrd_conform_row_active(execution, "WRT-011"))
        xrd_conform_probe_concurrent_write(execution, connection, object);
    if (xrd_conform_row_active(execution, "WRT-010"))
        xrd_conform_probe_truncated_write(execution, connection, object);
    if (xrd_conform_row_active(execution, "WRT-008"))
        xrd_conform_probe_oversized_write(execution);
    if (xrd_conform_row_active(execution, "WRT-007"))
        xrd_conform_probe_write_capacity(execution);
}

static void
run_writev_probes(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object)
{
    static const char *const ids[] = {
        "WVC-001", "WVC-003", "WVC-004", "WVC-005", "SYN-001", "SYN-002"
    };

    if (xrd_conform_any_row_active(execution, ids, sizeof(ids) / sizeof(ids[0])))
        probe_writev_sync(execution, connection, object);
    if (xrd_conform_row_active(execution, "WVC-002"))
        xrd_conform_probe_writev_limits(execution, connection, object);
}

static void
run_pgwrite_probes(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object)
{
    static const char *const basic_ids[] = {
        "PGW-001", "PGW-002", "PGW-003", "PGW-004", "PGW-011", "PGW-012",
        "PGW-014"
    };
    static const char *const cse_ids[] = {
        "PGW-005", "PGW-006", "PGW-007", "PGW-008", "PGW-009", "PGW-010"
    };

    if (xrd_conform_any_row_active(execution, basic_ids,
            sizeof(basic_ids) / sizeof(basic_ids[0])))
        probe_pgwrite(execution, connection, object);
    if (xrd_conform_any_row_active(execution, cse_ids,
            sizeof(cse_ids) / sizeof(cse_ids[0])))
        xrd_conform_probe_pgwrite_cse(execution, connection, object);
}

void
xrd_conform_probe_write_mutations(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object object;
    brix_status status;

    if (!write_family_active(execution)) return;
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-write", object.path, sizeof(object.path)) != 0) return;
    run_write_probes(execution, connection, &object);
    run_writev_probes(execution, connection, &object);
    if (xrd_conform_family_active(execution, "TRN"))
        probe_truncate(execution, connection, &object);
    run_pgwrite_probes(execution, connection, &object);
    if (xrd_conform_family_active(execution, "FAT"))
        xrd_conform_probe_fattr_mutations(execution, connection, &object);
    brix_status_clear(&status);
    remove_object(execution, connection, &object, &status);
}
