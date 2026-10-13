/* Phase-118 scratch-confined ROOT write-plane probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/frame_hdr.h"

static int
reserve_op(xrd_conform_execution *execution, size_t bytes,
    brix_status *status)
{
    char reason[64];

    if (xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) return 1;
    brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
    return 0;
}

static void
grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const char *failure, const brix_status *status)
{
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : failure, NULL, status == NULL ? NULL : status->msg);
}

/* ---- Test whether a write-plane clause survived scope filtering ----
 *
 * WHAT: Returns one when the named clause is active in this execution.
 * WHY: `--only` must not run unrelated destructive or disruptive probes; doing
 *      so can consume the wall budget and poison the cleanup connection.
 * HOW: Look up the result row and reject absent or explicitly skipped rows.
 */
static int
row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

/* ---- Test whether any clause in a small probe group is active ----
 *
 * WHAT: Returns one when at least one supplied clause is active.
 * WHY: Several wire exercises jointly own a subset of a family and should be
 *      skipped wholesale when `--only` selects a different subset.
 * HOW: Walk the immutable identifier array and delegate filtering to
 *      row_active().
 */
static int
any_row_active(xrd_conform_execution *execution,
    const char *const *ids, size_t count)
{
    size_t index;

    for (index = 0; index < count; index++)
        if (row_active(execution, ids[index])) return 1;
    return 0;
}

static int
open_write(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, int force, brix_file *file,
    brix_status *status)
{
    if (!reserve_op(execution, 0, status)) return -1;
    return brix_file_open_write(connection, object->path, force, 0, file, status);
}

static int
close_file(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, brix_status *status)
{
    if (!reserve_op(execution, 0, status)) return -1;
    return brix_file_close(connection, file, status);
}

static int
write_file(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, int64_t offset, const void *data, size_t length,
    brix_status *status)
{
    if (!reserve_op(execution, length, status)) return -1;
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

    if (!reserve_op(execution, 0, status)
        || brix_file_open_read(connection, object->path, &file, status) != 0)
        return -1;
    if (reserve_op(execution, length, status)) {
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
    if (!reserve_op(execution, 0, status)) return -1;
    return brix_stat(connection, object->path, info, status);
}

static int
truncate_object(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, int64_t size,
    brix_status *status)
{
    if (!reserve_op(execution, 0, status)) return -1;
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

    if (!reserve_op(execution, 0, status)) return -1;
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
    if (!reserve_op(execution, 0, status)) return -1;
    return brix_rm(connection, object->path, status);
}

static void
probe_write(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object)
{
    static const uint8_t initial[] = { 'a', 'b', 'c' };
    static const uint8_t overlap[] = { 'X', 'Y' };
    uint8_t actual[8193];
    brix_statinfo info;
    brix_file file;
    brix_status status;
    int negative_kxr;
    int rc;
    int hole_ok;

    brix_status_clear(&status);
    rc = open_write(execution, connection, object, 1, &file, &status);
    if (rc == 0) rc = write_file(execution, connection, &file, 0, initial,
        sizeof(initial), &status);
    if (rc == 0) rc = close_file(execution, connection, &file, &status);
    if (rc == 0) rc = read_exact(execution, connection, object, 0, actual,
        sizeof(initial), &status);
    grade(execution, "WRT-001", rc == 0
        && memcmp(actual, initial, sizeof(initial)) == 0,
        "write-at-eof-extended-exactly", "write-at-eof-mismatch", &status);
    if (!row_active(execution, "WRT-002")
        && !row_active(execution, "WRT-003")
        && !row_active(execution, "WRT-004")
        && !row_active(execution, "WRT-005")
        && !row_active(execution, "WRT-009")) return;

    if (open_write(execution, connection, object, 2, &file, &status) == 0) {
        rc = write_file(execution, connection, &file, 8192, "Z", 1, &status);
        close_file(execution, connection, &file, &status);
    }
    memset(actual, 0xff, sizeof(actual));
    rc = rc == 0 ? read_exact(execution, connection, object, 0, actual,
        sizeof(actual), &status) : rc;
    hole_ok = rc == 0 && actual[0] == 'a' && actual[1] == 'b'
        && actual[2] == 'c' && actual[8192] == 'Z';
    for (size_t index = 3; hole_ok && index < 8192; index++)
        hole_ok = actual[index] == 0;
    grade(execution, "WRT-002", hole_ok,
        "beyond-eof-write-created-zero-hole", "sparse-hole-mismatch", &status);
    if (!row_active(execution, "WRT-003")
        && !row_active(execution, "WRT-004")
        && !row_active(execution, "WRT-005")
        && !row_active(execution, "WRT-009")) return;

    stat_object(execution, connection, object, &info, &status);
    if (open_write(execution, connection, object, 2, &file, &status) == 0) {
        rc = write_file(execution, connection, &file, 0, actual, 0, &status);
        close_file(execution, connection, &file, &status);
    }
    grade(execution, "WRT-003", rc == 0
        && stat_object(execution, connection, object, &info, &status) == 0
        && info.size == 8193, "zero-write-preserved-size",
        "zero-write-changed-size", &status);
    if (!row_active(execution, "WRT-004")
        && !row_active(execution, "WRT-005")
        && !row_active(execution, "WRT-009")) return;

    if (open_write(execution, connection, object, 2, &file, &status) == 0) {
        rc = write_file(execution, connection, &file, 1, overlap,
            sizeof(overlap), &status);
        close_file(execution, connection, &file, &status);
    }
    rc = rc == 0 ? read_exact(execution, connection, object, 0, actual, 3,
        &status) : rc;
    grade(execution, "WRT-004", rc == 0 && memcmp(actual, "aXY", 3) == 0,
        "overlap-last-write-won", "overlap-write-mismatch", &status);
    if (!row_active(execution, "WRT-005")
        && !row_active(execution, "WRT-009")) return;

    if (reserve_op(execution, 0, &status)
        && brix_file_open_read(connection, object->path, &file, &status) == 0) {
        rc = write_file(execution, connection, &file, 0, "Q", 1, &status);
        close_file(execution, connection, &file, &status);
    }
    grade(execution, "WRT-005", rc != 0, "read-only-handle-write-refused",
        "read-only-handle-writable", &status);
    if (!row_active(execution, "WRT-009")) return;

    if (open_write(execution, connection, object, 2, &file, &status) == 0) {
        rc = write_file(execution, connection, &file, -1, "Q", 1, &status);
        negative_kxr = status.kxr;
        close_file(execution, connection, &file, &status);
    } else {
        negative_kxr = status.kxr;
    }
    grade(execution, "WRT-009", rc != 0 && negative_kxr == kXR_ArgInvalid,
        "negative-write-offset-refused", "negative-write-offset-wrong-answer",
        &status);
}

static void
probe_writev_sync(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object)
{
    static const uint8_t left[] = "left";
    static const uint8_t right[] = "right";
    uint8_t actual[14];
    brix_writev_seg segments[3] = {
        { 0, sizeof(left), left },
        { 6, 0, left },
        { 8, sizeof(right), right },
    };
    brix_file file;
    brix_statinfo info;
    brix_status status;
    int rc;

    brix_status_clear(&status);
    if (open_write(execution, connection, object, 1, &file, &status) != 0) return;
    if (!reserve_op(execution, sizeof(left) + sizeof(right), &status)) {
        close_file(execution, connection, &file, &status);
        return;
    }
    rc = brix_file_writev(connection, &file, segments, 3, 1, &status);
    if (rc != 0 && status.kxr == kXR_Unsupported) {
        if (reserve_op(execution, 0, &status)) {
            brix_status_clear(&status);
            rc = brix_file_sync(connection, &file, &status);
            grade(execution, "SYN-001", rc == 0, "sync-completed",
                "sync-failed", &status);
        }
        close_file(execution, connection, &file, &status);
        rc = stat_object(execution, connection, object, &info, &status);
        grade(execution, "WVC-005", rc == 0 && info.size == 0,
            "unsupported-writev-left-object-unmodified",
            "unsupported-writev-partially-modified-object", &status);
        xrd_conform_result_set(execution, "WVC-001",
            BRIX_CONFORM_VERDICT_SKIPPED, "capability-absent:writev", NULL,
            NULL);
        xrd_conform_result_set(execution, "WVC-003",
            BRIX_CONFORM_VERDICT_SKIPPED, "capability-absent:writev", NULL,
            NULL);
        xrd_conform_result_set(execution, "WVC-004",
            BRIX_CONFORM_VERDICT_SKIPPED, "capability-absent:writev", NULL,
            NULL);
        if (reserve_op(execution, 0, &status)
            && brix_file_open_read(connection, object->path, &file,
                &status) == 0) {
            if (reserve_op(execution, 0, &status)) {
                rc = brix_file_sync(connection, &file, &status);
                grade(execution, "SYN-002",
                    rc == 0 || status.kxr != kXR_ServerError,
                    "read-handle-sync-defined",
                    "read-handle-sync-server-error", &status);
            }
            close_file(execution, connection, &file, &status);
        }
        return;
    }
    xrd_conform_result_set(execution, "WVC-005",
        rc == 0 ? BRIX_CONFORM_VERDICT_SKIPPED
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        rc == 0 ? "capability-present:writev"
                : "unsupported-writev-returned-wrong-error",
        "kXR_Unsupported or implemented writev", status.msg);
    grade(execution, "WVC-001", rc == 0, "writev-elements-landed",
        "writev-refused", &status);
    grade(execution, "WVC-003", rc == 0, "writev-doSync-completed",
        "writev-doSync-failed", &status);
    grade(execution, "WVC-004", rc == 0, "zero-element-was-noop",
        "zero-element-broke-writev", &status);
    if (reserve_op(execution, 0, &status)) {
        rc = brix_file_sync(connection, &file, &status);
        grade(execution, "SYN-001", rc == 0, "sync-completed",
            "sync-failed", &status);
    }
    close_file(execution, connection, &file, &status);
    memset(actual, 0, sizeof(actual));
    if (read_exact(execution, connection, object, 0, actual, sizeof(actual),
            &status) == 0) {
        int exact = memcmp(actual, left, sizeof(left)) == 0
            && actual[6] == 0 && actual[7] == 0
            && memcmp(actual + 8, right, sizeof(right)) == 0;

        grade(execution, "WVC-001", exact,
            "writev-readback-byte-exact", "writev-readback-mismatch", &status);
        grade(execution, "WVC-003", exact, "writev-doSync-durable",
            "writev-doSync-data-missing", &status);
        grade(execution, "WVC-004", exact, "zero-element-was-noop",
            "zero-element-altered-writev", &status);
    } else {
        grade(execution, "WVC-001", 0, "writev-readback-byte-exact",
            "writev-readback-failed", &status);
        grade(execution, "WVC-003", 0, "writev-doSync-durable",
            "writev-doSync-readback-failed", &status);
        grade(execution, "WVC-004", 0, "zero-element-was-noop",
            "zero-element-readback-failed", &status);
    }

    if (reserve_op(execution, 0, &status)
        && brix_file_open_read(connection, object->path, &file, &status) == 0) {
        if (reserve_op(execution, 0, &status)) {
            rc = brix_file_sync(connection, &file, &status);
            grade(execution, "SYN-002", rc == 0 || status.kxr != kXR_ServerError,
                "read-handle-sync-defined", "read-handle-sync-server-error",
                &status);
        }
        close_file(execution, connection, &file, &status);
    }
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
    grade(execution, "TRN-001", rc == 0
        && stat_object(execution, connection, object, &info, &status) == 0
        && info.size == 4, "truncate-shrank-object", "truncate-shrink-failed",
        &status);
    if (open_write(execution, connection, object, 2, &file, &status) == 0) {
        rc = truncate_handle(execution, connection, &file, 8, &status);
        close_file(execution, connection, &file, &status);
    }
    grade(execution, "TRN-007", rc == 0
        && stat_object(execution, connection, object, &info, &status) == 0
        && info.size == 8, "handle-and-path-truncate-agree",
        "handle-truncate-differs-from-path", &status);
    rc = truncate_object(execution, connection, object, 16, &status);
    memset(actual, 0xff, sizeof(actual));
    if (rc == 0) rc = read_exact(execution, connection, object, 4, actual, 12,
        &status);
    for (size_t index = 0; zero && index < 12; index++) zero = actual[index] == 0;
    grade(execution, "TRN-002", rc == 0 && zero,
        "truncate-zero-extended", "truncate-extension-not-zero", &status);
    rc = truncate_object(execution, connection, object, 16, &status);
    grade(execution, "TRN-004", rc == 0, "same-size-truncate-noop",
        "same-size-truncate-failed", &status);
    rc = truncate_object(execution, connection, object, -1, &status);
    grade(execution, "TRN-005", rc != 0 && status.kxr == kXR_ArgInvalid,
        "negative-truncate-refused", "negative-truncate-wrong-answer", &status);
    rc = truncate_object(execution, connection, object, 0, &status);
    grade(execution, "TRN-003", rc == 0
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

    if (!row_active(execution, "PGW-014")) return;
    brix_status_clear(&status);
    if (open_write(execution, connection, object, 1, &file, &status) == 0) {
        if (reserve_op(execution, 1, &status))
            rc = brix_file_pgwrite(connection, &file, 0, &byte, 1, &status);
        close_file(execution, connection, &file, &status);
    }
    grade(execution, "PGW-014", rc != 0,
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
    if (!reserve_op(execution, sizeof(expected), &status)) {
        close_file(execution, connection, &file, &status);
        return;
    }
    rc = brix_file_pgwrite(connection, &file, 0, expected, sizeof(expected),
        &status);
    grade(execution, "PGW-001", rc == 0, "typed-status-response-validated",
        "pgwrite-status-invalid", &status);
    grade(execution, "PGW-002", rc == 0, "crc-first-pages-accepted",
        "crc-first-pages-refused", &status);
    grade(execution, "PGW-003", rc == 0, "status-offset-validated",
        "status-offset-mismatch", &status);
    if (rc == 0 && reserve_op(execution, sizeof(actual), &status)) {
        got = brix_file_pgread(connection, &file, 0, actual, sizeof(actual),
            &status);
        grade(execution, "PGW-004", got == (ssize_t) sizeof(actual)
            && memcmp(actual, expected, sizeof(actual)) == 0,
            "pgwrite-pgread-byte-exact", "pgwrite-readback-mismatch", &status);
    }
    if (reserve_op(execution, 17, &status)) {
        rc = brix_file_pgwrite(connection, &file, 1, expected + 1, 17, &status);
        grade(execution, "PGW-011", rc == 0 || status.kxr == kXR_ArgInvalid,
            rc == 0 ? "fractional-pgwrite-honoured"
                    : "fractional-pgwrite-defined-refusal",
            "fractional-pgwrite-silently-realigned", &status);
    }
    if (reserve_op(execution, 0, &status)) {
        rc = brix_file_pgwrite(connection, &file, 0, expected, 0, &status);
        grade(execution, "PGW-012", rc == 0, "zero-pgwrite-noop",
            "zero-pgwrite-failed", &status);
    }
    close_file(execution, connection, &file, &status);
}

void
xrd_conform_probe_write_mutations(xrd_conform_execution *execution,
    brix_conn *connection)
{
    static const char *const basic_write_ids[] = {
        "WRT-001", "WRT-002", "WRT-003", "WRT-004", "WRT-005", "WRT-009"
    };
    static const char *const writev_sync_ids[] = {
        "WVC-001", "WVC-003", "WVC-004", "WVC-005", "SYN-001", "SYN-002"
    };
    static const char *const pgwrite_basic_ids[] = {
        "PGW-001", "PGW-002", "PGW-003", "PGW-004", "PGW-011", "PGW-012",
        "PGW-014"
    };
    static const char *const pgwrite_cse_ids[] = {
        "PGW-005", "PGW-006", "PGW-007", "PGW-008", "PGW-009", "PGW-010"
    };
    xrd_conform_scratch_object object;
    brix_status status;

    if (!xrd_conform_family_active(execution, "WRT")
        && !xrd_conform_family_active(execution, "WVC")
        && !xrd_conform_family_active(execution, "SYN")
        && !xrd_conform_family_active(execution, "TRN")
        && !xrd_conform_family_active(execution, "PGW")
        && !xrd_conform_family_active(execution, "FAT")) return;
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-write", object.path, sizeof(object.path)) != 0) return;
    if (any_row_active(execution, basic_write_ids,
            sizeof(basic_write_ids) / sizeof(basic_write_ids[0])))
        probe_write(execution, connection, &object);
    if (row_active(execution, "WRT-011"))
        xrd_conform_probe_concurrent_write(execution, connection, &object);
    if (row_active(execution, "WRT-010"))
        xrd_conform_probe_truncated_write(execution, connection, &object);
    if (row_active(execution, "WRT-008"))
        xrd_conform_probe_oversized_write(execution);
    if (row_active(execution, "WRT-007"))
        xrd_conform_probe_write_capacity(execution);
    if (any_row_active(execution, writev_sync_ids,
            sizeof(writev_sync_ids) / sizeof(writev_sync_ids[0]))) {
        probe_writev_sync(execution, connection, &object);
    }
    if (row_active(execution, "WVC-002"))
        xrd_conform_probe_writev_limits(execution, connection, &object);
    if (xrd_conform_family_active(execution, "TRN"))
        probe_truncate(execution, connection, &object);
    if (any_row_active(execution, pgwrite_basic_ids,
            sizeof(pgwrite_basic_ids) / sizeof(pgwrite_basic_ids[0])))
        probe_pgwrite(execution, connection, &object);
    if (any_row_active(execution, pgwrite_cse_ids,
            sizeof(pgwrite_cse_ids) / sizeof(pgwrite_cse_ids[0])))
        xrd_conform_probe_pgwrite_cse(execution, connection, &object);
    if (xrd_conform_family_active(execution, "FAT"))
        xrd_conform_probe_fattr_mutations(execution, connection, &object);
    brix_status_clear(&status);
    remove_object(execution, connection, &object, &status);
}
