/*
 * Phase-118 exact-clause ROOT read-only policy probes.
 *
 * WHAT: Grades the ROOT rows whose oracle depends on a typed read-only export.
 * WHY: A writable scratch endpoint cannot prove EROFS precedence or honest
 *      stat/locate claims, while a read-only endpoint cannot plant fixtures.
 * HOW: Address pre-seeded objects only through the scratch capability builder,
 *      execute one explicitly selected clause, and distinguish EROFS from
 *      authorization, missing-object, and unexpectedly successful mutation.
 */
#include "xrd_conform_probe_helpers.h"

typedef void (*readonly_probe_fn)(xrd_conform_execution *, brix_conn *);

/* ---- Reserve one bounded read-only-policy exchange ----
 *
 * WHAT: Returns one after charging an exchange, or zero with status populated.
 * WHY: Exact-clause probes remain subject to the same remote resource ceilings.
 * HOW: Delegate accounting to xrd_conform_reserve and translate refusal into
 *      the native client status used by the probe helpers.
 */
static int
readonly_reserve(xrd_conform_execution *execution, size_t bytes,
    brix_status *status)
{
    char reason[64];

    if (xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) return 1;
    brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
    return 0;
}

/* ---- Build one fixed read-only fixture capability ----
 *
 * WHAT: Returns zero with a scratch-confined path, or minus one on invalid input.
 * WHY: Even pre-seeded fixtures must never let a remote mutation name raw paths.
 * HOW: Pass the run's authorized prefix and fixed leaf to the common builder.
 */
static int
readonly_path(xrd_conform_execution *execution, const char *leaf,
    xrd_conform_scratch_object *object)
{
    return brix_conform_scratch_path(execution->run->config.scratch, leaf,
        object->path, sizeof(object->path));
}

/* ---- Grade one operation against the EROFS wire contract ----
 *
 * WHAT: Marks id conformant only for a failed operation carrying fsReadOnly.
 * WHY: NotAuthorized, NotFound, success, and generic server errors are distinct
 *      security outcomes and must never be accepted as read-only evidence.
 * HOW: Compare the preserved return/status pair and record bounded evidence.
 */
static void
grade_readonly(xrd_conform_execution *execution, const char *id, int rc,
    int kxr, const char *message)
{
    char received[192];
    int pass = rc != 0 && kxr == kXR_fsReadOnly;

    snprintf(received, sizeof(received), "kxr=%d %.150s", kxr,
        message == NULL ? "" : message);
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "readonly-policy-refused-mutation"
             : "readonly-policy-wrong-answer",
        "kXR_fsReadOnly", received);
}

/* ---- Observe the ROOT half of the paired S3 read-only assertion ----
 *
 * WHAT: Records whether create-open was refused with exactly kXR_fsReadOnly.
 * WHY: S3-009 is conformant only when the same policy has matching ROOT and S3
 *      spellings; authorization or missing-path errors are not substitutes.
 * HOW: Build a fixed scratch capability, attempt typed create/truncate, close
 *      an unexpectedly admitted handle, and retain a tri-state observation.
 */
static void
probe_s3_readonly_twin(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object object;
    brix_file file = { { 0 }, 0, 0 };
    brix_status status;
    int rc;

    if (readonly_path(execution, "brix-conform-s3-readonly", &object) != 0)
        return;
    brix_status_clear(&status);
    if (!readonly_reserve(execution, 0, &status)) return;
    rc = brix_file_open_write(connection, object.path, 1, 0, &file, &status);
    execution->root_readonly_state = rc != 0 && status.kxr == kXR_fsReadOnly
        ? -1 : 1;
    if (rc == 0) {
        brix_status close_status;

        brix_status_clear(&close_status);
        brix_file_close(connection, &file, &close_status);
    }
}

/* ---- Probe ordinary write refusal on a read-only export ----
 *
 * WHAT: Grades WRT-006 using an existing scratch-derived file.
 * WHY: Opening for update avoids conflating read-only policy with create errors.
 * HOW: Try update-open, then one-byte write if admitted, preserve the first
 *      refusal, close any handle, and require fsReadOnly.
 */
static void
probe_readonly_write(xrd_conform_execution *execution, brix_conn *connection)
{
    xrd_conform_scratch_object object;
    brix_file file = { { 0 }, 0, 0 };
    brix_status status;
    char message[160];
    int opened = 0;
    int rc;
    int kxr;

    if (readonly_path(execution, "brix-conform-readonly-file", &object) != 0)
        return;
    brix_status_clear(&status);
    rc = readonly_reserve(execution, 0, &status)
        ? brix_file_open_update(connection, object.path, 0, &file, &status) : -1;
    if (rc == 0) {
        opened = 1;
        rc = readonly_reserve(execution, 1, &status)
            ? brix_file_write(connection, &file, 0, "W", 1, &status) : -1;
    }
    kxr = status.kxr;
    snprintf(message, sizeof(message), "%.159s", status.msg);
    if (opened) {
        brix_status close_status;

        brix_status_clear(&close_status);
        brix_file_close(connection, &file, &close_status);
    }
    grade_readonly(execution, "WRT-006", rc, kxr, message);
    grade_readonly(execution, "OPN-011", rc, kxr, message);
    grade_readonly(execution, "CAC-010", rc, kxr, message);
}

/* ---- Probe paged-write refusal on a read-only export ----
 *
 * WHAT: Grades PGW-013, or claim-skips it when pgwrite is not advertised.
 * WHY: Read-only policy must retain its EROFS spelling for CRC-protected writes.
 * HOW: Open the pre-seeded file for update, issue one exact page when admitted,
 *      preserve the refusal, close any handle, and compare the wire status.
 */
static void
probe_readonly_pgwrite(xrd_conform_execution *execution, brix_conn *connection)
{
    uint8_t page[4096] = { 0 };
    xrd_conform_scratch_object object;
    brix_file file = { { 0 }, 0, 0 };
    brix_status status;
    brix_status close_status;
    char message[160];
    int opened = 0;
    int rc;
    int kxr;

    if ((connection->server_flags & kXR_suppgrw) == 0) {
        xrd_conform_result_set(execution, "PGW-013",
            BRIX_CONFORM_VERDICT_SKIPPED, "claim-absent:kXR_suppgrw",
            NULL, NULL);
        return;
    }
    if (readonly_path(execution, "brix-conform-readonly-file", &object) != 0)
        return;
    brix_status_clear(&status);
    rc = readonly_reserve(execution, 0, &status)
        ? brix_file_open_update(connection, object.path, 0, &file, &status) : -1;
    if (rc == 0) {
        opened = 1;
        rc = readonly_reserve(execution, sizeof(page), &status)
            ? brix_file_pgwrite(connection, &file, 0, page, sizeof(page),
                &status) : -1;
    }
    kxr = status.kxr;
    snprintf(message, sizeof(message), "%.159s", status.msg);
    if (opened) {
        brix_status_clear(&close_status);
        brix_file_close(connection, &file, &close_status);
    }
    grade_readonly(execution, "PGW-013", rc, kxr, message);
}

typedef enum {
    READONLY_PATH_TRUNCATE,
    READONLY_PATH_MKDIR,
    READONLY_PATH_REMOVE,
    READONLY_PATH_CHMOD
} readonly_path_operation;

/* WHAT: Execute one typed metadata mutation against a scratch-confined path.
 * WHY: These probes share policy setup, but must retain each typed wire API.
 * HOW: Dispatch the closed operation enum; refuse an unrecognized operation.
 */
static int
readonly_path_call(brix_conn *connection, const xrd_conform_scratch_object *object,
    readonly_path_operation operation, brix_status *status)
{
    switch (operation) {
    case READONLY_PATH_TRUNCATE:
        return brix_truncate(connection, object->path, 0, status);
    case READONLY_PATH_MKDIR:
        return brix_mkdir(connection, object->path, 0755, 0, status);
    case READONLY_PATH_REMOVE:
        return brix_rm(connection, object->path, status);
    case READONLY_PATH_CHMOD:
        return brix_chmod(connection, object->path, 0600, status);
    }
    brix_status_set(status, XRDC_EUSAGE, 0, "invalid readonly mutation");
    return -1;
}

/* WHAT: Undo a successful mkdir/chmod without replacing the original verdict.
 * WHY: An unexpectedly writable fixture must not retain avoidable side effects.
 * HOW: Keep the existing rmdir/default-mode cleanup, using a separate status.
 */
static void
readonly_path_restore(brix_conn *connection,
    const xrd_conform_scratch_object *object,
    readonly_path_operation operation)
{
    brix_status ignored;
    brix_status_clear(&ignored);
    if (operation == READONLY_PATH_MKDIR) {
        (void) brix_rmdir(connection, object->path, &ignored);
    } else if (operation == READONLY_PATH_CHMOD) {
        (void) brix_chmod(connection, object->path, 0644, &ignored);
    }
}

/* WHAT: Run and grade a path mutation under the read-only policy contract.
 * WHY: Path capability, request budget and first-response ownership are common
 * invariants, not per-operation implementations that should drift apart.
 * HOW: Build the fixed fixture path, reserve, execute, preserve, clean up and
 * grade the exact first response as fsReadOnly (never authorization/not-found).
 */
static void
probe_readonly_path(xrd_conform_execution *execution, brix_conn *connection,
    readonly_path_operation operation, const char *clause)
{
    xrd_conform_scratch_object object;
    brix_status status;
    brix_status first;
    const char *leaf = operation == READONLY_PATH_MKDIR
        ? "brix-conform-readonly-newdir" : "brix-conform-readonly-file";
    int result;

    if (readonly_path(execution, leaf, &object) != 0) {
        return;
    }
    brix_status_clear(&status);
    result = readonly_reserve(execution, 0, &status)
        ? readonly_path_call(connection, &object, operation, &status) : -1;
    first = status;
    if (result == 0) {
        readonly_path_restore(connection, &object, operation);
    }
    grade_readonly(execution, clause, result, first.kxr, first.msg);
}

/* ---- Probe path truncate refusal on a read-only export ----
 *
 * WHAT: Grades TRN-006 against an existing scratch-derived file.
 * WHY: The endpoint policy must win over ordinary filesystem truncate behavior.
 * HOW: Issue a zero-size typed truncate and require its status to be fsReadOnly.
 */
static void
probe_readonly_truncate(xrd_conform_execution *execution, brix_conn *connection)
{
    probe_readonly_path(execution, connection, READONLY_PATH_TRUNCATE, "TRN-006");
}

/* ---- Probe mkdir refusal on a read-only export ----
 *
 * WHAT: Grades MKD-005 against an absent scratch-derived directory.
 * WHY: Policy evaluation must precede creation and return EROFS consistently.
 * HOW: Issue typed mkdir, clean up an unexpected writable success, then grade
 *      the preserved first response.
 */
static void
probe_readonly_mkdir(xrd_conform_execution *execution, brix_conn *connection)
{
    probe_readonly_path(execution, connection, READONLY_PATH_MKDIR, "MKD-005");
}

/* ---- Probe rename refusal on a read-only export ----
 *
 * WHAT: Grades MV-006 using existing source and absent target capabilities.
 * WHY: A read-only export must not rename even when both paths are authorized.
 * HOW: Attempt the typed move, reverse an unexpected writable success, and
 *      require the preserved first response to be fsReadOnly.
 */
static void
probe_readonly_move(xrd_conform_execution *execution, brix_conn *connection)
{
    xrd_conform_scratch_object source;
    xrd_conform_scratch_object target;
    brix_status status;
    char message[160];
    int rc;
    int kxr;

    if (readonly_path(execution, "brix-conform-readonly-source", &source) != 0
        || readonly_path(execution, "brix-conform-readonly-target", &target)
            != 0) return;
    brix_status_clear(&status);
    rc = readonly_reserve(execution, 0, &status)
        ? brix_mv(connection, source.path, target.path, &status) : -1;
    kxr = status.kxr;
    snprintf(message, sizeof(message), "%.159s", status.msg);
    if (rc == 0) brix_mv(connection, target.path, source.path, &status);
    grade_readonly(execution, "MV-006", rc, kxr, message);
}

/* ---- Probe remove refusal on a read-only export ----
 *
 * WHAT: Grades RM-007 against a pre-seeded scratch-derived file.
 * WHY: Missing-object and authorization answers cannot stand in for EROFS.
 * HOW: Issue one typed remove and compare its exact status without retrying.
 */
static void
probe_readonly_remove(xrd_conform_execution *execution, brix_conn *connection)
{
    probe_readonly_path(execution, connection, READONLY_PATH_REMOVE, "RM-007");
}

/* ---- Probe chmod refusal on a read-only export ----
 *
 * WHAT: Grades CHM-003 against a pre-seeded scratch-derived file.
 * WHY: Metadata mutation is governed by the same typed export policy as data.
 * HOW: Attempt mode change, restore an unexpected writable success, and grade
 *      the preserved first response as an EROFS contract.
 */
static void
probe_readonly_chmod(xrd_conform_execution *execution, brix_conn *connection)
{
    probe_readonly_path(execution, connection, READONLY_PATH_CHMOD, "CHM-003");
}

/* ---- Probe prepare-stage refusal on a read-only export ----
 *
 * WHAT: Grades PRP-007 using the existing read-only fixture.
 * WHY: Export mutation policy must reject staging before recall/cache work.
 * HOW: Submit one typed stage request and require the exact fsReadOnly result.
 */
static void
probe_readonly_prepare(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object object;
    const char *paths[1];
    char reply[256];
    brix_status status;
    int rc;

    if (readonly_path(execution, "brix-conform-readonly-file", &object) != 0)
        return;
    paths[0] = object.path;
    brix_status_clear(&status);
    rc = readonly_reserve(execution, 0, &status)
        ? brix_prepare(connection, paths, 1, kXR_stage, 0, 0,
            reply, sizeof(reply), &status) : -1;
    grade_readonly(execution, "PRP-007", rc, status.kxr, status.msg);
}

/* ---- Probe read-only stat flags and open agreement ----
 *
 * WHAT: Grades STA-005 and STA-006 from one stat/open observation pair.
 * WHY: Advertised writability must agree with the mutation policy clients see.
 * HOW: Stat the pre-seeded file, require readable without writable, attempt an
 *      update-open, close any unexpected handle, and compare both assertions.
 */
static void
probe_readonly_stat(xrd_conform_execution *execution, brix_conn *connection)
{
    xrd_conform_scratch_object object;
    brix_statinfo info;
    brix_file file;
    brix_status status;
    char received[192];
    int stat_rc;
    int open_rc;
    int open_kxr;
    int flags_ok;

    if (readonly_path(execution, "brix-conform-readonly-file", &object) != 0)
        return;
    memset(&info, 0, sizeof(info));
    brix_status_clear(&status);
    stat_rc = readonly_reserve(execution, 0, &status)
        ? brix_stat(connection, object.path, &info, &status) : -1;
    flags_ok = stat_rc == 0 && (info.flags & kXR_readable) != 0
        && (info.flags & kXR_writable) == 0;
    brix_status_clear(&status);
    open_rc = readonly_reserve(execution, 0, &status)
        ? brix_file_open_update(connection, object.path, 0, &file, &status) : -1;
    open_kxr = status.kxr;
    if (open_rc == 0) brix_file_close(connection, &file, &status);
    snprintf(received, sizeof(received), "flags=0x%x open-kxr=%d",
        info.flags, open_kxr);
    xrd_conform_result_set(execution, "STA-005",
        flags_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                 : BRIX_CONFORM_VERDICT_DIVERGENT,
        flags_ok ? "readonly-stat-flags-honest" : "readonly-stat-flags-wrong",
        "readable set; writable clear", received);
    xrd_conform_result_set(execution, "STA-006",
        flags_ok && open_rc != 0 && open_kxr == kXR_fsReadOnly
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        flags_ok && open_rc != 0 && open_kxr == kXR_fsReadOnly
            ? "stat-and-open-policy-agree" : "stat-and-open-policy-disagree",
        "writable clear; update-open kXR_fsReadOnly", received);
}

/* ---- Detect a writable promise in a locate response ----
 *
 * WHAT: Returns one when any whitespace-delimited endpoint has access byte w.
 * WHY: LOC-004 must inspect every endpoint, not only the first advertised node.
 * HOW: Walk bounded C-string tokens and compare the second byte of valid tokens.
 */
static int
locate_promises_write(const char *reply)
{
    const char *cursor = reply;
    const char *start;
    size_t length;

    while (xrd_conform_next_locate_token(&cursor, &start, &length)) {
        if (length > 2 && start[1] == 'w') return 1;
    }
    return 0;
}

/* ---- Probe locate/open agreement on a read-only export ----
 *
 * WHAT: Grades LOC-004 using one locate reply and one update-open refusal.
 * WHY: A returned write-access byte is a dangerous promise when writes fail.
 * HOW: Locate the pre-seeded file, scan all access bytes, attempt update-open,
 *      and require no writable promise plus an fsReadOnly refusal.
 */
static void
probe_readonly_locate(xrd_conform_execution *execution, brix_conn *connection)
{
    char reply[2048] = { 0 };
    char received[192];
    xrd_conform_scratch_object object;
    brix_file file;
    brix_status status;
    int locate_rc;
    int open_rc;
    int open_kxr;
    int pass;

    if (readonly_path(execution, "brix-conform-readonly-file", &object) != 0)
        return;
    brix_status_clear(&status);
    locate_rc = readonly_reserve(execution, 0, &status)
        ? brix_locate(connection, object.path, reply, sizeof(reply), &status)
        : -1;
    brix_status_clear(&status);
    open_rc = readonly_reserve(execution, 0, &status)
        ? brix_file_open_update(connection, object.path, 0, &file, &status) : -1;
    open_kxr = status.kxr;
    if (open_rc == 0) brix_file_close(connection, &file, &status);
    pass = locate_rc == 0 && !locate_promises_write(reply)
        && open_rc != 0 && open_kxr == kXR_fsReadOnly;
    snprintf(received, sizeof(received), "open-kxr=%d locate=%.140s",
        open_kxr, reply);
    xrd_conform_result_set(execution, "LOC-004",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "readonly-locate-promise-honest"
             : "readonly-locate-promise-wrong",
        "no w access byte; update-open kXR_fsReadOnly", received);
}

/* ---- Report whether the exact clause needs the read-only fixture ----
 *
 * WHAT: Returns one for the implemented read-only exact-clause vocabulary.
 * WHY: These rows must bypass ordinary plant-before-probe execution.
 * HOW: Compare --only against a bounded local table of stable clause ids.
 */
int
xrd_conform_readonly_exact_selected(const xrd_conform_execution *execution)
{
    static const char *const ids[] = {
        "WRT-006", "OPN-011", "PGW-013", "TRN-006", "MKD-005", "MV-006",
        "RM-007", "CHM-003", "PRP-007", "STA-005", "STA-006", "LOC-004",
        "FAT-009", "CAC-010",
        "S3-009", "XPR-006",
    };
    const char *only;
    size_t index;

    if (execution == NULL || execution->run == NULL) return 0;
    only = execution->run->config.only;
    if (only == NULL) return 0;
    for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++) {
        if (strcmp(only, ids[index]) == 0) return 1;
    }
    return 0;
}

/* ---- Dispatch one exact read-only clause probe ----
 *
 * WHAT: Executes the probe matching --only and leaves every other row untouched.
 * WHY: A single-clause run provides safe pre-seeded-fixture semantics and a
 *      reproducible negative without attempting to plant on a read-only export.
 * HOW: Select a same-signature probe from a local descriptor table and invoke it.
 */
void
xrd_conform_probe_readonly_exact(xrd_conform_execution *execution,
    brix_conn *connection)
{
    const struct readonly_probe {
        const char *id;
        readonly_probe_fn probe;
    } probes[] = {
        { "WRT-006", probe_readonly_write },
        { "OPN-011", probe_readonly_write },
        { "PGW-013", probe_readonly_pgwrite },
        { "TRN-006", probe_readonly_truncate },
        { "MKD-005", probe_readonly_mkdir },
        { "MV-006", probe_readonly_move },
        { "RM-007", probe_readonly_remove },
        { "CHM-003", probe_readonly_chmod },
        { "PRP-007", probe_readonly_prepare },
        { "STA-005", probe_readonly_stat },
        { "STA-006", probe_readonly_stat },
        { "LOC-004", probe_readonly_locate },
        { "FAT-009", xrd_conform_probe_fattr_readonly },
        { "CAC-010", probe_readonly_write },
        { "S3-009", probe_s3_readonly_twin },
        { "XPR-006", probe_s3_readonly_twin },
    };
    size_t index;

    for (index = 0; index < sizeof(probes) / sizeof(probes[0]); index++) {
        if (strcmp(execution->run->config.only, probes[index].id) == 0) {
            probes[index].probe(execution, connection);
            return;
        }
    }
}
