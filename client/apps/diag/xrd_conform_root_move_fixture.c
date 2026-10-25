/* Phase-118 cross-export kXR_mv refusal fixture. */
#include "xrd_conform_probe_helpers.h"


static int
same_authority(const brix_url *source, const brix_url *destination)
{
    return source->scheme == destination->scheme
        && source->port == destination->port
        && strcmp(source->host, destination->host) == 0;
}

static int
defined_cross_export_refusal(int kxr)
{
    return kxr == kXR_NotAuthorized || kxr == kXR_InvalidRequest
        || kxr == kXR_Unsupported || kxr == kXR_fsReadOnly;
}

static int
move_row_active(const brix_conform_result *row)
{
    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static int
move_refused_safely(int move_rc, int move_kxr, int source_present,
    int destination_present)
{
    return move_rc != 0 && defined_cross_export_refusal(move_kxr)
        && source_present && !destination_present;
}

static int
object_exists(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    brix_statinfo info;

    brix_status_clear(status);
    return xrd_conform_reserve_zero_status(execution, status)
        && brix_stat(connection, object->path, &info, status) == 0;
}

static int
create_source(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    static const uint8_t payload[] = "phase118-cross-export-move";
    brix_file file;
    int rc;

    brix_status_clear(status);
    if (!xrd_conform_reserve_zero_status(execution, status)
        || brix_file_open_write(connection, object->path, 1, 0, &file,
            status) != 0) return -1;
    rc = xrd_conform_reserve(execution, sizeof(payload), NULL, 0)
        ? brix_file_write(connection, &file, 0, payload, sizeof(payload),
            status) : -1;
    if (!xrd_conform_reserve_zero_status(execution, status)
        || brix_file_close(connection, &file, status) != 0) rc = -1;
    return rc;
}

static void
cleanup_objects(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *source,
    const xrd_conform_scratch_object *destination)
{
    brix_status status;

    if (xrd_conform_reserve_zero_status(execution, &status))
        brix_rm(connection, source->path, &status);
    if (xrd_conform_reserve_zero_status(execution, &status))
        brix_rm(connection, destination->path, &status);
}

/* WHAT: Attempt one rename between two explicitly asserted export roots.
 * WHY: A server must not implement cross-export rename as an unreported copy;
 *      the source and destination state are part of the security oracle.
 * HOW: Mint one run-keyed child beneath each scratch root, create the source,
 *      require a defined refusal, verify source-present/destination-absent,
 *      and clean both paths even after a divergent response. */
void
xrd_conform_probe_cross_export_move(xrd_conform_execution *execution)
{
    brix_conform_result *row = xrd_conform_result_find(execution, "MV-005");
    xrd_conform_scratch_object source, destination;
    brix_url source_url, destination_url;
    brix_conn connection;
    brix_status status;
    char leaf[80];
    char received[160];
    int move_rc = -1;
    int move_kxr = 0;
    int source_present = 0;
    int destination_present = 0;
    int pass;

    if (!move_row_active(row)) return;
    if (execution->run->move_fixture_target == NULL) return;
    brix_status_clear(&status);
    if (brix_endpoint_parse(execution->run->config.target, &source_url,
            &status) != 0
        || brix_endpoint_parse(execution->run->move_fixture_target,
            &destination_url, &status) != 0
        || !same_authority(&source_url, &destination_url)) {
        xrd_conform_result_set(execution, "MV-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "move-fixture-authority-mismatch", NULL, status.msg);
        return;
    }
    snprintf(leaf, sizeof(leaf), "brix-conform-mv-cross-%s",
        execution->run->key_hex);
    if (brix_conform_scratch_path(execution->run->config.scratch, leaf,
            source.path, sizeof(source.path)) != 0
        || brix_conform_scratch_path(destination_url.path, leaf,
            destination.path, sizeof(destination.path)) != 0) return;
    if (brix_connect(&connection, &source_url, &execution->run->opts,
            &status) != 0) {
        xrd_conform_result_set(execution, "MV-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "two-export-move-fixture-unavailable", NULL, status.msg);
        return;
    }
    if (create_source(execution, &connection, &source, &status) != 0
        || object_exists(execution, &connection, &destination, &status)) {
        cleanup_objects(execution, &connection, &source, &destination);
        brix_close(&connection);
        xrd_conform_result_set(execution, "MV-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "two-export-move-fixture-invalid-state", NULL, status.msg);
        return;
    }
    brix_status_clear(&status);
    if (xrd_conform_reserve_zero_status(execution, &status))
        move_rc = brix_mv(&connection, source.path, destination.path, &status);
    move_kxr = status.kxr;
    source_present = object_exists(execution, &connection, &source, &status);
    destination_present = object_exists(execution, &connection, &destination,
        &status);
    snprintf(received, sizeof(received),
        "mv=%d kxr=%d source=%d destination=%d", move_rc, move_kxr,
        source_present, destination_present);
    pass = move_refused_safely(move_rc, move_kxr, source_present,
        destination_present);
    xrd_conform_result_set(execution, "MV-005",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "cross-export-move-refused-without-copy"
            : "cross-export-move-was-undefined-or-mutated-state",
        "defined refusal; source=present destination=absent", received);
    cleanup_objects(execution, &connection, &source, &destination);
    brix_close(&connection);
}
