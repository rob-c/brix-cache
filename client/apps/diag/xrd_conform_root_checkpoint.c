/* Phase-118 scratch-confined kXR_chkpoint probes. */
#include "xrd_conform_probe_helpers.h"
#include "protocols/root/protocol/frame_hdr.h"
#include "xrd_conform_reply.h"
#include "protocols/root/protocol/codec/wire_codec.h"

#include <arpa/inet.h>




/* WHAT: Send one checkpoint sub-operation for an already-open write handle.
 * WHY: The client library has no convenience wrapper for the transactional op.
 * HOW: Pack the authoritative fixed body and retain the response for Query. */
static int
checkpoint_op(xrd_conform_execution *execution, brix_conn *connection,
    const brix_file *file, uint8_t opcode, xrd_conform_wire_reply *reply,
    brix_status *status)
{
    ClientChkPointRequest request;
    xrdw_chkpoint_req_t fields = { .opcode = opcode };
    uint16_t wire_status = 0;
    brix_resp_out response = { &wire_status, &reply->body, &reply->length };

    memset(reply, 0, sizeof(*reply));
    if (!xrd_conform_reserve_status(execution, sizeof(request), status)) return -1;
    memcpy(fields.fhandle, file->fhandle, sizeof(fields.fhandle));
    xrd_creq_begin(&request, sizeof(request), 0, kXR_chkpoint);
    xrdw_chkpoint_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(status);
    return brix_roundtrip(connection, &request, NULL, &response, status);
}

/* WHAT: Record a checkpoint verdict with bounded kXR evidence.
 * WHY: Unsupported, over-quota, and generic server failure are distinct results.
 * HOW: Map a boolean into the verdict algebra and preserve status text. */
static void
grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const char *failure, const brix_status *status)
{
    char received[192];

    snprintf(received, sizeof(received), "kxr=%d %.150s", status->kxr,
        status->msg);
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : failure, NULL, received);
}

/* WHAT: Create a known file through the public write API.
 * WHY: Rollback needs a byte oracle independent of checkpoint implementation.
 * HOW: Create/truncate, write the fixed seed, and close every request cleanly. */
static int
seed_file(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, const void *data, size_t length,
    brix_status *status)
{
    brix_file file;
    int rc;

    if (!xrd_conform_reserve_status(execution, 0, status)
        || brix_file_open_write(connection, object->path, 1, 0, &file,
            status) != 0)
        return -1;
    rc = xrd_conform_reserve_status(execution, length, status)
        ? brix_file_write(connection, &file, 0, data, length, status) : -1;
    if (!xrd_conform_reserve_status(execution, 0, status)
        || brix_file_close(connection, &file, status) != 0) rc = -1;
    return rc;
}

/* WHAT: Reopen a path and compare an exact bounded prefix.
 * WHY: CKP-003 must prove rollback bytes rather than infer from status alone.
 * HOW: Typed read-open/read/close and a byte-for-byte comparison. */
static int
read_matches(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, const void *expected, size_t length, brix_status *status)
{
    uint8_t actual[64];
    brix_file file;
    ssize_t got = -1;

    if (length > sizeof(actual) || !xrd_conform_reserve_status(execution, 0, status)
        || brix_file_open_read(connection, path, &file, status) != 0) return 0;
    if (xrd_conform_reserve_status(execution, length, status))
        got = brix_file_read(connection, &file, 0, actual, length, status);
    if (xrd_conform_reserve_status(execution, 0, status))
        brix_file_close(connection, &file, status);
    return got == (ssize_t) length && memcmp(actual, expected, length) == 0;
}

static void
cleanup_checkpoint_object(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object,
    brix_status *status)
{
    if (xrd_conform_reserve_status(execution, 0, status))
        brix_rm(connection, object->path, status);
}

static int
query_checkpoint_capacity(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, uint32_t *maximum,
    brix_status *status)
{
    xrd_conform_wire_reply reply = { 0 };
    uint32_t used = 0;
    int rc = checkpoint_op(execution, connection, file, kXR_ckpQuery,
        &reply, status);

    if (rc != 0 && status->kxr == kXR_Unsupported) {
        grade(execution, "CKP-001", 1, "checkpoint-explicitly-unsupported",
            "checkpoint-wrong-answer", status);
        xrd_conform_result_set(execution, "CKP-002",
            BRIX_CONFORM_VERDICT_SKIPPED, "checkpoint-unsupported", NULL, NULL);
        xrd_conform_result_set(execution, "CKP-003",
            BRIX_CONFORM_VERDICT_SKIPPED, "checkpoint-unsupported", NULL, NULL);
        xrd_conform_result_set(execution, "CKP-004",
            BRIX_CONFORM_VERDICT_SKIPPED, "checkpoint-unsupported", NULL, NULL);
        free(reply.body);
        return 0;
    }
    grade(execution, "CKP-001", rc == 0 && reply.length == 8,
        "checkpoint-query-implemented", "checkpoint-query-malformed", status);
    if (rc == 0 && reply.length == 8) {
        *maximum = xrdw_get_u32(reply.body);
        used = xrdw_get_u32(reply.body + 4);
    }
    grade(execution, "CKP-002", *maximum >= used && *maximum > 0,
        "checkpoint-capacity-consistent", "checkpoint-capacity-invalid",
        status);
    free(reply.body);
    return 1;
}

static int
rollback_restores_bytes(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    static const char before[] = "before-checkpoint";
    static const char after[] = "after-checkpoint!";
    xrd_conform_wire_reply reply = { 0 };
    int began;
    int wrote = 0;
    int rolled_back = 0;

    began = checkpoint_op(execution, connection, file, kXR_ckpBegin, &reply,
        status) == 0;
    free(reply.body);
    if (began && xrd_conform_reserve_status(execution, sizeof(after), status))
        wrote = brix_file_write(connection, file, 0, after, sizeof(after),
            status) == 0;
    if (began) {
        rolled_back = checkpoint_op(execution, connection, file,
            kXR_ckpRollback, &reply, status) == 0;
        free(reply.body);
    }
    if (xrd_conform_reserve_status(execution, 0, status))
        brix_file_close(connection, file, status);
    return began && wrote && rolled_back
        && read_matches(execution, connection, object->path, before,
            sizeof(before), status);
}

static int
overlimit_refused_without_loss(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object,
    uint32_t maximum, brix_status *status)
{
    xrd_conform_wire_reply reply = { 0 };
    brix_statinfo info;
    brix_file file;
    uint64_t oversized = (uint64_t) maximum + 1U;
    int refusal_kxr = 0;
    int rc;

    rc = xrd_conform_reserve_status(execution, 0, status)
        ? brix_truncate(connection, object->path, (int64_t) oversized, status)
        : -1;
    if (rc == 0 && xrd_conform_reserve_status(execution, 0, status))
        rc = brix_file_open_update(connection, object->path, 0, &file, status);
    if (rc == 0) {
        rc = checkpoint_op(execution, connection, &file, kXR_ckpBegin,
            &reply, status);
        refusal_kxr = status->kxr;
        free(reply.body);
        if (xrd_conform_reserve_status(execution, 0, status))
            brix_file_close(connection, &file, status);
    }
    memset(&info, 0, sizeof(info));
    return rc != 0 && refusal_kxr == kXR_overQuota
        && xrd_conform_reserve_status(execution, 0, status)
        && brix_stat(connection, object->path, &info, status) == 0
        && (uint64_t) info.size == oversized;
}

/* WHAT: Execute the complete safe checkpoint family against one scratch file.
 * WHY: Query, rollback, and over-limit refusal share one advertised capacity.
 * HOW: Query first, snapshot/write/rollback, then create a sparse max+1 object
 *      and require refusal without a size change before final cleanup. */
void
xrd_conform_probe_checkpoints(xrd_conform_execution *execution,
    brix_conn *connection)
{
    static const char before[] = "before-checkpoint";
    xrd_conform_scratch_object object;
    brix_file file;
    brix_status status;
    uint32_t maximum = 0;
    int rollback_ok;
    int overlimit_ok;

    if (!xrd_conform_family_active(execution, "CKP")
        || brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-checkpoint", object.path, sizeof(object.path)) != 0)
        return;
    brix_status_clear(&status);
    if (seed_file(execution, connection, &object, before, sizeof(before),
            &status) != 0 || !xrd_conform_reserve_status(execution, 0, &status)
        || brix_file_open_update(connection, object.path, 0, &file, &status) != 0)
        return;
    if (!query_checkpoint_capacity(execution, connection, &file, &maximum,
            &status)) {
        if (xrd_conform_reserve_status(execution, 0, &status))
            brix_file_close(connection, &file, &status);
        cleanup_checkpoint_object(execution, connection, &object, &status);
        return;
    }
    rollback_ok = rollback_restores_bytes(execution, connection, &file,
        &object, &status);
    grade(execution, "CKP-003", rollback_ok,
        "checkpoint-rollback-restored-bytes", "checkpoint-rollback-mismatch",
        &status);
    overlimit_ok = overlimit_refused_without_loss(execution, connection,
        &object, maximum, &status);
    grade(execution, "CKP-004", overlimit_ok,
        "overlimit-checkpoint-refused-before-data-loss",
        "overlimit-checkpoint-wrong-answer", &status);
    cleanup_checkpoint_object(execution, connection, &object, &status);
}
