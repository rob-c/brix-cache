/* Phase-118 kXR_refresh metadata revalidation probe. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/codec/wire_codec.h"
#include "protocols/root/protocol/stat_line.h"

#include <arpa/inet.h>

typedef struct {
    uint8_t *body;
    uint32_t length;
} refresh_reply;

static int
reserve_op(xrd_conform_execution *execution, size_t bytes,
    brix_status *status)
{
    char reason[64];

    if (xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) return 1;
    brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
    return 0;
}

static int
raw_open(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, uint16_t options, refresh_reply *reply,
    brix_status *status)
{
    ClientOpenRequest request;
    xrdw_open_req_t fields = { .mode = 0, .options = options, .optiont = 0 };
    brix_payload payload = { path, (uint32_t) strlen(path) };
    uint16_t wire_status = 0;
    brix_resp_out response = { &wire_status, &reply->body, &reply->length };

    memset(reply, 0, sizeof(*reply));
    if (!reserve_op(execution, sizeof(request) + payload.len, status)) return -1;
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_open);
    xrdw_open_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    brix_status_clear(status);
    return brix_roundtrip(connection, &request, &payload, &response, status);
}

static int
reply_size(const refresh_reply *reply, int64_t *size)
{
    brix_statline_ext ext;
    uint64_t id;
    int flags;
    long mtime;
    char text[256];
    size_t length;

    if (reply->length <= sizeof(ServerOpenBody)) return -1;
    length = reply->length - sizeof(ServerOpenBody);
    if (length >= sizeof(text)) return -1;
    memcpy(text, reply->body + sizeof(ServerOpenBody), length);
    text[length] = '\0';
    return brix_statline_parse(text, &id, size, &flags, &mtime, &ext);
}

static void
close_reply(xrd_conform_execution *execution, brix_conn *connection,
    const refresh_reply *reply, brix_status *status)
{
    brix_file file = { { 0 }, 0, 0 };

    if (reply->length < XRD_FHANDLE_LEN) return;
    memcpy(file.fhandle, reply->body, XRD_FHANDLE_LEN);
    if (reserve_op(execution, 0, status))
        brix_file_close(connection, &file, status);
}

static int
replace_from_auxiliary(xrd_conform_execution *execution,
    const xrd_conform_scratch_object *object, const void *data, size_t length,
    brix_status *status)
{
    brix_url url;
    brix_conn auxiliary;
    brix_file file;
    brix_opts opts = execution->run->opts;
    int connected = 0;
    int opened = 0;
    int rc = -1;

    opts.capture = NULL;
    if (brix_endpoint_parse(execution->target, &url, status) != 0
        || brix_connect(&auxiliary, &url, &opts, status) != 0) return -1;
    connected = 1;
    if (reserve_op(execution, 0, status)
        && brix_file_open_write(&auxiliary, object->path, 1, 0, &file,
            status) == 0) {
        opened = 1;
        if (reserve_op(execution, length, status)
            && brix_file_write(&auxiliary, &file, 0, data, length,
                status) == 0)
            rc = 0;
    }
    if (opened && (!reserve_op(execution, 0, status)
        || brix_file_close(&auxiliary, &file, status) != 0)) rc = -1;
    if (connected) brix_close(&auxiliary);
    return rc;
}

/* WHAT: Observe a refreshed open after another session replaces the object.
 * WHY: Reusing cached pre-mutation metadata would return a stale inline size.
 * HOW: Prime retstat at three bytes, replace with fourteen bytes through an
 *      independent authenticated connection, then parse refresh+retstat. */
void
xrd_conform_probe_open_refresh(xrd_conform_execution *execution,
    brix_conn *connection)
{
    static const char before[] = "old";
    static const char after[] = "refreshed-size";
    const brix_conform_result *row = xrd_conform_result_find(execution,
        "OPN-021");
    xrd_conform_scratch_object object;
    refresh_reply initial = { 0 }, refreshed = { 0 };
    brix_file file;
    brix_status status;
    int64_t initial_size = -1;
    int64_t refreshed_size = -1;
    int rc = -1;
    int pass;
    char received[160];

    if (row == NULL || row->verdict == BRIX_CONFORM_VERDICT_SKIPPED) return;
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-open-refresh", object.path,
            sizeof(object.path)) != 0) return;
    brix_status_clear(&status);
    if (reserve_op(execution, 0, &status)
        && brix_file_open_write(connection, object.path, 1, 0, &file,
            &status) == 0) {
        if (reserve_op(execution, sizeof(before) - 1, &status)
            && brix_file_write(connection, &file, 0, before,
                sizeof(before) - 1, &status) == 0
            && reserve_op(execution, 0, &status)
            && brix_file_close(connection, &file, &status) == 0
            && raw_open(execution, connection, object.path,
                kXR_open_read | kXR_retstat, &initial, &status) == 0
            && reply_size(&initial, &initial_size) == 0
            && replace_from_auxiliary(execution, &object, after,
                sizeof(after) - 1, &status) == 0
            && raw_open(execution, connection, object.path,
                kXR_open_read | kXR_refresh | kXR_retstat, &refreshed,
                &status) == 0
            && reply_size(&refreshed, &refreshed_size) == 0)
            rc = 0;
    }
    close_reply(execution, connection, &initial, &status);
    close_reply(execution, connection, &refreshed, &status);
    pass = rc == 0 && initial_size == (int64_t) (sizeof(before) - 1)
        && refreshed_size == (int64_t) (sizeof(after) - 1);
    snprintf(received, sizeof(received), "before=%lld refreshed=%lld kxr=%d",
        (long long) initial_size, (long long) refreshed_size, status.kxr);
    xrd_conform_result_set(execution, "OPN-021",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "refresh-open-observed-independent-metadata-change"
             : "refresh-open-returned-stale-or-invalid-metadata",
        "before=3 refreshed=14", received);
    if (reserve_op(execution, 0, &status))
        brix_rm(connection, object.path, &status);
    free(initial.body);
    free(refreshed.body);
}
