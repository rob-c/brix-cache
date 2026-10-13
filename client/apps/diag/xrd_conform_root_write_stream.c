/* Phase-118 concurrent and deliberately truncated ROOT write probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/frame_hdr.h"
#include "core/types/tunables.h"

#include <pthread.h>

typedef struct {
    brix_conn *connection;
    brix_file *file;
    int64_t offset;
    const uint8_t *data;
    size_t length;
    int rc;
    brix_status status;
} conform_write_job;

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

static int
open_write(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, int force, brix_file *file,
    brix_status *status)
{
    if (!reserve_op(execution, 0, status)) return -1;
    return brix_file_open_write(connection, object->path, force, 0, file,
        status);
}

static int
close_file(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, brix_status *status)
{
    if (!reserve_op(execution, 0, status)) return -1;
    return brix_file_close(connection, file, status);
}

static int
read_exact(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, void *data, size_t length,
    brix_status *status)
{
    brix_file file;
    ssize_t got = -1;

    if (!reserve_op(execution, 0, status)
        || brix_file_open_read(connection, object->path, &file, status) != 0)
        return -1;
    if (reserve_op(execution, length, status))
        got = brix_file_read(connection, &file, 0, data, length, status);
    if (close_file(execution, connection, &file, status) != 0) return -1;
    return got == (ssize_t) length ? 0 : -1;
}

static void *
run_write_job(void *opaque)
{
    conform_write_job *job = opaque;

    brix_status_clear(&job->status);
    job->rc = brix_file_write(job->connection, job->file, job->offset,
        job->data, job->length, &job->status);
    return NULL;
}

void
xrd_conform_probe_concurrent_write(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object)
{
    uint8_t left[4096], right[4096], actual[8192];
    conform_write_job jobs[2];
    pthread_t threads[2];
    brix_streamset streams;
    brix_file file;
    brix_status status;
    char reason[64];
    int created = 0;
    int ok;

    memset(left, 'L', sizeof(left));
    memset(right, 'R', sizeof(right));
    brix_status_clear(&status);
    if (open_write(execution, connection, object, 1, &file, &status) != 0) {
        grade(execution, "WRT-011", 0, "concurrent-extents-landed",
            "concurrent-write-open-failed", &status);
        return;
    }
    if (brix_streams_open(&streams, connection, 3, &status) < 2) {
        close_file(execution, connection, &file, &status);
        xrd_conform_result_set(execution, "WRT-011",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "two-bound-write-streams-unavailable", NULL, status.msg);
        return;
    }
    if (!xrd_conform_reserve(execution, sizeof(actual), reason,
            sizeof(reason))) {
        brix_streams_close(&streams);
        close_file(execution, connection, &file, &status);
        xrd_conform_result_set(execution, "WRT-011",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL, NULL);
        return;
    }
    memset(jobs, 0, sizeof(jobs));
    jobs[0] = (conform_write_job) {
        &streams.sec[0], &file, 0, left, sizeof(left), -1, { 0 }
    };
    jobs[1] = (conform_write_job) {
        &streams.sec[1], &file, sizeof(left), right, sizeof(right), -1, { 0 }
    };
    while (created < 2 && pthread_create(&threads[created], NULL,
            run_write_job, &jobs[created]) == 0) created++;
    for (int index = 0; index < created; index++)
        pthread_join(threads[index], NULL);
    close_file(execution, connection, &file, &status);
    brix_streams_close(&streams);
    ok = created == 2 && jobs[0].rc == 0 && jobs[1].rc == 0
        && read_exact(execution, connection, object, actual, sizeof(actual),
            &status) == 0
        && memcmp(actual, left, sizeof(left)) == 0
        && memcmp(actual + sizeof(left), right, sizeof(right)) == 0;
    grade(execution, "WRT-011", ok, "concurrent-extents-landed",
        created == 2 ? "concurrent-write-readback-mismatch"
                     : "concurrent-write-thread-failed",
        created == 2 && jobs[0].rc != 0 ? &jobs[0].status
            : created == 2 && jobs[1].rc != 0 ? &jobs[1].status : &status);
}

void
xrd_conform_probe_truncated_write(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object)
{
    static const uint8_t baseline[] = "complete-baseline";
    static const uint8_t prefix[] = "partial";
    uint8_t actual[sizeof(baseline)];
    ClientWriteRequest request;
    xrdw_write_req_t fields = { .offset = 0, .pathid = 0 };
    brix_payload_ext payload = {
        .data = prefix, .len = sizeof(prefix), .dlen = sizeof(prefix) + 17U
    };
    brix_streamset streams;
    brix_file file;
    brix_statinfo info;
    brix_status status;
    uint16_t stream_id;
    int rc;

    brix_status_clear(&status);
    rc = open_write(execution, connection, object, 1, &file, &status);
    if (rc == 0 && reserve_op(execution, sizeof(baseline), &status))
        rc = brix_file_write(connection, &file, 0, baseline, sizeof(baseline),
            &status);
    if (rc == 0) rc = close_file(execution, connection, &file, &status);
    if (rc != 0) {
        grade(execution, "WRT-010", 0, "truncated-write-discarded",
            "truncated-write-baseline-failed", &status);
        return;
    }
    if (open_write(execution, connection, object, 2, &file, &status) != 0) {
        grade(execution, "WRT-010", 0, "truncated-write-discarded",
            "truncated-write-update-open-failed", &status);
        return;
    }
    if (brix_streams_open(&streams, connection, 2, &status) < 1) {
        close_file(execution, connection, &file, &status);
        xrd_conform_result_set(execution, "WRT-010",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "bound-disposable-stream-unavailable", NULL, status.msg);
        return;
    }
    if (!reserve_op(execution, payload.dlen, &status)) {
        brix_streams_close(&streams);
        close_file(execution, connection, &file, &status);
        xrd_conform_result_set(execution, "WRT-010",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, status.msg, NULL, NULL);
        return;
    }
    memcpy(fields.fhandle, file.fhandle, sizeof(fields.fhandle));
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_write);
    xrdw_write_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    rc = brix_send_ext(&streams.sec[0], &request, &payload, &stream_id,
        &status);
    brix_streams_close(&streams);
    if (close_file(execution, connection, &file, &status) != 0) rc = -1;
    if (rc == 0 && read_exact(execution, connection, object, actual,
            sizeof(actual), &status) != 0) rc = -1;
    if (rc == 0 && (!reserve_op(execution, 0, &status)
            || brix_stat(connection, object->path, &info, &status) != 0))
        rc = -1;
    grade(execution, "WRT-010", rc == 0
        && info.size == (int64_t) sizeof(baseline)
        && memcmp(actual, baseline, sizeof(baseline)) == 0,
        "truncated-write-discarded", "truncated-write-partially-applied",
        &status);
}

/* WHAT: Advertise a write one byte beyond the server's streaming ceiling.
 * WHY: A path-sized framing gate or a silent reset does not define the write
 *      payload limit and leaves clients unable to classify the refusal.
 * HOW: Use a disposable authenticated connection, send only the request header,
 *      and require kXR_ArgTooLong before the server closes the unsynchronizable
 *      stream. */
void
xrd_conform_probe_oversized_write(xrd_conform_execution *execution)
{
    ClientWriteRequest request;
    brix_payload_ext payload = {
        .data = NULL, .len = 0, .dlen = BRIX_MAX_WRITE_STREAM + 1U
    };
    brix_resp_out response;
    brix_conn connection;
    brix_opts opts = execution->run->opts;
    brix_url url;
    brix_status status;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    uint16_t stream_id;
    uint16_t wire_status = 0;
    int rc = -1;

    brix_status_clear(&status);
    opts.capture = NULL;
    if (brix_endpoint_parse(execution->target, &url, &status) == 0
        && brix_connect(&connection, &url, &opts, &status) == 0) {
        memset(&request, 0, sizeof(request));
        request.requestid = htons(kXR_write);
        response.status = &wire_status;
        response.body = &body;
        response.blen = &body_length;
        if (reserve_op(execution, 0, &status)
            && brix_send_ext(&connection, &request, &payload, &stream_id,
                &status) == 0)
            rc = brix_recv(&connection, stream_id, &response, &status);
        brix_close(&connection);
    }
    free(body);
    grade(execution, "WRT-008", rc != 0 && status.kxr == kXR_ArgTooLong,
        "oversized-write-refused-with-ArgTooLong",
        "oversized-write-lacked-defined-error", &status);
}
