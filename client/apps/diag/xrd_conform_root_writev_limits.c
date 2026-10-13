/* Phase-118 ROOT write-vector count-boundary probe. */
#include "xrd_conform_internal.h"

#include <arpa/inet.h>

#define WVC_LIMIT XRDC_VEC_MAXSEGS
#define WVC_DESCRIPTOR_SIZE 16U

static int
reserve(xrd_conform_execution *execution, size_t bytes, brix_status *status)
{
    char reason[64];

    if (xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) return 1;
    brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
    return 0;
}

/* WHAT: Send 1025 descriptors on an isolated connection.
 * WHY: Stock refusal drops the link, which must not poison later probes.
 * HOW: Authenticate a second connection and send an all-zero descriptor block;
 *      count validation precedes handle validation and returns ArgTooLong. */
static int
probe_one_over(xrd_conform_execution *execution, brix_status *status)
{
    ClientWriteVRequest request;
    brix_payload_ext payload;
    brix_resp_out response;
    brix_conn connection;
    brix_opts opts = execution->run->opts;
    brix_url url;
    uint8_t *descriptors = NULL;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    uint16_t stream_id;
    uint16_t wire_status = 0;
    int rc = -1;

    opts.capture = NULL;
    if (brix_endpoint_parse(execution->target, &url, status) != 0
        || brix_connect(&connection, &url, &opts, status) != 0)
        return -1;
    descriptors = calloc(WVC_LIMIT + 1U, WVC_DESCRIPTOR_SIZE);
    if (descriptors == NULL) {
        brix_status_set(status, XRDC_EIO, errno,
            "writev boundary allocation failed");
        brix_close(&connection);
        return -1;
    }
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_writev);
    xrdw_writev_req_t fields = { .options = 0 };
    xrdw_writev_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    payload.data = descriptors;
    payload.len = (WVC_LIMIT + 1U) * WVC_DESCRIPTOR_SIZE;
    payload.dlen = payload.len;
    response.status = &wire_status;
    response.body = &body;
    response.blen = &body_length;
    brix_status_clear(status);
    if (reserve(execution, 0, status)
        && brix_send_ext(&connection, &request, &payload, &stream_id,
            status) == 0)
        rc = brix_recv(&connection, stream_id, &response, status);
    free(body);
    free(descriptors);
    brix_close(&connection);
    return rc != 0 && status->kxr == kXR_ArgTooLong ? 0 : -1;
}

/* WHAT: Exercise the exact 1024/1025 kXR_writev segment boundary remotely.
 * WHY: A local client cap alone cannot prove remote count enforcement.
 * HOW: Write and read back 1024 distinct bytes, then isolate the dropping
 *      one-over request on a fresh connection and require kXR_ArgTooLong. */
void
xrd_conform_probe_writev_limits(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object)
{
    brix_writev_seg *segments = NULL;
    uint8_t *expected = NULL;
    uint8_t *actual = NULL;
    brix_file file;
    brix_status status;
    ssize_t got = -1;
    size_t index;
    int at_limit = 0;
    int over_limit;

    segments = calloc(WVC_LIMIT, sizeof(*segments));
    expected = malloc(WVC_LIMIT);
    actual = malloc(WVC_LIMIT);
    if (segments == NULL || expected == NULL || actual == NULL) {
        xrd_conform_result_set(execution, "WVC-002",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "local-allocation-failed",
            "1024 exact; 1025 kXR_ArgTooLong", NULL);
        free(actual); free(expected); free(segments);
        return;
    }
    brix_conform_fill(&execution->run->key, 0, expected, WVC_LIMIT);
    for (index = 0; index < WVC_LIMIT; index++) {
        segments[index].offset = (int64_t) index;
        segments[index].len = 1;
        segments[index].data = expected + index;
    }
    brix_status_clear(&status);
    if (reserve(execution, 0, &status)
        && brix_file_open_write(connection, object->path, 1, 0, &file,
            &status) == 0) {
        if (reserve(execution, WVC_LIMIT, &status)
            && brix_file_writev(connection, &file, segments, WVC_LIMIT, 0,
                &status) == 0)
            at_limit = 1;
        if (!reserve(execution, 0, &status)
            || brix_file_close(connection, &file, &status) != 0)
            at_limit = 0;
    }
    if (at_limit && reserve(execution, 0, &status)
        && brix_file_open_read(connection, object->path, &file, &status) == 0) {
        if (reserve(execution, WVC_LIMIT, &status))
            got = brix_file_read(connection, &file, 0, actual, WVC_LIMIT,
                &status);
        if (!reserve(execution, 0, &status)
            || brix_file_close(connection, &file, &status) != 0)
            at_limit = 0;
    }
    at_limit = at_limit && got == WVC_LIMIT
        && memcmp(actual, expected, WVC_LIMIT) == 0;
    over_limit = probe_one_over(execution, &status) == 0;
    xrd_conform_result_set(execution, "WVC-002",
        at_limit && over_limit ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        at_limit && over_limit ? "writev-count-boundary-enforced"
            : "writev-count-boundary-mismatch",
        "1024 byte-exact; 1025 kXR_ArgTooLong",
        at_limit && over_limit ? NULL : status.msg);
    free(actual); free(expected); free(segments);
}
