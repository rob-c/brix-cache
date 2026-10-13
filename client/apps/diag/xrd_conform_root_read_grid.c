/* Phase-118 ordinary-read partition consistency probes. */
#include "xrd_conform_internal.h"

#include <pthread.h>

typedef struct {
    brix_conn *connection;
    brix_file *file;
    int64_t offset;
    uint8_t *buffer;
    size_t length;
    ssize_t got;
    brix_status status;
} conform_read_job;

static void *
run_read_job(void *opaque)
{
    conform_read_job *job = opaque;

    brix_status_clear(&job->status);
    job->got = brix_file_read(job->connection, job->file, job->offset,
        job->buffer, job->length, &job->status);
    return NULL;
}

static int
read_partition(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size, uint64_t pieces)
{
    uint64_t index;
    char reason[64];

    if (size == 0) return 1;
    if (pieces > size) pieces = size;
    for (index = 0; index < pieces; index++) {
        uint64_t begin = index * size / pieces;
        uint64_t end = (index + 1) * size / pieces;
        size_t length = (size_t) (end - begin);
        uint8_t *buffer;
        brix_status status;
        ssize_t got;

        if (!xrd_conform_reserve(execution, length, reason, sizeof(reason)))
            return -1;
        buffer = malloc(length == 0 ? 1 : length);
        if (buffer == NULL) return -1;
        brix_status_clear(&status);
        got = brix_file_read(connection, file, (int64_t) begin, buffer, length,
            &status);
        if (got != (ssize_t) length
            || (length > 0 && memcmp(buffer, baseline + begin, length) != 0)) {
            free(buffer);
            return 0;
        }
        free(buffer);
    }
    return 1;
}

void
xrd_conform_probe_read_partitions(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size)
{
    static const uint64_t boundary[] = { 2, 7 };
    static const uint64_t pairwise[] = { 2, 3, 7, 4096 };
    const uint64_t *counts = pairwise;
    size_t count = sizeof(pairwise) / sizeof(pairwise[0]);
    size_t index;
    int result = 1;

    if (execution->run->config.budget == BRIX_CONFORM_BOUNDARY) {
        counts = boundary;
        count = sizeof(boundary) / sizeof(boundary[0]);
    }
    for (index = 0; index < count && result > 0; index++)
        result = read_partition(execution, connection, file, baseline, size,
            counts[index]);
    if (result > 0 && execution->run->config.budget == BRIX_CONFORM_EXHAUSTIVE)
        result = read_partition(execution, connection, file, baseline, size,
            size);
    xrd_conform_result_set(execution, "RD-014",
        result > 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                   : result < 0 ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                                : BRIX_CONFORM_VERDICT_DIVERGENT,
        result > 0 ? "all-selected-partitions-reassembled-byte-exact"
                   : result < 0 ? "partition-grid-resource-ceiling"
                                : "partition-reassembly-mismatch",
        NULL, NULL);
}

void
xrd_conform_probe_read_substreams(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    uint64_t size)
{
    brix_streamset streams;
    brix_status status;
    pthread_t threads[2];
    conform_read_job jobs[2];
    uint8_t buffers[2][4096];
    char reason[64];
    size_t length = size < sizeof(buffers[0]) ? (size_t) size
                                               : sizeof(buffers[0]);
    int created = 0;
    int ok = 0;

    if (length == 0 || !xrd_conform_reserve(execution, length * 2, reason,
            sizeof(reason))) return;
    brix_status_clear(&status);
    if (brix_streams_open(&streams, connection, 3, &status) < 2) {
        xrd_conform_result_set(execution, "RD-016",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "two-bound-request-streams-unavailable", NULL, status.msg);
        return;
    }
    memset(jobs, 0, sizeof(jobs));
    for (created = 0; created < 2; created++) {
        jobs[created].connection = &streams.sec[created];
        jobs[created].file = file;
        jobs[created].offset = 0;
        jobs[created].buffer = buffers[created];
        jobs[created].length = length;
        if (pthread_create(&threads[created], NULL, run_read_job,
                &jobs[created]) != 0) break;
    }
    while (created > 0) {
        created--;
        pthread_join(threads[created], NULL);
    }
    ok = jobs[0].got == (ssize_t) length
        && jobs[1].got == (ssize_t) length
        && memcmp(buffers[0], baseline, length) == 0
        && memcmp(buffers[1], baseline, length) == 0
        && memcmp(buffers[0], buffers[1], length) == 0;
    xrd_conform_result_set(execution, "RD-016",
        ok ? BRIX_CONFORM_VERDICT_CONFORMANT
           : BRIX_CONFORM_VERDICT_DIVERGENT,
        ok ? "overlapping-bound-stream-reads-agree"
           : "bound-stream-read-mismatch", NULL, NULL);
    brix_streams_close(&streams);
}
