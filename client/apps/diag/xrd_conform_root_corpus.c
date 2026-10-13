/* Phase-118 sparse large-offset standard-corpus probe. */
#include "xrd_conform_internal.h"

#include <arpa/inet.h>

#define CONFORM_L_SIZE UINT64_C(5368709121)
#define CONFORM_L_OFFSET INT64_C(2147483649)
#define CONFORM_L_PROBE 8192U

static void
mark_large_unavailable(xrd_conform_execution *execution, const char *detail)
{
    xrd_conform_result_set(execution, "RD-011",
        BRIX_CONFORM_VERDICT_INCONCLUSIVE, "large-sparse-object-unavailable",
        NULL, detail);
    xrd_conform_result_set(execution, "PGR-028",
        BRIX_CONFORM_VERDICT_INCONCLUSIVE, "large-sparse-object-unavailable",
        NULL, detail);
}

static int
large_offset_io(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file)
{
    uint8_t expected[CONFORM_L_PROBE];
    uint8_t actual[CONFORM_L_PROBE];
    brix_status status;
    char reason[64];
    unsigned partials;
    ssize_t got;
    int exact;

    brix_conform_fill(&execution->run->key, (uint64_t) CONFORM_L_OFFSET,
        expected, sizeof(expected));
    if (!xrd_conform_reserve(execution, sizeof(expected), reason,
            sizeof(reason))) return -1;
    brix_status_clear(&status);
    if (brix_file_write(connection, file, CONFORM_L_OFFSET, expected,
            sizeof(expected), &status) != 0) return -1;
    if (!xrd_conform_reserve(execution, sizeof(actual), reason,
            sizeof(reason))) return -1;
    brix_status_clear(&status);
    got = brix_file_read(connection, file, CONFORM_L_OFFSET, actual,
        sizeof(actual), &status);
    exact = got == (ssize_t) sizeof(actual)
        && memcmp(actual, expected, sizeof(actual)) == 0;
    xrd_conform_result_set(execution, "RD-011",
        exact ? BRIX_CONFORM_VERDICT_CONFORMANT
              : BRIX_CONFORM_VERDICT_DIVERGENT,
        exact ? "large-offset-bytes-position-correct"
              : "large-offset-read-mismatch", NULL, status.msg);

    if (!xrd_conform_reserve(execution, sizeof(actual), reason,
            sizeof(reason))) return -1;
    partials = 0;
    brix_status_clear(&status);
    got = brix_file_pgread_profile(connection, file, CONFORM_L_OFFSET, actual,
        sizeof(actual), &partials, &status);
    exact = got == (ssize_t) sizeof(actual)
        && memcmp(actual, expected, sizeof(actual)) == 0;
    xrd_conform_result_set(execution, "PGR-028",
        exact ? BRIX_CONFORM_VERDICT_CONFORMANT
              : BRIX_CONFORM_VERDICT_DIVERGENT,
        exact ? "large-offset-page-crcs-position-correct"
              : "large-offset-pgread-mismatch", NULL, status.msg);
    return exact ? 1 : 0;
}

int
xrd_conform_probe_large_offset(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object object_storage;
    xrd_conform_scratch_object *object = &object_storage;
    brix_file file;
    brix_status status;
    int opened = 0;
    int io_result = -1;
    int cleanup_ok;

    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-L", object->path, sizeof(object->path)) != 0)
        return -1;
    brix_status_clear(&status);
    if (brix_file_open_write(connection, object->path, 1, 0, &file,
            &status) == 0) {
        opened = 1;
        if (brix_file_close(connection, &file, &status) == 0) opened = 0;
        if (!opened && brix_truncate(connection, object->path,
                (int64_t) CONFORM_L_SIZE, &status) == 0
            && brix_file_open_update(connection, object->path, 0, &file,
                &status) == 0) {
            opened = 1;
            io_result = large_offset_io(execution, connection, &file);
        }
    }
    if (io_result < 0) mark_large_unavailable(execution, status.msg);
    if (opened) {
        brix_status close_status;
        brix_status_clear(&close_status);
        brix_file_close(connection, &file, &close_status);
    }
    brix_status_clear(&status);
    cleanup_ok = brix_rm(connection, object->path, &status) == 0;
    return cleanup_ok ? 0 : -1;
}

static int
open_write_only(brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_file *file,
    brix_status *status)
{
    ClientOpenRequest request;
    xrdw_open_req_t fields = {
        .mode = 0644,
        .options = kXR_open_wrto | kXR_delete | kXR_mkpath,
        .optiont = 0
    };
    brix_payload payload = { object->path, (uint32_t) strlen(object->path) };
    uint16_t wire_status = 0;
    uint8_t *body = NULL;
    uint32_t body_length = 0;
    brix_resp_out response = { &wire_status, &body, &body_length };
    int rc;

    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_open);
    xrdw_open_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    rc = brix_roundtrip(connection, &request, &payload, &response, status);
    if (rc == 0 && body_length >= sizeof(file->fhandle)) {
        memcpy(file->fhandle, body, sizeof(file->fhandle));
        file->read_codec = 0;
        file->write_codec = 0;
    } else if (rc == 0) {
        brix_status_set(status, XRDC_EPROTO, 0,
                        "write-only open reply too short");
        rc = -1;
    }
    free(body);
    return rc;
}

int
xrd_conform_probe_write_only(xrd_conform_execution *execution,
    brix_conn *connection)
{
    xrd_conform_scratch_object object_storage;
    xrd_conform_scratch_object *object = &object_storage;
    brix_file file;
    brix_status status;
    uint8_t byte;
    char reason[64];
    ssize_t read_rc;
    ssize_t pgread_rc;
    int opened = 0;
    int cleanup_ok;

    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-write-only", object->path,
            sizeof(object->path)) != 0) return -1;
    if (!xrd_conform_reserve(execution, 2, reason, sizeof(reason))) return 0;
    brix_status_clear(&status);
    if (open_write_only(connection, object, &file, &status) != 0) {
        xrd_conform_result_set(execution, "RD-017",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "write-only-open-unavailable", NULL, status.msg);
        xrd_conform_result_set(execution, "PGR-029",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "write-only-open-unavailable", NULL, status.msg);
    } else {
        opened = 1;
        brix_status_clear(&status);
        read_rc = brix_file_read(connection, &file, 0, &byte, 1, &status);
        xrd_conform_result_set(execution, "RD-017",
            read_rc < 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                        : BRIX_CONFORM_VERDICT_DIVERGENT,
            read_rc < 0 ? "write-only-handle-read-refused"
                        : "write-only-handle-readable", NULL, status.msg);
        brix_status_clear(&status);
        pgread_rc = brix_file_pgread(connection, &file, 0, &byte, 1, &status);
        xrd_conform_result_set(execution, "PGR-029",
            pgread_rc < 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                          : BRIX_CONFORM_VERDICT_DIVERGENT,
            pgread_rc < 0 ? "write-only-handle-pgread-refused"
                          : "write-only-handle-pgreadable", NULL, status.msg);
    }
    if (opened) {
        brix_status close_status;
        brix_status_clear(&close_status);
        brix_file_close(connection, &file, &close_status);
    }
    brix_status_clear(&status);
    cleanup_ok = brix_rm(connection, object->path, &status) == 0;
    return cleanup_ok ? 0 : -1;
}

static int
probe_standard_object(xrd_conform_execution *execution,
    brix_conn *connection, xrd_conform_scratch_object *object, uint64_t size)
{
    brix_file file;
    brix_status status;
    uint8_t *baseline = NULL;
    int opened = 0;
    int rc = -1;

    brix_status_clear(&status);
    if (xrd_conform_plant_object(execution, connection, object, size,
            &status) == 0
        && brix_file_open_read(connection, object->path, &file, &status) == 0) {
        opened = 1;
        baseline = xrd_conform_read_baseline(execution, connection, &file,
            size, &status);
        if (baseline != NULL) {
            if (size == 0)
                xrd_conform_grade_read(execution, connection, &file, baseline,
                    size, "RD-010", 0, 1);
            xrd_conform_probe_pgread_standard(execution, connection, &file,
                baseline, size);
            if (size == XRDC_CONFORM_CHUNKED_SIZE
                && (xrd_conform_family_active(execution, "RD")
                    || xrd_conform_family_active(execution, "PGR")
                    || xrd_conform_family_active(execution, "CHU")))
                xrd_conform_probe_chunked_reads(execution, connection, &file,
                    baseline, (size_t) size);
            if (size == XRDC_CONFORM_CHUNKED_SIZE
                && xrd_conform_family_active(execution, "RDV")) {
                xrd_conform_probe_readv(execution, connection, &file,
                    object->path, baseline, size);
                xrd_conform_probe_readv_chunked(execution, connection, &file,
                    baseline, (size_t) size);
            }
            rc = 0;
        }
    }
    free(baseline);
    if (opened) {
        brix_status close_status;
        brix_status_clear(&close_status);
        if (brix_file_close(connection, &file, &close_status) != 0) rc = -1;
    }
    brix_status_clear(&status);
    if (brix_rm(connection, object->path, &status) != 0) rc = -1;
    return rc;
}

/* WHAT: Add exact empty, page-minus-one and chunked corpus members.
 * WHY: Their degenerate page semantics cannot be inferred from the Q object.
 * HOW: Build each path through the scratch capability and probe sequentially. */
int
xrd_conform_probe_standard_corpus(xrd_conform_execution *execution,
    brix_conn *connection)
{
    static const struct { const char *leaf; uint64_t size; } objects[] = {
        { "brix-conform-Z", 0 }, { "brix-conform-P0", 4095 },
        { "brix-conform-C-plus", XRDC_CONFORM_CHUNKED_SIZE }
    };
    size_t index;

    for (index = 0; index < sizeof(objects) / sizeof(objects[0]); index++) {
        xrd_conform_scratch_object object;

        if (brix_conform_scratch_path(execution->run->config.scratch,
                objects[index].leaf, object.path, sizeof(object.path)) != 0
            || probe_standard_object(execution, connection, &object,
                objects[index].size) != 0) return -1;
    }
    return 0;
}

int
xrd_conform_standard_corpus_needed(const xrd_conform_execution *execution)
{
    const char *only = execution->run->config.only;

    return only == NULL || strcmp(only, "RD-009") == 0
        || strcmp(only, "RD-010") == 0
        || strcmp(only, "PGR-016") == 0
        || strcmp(only, "PGR-017") == 0
        || strcmp(only, "PGR-025") == 0
        || strcmp(only, "PGR-026") == 0
        || strcmp(only, "RDV-018") == 0
        || strcmp(only, "CHU-001") == 0
        || strcmp(only, "CHU-002") == 0
        || strcmp(only, "CHU-003") == 0
        || strcmp(only, "CHU-004") == 0;
}

int
xrd_conform_large_offset_needed(const xrd_conform_execution *execution)
{
    const char *only = execution->run->config.only;

    return only == NULL || strcmp(only, "RD-011") == 0
        || strcmp(only, "PGR-028") == 0;
}

int
xrd_conform_write_only_needed(const xrd_conform_execution *execution)
{
    const char *only = execution->run->config.only;

    return only == NULL || strcmp(only, "RD-017") == 0
        || strcmp(only, "PGR-029") == 0;
}
