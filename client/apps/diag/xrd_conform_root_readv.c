/* Phase-118 typed root vector-read probes. */
#include "xrd_conform_internal.h"

/* WHAT: Reserve and issue one vector read. WHY: Every scenario must honor run
 * request/byte ceilings. HOW: Sum lengths overflow-safely, reserve, call API. */
static ssize_t
readv_bounded(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, brix_readv_seg *segments, size_t count, brix_status *status)
{
    size_t index;
    size_t total = 0;
    char reason[64];

    for (index = 0; index < count; index++) {
        if (segments[index].len > SIZE_MAX - total) return -1;
        total += segments[index].len;
    }
    if (!xrd_conform_reserve(execution, total, reason, sizeof(reason))) {
        brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
        return -1;
    }
    brix_status_clear(status);
    return brix_file_readv(connection, file, segments, count, status);
}

/* WHAT: Store a vector scenario verdict. WHY: Keep evidence and names uniform.
 * HOW: Translate one observed boolean to the shared result seam. */
static void
grade(xrd_conform_execution *execution, const char *id, int success,
    const char *pass_reason, const brix_status *status)
{
    xrd_conform_result_set(execution, id,
        success ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        success ? pass_reason : "readv-geometry-mismatch", NULL,
        success || status == NULL ? NULL : status->msg);
}

/* WHAT: Recognize calibrated whole-request EOF errors. WHY: Stock v5 reports
 * FSError while BriX reports IOError; both safely reject without segment data.
 * HOW: Accept only the two observed, defined wire errors and a failed call. */
static int
readv_eof_error(ssize_t got, const brix_readv_seg *segment,
    const brix_status *status)
{
    return got < 0 && segment->got == 0
        && (status->kxr == kXR_IOError || status->kxr == kXR_FSError);
}

/* WHAT: Exercise one-element, duplicate, descending and overlap geometries.
 * WHY: These rows catch element loss, reordering and cross-element confusion.
 * HOW: Issue small deterministic vectors and compare each returned extent. */
static void
probe_descending(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline)
{
    uint8_t buffers[2][16];
    brix_readv_seg segments[2];
    brix_status status;
    ssize_t got;

    memset(segments, 0, sizeof(segments));
    segments[0].offset = 1; segments[0].len = 1; segments[0].buf = buffers[0];
    segments[1].offset = 0; segments[1].len = 2; segments[1].buf = buffers[1];
    got = readv_bounded(execution, connection, file, segments, 2, &status);
    grade(execution, "RDV-003", got == 3
        && segments[0].got == 1 && segments[1].got == 2
        && buffers[0][0] == baseline[1]
        && memcmp(buffers[1], baseline, 2) == 0,
        "response-elements-preserve-request-order", &status);
    grade(execution, "RDV-007", got == 3 && buffers[0][0] == baseline[1]
        && memcmp(buffers[1], baseline, 2) == 0,
        "descending-elements-preserved", &status);
    grade(execution, "RDV-006", got == 3 && buffers[0][0] == baseline[1]
        && buffers[1][1] == baseline[1], "overlap-elements-independent", &status);
}

/* WHAT: Exercise single and duplicate vector geometries. WHY: Keep independent
 * ordering work out of the basic equality probe. HOW: Compare both buffers. */
static void
probe_geometries(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size)
{
    uint8_t buffers[2][16];
    brix_readv_seg segments[2];
    brix_status status;
    size_t length = size < 8 ? (size_t) size : 8;
    ssize_t got;

    if (length == 0) return;
    memset(segments, 0, sizeof(segments));
    segments[0].offset = 0; segments[0].len = length; segments[0].buf = buffers[0];
    got = readv_bounded(execution, connection, file, segments, 1, &status);
    grade(execution, "RDV-001", got == (ssize_t) length
        && segments[0].got == length && memcmp(buffers[0], baseline, length) == 0,
        "single-readv-equals-read", &status);
    segments[1] = segments[0]; segments[1].buf = buffers[1];
    got = readv_bounded(execution, connection, file, segments, 2, &status);
    grade(execution, "RDV-005", got == (ssize_t) (length * 2)
        && segments[0].got == length && segments[1].got == length
        && memcmp(buffers[0], baseline, length) == 0
        && memcmp(buffers[1], baseline, length) == 0,
        "duplicate-elements-preserved", &status);
    if (size >= 2) probe_descending(execution, connection, file, baseline);
}

/* WHAT: Exercise zero, past-EOF and straddling vector extents. WHY: Fractional
 * vector answers must preserve elements and clamp exactly. HOW: Use one element. */
static void
probe_edges(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, uint64_t size)
{
    uint8_t buffer[2];
    brix_readv_seg segment;
    brix_status status;
    ssize_t got;

    memset(&segment, 0, sizeof(segment)); segment.buf = buffer;
    got = readv_bounded(execution, connection, file, &segment, 1, &status);
    grade(execution, "RDV-008", got == 0 && segment.got == 0,
        "zero-element-preserved", &status);
    if (size <= INT64_MAX - 1) {
        segment.offset = (int64_t) size + 1; segment.len = 1; segment.got = 0;
        got = readv_bounded(execution, connection, file, &segment, 1, &status);
        grade(execution, "RDV-009",
            readv_eof_error(got, &segment, &status),
            "past-eof-request-failed-wholesale", &status);
    }
    if (size == 0 || size > INT64_MAX) return;
    segment.offset = (int64_t) size - 1; segment.len = 2; segment.got = 0;
    got = readv_bounded(execution, connection, file, &segment, 1, &status);
    grade(execution, "RDV-010",
        readv_eof_error(got, &segment, &status),
        "straddling-request-failed-wholesale", &status);
}

/* WHAT: Run safe typed vector-read probes. WHY: M3 needs real RDV evidence.
 * HOW: Delegate independent geometry and edge scenario groups. */
void
xrd_conform_probe_readv(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path,
    const uint8_t *baseline, uint64_t size)
{
    probe_geometries(execution, connection, file, baseline, size);
    probe_edges(execution, connection, file, size);
    xrd_conform_probe_readv_limits(execution, connection, file, path,
        baseline, size);
}

/* WHAT: Prove a >16 MiB vector reply stays one logical response and is exact.
 * WHY: Official XrdCl does not reassemble kXR_oksofar for readv.
 * HOW: Split into legal elements, count responses and compare every byte. */
void
xrd_conform_probe_readv_chunked(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const uint8_t *baseline,
    size_t size)
{
    const size_t segment_size = 2U * 1024U * 1024U - BRIX_READV_SEGSIZE;
    brix_readv_seg *segments;
    uint8_t *buffer;
    brix_status status;
    char reason[64];
    unsigned partials = 0;
    size_t count, index, cursor = 0;
    ssize_t got;
    int exact = 1;

    count = (size + segment_size - 1U) / segment_size;
    segments = calloc(count, sizeof(*segments));
    buffer = malloc(size);
    if (segments == NULL || buffer == NULL) {
        free(segments); free(buffer);
        return;
    }
    for (index = 0; index < count; index++) {
        size_t length = size - cursor;

        if (length > segment_size) length = segment_size;
        segments[index].offset = (int64_t) cursor;
        segments[index].len = length;
        segments[index].buf = buffer + cursor;
        cursor += length;
    }
    if (!xrd_conform_reserve(execution, size, reason, sizeof(reason))) {
        free(segments); free(buffer);
        return;
    }
    brix_status_clear(&status);
    got = brix_file_readv_profile(connection, file, segments, count,
        &partials, &status);
    for (index = 0; index < count && exact; index++)
        exact = segments[index].got == segments[index].len;
    exact = exact && got == (ssize_t) size
        && memcmp(buffer, baseline, size) == 0 && partials == 0;
    xrd_conform_result_set(execution, "RDV-018",
        exact ? BRIX_CONFORM_VERDICT_CONFORMANT
              : BRIX_CONFORM_VERDICT_DIVERGENT,
        exact ? "single-logical-response-streamed-byte-exact"
              : "large-readv-framing-mismatch",
        "one kXR_ok response; byte-exact", status.msg);
    free(segments); free(buffer);
}
