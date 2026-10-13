/* Phase-118 externally prepared cache-state fixtures. */
#include "xrd_conform_internal.h"

#define CACHE_FIXTURE_CHUNK 65536U

static int reserve(xrd_conform_execution *execution, size_t bytes,
    brix_status *status)
{
    char reason[64];

    if (xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) return 1;
    brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
    return 0;
}

static int row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static int read_object(xrd_conform_execution *execution,
    brix_conn *connection, const char *path, uint64_t size, uint8_t **bytes,
    brix_status *status)
{
    brix_file file;
    uint64_t offset = 0;
    int rc = -1;

    *bytes = NULL;
    if (size > SIZE_MAX || size > execution->run->config.byte_limit) {
        brix_status_set(status, XRDC_EUSAGE, 0,
            "cache fixture exceeds byte ceiling");
        return -1;
    }
    *bytes = malloc(size == 0 ? 1 : (size_t) size);
    if (*bytes == NULL) return -1;
    if (!reserve(execution, 0, status)
        || brix_file_open_read(connection, path, &file, status) != 0) {
        free(*bytes);
        *bytes = NULL;
        return -1;
    }
    while (offset < size) {
        size_t length = size - offset < CACHE_FIXTURE_CHUNK
            ? (size_t) (size - offset) : CACHE_FIXTURE_CHUNK;
        ssize_t got;

        if (!reserve(execution, length, status)) break;
        got = brix_file_read(connection, &file, (int64_t) offset,
            *bytes + offset, length, status);
        if (got != (ssize_t) length) break;
        offset += length;
    }
    if (offset == size) rc = 0;
    {
        brix_status ignored;

        brix_status_clear(&ignored);
        if (reserve(execution, 0, &ignored))
            brix_file_close(connection, &file, &ignored);
    }
    if (rc != 0) {
        free(*bytes);
        *bytes = NULL;
    }
    return rc;
}

static void grade_bytes(xrd_conform_execution *execution, const char *id,
    const char *success_reason, int cache_rc, int origin_rc,
    const uint8_t *cache_bytes, const uint8_t *origin_bytes, size_t size,
    const brix_status *status)
{
    int equal = cache_rc == 0 && origin_rc == 0
        && (size == 0 || memcmp(cache_bytes, origin_bytes, size) == 0);

    xrd_conform_result_set(execution, id,
        equal ? BRIX_CONFORM_VERDICT_CONFORMANT
              : cache_rc == 0 && origin_rc == 0
                  ? BRIX_CONFORM_VERDICT_DIVERGENT
                  : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        equal ? success_reason
              : cache_rc == 0 && origin_rc == 0
                  ? "cache-fixture-byte-mismatch"
                  : "cache-fixture-read-unavailable",
        NULL, equal || (cache_rc == 0 && origin_rc == 0) ? NULL : status->msg);
}

static void grade_capacity(xrd_conform_execution *execution, int cache_rc,
    int origin_rc, const uint8_t *cache_bytes, const uint8_t *origin_bytes,
    size_t size, const brix_status *status)
{
    int served = cache_rc == 0 && origin_rc == 0
        && (size == 0 || memcmp(cache_bytes, origin_bytes, size) == 0);
    int refused = cache_rc != 0 && (status->kxr == kXR_NoSpace
        || status->kxr == kXR_overQuota || status->kxr == kXR_NoMemory);
    int setup_failed = origin_rc != 0;

    xrd_conform_result_set(execution, "CAC-005",
        setup_failed ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                     : served || refused ? BRIX_CONFORM_VERDICT_CONFORMANT
                                         : BRIX_CONFORM_VERDICT_DIVERGENT,
        setup_failed ? "over-capacity-origin-unavailable"
                     : served ? "over-capacity-cache-evicted-and-served"
                              : refused ? "over-capacity-cache-refused-defined"
                                        : "over-capacity-cache-transient-or-wrong",
        "origin bytes or kXR_NoSpace/kXR_overQuota/kXR_NoMemory",
        setup_failed ? status->msg : NULL);
}

static void grade_corrupt(xrd_conform_execution *execution, int cache_rc,
    int origin_rc, const uint8_t *cache_bytes, const uint8_t *origin_bytes,
    size_t size, const brix_status *status)
{
    int refetched = cache_rc == 0 && origin_rc == 0
        && (size == 0 || memcmp(cache_bytes, origin_bytes, size) == 0);
    int failed_closed = cache_rc != 0 && status->kxr != 0;
    int setup_failed = origin_rc != 0;

    xrd_conform_result_set(execution, "CAC-009",
        setup_failed ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                     : refetched || failed_closed
                         ? BRIX_CONFORM_VERDICT_CONFORMANT
                         : BRIX_CONFORM_VERDICT_DIVERGENT,
        setup_failed ? "corrupt-cache-origin-unavailable"
                     : refetched ? "corrupt-cache-refetched-origin-bytes"
                                 : failed_closed ? "corrupt-cache-failed-closed"
                                    : "corrupt-cache-served-corruption",
        "origin bytes or explicit read failure",
        setup_failed ? status->msg : NULL);
}

static const char *fixture_row(const char *kind)
{
    if (kind == NULL) return NULL;
    if (strcmp(kind, "partial") == 0) return "CAC-003";
    if (strcmp(kind, "filling") == 0) return "CAC-004";
    if (strcmp(kind, "capacity") == 0) return "CAC-005";
    if (strcmp(kind, "corrupt") == 0) return "CAC-009";
    return NULL;
}

/* WHAT: Grade one externally prepared cache state against its explicit origin.
 * WHY: Partial, in-flight, over-capacity, and corrupt state cannot be created
 * honestly through the public ROOT protocol.
 * HOW: Require a named fixture kind, independently read the origin, and grade
 * only the matching row with byte equality or its narrowly defined refusal. */
void xrd_conform_probe_cache_fixture(xrd_conform_execution *execution,
    brix_conn *cache, brix_conn *origin, const brix_url *cache_url,
    const brix_url *origin_url)
{
    const char *kind = execution->run->cache_fixture_kind;
    const char *id = fixture_row(kind);
    brix_statinfo cache_info;
    brix_statinfo origin_info;
    brix_status status;
    uint8_t *cache_bytes = NULL;
    uint8_t *origin_bytes = NULL;
    int cache_rc;
    int origin_rc;
    size_t size;

    if (id == NULL || !row_active(execution, id)) return;
    brix_status_clear(&status);
    if (!reserve(execution, 0, &status)
        || brix_stat(origin, origin_url->path, &origin_info, &status) != 0
        || origin_info.size < 0) {
        xrd_conform_result_set(execution, id,
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "cache-fixture-origin-stat-unavailable", NULL, status.msg);
        return;
    }
    origin_rc = read_object(execution, origin, origin_url->path,
        (uint64_t) origin_info.size, &origin_bytes, &status);
    brix_status_clear(&status);
    cache_rc = reserve(execution, 0, &status)
            && brix_stat(cache, cache_url->path, &cache_info, &status) == 0
            && cache_info.size == origin_info.size
        ? read_object(execution, cache, cache_url->path,
            (uint64_t) origin_info.size, &cache_bytes, &status) : -1;
    size = (size_t) origin_info.size;
    if (strcmp(kind, "partial") == 0)
        grade_bytes(execution, id, "partial-cache-filled-and-unfilled-bytes-correct",
            cache_rc, origin_rc, cache_bytes, origin_bytes, size, &status);
    else if (strcmp(kind, "filling") == 0)
        grade_bytes(execution, id, "serve-while-filling-all-offsets-correct",
            cache_rc, origin_rc, cache_bytes, origin_bytes, size, &status);
    else if (strcmp(kind, "capacity") == 0)
        grade_capacity(execution, cache_rc, origin_rc, cache_bytes,
            origin_bytes, size, &status);
    else
        grade_corrupt(execution, cache_rc, origin_rc, cache_bytes,
            origin_bytes, size, &status);
    free(cache_bytes);
    free(origin_bytes);
}
