/* Phase-118 paired cache/origin byte, checksum, and metadata probes. */
#include "xrd_conform_internal.h"

#define CAC_READ_CHUNK 65536U

static int row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static int reserve(xrd_conform_execution *execution, size_t bytes,
    brix_status *status)
{
    char reason[64];

    if (xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) return 1;
    brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
    return 0;
}

static void pair_inconclusive(xrd_conform_execution *execution,
    const char *reason, const brix_status *status)
{
    static const char *const ids[] = {
        "CAC-001", "CAC-002", "CAC-003", "CAC-004", "CAC-005",
        "CAC-006", "CAC-007", "CAC-008", "CAC-009",
        "PRP-003", "PRP-004"
    };
    size_t index;

    for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++)
        if (row_active(execution, ids[index]))
            xrd_conform_result_set(execution, ids[index],
                BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL,
                status == NULL ? NULL : status->msg);
}

static int pair_read_active(xrd_conform_execution *execution)
{
    return row_active(execution, "CAC-001")
        || row_active(execution, "CAC-002")
        || row_active(execution, "CAC-007")
        || row_active(execution, "CAC-008");
}

static int parse_pair(xrd_conform_execution *execution, brix_url *cache,
    brix_url *origin, brix_status *status)
{
    if (execution->run->also_count == 0
        || brix_endpoint_parse(execution->run->config.target, cache,
            status) != 0
        || brix_endpoint_parse(execution->run->also[0], origin, status) != 0)
        return -1;
    return (cache->scheme == XRDC_SCHEME_ROOT
            || cache->scheme == XRDC_SCHEME_ROOTS)
        && (origin->scheme == XRDC_SCHEME_ROOT
            || origin->scheme == XRDC_SCHEME_ROOTS) ? 0 : -1;
}

static int read_whole(xrd_conform_execution *execution,
    brix_conn *connection, const char *path, uint64_t size, uint8_t **bytes,
    brix_status *status)
{
    brix_file file;
    uint64_t offset = 0;
    int rc = -1;

    if (size > SIZE_MAX || size > execution->run->config.byte_limit) {
        brix_status_set(status, XRDC_EUSAGE, 0,
            "paired object exceeds byte ceiling");
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
        size_t length = size - offset < CAC_READ_CHUNK
            ? (size_t) (size - offset) : CAC_READ_CHUNK;
        ssize_t got;

        if (!reserve(execution, length, status)) break;
        got = brix_file_read(connection, &file, (int64_t) offset,
            *bytes + offset, length, status);
        if (got != (ssize_t) length) break;
        offset += length;
    }
    if (offset == size) rc = 0;
    {
        brix_status close_status;

        brix_status_clear(&close_status);
        if (!reserve(execution, 0, &close_status)
            || brix_file_close(connection, &file, &close_status) != 0) rc = -1;
    }
    if (rc != 0) {
        free(*bytes);
        *bytes = NULL;
    }
    return rc;
}

static int extent_equal(xrd_conform_execution *execution,
    brix_conn *cache, brix_conn *origin, const brix_file *cache_file,
    const brix_file *origin_file, uint64_t size, int64_t offset,
    int32_t length, brix_status *status)
{
    uint8_t *cache_body = NULL;
    uint8_t *origin_body = NULL;
    uint32_t cache_length = 0;
    uint32_t origin_length = 0;
    uint16_t cache_status = 0;
    uint16_t origin_status = 0;
    uint64_t remaining = (uint64_t) offset < size
        ? size - (uint64_t) offset : 0;
    size_t expected = remaining < (uint32_t) length
        ? (size_t) remaining : (size_t) length;
    int cache_rc;
    int origin_rc;
    int equal;

    cache_rc = xrd_conform_root_raw_read(execution, cache,
        cache_file->fhandle, offset, length, NULL, 0, expected,
        &cache_status, &cache_body, &cache_length, status);
    origin_rc = xrd_conform_root_raw_read(execution, origin,
        origin_file->fhandle, offset, length, NULL, 0, expected,
        &origin_status, &origin_body, &origin_length, status);
    equal = cache_rc == 0 && origin_rc == 0
        && cache_status == kXR_ok && origin_status == kXR_ok
        && cache_length == origin_length
        && cache_length == expected
        && (expected == 0 || memcmp(cache_body, origin_body, expected) == 0);
    free(cache_body);
    free(origin_body);
    return equal;
}

static int fractional_grid_equal(xrd_conform_execution *execution,
    brix_conn *cache, brix_conn *origin, const brix_url *cache_url,
    const brix_url *origin_url, uint64_t size, brix_status *status)
{
    int64_t offsets[BRIX_CONFORM_AXIS_MAX];
    int64_t lengths[BRIX_CONFORM_AXIS_MAX];
    brix_file cache_file;
    brix_file origin_file;
    size_t offset_count;
    size_t offset_index;
    int pass = 1;

    if (!reserve(execution, 0, status)
        || brix_file_open_read(cache, cache_url->path, &cache_file,
            status) != 0) return -1;
    if (!reserve(execution, 0, status)
        || brix_file_open_read(origin, origin_url->path, &origin_file,
            status) != 0) {
        if (reserve(execution, 0, status))
            brix_file_close(cache, &cache_file, status);
        return -1;
    }
    offset_count = brix_conform_offsets(size, offsets,
        BRIX_CONFORM_AXIS_MAX);
    for (offset_index = 0; pass > 0 && offset_index < offset_count;
            offset_index++) {
        size_t length_count = brix_conform_lengths(size,
            offsets[offset_index], lengths, BRIX_CONFORM_AXIS_MAX);
        size_t length_index;

        for (length_index = 0; pass > 0 && length_index < length_count;
                length_index++) {
            if (!brix_conform_case_selected(execution->run->config.budget,
                    0, 1, offset_index, offset_count, length_index,
                    length_count, offsets[offset_index], lengths[length_index],
                    size)
                || offsets[offset_index] < 0 || lengths[length_index] < 0
                || lengths[length_index] > INT32_MAX)
                continue;
            if (!extent_equal(execution, cache, origin, &cache_file,
                    &origin_file, size, offsets[offset_index],
                    (int32_t) lengths[length_index], status))
                pass = status->kxr == XRDC_EUSAGE ? -1 : 0;
        }
    }

    if (reserve(execution, 0, status))
        if (brix_file_close(origin, &origin_file, status) != 0) pass = -1;
    if (reserve(execution, 0, status))
        if (brix_file_close(cache, &cache_file, status) != 0) pass = -1;
    return pass;
}

static void grade_checksums(xrd_conform_execution *execution,
    brix_conn *cache, brix_conn *origin, const brix_url *cache_url,
    const brix_url *origin_url)
{
    char cache_digest[129];
    char origin_digest[129];
    brix_status status;
    int rc;

    if (!row_active(execution, "CAC-007")) return;
    brix_status_clear(&status);
    rc = reserve(execution, 0, &status)
        && brix_query_cksum(cache, cache_url->path, "sha256", cache_digest,
            sizeof(cache_digest), &status) == 0
        && reserve(execution, 0, &status)
        && brix_query_cksum(origin, origin_url->path, "sha256", origin_digest,
            sizeof(origin_digest), &status) == 0;
    xrd_conform_result_set(execution, "CAC-007",
        rc && strcmp(cache_digest, origin_digest) == 0
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : rc ? BRIX_CONFORM_VERDICT_DIVERGENT
                 : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        rc && strcmp(cache_digest, origin_digest) == 0
            ? "cache-origin-checksum-agreement"
            : rc ? "cache-origin-checksum-mismatch"
                 : "cache-origin-checksum-unavailable",
        NULL, rc ? NULL : status.msg);
}

/* WHAT: Compare one explicit cache endpoint with its explicit origin pair.
 * WHY: Population and cache correctness cannot be inferred from one endpoint.
 * HOW: Read the cache twice before the ordinary run, then compare the selected
 * fractional grid, stat sizes, and server-calculated SHA-256 checksums. */
void xrd_conform_probe_cache_pair(xrd_conform_execution *execution)
{
    brix_url cache_url;
    brix_url origin_url;
    brix_conn cache;
    brix_conn origin;
    brix_opts opts = execution->run->opts;
    brix_statinfo cache_info;
    brix_statinfo origin_info;
    brix_status status;
    uint8_t *first = NULL;
    uint8_t *second = NULL;
    int grid;

    if (!xrd_conform_family_active(execution, "CAC")
        && !row_active(execution, "PRP-003")
        && !row_active(execution, "PRP-004")) return;
    brix_status_clear(&status);
    if (parse_pair(execution, &cache_url, &origin_url, &status) != 0) {
        pair_inconclusive(execution, "fixture-required:paired-cache-origin",
            &status);
        return;
    }
    opts.capture = NULL;
    if (brix_connect(&cache, &cache_url, &opts, &status) != 0) {
        pair_inconclusive(execution, "fixture-unavailable:paired-cache-origin",
            &status);
        return;
    }
    if (brix_connect(&origin, &origin_url, &opts, &status) != 0) {
        pair_inconclusive(execution, "fixture-unavailable:paired-cache-origin",
            &status);
        brix_close(&cache);
        return;
    }
    xrd_conform_probe_cache_evict(execution, &cache, &origin);
    xrd_conform_probe_cache_fixture(execution, &cache, &origin, &cache_url,
        &origin_url);
    if (!pair_read_active(execution)) {
        brix_close(&origin);
        brix_close(&cache);
        return;
    }
    if (!reserve(execution, 0, &status)
        || brix_stat(&cache, cache_url.path, &cache_info, &status) != 0
        || !reserve(execution, 0, &status)
        || brix_stat(&origin, origin_url.path, &origin_info, &status) != 0
        || cache_info.size < 0 || origin_info.size < 0) {
        pair_inconclusive(execution, "fixture-unavailable:paired-cache-origin",
            &status);
        brix_close(&origin);
        brix_close(&cache);
        return;
    }
    if (row_active(execution, "CAC-008"))
        xrd_conform_result_set(execution, "CAC-008",
            cache_info.size == origin_info.size
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
            cache_info.size == origin_info.size
                ? "cache-origin-stat-size-agreement"
                : "cache-origin-stat-size-mismatch",
            NULL, NULL);
    if (cache_info.size != origin_info.size) {
        if (row_active(execution, "CAC-001"))
            xrd_conform_result_set(execution, "CAC-001",
                BRIX_CONFORM_VERDICT_DIVERGENT,
                "cache-population-size-mismatch", NULL, NULL);
        if (row_active(execution, "CAC-002"))
            xrd_conform_result_set(execution, "CAC-002",
                BRIX_CONFORM_VERDICT_DIVERGENT,
                "cache-origin-range-size-mismatch", NULL, NULL);
    } else {
        if (row_active(execution, "CAC-001")) {
            int read_ok = read_whole(execution, &cache, cache_url.path,
                    (uint64_t) cache_info.size, &first, &status) == 0
                && read_whole(execution, &cache, cache_url.path,
                    (uint64_t) cache_info.size, &second, &status) == 0;
            int same = read_ok && memcmp(first, second,
                (size_t) cache_info.size) == 0;

            xrd_conform_result_set(execution, "CAC-001",
                same ? BRIX_CONFORM_VERDICT_CONFORMANT
                     : read_ok ? BRIX_CONFORM_VERDICT_DIVERGENT
                               : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
                same ? "first-and-second-cache-reads-identical"
                     : read_ok ? "cache-population-changed-bytes"
                               : "cache-population-read-failed",
                NULL, read_ok ? NULL : status.msg);
            free(first);
            free(second);
        }
        if (row_active(execution, "CAC-002")) {
            grid = fractional_grid_equal(execution, &cache, &origin,
                &cache_url, &origin_url, (uint64_t) cache_info.size, &status);
            xrd_conform_result_set(execution, "CAC-002",
                grid > 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                         : grid == 0 ? BRIX_CONFORM_VERDICT_DIVERGENT
                                     : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
                grid > 0 ? "cache-origin-fractional-grid-agreement"
                         : grid == 0 ? "cache-origin-fractional-grid-mismatch"
                                     : "cache-origin-grid-incomplete",
                NULL, grid < 0 ? status.msg : NULL);
        }
    }
    grade_checksums(execution, &cache, &origin, &cache_url, &origin_url);
    brix_close(&origin);
    brix_close(&cache);
}
