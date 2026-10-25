/* Phase-118 scratch-confined cache eviction and refetch probe. */
#include "xrd_conform_probe_helpers.h"

#define CAC_EVICT_SIZE 8192U



static int write_version(xrd_conform_execution *execution,
    brix_conn *origin, const xrd_conform_scratch_object *object,
    uint64_t seed_offset,
    uint8_t expected[CAC_EVICT_SIZE], brix_status *status)
{
    brix_file file;
    int opened = 0;
    int rc = -1;

    brix_conform_fill(&execution->run->key, seed_offset, expected,
        CAC_EVICT_SIZE);
    if (xrd_conform_reserve_status(execution, 0, status)
        && brix_file_open_write(origin, object->path, 1, 0, &file,
            status) == 0) {
        opened = 1;
        if (xrd_conform_reserve_status(execution, CAC_EVICT_SIZE, status)
            && brix_file_write(origin, &file, 0, expected,
                CAC_EVICT_SIZE, status) == 0)
            rc = 0;
    }
    if (opened) {
        if (!xrd_conform_reserve_status(execution, 0, status)
            || brix_file_close(origin, &file, status) != 0) rc = -1;
    }
    return rc;
}

static int read_version(xrd_conform_execution *execution, brix_conn *cache,
    const char *path, uint8_t actual[CAC_EVICT_SIZE], brix_status *status)
{
    brix_file file;
    int opened = 0;
    int rc = -1;

    if (xrd_conform_reserve_status(execution, 0, status)
        && brix_file_open_read(cache, path, &file, status) == 0) {
        ssize_t got;

        opened = 1;
        if (xrd_conform_reserve_status(execution, CAC_EVICT_SIZE, status)) {
            got = brix_file_read(cache, &file, 0, actual,
                CAC_EVICT_SIZE, status);
            if (got == CAC_EVICT_SIZE) rc = 0;
        }
    }
    if (opened) {
        if (!xrd_conform_reserve_status(execution, 0, status)
            || brix_file_close(cache, &file, status) != 0) rc = -1;
    }
    return rc;
}

static int prepare_path(xrd_conform_execution *execution, brix_conn *cache,
    const char *path, int options, int option_x, brix_status *status)
{
    const char *paths[] = { path };
    char reply[128];

    if (!xrd_conform_reserve_status(execution, 0, status)) return -1;
    return brix_prepare(cache, paths, 1, options, option_x, 0,
        reply, sizeof(reply), status);
}

static void cleanup(xrd_conform_execution *execution, brix_conn *cache,
    brix_conn *origin, const xrd_conform_scratch_object *object)
{
    brix_status ignored;

    brix_status_clear(&ignored);
    if (xrd_conform_reserve_status(execution, 0, &ignored))
        brix_rm(origin, object->path, &ignored);
    brix_status_clear(&ignored);
    prepare_path(execution, cache, object->path, kXR_stage, kXR_evict,
        &ignored);
}

static void grade_one(xrd_conform_execution *execution, const char *id,
    brix_conform_verdict verdict, const char *reason, const brix_status *status)
{
    if (xrd_conform_row_active(execution, id))
        xrd_conform_result_set(execution, id, verdict, reason, NULL,
            status == NULL ? NULL : status->msg);
}

static void grade_evict(xrd_conform_execution *execution,
    brix_conform_verdict verdict, const char *reason, const brix_status *status)
{
    grade_one(execution, "CAC-006", verdict, reason, status);
    grade_one(execution, "PRP-003", verdict, reason, status);
}

/* WHAT: Prove that accepted cache eviction causes a fresh origin fetch.
 * WHY: Returning a stale cache block after successful eviction can preserve
 * revoked or replaced content indefinitely.
 * HOW: Populate a scratch object, evict it, replace equal-length origin bytes,
 * and require the next cache read to equal the replacement exactly. */
static void probe_evict(xrd_conform_execution *execution,
    brix_conn *cache, brix_conn *origin)
{
    xrd_conform_scratch_object object;
    uint8_t old_bytes[CAC_EVICT_SIZE];
    uint8_t new_bytes[CAC_EVICT_SIZE];
    uint8_t actual[CAC_EVICT_SIZE];
    brix_status status;
    int populated;

    if (!xrd_conform_row_active(execution, "CAC-006")
        && !xrd_conform_row_active(execution, "PRP-003")) return;
    brix_status_clear(&status);
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-cache-evict", object.path,
            sizeof(object.path)) != 0) {
        grade_evict(execution, BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "scratch-path-invalid", &status);
        return;
    }
    if (write_version(execution, origin, &object, 0, old_bytes,
            &status) != 0) {
        grade_evict(execution, BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "cache-evict-origin-setup-failed", &status);
        cleanup(execution, cache, origin, &object);
        return;
    }
    populated = read_version(execution, cache, object.path, actual,
        &status) == 0;
    if (!populated || memcmp(actual, old_bytes, sizeof(actual)) != 0) {
        grade_evict(execution,
            populated ? BRIX_CONFORM_VERDICT_DIVERGENT
                      : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            populated ? "cache-population-returned-wrong-bytes"
                      : "cache-evict-population-failed",
            populated ? NULL : &status);
        cleanup(execution, cache, origin, &object);
        return;
    }
    if (prepare_path(execution, cache, object.path, kXR_stage, kXR_evict,
            &status) != 0) {
        grade_evict(execution, BRIX_CONFORM_VERDICT_DIVERGENT,
            "cache-evict-refused", &status);
        cleanup(execution, cache, origin, &object);
        return;
    }
    if (write_version(execution, origin, &object, CAC_EVICT_SIZE,
            new_bytes, &status) != 0) {
        grade_evict(execution, BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "cache-evict-origin-replacement-failed", &status);
        cleanup(execution, cache, origin, &object);
        return;
    }
    if (read_version(execution, cache, object.path, actual, &status) != 0) {
        grade_evict(execution, BRIX_CONFORM_VERDICT_DIVERGENT,
            "cache-refetch-after-evict-failed", &status);
    } else {
        int fresh = memcmp(actual, new_bytes, sizeof(actual)) == 0;

        grade_evict(execution,
            fresh ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
            fresh ? "cache-evict-refetched-replacement-bytes"
                  : "cache-evict-served-stale-or-wrong-bytes",
            NULL);
    }
    cleanup(execution, cache, origin, &object);
}

/* WHAT: Prove that kXR_fresh replaces a resident cache copy.
 * WHY: Accepting fresh while retaining resident bytes makes the wire promise
 * misleading and can preserve revoked content.
 * HOW: Populate old scratch bytes, replace the origin out of band, request a
 * fresh stage, and compare the next cache read with the replacement oracle. */
static void probe_fresh(xrd_conform_execution *execution,
    brix_conn *cache, brix_conn *origin)
{
    xrd_conform_scratch_object object;
    uint8_t old_bytes[CAC_EVICT_SIZE];
    uint8_t new_bytes[CAC_EVICT_SIZE];
    uint8_t actual[CAC_EVICT_SIZE];
    brix_status status;
    int populated;

    if (!xrd_conform_row_active(execution, "PRP-004")) return;
    brix_status_clear(&status);
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-cache-fresh", object.path,
            sizeof(object.path)) != 0) {
        grade_one(execution, "PRP-004", BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "scratch-path-invalid", &status);
        return;
    }
    if (write_version(execution, origin, &object, 0, old_bytes,
            &status) != 0) {
        grade_one(execution, "PRP-004", BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "cache-fresh-origin-setup-failed", &status);
        cleanup(execution, cache, origin, &object);
        return;
    }
    populated = read_version(execution, cache, object.path, actual,
        &status) == 0;
    if (!populated || memcmp(actual, old_bytes, sizeof(actual)) != 0) {
        grade_one(execution, "PRP-004",
            populated ? BRIX_CONFORM_VERDICT_DIVERGENT
                      : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            populated ? "cache-population-returned-wrong-bytes"
                      : "cache-fresh-population-failed",
            populated ? NULL : &status);
        cleanup(execution, cache, origin, &object);
        return;
    }
    if (write_version(execution, origin, &object, CAC_EVICT_SIZE,
            new_bytes, &status) != 0) {
        grade_one(execution, "PRP-004", BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "cache-fresh-origin-replacement-failed", &status);
        cleanup(execution, cache, origin, &object);
        return;
    }
    if (prepare_path(execution, cache, object.path,
            kXR_stage | kXR_fresh, 0, &status) != 0) {
        grade_one(execution, "PRP-004", BRIX_CONFORM_VERDICT_DIVERGENT,
            "cache-fresh-refused", &status);
        cleanup(execution, cache, origin, &object);
        return;
    }
    if (read_version(execution, cache, object.path, actual, &status) != 0) {
        grade_one(execution, "PRP-004", BRIX_CONFORM_VERDICT_DIVERGENT,
            "cache-refetch-after-fresh-failed", &status);
    } else {
        int fresh = memcmp(actual, new_bytes, sizeof(actual)) == 0;

        grade_one(execution, "PRP-004",
            fresh ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
            fresh ? "cache-fresh-refetched-replacement-bytes"
                  : "cache-fresh-served-stale-or-wrong-bytes",
            NULL);
    }
    cleanup(execution, cache, origin, &object);
}

void xrd_conform_probe_cache_evict(xrd_conform_execution *execution,
    brix_conn *cache, brix_conn *origin)
{
    probe_evict(execution, cache, origin);
    probe_fresh(execution, cache, origin);
}
