/* Phase-118 typed root metadata probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/stat_line.h"

#include <arpa/inet.h>

/* WHAT: Grade a boolean assertion with stable evidence. WHY: Metadata rows use
 * one uniform verdict spelling. HOW: Map true/false to conformant/divergent. */
static void
grade(xrd_conform_execution *execution, const char *id, int success,
    const char *pass_reason, const char *fail_reason)
{
    xrd_conform_result_set(execution, id,
        success ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        success ? pass_reason : fail_reason, NULL, NULL);
}

/* WHAT: Reserve one metadata exchange or mark its rows inconclusive. WHY:
 * Metadata operations are real requests and must obey the same hard ceiling.
 * HOW: Charge zero body bytes and copy the stable ceiling reason to each row. */
static int
reserve_stat(xrd_conform_execution *execution, const char *const *ids,
    size_t count)
{
    char reason[64];
    size_t index;

    if (xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return 1;
    for (index = 0; index < count; index++) {
        xrd_conform_result_set(execution, ids[index],
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, reason, NULL, NULL);
    }
    return 0;
}

static int
parse_stat_body(const uint8_t *body, uint32_t body_len, brix_statinfo *out)
{
    brix_statline_ext ext;
    char text[256];

    if (body == NULL || body_len == 0 || body_len >= sizeof(text)) return -1;
    memcpy(text, body, body_len);
    text[body_len] = '\0';
    if (brix_statline_parse(text, &out->id, &out->size, &out->flags,
            &out->mtime, &ext) != 0) return -1;
    return 0;
}

static int
stat_handle(brix_conn *connection, const brix_file *file,
    brix_statinfo *out, brix_status *status)
{
    ClientStatRequest request;
    uint8_t *body = NULL;
    uint32_t body_len = 0;
    uint16_t wire_status = 0;
    int rc;

    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_stat);
    memcpy(request.fhandle, file->fhandle, sizeof(request.fhandle));
    rc = brix_roundtrip_resilient(connection, &request, NULL, 0,
        XRDC_OP_READONLY, 0, &wire_status, &body, &body_len, status);
    if (rc == 0) rc = parse_stat_body(body, body_len, out);
    free(body);
    return rc;
}

static int
statx_pair(brix_conn *connection, const char *path, uint8_t flags[2],
    brix_status *status)
{
    ClientStatxRequest request;
    uint8_t *body = NULL;
    uint32_t body_len = 0;
    uint16_t wire_status = 0;
    char payload[XRDC_PATH_MAX + 3];
    int length;
    int rc;

    length = snprintf(payload, sizeof(payload), "%s\n/", path);
    if (length < 0 || (size_t) length >= sizeof(payload)) return -1;
    memset(&request, 0, sizeof(request));
    request.requestid = htons(kXR_statx);
    rc = brix_roundtrip_resilient(connection, &request, payload,
        (uint32_t) length, XRDC_OP_READONLY, 0, &wire_status, &body,
        &body_len, status);
    if (rc == 0 && body_len == 2) memcpy(flags, body, 2);
    else rc = -1;
    free(body);
    return rc;
}

static void
probe_stat_boundaries(xrd_conform_execution *execution,
    brix_conn *connection, const char *path, const brix_statinfo *baseline)
{
    static const unsigned char controls[] = { '\n', '\t', 0x7f };
    char test_path[XRDC_PATH_MAX];
    char long_path[4097];
    brix_statinfo info;
    brix_status status;
    char reason[64];
    size_t index;
    int safe = 1;
    int exercised = 1;

    for (index = 0; index < sizeof(controls); index++) {
        size_t path_len = strlen(path);

        if (path_len + 16 >= sizeof(test_path)) {
            exercised = 0;
            break;
        }
        memcpy(test_path, path, path_len);
        test_path[path_len] = (char) controls[index];
        memcpy(test_path + path_len + 1, "brix-control", 13);
        if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
            exercised = 0;
            break;
        }
        brix_status_clear(&status);
        if (brix_stat(connection, test_path, &info, &status) == 0
            && info.id == baseline->id) safe = 0;
    }
    grade(execution, "STA-017", exercised && safe,
        "control-path-answered-or-refused-without-truncation",
        exercised ? "control-path-silently-truncated" : "probe-budget-exhausted");

    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1] = '\0';
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    brix_status_clear(&status);
    {
        int refused = brix_stat(connection, long_path, &info, &status) != 0;
        int pass = refused && status.kxr == kXR_ArgTooLong;

        xrd_conform_result_set(execution, "STA-018",
            pass ? BRIX_CONFORM_VERDICT_CONFORMANT
                 : BRIX_CONFORM_VERDICT_DIVERGENT,
            pass ? "overlong-stat-kXR_ArgTooLong"
                 : "overlong-stat-wrong-answer",
            "kXR_ArgTooLong", status.msg);
    }
}

static void
probe_stat_forms(xrd_conform_execution *execution, brix_conn *connection,
    const brix_file *file, const char *path, const brix_statinfo *path_stat)
{
    static const char *const statx_ids[] = { "STA-015", "STA-016" };
    brix_statinfo handle_stat;
    brix_status status;
    char vfs[256];
    char trailing;
    char reason[64];
    long long nodes_rw, free_rw, util_rw, nodes_stage, free_stage, util_stage;
    uint8_t statx_flags[2];
    int handle_ok;
    int vfs_fields;

    if (xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
        brix_status_clear(&status);
        handle_ok = stat_handle(connection, file, &handle_stat, &status) == 0;
        grade(execution, "STA-008", handle_ok
            && handle_stat.id == path_stat->id
            && handle_stat.size == path_stat->size
            && handle_stat.flags == path_stat->flags
            && handle_stat.mtime == path_stat->mtime,
            "handle-stat-matches-path-stat", "handle-stat-differs-from-path-stat");
    }

    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    brix_status_clear(&status);
    memset(vfs, 0, sizeof(vfs));
    if (brix_statvfs(connection, "/", vfs, sizeof(vfs), &status) != 0) {
        grade(execution, "STA-013", 0, "vfs-stat-six-field-form",
            "vfs-stat-request-failed");
        return;
    }
    vfs_fields = sscanf(vfs, "%lld %lld %lld %lld %lld %lld %c",
        &nodes_rw, &free_rw, &util_rw, &nodes_stage, &free_stage,
        &util_stage, &trailing);
    grade(execution, "STA-013", vfs_fields == 6,
        "vfs-stat-six-field-form", "vfs-stat-file-form-or-invalid");

    if (!reserve_stat(execution, statx_ids,
            sizeof(statx_ids) / sizeof(statx_ids[0]))) return;
    brix_status_clear(&status);
    handle_ok = statx_pair(connection, path, statx_flags, &status) == 0;
    grade(execution, "STA-015", handle_ok
        && statx_flags[0] == (path_stat->flags & (kXR_isDir | kXR_offline))
        && (statx_flags[1] & kXR_isDir) != 0,
        "statx-one-ordered-flag-byte-per-path",
        "statx-shape-or-order-mismatch");
    grade(execution, "STA-016", handle_ok
        && statx_flags[0] == (path_stat->flags & (kXR_isDir | kXR_offline)),
        "statx-flags-agree-with-stat", "statx-flags-disagree-with-stat");
}

static void
grade_primary_stat(xrd_conform_execution *execution,
    const brix_statinfo *first, int first_ok, uint64_t size, time_t now)
{
    grade(execution, "STA-002", first_ok && first->size >= 0
        && (uint64_t) first->size == size, "stat-size-matches-read",
        "stat-size-mismatch");
    grade(execution, "STA-003", first_ok
        && (first->flags & (kXR_isDir | kXR_other)) == 0,
        "regular-file-flags", "unexpected-file-type-flags");
    grade(execution, "STA-009", first_ok && first->mtime > 0
        && now != (time_t) -1 && first->mtime <= now + 300,
        "plausible-unix-mtime", "implausible-unix-mtime");
    grade(execution, "STA-010", first_ok
        && (first->flags & kXR_offline) == 0,
        "readable-object-not-marked-offline", "online-object-marked-offline");
    grade(execution, "STA-001", first_ok && first->size >= 0,
        "stat-line-size-before-flags", "stat-line-order-invalid");
}

static void
probe_missing_stat(xrd_conform_execution *execution, brix_conn *connection,
    const char *path, brix_statinfo *info)
{
    static const char *const missing_ids[] = { "STA-007", "ERR-001" };
    brix_status status;
    char missing[XRDC_PATH_MAX];

    if ((size_t) snprintf(missing, sizeof(missing), "%s.brix-missing-%.8s",
            path, execution->run->key_hex) >= sizeof(missing)) return;
    if (!reserve_stat(execution, missing_ids,
            sizeof(missing_ids) / sizeof(missing_ids[0]))) return;
    brix_status_clear(&status);
    grade(execution, "STA-007",
        brix_stat(connection, missing, info, &status) != 0
            && status.kxr == kXR_NotFound,
        "missing-stat-kXR_NotFound", "missing-stat-wrong-answer");
    grade(execution, "ERR-001", status.kxr == kXR_NotFound,
        "ENOENT-mapped-kXR_NotFound", "ENOENT-mapping-mismatch");
}

/* WHAT: Exercise stat size/type/time/stability and missing-path mapping.
 * WHY: These assertions are fully observable through the typed metadata API.
 * HOW: Stat twice, compare learned body size, then stat a keyed absent sibling. */
void
xrd_conform_probe_stat(xrd_conform_execution *execution,
    brix_conn *connection, const brix_file *file, const char *path,
    uint64_t size)
{
    static const char *const first_ids[] = {
        "STA-001", "STA-002", "STA-003", "STA-009", "STA-010", "STA-014"
    };
    static const char *const second_ids[] = { "STA-014" };
    brix_statinfo first, second, root;
    brix_status status;
    time_t now = time(NULL);
    int first_ok;
    int second_ok;
    int second_reserved;
    int root_reserved;
    int root_ok = 0;

    brix_status_clear(&status);
    if (!reserve_stat(execution, first_ids,
            sizeof(first_ids) / sizeof(first_ids[0]))) return;
    first_ok = brix_stat(connection, path, &first, &status) == 0;
    brix_status_clear(&status);
    second_reserved = reserve_stat(execution, second_ids,
        sizeof(second_ids) / sizeof(second_ids[0]));
    second_ok = second_reserved
        && brix_stat(connection, path, &second, &status) == 0;
    grade_primary_stat(execution, &first, first_ok, size, now);
    root_reserved = reserve_stat(execution, second_ids,
        sizeof(second_ids) / sizeof(second_ids[0]));
    if (root_reserved) {
        brix_status_clear(&status);
        root_ok = brix_stat(connection, "/", &root, &status) == 0;
    }
    if (second_reserved && root_reserved) {
        grade(execution, "STA-014", first_ok && second_ok
            && first.id == second.id
            && root_ok && root.id != first.id,
            "stat-id-stable-and-distinct", "stat-id-not-stable-or-distinct");
    }
    if (first_ok) {
        probe_stat_forms(execution, connection, file, path, &first);
        probe_stat_boundaries(execution, connection, path, &first);
    }
    probe_missing_stat(execution, connection, path, &first);
}
