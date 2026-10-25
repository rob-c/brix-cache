/* Phase-118 paired ROOT/HTTP errno fixture matrix. */
#include "xrd_conform_internal.h"

typedef struct {
    const char *name;
    uint16_t    kxr;
    int         http;
} http_error_pair;

/* WHAT: Return the six cross-plane mappings required by ERR-043.
 * WHY: Keep the contract local and immutable without adding a file-scope global.
 * HOW: Return one function-owned constant descriptor array and its count. */
static const http_error_pair *
http_error_pairs(size_t *count)
{
    static const http_error_pair pairs[] = {
        { "ENOENT", kXR_NotFound, 404 },
        { "EACCES", kXR_NotAuthorized, 403 },
        { "EROFS", kXR_fsReadOnly, 403 },
        { "EINVAL", kXR_ArgInvalid, 400 },
        { "EIO", kXR_IOError, 500 },
        { "ENOMEM", kXR_NoMemory, 507 },
    };

    *count = sizeof(pairs) / sizeof(pairs[0]);
    return pairs;
}

/* WHAT: Find one labelled fixture for the requested transport plane.
 * WHY: Root and HTTP fixtures may share an errno name but are distinct evidence.
 * HOW: Scan the bounded parsed option vector for an exact name and plane bit. */
static const char *
fixture_target(const xrd_conform_run *run, const char *name, int is_http)
{
    size_t index;

    for (index = 0; index < run->error_fixture_count; index++)
        if (run->error_fixtures[index].is_http == is_http
            && strcmp(run->error_fixtures[index].errno_name, name) == 0)
            return run->error_fixtures[index].target;
    return NULL;
}

/* WHAT: Issue one GET to an HTTP error fixture and return its status/reason.
 * WHY: ERR-043 requires a real HTTP response paired with the real ROOT response.
 * HOW: Parse the explicit URL, perform a bounded GET, and free every body. */
static int
observe_http_once(xrd_conform_execution *execution, const char *target,
    const char *method, int *status_code, char reason[128])
{
    brix_weburl url;
    brix_http_resp response;
    brix_status status;
    int rc;

    if (brix_weburl_parse(target, &url) != 0) return -1;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = strcmp(method, "PUT") == 0
        ? xrd_conform_http_request_body(execution, &url, method, NULL, NULL,
            "R", 1, 4096, &response, &status)
        : xrd_conform_http_request_fields(execution, &url, method, NULL, NULL,
            4096, &response, &status);
    if (rc != 0) {
        snprintf(reason, 128, "%.127s", status.msg);
        return -1;
    }
    *status_code = response.status;
    snprintf(reason, 128, "%.127s", response.reason);
    brix_http_resp_free(&response);
    return 0;
}

/* WHAT: Observe and compare one ROOT/HTTP mapping pair twice on HTTP.
 * WHY: A transient or changing HTTP answer is not cross-plane agreement.
 * HOW: Require exact kXR, exact HTTP status, and repeat-stable HTTP evidence. */
static int
pair_matches(xrd_conform_execution *execution, const http_error_pair *pair,
    const char *root_target, const char *http_target)
{
    uint16_t root_code = 0;
    int first_status = 0;
    int repeat_status = 0;
    char root_message[128];
    char first_reason[128];
    char repeat_reason[128];

    return xrd_conform_observe_root_error(execution, root_target, &root_code,
            root_message) == 0
        && observe_http_once(execution, http_target, "GET", &first_status,
            first_reason) == 0
        && observe_http_once(execution, http_target, "GET", &repeat_status,
            repeat_reason) == 0
        && root_code == pair->kxr && first_status == pair->http
        && repeat_status == first_status
        && strcmp(repeat_reason, first_reason) == 0;
}

static int
readonly_create_matches(xrd_conform_execution *execution,
    const char *root_target, const char *http_target)
{
    uint16_t root_code = 0;
    int first_status = 0;
    int repeat_status = 0;
    char root_message[128];
    char first_reason[128];
    char repeat_reason[128];

    return root_target != NULL && http_target != NULL
        && xrd_conform_observe_root_error(execution, root_target, &root_code,
            root_message) == 0
        && observe_http_once(execution, http_target, "PUT", &first_status,
            first_reason) == 0
        && observe_http_once(execution, http_target, "PUT", &repeat_status,
            repeat_reason) == 0
        && root_code == kXR_fsReadOnly && first_status == 403
        && repeat_status == first_status
        && strcmp(repeat_reason, first_reason) == 0;
}

/* WHAT: Grade the paired ROOT/HTTP read-only creation contract.
 * WHY: HTC-002 requires a denied mutation, not inference from a safe GET.
 * HOW: Require exact EROFS fixtures, issue PUT twice, and compare native codes. */
static void
grade_readonly_create(xrd_conform_execution *execution)
{
    const brix_conform_result *row = xrd_conform_result_find(execution,
        "HTC-002");
    const char *root_target = fixture_target(execution->run, "EROFS", 0);
    const char *http_target = fixture_target(execution->run, "EROFS", 1);
    int matched;

    if (row == NULL || row->verdict == BRIX_CONFORM_VERDICT_SKIPPED
        || (root_target == NULL && http_target == NULL)) return;
    matched = readonly_create_matches(execution, root_target, http_target);
    xrd_conform_result_set(execution, "HTC-002",
        matched ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        matched ? "root-and-http-readonly-create-agree"
                : "readonly-create-fixture-incomplete-or-divergent",
        "ROOT kXR_fsReadOnly and repeat-stable HTTP PUT 403",
        matched ? "root=3025 http-put=403 stable=1"
                : "missing-or-mismatched-EROFS-pair");
}

/* WHAT: Grade a complete six-category ROOT-to-HTTP error-mapping row.
 * WHY: ERR-043 and HTE-001 express the same cross-plane mapping contract.
 * HOW: Require labelled fixtures for both planes of every category, then fold
 *      six exact, deterministic comparisons into the selected row. */
static void
grade_matrix(xrd_conform_execution *execution, const char *id)
{
    const http_error_pair *pairs;
    const brix_conform_result *row;
    size_t count;
    size_t index;
    size_t supplied = 0;
    size_t matched = 0;
    char received[96];

    row = xrd_conform_result_find(execution, id);
    if (row == NULL || row->verdict == BRIX_CONFORM_VERDICT_SKIPPED) return;
    pairs = http_error_pairs(&count);
    for (index = 0; index < count; index++) {
        const char *root_target = fixture_target(execution->run,
            pairs[index].name, 0);
        const char *http_target = fixture_target(execution->run,
            pairs[index].name, 1);

        if (root_target == NULL && http_target == NULL) continue;
        if (root_target == NULL || http_target == NULL) {
            supplied++;
            continue;
        }
        supplied++;
        if (pair_matches(execution, &pairs[index], root_target, http_target))
            matched++;
    }
    if (supplied == 0) return;
    snprintf(received, sizeof(received), "pairs=%zu/%zu exact=%zu/%zu",
        supplied, count, matched, count);
    xrd_conform_result_set(execution, id,
        supplied == count && matched == count
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        supplied == count && matched == count
            ? "root-and-http-error-matrix-agrees"
            : "root-and-http-error-matrix-incomplete-or-divergent",
        "six labelled ROOT/HTTP errno pairs", received);
}

/* WHAT: Apply the shared matrix evidence to every active contract row.
 * WHY: The ERR consistency row and HTTP error row must never drift apart.
 * HOW: Grade both ids; the result helper preserves out-of-scope skipped rows. */
void
xrd_conform_probe_http_error_fixtures(xrd_conform_execution *execution)
{
    grade_matrix(execution, "ERR-043");
    grade_matrix(execution, "HTE-001");
    grade_readonly_create(execution);
}
