/* Phase-118 scratch-confined cross-plane mutation agreement. */
#include "xrd_conform_internal.h"
#include "core/compat/uri.h"

#define XPR_MUTATION_SIZE 257U

static const char *
fixture_target(const xrd_conform_run *run, const char *plane)
{
    size_t index;

    for (index = 0; index < run->mutation_fixture_count; index++)
        if (strcmp(run->mutation_fixtures[index].plane, plane) == 0)
            return run->mutation_fixtures[index].target;
    return NULL;
}

static int
scratch_weburl(xrd_conform_execution *execution, const char *target,
    brix_weburl *url)
{
    char path[XRDC_PATH_MAX];

    if (brix_weburl_parse(target, url) != 0
        || brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-xpr-mutation", path, sizeof(path)) != 0)
        return -1;
    return (size_t) snprintf(url->path, sizeof(url->path), "%s", path)
        < sizeof(url->path) ? 0 : -1;
}

static int
http_request(xrd_conform_execution *execution, const brix_weburl *url,
    const char *method, const char *token, const void *body, size_t length,
    brix_http_resp *response)
{
    brix_status status;

    memset(response, 0, sizeof(*response));
    brix_status_clear(&status);
    return xrd_conform_http_request_body(execution, url, method, token, NULL,
        body, length, 8192, response, &status);
}

static int
root_stat_size(xrd_conform_execution *execution, const char *target,
    uint64_t expected, int absent)
{
    brix_url url;
    brix_conn connection;
    brix_statinfo info;
    brix_status status;
    char path[XRDC_PATH_MAX];
    char reason[64];
    int rc;
    int matched;

    brix_status_clear(&status);
    if (brix_url_parse(target, &url, &status) != 0
        || brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-xpr-mutation", path, sizeof(path)) != 0
        || !xrd_conform_reserve(execution, 0, reason, sizeof(reason))
        || brix_connect(&connection, &url, &execution->run->opts, &status) != 0)
        return 0;
    brix_status_clear(&status);
    rc = brix_stat(&connection, path, &info, &status);
    matched = absent ? rc != 0 && status.kxr == kXR_NotFound
                     : rc == 0 && info.size >= 0
                        && (uint64_t) info.size == expected;
    brix_close(&connection);
    return matched;
}

static int
s3_listed(xrd_conform_execution *execution, const brix_weburl *object)
{
    brix_weburl listing = *object;
    brix_http_resp response;
    const char *bucket_end = strchr(object->path + 1, '/');
    const char *key;
    char encoded[XRDC_PATH_MAX * 3];
    char marker[XRDC_PATH_MAX + 16];
    size_t bucket_length;
    int rc;
    int matched;

    if (bucket_end == NULL) return 0;
    key = bucket_end + 1;
    bucket_length = (size_t) (bucket_end - object->path);
    if (brix_http_urlencode((const unsigned char *) key, strlen(key), encoded,
            sizeof(encoded), "") < 0
        || (size_t) snprintf(listing.path, sizeof(listing.path),
            "%.*s?list-type=2&max-keys=2&prefix=%s", (int) bucket_length,
            object->path, encoded) >= sizeof(listing.path)
        || (size_t) snprintf(marker, sizeof(marker), "<Key>%s</Key>", key)
            >= sizeof(marker)) return 0;
    rc = http_request(execution, &listing, "GET", NULL, NULL, 0, &response);
    matched = rc == 0 && response.status == 200 && response.body != NULL
        && strstr(response.body, "<IsTruncated>false</IsTruncated>") != NULL
        && strstr(response.body, marker) != NULL;
    if (rc == 0) brix_http_resp_free(&response);
    return matched;
}

static int
object_bytes(xrd_conform_execution *execution, const brix_weburl *object,
    const uint8_t *expected, size_t length, int absent)
{
    brix_http_resp response;
    int rc = http_request(execution, object, "GET", NULL, NULL, 0, &response);
    int matched = rc == 0 && (absent ? response.status == 404
        : response.status >= 200 && response.status < 300
            && response.body_len == length
            && memcmp(response.body, expected, length) == 0);

    if (rc == 0) brix_http_resp_free(&response);
    return matched;
}

void
xrd_conform_probe_mutation_fixtures(xrd_conform_execution *execution)
{
    const brix_conform_result *xpr_row = xrd_conform_result_find(execution,
        "XPR-009");
    const brix_conform_result *htc_row = xrd_conform_result_find(execution,
        "HTC-001");
    const char *root = fixture_target(execution->run, "root");
    const char *http = fixture_target(execution->run, "http");
    const char *s3 = fixture_target(execution->run, "s3");
    brix_weburl http_object;
    brix_weburl s3_object;
    brix_http_resp response;
    uint8_t payload[XPR_MUTATION_SIZE];
    char *token = NULL;
    int put_ok = 0;
    int root_ok = 0;
    int http_bytes_ok = 0;
    int list_ok = 0;
    int bytes_ok = 0;
    int common_cleanup_ok = 0;
    int xpr_cleanup_ok = 0;
    int xpr_active;
    int htc_active;
    int xpr_ready = 0;
    char received[128];

    xpr_active = xpr_row != NULL
        && xpr_row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
    htc_active = htc_row != NULL
        && htc_row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
    if ((!xpr_active && !htc_active)
        || execution->run->mutation_fixture_count == 0) return;
    if (root == NULL || http == NULL
        || scratch_weburl(execution, http, &http_object) != 0
        || http_object.is_s3) return;
    if (s3 != NULL && scratch_weburl(execution, s3, &s3_object) == 0
        && s3_object.is_s3) xpr_ready = 1;
    if (xpr_active && !xpr_ready && !htc_active) return;
    brix_conform_fill(&execution->run->key, 0, payload, sizeof(payload));
    token = brix_token_discover();
    if (http_request(execution, &http_object, "PUT", token, payload,
            sizeof(payload), &response) == 0) {
        put_ok = response.status >= 200 && response.status < 300;
        brix_http_resp_free(&response);
    }
    if (put_ok) {
        root_ok = root_stat_size(execution, root, sizeof(payload), 0);
        http_bytes_ok = object_bytes(execution, &http_object, payload,
            sizeof(payload), 0);
        if (xpr_ready) {
            list_ok = s3_listed(execution, &s3_object);
            bytes_ok = object_bytes(execution, &s3_object, payload,
                sizeof(payload), 0);
        }
    }
    if (http_request(execution, &http_object, "DELETE", token, NULL, 0,
            &response) == 0) {
        common_cleanup_ok = response.status >= 200 && response.status < 300;
        brix_http_resp_free(&response);
    }
    common_cleanup_ok = common_cleanup_ok
        && root_stat_size(execution, root, 0, 1);
    if (xpr_ready)
        xpr_cleanup_ok = common_cleanup_ok
            && object_bytes(execution, &s3_object, payload,
                sizeof(payload), 1);
    free(token);
    if (htc_active) {
        snprintf(received, sizeof(received),
            "put=%d http-bytes=%d root-size=%d cleanup=%d",
            put_ok, http_bytes_ok, root_ok, common_cleanup_ok);
        xrd_conform_result_set(execution, "HTC-001",
            put_ok && http_bytes_ok && root_ok && common_cleanup_ok
                ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
            put_ok && http_bytes_ok && root_ok && common_cleanup_ok
                ? "http-create-visible-byte-exactly-through-root"
                : "http-create-readback-or-cleanup-mismatch",
            "HTTP PUT reads back byte-exactly over HTTP and at exact ROOT size",
            received);
    }
    if (!xpr_active || !xpr_ready) return;
    snprintf(received, sizeof(received),
        "put=%d root-size=%d s3-list=%d s3-bytes=%d cleanup=%d",
        put_ok, root_ok, list_ok, bytes_ok, xpr_cleanup_ok);
    xrd_conform_result_set(execution, "XPR-009",
        put_ok && root_ok && list_ok && bytes_ok && xpr_cleanup_ok
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        put_ok && root_ok && list_ok && bytes_ok && xpr_cleanup_ok
            ? "cross-plane-mutation-agreement"
            : "cross-plane-mutation-or-cleanup-mismatch",
        "HTTP PUT visible at ROOT stat and S3 list/GET, then absent everywhere",
        received);
}
