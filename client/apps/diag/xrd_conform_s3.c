/* Phase-118 S3 consistency probes. */
#include "xrd_conform_internal.h"
#include "core/compat/host_format.h"
#include "core/compat/uri.h"

#define S3_LIST_TOKEN_MAX 8192

typedef struct {
    xrd_conform_execution *execution;
    const brix_weburl     *base;
    brix_weburl            objects[3];
    char                   prefix_path[XRDC_PATH_MAX];
    int                    seen[3];
    int                    extra;
    int                    replay_ok;
} s3_list_probe;

static int row_active(xrd_conform_execution *execution, const char *id);
static void delete_scratch(xrd_conform_execution *execution,
    const brix_weburl *scratch);

int
xrd_conform_s3_credentials(const char **access, const char **secret,
    const char **region)
{
    *access = getenv("AWS_ACCESS_KEY_ID");
    *secret = getenv("AWS_SECRET_ACCESS_KEY");
    *region = getenv("AWS_DEFAULT_REGION");
    if ((*access == NULL) != (*secret == NULL)) return -2;
    if (*access == NULL) return 0;
    if (!xrd_conform_credential_safe(*access)
        || !xrd_conform_credential_safe(*secret)
        || (*region != NULL && !xrd_conform_credential_safe(*region))) return -3;
    if (*region == NULL) *region = "us-east-1";
    return 1;
}

static int
s3_request_parts(const brix_weburl *url, char uri[XRDC_PATH_MAX],
    const char **query)
{
    size_t uri_length;

    *query = strchr(url->path, '?');
    uri_length = *query == NULL ? strlen(url->path)
                                : (size_t) (*query - url->path);
    if (uri_length == 0 || uri_length >= XRDC_PATH_MAX) return -1;
    memcpy(uri, url->path, uri_length);
    uri[uri_length] = '\0';
    if (*query != NULL && ((*query)[1] == '\0'
        || strchr(*query + 1, '#') != NULL)) return -1;
    return 0;
}

/* WHAT: Build a SigV4 block for a path or canonical-query S3 request.
 * WHY: Credential validation and query signing belong to the S3 probe unit.
 * HOW: Fail closed on partial/unsafe credentials and sign host:port exactly. */
int
xrd_conform_s3_auth_headers(const brix_weburl *url, const char *method,
    char authentication[2048])
{
    char host[300];
    char uri[XRDC_PATH_MAX];
    const char *payload_hash = "UNSIGNED-PAYLOAD";
    const char *access;
    const char *secret;
    const char *region;
    const char *query;
    int credential_state;

    authentication[0] = '\0';
    credential_state = xrd_conform_s3_credentials(&access, &secret, &region);
    if (credential_state <= 0) return credential_state;
    if (s3_request_parts(url, uri, &query) != 0) return -4;
    brix_format_host_port(url->host, (uint16_t) url->port, host, sizeof(host));
    if (query != NULL)
        return brix_s3_sign_v4_q(method, host, uri, query + 1, access, secret,
            region, payload_hash, authentication, 2048) == 0 ? 0 : -5;
    return brix_s3_sign_v4(method, host, uri, access, secret, region,
        payload_hash, authentication, 2048) == 0 ? 0 : -5;
}

static void
skip_listing_rows(xrd_conform_execution *execution)
{
    static const char *const ids[] = { "S3-003", "S3-004" };
    size_t index;

    for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++)
        if (row_active(execution, ids[index]))
            xrd_conform_result_set(execution, ids[index],
                BRIX_CONFORM_VERDICT_SKIPPED,
                "fixture-absent:mutable-path-style-s3-scratch", NULL, NULL);
}

static void
grade_listing_rows(xrd_conform_execution *execution, int normal, int paged,
    int replay_ok)
{
    if (row_active(execution, "S3-003"))
        xrd_conform_result_set(execution, "S3-003",
            normal && paged ? BRIX_CONFORM_VERDICT_CONFORMANT
                            : BRIX_CONFORM_VERDICT_DIVERGENT,
            normal && paged ? "s3-list-and-pagination-keysets-match"
                            : "s3-list-or-pagination-keyset-mismatch",
            "three planted keys exactly once in both listings", NULL);
    if (row_active(execution, "S3-004"))
        xrd_conform_result_set(execution, "S3-004",
            paged && replay_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                               : BRIX_CONFORM_VERDICT_DIVERGENT,
            paged && replay_ok ? "s3-continuation-token-replay-stable"
                               : "s3-continuation-token-replay-diverged",
            "same opaque token returns a byte-identical page", NULL);
}

static void
delete_list_objects(s3_list_probe *probe)
{
    size_t index;

    for (index = 0; index < 3; index++)
        delete_scratch(probe->execution, &probe->objects[index]);
}

static int
row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static int
empty_get_ok(xrd_conform_execution *execution, const brix_weburl *scratch,
    brix_status *status)
{
    brix_http_resp response;
    int rc;
    int ok;

    memset(&response, 0, sizeof(response));
    rc = xrd_conform_http_request_fields(execution, scratch, "GET", NULL,
        NULL, 1, &response, status);
    ok = rc == 0 && response.status == 200 && response.body_len == 0;
    if (rc == 0) brix_http_resp_free(&response);
    return ok;
}

static int
empty_range_ok(xrd_conform_execution *execution, const brix_weburl *scratch,
    brix_status *status)
{
    brix_http_resp response;
    int rc;
    int ok;

    memset(&response, 0, sizeof(response));
    rc = xrd_conform_http_request_fields(execution, scratch, "GET", NULL,
        "Range: bytes=0-\r\n", 64, &response, status);
    ok = rc == 0 && response.status == 416;
    if (rc == 0) brix_http_resp_free(&response);
    return ok;
}

static void
delete_scratch(xrd_conform_execution *execution, const brix_weburl *scratch)
{
    brix_http_resp response;
    brix_status status;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    if (xrd_conform_http_request_fields(execution, scratch, "DELETE", NULL,
            NULL, 0, &response, &status) == 0)
        brix_http_resp_free(&response);
}

/* WHAT: Exercise the zero-object S3 range branch without touching adopted data.
 * WHY: HTR-009 is part of S3-002 but cannot run against a non-empty baseline.
 * HOW: Create an empty scratch key, require empty GET and ranged 416, delete. */
static void
probe_zero_range(xrd_conform_execution *execution, const brix_weburl *base)
{
    brix_weburl scratch = *base;
    brix_http_resp response;
    brix_status status;
    char path[XRDC_PATH_MAX];
    int put_rc;
    int get_ok = 0;
    int range_ok = 0;

    if (!row_active(execution, "HTR-009")) return;
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-s3-zero", path, sizeof(path)) != 0
        || (size_t) snprintf(scratch.path, sizeof(scratch.path), "%s", path)
            >= sizeof(scratch.path)) {
        xrd_conform_result_set(execution, "HTR-009",
            BRIX_CONFORM_VERDICT_SKIPPED,
            "fixture-absent:mutable-s3-scratch", NULL, NULL);
        return;
    }
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    put_rc = xrd_conform_http_request_body(execution, &scratch, "PUT", NULL,
        NULL, NULL, 0, 0, &response, &status);
    if (put_rc == 0) brix_http_resp_free(&response);
    if (put_rc == 0) {
        get_ok = empty_get_ok(execution, &scratch, &status);
        range_ok = empty_range_ok(execution, &scratch, &status);
    }
    xrd_conform_result_set(execution, "HTR-009",
        put_rc == 0 && get_ok && range_ok
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        put_rc == 0 && get_ok && range_ok
            ? "s3-zero-object-get-empty-range-unsatisfiable"
            : "s3-zero-object-range-semantics-invalid",
        "empty GET 200 and bytes=0- returns 416", status.msg);
    delete_scratch(execution, &scratch);
}

/* WHAT: Grade S3-002 from the complete HTTP range-grid observations.
 * WHY: S3 range behavior is HTTP range behavior plus a cross-family promise;
 *      rerunning the same requests would waste ceilings and could drift.
 * HOW: Propagate any divergence, require every dependency to be conformant,
 *      and retain uncertainty when an optional response was not observed. */
void
xrd_conform_probe_s3_range_agreement(xrd_conform_execution *execution,
    const brix_weburl *url)
{
    static const char *const dependencies[] = {
        "HTR-003", "HTR-004", "HTR-005", "HTR-006", "HTR-007",
        "HTR-008", "HTR-009", "HTR-010", "HTR-011", "HTR-012",
        "HTR-013", "HTR-014"
    };
    const brix_conform_result *s3;
    size_t index;
    int complete = 1;

    if (!url->is_s3) return;
    probe_zero_range(execution, url);
    s3 = xrd_conform_result_find(execution, "S3-002");
    if (s3 == NULL || s3->verdict == BRIX_CONFORM_VERDICT_SKIPPED) return;
    for (index = 0; index < sizeof(dependencies) / sizeof(dependencies[0]);
            index++) {
        const brix_conform_result *row = xrd_conform_result_find(execution,
            dependencies[index]);

        if (row != NULL && row->verdict == BRIX_CONFORM_VERDICT_DIVERGENT) {
            xrd_conform_result_set(execution, "S3-002",
                BRIX_CONFORM_VERDICT_DIVERGENT,
                "s3-range-grid-diverged-from-http-semantics", NULL,
                dependencies[index]);
            return;
        }
        if (row == NULL || row->verdict != BRIX_CONFORM_VERDICT_CONFORMANT)
            complete = 0;
    }
    xrd_conform_result_set(execution, "S3-002",
        complete ? BRIX_CONFORM_VERDICT_CONFORMANT
                 : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
        complete ? "s3-range-grid-matches-http-semantics"
                 : "s3-range-grid-incomplete",
        "HTR-003 through HTR-014 conformant on the S3 target", NULL);
}

static int
s3_error_is(xrd_conform_execution *execution, const brix_weburl *url,
    const char *code)
{
    brix_http_resp response;
    brix_status status;
    char needle[64];
    int rc;
    int matches;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "GET", NULL, NULL,
        4096, &response, &status);
    snprintf(needle, sizeof(needle), "<Code>%s</Code>", code);
    matches = rc == 0 && response.status == 404 && response.body != NULL
        && strstr(response.body, needle) != NULL
        && strstr(response.body, "<Code>InternalError</Code>") == NULL;
    if (rc == 0) brix_http_resp_free(&response);
    return matches;
}

static int
missing_s3_paths(xrd_conform_execution *execution, const brix_weburl *url,
    brix_weburl *key, brix_weburl *bucket)
{
    const char *key_part;

    if (url->path[0] != '/') return -1;
    key_part = strchr(url->path + 1, '/');
    if (key_part == NULL || key_part[1] == '\0') return -1;
    *key = *url;
    *bucket = *url;
    if ((size_t) snprintf(key->path, sizeof(key->path),
            "%s.brix-conform-missing-%.8s", url->path,
            execution->run->key_hex) >= sizeof(key->path)) return -1;
    if ((size_t) snprintf(bucket->path, sizeof(bucket->path),
            "/brix-conform-missing-%.8s%s", execution->run->key_hex,
            key_part) >= sizeof(bucket->path)) return -1;
    return 0;
}

/* WHAT: Distinguish a missing S3 key from a missing path-style bucket.
 * WHY: A generic InternalError hides the failure class and breaks AWS clients.
 * HOW: Request generated absent names and require the exact bounded XML codes. */
void
xrd_conform_probe_s3_missing_codes(xrd_conform_execution *execution,
    const brix_weburl *url)
{
    brix_weburl missing_key;
    brix_weburl missing_bucket;
    int key_ok;
    int bucket_ok;

    if (!url->is_s3 || !row_active(execution, "S3-010")) return;
    if (missing_s3_paths(execution, url, &missing_key, &missing_bucket) != 0) {
        xrd_conform_result_set(execution, "S3-010",
            BRIX_CONFORM_VERDICT_SKIPPED,
            "fixture-absent:path-style-bucket-and-key", NULL, NULL);
        return;
    }
    key_ok = s3_error_is(execution, &missing_key, "NoSuchKey");
    bucket_ok = s3_error_is(execution, &missing_bucket, "NoSuchBucket");
    xrd_conform_result_set(execution, "S3-010",
        key_ok && bucket_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                            : BRIX_CONFORM_VERDICT_DIVERGENT,
        key_ok && bucket_ok ? "s3-missing-codes-distinguished"
                            : "s3-missing-code-invalid",
        "NoSuchKey and NoSuchBucket XML",
        key_ok && bucket_ok ? NULL
            : key_ok ? "missing bucket did not return NoSuchBucket"
                     : "missing key did not return NoSuchKey");
}

static int
xml_value(const char *body, const char *open, const char *close, char *out,
    size_t out_size)
{
    const char *start = strstr(body, open);
    const char *end;
    size_t length;

    if (start == NULL) return 0;
    start += strlen(open);
    end = strstr(start, close);
    if (end == NULL) return 0;
    length = (size_t) (end - start);
    if (length >= out_size) return -1;
    memcpy(out, start, length);
    out[length] = '\0';
    return 1;
}

static const char *
s3_object_key(const char *path)
{
    const char *slash = path[0] == '/' ? strchr(path + 1, '/') : NULL;

    return slash == NULL ? NULL : slash + 1;
}

static int
list_page_url(const s3_list_probe *probe, unsigned max_keys,
    const char *token, brix_weburl *out)
{
    const char *bucket_end = strchr(probe->prefix_path + 1, '/');
    const char *prefix;
    char encoded_prefix[XRDC_PATH_MAX * 3];
    char encoded_token[S3_LIST_TOKEN_MAX * 3];
    char query[XRDC_PATH_MAX * 4];
    size_t bucket_length;
    int written;

    if (probe->prefix_path[0] != '/' || bucket_end == NULL) return -1;
    bucket_length = (size_t) (bucket_end - probe->prefix_path);
    prefix = bucket_end + 1;
    if (brix_http_urlencode((const unsigned char *) prefix, strlen(prefix),
            encoded_prefix, sizeof(encoded_prefix), "") < 0) return -1;
    if (token[0] != '\0'
        && brix_http_urlencode((const unsigned char *) token, strlen(token),
            encoded_token, sizeof(encoded_token), "") < 0) return -1;
    written = token[0] == '\0'
        ? snprintf(query, sizeof(query), "list-type=2%s%sprefix=%s",
            max_keys == 0 ? "&" : "&max-keys=", max_keys == 0 ? "" : "1&",
            encoded_prefix)
        : snprintf(query, sizeof(query),
            "continuation-token=%s&list-type=2%s%sprefix=%s", encoded_token,
            max_keys == 0 ? "&" : "&max-keys=", max_keys == 0 ? "" : "1&",
            encoded_prefix);
    if (written < 0 || (size_t) written >= sizeof(query)) return -1;
    *out = *probe->base;
    if (bucket_length + 1U + (size_t) written >= sizeof(out->path)) return -1;
    memcpy(out->path, probe->prefix_path, bucket_length);
    out->path[bucket_length] = '?';
    memcpy(out->path + bucket_length + 1, query, (size_t) written + 1);
    return 0;
}

static int
fetch_list_page(s3_list_probe *probe, unsigned max_keys, const char *token,
    brix_http_resp *response)
{
    brix_weburl page;
    brix_status status;

    if (list_page_url(probe, max_keys, token, &page) != 0) return -1;
    memset(response, 0, sizeof(*response));
    brix_status_clear(&status);
    return xrd_conform_http_request_fields(probe->execution, &page, "GET",
        NULL, NULL, 32768, response, &status) == 0 && response->status == 200
        ? 0 : -1;
}

static int
scan_list_page(s3_list_probe *probe, const brix_http_resp *response,
    char *next, size_t next_size, int *more)
{
    const char *cursor = response->body == NULL ? "" : response->body;
    size_t page_count = 0;

    while ((cursor = strstr(cursor, "<Key>")) != NULL) {
        char key[XRDC_PATH_MAX];
        int match = -1;
        size_t index;

        if (xml_value(cursor, "<Key>", "</Key>", key, sizeof(key)) != 1)
            return -1;
        for (index = 0; index < 3; index++) {
            const char *expected = s3_object_key(probe->objects[index].path);

            if (expected != NULL && strcmp(key, expected) == 0)
                match = (int) index;
        }
        if (match < 0 || probe->seen[match]) probe->extra = 1;
        else probe->seen[match] = 1;
        page_count++;
        cursor += 5;
    }
    *more = response->body != NULL
        && strstr(response->body, "<IsTruncated>true</IsTruncated>") != NULL;
    next[0] = '\0';
    if (*more && xml_value(response->body, "<NextContinuationToken>",
            "</NextContinuationToken>", next, next_size) != 1) return -1;
    return (int) page_count;
}

static int
collect_listing(s3_list_probe *probe, unsigned max_keys, int replay)
{
    char token[S3_LIST_TOKEN_MAX] = "";
    unsigned round;

    memset(probe->seen, 0, sizeof(probe->seen));
    probe->extra = 0;
    probe->replay_ok = 0;
    for (round = 0; round < 8; round++) {
        brix_http_resp response;
        brix_http_resp repeated;
        char next[S3_LIST_TOKEN_MAX];
        int more;
        int count;

        if (fetch_list_page(probe, max_keys, token, &response) != 0) return 0;
        if (replay && round == 1) {
            if (fetch_list_page(probe, max_keys, token, &repeated) == 0) {
                probe->replay_ok = repeated.status == response.status
                    && repeated.body_len == response.body_len
                    && memcmp(repeated.body, response.body,
                        response.body_len) == 0;
                brix_http_resp_free(&repeated);
            }
        }
        count = scan_list_page(probe, &response, next, sizeof(next), &more);
        brix_http_resp_free(&response);
        if (count < 0 || (max_keys == 1 && count > 1)) return 0;
        if (!more)
            return !probe->extra && probe->seen[0] && probe->seen[1]
                && probe->seen[2];
        snprintf(token, sizeof(token), "%s", next);
    }
    return 0;
}

static int
prepare_list_objects(xrd_conform_execution *execution, const brix_weburl *url,
    s3_list_probe *probe)
{
    static const char suffixes[] = { 'a', 'b', 'c' };
    size_t index;
    size_t prefix_length;

    memset(probe, 0, sizeof(*probe));
    probe->execution = execution;
    probe->base = url;
    for (index = 0; index < 3; index++) {
        char name[64];

        snprintf(name, sizeof(name), "brix-conform-s3-list-%c", suffixes[index]);
        probe->objects[index] = *url;
        if (brix_conform_scratch_path(execution->run->config.scratch, name,
                probe->objects[index].path,
                sizeof(probe->objects[index].path)) != 0) return -1;
    }
    prefix_length = strlen(probe->objects[0].path) - 1;
    if (prefix_length >= sizeof(probe->prefix_path)) return -1;
    memcpy(probe->prefix_path, probe->objects[0].path, prefix_length);
    probe->prefix_path[prefix_length] = '\0';
    return s3_object_key(probe->prefix_path) == NULL ? -1 : 0;
}

static int
put_list_objects(s3_list_probe *probe)
{
    size_t index;

    for (index = 0; index < 3; index++) {
        brix_http_resp response;
        brix_status status;
        char body = (char) ('a' + index);
        int rc;

        memset(&response, 0, sizeof(response));
        brix_status_clear(&status);
        rc = xrd_conform_http_request_body(probe->execution,
            &probe->objects[index], "PUT", NULL, NULL, &body, 1, 0,
            &response, &status);
        if (rc != 0 || response.status < 200 || response.status >= 300) {
            if (rc == 0) brix_http_resp_free(&response);
            while (index > 0) {
                index--;
                delete_scratch(probe->execution, &probe->objects[index]);
            }
            return -1;
        }
        brix_http_resp_free(&response);
    }
    return 0;
}

/* WHAT: Compare ordinary and one-key S3 listings and replay a continuation.
 * WHY: Pagination must neither lose keys nor turn tokens into mutable cursors.
 * HOW: Plant three scratch keys, enumerate twice, replay page two, then clean. */
void
xrd_conform_probe_s3_listing(xrd_conform_execution *execution,
    const brix_weburl *url)
{
    s3_list_probe probe;
    int normal;
    int paged;

    if (!url->is_s3 || (!row_active(execution, "S3-003")
        && !row_active(execution, "S3-004"))) return;
    if (prepare_list_objects(execution, url, &probe) != 0
        || put_list_objects(&probe) != 0) {
        skip_listing_rows(execution);
        return;
    }
    normal = collect_listing(&probe, 0, 0);
    paged = collect_listing(&probe, 1, 1);
    grade_listing_rows(execution, normal, paged, probe.replay_ok);
    delete_list_objects(&probe);
}
