/* Phase-118 S3 wire-path and unusual-key conformance probes. */
#include "xrd_conform_internal.h"
#include "core/compat/uri.h"

static int
row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

/* WHAT: Encode only the S3 URI while preserving an already-canonical query.
 * WHY: SigV4 hashes the encoded URI, and raw spaces must never enter HTTP/1.1.
 * HOW: RFC-3986 encode path bytes with slash safe, then append the query. */
int
xrd_conform_s3_wire_path(const brix_weburl *url, char *out, size_t out_size)
{
    const char *query = strchr(url->path, '?');
    size_t uri_length = query == NULL ? strlen(url->path)
                                      : (size_t) (query - url->path);
    ssize_t encoded;

    encoded = brix_http_urlencode((const unsigned char *) url->path,
        uri_length, out, out_size, "/");
    if (encoded < 0) return -1;
    if (query == NULL) return 0;
    if ((size_t) encoded + strlen(query) >= out_size) return -1;
    memcpy(out + encoded, query, strlen(query) + 1);
    return 0;
}

static const char *
object_key(const char *path)
{
    const char *slash = path[0] == '/' ? strchr(path + 1, '/') : NULL;

    return slash == NULL ? NULL : slash + 1;
}

static int
special_paths(xrd_conform_execution *execution, const brix_weburl *base,
    brix_weburl objects[4], char prefix[XRDC_PATH_MAX])
{
    static const char *const leaves[] = {
        "brix-conform-s3-key-plus+",
        "brix-conform-s3-key-percent%",
        "brix-conform-s3-key-space name",
        "brix-conform-s3-key-utf8-\xc3\xa9"
    };
    size_t index;

    for (index = 0; index < 4; index++) {
        objects[index] = *base;
        if (brix_conform_scratch_path(execution->run->config.scratch,
                leaves[index], objects[index].path,
                sizeof(objects[index].path)) != 0) return -1;
    }
    return brix_conform_scratch_path(execution->run->config.scratch,
        "brix-conform-s3-key-", prefix, XRDC_PATH_MAX);
}

static int
put_special(xrd_conform_execution *execution, brix_weburl objects[4],
    size_t *created)
{
    for (*created = 0; *created < 4; (*created)++) {
        brix_http_resp response;
        brix_status status;
        char body = (char) ('A' + *created);
        int rc;

        memset(&response, 0, sizeof(response));
        brix_status_clear(&status);
        rc = xrd_conform_http_request_body(execution, &objects[*created],
            "PUT", NULL, NULL, &body, 1, 0, &response, &status);
        if (rc != 0 || response.status < 200 || response.status >= 300) {
            if (rc == 0) brix_http_resp_free(&response);
            return -1;
        }
        brix_http_resp_free(&response);
    }
    return 0;
}

static int
get_special(xrd_conform_execution *execution, brix_weburl objects[4])
{
    size_t index;

    for (index = 0; index < 4; index++) {
        brix_http_resp response;
        brix_status status;
        int rc;

        memset(&response, 0, sizeof(response));
        brix_status_clear(&status);
        rc = xrd_conform_http_request_fields(execution, &objects[index],
            "GET", NULL, NULL, 1, &response, &status);
        if (rc != 0 || response.status != 200 || response.body_len != 1
            || response.body[0] != (char) ('A' + index)) {
            if (rc == 0) brix_http_resp_free(&response);
            return 0;
        }
        brix_http_resp_free(&response);
    }
    return 1;
}

static int
listing_url(const brix_weburl *base, const char *prefix, brix_weburl *out)
{
    const char *bucket_end = strchr(prefix + 1, '/');
    char encoded[XRDC_PATH_MAX * 3];
    size_t bucket_length;
    int written;

    if (prefix[0] != '/' || bucket_end == NULL) return -1;
    bucket_length = (size_t) (bucket_end - prefix);
    if (brix_http_urlencode((const unsigned char *) bucket_end + 1,
            strlen(bucket_end + 1), encoded, sizeof(encoded), "") < 0) return -1;
    *out = *base;
    written = snprintf(out->path, sizeof(out->path), "%.*s?list-type=2&prefix=%s",
        (int) bucket_length, prefix, encoded);
    return written < 0 || (size_t) written >= sizeof(out->path) ? -1 : 0;
}

static int
key_index(brix_weburl objects[4], const char *key, size_t key_length)
{
    size_t index;

    for (index = 0; index < 4; index++) {
        const char *expected = object_key(objects[index].path);

        if (expected != NULL && strlen(expected) == key_length
            && memcmp(expected, key, key_length) == 0) return (int) index;
    }
    return -1;
}

/* ---- Compare a ListObjectsV2 page with the exact unusual-key set ----
 *
 * WHAT: Returns one only when all four expected keys occur exactly once and no
 *       other key is present; malformed XML fragments return zero.
 * WHY: Membership-only checks can accept duplicated, rewritten or injected
 *      names and would not establish a lossless S3 listing round trip.
 * HOW: Walk bounded Key elements, map each value to an expected object, reject
 *      unknown/duplicate entries, then require all four bits and four entries.
 */
static int
list_has_special(xrd_conform_execution *execution, const brix_weburl *base,
    brix_weburl objects[4], const char *prefix)
{
    brix_weburl listing;
    brix_http_resp response;
    brix_status status;
    const char *cursor;
    unsigned seen = 0;
    size_t found = 0;
    int rc;

    if (listing_url(base, prefix, &listing) != 0) return 0;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, &listing, "GET", NULL,
        NULL, 32768, &response, &status);
    if (rc != 0 || response.status != 200 || response.body == NULL) {
        if (rc == 0) brix_http_resp_free(&response);
        return 0;
    }
    cursor = response.body;
    while ((cursor = strstr(cursor, "<Key>")) != NULL) {
        const char *value = cursor + strlen("<Key>");
        const char *end = strstr(value, "</Key>");
        int index;

        if (end == NULL) {
            brix_http_resp_free(&response);
            return 0;
        }
        index = key_index(objects, value, (size_t) (end - value));
        if (index < 0 || (seen & (1U << (unsigned) index)) != 0) {
            brix_http_resp_free(&response);
            return 0;
        }
        seen |= 1U << (unsigned) index;
        found++;
        cursor = end + strlen("</Key>");
    }
    brix_http_resp_free(&response);
    return found == 4 && seen == 0x0fU;
}

static void
delete_special(xrd_conform_execution *execution, brix_weburl objects[4],
    size_t created)
{
    while (created > 0) {
        brix_http_resp response;
        brix_status status;

        created--;
        memset(&response, 0, sizeof(response));
        brix_status_clear(&status);
        if (xrd_conform_http_request_fields(execution, &objects[created],
                "DELETE", NULL, NULL, 0, &response, &status) == 0)
            brix_http_resp_free(&response);
    }
}

void
xrd_conform_probe_s3_special_keys(xrd_conform_execution *execution,
    const brix_weburl *url)
{
    brix_weburl objects[4];
    char prefix[XRDC_PATH_MAX];
    size_t created = 0;
    int pass;

    if (!url->is_s3 || !row_active(execution, "S3-014")) return;
    if (special_paths(execution, url, objects, prefix) != 0
        || put_special(execution, objects, &created) != 0) {
        delete_special(execution, objects, created);
        xrd_conform_result_set(execution, "S3-014",
            BRIX_CONFORM_VERDICT_SKIPPED,
            "fixture-absent:mutable-path-style-s3-scratch", NULL, NULL);
        return;
    }
    pass = get_special(execution, objects)
        && list_has_special(execution, url, objects, prefix);
    xrd_conform_result_set(execution, "S3-014",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "s3-special-keys-list-and-get-roundtrip"
             : "s3-special-key-roundtrip-mismatch",
        "+, %, space and UTF-8 keys list and get unchanged", NULL);
    delete_special(execution, objects, created);
}
