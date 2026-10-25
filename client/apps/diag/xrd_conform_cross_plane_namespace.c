/* Phase-118 bounded cross-plane namespace-set comparison. */
#include "xrd_conform_probe_helpers.h"
#include "core/compat/uri.h"

#define XPR_NAMESPACE_MAX 65

typedef struct {
    char names[XPR_NAMESPACE_MAX][XRDC_NAME_MAX];
    size_t count;
} namespace_names;


static int
namespace_row_active(xrd_conform_execution *execution)
{
    return xrd_conform_row_active(execution, "XPR-004")
        || xrd_conform_row_active(execution, "DAV-002");
}

static int
split_parent(const char *path, char parent[XRDC_PATH_MAX], char self[XRDC_NAME_MAX])
{
    const char *slash = strrchr(path, '/');
    size_t parent_length;
    size_t self_length;

    if (slash == NULL || slash[1] == '\0') return -1;
    parent_length = slash == path ? 1U : (size_t) (slash - path);
    self_length = strlen(slash + 1);
    if (parent_length >= XRDC_PATH_MAX || self_length >= XRDC_NAME_MAX)
        return -1;
    memcpy(parent, path, parent_length);
    parent[parent_length] = '\0';
    memcpy(self, slash + 1, self_length + 1);
    return 0;
}

static int
add_name(namespace_names *set, const char *name, size_t length)
{
    size_t index;

    if (length == 0 || length >= XRDC_NAME_MAX
        || set->count >= XPR_NAMESPACE_MAX) return -1;
    for (index = 0; index < length; index++)
        if (name[index] == '\0' || name[index] == '/' || name[index] == '&')
            return -1;
    memcpy(set->names[set->count], name, length);
    set->names[set->count][length] = '\0';
    set->count++;
    return 0;
}

static int
compare_name(const void *left, const void *right)
{
    return strcmp((const char *) left, (const char *) right);
}

/* WHAT: Hash a sorted, length-unambiguous direct-child set.
 * WHY: Execution state stays bounded while comparison remains byte-exact.
 * HOW: Sort fixed-width names, reject duplicates, serialize each with its NUL. */
static int
namespace_digest(namespace_names *set, char digest[65])
{
    unsigned char *serialized;
    size_t length = 0;
    size_t offset = 0;
    size_t index;

    if (set->count > 64) return -1;
    qsort(set->names, set->count, XRDC_NAME_MAX, compare_name);
    for (index = 0; index < set->count; index++) {
        if (index > 0 && strcmp(set->names[index - 1], set->names[index]) == 0)
            return -1;
        length += strlen(set->names[index]) + 1;
    }
    serialized = malloc(length == 0 ? 1 : length);
    if (serialized == NULL) return -1;
    for (index = 0; index < set->count; index++) {
        size_t name_length = strlen(set->names[index]) + 1;

        memcpy(serialized + offset, set->names[index], name_length);
        offset += name_length;
    }
    brix_s3_sha256_hex(serialized, length, digest);
    free(serialized);
    return 0;
}

void
xrd_conform_probe_root_namespace(xrd_conform_execution *execution,
    brix_conn *connection, const char *path)
{
    namespace_names set = { { { 0 } }, 0 };
    brix_dirent *entries = NULL;
    brix_status status;
    char parent[XRDC_PATH_MAX];
    char self[XRDC_NAME_MAX];
    char reason[64];
    size_t count = 0;
    size_t index;

    if (!namespace_row_active(execution) || split_parent(path, parent, self) != 0
        || !xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    brix_status_clear(&status);
    if (brix_dirlist(connection, parent, 0, &entries, &count, &status) != 0)
        return;
    for (index = 0; index < count; index++)
        if (add_name(&set, entries[index].name,
                strlen(entries[index].name)) != 0) break;
    if (index == count
        && namespace_digest(&set, execution->root_namespace) == 0)
        execution->root_namespace_state = 1;
    free(entries);
}

static int
webdav_names(const brix_http_resp *response, const char *self,
    namespace_names *set, brix_status *status)
{
    brix_dirent *entries = NULL;
    size_t count = 0;
    size_t index;

    if (response->status != 207 || response->body == NULL
        || strstr(response->body, "response") == NULL
        || brix_webdav_parse_dirents(response->body, response->body_len, self,
            &entries, &count, status) != 0) return -1;
    for (index = 0; index < count; index++)
        if (add_name(set, entries[index].name,
                strlen(entries[index].name)) != 0) break;
    free(entries);
    return index == count ? 0 : -1;
}

static int
xml_names(const char *body, const char *open, const char *close,
    const char *prefix, int collection, namespace_names *set)
{
    const char *cursor = body;
    size_t prefix_length = strlen(prefix);

    while ((cursor = strstr(cursor, open)) != NULL) {
        const char *start = cursor + strlen(open);
        const char *end = strstr(start, close);
        size_t length;

        if (end == NULL || strncmp(start, prefix, prefix_length) != 0)
            return -1;
        start += prefix_length;
        length = (size_t) (end - start);
        if (collection && length > 0 && start[length - 1] == '/') length--;
        if (add_name(set, start, length) != 0) return -1;
        cursor = end + strlen(close);
    }
    return 0;
}

static int
s3_list_url(const brix_weburl *url, brix_weburl *listing,
    char prefix[XRDC_PATH_MAX])
{
    const char *bucket_end = strchr(url->path + 1, '/');
    const char *key;
    const char *slash;
    char encoded[XRDC_PATH_MAX * 3];
    size_t bucket_length;
    size_t prefix_length;

    if (url->path[0] != '/' || bucket_end == NULL) return -1;
    key = bucket_end + 1;
    slash = strrchr(key, '/');
    prefix_length = slash == NULL ? 0 : (size_t) (slash - key + 1);
    if (prefix_length >= XRDC_PATH_MAX) return -1;
    memcpy(prefix, key, prefix_length);
    prefix[prefix_length] = '\0';
    if (brix_http_urlencode((const unsigned char *) prefix, prefix_length,
            encoded, sizeof(encoded), "") < 0) return -1;
    bucket_length = (size_t) (bucket_end - url->path);
    *listing = *url;
    return (size_t) snprintf(listing->path, sizeof(listing->path),
        "%.*s?delimiter=%%2F&list-type=2&max-keys=65%s%s",
        (int) bucket_length, url->path, prefix_length == 0 ? "" : "&prefix=",
        encoded) < sizeof(listing->path) ? 0 : -1;
}

static int
s3_names(const brix_http_resp *response, const char *prefix,
    namespace_names *set)
{
    if (response->status != 200 || response->body == NULL
        || strstr(response->body, "<ListBucketResult") == NULL
        || strstr(response->body, "<IsTruncated>false</IsTruncated>") == NULL)
        return -1;
    return xml_names(response->body, "<Key>", "</Key>", prefix, 0, set) == 0
        && xml_names(response->body, "<Prefix>", "</Prefix>", prefix, 1,
            set) == 0 ? 0 : -1;
}

void
xrd_conform_probe_web_namespace(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    namespace_names set = { { { 0 } }, 0 };
    brix_weburl listing;
    brix_http_resp response;
    brix_status status;
    char parent[XRDC_PATH_MAX];
    char target[XRDC_NAME_MAX];
    char self[XRDC_NAME_MAX] = "";
    char prefix[XRDC_PATH_MAX] = "";
    int *state;
    char *digest;
    int rc;

    if (!namespace_row_active(execution)) return;
    if (url->is_s3) {
        rc = s3_list_url(url, &listing, prefix);
    } else {
        const char *slash;

        rc = split_parent(url->path, parent, target);
        listing = *url;
        slash = strrchr(parent, '/');
        if (slash != NULL) {
            snprintf(self, sizeof(self), "%s", slash + 1);
        } else {
            size_t parent_length = strlen(parent);

            if (parent_length >= sizeof(self)) return;
            memcpy(self, parent, parent_length + 1);
        }
    }
    if (rc != 0) return;
    if (!url->is_s3) snprintf(listing.path, sizeof(listing.path), "%s", parent);
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, &listing,
        url->is_s3 ? "GET" : "PROPFIND", token,
        url->is_s3 ? NULL : "Depth: 1\r\n", 65536, &response, &status);
    if (rc != 0) return;
    rc = url->is_s3 ? s3_names(&response, prefix, &set)
                    : webdav_names(&response, self, &set, &status);
    state = url->is_s3 ? &execution->s3_namespace_state
                       : &execution->http_namespace_state;
    digest = url->is_s3 ? execution->s3_namespace
                        : execution->http_namespace;
    if (rc == 0 && namespace_digest(&set, digest) == 0) *state = 1;
    brix_http_resp_free(&response);
}

void
xrd_conform_finalize_namespace(xrd_conform_execution *execution)
{
    const char *digests[] = { execution->root_namespace,
        execution->http_namespace, execution->s3_namespace };
    const int states[] = { execution->root_namespace_state,
        execution->http_namespace_state, execution->s3_namespace_state };
    const char *expected = NULL;
    size_t index;
    int observations = 0;
    int agreement = 1;

    if (xrd_conform_row_active(execution, "DAV-002")) {
        if (execution->root_namespace_state
            && execution->http_namespace_state) {
            int dav_agreement = strcmp(execution->root_namespace,
                execution->http_namespace) == 0;

            xrd_conform_result_set(execution, "DAV-002",
                dav_agreement ? BRIX_CONFORM_VERDICT_CONFORMANT
                              : BRIX_CONFORM_VERDICT_DIVERGENT,
                dav_agreement ? "webdav-root-direct-child-sets-agree"
                              : "webdav-root-direct-child-set-mismatch",
                "bounded duplicate-free direct-child name sets agree", NULL);
        } else {
            xrd_conform_result_set(execution, "DAV-002",
                BRIX_CONFORM_VERDICT_INCONCLUSIVE,
                "fixture-required:paired-root-directory", NULL, NULL);
        }
    }
    if (!xrd_conform_row_active(execution, "XPR-004")) return;

    for (index = 0; index < 3; index++) {
        if (states[index] == 0) continue;
        if (expected == NULL) expected = digests[index];
        else if (strcmp(expected, digests[index]) != 0) agreement = 0;
        observations++;
    }
    if (observations < 2) return;
    xrd_conform_result_set(execution, "XPR-004",
        agreement ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
        agreement ? "cross-plane-namespace-set-agreement"
                  : "cross-plane-namespace-set-mismatch",
        "bounded direct-child name sets agree on every observed plane", NULL);
}
