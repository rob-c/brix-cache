/* Phase-118 bounded WebDAV multistatus-to-resource comparison. */
#include "xrd_conform_internal.h"

#define DAV_RESOURCE_MAX 16U

typedef struct {
    char href[XRDC_PATH_MAX];
    int  status;
} dav_resource;

static int
row_active(xrd_conform_execution *execution)
{
    const brix_conform_result *row = xrd_conform_result_find(execution,
        "DAV-009");

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

/* Match an XML tag by local name while accepting arbitrary namespace prefixes. */
static int
local_name(const char *cursor, const char *limit, const char *name, int closing)
{
    const char *end;
    const char *colon;
    const char *local;
    size_t length = strlen(name);

    if (cursor >= limit || *cursor++ != '<') return 0;
    if (cursor < limit && (*cursor == '/') != closing) return 0;
    if (closing) cursor++;
    end = cursor;
    while (end < limit && *end != '>' && *end != ' ' && *end != '\t'
        && *end != '\r' && *end != '\n') end++;
    colon = memchr(cursor, ':', (size_t) (end - cursor));
    local = colon == NULL ? cursor : colon + 1;
    return (size_t) (end - local) == length
        && strncasecmp(local, name, length) == 0;
}

static const char *
find_tag(const char *cursor, const char *limit, const char *name, int closing)
{
    while (cursor < limit && (cursor = memchr(cursor, '<',
            (size_t) (limit - cursor))) != NULL) {
        if (local_name(cursor, limit, name, closing)) return cursor;
        cursor++;
    }
    return NULL;
}

static int
element_text(const char *start, const char *limit, const char *name,
    char *out, size_t capacity)
{
    const char *open = find_tag(start, limit, name, 0);
    const char *text;
    const char *close;
    size_t length;

    if (open == NULL || (text = memchr(open, '>',
            (size_t) (limit - open))) == NULL) return -1;
    text++;
    close = find_tag(text, limit, name, 1);
    if (close == NULL) return -1;
    length = (size_t) (close - text);
    if (length == 0 || length >= capacity) return -1;
    memcpy(out, text, length);
    out[length] = '\0';
    return 0;
}

static int
status_code(const char *text)
{
    const char *space = strchr(text, ' ');

    if (space == NULL || strlen(space + 1) < 3
        || space[1] < '2' || space[1] > '5'
        || space[2] < '0' || space[2] > '9'
        || space[3] < '0' || space[3] > '9') return 0;
    return (space[1] - '0') * 100 + (space[2] - '0') * 10
        + space[3] - '0';
}

static int
parse_resources(const char *body, size_t body_length, dav_resource resources[],
    size_t *count)
{
    const char *cursor = body;
    const char *limit = body + body_length;

    *count = 0;
    while ((cursor = find_tag(cursor, limit, "response", 0)) != NULL) {
        const char *close = find_tag(cursor + 1, limit, "response", 1);
        char status[64];
        size_t index;

        if (close == NULL || *count >= DAV_RESOURCE_MAX
            || element_text(cursor, close, "href", resources[*count].href,
                sizeof(resources[*count].href)) != 0
            || element_text(cursor, close, "status", status,
                sizeof(status)) != 0
            || (resources[*count].status = status_code(status)) == 0)
            return -1;
        for (index = 0; index < *count; index++)
            if (strcmp(resources[index].href, resources[*count].href) == 0)
                return -1;
        (*count)++;
        cursor = close + 1;
    }
    return *count == 0 ? -1 : 0;
}

static int
propfind(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, const char *depth, brix_http_resp *response)
{
    static const char body[] =
        "<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><allprop/>"
        "</propfind>";
    char fields[96];
    brix_status status;

    snprintf(fields, sizeof(fields),
        "Depth: %s\r\nContent-Type: application/xml\r\n", depth);
    memset(response, 0, sizeof(*response));
    brix_status_clear(&status);
    return xrd_conform_http_request_body(execution, url, "PROPFIND", token,
        fields, body, sizeof(body) - 1, 65536, response, &status);
}

static int
resource_status(xrd_conform_execution *execution, const brix_weburl *base,
    const char *token, const char *href, int *status)
{
    brix_weburl resource = *base;
    brix_http_resp response;
    dav_resource parsed[DAV_RESOURCE_MAX];
    size_t count = 0;
    int rc;

    if (href[0] != '/' || strlen(href) >= sizeof(resource.path)) return -1;
    snprintf(resource.path, sizeof(resource.path), "%s", href);
    rc = propfind(execution, &resource, token, "0", &response);
    if (rc == 0 && response.status == 207
        && parse_resources(response.body, response.body_len, parsed, &count) == 0
        && count == 1 && strcmp(parsed[0].href, href) == 0)
        *status = parsed[0].status;
    else rc = -1;
    if (response.body != NULL) brix_http_resp_free(&response);
    return rc;
}

void
xrd_conform_probe_webdav_multistatus(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    brix_weburl collection = *url;
    brix_http_resp response;
    dav_resource resources[DAV_RESOURCE_MAX];
    size_t count = 0;
    size_t matched = 0;
    size_t index;
    char received[80];
    char *slash;
    int rc;

    if (!row_active(execution)) return;
    slash = strrchr(collection.path, '/');
    if (slash == NULL) return;
    slash[slash == collection.path ? 1 : 0] = '\0';
    rc = propfind(execution, &collection, token, "1", &response);
    if (rc == 0 && response.status == 207
        && parse_resources(response.body, response.body_len, resources,
            &count) == 0) {
        for (index = 0; index < count; index++) {
            int observed = 0;

            if (resource_status(execution, url, token, resources[index].href,
                    &observed) == 0 && observed == resources[index].status)
                matched++;
        }
    }
    snprintf(received, sizeof(received), "resources=%zu matched=%zu", count,
        matched);
    xrd_conform_result_set(execution, "DAV-009",
        count != 0 && matched == count ? BRIX_CONFORM_VERDICT_CONFORMANT
                                       : BRIX_CONFORM_VERDICT_DIVERGENT,
        count != 0 && matched == count
            ? "multistatus-matches-single-resource-answers"
            : "multistatus-malformed-duplicate-or-mismatched",
        "unique bounded href set with matching Depth-0 statuses", received);
    if (rc == 0) brix_http_resp_free(&response);
}
