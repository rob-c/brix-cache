/* Phase-118 DAV-008 outside-export mutation boundary probe. */
#include "xrd_conform_internal.h"

typedef struct {
    int    status;
    size_t length;
    char   digest[65];
} dav_observation;

static int row_active(xrd_conform_execution *execution)
{
    const brix_conform_result *row = xrd_conform_result_find(execution,
        "DAV-008");

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

static int observe_resource(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    dav_observation *observation)
{
    brix_http_resp response;
    brix_status status;
    int rc;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "GET", token, NULL,
        4096, &response, &status);
    if (rc != 0) return -1;
    observation->status = response.status;
    observation->length = response.body_len;
    brix_s3_sha256_hex(response.body, response.body_len,
        observation->digest);
    brix_http_resp_free(&response);
    return 0;
}

static int observation_equal(const dav_observation *left,
    const dav_observation *right)
{
    return left->status == right->status && left->length == right->length
        && strcmp(left->digest, right->digest) == 0;
}

static int source_unchanged(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token, const char *expected)
{
    brix_http_resp response;
    brix_status status;
    size_t length = strlen(expected);
    int pass;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    if (xrd_conform_http_request_fields(execution, url, "GET", token, NULL,
            length, &response, &status) != 0) return 0;
    pass = response.status >= 200 && response.status < 300
        && response.body_len == length
        && memcmp(response.body, expected, length) == 0;
    brix_http_resp_free(&response);
    return pass;
}

static int outside_fixture_valid(xrd_conform_execution *execution,
    const brix_weburl *base, brix_weburl *outside)
{
    const char *scratch = execution->run->config.scratch;
    size_t scratch_length;

    if (execution->run->webdav_outside_target == NULL
        || brix_weburl_parse(execution->run->webdav_outside_target,
            outside) != 0 || outside->is_s3 || outside->tls != base->tls
        || outside->port != base->port
        || strcmp(outside->host, base->host) != 0 || scratch == NULL)
        return 0;
    scratch_length = strlen(scratch);
    return !(strncmp(outside->path, scratch, scratch_length) == 0
        && (outside->path[scratch_length] == '\0'
            || outside->path[scratch_length] == '/'));
}

/* WHAT: Refuse COPY and MOVE to an explicitly authorized outside-export URL.
 * WHY: A scratch-only destination cannot establish the export boundary.
 * HOW: Snapshot the sacrificial URL, plant two scratch sources, require both
 * mutations to fail, verify both sources and the unchanged destination. */
void xrd_conform_probe_webdav_outside(xrd_conform_execution *execution,
    const brix_weburl *base, const char *token)
{
    brix_weburl outside;
    brix_weburl copy_source;
    brix_weburl move_source;
    dav_observation before;
    dav_observation after;
    char fields[768];
    int copy_status = 0;
    int move_status = 0;
    int pass;

    if (!row_active(execution)) return;
    if (!outside_fixture_valid(execution, base, &outside)) {
        xrd_conform_result_set(execution, "DAV-008",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:outside-export-destination", NULL, NULL);
        return;
    }
    if (xrd_conform_webdav_scratch_url(execution, base,
            "brix-conform-dav-copy-outside", &copy_source) != 0
        || xrd_conform_webdav_scratch_url(execution, base,
            "brix-conform-dav-move-outside", &move_source) != 0
        || xrd_conform_webdav_destination_fields(&outside, fields,
            sizeof(fields)) != 0
        || observe_resource(execution, &outside, token, &before) != 0
        || before.status != 404
        || xrd_conform_webdav_put_fixture(execution, &copy_source, token,
            "copy-source") != 0
        || xrd_conform_webdav_put_fixture(execution, &move_source, token,
            "move-source") != 0) {
        xrd_conform_result_set(execution, "DAV-008",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-setup:outside-export-destination", NULL, NULL);
        return;
    }
    pass = xrd_conform_webdav_mutation(execution, &copy_source, "COPY",
            token, fields, &copy_status) == 0
        && copy_status >= 400 && copy_status < 500
        && xrd_conform_webdav_mutation(execution, &move_source, "MOVE",
            token, fields, &move_status) == 0
        && move_status >= 400 && move_status < 500
        && source_unchanged(execution, &copy_source, token, "copy-source")
        && source_unchanged(execution, &move_source, token, "move-source")
        && observe_resource(execution, &outside, token, &after) == 0
        && observation_equal(&before, &after);
    xrd_conform_result_set(execution, "DAV-008",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "outside-export-copy-move-refused"
             : "outside-export-destination-accepted-or-mutated",
        NULL, pass ? "COPY/MOVE refused; sources and destination unchanged"
                   : "outside-export contract changed");
    xrd_conform_webdav_cleanup(execution, &copy_source, token);
    xrd_conform_webdav_cleanup(execution, &move_source, token);
    if ((copy_status >= 200 && copy_status < 300)
        || (move_status >= 200 && move_status < 300))
        xrd_conform_webdav_cleanup(execution, &outside, token);
}
