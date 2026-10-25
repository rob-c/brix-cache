/* Phase-118 scratch-confined HTTP creation probes. */
#include "xrd_conform_probe_helpers.h"


/* WHAT: Construct one URL beneath the authorized scratch prefix.
 * WHY: A create probe must never overwrite the adopted baseline object.
 * HOW: Use the common prefix-bound builder and copy its checked result. */
static int
scratch_url(xrd_conform_execution *execution, const brix_weburl *base,
    const char *leaf, brix_weburl *scratch)
{
    char path[XRDC_PATH_MAX];

    if (brix_conform_scratch_path(execution->run->config.scratch, leaf,
            path, sizeof(path)) != 0) return -1;
    *scratch = *base;
    return (size_t) snprintf(scratch->path, sizeof(scratch->path), "%s", path)
        < sizeof(scratch->path) ? 0 : -1;
}

/* WHAT: Remove one scratch object after an HTTP create probe.
 * WHY: Assessment must not leave remotely visible mutable artifacts.
 * HOW: Issue bounded DELETE and release any returned response storage. */
static void
cleanup(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token)
{
    brix_http_resp response;
    brix_status status;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    if (xrd_conform_http_request_fields(execution, url, "DELETE", token,
            NULL, 0, &response, &status) == 0)
        brix_http_resp_free(&response);
}

/* WHAT: Prove a zero-length PUT creates a visible zero-length object.
 * WHY: Empty payloads must remain valid data rather than becoming no-ops.
 * HOW: PUT under scratch, GET it with a one-byte ceiling, then DELETE it. */
static void
probe_zero_put(xrd_conform_execution *execution, const brix_weburl *base,
    const char *token)
{
    brix_weburl scratch;
    brix_http_resp put_response;
    brix_http_resp get_response;
    brix_status status;
    int put_rc;
    int get_rc = -1;
    int pass;

    if (!xrd_conform_row_active(execution, "HTC-003")) return;
    if (scratch_url(execution, base, "brix-conform-http-zero", &scratch) != 0) {
        xrd_conform_result_set(execution, "HTC-003",
            BRIX_CONFORM_VERDICT_SKIPPED,
            "fixture-absent:mutable-http-scratch", NULL, NULL);
        return;
    }
    memset(&put_response, 0, sizeof(put_response));
    memset(&get_response, 0, sizeof(get_response));
    brix_status_clear(&status);
    put_rc = xrd_conform_http_request_body(execution, &scratch, "PUT", token,
        NULL, NULL, 0, 0, &put_response, &status);
    if (put_rc == 0) brix_http_resp_free(&put_response);
    if (put_rc == 0)
        get_rc = xrd_conform_http_request_fields(execution, &scratch, "GET",
            token, NULL, 1, &get_response, &status);
    pass = put_rc == 0 && get_rc == 0
        && get_response.status >= 200 && get_response.status < 300
        && get_response.body_len == 0;
    xrd_conform_result_set(execution, "HTC-003",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "zero-length-put-created-empty-object"
             : "zero-length-put-object-missing-or-nonempty",
        "successful GET with zero response bytes", status.msg);
    if (get_rc == 0) brix_http_resp_free(&get_response);
    cleanup(execution, &scratch, token);
}

/* WHAT: Return whether one scratch path remained absent after a bad PUT.
 * WHY: Rejecting malformed framing is insufficient if partial bytes committed.
 * HOW: GET with a small ceiling and require an explicit 404 response. */
static int
object_absent(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token)
{
    brix_http_resp response;
    brix_status status;
    int rc;
    int absent;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "GET", token,
        NULL, 64, &response, &status);
    absent = rc == 0 && response.status == 404;
    if (rc == 0) brix_http_resp_free(&response);
    return absent;
}

/* WHAT: Send one intentionally malformed PUT and prove no object committed.
 * WHY: Request-framing failures must be atomic from the client's perspective.
 * HOW: Use exact raw bytes under scratch, close the request side, then GET. */
static void
probe_malformed_put(xrd_conform_execution *execution,
    const brix_weburl *base, const char *token, const char *id,
    const char *leaf, const char *fields, const char *body)
{
    brix_weburl scratch;
    brix_http_resp response;
    brix_status status;
    xrd_conform_raw_http request;
    int rc;
    int pass;

    if (!xrd_conform_row_active(execution, id)) return;
    if (scratch_url(execution, base, leaf, &scratch) != 0) {
        xrd_conform_result_set(execution, id, BRIX_CONFORM_VERDICT_SKIPPED,
            "fixture-absent:mutable-http-scratch", NULL, NULL);
        return;
    }
    memset(&request, 0, sizeof(request));
    request.method = "PUT";
    request.target = scratch.path;
    request.fields = fields;
    request.body = body;
    request.body_length = strlen(body);
    request.expected_bytes = 4096;
    request.finish_write = 1;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_raw_request(execution, &scratch, token, &request,
        &response, &status);
    if (rc == 0) brix_http_resp_free(&response);
    pass = object_absent(execution, &scratch, token);
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "malformed-put-left-no-object"
             : "malformed-put-committed-partial-object",
        "scratch path remains absent", rc == 0 ? "rejected" : status.msg);
    cleanup(execution, &scratch, token);
}

/* WHAT: Run authorized HTTP create probes and classify missing paired fixtures.
 * WHY: Cross-plane and truncated-wire assertions need capabilities not implied
 *      by a single adopted HTTP target.
 * HOW: Execute the safe zero PUT and explicitly gate every remaining row. */
void
xrd_conform_probe_http_create(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    static const struct { const char *id; const char *reason; } gated[] = {
        { "HTC-001", "fixture-required:paired-root-http-scratch" },
        { "HTC-002", "fixture-required:paired-readonly-root-http" }
    };
    size_t index;

    if (!xrd_conform_family_active(execution, "HTC") || url->is_s3) return;
    probe_zero_put(execution, url, token);
    probe_malformed_put(execution, url, token, "HTC-004",
        "brix-conform-http-short", "Content-Length: 8\r\n", "abc");
    probe_malformed_put(execution, url, token, "HTC-005",
        "brix-conform-http-chunk", "Transfer-Encoding: chunked\r\n",
        "3\r\nabc\r\n0\r\nX");
    for (index = 0; index < sizeof(gated) / sizeof(gated[0]); index++) {
        if (strcmp(gated[index].id, "HTC-001") == 0
            && execution->run->mutation_fixture_count != 0) continue;
        if (strcmp(gated[index].id, "HTC-002") == 0
            && execution->run->error_fixture_count != 0) continue;
        xrd_conform_result_set(execution, gated[index].id,
            BRIX_CONFORM_VERDICT_SKIPPED, gated[index].reason, NULL, NULL);
    }
}
