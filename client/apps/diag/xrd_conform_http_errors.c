/* Phase-118 HTTP error mapping and request-confusion probes. */
#include "xrd_conform_probe_helpers.h"
#include "core/compat/host_format.h"



/* WHAT: Clone a parsed URL with one exact request-target string.
 * WHY: Host and TLS policy must stay constant across target-form comparisons.
 * HOW: Copy the value object and bounds-check the replacement path. */
static int
with_path(const brix_weburl *source, const char *path, brix_weburl *out)
{
    *out = *source;
    return (size_t) snprintf(out->path, sizeof(out->path), "%s", path)
        < sizeof(out->path) ? 0 : -1;
}

/* WHAT: Return whether an error body contains high-risk disclosure markers.
 * WHY: Filesystem paths and credentials must never be reflected to a client.
 * HOW: Scan the bounded decoded body and the discovered bearer value. */
static int
error_body_safe(const brix_http_resp *response, const char *token)
{
    static const char *const markers[] = {
        "/etc/", "/var/", "/home/", "/Users/", "BEGIN PRIVATE KEY",
        "Authorization:", "Bearer ", "AWS_SECRET_ACCESS_KEY"
    };
    size_t index;

    if (response->body == NULL) return 1;
    for (index = 0; index < sizeof(markers) / sizeof(markers[0]); index++)
        if (strcasestr(response->body, markers[index]) != NULL) return 0;
    return token == NULL || token[0] == '\0'
        || strstr(response->body, token) == NULL;
}

/* WHAT: Fetch a guaranteed-nonbaseline sibling and inspect its error response.
 * WHY: HTE-002 needs a live failure body rather than source-level assurances.
 * HOW: Append a fixed suffix, require 404 and scan bounded returned bytes. */
static void
probe_missing_error(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token)
{
    brix_weburl missing;
    brix_http_resp response;
    brix_status status;
    char path[XRDC_PATH_MAX];
    int rc;
    int pass;

    if (!xrd_conform_row_active(execution, "HTE-002")) return;
    if ((size_t) snprintf(path, sizeof(path), "%s.brix-conform-missing",
            url->path) >= sizeof(path) || with_path(url, path, &missing) != 0) {
        xrd_conform_result_set(execution, "HTE-002",
            BRIX_CONFORM_VERDICT_SKIPPED, "fixture-path-too-long", NULL, NULL);
        return;
    }
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, &missing, "GET", token,
        NULL, 4096, &response, &status);
    pass = rc == 0 && response.status == 404
        && error_body_safe(&response, token);
    xrd_conform_grade_received(execution, "HTE-002", pass, "error-body-disclosure-scan-clean",
        "error-body-leaked-sensitive-material",
        rc == 0 ? response.reason : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

/* WHAT: Send a percent-encoded CRLF request target.
 * WHY: Decoding it into headers would permit response splitting or injection.
 * HOW: Require a client-error status and absence of the injected header. */
static void
probe_path_injection(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    brix_weburl hostile;
    brix_http_resp response;
    brix_status status;
    char path[XRDC_PATH_MAX];
    char injected[32];
    int rc;
    int pass;

    if (!xrd_conform_row_active(execution, "HTE-004")) return;
    if ((size_t) snprintf(path, sizeof(path), "%s%%0d%%0aX-Brix:injected",
            url->path) >= sizeof(path) || with_path(url, path, &hostile) != 0) {
        xrd_conform_result_set(execution, "HTE-004",
            BRIX_CONFORM_VERDICT_SKIPPED, "fixture-path-too-long", NULL, NULL);
        return;
    }
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, &hostile, "GET", token,
        NULL, 4096, &response, &status);
    pass = rc == 0 && response.status >= 400 && response.status < 500
        && !brix_http_header(&response, "X-Brix", injected, sizeof(injected))
        && (response.body == NULL
            || strstr(response.body, "HTTP/1.1 ") == NULL);
    xrd_conform_grade_received(execution, "HTE-004", pass, "encoded-crlf-rejected",
        "encoded-crlf-was-reflected-or-served",
        rc == 0 ? response.reason : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

/* WHAT: Submit both ambiguous HTTP request-framing shapes.
 * WHY: Accepting either enables front-end/back-end request smuggling.
 * HOW: Send duplicate Content-Length and CL+TE, accepting 400 or hard close. */
static int
ambiguous_request_rejected(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token, const char *fields)
{
    brix_http_resp response;
    brix_status status;
    int rc;
    int rejected;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "PUT", token,
        fields, 4096, &response, &status);
    rejected = rc != 0 || response.status == 400;
    if (rc == 0) brix_http_resp_free(&response);
    return rejected;
}

/* WHAT: Exercise duplicate-length and conflicting-transfer request framing.
 * WHY: Both RFC-9112 ambiguity forms must fail closed.
 * HOW: Require rejection independently, then combine the result. */
static void
probe_request_smuggling(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    int duplicate;
    int conflict;

    if (!xrd_conform_row_active(execution, "HTE-006")) return;
    duplicate = ambiguous_request_rejected(execution, url, token,
        "Content-Length: 1\r\nContent-Length: 2\r\n");
    conflict = ambiguous_request_rejected(execution, url, token,
        "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n");
    xrd_conform_grade_received(execution, "HTE-006", duplicate && conflict,
        "ambiguous-request-framing-rejected",
        "ambiguous-request-framing-accepted", NULL);
}

/* WHAT: Compare absolute-form GET bytes to the origin-form baseline.
 * WHY: Proxies and direct clients may legally use either request-target form.
 * HOW: Construct an exact same-authority URL and compare status and body. */
static void
probe_absolute_form(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, const brix_http_resp *baseline)
{
    brix_weburl absolute;
    brix_http_resp response;
    brix_status status;
    char authority[300];
    char target[XRDC_PATH_MAX];
    int rc;
    int pass;

    if (!xrd_conform_row_active(execution, "HTE-007")) return;
    brix_format_host_port(url->host, (uint16_t) url->port, authority,
        sizeof(authority));
    if ((size_t) snprintf(target, sizeof(target), "%s://%s%s",
            url->tls ? "https" : "http", authority, url->path)
            >= sizeof(target) || with_path(url, target, &absolute) != 0) {
        xrd_conform_result_set(execution, "HTE-007",
            BRIX_CONFORM_VERDICT_SKIPPED, "absolute-form-target-too-long",
            NULL, NULL);
        return;
    }
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, &absolute, "GET", token,
        NULL, baseline->body_len, &response, &status);
    pass = rc == 0 && response.status == 200
        && response.body_len == baseline->body_len
        && memcmp(response.body, baseline->body, baseline->body_len) == 0;
    xrd_conform_grade_received(execution, "HTE-007", pass, "absolute-and-origin-form-identical",
        "absolute-form-diverged", rc == 0 ? response.reason : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

/* WHAT: Compare literal and encoded parent traversal outcomes.
 * WHY: Alternate decoding must not turn one spelling into an export escape.
 * HOW: Request sibling paths using both forms and require identical rejection. */
static void
probe_traversal(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token)
{
    const char *const suffixes[] = { "/../brix-conform-outside",
                                     "/%2e%2e%2fbrix-conform-outside" };
    int statuses[2] = { 0, 0 };
    size_t index;

    if (!xrd_conform_row_active(execution, "HTE-008")) return;
    for (index = 0; index < 2; index++) {
        brix_weburl hostile;
        brix_http_resp response;
        brix_status status;

        if (with_path(url, suffixes[index], &hostile) != 0) return;
        memset(&response, 0, sizeof(response));
        brix_status_clear(&status);
        if (xrd_conform_http_request_fields(execution, &hostile, "GET", token,
                NULL, 4096, &response, &status) == 0) {
            statuses[index] = response.status;
            brix_http_resp_free(&response);
        }
    }
    xrd_conform_grade_received(execution, "HTE-008", statuses[0] >= 400 && statuses[0] < 500
        && statuses[0] == statuses[1], "traversal-encodings-equally-rejected",
        "traversal-encoding-policy-diverged", NULL);
}

/* WHAT: Send request lines exactly at and one byte above the configured cap.
 * WHY: HTE-005 cannot infer a deployment-specific parser limit honestly.
 * HOW: Frame bounded raw GETs and require an explicit 414 for both lengths. */
static void
probe_request_line_limit(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    unsigned limit = execution->run->http_request_line_limit;
    unsigned delta;
    int pass = 1;

    if (!xrd_conform_row_active(execution, "HTE-005")) return;
    if (limit == 0) {
        xrd_conform_result_set(execution, "HTE-005",
            BRIX_CONFORM_VERDICT_SKIPPED,
            "fixture-required:request-line-limit-boundary", NULL, NULL);
        return;
    }
    for (delta = 0; delta < 2; delta++) {
        size_t target_length = (size_t) limit + delta - 15U;
        char *target = malloc(target_length + 1U);
        xrd_conform_raw_http request;
        brix_http_resp response;
        brix_status status;
        int rc;

        if (target == NULL) {
            pass = 0;
            continue;
        }
        target[0] = '/';
        memset(target + 1, 'a', target_length - 1U);
        target[target_length] = '\0';
        memset(&request, 0, sizeof(request));
        request.method = "GET";
        request.target = target;
        request.expected_bytes = 4096;
        memset(&response, 0, sizeof(response));
        brix_status_clear(&status);
        rc = xrd_conform_http_raw_request(execution, url, token, &request,
            &response, &status);
        pass = pass && rc == 0 && response.status == 414;
        if (rc == 0) brix_http_resp_free(&response);
        free(target);
    }
    xrd_conform_grade_received(execution, "HTE-005", pass, "request-line-boundary-rejected",
        "request-line-boundary-not-414", "HTTP 414 at limit and limit+1");
}

/* WHAT: Run every currently self-contained HTTP error probe.
 * WHY: HTE rows must be explicit even when composite fault fixtures are absent.
 * HOW: Execute safe reads, then mark the two external-fixture matrices. */
void
xrd_conform_probe_http_errors(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *baseline)
{
    if (!xrd_conform_family_active(execution, "HTE")) return;
    probe_missing_error(execution, url, token);
    probe_path_injection(execution, url, token);
    probe_request_smuggling(execution, url, token);
    probe_absolute_form(execution, url, token, baseline);
    probe_traversal(execution, url, token);
    probe_request_line_limit(execution, url, token);
    xrd_conform_result_set(execution, "HTE-001",
        BRIX_CONFORM_VERDICT_SKIPPED,
        "fixture-required:complete-http-errno-matrix", NULL, NULL);
}
