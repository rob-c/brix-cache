/*
 * Phase-118 HTTP/WebDAV read-plane probes.
 *
 * WHAT: Grades bounded GET, HEAD and single-range behaviour on an adopted URL.
 * WHY: Cross-plane work needs an independently observed HTTP result vector.
 * HOW: Authenticate through shared discovery, learn one full-body baseline,
 *      then compare RFC-9110 range responses against those exact bytes.
 */
#include "xrd_conform_internal.h"
#include "core/compat/host_format.h"

#define CONFORM_HTTP_PLANTED_SIZE 65536U

/* WHAT: Return whether one web baseline row survived scope selection.
 * WHY: Planting is authorized only when its exact PRF clause will be graded.
 * HOW: Find the row and reject the execution engine's skipped verdict. */
static int
baseline_row_active(xrd_conform_execution *execution, int is_s3)
{
    const char *expected = is_s3 ? "S3-001" : "HTR-001";
    const brix_conform_result *row = xrd_conform_result_find(execution,
        expected);

    return execution->run->config.only != NULL
        && strcmp(execution->run->config.only, expected) == 0
        && row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

/* WHAT: Plant one bounded PRF object below the authorized web scratch prefix.
 * WHY: HTR-001/S3-001 require an independent oracle, not adopted-body echo.
 * HOW: Build the shared scratch URL, fill 64 KiB from the run key, and PUT it. */
static int
plant_http_baseline(xrd_conform_execution *execution,
    const brix_weburl *base, const char *token, brix_weburl *planted)
{
    uint8_t *body;
    brix_http_resp response;
    brix_status status;
    int rc;
    int success;

    if (!execution->run->config.allow_mutate
        || !baseline_row_active(execution, base->is_s3)
        || xrd_conform_webdav_scratch_url(execution, base,
            "brix-conform-http-prf", planted) != 0) return 0;
    body = malloc(CONFORM_HTTP_PLANTED_SIZE);
    if (body == NULL) return -1;
    brix_conform_fill(&execution->run->key, 0, body,
        CONFORM_HTTP_PLANTED_SIZE);
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, planted, "PUT", token,
        NULL, body, CONFORM_HTTP_PLANTED_SIZE, 4096, &response, &status);
    free(body);
    success = rc == 0 && response.status >= 200 && response.status < 300;
    if (rc == 0) brix_http_resp_free(&response);
    return success ? 1 : -1;
}

/* WHAT: Remove the exact PRF object planted by this assessment.
 * WHY: Authorized mutation must leave no persistent assessment artifact.
 * HOW: Send one bounded DELETE and release any returned response storage. */
static int
cleanup_http_baseline(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    brix_http_resp response;
    brix_status status;
    int rc;
    int success;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "DELETE", token,
        NULL, 4096, &response, &status);
    success = rc == 0 && response.status >= 200 && response.status < 300;
    if (rc == 0) brix_http_resp_free(&response);
    return success ? 0 : -1;
}

/* ---- Validate a bearer value before forming an HTTP header ----
 *
 * WHAT: Rejects controls, whitespace and oversized discovered token values.
 * WHY: Credential discovery must never become a request-header injection seam.
 * HOW: Accept visible non-space ASCII only, with a conservative 8 KiB bound.
 */
int
xrd_conform_credential_safe(const char *token)
{
    const unsigned char *cursor = (const unsigned char *) token;
    size_t length = 0;

    if (token == NULL) return 1;
    while (*cursor != '\0') {
        if (*cursor <= 0x20 || *cursor >= 0x7f || ++length > 8192) return 0;
        cursor++;
    }
    return length > 0;
}

/* ---- Build private authenticated request headers ----
 *
 * WHAT: Returns an owned bearer-or-SigV4 header block plus optional Range.
 * WHY: S3 credentials are not bearer tokens and every method has its own SigV4.
 * HOW: Validate discovered values, sign the exact host/path/method, then append
 *      Range outside the signed-header set used by the shared signer.
 */
char *
xrd_conform_http_headers(const brix_weburl *url, const char *method,
    const char *token,
    const char *fields, const char **failure)
{
    char authentication[2048] = "";
    size_t token_len = token == NULL ? 0 : strlen(token);
    size_t fields_len = fields == NULL ? 0 : strlen(fields);
    size_t size;
    char *headers;

    *failure = "invalid bearer credential";
    if (!xrd_conform_credential_safe(token)) return NULL;
    if (url->is_s3) {
        int signed_rc = xrd_conform_s3_auth_headers(url, method,
            authentication);

        if (signed_rc != 0) {
            *failure = signed_rc == -2 ? "partial S3 credential pair"
                : signed_rc == -3 ? "unsafe S3 credential value"
                : signed_rc == -4 ? "S3 URL query cannot be header-signed"
                : "S3 SigV4 construction failed";
            return NULL;
        }
    } else if (token != NULL) {
        snprintf(authentication, sizeof(authentication),
            "Authorization: Bearer %s\r\n", token);
    }
    size = strlen(authentication) + token_len + fields_len + 1;
    headers = malloc(size);
    if (headers == NULL) return NULL;
    snprintf(headers, size, "%s", authentication);
    if (fields != NULL) {
        size_t used = strlen(headers);

        snprintf(headers + used, size - used, "%s", fields);
    }
    *failure = NULL;
    return headers;
}

/* ---- Issue one bounded HTTP request ----
 *
 * WHAT: Charges a request, executes it through the shared client and returns it.
 * WHY: Every network operation must pass the common resource ceilings.
 * HOW: Reserve predicted response bytes, call brix_http_req with shared TLS opts.
 */
int
xrd_conform_http_request_custom(xrd_conform_execution *execution,
    const brix_weburl *url, const char *method, const char *headers,
    const void *body, size_t body_length,
    size_t expected_bytes, brix_http_resp *response, brix_status *status)
{
    char reason[64];
    char proxy[XRDC_PATH_MAX];
    char wire_path[XRDC_PATH_MAX * 4];
    const char *request_path = url->path;
    const char *client_cert = brix_web_proxy_pem(proxy, sizeof(proxy));

    if (body_length > SIZE_MAX - expected_bytes) {
        brix_status_set(status, XRDC_EUSAGE, 0,
            "HTTP request/response byte count overflow");
        return -1;
    }
    if (!xrd_conform_reserve(execution, body_length + expected_bytes,
            reason, sizeof(reason))) {
        brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
        return -1;
    }
    if (url->is_s3) {
        if (xrd_conform_s3_wire_path(url, wire_path, sizeof(wire_path)) != 0) {
            brix_status_set(status, XRDC_EUSAGE, 0,
                "S3 request path cannot be encoded safely");
            return -1;
        }
        request_path = wire_path;
    }
    {
        return brix_http_req(url->host, url->port, url->tls, method,
        request_path,
        headers, body, body_length, 10000, execution->run->opts.verify_host,
        brix_resolve_ca_dir(execution->run->opts.ca_dir), client_cert, response,
        status);
    }
}

int
xrd_conform_http_request_body(xrd_conform_execution *execution,
    const brix_weburl *url, const char *method, const char *token,
    const char *fields, const void *body, size_t body_length,
    size_t expected_bytes, brix_http_resp *response, brix_status *status)
{
    const char *header_failure = NULL;
    char *headers = xrd_conform_http_headers(url, method, token, fields,
        &header_failure);
    int rc;

    if (headers == NULL) {
        brix_status_set(status, XRDC_EAUTH, 0, "%s",
            header_failure == NULL ? "HTTP header allocation failed"
                                   : header_failure);
        return -1;
    }
    rc = xrd_conform_http_request_custom(execution, url, method, headers,
        body, body_length, expected_bytes, response, status);
    free(headers);
    return rc;
}

/* ---- Issue one body-free bounded HTTP request ----
 *
 * WHAT: Preserves the existing field-only interface and returns transport rc.
 * WHY: Read probes should not carry nullable body arguments at every callsite.
 * HOW: Delegate to the body-capable helper with an empty request body.
 */
int
xrd_conform_http_request_fields(xrd_conform_execution *execution,
    const brix_weburl *url, const char *method, const char *token,
    const char *fields, size_t expected_bytes,
    brix_http_resp *response, brix_status *status)
{
    return xrd_conform_http_request_body(execution, url, method, token,
        fields, NULL, 0, expected_bytes, response, status);
}

int
xrd_conform_http_request(xrd_conform_execution *execution,
    const brix_weburl *url,
    const char *method, const char *token, const char *range,
    size_t expected_bytes, brix_http_resp *response, brix_status *status)
{
    char fields[160];

    if (range == NULL)
        return xrd_conform_http_request_fields(execution, url, method, token, NULL,
            expected_bytes, response, status);
    if ((size_t) snprintf(fields, sizeof(fields), "Range: %s\r\n", range)
        >= sizeof(fields)) {
        brix_status_set(status, XRDC_EUSAGE, 0, "HTTP range too long");
        return -1;
    }
    return xrd_conform_http_request_fields(execution, url, method, token, fields,
        expected_bytes, response, status);
}

/* WHAT: Probe unknown-method handling. WHY: A protocol extension must be a
 * client error with method discovery, never an internal error. HOW: Send one
 * bounded extension method and require 405 plus a non-empty Allow header. */
static void
probe_unknown_method(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token)
{
    brix_http_resp response;
    brix_status status;
    char allow[512];
    int rc;
    int pass;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request(execution, url, "BRIXCONFORM", token, NULL, 0,
        &response, &status);
    pass = rc == 0 && response.status == 405
        && brix_http_header(&response, "Allow", allow, sizeof(allow))
        && allow[0] != '\0';
    xrd_conform_result_set(execution, "HTE-003",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "unknown-method-rejected-with-allow"
             : "unknown-method-response-invalid",
        "HTTP 405 with non-empty Allow", rc == 0 ? NULL : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

/* ---- Establish a bounded HTTP object size ----
 *
 * WHAT: Returns zero with a valid successful HEAD Content-Length.
 * WHY: The GET body must be ceiling-checked before the server can send it.
 * HOW: Issue HEAD, parse strict length, compare configured and address bounds.
 */
static int
http_baseline_size(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, uint64_t *size, brix_status *status)
{
    brix_http_resp response;
    int rc;

    memset(&response, 0, sizeof(response));
    rc = xrd_conform_http_request(execution, url, "HEAD", token, NULL, 0, &response,
        status);
    if (rc != 0) return -1;
    rc = response.status >= 200 && response.status < 400
        && xrd_conform_http_content_length(&response, size) == 0
        && *size <= execution->run->config.byte_limit && *size <= SIZE_MAX
        ? 0 : -1;
    brix_http_resp_free(&response);
    return rc;
}

/* WHAT: Observe whether a generated sibling is absent on this web plane.
 * WHY: XPR-007 must compare actual namespace answers, not successful baselines.
 * HOW: Record 404 as absent, 2xx as exposed, and retain uncertainty otherwise. */
static void
probe_cross_plane_missing(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    const brix_conform_result *row = xrd_conform_result_find(execution,
        "XPR-007");
    brix_weburl missing = *url;
    brix_http_resp response;
    brix_status status;
    int rc;
    int state = 0;

    if (row == NULL || row->verdict == BRIX_CONFORM_VERDICT_SKIPPED) return;
    if ((size_t) snprintf(missing.path, sizeof(missing.path),
            "%s.brix-conform-missing-%.8s", url->path,
            execution->run->key_hex) >= sizeof(missing.path)) return;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, &missing, "GET", token,
        NULL, 4096, &response, &status);
    if (rc == 0 && response.status == 404) state = 1;
    else if (rc == 0 && response.status >= 200 && response.status < 300)
        state = -1;
    if (url->is_s3) execution->s3_missing_state = state;
    else execution->http_missing_state = state;
    if (rc == 0) brix_http_resp_free(&response);
}

/* ---- Fetch and grade the adopted HTTP baseline ----
 *
 * WHAT: Returns zero after a complete GET and all supported boundary probes.
 * WHY: Isolating response ownership keeps top-level failure cleanup simple.
 * HOW: GET exact HEAD size, record plane digest, run boundary comparisons.
 */
static int
http_baseline_grade(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, uint64_t size, int prf_proven, brix_status *status)
{
    brix_http_resp response;
    int rc;

    memset(&response, 0, sizeof(response));
    rc = xrd_conform_http_request(execution, url, "GET", token, NULL,
        (size_t) size,
        &response, status);
    if (rc != 0) {
        if (!url->is_s3 && strstr(status->msg,
                "Content-Length body truncated") != NULL) {
            xrd_conform_result_set(execution, "HTR-015",
                BRIX_CONFORM_VERDICT_DIVERGENT,
                "GET-content-length-truncated", "advertised bytes delivered",
                status->msg);
        }
        return -1;
    }
    if (!response.framing_valid) {
        xrd_conform_result_set(execution, "HTR-016",
            BRIX_CONFORM_VERDICT_DIVERGENT, "chunked-body-framing-invalid",
            "complete chunks followed by zero chunk", NULL);
        brix_http_resp_free(&response);
        return -1;
    }
    if (response.status < 200 || response.status >= 300
        || response.body_len != (size_t) size) {
        brix_http_resp_free(&response);
        return -1;
    }
    if (url->is_s3) execution->s3_size = response.body_len;
    brix_s3_sha256_hex(response.body, response.body_len,
        url->is_s3 ? execution->s3_digest : execution->http_digest);
    if (url->is_s3) execution->have_s3 = 1;
    else execution->have_http = 1;
    xrd_conform_probe_http_boundaries(execution, url, token, &response);
    xrd_conform_probe_http_validators(execution, url, token, &response);
    xrd_conform_probe_http_semantics(execution, url, token, &response);
    xrd_conform_probe_s3_checksum(execution, url, &response);
    xrd_conform_probe_web_traversal(execution, url, token);
    xrd_conform_probe_web_case(execution, url, token);
    xrd_conform_probe_web_namespace(execution, url, token);
    xrd_conform_probe_web_filenames(execution, url, token);
    xrd_conform_probe_http_errors(execution, url, token, &response);
    xrd_conform_probe_webdav(execution, url, token, &response);
    xrd_conform_probe_http_create(execution, url, token);
    probe_unknown_method(execution, url, token);
    xrd_conform_probe_s3_auth(execution, url);
    xrd_conform_probe_s3_readonly(execution, url);
    xrd_conform_probe_s3_range_agreement(execution, url);
    xrd_conform_probe_s3_missing_codes(execution, url);
    xrd_conform_probe_s3_listing(execution, url);
    xrd_conform_probe_s3_special_keys(execution, url);
    xrd_conform_probe_s3_multipart(execution, url);
    probe_cross_plane_missing(execution, url, token);
    if (prf_proven) {
        uint8_t *expected = malloc(CONFORM_HTTP_PLANTED_SIZE);
        int exact;

        if (expected != NULL)
            brix_conform_fill(&execution->run->key, 0, expected,
                CONFORM_HTTP_PLANTED_SIZE);
        exact = expected != NULL
            && response.body_len == CONFORM_HTTP_PLANTED_SIZE
            && memcmp(response.body, expected,
                CONFORM_HTTP_PLANTED_SIZE) == 0;
        free(expected);
        xrd_conform_result_set(execution,
            url->is_s3 ? "S3-001" : "HTR-001",
            exact ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
            exact ? "planted-prf-object-byte-exact"
                  : "planted-prf-object-mismatch",
            "65536 PRF bytes", NULL);
    } else {
        xrd_conform_result_set(execution,
            url->is_s3 ? "S3-001" : "HTR-001",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "adopted-body-not-prf-proven",
            NULL, NULL);
    }
    if (!url->is_s3) execution->http_size = response.body_len;
    brix_http_resp_free(&response);
    return 0;
}

/* ---- Run an adopted HTTP/WebDAV/S3 read-plane assessment ----
 *
 * WHAT: Returns zero after a bounded usable GET, otherwise incomplete code 3.
 * WHY: Without a complete baseline no later range answer has a byte oracle.
 * HOW: HEAD-gate size, GET once, grade observable rows, retain unknowns as such.
 */
int
xrd_conform_run_http(xrd_conform_execution *execution)
{
    brix_weburl url;
    brix_weburl planted_url;
    const brix_weburl *baseline_url = &url;
    brix_status status;
    char *token = NULL;
    uint64_t size;
    int planted = 0;
    int rc = 3;

    if (brix_weburl_parse(execution->target, &url) != 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: target is not a valid web URL\n");
        return 3;
    }
    if (!url.is_s3) token = brix_token_discover();
    planted = plant_http_baseline(execution, &url, token, &planted_url);
    if (planted > 0) baseline_url = &planted_url;
    brix_status_clear(&status);
    if (planted < 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: HTTP PRF baseline plant failed\n");
    } else if (http_baseline_size(execution, baseline_url, token, &size,
            &status) != 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: HTTP baseline HEAD failed or exceeded ceiling: %s\n",
            status.msg);
    } else {
        brix_status_clear(&status);
        if (http_baseline_grade(execution, baseline_url, token, size,
                planted > 0, &status) == 0) {
            rc = 0;
        } else if (execution->run->config.only != NULL
            && (strcmp(execution->run->config.only, "HTR-015") == 0
                || strcmp(execution->run->config.only, "HTR-016") == 0)) {
            brix_conform_result *row = xrd_conform_result_find(execution,
                execution->run->config.only);

            if (row != NULL
                && row->verdict == BRIX_CONFORM_VERDICT_DIVERGENT) rc = 0;
        } else {
            BRIX_CLIENT_LOG("ERROR",
                "xrd conform: HTTP baseline GET failed: %s\n",
                status.msg);
        }
    }
    if (planted > 0
        && cleanup_http_baseline(execution, &planted_url, token) != 0) rc = 3;
    free(token);
    return rc;
}
