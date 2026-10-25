/* Phase-118 WebDAV/native third-party-copy equivalence probe. */
#include "xrd_conform_internal.h"
#include "core/compat/host_format.h"

static int
web_url_text(const brix_weburl *url, char *text, size_t capacity)
{
    char authority[300];

    if (brix_format_host_port(url->host, (uint16_t) url->port,
            authority, sizeof(authority)) == 0) return -1;
    return (size_t) snprintf(text, capacity, "%s://%s%s",
        url->tls ? "https" : "http", authority, url->path) < capacity ? 0 : -1;
}

static int
request(xrd_conform_execution *execution, const brix_weburl *url,
    const char *method, const char *token, const char *fields,
    const void *body, size_t body_length, size_t expected,
    brix_http_resp *response, brix_status *status)
{
    memset(response, 0, sizeof(*response));
    brix_status_clear(status);
    return xrd_conform_http_request_body(execution, url, method, token, fields,
        body, body_length, expected, response, status);
}

static int
successful_status(int status)
{
    return status >= 200 && status < 300;
}

static int
prepare_webdav_pair(xrd_conform_execution *execution, brix_weburl *source,
    brix_weburl *destination, char *fields, size_t fields_size)
{
    brix_weburl source_base;
    brix_weburl destination_base;
    char source_text[XRDC_PATH_MAX + 320];

    return execution->run->also_count >= 3
        && brix_weburl_parse(execution->run->also[1], &source_base) == 0
        && brix_weburl_parse(execution->run->also[2], &destination_base) == 0
        && !source_base.is_s3 && !destination_base.is_s3
        && xrd_conform_webdav_scratch_url(execution, &source_base,
            "brix-conform-tpc-webdav-source", source) == 0
        && xrd_conform_webdav_scratch_url(execution, &destination_base,
            "brix-conform-tpc-webdav-destination", destination) == 0
        && web_url_text(source, source_text, sizeof(source_text)) == 0
        && (size_t) snprintf(fields, fields_size,
            "Source: %s\r\nCredential: none\r\n", source_text) < fields_size;
}

static void
run_webdav_copy(xrd_conform_execution *execution, const brix_weburl *source,
    const brix_weburl *destination, const char *token, const char *fields,
    const uint8_t *native_bytes, size_t native_length, int *planted,
    int *copied, int *exact, brix_status *status)
{
    brix_http_resp response;

    if (request(execution, source, "PUT", token, NULL, native_bytes,
            native_length, 4096, &response, status) == 0) {
        *planted = successful_status(response.status);
        brix_http_resp_free(&response);
    }
    if (*planted && request(execution, destination, "COPY", token, fields,
            NULL, 0, 4096, &response, status) == 0) {
        *copied = successful_status(response.status);
        brix_http_resp_free(&response);
    }
    if (*copied && request(execution, destination, "GET", token, NULL,
            NULL, 0, native_length, &response, status) == 0) {
        *exact = response.status == 200 && response.framing_valid
            && response.body_len == native_length
            && memcmp(response.body, native_bytes, native_length) == 0;
        brix_http_resp_free(&response);
    }
}

static void
grade_webdav_copy(xrd_conform_execution *execution, int native_exact,
    int planted, int copied, int exact, const brix_status *status)
{
    int passed = native_exact && planted && copied && exact;

    xrd_conform_result_set(execution, "TPC-006",
        passed ? BRIX_CONFORM_VERDICT_CONFORMANT
               : BRIX_CONFORM_VERDICT_DIVERGENT,
        passed ? "native-and-webdav-tpc-byte-exact"
            : !native_exact ? "native-tpc-not-byte-exact"
            : !planted ? "webdav-tpc-source-plant-failed"
            : !copied ? "webdav-tpc-copy-failed"
                      : "webdav-tpc-byte-mismatch",
        "bearer-authenticated WebDAV COPY equals native TPC bytes",
        status->msg);
}

/* WHAT: Compare a bearer-authenticated WebDAV pull with the native TPC result.
 * WHY: Advertising both transfer planes is useful only when they land the same
 *      bytes and the HTTP path really authenticates the COPY request.
 * HOW: Derive two scratch objects from explicit WebDAV endpoints, PUT the
 *      native oracle bytes, COPY with Source/Credential headers, then GET and
 *      compare independently before bounded best-effort cleanup. */
void
xrd_conform_probe_tpc_webdav(xrd_conform_execution *execution,
    const uint8_t *native_bytes, size_t native_length, int native_exact)
{
    const char *kind = execution->run->tpc_fixture_kind;
    brix_weburl source;
    brix_weburl destination;
    brix_status status;
    char fields[XRDC_PATH_MAX + 384];
    char *token;
    int planted = 0;
    int copied = 0;
    int exact = 0;

    if (kind == NULL || strcmp(kind, "native-and-webdav") != 0) return;
    if (!prepare_webdav_pair(execution, &source, &destination, fields,
            sizeof(fields))) {
        xrd_conform_result_set(execution, "TPC-006",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:native-and-webdav-tpc", NULL, NULL);
        return;
    }
    token = brix_token_discover();
    if (token == NULL || !xrd_conform_credential_safe(token)) {
        xrd_conform_result_set(execution, "TPC-006",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-required:webdav-bearer", "safe discovered bearer", NULL);
        free(token);
        return;
    }
    xrd_conform_webdav_cleanup(execution, &destination, token);
    xrd_conform_webdav_cleanup(execution, &source, token);
    run_webdav_copy(execution, &source, &destination, token, fields,
        native_bytes, native_length, &planted, &copied, &exact, &status);
    grade_webdav_copy(execution, native_exact, planted, copied, exact,
        &status);
    xrd_conform_webdav_cleanup(execution, &destination, token);
    xrd_conform_webdav_cleanup(execution, &source, token);
    free(token);
}
