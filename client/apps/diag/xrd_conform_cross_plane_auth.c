/* Phase-118 explicit same-identity cross-plane authorization fixtures. */
#include "xrd_conform_internal.h"

static const char *
denied_target(const xrd_conform_run *run, const char *plane)
{
    size_t index;

    for (index = 0; index < run->denied_fixture_count; index++)
        if (strcmp(run->denied_fixtures[index].plane, plane) == 0)
            return run->denied_fixtures[index].target;
    return NULL;
}

static int
root_denied(xrd_conform_execution *execution, const char *target)
{
    brix_url url;
    brix_conn connection;
    brix_statinfo info;
    brix_status status;
    char reason[64];
    int matched = 0;

    brix_status_clear(&status);
    if (brix_url_parse(target, &url, &status) != 0
        || (url.scheme != XRDC_SCHEME_ROOT && url.scheme != XRDC_SCHEME_ROOTS)
        || !xrd_conform_reserve(execution, 0, reason, sizeof(reason))
        || brix_connect(&connection, &url, &execution->run->opts, &status) != 0)
        return 0;
    brix_status_clear(&status);
    if (brix_stat(&connection, url.path, &info, &status) != 0)
        matched = status.kxr == kXR_NotAuthorized;
    brix_close(&connection);
    return matched;
}

static int
web_denied(xrd_conform_execution *execution, const char *target,
    int require_s3)
{
    brix_weburl url;
    brix_http_resp response;
    brix_status status;
    char *token = NULL;
    int rc;
    int matched;

    if (brix_weburl_parse(target, &url) != 0 || url.is_s3 != require_s3)
        return 0;
    if (!url.is_s3) token = brix_token_discover();
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, &url, "GET", token,
        NULL, 4096, &response, &status);
    free(token);
    if (rc != 0) return 0;
    matched = response.status == 403;
    if (require_s3)
        matched = matched && response.body != NULL
            && strstr(response.body, "<Code>AccessDenied</Code>") != NULL;
    brix_http_resp_free(&response);
    return matched;
}

/* WHAT: Check one explicitly paired denied identity on ROOT, HTTP and S3.
 * WHY: Independent 403 fixtures cannot establish identity or policy pairing.
 * HOW: Require one operator-labelled endpoint per plane and exact spellings. */
void
xrd_conform_probe_denied_fixtures(xrd_conform_execution *execution)
{
    const brix_conform_result *row = xrd_conform_result_find(execution,
        "XPR-005");
    const char *root;
    const char *http;
    const char *s3;
    size_t supplied;
    size_t matched = 0;
    char received[80];

    if (row == NULL || row->verdict == BRIX_CONFORM_VERDICT_SKIPPED
        || execution->run->denied_fixture_count == 0) return;
    root = denied_target(execution->run, "root");
    http = denied_target(execution->run, "http");
    s3 = denied_target(execution->run, "s3");
    supplied = (root != NULL ? 1U : 0U) + (http != NULL ? 1U : 0U)
        + (s3 != NULL ? 1U : 0U);
    if (root != NULL && root_denied(execution, root)) matched++;
    if (http != NULL && web_denied(execution, http, 0)) matched++;
    if (s3 != NULL && web_denied(execution, s3, 1)) matched++;
    snprintf(received, sizeof(received), "planes=%zu/3 exact=%zu/3",
        supplied, matched);
    if (supplied < 3) {
        xrd_conform_result_set(execution, "XPR-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "cross-plane-denied-identity-incomplete",
            "ROOT NotAuthorized; HTTP 403; S3 403 AccessDenied", received);
        return;
    }
    xrd_conform_result_set(execution, "XPR-005",
        matched == 3 ? BRIX_CONFORM_VERDICT_CONFORMANT
                     : BRIX_CONFORM_VERDICT_DIVERGENT,
        matched == 3 ? "cross-plane-authorization-denial-agreement"
                     : "cross-plane-authorization-denial-mismatch",
        "ROOT NotAuthorized; HTTP 403; S3 403 AccessDenied", received);
}
