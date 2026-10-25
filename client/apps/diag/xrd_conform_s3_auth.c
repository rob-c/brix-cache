/* Phase-118 S3 authentication-boundary probes. */
#include "xrd_conform_probe_helpers.h"
#include "core/compat/host_format.h"


/* WHAT: Return whether this run explicitly selected a paired read-only clause.
 * WHY: Writable general runs must not be judged as read-only fixture failures.
 * HOW: Compare the exact selector with the two rows sharing this observation. */
static int
readonly_clause_selected(const xrd_conform_execution *execution)
{
    const char *only = execution->run->config.only;

    return only != NULL && (strcmp(only, "S3-009") == 0
        || strcmp(only, "XPR-006") == 0);
}

static int
request_with_headers(xrd_conform_execution *execution, const brix_weburl *url,
    const char *method, const char *headers, size_t expected,
    unsigned *http_status, brix_status *status)
{
    brix_http_resp response;
    int rc;

    memset(&response, 0, sizeof(response));
    brix_status_clear(status);
    rc = xrd_conform_http_request_custom(execution, url, method, headers,
        NULL, 0, expected, &response, status);
    if (rc == 0) {
        *http_status = response.status;
        brix_http_resp_free(&response);
    }
    return rc;
}

static int
auth_rejected(unsigned status)
{
    return status == 401 || status == 403;
}

/* Corrupt one nibble of a valid signature and require an authorization error. */
static void
probe_tampered_signature(xrd_conform_execution *execution,
    const brix_weburl *url)
{
    char headers[2048];
    char *signature;
    brix_status status;
    unsigned http_status = 0;
    int rc;

    if (!xrd_conform_row_active(execution, "S3-005")) return;
    rc = xrd_conform_s3_auth_headers(url, "HEAD", headers);
    if (rc == 0 && headers[0] == '\0') {
        xrd_conform_result_set(execution, "S3-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "no-s3-credentials", NULL,
            NULL);
        return;
    }
    signature = rc == 0 ? strstr(headers, "Signature=") : NULL;
    if (signature == NULL || signature[10] == '\0') {
        xrd_conform_result_set(execution, "S3-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "s3-signature-build-failed",
            NULL, NULL);
        return;
    }
    signature[10] = signature[10] == '0' ? '1' : '0';
    rc = request_with_headers(execution, url, "HEAD", headers, 0,
        &http_status, &status);
    xrd_conform_result_set(execution, "S3-005",
        rc == 0 && auth_rejected(http_status)
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        rc == 0 && auth_rejected(http_status)
            ? "tampered-signature-rejected" : "tampered-signature-accepted",
        "HTTP 401 or 403", rc == 0 ? NULL : status.msg);
}

static int
presigned_url(const brix_weburl *url, const char *access, const char *secret,
    const char *region, time_t signed_at, unsigned expires,
    brix_weburl *presigned)
{
    char host[300];
    char query[4096];
    int written;

    if (strchr(url->path, '?') != NULL) return -1;
    brix_format_host_port(url->host, (uint16_t) url->port, host, sizeof(host));
    if (brix_s3_presign_v4_at("GET", host, url->path, access, secret, region,
            signed_at, expires, query, sizeof(query)) != 0) return -1;
    *presigned = *url;
    written = snprintf(presigned->path, sizeof(presigned->path), "%s?%s",
        url->path, query);
    return written < 0 || (size_t) written >= sizeof(presigned->path) ? -1 : 0;
}

static int
presigned_get(xrd_conform_execution *execution, const brix_weburl *url,
    unsigned *http_status, brix_status *status)
{
    return request_with_headers(execution, url, "GET", "",
        (size_t) execution->s3_size,
        http_status, status);
}

static void
presigned_unavailable(xrd_conform_execution *execution)
{
    if (xrd_conform_row_active(execution, "S3-006"))
        xrd_conform_result_set(execution, "S3-006",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "presign-unavailable", NULL,
            NULL);
    if (xrd_conform_row_active(execution, "S3-007"))
        xrd_conform_result_set(execution, "S3-007",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "presign-unavailable", NULL,
            NULL);
}

static void
grade_presigned_expiry(xrd_conform_execution *execution, int valid_rc,
    unsigned valid_status, int expired_rc, unsigned expired_status)
{
    int pass;

    if (!xrd_conform_row_active(execution, "S3-006")) return;
    pass = valid_rc == 0 && valid_status >= 200 && valid_status < 300
        && expired_rc == 0 && auth_rejected(expired_status);
    xrd_conform_result_set(execution, "S3-006",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        expired_rc == 0 && auth_rejected(expired_status)
            ? "expired-presigned-url-rejected"
            : "expired-presigned-url-accepted",
        "current URL 2xx and expired URL 401/403", NULL);
}

static void
grade_presigned_replay(xrd_conform_execution *execution, int valid_rc,
    unsigned valid_status, int replay_rc, unsigned replay_status)
{
    int pass;

    if (!xrd_conform_row_active(execution, "S3-007")) return;
    pass = valid_rc == 0 && valid_status >= 200 && valid_status < 300
        && replay_rc == 0 && auth_rejected(replay_status);
    xrd_conform_result_set(execution, "S3-007",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        replay_rc == 0 && auth_rejected(replay_status)
            ? "presigned-path-replay-rejected"
            : "presigned-path-replay-accepted",
        "original URL 2xx and replay URL 401/403", NULL);
}

/* Require a current URL to work while expiration and path replay fail closed. */
static void
probe_presigned_urls(xrd_conform_execution *execution,
    const brix_weburl *url)
{
    const char *access;
    const char *secret;
    const char *region;
    brix_weburl valid, expired, replay;
    brix_status status;
    unsigned valid_status = 0, expired_status = 0, replay_status = 0;
    time_t now = time(NULL);
    int credential_state;
    int valid_rc, expired_rc, replay_rc;
    int written;

    if (!xrd_conform_row_active(execution, "S3-006")
        && !xrd_conform_row_active(execution, "S3-007")) return;
    credential_state = xrd_conform_s3_credentials(&access, &secret, &region);
    if (credential_state <= 0 || now == (time_t) -1
        || presigned_url(url, access, secret, region, now, 300, &valid) != 0
        || presigned_url(url, access, secret, region, now - 3600, 1,
            &expired) != 0) {
        presigned_unavailable(execution);
        return;
    }
    replay = *url;
    written = snprintf(replay.path, sizeof(replay.path),
        "%s.brix-conform-presign-replay%s", url->path,
        strchr(valid.path, '?'));
    if (written < 0 || (size_t) written >= sizeof(replay.path)) return;
    valid_rc = presigned_get(execution, &valid, &valid_status, &status);
    expired_rc = presigned_get(execution, &expired, &expired_status, &status);
    replay_rc = presigned_get(execution, &replay, &replay_status, &status);
    grade_presigned_expiry(execution, valid_rc, valid_status, expired_rc,
        expired_status);
    grade_presigned_replay(execution, valid_rc, valid_status, replay_rc,
        replay_status);
}

static void
probe_auth_confusion(xrd_conform_execution *execution,
    const brix_weburl *url)
{
    char headers[2048];
    char *token = NULL;
    brix_weburl signed_url = *url;
    brix_status status;
    unsigned http_status = 0;
    int rc;
    int written;

    if (!xrd_conform_row_active(execution, "S3-008")) return;
    if (url->is_s3) {
        token = brix_token_discover();
        written = token == NULL ? -1 : snprintf(headers, sizeof(headers),
            "Authorization: Bearer %s\r\n", token);
        if (!xrd_conform_credential_safe(token) || written < 0
            || (size_t) written >= sizeof(headers)) {
            free(token);
            return;
        }
        rc = request_with_headers(execution, url, "HEAD",
            headers, 0, &http_status, &status);
        free(token);
        if (rc == 0)
            execution->s3_bearer_state = auth_rejected(http_status) ? -1 : 1;
        return;
    }
    signed_url.is_s3 = 1;
    rc = xrd_conform_s3_auth_headers(&signed_url, "HEAD", headers);
    if (rc != 0 || headers[0] == '\0') return;
    rc = request_with_headers(execution, url, "HEAD", headers, 0,
        &http_status, &status);
    if (rc == 0)
        execution->http_sigv4_state = auth_rejected(http_status) ? -1 : 1;
}

void
xrd_conform_probe_s3_auth(xrd_conform_execution *execution,
    const brix_weburl *url)
{
    if (url->is_s3) {
        probe_tampered_signature(execution, url);
        probe_presigned_urls(execution, url);
    }
    probe_auth_confusion(execution, url);
}

void
xrd_conform_finalize_s3_auth(xrd_conform_execution *execution)
{
    int paired;

    if (!xrd_conform_row_active(execution, "S3-008")) return;
    paired = execution->s3_bearer_state != 0
        && execution->http_sigv4_state != 0;
    xrd_conform_result_set(execution, "S3-008",
        !paired ? BRIX_CONFORM_VERDICT_INCONCLUSIVE
                : execution->s3_bearer_state < 0
                    && execution->http_sigv4_state < 0
                    ? BRIX_CONFORM_VERDICT_CONFORMANT
                    : BRIX_CONFORM_VERDICT_DIVERGENT,
        !paired ? "requires-paired-s3-wlcg-auth-fixture"
                : execution->s3_bearer_state < 0
                    && execution->http_sigv4_state < 0
                    ? "cross-plane-auth-confusion-rejected"
                    : "cross-plane-auth-confusion-accepted",
        "bearer rejected by S3 and SigV4 rejected by HTTP", NULL);
}

/* WHAT: Return one for AccessDenied, zero for wrong, or minus one for transport.
 * WHY: The caller must distinguish a divergent answer from missing evidence.
 * HOW: Send one bounded PUT and inspect its status and exact XML code. */
static int
readonly_put_refused(xrd_conform_execution *execution,
    const brix_weburl *scratch)
{
    static const char body[] = "R";
    brix_http_resp response;
    brix_status status;
    int rc;
    int refused;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, scratch, "PUT", NULL, NULL,
        body, sizeof(body) - 1, 4096, &response, &status);
    refused = rc == 0 && response.status == 403 && response.body != NULL
        && strstr(response.body, "<Code>AccessDenied</Code>") != NULL;
    if (rc == 0) brix_http_resp_free(&response);
    return rc == 0 ? refused : -1;
}

/* WHAT: Return one when the refused key is absent, zero if visible, -1 on I/O.
 * WHY: A cosmetic denial must never conceal a committed object mutation.
 * HOW: Issue a bounded GET and require the missing-object HTTP status. */
static int
readonly_key_absent(xrd_conform_execution *execution,
    const brix_weburl *scratch)
{
    brix_http_resp response;
    brix_status status;
    int rc;
    int absent;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, scratch, "GET", NULL,
        NULL, 4096, &response, &status);
    absent = rc == 0 && response.status == 404;
    if (rc == 0) brix_http_resp_free(&response);
    return rc == 0 ? absent : -1;
}

/* ---- Observe the S3 half of the paired read-only assertion ----
 *
 * WHAT: Records exact AccessDenied refusal and post-refusal object absence.
 * WHY: A cosmetic 403 is insufficient if the rejected PUT still mutates data.
 * HOW: PUT one byte to a builder-confined key, require the AWS XML spelling,
 *      then GET the key and require it to remain absent.
 */
void
xrd_conform_probe_s3_readonly(xrd_conform_execution *execution,
    const brix_weburl *url)
{
    brix_weburl scratch = *url;
    int refused;
    int absent;

    if (!url->is_s3 || !readonly_clause_selected(execution)
        || (!xrd_conform_row_active(execution, "S3-009")
            && !xrd_conform_row_active(execution, "XPR-006"))) return;
    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-s3-readonly", scratch.path,
            sizeof(scratch.path)) != 0) return;
    refused = readonly_put_refused(execution, &scratch);
    absent = readonly_key_absent(execution, &scratch);
    if (refused >= 0 && absent >= 0)
        execution->s3_readonly_state = refused && absent ? -1 : 1;
}

/* ---- Grade the paired ROOT/S3 read-only assertion ----
 *
 * WHAT: Resolves S3-009 after every primary and --also target has run.
 * WHY: Neither plane alone establishes the cross-protocol policy agreement.
 * HOW: Fail on any observed wrong answer, pass only two exact observations,
 *      and otherwise retain an explicit paired-fixture requirement.
 */
void
xrd_conform_finalize_s3_readonly(xrd_conform_execution *execution)
{
    static const char *const ids[] = { "S3-009", "XPR-006" };
    int root = execution->root_readonly_state;
    int s3 = execution->s3_readonly_state;
    size_t index;

    if (!readonly_clause_selected(execution)) {
        for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++)
            if (xrd_conform_row_active(execution, ids[index]))
                xrd_conform_result_set(execution, ids[index],
                    BRIX_CONFORM_VERDICT_SKIPPED,
                    "fixture-required:paired-root-s3-readonly", NULL, NULL);
        return;
    }
    for (index = 0; index < sizeof(ids) / sizeof(ids[0]); index++)
        if (xrd_conform_row_active(execution, ids[index]))
            xrd_conform_result_set(execution, ids[index],
                root > 0 || s3 > 0 ? BRIX_CONFORM_VERDICT_DIVERGENT
                    : root < 0 && s3 < 0 ? BRIX_CONFORM_VERDICT_CONFORMANT
                                         : BRIX_CONFORM_VERDICT_INCONCLUSIVE,
                root > 0 || s3 > 0 ? "readonly-cross-plane-answer-wrong"
                    : root < 0 && s3 < 0
                        ? "readonly-cross-plane-policy-agrees"
                        : "requires-paired-root-s3-readonly-fixture",
                "kXR_fsReadOnly and 403 AccessDenied with no created object",
                NULL);
}
