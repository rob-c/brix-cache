/* Phase-118 WebDAV, S3, OCI and GridFTP read-only spelling matrix. */
#include "xrd_conform_internal.h"
#include "protocols/ftp/ftp_client.h"

static const char *
readonly_target(const xrd_conform_run *run, const char *plane)
{
    size_t index;

    for (index = 0; index < run->readonly_fixture_count; index++)
        if (strcmp(run->readonly_fixtures[index].plane, plane) == 0)
            return run->readonly_fixtures[index].target;
    return NULL;
}

/* WHAT: Attempt one HTTP-plane mutation and inspect its native denial spelling.
 * WHY: A shared status alone cannot prove the S3 and OCI response vocabularies.
 * HOW: PUT one byte through the normal bounded HTTP client and compare status
 *      plus the plane-specific response marker. */
static int
http_readonly_matches(xrd_conform_execution *execution, const char *target,
    const char *plane)
{
    brix_weburl url;
    brix_http_resp response;
    brix_status status;
    int rc;
    int matched;

    if (brix_weburl_parse(target, &url) != 0) return 0;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, &url, "PUT", NULL, NULL,
        "R", 1, 4096, &response, &status);
    if (rc != 0) return 0;
    matched = response.status == 403;
    if (strcmp(plane, "s3") == 0)
        matched = matched && response.body != NULL
            && strstr(response.body, "<Code>AccessDenied</Code>") != NULL;
    else if (strcmp(plane, "oci") == 0)
        matched = matched && response.body != NULL
            && strstr(response.body, "DENIED") != NULL;
    brix_http_resp_free(&response);
    return matched;
}

/* WHAT: Attempt an FTP STOR without opening a data channel.
 * WHY: A read-only GridFTP endpoint must reject at the control policy gate.
 * HOW: Use the production FTP parser/session, issue STOR, and require the exact
 *      550 read-only phrase rather than accepting an unrelated missing error. */
static int
gridftp_readonly_matches(xrd_conform_execution *execution, const char *target)
{
    brix_ftpurl url;
    brix_ftp_sess *session;
    brix_status status;
    char reason[64];
    int matched = 0;

    if (brix_ftpurl_parse(target, &url) != 0
        || !xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return 0;
    session = calloc(1, sizeof(*session));
    if (session == NULL) return 0;
    brix_status_clear(&status);
    if (brix_ftp_session_open(session, &url, &execution->run->opts,
            &status) == 0
        && brix_ftp_cmd(session, &status, "STOR %s", url.path) == 0)
        matched = session->code == 550
            && strstr(session->text, "Permission denied (read-only)") != NULL;
    brix_ftp_close(session);
    free(session);
    return matched;
}

/* WHAT: Grade all four non-ROOT read-only protocol spellings together.
 * WHY: ERR-044 is a matrix assertion; a single 403 is not complete evidence.
 * HOW: Require exactly one labelled endpoint per plane and all exact answers. */
void
xrd_conform_probe_readonly_fixtures(xrd_conform_execution *execution)
{
    static const char *const planes[] = { "webdav", "s3", "oci", "gridftp" };
    const brix_conform_result *row;
    size_t index;
    size_t supplied = 0;
    size_t matched = 0;
    char received[80];

    row = xrd_conform_result_find(execution, "ERR-044");
    if (row == NULL || row->verdict == BRIX_CONFORM_VERDICT_SKIPPED) return;
    for (index = 0; index < sizeof(planes) / sizeof(planes[0]); index++) {
        const char *target = readonly_target(execution->run, planes[index]);

        if (target == NULL) continue;
        supplied++;
        if (strcmp(planes[index], "gridftp") == 0) {
            if (gridftp_readonly_matches(execution, target)) matched++;
        } else if (http_readonly_matches(execution, target, planes[index])) {
            matched++;
        }
    }
    if (supplied == 0) return;
    snprintf(received, sizeof(received), "planes=%zu/4 exact=%zu/4",
        supplied, matched);
    xrd_conform_result_set(execution, "ERR-044",
        supplied == 4 && matched == 4 ? BRIX_CONFORM_VERDICT_CONFORMANT
                                      : BRIX_CONFORM_VERDICT_DIVERGENT,
        supplied == 4 && matched == 4
            ? "readonly-protocol-spellings-agree"
            : "readonly-protocol-spellings-incomplete-or-divergent",
        "WebDAV 403; S3 AccessDenied; OCI DENIED; GridFTP 550 read-only",
        received);
}
