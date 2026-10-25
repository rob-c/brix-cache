/* Phase-118 cross-plane path-normalization evidence. */
#include "xrd_conform_probe_helpers.h"


/* WHAT: Submit one literal parent segment through the ROOT stat operation.
 * WHY: XPR-008 needs the same hostile relative shape on each selected plane.
 * HOW: Append /../outside and retain only a defined protocol refusal or success. */
void
xrd_conform_probe_root_traversal(xrd_conform_execution *execution,
    brix_conn *connection, const char *path)
{
    const char *const suffixes[] = {
        "/../brix-conform-outside",
        "/%2e%2e%2fbrix-conform-outside"
    };
    brix_statinfo info;
    brix_status status;
    char hostile[XRDC_PATH_MAX];
    char reason[64];
    size_t index;
    int state = 1;

    if (!xrd_conform_row_active(execution, "XPR-008")) return;
    for (index = 0; index < sizeof(suffixes) / sizeof(suffixes[0]); index++) {
        if ((size_t) snprintf(hostile, sizeof(hostile), "%s%s", path,
                suffixes[index]) >= sizeof(hostile)
            || !xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
            state = 0;
            break;
        }
        brix_status_clear(&status);
        if (brix_stat(connection, hostile, &info, &status) == 0) state = -1;
        else if (status.kxr == 0) state = 0;
    }
    execution->root_traversal_state = state;
}

/* WHAT: Submit the ROOT-equivalent hostile path through one HTTP-family plane.
 * WHY: A decoder disagreement can expose an object hidden on the other plane.
 * HOW: Preserve authority, replace only the path, and classify 4xx vs 2xx. */
void
xrd_conform_probe_web_traversal(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    const char *const suffixes[] = {
        "/../brix-conform-outside",
        "/%2e%2e%2fbrix-conform-outside"
    };
    brix_weburl hostile = *url;
    brix_http_resp response;
    brix_status status;
    int *state;
    size_t index;
    int rc;

    if (!xrd_conform_row_active(execution, "XPR-008")) return;
    state = url->is_s3 ? &execution->s3_traversal_state
                       : &execution->http_traversal_state;
    *state = 1;
    for (index = 0; index < sizeof(suffixes) / sizeof(suffixes[0]); index++) {
        if ((size_t) snprintf(hostile.path, sizeof(hostile.path), "%s%s",
                url->path, suffixes[index]) >= sizeof(hostile.path)) {
            *state = 0;
            return;
        }
        memset(&response, 0, sizeof(response));
        brix_status_clear(&status);
        rc = xrd_conform_http_request_fields(execution, &hostile, "GET", token,
            NULL, 4096, &response, &status);
        if (rc != 0 || response.status >= 500) *state = 0;
        else if (response.status >= 200 && response.status < 300) *state = -1;
        else if (response.status < 400) *state = 0;
        if (rc == 0) brix_http_resp_free(&response);
    }
}

void
xrd_conform_finalize_traversal(xrd_conform_execution *execution)
{
    const int states[] = {
        execution->root_traversal_state,
        execution->http_traversal_state,
        execution->s3_traversal_state
    };
    size_t index;
    int observations = 0;
    int refused = 1;

    for (index = 0; index < sizeof(states) / sizeof(states[0]); index++) {
        if (states[index] == 0) continue;
        observations++;
        if (states[index] != 1) refused = 0;
    }
    if (observations < 2) return;
    xrd_conform_result_set(execution, "XPR-008",
        refused ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        refused ? "cross-plane-traversal-refused"
                : "cross-plane-traversal-exposed",
        "literal and encoded parent segments refused on every observed plane",
        NULL);
}

/* WHAT: Derive one bounded path differing only in basename letter case.
 * WHY: XPR-010 must not accidentally compare a different directory or object.
 * HOW: Copy the path and toggle the first ASCII letter after its final slash. */
static int
case_variant(const char *path, char out[XRDC_PATH_MAX])
{
    char *name;
    char *cursor;

    if ((size_t) snprintf(out, XRDC_PATH_MAX, "%s", path) >= XRDC_PATH_MAX)
        return -1;
    name = strrchr(out, '/');
    name = name == NULL ? out : name + 1;
    for (cursor = name; *cursor != '\0'; cursor++) {
        if (*cursor >= 'a' && *cursor <= 'z') {
            *cursor = (char) (*cursor - 'a' + 'A');
            return 0;
        }
        if (*cursor >= 'A' && *cursor <= 'Z') {
            *cursor = (char) (*cursor - 'A' + 'a');
            return 0;
        }
    }
    return -1;
}

void
xrd_conform_probe_root_case(xrd_conform_execution *execution,
    brix_conn *connection, const char *path)
{
    brix_statinfo info;
    brix_status status;
    char alternate[XRDC_PATH_MAX];
    char reason[64];
    int rc;

    if (!xrd_conform_row_active(execution, "XPR-010")
        || case_variant(path, alternate) != 0
        || !xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return;
    brix_status_clear(&status);
    rc = brix_stat(connection, alternate, &info, &status);
    if (rc == 0) execution->root_case_state = 2;
    else if (status.kxr == kXR_NotFound) execution->root_case_state = 1;
}

void
xrd_conform_probe_web_case(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    brix_weburl alternate = *url;
    brix_http_resp response;
    brix_status status;
    int *state;
    int rc;

    if (!xrd_conform_row_active(execution, "XPR-010")
        || case_variant(url->path, alternate.path) != 0) return;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, &alternate, "GET", token,
        NULL, 4096, &response, &status);
    state = url->is_s3 ? &execution->s3_case_state
                       : &execution->http_case_state;
    if (rc == 0 && response.status == 404) *state = 1;
    else if (rc == 0 && response.status >= 200 && response.status < 300)
        *state = 2;
    if (rc == 0) brix_http_resp_free(&response);
}

void
xrd_conform_finalize_case(xrd_conform_execution *execution)
{
    const int states[] = {
        execution->root_case_state,
        execution->http_case_state,
        execution->s3_case_state
    };
    size_t index;
    int expected = 0;
    int observations = 0;
    int agreement = 1;

    for (index = 0; index < sizeof(states) / sizeof(states[0]); index++) {
        if (states[index] == 0) continue;
        if (expected == 0) expected = states[index];
        else if (states[index] != expected) agreement = 0;
        observations++;
    }
    if (observations < 2) return;
    xrd_conform_result_set(execution, "XPR-010",
        agreement ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
        agreement ? "cross-plane-case-policy-agreement"
                  : "cross-plane-case-policy-mismatch",
        "case-variant presence or absence agrees on every observed plane", NULL);
}

/* WHAT: Construct the UTF-8, Latin-1 and raw-byte sibling names for one plane.
 * WHY: HTTP needs percent-encoded octets while S3 canonicalization starts from
 *      raw key bytes; using one representation would double-encode one plane.
 * HOW: Append a fixed class tag plus either canonical escapes or literal bytes. */
static int
filename_variant(const char *path, int web_encoded, size_t index,
    char out[XRDC_PATH_MAX])
{
    static const char *const raw_suffixes[] = {
        ".brix-conform-utf8-\xc3\xa9",
        ".brix-conform-latin1-\xe9",
        ".brix-conform-raw-\xff"
    };
    static const char *const encoded_suffixes[] = {
        ".brix-conform-utf8-%C3%A9",
        ".brix-conform-latin1-%E9",
        ".brix-conform-raw-%FF"
    };
    const char *suffix = web_encoded ? encoded_suffixes[index]
                                     : raw_suffixes[index];

    return (size_t) snprintf(out, XRDC_PATH_MAX, "%s%s", path, suffix)
        < XRDC_PATH_MAX ? 0 : -1;
}

void
xrd_conform_probe_root_filenames(xrd_conform_execution *execution,
    brix_conn *connection, const char *path)
{
    brix_statinfo info;
    brix_status status;
    char variant[XRDC_PATH_MAX];
    char reason[64];
    size_t index;

    if (!xrd_conform_row_active(execution, "XPR-011")) return;
    for (index = 0; index < 3; index++) {
        if (filename_variant(path, 0, index, variant) != 0
            || !xrd_conform_reserve(execution, 0, reason, sizeof(reason)))
            return;
        brix_status_clear(&status);
        if (brix_stat(connection, variant, &info, &status) == 0) return;
        if (status.kxr == kXR_ArgInvalid
            || status.kxr == kXR_InvalidRequest
            || status.kxr == kXR_NotAuthorized)
            execution->root_filename_state[index] = 1;
    }
}

static int
web_filename_state(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, size_t index)
{
    brix_weburl variant = *url;
    brix_http_resp response;
    brix_status status;
    char digest[65];
    const char *expected = url->is_s3 ? execution->s3_digest
                                      : execution->http_digest;
    int rc;

    if (filename_variant(url->path, !url->is_s3, index, variant.path) != 0)
        return 0;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, &variant, "GET", token,
        NULL, 65536, &response, &status);
    if (rc != 0) return 0;
    if (response.status == 400 || response.status == 403) rc = 1;
    else if (response.status >= 200 && response.status < 300) {
        brix_s3_sha256_hex(response.body, response.body_len, digest);
        rc = strcmp(digest, expected) == 0 ? 2 : -1;
    } else rc = 0;
    brix_http_resp_free(&response);
    return rc;
}

void
xrd_conform_probe_web_filenames(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    int *states = url->is_s3 ? execution->s3_filename_state
                             : execution->http_filename_state;
    size_t index;

    if (!xrd_conform_row_active(execution, "XPR-011")) return;
    for (index = 0; index < 3; index++)
        states[index] = web_filename_state(execution, url, token, index);
}

void
xrd_conform_finalize_filenames(xrd_conform_execution *execution)
{
    const int *states[] = { execution->root_filename_state,
        execution->http_filename_state, execution->s3_filename_state };
    const int enabled[] = { execution->have_root, execution->have_http,
        execution->have_s3 };
    size_t class_index;
    size_t plane_index;
    int observations = 0;
    int agreement = 1;

    for (class_index = 0; class_index < 3; class_index++) {
        int expected = 0;

        for (plane_index = 0; plane_index < 3; plane_index++) {
            int state;

            if (!enabled[plane_index]) continue;
            state = states[plane_index][class_index];
            if (state == 0) return;
            if (state < 0) agreement = 0;
            if (expected == 0) expected = state;
            else if (state != expected) agreement = 0;
            observations++;
        }
    }
    if (observations < 6) return;
    xrd_conform_result_set(execution, "XPR-011",
        agreement ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
        agreement ? "cross-plane-filename-encoding-agreement"
                  : "cross-plane-filename-encoding-mismatch",
        "UTF-8, Latin-1 and raw-byte names agree or are explicitly refused",
        NULL);
}
