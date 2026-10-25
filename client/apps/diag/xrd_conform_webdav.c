/* Phase-118 read-only WebDAV multistatus probes. */
#include "xrd_conform_probe_helpers.h"
#include "core/compat/host_format.h"



/* WHAT: Match one XML element's local name at a '<' byte.
 * WHY: WebDAV servers freely choose namespace prefixes and letter case.
 * HOW: Skip slash/prefix, compare the local name and require a name boundary. */
static int
xml_local_name(const char *cursor, const char *name, int closing)
{
    const char *local;
    const char *colon;
    const char *end;
    size_t length = strlen(name);

    if (cursor == NULL || *cursor != '<') return 0;
    cursor++;
    if ((*cursor == '/') != closing) return 0;
    if (closing) cursor++;
    end = cursor;
    while (*end != '\0' && *end != '>' && *end != ' ' && *end != '\t'
        && *end != '\r' && *end != '\n') end++;
    colon = memchr(cursor, ':', (size_t) (end - cursor));
    local = colon == NULL ? cursor : colon + 1;
    return (size_t) (end - local) == length
        && strncasecmp(local, name, length) == 0;
}

/* WHAT: Count opening elements with one local name.
 * WHY: DAV-001 requires exactly one response independent of prefix spelling.
 * HOW: Walk bounded NUL-terminated decoded XML and inspect each '<'. */
size_t
xrd_conform_webdav_xml_count(const char *body, const char *name)
{
    const char *cursor = body;
    size_t count = 0;

    if (body == NULL) return 0;
    while ((cursor = strchr(cursor, '<')) != NULL) {
        if (xml_local_name(cursor, name, 0)) count++;
        cursor++;
    }
    return count;
}

/* WHAT: Return the text between a named opening and closing element.
 * WHY: Content-length comparison must parse digits only inside its property.
 * HOW: Locate a prefix-agnostic opening tag, then the next matching close tag. */
static int
xml_element_text(const char *body, const char *name, char *out, size_t capacity)
{
    const char *cursor = body;
    const char *text;
    const char *close;
    size_t length;

    if (body == NULL || capacity == 0) return 0;
    while ((cursor = strchr(cursor, '<')) != NULL
        && !xml_local_name(cursor, name, 0)) cursor++;
    if (cursor == NULL || (text = strchr(cursor, '>')) == NULL) return 0;
    text++;
    close = text;
    while ((close = strchr(close, '<')) != NULL
        && !xml_local_name(close, name, 1)) close++;
    if (close == NULL) return 0;
    length = (size_t) (close - text);
    if (length == 0 || length >= capacity) return 0;
    memcpy(out, text, length);
    out[length] = '\0';
    return 1;
}

/* WHAT: Validate every embedded HTTP status line in a multistatus body.
 * WHY: DAV-009 must not accept malformed or missing per-resource outcomes.
 * HOW: Require one status per response and a three-digit 2xx..5xx code. */
static int
xml_statuses_valid(const char *body)
{
    const char *cursor = body;
    size_t statuses = 0;
    size_t responses = xrd_conform_webdav_xml_count(body, "response");

    if (body == NULL || responses == 0) return 0;
    while ((cursor = strcasestr(cursor, "HTTP/1.1 ")) != NULL) {
        const char *code = cursor + 9;

        if (code[0] < '2' || code[0] > '5'
            || code[1] < '0' || code[1] > '9'
            || code[2] < '0' || code[2] > '9') return 0;
        statuses++;
        cursor = code + 3;
    }
    return statuses >= responses;
}

/* WHAT: Issue one bounded PROPFIND with an exact Depth value.
 * WHY: All four read-only DAV rows share request construction and ceilings.
 * HOW: Send an allprop XML body and return the owned response. */
static int
propfind(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, const char *depth, brix_http_resp *response,
    brix_status *status)
{
    static const char body[] =
        "<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><allprop/>"
        "</propfind>";
    char fields[96];

    snprintf(fields, sizeof(fields),
        "Depth: %s\r\nContent-Type: application/xml\r\n", depth);
    memset(response, 0, sizeof(*response));
    brix_status_clear(status);
    return xrd_conform_http_request_body(execution, url, "PROPFIND", token,
        fields, body, sizeof(body) - 1, 65536, response, status);
}

/* WHAT: Grade Depth 0 cardinality and size.
 * WHY: One adopted object supplies independent GET length and DAV properties.
 * HOW: Require 207, one response and a matching getcontentlength property. */
static void
probe_depth_zero(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, const brix_http_resp *baseline)
{
    brix_http_resp response;
    brix_status status;
    char length_text[64];
    char *end = NULL;
    unsigned long long length = 0;
    int rc;
    int have_length;

    rc = propfind(execution, url, token, "0", &response, &status);
    have_length = rc == 0 && xml_element_text(response.body,
        "getcontentlength", length_text, sizeof(length_text));
    if (have_length) {
        errno = 0;
        length = strtoull(length_text, &end, 10);
        have_length = errno == 0 && end != length_text && *end == '\0';
    }
    if (xrd_conform_row_active(execution, "DAV-001"))
        xrd_conform_grade_received(execution, "DAV-001", rc == 0 && response.status == 207
            && xrd_conform_webdav_xml_count(response.body, "response") == 1,
            "depth-zero-returned-one-response",
            "depth-zero-cardinality-invalid", rc == 0 ? response.reason
                                                        : status.msg);
    if (xrd_conform_row_active(execution, "DAV-004"))
        xrd_conform_grade_received(execution, "DAV-004", rc == 0 && response.status == 207
            && have_length && length == baseline->body_len,
            "dav-content-length-matches-get",
            "dav-content-length-mismatch", have_length ? length_text
                                                         : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

/* WHAT: Grade the finite-depth policy for Depth infinity.
 * WHY: A server must either return a complete multistatus or explicitly refuse.
 * HOW: Accept valid 207 XML or 403, never another partial-looking answer. */
static void
probe_depth_infinity(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    brix_http_resp response;
    brix_status status;
    int rc;
    int pass;

    if (!xrd_conform_row_active(execution, "DAV-003")) return;
    rc = propfind(execution, url, token, "infinity", &response, &status);
    pass = rc == 0 && (response.status == 403
        || (response.status == 207
            && xrd_conform_webdav_xml_count(response.body, "response") == 1
            && xml_statuses_valid(response.body)));
    xrd_conform_grade_received(execution, "DAV-003", pass,
        response.status == 403 ? "infinite-depth-explicitly-refused"
                               : "infinite-depth-complete-multistatus",
        "infinite-depth-partial-or-invalid",
        rc == 0 ? response.reason : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

/* WHAT: Build a WebDAV URL beneath authorized mutation authority.
 * WHY: Collection probes must never derive destinations from adopted content.
 * HOW: Use the common scratch path capability and retain endpoint identity. */
int
xrd_conform_webdav_scratch_url(xrd_conform_execution *execution,
    const brix_weburl *base,
    const char *leaf, brix_weburl *scratch)
{
    char path[XRDC_PATH_MAX];

    if (brix_conform_scratch_path(execution->run->config.scratch, leaf,
            path, sizeof(path)) != 0) return -1;
    *scratch = *base;
    return (size_t) snprintf(scratch->path, sizeof(scratch->path), "%s", path)
        < sizeof(scratch->path) ? 0 : -1;
}

/* WHAT: Issue one body-free mutation and retain its HTTP status.
 * WHY: DAV rows distinguish exact protocol outcomes such as 405 and 412.
 * HOW: Use the bounded shared request seam and immediately free its response. */
int
xrd_conform_webdav_mutation(xrd_conform_execution *execution,
    const brix_weburl *url,
    const char *method, const char *token, const char *fields, int *http_status)
{
    brix_http_resp response;
    brix_status status;
    int rc;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, method, token,
        fields, 4096, &response, &status);
    if (rc != 0) return -1;
    *http_status = response.status;
    brix_http_resp_free(&response);
    return 0;
}

/* WHAT: Remove one scratch resource on a best-effort bounded request.
 * WHY: A failed assertion must not strand its temporary WebDAV resource.
 * HOW: Send DELETE through the same shared request seam and ignore its status. */
void
xrd_conform_webdav_cleanup(xrd_conform_execution *execution,
    const brix_weburl *url,
    const char *token)
{
    int status;

    xrd_conform_webdav_mutation(execution, url, "DELETE", token, NULL,
        &status);
}

/* WHAT: Prove MKCOL on an existing scratch collection returns 405.
 * WHY: Idempotent client wrappers must not hide the wire-level DAV contract.
 * HOW: Create once, create again, xrd_conform_grade_received the second response and clean up. */
static void
probe_existing_collection(xrd_conform_execution *execution,
    const brix_weburl *base, const char *token)
{
    brix_weburl collection;
    int first = 0;
    int second = 0;
    int pass;

    if (!xrd_conform_row_active(execution, "DAV-005")) return;
    if (xrd_conform_webdav_scratch_url(execution, base,
            "brix-conform-dav-existing",
            &collection) != 0) {
        xrd_conform_result_set(execution, "DAV-005",
            BRIX_CONFORM_VERDICT_SKIPPED,
            "fixture-absent:mutable-webdav-collection", NULL, NULL);
        return;
    }
    pass = xrd_conform_webdav_mutation(execution, &collection, "MKCOL",
        token, NULL, &first) == 0
        && (first == 200 || first == 201)
        && xrd_conform_webdav_mutation(execution, &collection, "MKCOL",
            token, NULL, &second) == 0
        && second == 405;
    xrd_conform_grade_received(execution, "DAV-005", pass,
        "mkcol-existing-returned-405", "mkcol-existing-status-invalid",
        pass ? "405" : "not-405");
    xrd_conform_webdav_cleanup(execution, &collection, token);
}

/* WHAT: Format an absolute same-authority WebDAV Destination header.
 * WHY: RFC-4918 requires a URI and IPv6 authorities require bracketing.
 * HOW: Reuse the common host formatter and append the scratch path. */
int
xrd_conform_webdav_destination_fields(const brix_weburl *url, char *fields,
    size_t capacity)
{
    char authority[300];

    if (brix_format_host_port(url->host, (uint16_t) url->port,
            authority, sizeof(authority)) == 0) return -1;
    return (size_t) snprintf(fields, capacity,
        "Destination: %s://%s%s\r\nOverwrite: F\r\n",
        url->tls ? "https" : "http", authority, url->path) < capacity ? 0 : -1;
}

/* WHAT: Issue one body-carrying mutation and retain its HTTP status.
 * WHY: PUT and LOCK probes need the same bounded response ownership rules.
 * HOW: Use the authenticated request seam, save status and free the response. */
static int
body_mutation(xrd_conform_execution *execution, const brix_weburl *url,
    const char *method, const char *token, const char *fields,
    const char *body, int *http_status)
{
    brix_http_resp response;
    brix_status status;
    int rc;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, url, method, token, fields,
        body, strlen(body), 4096, &response, &status);
    if (rc == 0) {
        *http_status = response.status;
        brix_http_resp_free(&response);
    }
    return rc;
}

/* WHAT: Create one scratch object with fixed content.
 * WHY: MOVE overwrite behavior requires independently existing source/target.
 * HOW: PUT a short constant body and accept any successful HTTP status. */
int
xrd_conform_webdav_put_fixture(xrd_conform_execution *execution,
    const brix_weburl *url,
    const char *token, const char *body)
{
    int status = 0;

    return body_mutation(execution, url, "PUT", token, NULL, body, &status) == 0
        && status >= 200 && status < 300 ? 0 : -1;
}

/* WHAT: Prove MOVE with Overwrite:F refuses an existing target.
 * WHY: Silently replacing the target would violate explicit client intent.
 * HOW: Plant two scratch files, send absolute Destination, require 412, clean. */
static void
probe_no_overwrite(xrd_conform_execution *execution, const brix_weburl *base,
    const char *token)
{
    brix_weburl source;
    brix_weburl target;
    char fields[768];
    int status = 0;
    int pass;

    if (!xrd_conform_row_active(execution, "DAV-007")) return;
    if (xrd_conform_webdav_scratch_url(execution, base,
            "brix-conform-dav-source", &source) != 0
        || xrd_conform_webdav_scratch_url(execution, base,
            "brix-conform-dav-target", &target) != 0
        || xrd_conform_webdav_destination_fields(&target, fields,
            sizeof(fields)) != 0) {
        xrd_conform_result_set(execution, "DAV-007",
            BRIX_CONFORM_VERDICT_SKIPPED,
            "fixture-absent:webdav-overwrite-target", NULL, NULL);
        return;
    }
    pass = xrd_conform_webdav_put_fixture(execution, &source, token,
            "source") == 0
        && xrd_conform_webdav_put_fixture(execution, &target, token,
            "target") == 0
        && xrd_conform_webdav_mutation(execution, &source, "MOVE", token,
            fields, &status) == 0
        && status == 412;
    xrd_conform_grade_received(execution, "DAV-007", pass,
        "move-overwrite-f-returned-412", "move-overwrite-f-status-invalid",
        pass ? "412" : "not-412");
    xrd_conform_webdav_cleanup(execution, &source, token);
    xrd_conform_webdav_cleanup(execution, &target, token);
}

/* WHAT: Return whether a Lock-Token is safe to place in a request header.
 * WHY: A hostile peer must not turn its response token into header injection.
 * HOW: Require a non-empty bounded visible-ASCII value without whitespace. */
static int
lock_token_safe(const char *token)
{
    const unsigned char *cursor = (const unsigned char *) token;
    size_t length = 0;

    if (token == NULL || *token == '\0') return 0;
    while (*cursor != '\0') {
        if (*cursor <= 0x20 || *cursor >= 0x7f || ++length > 512) return 0;
        cursor++;
    }
    return 1;
}

/* WHAT: Acquire one exclusive write lock and return its response token.
 * WHY: DAV-010 needs the server-issued capability for an exact UNLOCK.
 * HOW: Send bounded XML, require success, then validate the header value. */
static int
acquire_lock(xrd_conform_execution *execution, const brix_weburl *url,
    const char *token, char lock_token[513])
{
    static const char body[] =
        "<D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:exclusive/>"
        "</D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>";
    brix_http_resp response;
    brix_status status;
    int rc;
    int pass;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, url, "LOCK", token,
        "Content-Type: application/xml\r\nTimeout: Second-60\r\n",
        body, sizeof(body) - 1, 4096, &response, &status);
    pass = rc == 0 && (response.status == 200 || response.status == 201)
        && brix_http_header(&response, "Lock-Token", lock_token, 513)
        && lock_token_safe(lock_token);
    if (rc == 0) brix_http_resp_free(&response);
    return pass ? 0 : -1;
}

/* WHAT: Prove LOCK enforcement and exact-token UNLOCK under scratch.
 * WHY: A lock that does not gate writes or cannot be released is not usable.
 * HOW: Plant, lock, require bare PUT=423, unlock with token, then delete. */
static void
probe_locking(xrd_conform_execution *execution, const brix_weburl *base,
    const char *token)
{
    brix_weburl object;
    char lock_token[513] = "";
    char fields[544];
    int put_status = 0;
    int unlock_status = 0;
    int write_rc = -1;
    int unlock_rc = -1;
    int locked = 0;
    int pass = 0;

    if (!xrd_conform_row_active(execution, "DAV-010")) return;
    if (xrd_conform_webdav_scratch_url(execution, base,
            "brix-conform-dav-lock", &object) != 0) {
        xrd_conform_result_set(execution, "DAV-010",
            BRIX_CONFORM_VERDICT_SKIPPED,
            "fixture-absent:webdav-locking-scratch", NULL, NULL);
        return;
    }
    if (xrd_conform_webdav_put_fixture(execution, &object, token,
            "locked") == 0
        && acquire_lock(execution, &object, token, lock_token) == 0) {
        locked = 1;
        write_rc = body_mutation(execution, &object, "PUT", token, NULL,
            "replace", &put_status);
        if ((size_t) snprintf(fields, sizeof(fields), "Lock-Token: %s\r\n",
                lock_token) < sizeof(fields))
            unlock_rc = xrd_conform_webdav_mutation(execution, &object,
                "UNLOCK", token, fields, &unlock_status);
    }
    pass = locked && write_rc == 0 && put_status == 423 && unlock_rc == 0
        && (unlock_status == 200 || unlock_status == 204);
    xrd_conform_grade_received(execution, "DAV-010", pass,
        "lock-gated-write-and-unlocked", "lock-enforcement-or-unlock-failed",
        pass ? "PUT=423 UNLOCK=success" : "locking-contract-mismatch");
    xrd_conform_webdav_cleanup(execution, &object, token);
}

/* WHAT: Submit an external-entity XML document and require refusal.
 * WHY: Expanding attacker-controlled entities permits file disclosure and SSRF.
 * HOW: Use a local file URI, require 4xx and reject common passwd reflection. */
static void
probe_external_entity(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token)
{
    static const char body[] =
        "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM "
        "\"file:///etc/passwd\">]><D:propfind xmlns:D=\"DAV:\">"
        "<D:prop><e/></D:prop></D:propfind>";
    brix_http_resp response;
    brix_status status;
    int rc;
    int pass;

    if (!xrd_conform_row_active(execution, "DAV-011")) return;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, url, "PROPFIND", token,
        "Depth: 0\r\nContent-Type: application/xml\r\n",
        body, sizeof(body) - 1, 4096, &response, &status);
    pass = rc == 0 && response.status >= 400 && response.status < 500
        && (response.body == NULL
            || (strstr(response.body, "root:x:") == NULL
                && strstr(response.body, "daemon:") == NULL));
    xrd_conform_grade_received(execution, "DAV-011", pass,
        "external-entity-document-refused",
        "external-entity-document-accepted-or-reflected",
        rc == 0 ? response.reason : status.msg);
    if (rc == 0) brix_http_resp_free(&response);
}

/* WHAT: Run safe adopted-object WebDAV probes and classify missing fixtures.
 * WHY: No mutation or external-entity request may occur without its authority.
 * HOW: Execute the local probes, then gate only topology rows not finalized
 * by the shared ROOT/WebDAV namespace reconciler. */
void
xrd_conform_probe_webdav(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const brix_http_resp *baseline)
{
    const brix_conform_result *rm008 = xrd_conform_result_find(execution,
        "RM-008");

    if (!xrd_conform_family_active(execution, "DAV")) {
        if (rm008 != NULL && rm008->verdict != BRIX_CONFORM_VERDICT_SKIPPED)
            xrd_conform_probe_webdav_delete(execution, url, token);
        return;
    }
    probe_depth_zero(execution, url, token, baseline);
    probe_depth_infinity(execution, url, token);
    probe_existing_collection(execution, url, token);
    probe_no_overwrite(execution, url, token);
    xrd_conform_probe_webdav_outside(execution, url, token);
    probe_locking(execution, url, token);
    probe_external_entity(execution, url, token);
    xrd_conform_probe_webdav_multistatus(execution, url, token);
    xrd_conform_probe_webdav_delete(execution, url, token);
}
