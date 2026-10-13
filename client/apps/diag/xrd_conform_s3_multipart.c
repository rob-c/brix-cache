/* Phase-118 S3 multipart-upload conformance probes. */
#include "xrd_conform_internal.h"
#include "core/compat/uri.h"

#define S3_MULTIPART_MIN_PART (5U * 1024U * 1024U)
#define S3_UPLOAD_ID_MAX 1024

typedef struct {
    xrd_conform_execution *execution;
    brix_weburl            object;
    char                   upload_id[S3_UPLOAD_ID_MAX];
} s3_multipart;

/* ---- Decide whether a scoped result row is executable ----
 *
 * WHAT: Returns one only for an existing row that was not safety-skipped.
 * WHY: Multipart requests must never bypass registry scope or mutate authority.
 * HOW: Find the result and inspect its precomputed skip verdict.
 */
static int
row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

/* ---- Extract one bounded XML element without entity interpretation ----
 *
 * WHAT: Copies the first exact element value and returns one, zero, or -1.
 * WHY: Upload identifiers are server-controlled and must not overflow a query.
 * HOW: Locate literal tags, measure their enclosed bytes, and copy if bounded.
 */
static int
xml_value(const char *body, const char *tag, char *out, size_t out_size)
{
    char open[64];
    char close[64];
    const char *start;
    const char *end;
    size_t length;

    if (snprintf(open, sizeof(open), "<%s>", tag) < 0
        || snprintf(close, sizeof(close), "</%s>", tag) < 0) return -1;
    start = body == NULL ? NULL : strstr(body, open);
    if (start == NULL) return 0;
    start += strlen(open);
    end = strstr(start, close);
    if (end == NULL) return 0;
    length = (size_t) (end - start);
    if (length == 0 || length >= out_size) return -1;
    memcpy(out, start, length);
    out[length] = '\0';
    return 1;
}

/* ---- Validate a response-derived upload identifier ----
 *
 * WHAT: Returns one for non-empty visible ASCII without XML metacharacters.
 * WHY: A hostile identifier must not inject a query, control byte, or XML body.
 * HOW: Walk the bounded string and reject controls, spaces, ampersand and tags.
 */
static int
upload_id_safe(const char *value)
{
    const unsigned char *cursor = (const unsigned char *) value;

    if (*cursor == '\0') return 0;
    while (*cursor != '\0') {
        if (*cursor <= 0x20 || *cursor >= 0x7f || *cursor == '&'
            || *cursor == '<' || *cursor == '>') return 0;
        cursor++;
    }
    return 1;
}

/* ---- Build a canonical multipart query URL ----
 *
 * WHAT: Returns zero after appending an encoded upload id and optional part.
 * WHY: SigV4 signs the exact sorted query sent on the wire.
 * HOW: RFC-3986 encode the opaque id, then format canonical parameter order.
 */
static int
multipart_url(const s3_multipart *upload, unsigned part, brix_weburl *out)
{
    char encoded[S3_UPLOAD_ID_MAX * 3];
    int written;

    if (brix_http_urlencode((const unsigned char *) upload->upload_id,
            strlen(upload->upload_id), encoded, sizeof(encoded), "") < 0)
        return -1;
    *out = upload->object;
    written = part == 0
        ? snprintf(out->path, sizeof(out->path), "%s?uploadId=%s",
            upload->object.path, encoded)
        : snprintf(out->path, sizeof(out->path),
            "%s?partNumber=%u&uploadId=%s", upload->object.path, part,
            encoded);
    return written < 0 || (size_t) written >= sizeof(out->path) ? -1 : 0;
}

/* ---- Initiate one scratch-confined multipart upload ----
 *
 * WHAT: Returns zero with a bounded safe UploadId after an HTTP success.
 * WHY: Every later multipart operation must be tied to an explicit capability.
 * HOW: Build the scratch path, POST the initiation query, and parse its XML.
 */
static int
multipart_start(xrd_conform_execution *execution, const brix_weburl *base,
    const char *leaf, s3_multipart *upload)
{
    brix_weburl request = *base;
    brix_http_resp response;
    brix_status status;
    char path[XRDC_PATH_MAX];
    int rc;

    memset(upload, 0, sizeof(*upload));
    upload->execution = execution;
    upload->object = *base;
    if (brix_conform_scratch_path(execution->run->config.scratch, leaf, path,
            sizeof(path)) != 0
        || (size_t) snprintf(upload->object.path,
            sizeof(upload->object.path), "%s", path)
            >= sizeof(upload->object.path)
        || (size_t) snprintf(request.path, sizeof(request.path), "%s?uploads=",
            path) >= sizeof(request.path)) return -1;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(execution, &request, "POST", NULL,
        NULL, NULL, 0, 4096, &response, &status);
    if (rc != 0 || response.status < 200 || response.status >= 300
        || xml_value(response.body, "UploadId", upload->upload_id,
            sizeof(upload->upload_id)) != 1
        || !upload_id_safe(upload->upload_id)) {
        if (rc == 0) brix_http_resp_free(&response);
        return -1;
    }
    brix_http_resp_free(&response);
    return 0;
}

/* ---- Upload one numbered part and retain its server ETag ----
 *
 * WHAT: Returns zero for a 2xx part PUT with a bounded non-empty ETag header.
 * WHY: CompleteMultipartUpload must name exactly the accepted part versions.
 * HOW: Build the canonical query, PUT bounded bytes, and copy the response ETag.
 */
static int
multipart_put(s3_multipart *upload, unsigned part, const void *body,
    size_t body_length, char etag[128])
{
    brix_weburl request;
    brix_http_resp response;
    brix_status status;
    int rc;

    if (multipart_url(upload, part, &request) != 0) return -1;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(upload->execution, &request, "PUT",
        NULL, NULL, body, body_length, 0, &response, &status);
    if (rc != 0 || response.status < 200 || response.status >= 300
        || brix_http_header(&response, "ETag", etag, 128) != 1
        || etag[0] == '\0') {
        if (rc == 0) brix_http_resp_free(&response);
        return -1;
    }
    brix_http_resp_free(&response);
    return 0;
}

/* ---- Submit a complete manifest and classify its response ----
 *
 * WHAT: Returns the HTTP status, or -1 on local/transport failure, and copies
 *       the result ETag when present.
 * WHY: The three rows distinguish successful assembly from two exact refusals.
 * HOW: POST the caller-built manifest to the upload id and inspect response XML.
 */
static int
multipart_complete(s3_multipart *upload, const char *manifest,
    char result_etag[128])
{
    brix_weburl request;
    brix_http_resp response;
    brix_status status;
    int rc;
    int response_status;

    result_etag[0] = '\0';
    if (multipart_url(upload, 0, &request) != 0) return -1;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_body(upload->execution, &request, "POST",
        NULL, "Content-Type: application/xml\r\n", manifest,
        strlen(manifest), 4096, &response, &status);
    if (rc != 0) return -1;
    response_status = response.status;
    (void) xml_value(response.body, "ETag", result_etag, 128);
    brix_http_resp_free(&response);
    return response_status;
}

/* ---- Format an exact two-part completion manifest ----
 *
 * WHAT: Returns zero with complete XML, or -1 on formatting truncation.
 * WHY: A truncated diagnostic request cannot be used as a protocol oracle.
 * HOW: Format both part numbers and caller-provided bounded ETags, then size-check.
 */
static int
two_part_manifest(char *out, size_t out_size, const char *etag1,
    const char *etag2)
{
    int written = snprintf(out, out_size,
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
        "<ETag>%s</ETag></Part><Part><PartNumber>2</PartNumber>"
        "<ETag>%s</ETag></Part></CompleteMultipartUpload>", etag1, etag2);

    return written < 0 || (size_t) written >= out_size ? -1 : 0;
}

/* ---- Delete an object or abort its still-live multipart upload ----
 *
 * WHAT: Best-effort cleanup of the object and optional upload id.
 * WHY: Every mutation remains scratch-confined and leaves no assessor residue.
 * HOW: DELETE the upload query first, then DELETE the final object path.
 */
static void
multipart_cleanup(s3_multipart *upload, int abort_upload)
{
    brix_weburl targets[2];
    size_t count = 1;
    size_t index;

    targets[0] = upload->object;
    if (abort_upload && multipart_url(upload, 0, &targets[1]) == 0) count = 2;
    for (index = count; index > 0; index--) {
        brix_http_resp response;
        brix_status status;

        memset(&response, 0, sizeof(response));
        brix_status_clear(&status);
        if (xrd_conform_http_request_fields(upload->execution,
                &targets[index - 1], "DELETE", NULL, NULL, 0, &response,
                &status) == 0) brix_http_resp_free(&response);
    }
}

/* ---- Verify the successfully completed object byte-for-byte ----
 *
 * WHAT: Returns one only for part-one bytes followed by part-two bytes.
 * WHY: Upload order must not override the ordered completion manifest.
 * HOW: GET the object once, check exact length, then compare both regions.
 */
static int
multipart_get_matches(s3_multipart *upload, const uint8_t *first,
    size_t first_length, const uint8_t *second, size_t second_length)
{
    brix_http_resp response;
    brix_status status;
    size_t expected = first_length + second_length;
    int rc;
    int matches;

    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(upload->execution, &upload->object,
        "GET", NULL, NULL, expected, &response, &status);
    matches = rc == 0 && response.status == 200
        && response.body_len == expected
        && memcmp(response.body, first, first_length) == 0
        && memcmp(response.body + first_length, second, second_length) == 0;
    if (rc == 0) brix_http_resp_free(&response);
    return matches;
}

/* ---- Exercise successful out-of-order assembly and multipart ETag ----
 *
 * WHAT: Returns one for exact assembly and writes whether ETag has `-2` form.
 * WHY: S3-011 and S3-013 share one authoritative successful lifecycle.
 * HOW: Upload part 2 before part 1, complete in 1/2 order, GET, then clean.
 */
static int
probe_successful_multipart(xrd_conform_execution *execution,
    const brix_weburl *url, int *etag_ok)
{
    s3_multipart upload;
    uint8_t *first = malloc(S3_MULTIPART_MIN_PART);
    static const uint8_t second[] = { 'e', 'n', 'd' };
    char etag1[128];
    char etag2[128];
    char result_etag[128];
    char manifest[768];
    int status;
    int pass = 0;

    *etag_ok = 0;
    if (first == NULL) return -1;
    brix_conform_fill(&execution->run->key, 0, first,
        S3_MULTIPART_MIN_PART);
    if (multipart_start(execution, url, "brix-conform-s3-multipart",
            &upload) != 0) {
        free(first);
        return -1;
    }
    if (multipart_put(&upload, 2, second, sizeof(second), etag2) == 0
        && multipart_put(&upload, 1, first, S3_MULTIPART_MIN_PART, etag1) == 0
        && two_part_manifest(manifest, sizeof(manifest), etag1, etag2) == 0) {
        status = multipart_complete(&upload, manifest, result_etag);
        *etag_ok = status >= 200 && status < 300
            && strstr(result_etag, "-2") != NULL;
        pass = status >= 200 && status < 300
            && multipart_get_matches(&upload, first,
                S3_MULTIPART_MIN_PART, second, sizeof(second));
    }
    multipart_cleanup(&upload, !pass);
    free(first);
    return pass;
}

/* ---- Require completion to reject a referenced missing part ----
 *
 * WHAT: Returns one only when a manifest naming an absent part is HTTP 400.
 * WHY: Silent omission would publish an object different from the manifest.
 * HOW: Upload part one, request parts one and two, then abort the upload.
 */
static int
probe_missing_part(xrd_conform_execution *execution, const brix_weburl *url)
{
    s3_multipart upload;
    char etag[128];
    char ignored[128];
    char manifest[640];
    const char byte = 'x';
    int status = -1;

    if (multipart_start(execution, url, "brix-conform-s3-missing-part",
            &upload) != 0) return 0;
    if (multipart_put(&upload, 1, &byte, 1, etag) == 0
        && two_part_manifest(manifest, sizeof(manifest), etag,
            "\"absent\"") == 0)
        status = multipart_complete(&upload, manifest, ignored);
    multipart_cleanup(&upload, 1);
    return status == 400;
}

/* ---- Require a sub-minimum non-final part to fail at completion ----
 *
 * WHAT: Returns one only when two one-byte parts cannot be completed.
 * WHY: S3 permits a small final part, never a small earlier part.
 * HOW: Upload both small parts, complete in order, require 400, then abort.
 */
static int
probe_small_nonfinal(xrd_conform_execution *execution, const brix_weburl *url)
{
    s3_multipart upload;
    char etag1[128];
    char etag2[128];
    char ignored[128];
    char manifest[768];
    const char bytes[] = { 'a', 'b' };
    int status = -1;

    if (multipart_start(execution, url, "brix-conform-s3-small-part",
            &upload) != 0) return 0;
    if (multipart_put(&upload, 1, bytes, 1, etag1) == 0
        && multipart_put(&upload, 2, bytes + 1, 1, etag2) == 0
        && two_part_manifest(manifest, sizeof(manifest), etag1, etag2) == 0)
        status = multipart_complete(&upload, manifest, ignored);
    multipart_cleanup(&upload, 1);
    return status == 400;
}

/* ---- Mark all executable multipart rows as lacking a fixture ----
 *
 * WHAT: Converts each active multipart row to an explicit fixture skip.
 * WHY: An endpoint without multipart support is not evidence of divergence.
 * HOW: Iterate the fixed row set and preserve any prior safety skip.
 */
static void
skip_multipart_rows(xrd_conform_execution *execution)
{
    const char *const ids[] = { "S3-011", "S3-012", "S3-013" };
    size_t index;

    for (index = 0; index < 3; index++)
        if (row_active(execution, ids[index]))
            xrd_conform_result_set(execution, ids[index],
                BRIX_CONFORM_VERDICT_SKIPPED,
                "fixture-absent:s3-multipart-upload", NULL, NULL);
}

/* ---- Grade multipart assembly and missing-part behavior ----
 *
 * WHAT: Sets S3-011 from its successful and hostile observations.
 * WHY: Both halves are required by the single ledger assertion.
 * HOW: Require exact assembly and an HTTP-400 missing-part completion.
 */
static void
grade_multipart_assembly(xrd_conform_execution *execution, int success,
    int missing_rejected)
{
    int pass;

    if (!row_active(execution, "S3-011")) return;
    pass = success && missing_rejected;
    xrd_conform_result_set(execution, "S3-011",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "s3-multipart-order-and-missing-part-correct"
             : "s3-multipart-assembly-or-missing-part-invalid",
        "out-of-order PUTs assemble by manifest; missing part returns 400",
        NULL);
}

/* ---- Grade multipart size enforcement ----
 *
 * WHAT: Sets S3-012 from the small-nonfinal completion response.
 * WHY: The final-part exception must not leak to earlier parts.
 * HOW: Require the controlled two-small-part completion to return HTTP 400.
 */
static void
grade_multipart_size(xrd_conform_execution *execution, int small_rejected)
{
    if (!row_active(execution, "S3-012")) return;
    xrd_conform_result_set(execution, "S3-012",
        small_rejected ? BRIX_CONFORM_VERDICT_CONFORMANT
                       : BRIX_CONFORM_VERDICT_DIVERGENT,
        small_rejected ? "s3-small-nonfinal-part-rejected"
                       : "s3-small-nonfinal-part-accepted",
        "sub-5-MiB non-final part returns 400 at completion", NULL);
}

/* ---- Grade multipart ETag shape ----
 *
 * WHAT: Sets S3-013 from a successful two-part completion ETag.
 * WHY: Multipart identifiers must not be interpreted as ordinary MD5 values.
 * HOW: Require success and the part-count suffix observed by the lifecycle.
 */
static void
grade_multipart_etag(xrd_conform_execution *execution, int success,
    int etag_ok)
{
    int pass;

    if (!row_active(execution, "S3-013")) return;
    pass = success && etag_ok;
    xrd_conform_result_set(execution, "S3-013",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "s3-multipart-etag-has-part-count"
             : "s3-multipart-etag-shape-invalid",
        "completed two-part ETag contains -2", NULL);
}

/* ---- Run the S3 multipart semantic trio ----
 *
 * WHAT: Grades S3-011, S3-012 and S3-013 from isolated scratch lifecycles.
 * WHY: Assembly, size enforcement and ETag shape require related but distinct
 *      negative oracles rather than one happy-path multipart request.
 * HOW: Run success, missing-part and small-nonfinal cases, grade, and clean.
 */
void
xrd_conform_probe_s3_multipart(xrd_conform_execution *execution,
    const brix_weburl *url)
{
    int etag_ok;
    int success;
    int missing_rejected;
    int small_rejected;

    if (!url->is_s3 || (!row_active(execution, "S3-011")
        && !row_active(execution, "S3-012")
        && !row_active(execution, "S3-013"))) return;
    success = probe_successful_multipart(execution, url, &etag_ok);
    if (success < 0) {
        skip_multipart_rows(execution);
        return;
    }
    missing_rejected = probe_missing_part(execution, url);
    small_rejected = probe_small_nonfinal(execution, url);
    grade_multipart_assembly(execution, success, missing_rejected);
    grade_multipart_size(execution, small_rejected);
    grade_multipart_etag(execution, success, etag_ok);
}
