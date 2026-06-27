/*
 * vfs_s3_mpu.c - extracted concern
 * Phase-38 split of vfs_s3.c; behavior-identical.
 */
#include "vfs_s3_internal.h"


/* MPU: upload one part */
/*
 * s3_mpu_upload_part — upload a single MPU part and save its ETag.
 *
 * WHAT: PUTs `data[0..len)` as part number `part_num` of the active upload;
 *       extracts the ETag from the 200 response header and stores it in
 *       sf->etags[part_num - 1].
 * WHY:  each UploadPart call must be made when the part buffer is full (or the
 *       last partial part at commit time); the returned ETag is mandatory in the
 *       CompleteMultipartUpload XML body.
 * HOW:  build the wire path "/key?partNumber=N&uploadId=ID"; sign with canon_qs
 *       "partNumber=N&uploadId=ID" (sorted: p < u); PUT via xrdc_http_req;
 *       extract ETag header; grow etags array; advance part_count.
 */
int
s3_mpu_upload_part(vfs_s3_file *sf, int part_num,
                   const void *data, size_t len,
                   xrdc_status *st)
{
    char           wire_path[XRDC_PATH_MAX + 256];
    char           canon_qs[256];
    char           auth_hdrs[S3_AUTH_HDRS_CAP];
    xrdc_http_resp resp;
    char           etag_val[S3_ETAG_LEN];
    int            pn = snprintf(wire_path, sizeof(wire_path),
                                 "%s?partNumber=%d&uploadId=%s",
                                 sf->key_path, part_num, sf->upload_id);

    if (pn < 0 || (size_t) pn >= sizeof(wire_path)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "s3 mpu: part path too long");
        return -1;
    }
    /* Canonical query string: partNumber=N&uploadId=ID (p < u → already sorted) */
    pn = snprintf(canon_qs, sizeof(canon_qs),
                  "partNumber=%d&uploadId=%s", part_num, sf->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(canon_qs)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "s3 mpu: canon_qs too long");
        return -1;
    }

    if (s3_sign(sf, "PUT", canon_qs, auth_hdrs, sizeof(auth_hdrs), st) != 0) {
        return -1;
    }
    if (xrdc_http_req(sf->host, sf->port, sf->tls, "PUT", wire_path,
                      auth_hdrs, data, len, S3_REQ_TIMEOUT_MS, 0, NULL,
                      &resp, st) != 0) {
        return -1;
    }
    if (resp.status != 200) {
        int rc = s3_http_err(resp.status, "UploadPart", sf->key_path, st);
        xrdc_http_resp_free(&resp);
        return rc;
    }
    /* Extract ETag from response header for CompleteMultipartUpload XML */
    etag_val[0] = '\0';
    xrdc_http_header(&resp, "ETag", etag_val, sizeof(etag_val));
    if (etag_val[0] == '\0') {
        xrdc_status_set(st, XRDC_EIO, 0,
                        "s3 UploadPart: server returned no ETag");
        xrdc_http_resp_free(&resp);
        return -1;
    }
    xrdc_http_resp_free(&resp);

    if (s3_etag_ensure_cap(sf, part_num, st) != 0) {
        return -1;
    }
    snprintf(sf->etags[part_num - 1].val, S3_ETAG_LEN, "%s", etag_val);
    sf->part_count = part_num;
    return 0;
}


/* MPU: flush part buffer */
/*
 * s3_mpu_flush_part_buf — upload the current part buffer and reset it.
 *
 * WHAT: calls s3_mpu_upload_part for sf->part_buf[0..sf->part_buf_len),
 *       then resets sf->part_buf_len to 0 for the next part.
 * WHY:  deduplicates the flush-on-full and flush-at-commit paths.
 * HOW:  guard on part_buf_len > 0 (skip empty flush); delegate; reset.
 */
int
s3_mpu_flush_part_buf(vfs_s3_file *sf, xrdc_status *st)
{
    int next_part;

    if (sf->part_buf_len == 0) {
        return 0;   /* nothing to flush */
    }
    next_part = sf->part_count + 1;
    if (s3_mpu_upload_part(sf, next_part, sf->part_buf, sf->part_buf_len,
                           st) != 0) {
        return -1;
    }
    sf->part_buf_len = 0;
    return 0;
}


/* MPU: CreateMultipartUpload */
/*
 * s3_mpu_create — issue POST /key?uploads to initiate a multipart upload.
 *
 * WHAT: sends a signed POST with the "uploads=" bare-flag query parameter;
 *       extracts the <UploadId> from the XML response body.
 * WHY:  multipart upload begins with this handshake; the UploadId is used in
 *       every subsequent UploadPart and CompleteMultipartUpload request.
 * HOW:  sign with canon_qs="uploads="; POST wire path "/key?uploads"; parse
 *       <UploadId> from resp.body with xml_extract_tag; store in sf->upload_id.
 */
int
s3_mpu_create(vfs_s3_file *sf, xrdc_status *st)
{
    char           wire_path[XRDC_PATH_MAX + 16];
    char           auth_hdrs[S3_AUTH_HDRS_CAP];
    xrdc_http_resp resp;
    int            pn = snprintf(wire_path, sizeof(wire_path),
                                 "%s?uploads", sf->key_path);

    if (pn < 0 || (size_t) pn >= sizeof(wire_path)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "s3 mpu: key path too long");
        return -1;
    }
    /* canon_qs for ?uploads bare flag: "uploads=" per SigV4 spec */
    if (s3_sign(sf, "POST", "uploads=", auth_hdrs, sizeof(auth_hdrs), st) != 0) {
        return -1;
    }
    if (xrdc_http_req(sf->host, sf->port, sf->tls, "POST", wire_path,
                      auth_hdrs, NULL, 0, S3_REQ_TIMEOUT_MS, 0, NULL,
                      &resp, st) != 0) {
        return -1;
    }
    if (resp.status != 200) {
        int rc = s3_http_err(resp.status, "CreateMultipartUpload",
                             sf->key_path, st);
        xrdc_http_resp_free(&resp);
        return rc;
    }
    if (resp.body == NULL || resp.body_len == 0) {
        xrdc_http_resp_free(&resp);
        xrdc_status_set(st, XRDC_EIO, 0,
                        "s3 CreateMultipartUpload: empty response body");
        return -1;
    }
    if (xml_extract_tag(resp.body, "UploadId",
                        sf->upload_id, sizeof(sf->upload_id)) != 0) {
        xrdc_http_resp_free(&resp);
        xrdc_status_set(st, XRDC_EIO, 0,
                        "s3 CreateMultipartUpload: <UploadId> not found in "
                        "response");
        return -1;
    }
    xrdc_http_resp_free(&resp);
    return 0;
}


/* MPU: CompleteMultipartUpload */
/*
 * s3_mpu_complete_xml_size — compute the exact size of the CompleteMultipartUpload
 * XML body for `n_parts` parts (without including the actual ETag values).
 *
 * WHAT: pre-calculates the buffer size needed for the XML body.
 * WHY:  avoids a realloc loop when building the XML string.
 * HOW:  fixed preamble + per-part overhead (part number + ETag length estimate) +
 *       closing tag.  Uses S3_ETAG_LEN as an upper bound per part.
 */
size_t
s3_mpu_complete_xml_size(int n_parts)
{
    /* preamble + postamble */
    size_t base = 120;
    /* per part: "<Part><PartNumber>NNNNN</PartNumber><ETag>...</ETag></Part>\n" */
    size_t per_part = 60 + S3_ETAG_LEN;

    return base + (size_t) n_parts * per_part + 1;
}


/*
 * s3_mpu_complete — build + send CompleteMultipartUpload XML body.
 *
 * WHAT: POST /key?uploadId=ID with an XML body listing all parts by PartNumber
 *       and ETag; checks for a 200 response.
 * WHY:  finalises the multipart upload — the server assembles the parts into the
 *       final object in part-number order.
 * HOW:  malloc XML buffer; snprintf each <Part>; sign with canon_qs "uploadId=ID";
 *       POST; check 200.  The server ignores the XML body (it assembles by scanning
 *       part.N files in order), but we send it for S3 spec compliance.
 */
int
s3_mpu_complete(vfs_s3_file *sf, xrdc_status *st)
{
    char           wire_path[XRDC_PATH_MAX + S3_UPLOAD_ID_LEN + 16];
    char           canon_qs[S3_UPLOAD_ID_LEN + 16];
    char           auth_hdrs[S3_AUTH_HDRS_CAP];
    xrdc_http_resp resp;
    char          *xml;
    size_t         xml_cap;
    size_t         xml_len;
    int            i;
    int            pn;

    pn = snprintf(wire_path, sizeof(wire_path),
                  "%s?uploadId=%s", sf->key_path, sf->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(wire_path)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "s3 complete mpu: path too long");
        return -1;
    }
    pn = snprintf(canon_qs, sizeof(canon_qs), "uploadId=%s", sf->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(canon_qs)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "s3 complete mpu: canon_qs too long");
        return -1;
    }

    xml_cap = s3_mpu_complete_xml_size(sf->part_count);
    xml = malloc(xml_cap);
    if (xml == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 complete mpu: out of memory for XML");
        return -1;
    }

    /* Build CompleteMultipartUpload XML */
    xml_len = (size_t) snprintf(xml, xml_cap,
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<CompleteMultipartUpload>\n");
    for (i = 0; i < sf->part_count; i++) {
        int written = snprintf(xml + xml_len, xml_cap - xml_len,
                               "  <Part><PartNumber>%d</PartNumber>"
                               "<ETag>%s</ETag></Part>\n",
                               i + 1, sf->etags[i].val);
        if (written < 0 || (size_t) written >= xml_cap - xml_len) {
            free(xml);
            xrdc_status_set(st, XRDC_EIO, 0,
                            "s3 complete mpu: XML buffer overflow");
            return -1;
        }
        xml_len += (size_t) written;
    }
    {
        int tail = snprintf(xml + xml_len, xml_cap - xml_len,
                            "</CompleteMultipartUpload>\n");
        if (tail < 0 || (size_t) tail >= xml_cap - xml_len) {
            free(xml);
            xrdc_status_set(st, XRDC_EIO, 0,
                            "s3 complete mpu: XML buffer overflow (tail)");
            return -1;
        }
        xml_len += (size_t) tail;
    }

    if (s3_sign(sf, "POST", canon_qs, auth_hdrs, sizeof(auth_hdrs), st) != 0) {
        free(xml);
        return -1;
    }
    if (xrdc_http_req(sf->host, sf->port, sf->tls, "POST", wire_path,
                      auth_hdrs, xml, xml_len, S3_REQ_TIMEOUT_MS, 0, NULL,
                      &resp, st) != 0) {
        free(xml);
        return -1;
    }
    free(xml);

    if (resp.status != 200) {
        int rc = s3_http_err(resp.status, "CompleteMultipartUpload",
                             sf->key_path, st);
        xrdc_http_resp_free(&resp);
        return rc;
    }
    xrdc_http_resp_free(&resp);
    return 0;
}


/* MPU: AbortMultipartUpload */
/*
 * s3_mpu_abort_upload — send DELETE /key?uploadId=ID (AbortMultipartUpload).
 *
 * WHAT: cleans up the server-side staging directory for the active upload.
 * WHY:  a failed or cancelled write must not leave orphan parts consuming
 *       server disk space.
 * HOW:  sign + DELETE; a 204 No Content response indicates success.  Errors are
 *       logged but do not make abort() fail (the local state is already torn down).
 */
void
s3_mpu_abort_upload(vfs_s3_file *sf)
{
    char           wire_path[XRDC_PATH_MAX + S3_UPLOAD_ID_LEN + 16];
    char           canon_qs[S3_UPLOAD_ID_LEN + 16];
    char           auth_hdrs[S3_AUTH_HDRS_CAP];
    xrdc_http_resp resp;
    xrdc_status    st;
    int            pn;

    if (sf->upload_id[0] == '\0') {
        return;   /* CreateMultipartUpload never completed; nothing to abort */
    }
    xrdc_status_clear(&st);

    pn = snprintf(wire_path, sizeof(wire_path),
                  "%s?uploadId=%s", sf->key_path, sf->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(wire_path)) {
        return;   /* path too long — best-effort cleanup only */
    }
    pn = snprintf(canon_qs, sizeof(canon_qs), "uploadId=%s", sf->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(canon_qs)) {
        return;
    }
    if (s3_sign(sf, "DELETE", canon_qs, auth_hdrs, sizeof(auth_hdrs), &st) != 0) {
        return;
    }
    if (xrdc_http_req(sf->host, sf->port, sf->tls, "DELETE", wire_path,
                      auth_hdrs, NULL, 0, S3_REQ_TIMEOUT_MS, 0, NULL,
                      &resp, &st) != 0) {
        return;
    }
    /* 204 = success; anything else is a best-effort failure — we cannot retry. */
    xrdc_http_resp_free(&resp);
}
