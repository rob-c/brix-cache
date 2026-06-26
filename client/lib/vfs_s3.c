/* client/lib/vfs_s3.c
 *
 * WHAT: S3/object-store storage backend for xrdc_vfs.
 *       Provides read (SigV4-signed ranged GET) and write (single PUT for small
 *       objects with known size; multipart upload otherwise) over the S3 REST API.
 * WHY:  The copy engine needs a VFS-uniform seam for S3 endpoints — the same
 *       xrdc_vfs_open/pread/pwrite/commit/close surface used for local POSIX and
 *       block-device backends.  Note: this overlaps copy_web's S3 path deliberately;
 *       both coexist until task C3 rewires the copy engine to route through the VFS
 *       seam (accepted plan decision).
 * HOW:  open(READ) stores URL parts + creds; pread signs+issues a ranged GET via
 *       xrdc_http_req.  open(WRITE) picks single-PUT (expected_size>=0 && small)
 *       or multipart (MPU): MPU issues CreateMultipartUpload, PutPart on each full
 *       part buffer flush, CompleteMultipartUpload on commit.  abort() calls
 *       AbortMultipartUpload or discards the single-PUT buffer.
 *       SigV4 signing reuses xrdc_s3_sign_v4_q (s3.c) — NOT reinvented here.
 *       HTTP transport is xrdc_http_req (http.c) for all operations.
 *       Capabilities: no RANDOM_WRITE (append/stream only), no ATOMIC_TEMP
 *       (native S3 commit, not rename).
 *       ngx-free; no goto; functional/modular; one responsibility per function.
 */

#include "vfs.h"
#include "xrdc.h"
#include "compat/host_format.h"   /* xrootd_format_host_port for SigV4 host header */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Constants ----------------------------------------------------------- */

/*
 * S3_PART_MAX_DEFAULT — default maximum bytes per multipart upload part (64 MiB).
 * WHAT: The threshold that determines single-PUT vs MPU, and the MPU part buffer size.
 * WHY:  AWS S3 requires parts >= 5 MiB (except the last); 64 MiB is a good production
 *       default that keeps part counts low for large files.
 * HOW:  Overridden at runtime via S3_PART_MAX_OVERRIDE env for testing small objects.
 */
#define S3_PART_MAX_DEFAULT  (64LL * 1024 * 1024)
#define S3_PART_MAX_ENV      "S3_PART_MAX_OVERRIDE"

/*
 * S3_PREAD_MAX — maximum bytes requested in a single ranged GET.
 * WHAT: Caps a single pread to stay within xrdc_http_req's 8 MiB response ceiling
 *       (XRDC_HTTPX_MAX in http.c = 8 MiB, minus header overhead).
 * WHY:  xrdc_http_req buffers the full response; exceeding the ceiling returns an
 *       error rather than truncating silently.  Callers handle short pread returns.
 * HOW:  7 MiB leaves 1 MiB headroom for response headers.
 */
#define S3_PREAD_MAX         (7LL * 1024 * 1024)

#define S3_REQ_TIMEOUT_MS    300000   /* 5 min — matches XRDC_WEB_TIMEOUT_MS */
#define S3_AUTH_HDRS_CAP     4096     /* SigV4 header block buffer size */
#define S3_ETAG_LEN          96       /* ETag value from UploadPart response */
#define S3_UPLOAD_ID_LEN     128      /* upload_id from CreateMultipartUpload */
#define S3_ETAG_INIT_CAP     16       /* initial per-part ETag array capacity */
#define S3_PUT_BUF_INIT      (64 * 1024)  /* initial single-PUT buffer (64 KiB) */
#define S3_REGION_DEFAULT    "us-east-1"

/* ---- Per-part ETag record ------------------------------------------------ */

/*
 * s3_part_etag — holds the ETag string returned by UploadPart.
 *
 * WHAT: stores the raw ETag header value (including surrounding quotes when the
 *       server emits them, e.g. `"\"1234-5678\""`).
 * WHY:  CompleteMultipartUpload XML requires each part's ETag from the server.
 * HOW:  extracted from the response ETag header via xrdc_http_header().
 */
typedef struct {
    char val[S3_ETAG_LEN];
} s3_part_etag;

/* ---- Concrete per-handle struct ----------------------------------------- */

/*
 * vfs_s3_file — concrete file handle for the S3 backend.
 *
 * WHAT: extends xrdc_vfs_file with all S3 state: URL parts, credentials, and
 *       per-mode buffers for single-PUT or multipart upload.
 * HOW:  base MUST be first (struct alias cast to xrdc_vfs_file *).
 *       is_mpu: 1 → multipart upload path; 0 → single-PUT or read.
 *       Single-PUT: put_buf grows via realloc as pwrite calls arrive.
 *       MPU: part_buf holds the current part being accumulated; when full it is
 *       flushed via PUT UploadPart, the ETag is saved, and the buffer resets.
 */
typedef struct {
    xrdc_vfs_file  base;          /* MUST be first — aliased by the façade */
    /* URL components (from xrdc_weburl_parse) */
    char           host[256];
    int            port;
    int            tls;
    char           key_path[XRDC_PATH_MAX];   /* e.g. "/bucket/key" */
    /* credentials */
    char           ak[128];        /* AWS_ACCESS_KEY_ID */
    char           sk[256];        /* AWS_SECRET_ACCESS_KEY */
    char           region[64];     /* AWS_DEFAULT_REGION */
    /* read state */
    int64_t        obj_size;       /* -1 = not yet loaded (lazy HEAD) */
    /* write mode */
    int            is_write;       /* 1 when opened for writing */
    int            is_mpu;         /* 1 = multipart upload, 0 = single-PUT */
    int64_t        part_size;      /* bytes per MPU part (S3_PART_MAX or override) */
    /* single-PUT buffer (used when is_mpu == 0 && is_write == 1) */
    void          *put_buf;        /* malloc'd; grows via realloc */
    size_t         put_len;        /* bytes accumulated so far */
    size_t         put_cap;        /* put_buf capacity in bytes */
    int64_t        put_write_off;  /* sequential write boundary for single-PUT */
    /* MPU state (used when is_mpu == 1) */
    char           upload_id[S3_UPLOAD_ID_LEN]; /* from CreateMultipartUpload */
    int            part_count;     /* number of parts uploaded so far */
    s3_part_etag  *etags;          /* malloc'd array of per-part ETags */
    int            etag_cap;       /* allocated slots in etags */
    int64_t        mpu_write_off;  /* next expected write offset */
    void          *part_buf;       /* current partial part buffer (malloc'd) */
    size_t         part_buf_len;   /* bytes accumulated in part_buf */
} vfs_s3_file;

/* ---- Credential loading -------------------------------------------------- */

/*
 * s3_creds_load — fill the ak/sk/region fields from opts or environment.
 *
 * WHAT: copies S3 credentials into *sf from opts (if cred != NULL, future C2),
 *       falling back to AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
 *       AWS_DEFAULT_REGION environment variables.
 * WHY:  opts->cred (xrdc_cred_store) is not yet implemented (task C2); this
 *       interim fallback keeps A5 functional for testing.
 * HOW:  getenv() for each key; default region to "us-east-1".  Returns -1 with
 *       st set when neither source has access/secret keys (anonymous access is
 *       allowed; the server may reject unsigned requests with 403).
 */
static void
s3_creds_load(vfs_s3_file *sf, const xrdc_vfs_open_opts *opts)
{
    const char *ak = getenv("AWS_ACCESS_KEY_ID");
    const char *sk = getenv("AWS_SECRET_ACCESS_KEY");
    const char *rg = getenv("AWS_DEFAULT_REGION");

    (void) opts;   /* cred store not yet wired (task C2) */

    snprintf(sf->ak,     sizeof(sf->ak),     "%s", ak ? ak : "");
    snprintf(sf->sk,     sizeof(sf->sk),     "%s", sk ? sk : "");
    snprintf(sf->region, sizeof(sf->region), "%s",
             (rg && rg[0]) ? rg : S3_REGION_DEFAULT);
}

/* ---- SigV4 signing helpers ----------------------------------------------- */

/*
 * s3_sign — build a SigV4 Authorization header block for a request.
 *
 * WHAT: calls xrdc_s3_sign_v4_q with the UNSIGNED-PAYLOAD sentinel and writes
 *       the "x-amz-date:\r\nx-amz-content-sha256:\r\nAuthorization:\r\n" block
 *       into hdrs[hdrsz].
 * WHY:  every HTTP operation (GET/HEAD/PUT/POST/DELETE) must be SigV4-signed;
 *       UNSIGNED-PAYLOAD matches copy_web's approach and is accepted by our server.
 * HOW:  builds the signed host string (bracketed for IPv6) via
 *       xrootd_format_host_port, then delegates to xrdc_s3_sign_v4_q.
 *       canon_qs = "" for simple object paths; "uploads=" / "partNumber=N&uploadId=X" /
 *       "uploadId=X" for multipart operations.
 */
static int
s3_sign(vfs_s3_file *sf, const char *method, const char *canon_qs,
        char *hdrs, size_t hdrsz, xrdc_status *st)
{
    char host[300];
    xrootd_format_host_port(sf->host, (uint16_t) sf->port, host, sizeof(host));
    if (xrdc_s3_sign_v4_q(method, host, sf->key_path, canon_qs,
                           sf->ak, sf->sk, sf->region,
                           "UNSIGNED-PAYLOAD", hdrs, hdrsz) != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "s3 sign: SigV4 failed for %s %s",
                        method, sf->key_path);
        return -1;
    }
    return 0;
}

/* ---- HTTP status → xrdc error mapping ----------------------------------- */

/*
 * s3_http_err — map an S3 HTTP error status to an xrdc error code and set *st.
 *
 * WHAT: maps the HTTP status from a failed S3 response to a clean xrdc error.
 * WHY:  callers need a consistent error when the server returns 403/404/5xx.
 * HOW:  403/401 → XRDC_EAUTH; anything else → XRDC_EIO with the status embedded
 *       in the message.
 */
static int
s3_http_err(int status, const char *op, const char *path, xrdc_status *st)
{
    if (status == 401 || status == 403) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "s3 %s: authentication/authorisation failed "
                        "(HTTP %d) on %s — check AWS_ACCESS_KEY_ID / "
                        "AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION",
                        op, status, path);
    } else if (status == 404) {
        xrdc_status_set(st, XRDC_ENOENT, 0,
                        "s3 %s: object not found (HTTP 404) on %s",
                        op, path);
    } else {
        xrdc_status_set(st, XRDC_EIO, 0,
                        "s3 %s: server returned HTTP %d on %s",
                        op, status, path);
    }
    return -1;
}

/* ---- XML tag extraction -------------------------------------------------- */

/*
 * xml_extract_tag — extract the text content of a named XML element.
 *
 * WHAT: finds <tag>…</tag> in `xml` and copies the content into out[outsz].
 * WHY:  avoids pulling in a full XML parser for the simple scalar values we need
 *       (UploadId from CreateMultipartUpload; we never need attributes or nesting).
 * HOW:  strstr for "<tag>"; then strstr for "</tag>"; memcpy the slice.
 *       Returns 0 on success, -1 if either tag is absent or content overflows.
 */
static int
xml_extract_tag(const char *xml, const char *tag,
                char *out, size_t outsz)
{
    char   open_tag[64];
    char   close_tag[64];
    const char *p;
    const char *e;
    size_t  n;

    snprintf(open_tag,  sizeof(open_tag),  "<%s>",  tag);
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);

    p = strstr(xml, open_tag);
    if (p == NULL) {
        return -1;
    }
    p += strlen(open_tag);

    e = strstr(p, close_tag);
    if (e == NULL) {
        return -1;
    }

    n = (size_t) (e - p);
    if (n == 0 || n >= outsz) {
        return -1;
    }
    memcpy(out, p, n);
    out[n] = '\0';
    return 0;
}

/* ---- HEAD to get object size --------------------------------------------- */

/*
 * s3_load_size — issue a SigV4-signed HEAD and populate sf->obj_size.
 *
 * WHAT: sends HEAD /key, parses the Content-Length response header, stores the
 *       result in sf->obj_size (or -1 if Content-Length is absent).
 * WHY:  fstat() on a read handle needs the object size; the HEAD is deferred
 *       to the first fstat call (lazy) to avoid a round-trip on write handles.
 * HOW:  s3_sign + xrdc_http_req; parse Content-Length with xrdc_http_header.
 */
static int
s3_load_size(vfs_s3_file *sf, xrdc_status *st)
{
    char           auth_hdrs[S3_AUTH_HDRS_CAP];
    xrdc_http_resp resp;
    char           cl_buf[32];

    if (s3_sign(sf, "HEAD", "", auth_hdrs, sizeof(auth_hdrs), st) != 0) {
        return -1;
    }
    if (xrdc_http_req(sf->host, sf->port, sf->tls, "HEAD", sf->key_path,
                      auth_hdrs, NULL, 0, S3_REQ_TIMEOUT_MS, 0, NULL,
                      &resp, st) != 0) {
        return -1;
    }
    if (resp.status != 200) {
        int rc = s3_http_err(resp.status, "HEAD", sf->key_path, st);
        xrdc_http_resp_free(&resp);
        return rc;
    }
    sf->obj_size = -1;
    if (xrdc_http_header(&resp, "Content-Length", cl_buf, sizeof(cl_buf))) {
        sf->obj_size = strtoll(cl_buf, NULL, 10);
    }
    xrdc_http_resp_free(&resp);
    return 0;
}

/* ---- MPU ETag array management ------------------------------------------ */

/*
 * s3_etag_ensure_cap — grow the per-part ETag array to hold at least `needed`
 * entries.
 *
 * WHAT: realloc-based growth (doubles capacity until >= needed).
 * WHY:  the number of parts is not known at open() for unlimited-size uploads.
 * HOW:  realloc + update cap; on OOM return -1 with st set (existing array intact).
 */
static int
s3_etag_ensure_cap(vfs_s3_file *sf, int needed, xrdc_status *st)
{
    int           new_cap;
    s3_part_etag *new_etags;

    if (sf->etag_cap >= needed) {
        return 0;
    }
    new_cap = (sf->etag_cap == 0) ? S3_ETAG_INIT_CAP : sf->etag_cap * 2;
    while (new_cap < needed) {
        new_cap *= 2;
    }
    new_etags = realloc(sf->etags, (size_t) new_cap * sizeof(s3_part_etag));
    if (new_etags == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 mpu: out of memory allocating ETag array");
        return -1;
    }
    sf->etags    = new_etags;
    sf->etag_cap = new_cap;
    return 0;
}

/* ---- MPU: upload one part ------------------------------------------------ */

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
static int
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

/* ---- MPU: flush part buffer ---------------------------------------------- */

/*
 * s3_mpu_flush_part_buf — upload the current part buffer and reset it.
 *
 * WHAT: calls s3_mpu_upload_part for sf->part_buf[0..sf->part_buf_len),
 *       then resets sf->part_buf_len to 0 for the next part.
 * WHY:  deduplicates the flush-on-full and flush-at-commit paths.
 * HOW:  guard on part_buf_len > 0 (skip empty flush); delegate; reset.
 */
static int
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

/* ---- MPU: CreateMultipartUpload ------------------------------------------ */

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
static int
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

/* ---- MPU: CompleteMultipartUpload --------------------------------------- */

/*
 * s3_mpu_complete_xml_size — compute the exact size of the CompleteMultipartUpload
 * XML body for `n_parts` parts (without including the actual ETag values).
 *
 * WHAT: pre-calculates the buffer size needed for the XML body.
 * WHY:  avoids a realloc loop when building the XML string.
 * HOW:  fixed preamble + per-part overhead (part number + ETag length estimate) +
 *       closing tag.  Uses S3_ETAG_LEN as an upper bound per part.
 */
static size_t
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
static int
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

/* ---- MPU: AbortMultipartUpload ------------------------------------------ */

/*
 * s3_mpu_abort_upload — send DELETE /key?uploadId=ID (AbortMultipartUpload).
 *
 * WHAT: cleans up the server-side staging directory for the active upload.
 * WHY:  a failed or cancelled write must not leave orphan parts consuming
 *       server disk space.
 * HOW:  sign + DELETE; a 204 No Content response indicates success.  Errors are
 *       logged but do not make abort() fail (the local state is already torn down).
 */
static void
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

/* ---- vtable: pread ------------------------------------------------------- */

/*
 * s3_pread — read n bytes at offset off from the S3 object into buf.
 *
 * WHAT: issues a SigV4-signed GET with a "Range: bytes=off-end\r\n" header;
 *       copies the 206 (or 200) response body into buf.
 * WHY:  VFS callers need seekable reads; S3 supports this via HTTP Range.
 * HOW:  cap n at S3_PREAD_MAX to stay within xrdc_http_req's 8 MiB body limit;
 *       build combined auth+range extra_headers string; issue GET; check status;
 *       memcpy body to buf; return bytes copied.
 */
static ssize_t
s3_pread(xrdc_vfs_file *f, int64_t off, void *buf, size_t n, xrdc_status *st)
{
    vfs_s3_file   *sf = (vfs_s3_file *) f;
    char           auth_hdrs[S3_AUTH_HDRS_CAP];
    char           combined[S3_AUTH_HDRS_CAP + 80];
    xrdc_http_resp resp;
    int64_t        end;
    size_t         n_capped;
    ssize_t        copied;
    int            cn;

    if (n == 0) {
        return 0;
    }
    n_capped = (n > (size_t) S3_PREAD_MAX) ? (size_t) S3_PREAD_MAX : n;
    end = off + (int64_t) n_capped - 1;

    if (s3_sign(sf, "GET", "", auth_hdrs, sizeof(auth_hdrs), st) != 0) {
        return -1;
    }
    cn = snprintf(combined, sizeof(combined),
                  "Range: bytes=%lld-%lld\r\n%s",
                  (long long) off, (long long) end, auth_hdrs);
    if (cn < 0 || (size_t) cn >= sizeof(combined)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "s3 pread: header too long");
        return -1;
    }
    if (xrdc_http_req(sf->host, sf->port, sf->tls, "GET", sf->key_path,
                      combined, NULL, 0, S3_REQ_TIMEOUT_MS, 0, NULL,
                      &resp, st) != 0) {
        return -1;
    }
    if (resp.status != 206 && resp.status != 200) {
        s3_http_err(resp.status, "GET", sf->key_path, st);
        xrdc_http_resp_free(&resp);
        return -1;
    }
    if (resp.body == NULL || resp.body_len == 0) {
        xrdc_http_resp_free(&resp);
        return 0;   /* EOF or empty range */
    }
    copied = (resp.body_len < n_capped) ? (ssize_t) resp.body_len
                                        : (ssize_t) n_capped;
    memcpy(buf, resp.body, (size_t) copied);
    xrdc_http_resp_free(&resp);
    return copied;
}

/* ---- vtable: pwrite ------------------------------------------------------ */

/*
 * s3_pwrite_check_sequential — verify that the write offset matches the expected
 * boundary for sequential S3 writes.
 *
 * WHAT: returns -1 with XRDC_EUSAGE if off != *expected_off.
 * WHY:  S3 requires sequential writes; a non-sequential offset cannot be satisfied
 *       without random-write support (which S3 does not have).
 * HOW:  simple integer comparison.
 */
static int
s3_pwrite_check_sequential(int64_t off, int64_t expected_off,
                           const char *path, xrdc_status *st)
{
    if (off != expected_off) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "s3 backend requires sequential writes "
                        "(got offset %lld, expected %lld) on %s",
                        (long long) off, (long long) expected_off, path);
        return -1;
    }
    return 0;
}

/*
 * s3_pwrite_single — append data to the single-PUT in-memory buffer.
 *
 * WHAT: copies data[0..n) into sf->put_buf, growing it via realloc if needed.
 * WHY:  single-PUT mode buffers the whole object in memory; the PUT is issued at
 *       commit() time so we know the Content-Length.
 * HOW:  check sequential offset; realloc if put_len + n > put_cap; memcpy; advance.
 */
static int
s3_pwrite_single(vfs_s3_file *sf, int64_t off, const void *data, size_t n,
                 xrdc_status *st)
{
    size_t new_len;
    void  *new_buf;

    if (s3_pwrite_check_sequential(off, sf->put_write_off, sf->key_path,
                                   st) != 0) {
        return -1;
    }
    new_len = sf->put_len + n;
    if (new_len > sf->put_cap) {
        size_t new_cap = sf->put_cap * 2;
        while (new_cap < new_len) {
            new_cap *= 2;
        }
        new_buf = realloc(sf->put_buf, new_cap);
        if (new_buf == NULL) {
            xrdc_status_set(st, XRDC_EIO, ENOMEM,
                            "s3 single-put: out of memory");
            return -1;
        }
        sf->put_buf = new_buf;
        sf->put_cap = new_cap;
    }
    memcpy((char *) sf->put_buf + sf->put_len, data, n);
    sf->put_len      += n;
    sf->put_write_off = off + (int64_t) n;
    return 0;
}

/*
 * s3_pwrite_mpu — append data to the MPU part buffer, flushing full parts.
 *
 * WHAT: copies data[0..n) into sf->part_buf chunk by chunk; when part_buf fills
 *       (part_buf_len reaches part_size), uploads the part via
 *       s3_mpu_flush_part_buf() and resets for the next part.
 * WHY:  MPU requires fixed-size parts (except the last); this incrementally fills
 *       the buffer and uploads complete parts as they accumulate.
 * HOW:  sequential guard; copy-loop that fills the part buffer and flushes when
 *       full; advance mpu_write_off.
 */
static int
s3_pwrite_mpu(vfs_s3_file *sf, int64_t off, const void *data, size_t n,
              xrdc_status *st)
{
    const char *src      = (const char *) data;
    size_t      remaining = n;

    if (s3_pwrite_check_sequential(off, sf->mpu_write_off, sf->key_path,
                                   st) != 0) {
        return -1;
    }
    while (remaining > 0) {
        size_t space  = (size_t) sf->part_size - sf->part_buf_len;
        size_t to_copy = (remaining < space) ? remaining : space;

        memcpy((char *) sf->part_buf + sf->part_buf_len, src, to_copy);
        sf->part_buf_len += to_copy;
        src              += to_copy;
        remaining        -= to_copy;

        if (sf->part_buf_len == (size_t) sf->part_size) {
            if (s3_mpu_flush_part_buf(sf, st) != 0) {
                return -1;
            }
        }
    }
    sf->mpu_write_off = off + (int64_t) n;
    return 0;
}

/*
 * s3_pwrite — write n bytes from buf at offset off.
 *
 * WHAT: dispatcher that routes to s3_pwrite_single or s3_pwrite_mpu based on
 *       the handle's write mode (sf->is_mpu).
 * WHY:  the vtable interface is uniform; mode dispatch is one place.
 * HOW:  cast f to vfs_s3_file; check is_write; delegate.
 */
static int
s3_pwrite(xrdc_vfs_file *f, int64_t off, const void *buf, size_t n,
          xrdc_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    if (!sf->is_write) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "s3 pwrite: handle opened for read");
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    if (sf->is_mpu) {
        return s3_pwrite_mpu(sf, off, buf, n, st);
    }
    return s3_pwrite_single(sf, off, buf, n, st);
}

/* ---- vtable: fstat ------------------------------------------------------- */

/*
 * s3_fstat — fill *out with size metadata for the open handle.
 *
 * WHAT: for READ handles, issues a lazy HEAD if size not yet loaded; for WRITE
 *       handles returns the accumulated byte count as the current size.
 * WHY:  copy.c may call fstat after open to get the object size for progress.
 * HOW:  READ: lazy s3_load_size; WRITE single-PUT: put_len; WRITE MPU:
 *       mpu_write_off (total bytes written so far).
 */
static int
s3_fstat(xrdc_vfs_file *f, xrdc_vfs_stat *out, xrdc_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    out->is_dir = 0;
    out->mtime  = 0;
    out->exists = 1;

    if (sf->is_write) {
        out->size = sf->is_mpu ? sf->mpu_write_off : (int64_t) sf->put_len;
        return 0;
    }
    /* READ handle: load size lazily on first fstat. */
    if (sf->obj_size < 0) {
        if (s3_load_size(sf, st) != 0) {
            return -1;
        }
    }
    out->size = sf->obj_size;
    return 0;
}

/* ---- vtable: truncate ---------------------------------------------------- */

/*
 * s3_truncate — unsupported on S3 (not advertised in caps).
 *
 * WHAT: always returns XRDC_EUSAGE.
 * WHY:  S3 objects are immutable once committed; in-place truncation is not
 *       possible without re-uploading.  The backend does not advertise
 *       XRDC_VFS_CAP_TRUNCATE, so callers that check caps won't reach here.
 * HOW:  unconditional error return.
 */
static int
s3_truncate(xrdc_vfs_file *f, int64_t size, xrdc_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;
    (void) size;
    xrdc_status_set(st, XRDC_EUSAGE, 0,
                    "s3 backend does not support truncate on %s",
                    sf->key_path);
    return -1;
}

/* ---- vtable: sync -------------------------------------------------------- */

/*
 * s3_sync — no-op for the S3 backend.
 *
 * WHAT: returns 0 immediately.
 * WHY:  S3 object stores are synchronous by nature — a successful PUT or MPU
 *       part acknowledgement means the data is durable.  There is no separate
 *       flush step needed between pwrite calls.
 * HOW:  unconditional 0 return.
 */
static int
s3_sync(xrdc_vfs_file *f, xrdc_status *st)
{
    (void) f;
    (void) st;
    return 0;
}

/* ---- vtable: commit ------------------------------------------------------ */

/*
 * s3_commit_single — PUT the entire buffered object in a single request.
 *
 * WHAT: issues a SigV4-signed PUT with sf->put_buf as the body; checks 200.
 * WHY:  single-PUT mode defers the actual HTTP transfer until commit so that
 *       Content-Length is known at the time of the PUT.
 * HOW:  sign PUT (no query string); xrdc_http_req with put_buf; check 200.
 */
static int
s3_commit_single(vfs_s3_file *sf, xrdc_status *st)
{
    char           auth_hdrs[S3_AUTH_HDRS_CAP];
    xrdc_http_resp resp;

    if (s3_sign(sf, "PUT", "", auth_hdrs, sizeof(auth_hdrs), st) != 0) {
        return -1;
    }
    if (xrdc_http_req(sf->host, sf->port, sf->tls, "PUT", sf->key_path,
                      auth_hdrs,
                      sf->put_buf, sf->put_len,
                      S3_REQ_TIMEOUT_MS, 0, NULL, &resp, st) != 0) {
        return -1;
    }
    if (resp.status != 200) {
        int rc = s3_http_err(resp.status, "PUT", sf->key_path, st);
        xrdc_http_resp_free(&resp);
        return rc;
    }
    xrdc_http_resp_free(&resp);
    return 0;
}

/*
 * s3_commit_mpu — flush the final partial part then CompleteMultipartUpload.
 *
 * WHAT: uploads any remaining data in sf->part_buf as the last part, then
 *       issues CompleteMultipartUpload with all part ETags.
 * WHY:  the MPU must be explicitly finalised; any unflushed partial part must be
 *       uploaded first (the last part is the only one allowed to be < 5 MiB on
 *       real S3; our server has no minimum size restriction).
 * HOW:  s3_mpu_flush_part_buf; s3_mpu_complete.
 */
static int
s3_commit_mpu(vfs_s3_file *sf, xrdc_status *st)
{
    if (s3_mpu_flush_part_buf(sf, st) != 0) {
        return -1;
    }
    if (sf->part_count == 0) {
        /* Zero-byte MPU: upload an empty last part so complete has at least one
         * part; the server assembles an empty object. */
        if (s3_mpu_upload_part(sf, 1, NULL, 0, st) != 0) {
            return -1;
        }
    }
    return s3_mpu_complete(sf, st);
}

/*
 * s3_commit — finalise a write handle.
 *
 * WHAT: for single-PUT → PUT the buffer; for MPU → flush + CompleteMultipartUpload.
 *       No-op for READ handles.
 * WHY:  the vtable commit() is the single finalise point for all backends.
 * HOW:  dispatch on is_mpu; delegate.
 */
static int
s3_commit(xrdc_vfs_file *f, xrdc_status *st)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    if (!sf->is_write) {
        return 0;   /* READ handle — nothing to commit */
    }
    if (sf->is_mpu) {
        return s3_commit_mpu(sf, st);
    }
    return s3_commit_single(sf, st);
}

/* ---- vtable: abort ------------------------------------------------------- */

/*
 * s3_abort — discard a partial write.
 *
 * WHAT: MPU → AbortMultipartUpload (removes server-side staging directory);
 *       single-PUT → discard the in-memory buffer (no server cleanup needed).
 *       READ handles → no-op.
 * WHY:  a failed transfer must not leave orphan server resources.
 * HOW:  is_mpu → s3_mpu_abort_upload (best-effort: errors are swallowed);
 *       single-PUT: put_len reset to 0 (buffer freed in close).
 */
static void
s3_abort(xrdc_vfs_file *f)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    if (!sf->is_write) {
        return;
    }
    if (sf->is_mpu) {
        s3_mpu_abort_upload(sf);
    } else {
        sf->put_len = 0;   /* discard buffer; close() frees the allocation */
    }
}

/* ---- vtable: close ------------------------------------------------------- */

/*
 * s3_close — release all resources held by the handle.
 *
 * WHAT: frees all malloc'd buffers (put_buf, part_buf, etags) and the handle
 *       struct itself.  Must be called after commit() or abort().
 * WHY:  owns all resources allocated by s3_be_open(); one release point.
 * HOW:  free each field; free(sf).
 */
static void
s3_close(xrdc_vfs_file *f)
{
    vfs_s3_file *sf = (vfs_s3_file *) f;

    free(sf->put_buf);
    free(sf->part_buf);
    free(sf->etags);
    free(sf);
}

/* ---- vtable singleton ---------------------------------------------------- */

static const xrdc_vfs_ops s_s3_ops = {
    .pread    = s3_pread,
    .pwrite   = s3_pwrite,
    .fstat    = s3_fstat,
    .truncate = s3_truncate,
    .sync     = s3_sync,
    .commit   = s3_commit,
    .abort    = s3_abort,
    .close    = s3_close,
};

/* ---- Backend open + stat ------------------------------------------------- */

/*
 * s3_part_size_from_env — load the effective MPU part size.
 *
 * WHAT: returns S3_PART_MAX_DEFAULT unless S3_PART_MAX_OVERRIDE is set in the
 *       environment, in which case that value is used (minimum 1 byte).
 * WHY:  tests need to exercise the multipart code path with small objects; the
 *       env override lets a test set part_size=512 without recompiling.
 * HOW:  getenv + strtoll; fall back to default on absent/invalid values.
 */
static int64_t
s3_part_size_from_env(void)
{
    const char *e = getenv(S3_PART_MAX_ENV);
    int64_t     v;

    if (e == NULL || e[0] == '\0') {
        return S3_PART_MAX_DEFAULT;
    }
    v = strtoll(e, NULL, 10);
    return (v > 0) ? v : S3_PART_MAX_DEFAULT;
}

/*
 * s3_alloc_handle — allocate and zero-fill a vfs_s3_file.
 *
 * WHAT: calloc a vfs_s3_file; return NULL on OOM.
 * WHY:  factor allocation out of s3_be_open so that path is readable.
 * HOW:  calloc; no other initialisation (caller sets fields).
 */
static vfs_s3_file *
s3_alloc_handle(void)
{
    return (vfs_s3_file *) calloc(1, sizeof(vfs_s3_file));
}

/*
 * s3_open_read — open a handle for reading.
 *
 * WHAT: sets the read-mode-specific field (lazy obj_size); common fields
 *       (host/port/tls/key_path/creds/ops/caps) are already set by s3_be_open.
 * WHY:  deferred HEAD avoids a round-trip for callers that only write or never
 *       call fstat.
 * HOW:  set obj_size = -1; base ops/caps are set by s3_be_open after dispatch.
 */
static int
s3_open_read(vfs_s3_file *sf, xrdc_status *st)
{
    (void) st;

    sf->obj_size = -1;   /* loaded lazily by s3_fstat → s3_load_size */
    return 0;
}

/*
 * s3_open_write_single — initialise a single-PUT write handle.
 *
 * WHAT: allocates the in-memory PUT buffer; decides the initial capacity from
 *       opts->expected_size (when known) or S3_PUT_BUF_INIT.
 * WHY:  single-PUT mode is used when the full object fits in one part and the
 *       size is known at open() time.
 * HOW:  malloc put_buf to max(expected_size, S3_PUT_BUF_INIT); set is_write=1.
 */
static int
s3_open_write_single(vfs_s3_file *sf, const xrdc_vfs_open_opts *opts,
                     xrdc_status *st)
{
    size_t cap;

    cap = (opts->expected_size > 0)
          ? (size_t) opts->expected_size
          : S3_PUT_BUF_INIT;
    if (cap < (size_t) S3_PUT_BUF_INIT) {
        cap = S3_PUT_BUF_INIT;
    }
    sf->put_buf = malloc(cap);
    if (sf->put_buf == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 open write: out of memory for PUT buffer");
        return -1;
    }
    sf->put_cap      = cap;
    sf->put_len      = 0;
    sf->put_write_off = 0;
    sf->is_write     = 1;
    sf->is_mpu       = 0;
    return 0;
}

/*
 * s3_open_write_mpu — initiate a multipart upload and initialise the MPU handle.
 *
 * WHAT: issues CreateMultipartUpload (POST /key?uploads), stores the UploadId,
 *       and allocates the part buffer.
 * WHY:  MPU is used when expected_size is unknown or larger than one part;
 *       the upload handle is ready for s3_pwrite_mpu calls immediately after.
 * HOW:  CreateMultipartUpload → parse UploadId → malloc part_buf of part_size;
 *       set is_write=1, is_mpu=1.  sf->part_size is set by s3_be_open before
 *       dispatch so it is not re-read here.
 */
static int
s3_open_write_mpu(vfs_s3_file *sf, xrdc_status *st)
{
    if (s3_mpu_create(sf, st) != 0) {
        return -1;
    }
    sf->part_buf = malloc((size_t) sf->part_size);
    if (sf->part_buf == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 open write mpu: out of memory for part buffer");
        /* upload was created on server; best-effort abort */
        s3_mpu_abort_upload(sf);
        return -1;
    }
    sf->part_buf_len  = 0;
    sf->mpu_write_off = 0;
    sf->part_count    = 0;
    sf->etags         = NULL;
    sf->etag_cap      = 0;
    sf->is_write      = 1;
    sf->is_mpu        = 1;
    return 0;
}

/*
 * s3_be_open — allocate a vfs_s3_file and prepare the handle.
 *
 * WHAT: parses the URL; reads credentials; chooses single-PUT or MPU write mode;
 *       returns a ready handle in *out.
 * WHY:  single entry point for the S3 backend; hides URL/mode routing from the
 *       façade.
 * HOW:  xrdc_weburl_parse; s3_alloc_handle; route to s3_open_read /
 *       s3_open_write_single / s3_open_write_mpu based on flags + expected_size.
 *       On any failure, free sf and return -1.
 */
static int
s3_be_open(const xrdc_vfs_backend *be, const char *url, int flags,
           const xrdc_vfs_open_opts *opts, xrdc_vfs_file **out,
           xrdc_status *st)
{
    xrdc_weburl     wu;
    vfs_s3_file    *sf;
    int64_t         part_sz;
    int             rc;

    (void) be;

    *out = NULL;

    if (xrdc_weburl_parse(url, &wu) != 0 || !wu.is_s3) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "s3 backend: not an S3 URL: %s", url);
        return -1;
    }

    sf = s3_alloc_handle();
    if (sf == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 open: out of memory allocating handle");
        return -1;
    }
    snprintf(sf->host,     sizeof(sf->host),     "%s", wu.host);
    sf->port = wu.port;
    sf->tls  = wu.tls;
    snprintf(sf->key_path, sizeof(sf->key_path), "%s", wu.path);
    s3_creds_load(sf, opts);

    if (flags & XRDC_VFS_WRITE) {
        /* Choose single-PUT vs MPU based on expected_size and part_size. */
        part_sz = s3_part_size_from_env();
        if (opts != NULL && opts->expected_size >= 0
            && opts->expected_size <= part_sz) {
            rc = s3_open_write_single(sf, opts, st);
        } else {
            sf->part_size = part_sz;
            rc = s3_open_write_mpu(sf, st);
        }
    } else {
        rc = s3_open_read(sf, st);
    }

    if (rc != 0) {
        free(sf);
        return -1;
    }

    sf->base.ops  = &s_s3_ops;
    sf->base.caps = 0;   /* S3: no RANDOM_WRITE, no TRUNCATE, no ATOMIC_TEMP */

    *out = &sf->base;
    return 0;
}

/*
 * s3_be_stat — stat an S3 object URL without opening a handle.
 *
 * WHAT: allocates a temporary handle, issues HEAD, fills *out, frees the handle.
 * WHY:  allows existence/size checks without a full open (mirrors posix_be_stat).
 * HOW:  s3_alloc_handle; parse URL; s3_load_size; fill xrdc_vfs_stat; free.
 *       ENOENT-equivalent (404) → exists=0, return 0; other errors → -1.
 */
static int
s3_be_stat(const xrdc_vfs_backend *be, const char *url,
           xrdc_vfs_stat *out, xrdc_status *st)
{
    xrdc_weburl     wu;
    vfs_s3_file    *sf;
    int             rc;

    (void) be;

    if (xrdc_weburl_parse(url, &wu) != 0 || !wu.is_s3) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "s3 stat: not an S3 URL: %s", url);
        return -1;
    }

    sf = s3_alloc_handle();
    if (sf == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "s3 stat: out of memory");
        return -1;
    }
    snprintf(sf->host,     sizeof(sf->host),     "%s", wu.host);
    sf->port = wu.port;
    sf->tls  = wu.tls;
    snprintf(sf->key_path, sizeof(sf->key_path), "%s", wu.path);

    /* Use no-op open_opts for stat (no cred store yet). */
    {
        xrdc_vfs_open_opts dummy_opts;
        memset(&dummy_opts, 0, sizeof(dummy_opts));
        dummy_opts.expected_size = -1;
        s3_creds_load(sf, &dummy_opts);
    }

    sf->obj_size = -1;
    rc = s3_load_size(sf, st);
    if (rc != 0) {
        /* 404 → exists=0 (not an error at the stat level) */
        if (st->kxr == XRDC_ENOENT) {
            out->exists = 0;
            out->size   = 0;
            out->mtime  = 0;
            out->is_dir = 0;
            free(sf);
            xrdc_status_clear(st);
            return 0;
        }
        free(sf);
        return -1;
    }

    out->size   = sf->obj_size;
    out->mtime  = 0;
    out->is_dir = 0;
    out->exists = 1;
    free(sf);
    return 0;
}

/* ---- Backend descriptor + accessor --------------------------------------- */

static const xrdc_vfs_backend s_s3_backend = {
    .scheme = "s3",
    .caps   = 0,   /* no RANDOM_WRITE, no TRUNCATE, no ATOMIC_TEMP */
    .open   = s3_be_open,
    .stat   = s3_be_stat,
};

/*
 * xrdc_vfs_s3_backend — pure factory: return the S3 backend descriptor.
 *
 * WHAT: strong definition that overrides the weak stub in vfs.c; called once
 *       during vfs_init_backends() (pthread_once).  Returns the static
 *       descriptor; vfs.c's init owns the xrdc_vfs_register_backend() call.
 * WHY:  registration is the façade's responsibility — the accessor must not
 *       double-register (which would consume registry slots).
 * HOW:  return the static descriptor directly.
 */
const xrdc_vfs_backend *
xrdc_vfs_s3_backend(void)
{
    return &s_s3_backend;
}
