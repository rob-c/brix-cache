/*
 * vfs_s3_http.c - extracted concern
 * Phase-38 split of vfs_s3.c; behavior-identical.
 */
#include "vfs_s3_internal.h"

void
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


/* SigV4 signing helpers */
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
int
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


/* HTTP status → xrdc error mapping */
/*
 * s3_http_err — map an S3 HTTP error status to an xrdc error code and set *st.
 *
 * WHAT: maps the HTTP status from a failed S3 response to a clean xrdc error.
 * WHY:  callers need a consistent error when the server returns 403/404/5xx.
 * HOW:  403/401 → XRDC_EAUTH; anything else → XRDC_EIO with the status embedded
 *       in the message.
 */
int
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


/* XML tag extraction */
/*
 * xml_extract_tag — extract the text content of a named XML element.
 *
 * WHAT: finds <tag>…</tag> in `xml` and copies the content into out[outsz].
 * WHY:  avoids pulling in a full XML parser for the simple scalar values we need
 *       (UploadId from CreateMultipartUpload; we never need attributes or nesting).
 * HOW:  strstr for "<tag>"; then strstr for "</tag>"; memcpy the slice.
 *       Returns 0 on success, -1 if either tag is absent or content overflows.
 */
int
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


/* MPU ETag array management */
/*
 * s3_etag_ensure_cap — grow the per-part ETag array to hold at least `needed`
 * entries.
 *
 * WHAT: realloc-based growth (doubles capacity until >= needed).
 * WHY:  the number of parts is not known at open() for unlimited-size uploads.
 * HOW:  realloc + update cap; on OOM return -1 with st set (existing array intact).
 */
int
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
