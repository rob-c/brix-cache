/*
 * sd_s3.c — shared S3 storage driver, read path. See sd_s3.h.
 *
 * Ported from client/lib/vfs_s3*.c with two changes that make it shareable:
 *   1. the HTTP transport is injected (sd_s3_transport.h) instead of calling the
 *      client's xrdc_http_* directly;
 *   2. the error model is a neutral (rc, errbuf) pair instead of xrdc_status.
 * SigV4 signing uses the same shared kernels (sigv4 / crypto / hex / uri) the
 * server's verify path uses, so client-signs == server-verifies byte-for-byte.
 */
#include "sd_s3.h"

#include "../../../compat/crypto.h"        /* xrootd_sha256 / xrootd_hmac_sha256 */
#include "../../../compat/hex.h"           /* xrootd_hex_encode */
#include "../../../compat/sigv4.h"         /* xrootd_sigv4_signing_key */
#include "../../../compat/uri.h"           /* xrootd_http_urlencode */
#include "../../../compat/host_format.h"   /* xrootd_format_host_port */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>   /* gettimeofday — NOT <time.h>, which `-I src/compat`
                         * shadows with compat/time.h (a known conflict; that
                         * helper is module-only, absent from libxrdproto). */

#define SD_S3_AUTH_HDRS_CAP  4096
#define SD_S3_PREAD_MAX      (7LL * 1024 * 1024)
#define SD_S3_KEY_MAX        4096
#define SD_S3_ETAG_LEN       96
#define SD_S3_UPLOAD_ID_LEN  128
#define SD_S3_ETAG_INIT_CAP  16
#define SD_S3_PUT_BUF_INIT   (64 * 1024)

typedef struct { char val[SD_S3_ETAG_LEN]; } sd_s3_part_etag;

struct sd_s3_file {
    char                         host[256];
    int                          port;
    int                          tls;
    char                         key[SD_S3_KEY_MAX];
    char                         ak[128];
    char                         sk[256];
    char                         region[64];
    const xrootd_s3_transport_t *transport;
    void                        *tctx;
    int                          timeout_ms;
    int64_t                      obj_size;   /* -1 until first HEAD */

    /* write state */
    int                          is_write;
    int                          is_mpu;
    int64_t                      part_size;
    /* single PUT */
    void                        *put_buf;
    size_t                       put_len;
    size_t                       put_cap;
    int64_t                      put_write_off;
    /* multipart */
    char                         upload_id[SD_S3_UPLOAD_ID_LEN];
    int                          part_count;
    sd_s3_part_etag             *etags;
    int                          etag_cap;
    int64_t                      mpu_write_off;
    void                        *part_buf;
    size_t                       part_buf_len;
};

static void
sd_s3_set_err(char *errbuf, size_t errcap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void
sd_s3_set_err(char *errbuf, size_t errcap, const char *fmt, ...)
{
    va_list ap;
    if (errbuf == NULL || errcap == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(errbuf, errcap, fmt, ap);
    va_end(ap);
}

/* sd_s3_utc_now — current UTC as SigV4 amzdate (YYYYMMDDTHHMMSSZ) + datestamp
 * (YYYYMMDD), computed self-contained from the epoch (civil-from-days) so it
 * needs neither <time.h> (shadowed here) nor the module-only compat/time.c. */
static void
sd_s3_utc_now(char amzdate[20], char datestamp[12])
{
    struct timeval tv;
    long long      secs, days, rem, z, era, y;
    unsigned       doe, yoe, doy, mp, d, m;
    int            hh, mm, ss;

    gettimeofday(&tv, NULL);
    secs = (long long) tv.tv_sec;
    days = secs / 86400;
    rem  = secs % 86400;
    if (rem < 0) { rem += 86400; days -= 1; }
    hh = (int) (rem / 3600);
    mm = (int) ((rem % 3600) / 60);
    ss = (int) (rem % 60);

    /* Howard Hinnant's civil_from_days (days since 1970-01-01, UTC). */
    z   = days + 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = (unsigned) (z - era * 146097);
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y   = (long long) yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp  = (5 * doy + 2) / 153;
    d   = doy - (153 * mp + 2) / 5 + 1;
    m   = mp < 10 ? mp + 3 : mp - 9;
    y  += (m <= 2);

    /* Bound the year to 4 digits (real epochs are well within 0000-9999) so the
     * fixed amzdate[20]/datestamp[12] buffers are provably large enough. */
    {
        int yr = (int) (((y % 10000) + 10000) % 10000);
        unsigned mo = m % 100, da = d % 100;
        snprintf(datestamp, 12, "%04d%02u%02u", yr, mo, da);
        snprintf(amzdate, 20, "%04d%02u%02uT%02u%02u%02uZ",
                 yr, mo, da, hh % 100, mm % 100, ss % 100);
    }
}

static void
sd_s3_sha256_hex(const void *data, size_t len, char *out /* >=65 */)
{
    uint8_t d[32];
    xrootd_sha256((const uint8_t *) data, len, d);
    xrootd_hex_encode(d, 32, out);
}

/* sd_s3_sign — build the SigV4 x-amz-date / content-sha256 / Authorization header
 * block for `method` on this object (payload = UNSIGNED-PAYLOAD). Ported from
 * xrdc_s3_sign_v4_q; all kernels are shared. 0 / -1. */
static int
sd_s3_sign(const sd_s3_file *f, const char *method, const char *canon_qs,
           char *hdrs, size_t hdrsz)
{
    const char *payload_hex = "UNSIGNED-PAYLOAD";
    char        host[300];
    char        amzdate[20], datestamp[12];
    char        canon_hex[65], sighex[65];
    char        canon[8192], scope[160], sts[640], enc_uri[2048];
    uint8_t     k4[32], sig[32];
    int         cn;

    if (canon_qs == NULL) { canon_qs = ""; }
    xrootd_format_host_port(f->host, (uint16_t) f->port, host, sizeof(host));
    sd_s3_utc_now(amzdate, datestamp);

    if (xrootd_http_urlencode((const unsigned char *) f->key, strlen(f->key),
                              enc_uri, sizeof(enc_uri), "/") < 0) {
        return -1;
    }
    cn = snprintf(canon, sizeof(canon),
             "%s\n%s\n%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n\n"
             "host;x-amz-content-sha256;x-amz-date\n%s",
             method, enc_uri, canon_qs, host, payload_hex, amzdate, payload_hex);
    if (cn < 0 || (size_t) cn >= sizeof(canon)) {
        return -1;
    }
    sd_s3_sha256_hex(canon, strlen(canon), canon_hex);

    cn = snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request",
                  datestamp, f->region);
    if (cn < 0 || (size_t) cn >= sizeof(scope)) {
        return -1;
    }
    cn = snprintf(sts, sizeof(sts), "AWS4-HMAC-SHA256\n%s\n%s\n%s",
                  amzdate, scope, canon_hex);
    if (cn < 0 || (size_t) cn >= sizeof(sts)) {
        return -1;
    }

    if (!xrootd_sigv4_signing_key((const uint8_t *) f->sk, strlen(f->sk),
                                  datestamp, f->region, "s3", k4)
        || !xrootd_hmac_sha256(k4, 32, (const uint8_t *) sts, strlen(sts), sig)) {
        return -1;
    }
    xrootd_hex_encode(sig, 32, sighex);

    cn = snprintf(hdrs, hdrsz,
             "x-amz-date: %s\r\nx-amz-content-sha256: %s\r\n"
             "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
             "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s\r\n",
             amzdate, payload_hex, f->ak, scope, sighex);
    if (cn < 0 || (size_t) cn >= hdrsz) {
        return -1;
    }
    return 0;
}

/* Map a non-2xx HTTP status to -1 with a diagnostic; returns -1 always. Sets
 * errno to the matching POSIX class (EACCES for 401/403, ENOENT for 404, else
 * EIO) so callers can recover the error category — the message channel alone
 * loses it. The client S3 VFS maps this errno to XRDC_EAUTH/ENOENT; the server
 * S3 backend maps it to kXR via the canonical errno↔kXR table. */
static int
sd_s3_status_err(int status, const char *op, const char *key,
                 char *errbuf, size_t errcap)
{
    if (status == 401 || status == 403) {
        sd_s3_set_err(errbuf, errcap,
            "s3 %s: auth failed (HTTP %d) on %s — check AK/SK/region",
            op, status, key);
        errno = EACCES;
    } else if (status == 404) {
        sd_s3_set_err(errbuf, errcap, "s3 %s: not found (HTTP 404) on %s",
                      op, key);
        errno = ENOENT;
    } else {
        sd_s3_set_err(errbuf, errcap, "s3 %s: HTTP %d on %s", op, status, key);
        errno = EIO;
    }
    return -1;
}

sd_s3_file *
sd_s3_open_read(const sd_s3_open_params *p, char *errbuf, size_t errcap)
{
    sd_s3_file *f;

    if (p == NULL || p->host == NULL || p->key == NULL || p->transport == NULL) {
        sd_s3_set_err(errbuf, errcap, "s3 open: bad parameters");
        return NULL;
    }
    f = calloc(1, sizeof(*f));
    if (f == NULL) {
        sd_s3_set_err(errbuf, errcap, "s3 open: out of memory");
        return NULL;
    }
    snprintf(f->host, sizeof(f->host), "%s", p->host);
    snprintf(f->key, sizeof(f->key), "%s", p->key);
    snprintf(f->ak, sizeof(f->ak), "%s", p->ak ? p->ak : "");
    snprintf(f->sk, sizeof(f->sk), "%s", p->sk ? p->sk : "");
    snprintf(f->region, sizeof(f->region), "%s",
             (p->region && p->region[0]) ? p->region : "us-east-1");
    f->port       = p->port;
    f->tls        = p->tls;
    f->transport  = p->transport;
    f->tctx       = p->tctx;
    f->timeout_ms = (p->timeout_ms > 0) ? p->timeout_ms : 300000;
    f->obj_size   = -1;
    return f;
}

int
sd_s3_size(sd_s3_file *f, int64_t *out_size, char *errbuf, size_t errcap)
{
    char             auth[SD_S3_AUTH_HDRS_CAP];
    char             cl[32];
    xrootd_s3_resp_t resp;

    if (f->obj_size >= 0) {
        if (out_size != NULL) { *out_size = f->obj_size; }
        return 0;
    }
    if (sd_s3_sign(f, "HEAD", "", auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 HEAD: SigV4 sign failed on %s", f->key);
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "HEAD",
                              f->key, auth, NULL, 0, f->timeout_ms, &resp,
                              errbuf, errcap) != 0) {
        return -1;
    }
    if (resp.status != 200) {
        int rc = sd_s3_status_err(resp.status, "HEAD", f->key, errbuf, errcap);
        f->transport->resp_free(&resp);
        return rc;
    }
    if (f->transport->resp_header(&resp, "Content-Length", cl, sizeof(cl)) == 0) {
        f->obj_size = (int64_t) strtoll(cl, NULL, 10);
    } else {
        f->obj_size = -1;
    }
    f->transport->resp_free(&resp);
    if (out_size != NULL) { *out_size = f->obj_size; }
    return 0;
}

ssize_t
sd_s3_pread(sd_s3_file *f, void *buf, size_t n, off_t off,
            char *errbuf, size_t errcap)
{
    char             auth[SD_S3_AUTH_HDRS_CAP];
    char             combined[SD_S3_AUTH_HDRS_CAP + 80];
    xrootd_s3_resp_t resp;
    const void      *body;
    size_t           body_len = 0, n_capped;
    ssize_t          copied;
    int64_t          end;
    int              cn;

    if (n == 0) {
        return 0;
    }
    n_capped = (n > (size_t) SD_S3_PREAD_MAX) ? (size_t) SD_S3_PREAD_MAX : n;
    end = (int64_t) off + (int64_t) n_capped - 1;

    if (sd_s3_sign(f, "GET", "", auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 GET: SigV4 sign failed on %s", f->key);
        return -1;
    }
    cn = snprintf(combined, sizeof(combined), "Range: bytes=%lld-%lld\r\n%s",
                  (long long) off, (long long) end, auth);
    if (cn < 0 || (size_t) cn >= sizeof(combined)) {
        sd_s3_set_err(errbuf, errcap, "s3 GET: header too long");
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "GET",
                              f->key, combined, NULL, 0, f->timeout_ms, &resp,
                              errbuf, errcap) != 0) {
        return -1;
    }
    if (resp.status == 416) {
        /* Range Not Satisfiable: the offset is at/after the object end - a
         * positional read past EOF returns 0 (the pread/copy-loop EOF signal). */
        f->transport->resp_free(&resp);
        return 0;
    }
    if (resp.status != 206 && resp.status != 200) {
        sd_s3_status_err(resp.status, "GET", f->key, errbuf, errcap);
        f->transport->resp_free(&resp);
        return -1;
    }
    body = f->transport->resp_body(&resp, &body_len);
    if (body == NULL || body_len == 0) {
        f->transport->resp_free(&resp);
        return 0;   /* EOF / empty range */
    }
    copied = (body_len < n_capped) ? (ssize_t) body_len : (ssize_t) n_capped;
    memcpy(buf, body, (size_t) copied);
    f->transport->resp_free(&resp);
    return copied;
}

int
sd_s3_delete(const sd_s3_open_params *p, char *errbuf, size_t errcap)
{
    sd_s3_file      *f;
    char             auth[SD_S3_AUTH_HDRS_CAP];
    xrootd_s3_resp_t resp;
    int              rc = 0;

    f = sd_s3_open_read(p, errbuf, errcap);   /* builds the handle; no I/O */
    if (f == NULL) {
        return -1;
    }
    if (sd_s3_sign(f, "DELETE", "", auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 DELETE: SigV4 sign failed on %s", f->key);
        sd_s3_close(f);
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "DELETE",
                              f->key, auth, NULL, 0, f->timeout_ms, &resp,
                              errbuf, errcap) != 0) {
        sd_s3_close(f);
        return -1;
    }
    /* S3 DELETE is idempotent: 204/200 succeed, 404 means already gone. */
    if (resp.status != 204 && resp.status != 200 && resp.status != 404) {
        rc = sd_s3_status_err(resp.status, "DELETE", f->key, errbuf, errcap);
    }
    f->transport->resp_free(&resp);
    sd_s3_close(f);
    return rc;
}

/* ---- write path: single PUT + multipart upload ----------------------- */

/* Extract <tag>…</tag> text from an XML body into out[outsz]. 0 / -1. */
static int
sd_s3_xml_tag(const char *xml, const char *tag, char *out, size_t outsz)
{
    char        open_tag[64], close_tag[64];
    const char *p, *e;
    size_t      n;

    snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
    p = strstr(xml, open_tag);
    if (p == NULL) { return -1; }
    p += strlen(open_tag);
    e = strstr(p, close_tag);
    if (e == NULL) { return -1; }
    n = (size_t) (e - p);
    if (n == 0 || n >= outsz) { return -1; }
    memcpy(out, p, n);
    out[n] = '\0';
    return 0;
}

static int
sd_s3_etag_ensure_cap(sd_s3_file *f, int needed, char *errbuf, size_t errcap)
{
    int              new_cap;
    sd_s3_part_etag *ne;

    if (f->etag_cap >= needed) { return 0; }
    new_cap = (f->etag_cap == 0) ? SD_S3_ETAG_INIT_CAP : f->etag_cap * 2;
    while (new_cap < needed) { new_cap *= 2; }
    ne = realloc(f->etags, (size_t) new_cap * sizeof(*ne));
    if (ne == NULL) {
        sd_s3_set_err(errbuf, errcap, "s3 mpu: out of memory for ETag array");
        return -1;
    }
    f->etags = ne;
    f->etag_cap = new_cap;
    return 0;
}

static int
sd_s3_mpu_upload_part(sd_s3_file *f, int part_num, const void *data, size_t len,
                      char *errbuf, size_t errcap)
{
    char             wire[SD_S3_KEY_MAX + 256], qs[256], auth[SD_S3_AUTH_HDRS_CAP];
    char             etag[SD_S3_ETAG_LEN];
    xrootd_s3_resp_t resp;
    int              pn;

    pn = snprintf(wire, sizeof(wire), "%s?partNumber=%d&uploadId=%s",
                  f->key, part_num, f->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(wire)) {
        sd_s3_set_err(errbuf, errcap, "s3 mpu: part path too long");
        return -1;
    }
    pn = snprintf(qs, sizeof(qs), "partNumber=%d&uploadId=%s",
                  part_num, f->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(qs)) {
        sd_s3_set_err(errbuf, errcap, "s3 mpu: canon_qs too long");
        return -1;
    }
    if (sd_s3_sign(f, "PUT", qs, auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 UploadPart: sign failed");
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "PUT", wire,
                              auth, data, len, f->timeout_ms, &resp,
                              errbuf, errcap) != 0) {
        return -1;
    }
    if (resp.status != 200) {
        int rc = sd_s3_status_err(resp.status, "UploadPart", f->key, errbuf, errcap);
        f->transport->resp_free(&resp);
        return rc;
    }
    etag[0] = '\0';
    f->transport->resp_header(&resp, "ETag", etag, sizeof(etag));
    f->transport->resp_free(&resp);
    if (etag[0] == '\0') {
        sd_s3_set_err(errbuf, errcap, "s3 UploadPart: server returned no ETag");
        return -1;
    }
    if (sd_s3_etag_ensure_cap(f, part_num, errbuf, errcap) != 0) {
        return -1;
    }
    snprintf(f->etags[part_num - 1].val, SD_S3_ETAG_LEN, "%s", etag);
    f->part_count = part_num;
    return 0;
}

static int
sd_s3_mpu_flush(sd_s3_file *f, char *errbuf, size_t errcap)
{
    if (f->part_buf_len == 0) { return 0; }
    if (sd_s3_mpu_upload_part(f, f->part_count + 1, f->part_buf,
                              f->part_buf_len, errbuf, errcap) != 0) {
        return -1;
    }
    f->part_buf_len = 0;
    return 0;
}

static int
sd_s3_mpu_create(sd_s3_file *f, char *errbuf, size_t errcap)
{
    char             wire[SD_S3_KEY_MAX + 16], auth[SD_S3_AUTH_HDRS_CAP];
    xrootd_s3_resp_t resp;
    const void      *body;
    size_t           blen = 0;
    int              pn;

    pn = snprintf(wire, sizeof(wire), "%s?uploads", f->key);
    if (pn < 0 || (size_t) pn >= sizeof(wire)) {
        sd_s3_set_err(errbuf, errcap, "s3 mpu: key path too long");
        return -1;
    }
    if (sd_s3_sign(f, "POST", "uploads=", auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 CreateMPU: sign failed");
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "POST", wire,
                              auth, NULL, 0, f->timeout_ms, &resp,
                              errbuf, errcap) != 0) {
        return -1;
    }
    if (resp.status != 200) {
        int rc = sd_s3_status_err(resp.status, "CreateMPU", f->key, errbuf, errcap);
        int e  = errno;                      /* preserve across resp_free cleanup */
        f->transport->resp_free(&resp);
        errno = e;
        return rc;
    }
    body = f->transport->resp_body(&resp, &blen);
    if (body == NULL || blen == 0
        || sd_s3_xml_tag((const char *) body, "UploadId",
                         f->upload_id, sizeof(f->upload_id)) != 0) {
        f->transport->resp_free(&resp);
        sd_s3_set_err(errbuf, errcap, "s3 CreateMPU: no <UploadId> in response");
        return -1;
    }
    f->transport->resp_free(&resp);
    return 0;
}

static int
sd_s3_mpu_complete(sd_s3_file *f, char *errbuf, size_t errcap)
{
    char             wire[SD_S3_KEY_MAX + SD_S3_UPLOAD_ID_LEN + 16];
    char             qs[SD_S3_UPLOAD_ID_LEN + 16], auth[SD_S3_AUTH_HDRS_CAP];
    xrootd_s3_resp_t resp;
    char            *xml;
    size_t           cap, len;
    int              i, pn;

    pn = snprintf(wire, sizeof(wire), "%s?uploadId=%s", f->key, f->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(wire)) {
        sd_s3_set_err(errbuf, errcap, "s3 CompleteMPU: path too long");
        return -1;
    }
    pn = snprintf(qs, sizeof(qs), "uploadId=%s", f->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(qs)) {
        sd_s3_set_err(errbuf, errcap, "s3 CompleteMPU: canon_qs too long");
        return -1;
    }
    cap = 120 + (size_t) f->part_count * (60 + SD_S3_ETAG_LEN) + 1;
    xml = malloc(cap);
    if (xml == NULL) {
        sd_s3_set_err(errbuf, errcap, "s3 CompleteMPU: out of memory for XML");
        return -1;
    }
    len = (size_t) snprintf(xml, cap,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<CompleteMultipartUpload>\n");
    for (i = 0; i < f->part_count; i++) {
        int w = snprintf(xml + len, cap - len,
                "  <Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>\n",
                i + 1, f->etags[i].val);
        if (w < 0 || (size_t) w >= cap - len) {
            free(xml);
            sd_s3_set_err(errbuf, errcap, "s3 CompleteMPU: XML overflow");
            return -1;
        }
        len += (size_t) w;
    }
    {
        int t = snprintf(xml + len, cap - len, "</CompleteMultipartUpload>\n");
        if (t < 0 || (size_t) t >= cap - len) {
            free(xml);
            sd_s3_set_err(errbuf, errcap, "s3 CompleteMPU: XML overflow (tail)");
            return -1;
        }
        len += (size_t) t;
    }
    if (sd_s3_sign(f, "POST", qs, auth, sizeof(auth)) != 0) {
        free(xml);
        sd_s3_set_err(errbuf, errcap, "s3 CompleteMPU: sign failed");
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "POST", wire,
                              auth, xml, len, f->timeout_ms, &resp,
                              errbuf, errcap) != 0) {
        free(xml);
        return -1;
    }
    free(xml);
    if (resp.status != 200) {
        int rc = sd_s3_status_err(resp.status, "CompleteMPU", f->key, errbuf, errcap);
        f->transport->resp_free(&resp);
        return rc;
    }
    f->transport->resp_free(&resp);
    return 0;
}

static void
sd_s3_mpu_abort(sd_s3_file *f)
{
    char             wire[SD_S3_KEY_MAX + SD_S3_UPLOAD_ID_LEN + 16];
    char             qs[SD_S3_UPLOAD_ID_LEN + 16], auth[SD_S3_AUTH_HDRS_CAP];
    xrootd_s3_resp_t resp;
    int              pn;

    if (f->upload_id[0] == '\0') { return; }
    pn = snprintf(wire, sizeof(wire), "%s?uploadId=%s", f->key, f->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(wire)) { return; }
    pn = snprintf(qs, sizeof(qs), "uploadId=%s", f->upload_id);
    if (pn < 0 || (size_t) pn >= sizeof(qs)) { return; }
    if (sd_s3_sign(f, "DELETE", qs, auth, sizeof(auth)) != 0) { return; }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "DELETE", wire,
                              auth, NULL, 0, f->timeout_ms, &resp,
                              NULL, 0) != 0) {
        return;   /* best-effort */
    }
    f->transport->resp_free(&resp);
}

static int
sd_s3_check_sequential(int64_t off, int64_t expected, char *errbuf, size_t errcap)
{
    if (off != expected) {
        sd_s3_set_err(errbuf, errcap,
            "s3 requires sequential writes (got %lld, expected %lld)",
            (long long) off, (long long) expected);
        errno = EINVAL;   /* usage error: maps to XRDC_EUSAGE / kXR_ArgInvalid */
        return -1;
    }
    return 0;
}

sd_s3_file *
sd_s3_open_write(const sd_s3_open_params *p, int64_t expected_size,
                 int64_t part_size, char *errbuf, size_t errcap)
{
    sd_s3_file *f = sd_s3_open_read(p, errbuf, errcap);
    if (f == NULL) {
        return NULL;
    }
    f->is_write  = 1;
    f->part_size = (part_size > 0) ? part_size : (64LL * 1024 * 1024);

    if (expected_size >= 0 && expected_size <= f->part_size) {
        /* single buffered PUT */
        size_t cap = (expected_size > 0) ? (size_t) expected_size
                                         : (size_t) SD_S3_PUT_BUF_INIT;
        if (cap < (size_t) SD_S3_PUT_BUF_INIT) { cap = SD_S3_PUT_BUF_INIT; }
        f->put_buf = malloc(cap);
        if (f->put_buf == NULL) {
            sd_s3_set_err(errbuf, errcap, "s3 open write: out of memory (PUT)");
            sd_s3_close(f);
            return NULL;
        }
        f->put_cap = cap;
    } else {
        /* multipart upload */
        if (sd_s3_mpu_create(f, errbuf, errcap) != 0) {
            int e = errno;               /* preserve the CreateMPU error class */
            sd_s3_close(f);
            errno = e;
            return NULL;
        }
        f->part_buf = malloc((size_t) f->part_size);
        if (f->part_buf == NULL) {
            sd_s3_set_err(errbuf, errcap, "s3 open write: out of memory (part)");
            sd_s3_mpu_abort(f);
            sd_s3_close(f);
            return NULL;
        }
        f->is_mpu = 1;
    }
    return f;
}

int
sd_s3_pwrite(sd_s3_file *f, const void *buf, size_t n, off_t off,
             char *errbuf, size_t errcap)
{
    if (!f->is_write) {
        sd_s3_set_err(errbuf, errcap, "s3 pwrite: handle opened for read");
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    if (f->is_mpu) {
        const char *src = (const char *) buf;
        size_t      rem = n;
        if (sd_s3_check_sequential((int64_t) off, f->mpu_write_off,
                                   errbuf, errcap) != 0) {
            return -1;
        }
        while (rem > 0) {
            size_t space  = (size_t) f->part_size - f->part_buf_len;
            size_t tocopy = (rem < space) ? rem : space;
            memcpy((char *) f->part_buf + f->part_buf_len, src, tocopy);
            f->part_buf_len += tocopy;
            src += tocopy;
            rem -= tocopy;
            if (f->part_buf_len == (size_t) f->part_size
                && sd_s3_mpu_flush(f, errbuf, errcap) != 0) {
                return -1;
            }
        }
        f->mpu_write_off = (int64_t) off + (int64_t) n;
        return 0;
    }

    /* single buffered PUT */
    if (sd_s3_check_sequential((int64_t) off, f->put_write_off,
                               errbuf, errcap) != 0) {
        return -1;
    }
    if (f->put_len + n > f->put_cap) {
        size_t nc = f->put_cap ? f->put_cap * 2 : SD_S3_PUT_BUF_INIT;
        void  *nb;
        while (nc < f->put_len + n) { nc *= 2; }
        nb = realloc(f->put_buf, nc);
        if (nb == NULL) {
            sd_s3_set_err(errbuf, errcap, "s3 single-put: out of memory");
            return -1;
        }
        f->put_buf = nb;
        f->put_cap = nc;
    }
    memcpy((char *) f->put_buf + f->put_len, buf, n);
    f->put_len += n;
    f->put_write_off = (int64_t) off + (int64_t) n;
    return 0;
}

int
sd_s3_commit(sd_s3_file *f, char *errbuf, size_t errcap)
{
    if (!f->is_write) {
        return 0;   /* read handle */
    }
    if (f->is_mpu) {
        if (sd_s3_mpu_flush(f, errbuf, errcap) != 0) {
            return -1;
        }
        if (f->part_count == 0
            && sd_s3_mpu_upload_part(f, 1, NULL, 0, errbuf, errcap) != 0) {
            return -1;   /* zero-byte object: one empty part */
        }
        return sd_s3_mpu_complete(f, errbuf, errcap);
    }
    /* single PUT of the whole buffer */
    {
        char             auth[SD_S3_AUTH_HDRS_CAP];
        xrootd_s3_resp_t resp;
        if (sd_s3_sign(f, "PUT", "", auth, sizeof(auth)) != 0) {
            sd_s3_set_err(errbuf, errcap, "s3 PUT: sign failed");
            return -1;
        }
        if (f->transport->request(f->tctx, f->host, f->port, f->tls, "PUT",
                                  f->key, auth, f->put_buf, f->put_len,
                                  f->timeout_ms, &resp, errbuf, errcap) != 0) {
            return -1;
        }
        if (resp.status != 200) {
            int rc = sd_s3_status_err(resp.status, "PUT", f->key, errbuf, errcap);
            f->transport->resp_free(&resp);
            return rc;
        }
        f->transport->resp_free(&resp);
    }
    return 0;
}

void
sd_s3_abort(sd_s3_file *f)
{
    if (f == NULL || !f->is_write) {
        return;
    }
    if (f->is_mpu) {
        sd_s3_mpu_abort(f);
    } else {
        f->put_len = 0;   /* drop the buffer; close() frees it */
    }
}

int64_t
sd_s3_write_size(const sd_s3_file *f)
{
    return f->is_mpu ? f->mpu_write_off : (int64_t) f->put_len;
}

void
sd_s3_close(sd_s3_file *f)
{
    if (f == NULL) {
        return;
    }
    free(f->put_buf);
    free(f->part_buf);
    free(f->etags);
    free(f);
}

/* ---- object metadata (x-amz-meta-*) ----------------------------------- */

ssize_t
sd_s3_get_meta(sd_s3_file *f, const char *name, char *buf, size_t cap,
               char *errbuf, size_t errcap)
{
    char             auth[SD_S3_AUTH_HDRS_CAP];
    char             hname[160];
    xrootd_s3_resp_t resp;
    int              n;

    if (f == NULL || name == NULL || buf == NULL || cap == 0) {
        sd_s3_set_err(errbuf, errcap, "s3 get-meta: bad parameters");
        return -1;
    }
    n = snprintf(hname, sizeof(hname), "x-amz-meta-%s", name);
    if (n < 0 || (size_t) n >= sizeof(hname)) {
        sd_s3_set_err(errbuf, errcap, "s3 get-meta: attribute name too long");
        return -1;
    }
    if (sd_s3_sign(f, "HEAD", "", auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 HEAD: SigV4 sign failed on %s", f->key);
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "HEAD",
                              f->key, auth, NULL, 0, f->timeout_ms, &resp,
                              errbuf, errcap) != 0)
    {
        return -1;
    }
    if (resp.status != 200) {
        int rc = sd_s3_status_err(resp.status, "HEAD", f->key, errbuf, errcap);
        f->transport->resp_free(&resp);
        return rc;   /* -1 */
    }
    if (f->transport->resp_header(&resp, hname, buf, cap) != 0) {
        f->transport->resp_free(&resp);
        buf[0] = '\0';
        return 0;    /* attribute absent */
    }
    f->transport->resp_free(&resp);
    return (ssize_t) strlen(buf);
}

int
sd_s3_get_unixattr(sd_s3_file *f, xrootd_meta_advisory_t *out,
                   char *errbuf, size_t errcap)
{
    char    blob[512];
    ssize_t n;

    if (out == NULL) {
        return -1;
    }
    n = sd_s3_get_meta(f, XROOTD_META_ADVISORY_S3META, blob, sizeof(blob),
                       errbuf, errcap);
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        return 0;    /* object carries no advisory metadata */
    }
    if (xrootd_meta_advisory_decode(blob, (size_t) n, out) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 get-unixattr: blob decode failed");
        return -1;
    }
    return 1;
}

/* One header for the extended SigV4 signer (name lowercase, value verbatim). */
typedef struct { const char *name; const char *value; } sd_s3_sign_hdr_t;

static int
sd_s3_sign_hdr_cmp(const void *a, const void *b)
{
    return strcmp(((const sd_s3_sign_hdr_t *) a)->name,
                  ((const sd_s3_sign_hdr_t *) b)->name);
}

/*
 * sd_s3_sign_ext — SigV4 over an arbitrary set of additional x-amz-* headers (on
 * top of the fixed host / x-amz-content-sha256 / x-amz-date). Used by set-meta,
 * whose copy-onto-self carries x-amz-copy-source, x-amz-metadata-directive and
 * the x-amz-meta-* pairs — all of which AWS requires in the signed header set.
 * Emits the complete request header block to send (the extra headers + the
 * Authorization line). 0 / -1. Reuses every kernel sd_s3_sign uses.
 */
static int
sd_s3_sign_ext(const sd_s3_file *f, const char *method, const char *canon_qs,
               const sd_s3_sign_hdr_t *extra, size_t n_extra,
               char *hdrs, size_t hdrsz)
{
    const char       *payload_hex = "UNSIGNED-PAYLOAD";
    char              host[300], amzdate[20], datestamp[12];
    char              canon_hex[65], sighex[65];
    char              scope[160], sts[640], enc_uri[2048];
    char              canon[16384], signed_list[2048];
    sd_s3_sign_hdr_t  all[3 + 32];
    uint8_t           k4[32], sig[32];
    size_t            n_all = 0, i, sl = 0;
    int               off, cn;

    if (n_extra > 32) {
        return -1;
    }
    if (canon_qs == NULL) {
        canon_qs = "";
    }
    xrootd_format_host_port(f->host, (uint16_t) f->port, host, sizeof(host));
    sd_s3_utc_now(amzdate, datestamp);
    if (xrootd_http_urlencode((const unsigned char *) f->key, strlen(f->key),
                              enc_uri, sizeof(enc_uri), "/") < 0)
    {
        return -1;
    }

    all[n_all].name = "host";                 all[n_all++].value = host;
    all[n_all].name = "x-amz-content-sha256"; all[n_all++].value = payload_hex;
    all[n_all].name = "x-amz-date";           all[n_all++].value = amzdate;
    for (i = 0; i < n_extra; i++) {
        all[n_all++] = extra[i];
    }
    qsort(all, n_all, sizeof(all[0]), sd_s3_sign_hdr_cmp);

    off = snprintf(canon, sizeof(canon), "%s\n%s\n%s\n", method, enc_uri,
                   canon_qs);
    if (off < 0 || (size_t) off >= sizeof(canon)) {
        return -1;
    }
    for (i = 0; i < n_all; i++) {
        cn = snprintf(canon + off, sizeof(canon) - (size_t) off, "%s:%s\n",
                      all[i].name, all[i].value);
        if (cn < 0 || (size_t) (off + cn) >= sizeof(canon)) {
            return -1;
        }
        off += cn;
        cn = snprintf(signed_list + sl, sizeof(signed_list) - sl, "%s%s",
                      (i ? ";" : ""), all[i].name);
        if (cn < 0 || sl + (size_t) cn >= sizeof(signed_list)) {
            return -1;
        }
        sl += (size_t) cn;
    }
    cn = snprintf(canon + off, sizeof(canon) - (size_t) off, "\n%s\n%s",
                  signed_list, payload_hex);
    if (cn < 0 || (size_t) (off + cn) >= sizeof(canon)) {
        return -1;
    }
    sd_s3_sha256_hex(canon, strlen(canon), canon_hex);

    cn = snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request", datestamp,
                  f->region);
    if (cn < 0 || (size_t) cn >= sizeof(scope)) {
        return -1;
    }
    cn = snprintf(sts, sizeof(sts), "AWS4-HMAC-SHA256\n%s\n%s\n%s", amzdate,
                  scope, canon_hex);
    if (cn < 0 || (size_t) cn >= sizeof(sts)) {
        return -1;
    }
    if (!xrootd_sigv4_signing_key((const uint8_t *) f->sk, strlen(f->sk),
                                  datestamp, f->region, "s3", k4)
        || !xrootd_hmac_sha256(k4, 32, (const uint8_t *) sts, strlen(sts), sig))
    {
        return -1;
    }
    xrootd_hex_encode(sig, 32, sighex);

    off = snprintf(hdrs, hdrsz,
                   "x-amz-date: %s\r\nx-amz-content-sha256: %s\r\n",
                   amzdate, payload_hex);
    if (off < 0 || (size_t) off >= hdrsz) {
        return -1;
    }
    for (i = 0; i < n_extra; i++) {
        cn = snprintf(hdrs + off, hdrsz - (size_t) off, "%s: %s\r\n",
                      extra[i].name, extra[i].value);
        if (cn < 0 || (size_t) (off + cn) >= hdrsz) {
            return -1;
        }
        off += cn;
    }
    cn = snprintf(hdrs + off, hdrsz - (size_t) off,
                  "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
                  "SignedHeaders=%s, Signature=%s\r\n",
                  f->ak, scope, signed_list, sighex);
    if (cn < 0 || (size_t) (off + cn) >= hdrsz) {
        return -1;
    }
    return 0;
}

static int
sd_s3_set_meta_f(sd_s3_file *f, const sd_s3_meta_kv *kv, size_t nkv,
                 char *errbuf, size_t errcap)
{
    char             auth[SD_S3_AUTH_HDRS_CAP];
    sd_s3_sign_hdr_t extra[2 + 32];
    char             names[32][160];
    char             lname[160];
    size_t           n_extra = 0, i, j, nl;
    xrootd_s3_resp_t resp;

    if (nkv > 32) {
        sd_s3_set_err(errbuf, errcap, "s3 set-meta: too many attributes");
        return -1;
    }
    /* Self-copy with REPLACE: update only metadata, never re-upload the bytes. */
    extra[n_extra].name = "x-amz-copy-source";
    extra[n_extra++].value = f->key;
    extra[n_extra].name = "x-amz-metadata-directive";
    extra[n_extra++].value = "REPLACE";

    for (i = 0; i < nkv; i++) {
        if (kv[i].name == NULL || kv[i].value == NULL) {
            sd_s3_set_err(errbuf, errcap, "s3 set-meta: null attribute");
            return -1;
        }
        nl = strlen(kv[i].name);
        if (nl >= sizeof(lname)) {
            sd_s3_set_err(errbuf, errcap, "s3 set-meta: attribute name too long");
            return -1;
        }
        for (j = 0; j < nl; j++) {     /* AWS lowercases user-metadata names */
            char c = kv[i].name[j];
            lname[j] = (c >= 'A' && c <= 'Z') ? (char) (c - 'A' + 'a') : c;
        }
        lname[nl] = '\0';
        if (snprintf(names[i], sizeof(names[i]), "x-amz-meta-%s", lname)
                >= (int) sizeof(names[i]))
        {
            sd_s3_set_err(errbuf, errcap, "s3 set-meta: attribute name too long");
            return -1;
        }
        extra[n_extra].name    = names[i];
        extra[n_extra++].value = kv[i].value;
    }

    if (sd_s3_sign_ext(f, "PUT", "", extra, n_extra, auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 set-meta: SigV4 sign failed on %s",
                      f->key);
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "PUT",
                              f->key, auth, NULL, 0, f->timeout_ms, &resp,
                              errbuf, errcap) != 0)
    {
        return -1;
    }
    if (resp.status != 200) {
        int rc = sd_s3_status_err(resp.status, "CopyObject(REPLACE)", f->key,
                                  errbuf, errcap);
        f->transport->resp_free(&resp);
        return rc;
    }
    f->transport->resp_free(&resp);
    return 0;
}

int
sd_s3_set_meta(const sd_s3_open_params *p, const sd_s3_meta_kv *kv, size_t nkv,
               char *errbuf, size_t errcap)
{
    sd_s3_file *f;
    int         rc;

    f = sd_s3_open_read(p, errbuf, errcap);   /* binds endpoint+creds, no I/O */
    if (f == NULL) {
        return -1;
    }
    rc = sd_s3_set_meta_f(f, kv, nkv, errbuf, errcap);
    sd_s3_close(f);
    return rc;
}

int
sd_s3_set_unixattr(const sd_s3_open_params *p, const xrootd_meta_advisory_t *a,
                   char *errbuf, size_t errcap)
{
    char          blob[256];
    sd_s3_meta_kv kv;

    if (a == NULL || xrootd_meta_advisory_encode(a, blob, sizeof(blob)) < 0) {
        sd_s3_set_err(errbuf, errcap, "s3 set-unixattr: advisory encode failed");
        return -1;
    }
    kv.name  = XROOTD_META_ADVISORY_S3META;
    kv.value = blob;
    return sd_s3_set_meta(p, &kv, 1, errbuf, errcap);
}
