/*
 * sd_s3_write.c — S3 write path: single buffered PUT + multipart upload.
 *
 * Split verbatim out of sd_s3.c: open-for-write, sequential pwrite buffering,
 * commit (single PUT or flush-last-part + CompleteMultipartUpload), abort, and
 * the write-size accessor, plus the private MPU helpers (CreateMPU, UploadPart,
 * flush, CompleteMPU, AbortMPU, ETag-array growth, and the CompleteMPU XML
 * <UploadId>/<ETag> tag extraction). Shares the sd_s3_file layout and the SigV4
 * signing + error-mapping primitives through sd_s3_internal.h; reuses the read
 * path's sd_s3_open_read / sd_s3_close (declared in sd_s3.h).
 */
#include "sd_s3.h"
#include "sd_s3_internal.h"     /* sd_s3_file layout + SigV4/error primitives (split out) */

#include "core/compat/crypto.h"        /* brix_sha256 / brix_hmac_sha256 */
#include "core/compat/hex.h"           /* brix_hex_encode */
#include "core/compat/sigv4.h"         /* brix_sigv4_signing_key */
#include "core/compat/uri.h"           /* brix_http_urlencode */
#include "core/compat/host_format.h"   /* brix_format_host_port */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>   /* gettimeofday — NOT <time.h>, which `-I src/compat`
                         * shadows with compat/time.h (a known conflict; that
                         * helper is module-only, absent from libxrdproto). */

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
    brix_s3_resp_t resp;
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
    brix_s3_resp_t resp;
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
    brix_s3_resp_t resp;
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
    brix_s3_resp_t resp;
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
        brix_s3_resp_t resp;
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
