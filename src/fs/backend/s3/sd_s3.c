/*
 * sd_s3.c — shared S3 storage driver, read path. See sd_s3.h.
 *
 * Ported from client/lib/vfs_s3*.c with two changes that make it shareable:
 *   1. the HTTP transport is injected (sd_s3_transport.h) instead of calling the
 *      client's xrdc_http_* directly;
 *   2. the error model is a neutral (rc, errbuf) pair instead of xrdc_status.
 * SigV4 signing uses the same shared kernels (sigv4 / crypto / hex / uri) the
 * server's verify path uses, so client-signs == server-verifies byte-for-byte.
 *
 * The SigV4 signing + error-mapping primitives live in sd_s3_sign.c; the
 * single-PUT / multipart write path lives in sd_s3_write.c. Both share the
 * sd_s3_file layout via sd_s3_internal.h.
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
    brix_s3_resp_t resp;

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
    brix_s3_resp_t resp;
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

    /* Hostile / broken in-path integrity guards.  A ranged GET must come back as
     * a 206 whose Content-Range starts exactly at the byte we asked for.  Any
     * other shape means an in-path box (or a non-compliant origin) shifted the
     * range, replied with the whole object, or emptied the body — and blindly
     * copying that lands the WRONG bytes at `off`, or truncates the object, a
     * silent corruption the TCP checksum cannot catch.  Fail the read (EIO) so
     * the copy loop aborts rather than committing bad data.  These are the exact
     * failure modes of a flaky NIC / meddling middlebox on an uncooperative
     * network, so the check is unconditional, not gated behind a knob. */
    if (resp.status == 200 && off != 0) {
        /* Range ignored: a 200 body starts at object offset 0, not `off`, so it
         * cannot be positioned at `off` without corrupting the read. */
        sd_s3_set_err(errbuf, errcap,
            "s3 GET %s: origin ignored Range (200 for bytes=%lld-) - refusing to "
            "position a whole-object body at offset %lld",
            f->key, (long long) off, (long long) off);
        f->transport->resp_free(&resp);
        return -1;
    }
    if (resp.status == 206) {
        char      cr[128];
        long long cr_start = -1;

        if (f->transport->resp_header(&resp, "Content-Range", cr, sizeof(cr)) == 0
            && (sscanf(cr, "bytes %lld-", &cr_start) != 1
                || cr_start != (long long) off))
        {
            sd_s3_set_err(errbuf, errcap,
                "s3 GET %s: Content-Range \"%.80s\" does not start at requested "
                "offset %lld - refusing a misaligned/mangled range",
                f->key, cr, (long long) off);
            f->transport->resp_free(&resp);
            return -1;
        }
    }

    body = f->transport->resp_body(&resp, &body_len);
    if (body == NULL || body_len == 0) {
        /* A well-formed but empty body at an offset the object provably extends
         * past is NOT EOF — it is a truncated / emptied response a broken in-path
         * box can forge (curl sees a complete zero-length body, so the transport
         * layer cannot catch it).  Treat it as a fault so the fill aborts instead
         * of silently truncating the object down to `off` bytes. */
        int at_eof = (f->obj_size >= 0)
                     ? (off >= f->obj_size)
                     : (resp.status == 200);
        f->transport->resp_free(&resp);
        if (!at_eof) {
            sd_s3_set_err(errbuf, errcap,
                "s3 GET %s: empty body at offset %lld before object end "
                "(size %lld) - treating as a truncated response, not EOF",
                f->key, (long long) off, (long long) f->obj_size);
            return -1;
        }
        return 0;   /* genuine EOF / empty object */
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
    brix_s3_resp_t resp;
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
