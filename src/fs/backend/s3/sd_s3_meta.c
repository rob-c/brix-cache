/*
 * sd_s3_meta.c — S3 object metadata (x-amz-meta-*) get/set + POSIX unixattr
 * advisory encoding.  Split out of sd_s3.c: the metadata path (HEAD to read
 * user metadata, and metadata-copy PUT to set it) with its own extended SigV4
 * signer (sd_s3_sign_ext, which must sign the x-amz-meta-* headers).  Uses the
 * shared sd_s3_file layout + signing primitives via sd_s3_internal.h; the public
 * entry points (sd_s3_get_meta/set_meta/get_unixattr/set_unixattr) are declared
 * in sd_s3.h.
 */

#include "sd_s3_internal.h"
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
#include <sys/time.h>

/* ---- object metadata (x-amz-meta-*) ----------------------------------- */

ssize_t
sd_s3_get_meta(sd_s3_file *f, const char *name, char *buf, size_t cap,
               char *errbuf, size_t errcap)
{
    char             auth[SD_S3_AUTH_HDRS_CAP];
    char             hname[160];
    brix_s3_resp_t resp;
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
sd_s3_get_unixattr(sd_s3_file *f, brix_meta_advisory_t *out,
                   char *errbuf, size_t errcap)
{
    char    blob[512];
    ssize_t n;

    if (out == NULL) {
        return -1;
    }
    n = sd_s3_get_meta(f, BRIX_META_ADVISORY_S3META, blob, sizeof(blob),
                       errbuf, errcap);
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        return 0;    /* object carries no advisory metadata */
    }
    if (brix_meta_advisory_decode(blob, (size_t) n, out) != 0) {
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
    brix_format_host_port(f->host, (uint16_t) f->port, host, sizeof(host));
    sd_s3_utc_now(amzdate, datestamp);
    if (brix_http_urlencode((const unsigned char *) f->key, strlen(f->key),
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
    if (!brix_sigv4_signing_key((const uint8_t *) f->sk, strlen(f->sk),
                                  datestamp, f->region, "s3", k4)
        || !brix_hmac_sha256(k4, 32, (const uint8_t *) sts, strlen(sts), sig))
    {
        return -1;
    }
    brix_hex_encode(sig, 32, sighex);

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
    brix_s3_resp_t resp;

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
sd_s3_set_unixattr(const sd_s3_open_params *p, const brix_meta_advisory_t *a,
                   char *errbuf, size_t errcap)
{
    char          blob[256];
    sd_s3_meta_kv kv;

    if (a == NULL || brix_meta_advisory_encode(a, blob, sizeof(blob)) < 0) {
        sd_s3_set_err(errbuf, errcap, "s3 set-unixattr: advisory encode failed");
        return -1;
    }
    kv.name  = BRIX_META_ADVISORY_S3META;
    kv.value = blob;
    return sd_s3_set_meta(p, &kv, 1, errbuf, errcap);
}
