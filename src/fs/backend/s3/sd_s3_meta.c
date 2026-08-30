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

/*
 * WHAT: Run an already-signed HEAD and hand back the LIVE response. 0 with
 *       *resp filled (the caller must resp_free it), or -1 with errbuf set.
 * WHY:  Three readers want the same wire leg and the same status verdict — a
 *       user-metadata attribute, a stored checksum, and the archive-state pair
 *       (sd_s3_archive.c) — and they differ only in what they sign and which
 *       headers they then pull out. Handing back the live response rather than
 *       one extracted value is what lets the archive reader take THREE headers
 *       off ONE round trip instead of HEADing the object three times.
 * HOW:  The caller signs (the signer differs: a plain HEAD vs one carrying an
 *       extra x-amz-* header, which AWS requires in the signed set) and passes
 *       the finished header block. Non-200 is mapped and the response released
 *       here, so a failing caller never has to remember to free.
 */
int
sd_s3_head_send(sd_s3_file *f, const char *hdrs, brix_s3_resp_t *resp,
                char *errbuf, size_t errcap)
{
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "HEAD",
                              f->key, hdrs, NULL, 0, f->timeout_ms, resp,
                              errbuf, errcap) != 0)
    {
        return -1;
    }
    if (resp->status != 200) {
        int rc = sd_s3_status_err(resp->status, "HEAD", f->key, errbuf, errcap);
        f->transport->resp_free(resp);
        return rc;   /* -1 */
    }
    return 0;
}

/*
 * WHAT: One named response header off an already-signed HEAD. >0 = the value's
 *       length, 0 = the header is absent, -1 = error (errbuf).
 * WHY:  An absent header is NOT an error: on S3 it means "this object carries
 *       no such value", which both the metadata and the checksum reader report
 *       as a decline rather than a failure.
 */
static ssize_t
sd_s3_head_header(sd_s3_file *f, const char *hdrs, const char *want,
                  const sd_s3_meta_buf *out, char *errbuf, size_t errcap)
{
    brix_s3_resp_t resp;

    if (sd_s3_head_send(f, hdrs, &resp, errbuf, errcap) != 0) {
        return -1;
    }
    if (f->transport->resp_header(&resp, want, out->buf, out->cap) != 0) {
        f->transport->resp_free(&resp);
        out->buf[0] = '\0';
        return 0;    /* header absent */
    }
    f->transport->resp_free(&resp);
    return (ssize_t) strlen(out->buf);
}

ssize_t
sd_s3_get_meta(sd_s3_file *f, const char *name, const sd_s3_meta_buf *out,
               char *errbuf, size_t errcap)
{
    char             auth[SD_S3_AUTH_HDRS_CAP];
    char             hname[160];
    int              n;

    if (f == NULL || name == NULL || out == NULL || out->buf == NULL
        || out->cap == 0)
    {
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
    return sd_s3_head_header(f, auth, hname, out, errbuf, errcap);
}

ssize_t
sd_s3_get_checksum(sd_s3_file *f, const char *hdr_name,
                   const sd_s3_meta_buf *out, char *errbuf, size_t errcap)
{
    /* HeadObject returns a stored checksum only when asked; the ETag comes back
     * either way, so one request shape serves both. AWS requires every x-amz-*
     * header a request carries to be in the SIGNED set, hence sd_s3_sign_ext. */
    static const sd_s3_sign_hdr_t ck_mode = { "x-amz-checksum-mode", "ENABLED" };
    const sd_s3_sign_req_t        req = { "HEAD", "", &ck_mode, 1 };
    char                          auth[SD_S3_AUTH_HDRS_CAP];

    if (f == NULL || hdr_name == NULL || out == NULL || out->buf == NULL
        || out->cap == 0)
    {
        sd_s3_set_err(errbuf, errcap, "s3 get-checksum: bad parameters");
        return -1;
    }
    if (sd_s3_sign_ext(f, &req, auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 HEAD: SigV4 sign failed on %s", f->key);
        return -1;
    }
    return sd_s3_head_header(f, auth, hdr_name, out, errbuf, errcap);
}

/* One "user.<name>" listxattr entry from a raw "x-amz-meta-<name>: v" header
 * line. Appends to buf[*used..cap) when buf is non-NULL and always advances
 * *need by the entry size; the caller compares need vs cap at the end. */
static void
sd_s3_list_meta_emit(const char *name, size_t nlen, char *buf, size_t cap,
                     size_t *need)
{
    size_t entry = sizeof("user.") - 1 + nlen + 1;

    if (buf != NULL && *need + entry <= cap) {
        memcpy(buf + *need, "user.", sizeof("user.") - 1);
        memcpy(buf + *need + sizeof("user.") - 1, name, nlen);
        buf[*need + entry - 1] = '\0';
    }
    *need += entry;
}

/* Scan the raw response header block for "x-amz-meta-<name>:" lines and emit
 * each as a "user.<name>" listxattr entry (the advisory blob is skipped — it
 * surfaces as POSIX attrs, not as a user xattr). Returns the total byte need;
 * the caller compares it against cap. */
static size_t
sd_s3_list_meta_scan(const char *hdrs, char *buf, size_t cap)
{
    static const char pfx[] = "x-amz-meta-";
    const size_t      pfxlen = sizeof(pfx) - 1;
    const char       *p;
    size_t            need = 0;

    for (p = hdrs; *p != '\0'; ) {
        const char *eol = p + strcspn(p, "\r\n");
        const char *colon;

        if ((size_t) (eol - p) > pfxlen
            && strncasecmp(p, pfx, pfxlen) == 0
            && (colon = memchr(p, ':', (size_t) (eol - p))) != NULL
            && colon > p + pfxlen)
        {
            const char *name = p + pfxlen;
            size_t      nlen = (size_t) (colon - name);

            /* The advisory blob surfaces as POSIX attrs, not as a user xattr. */
            if (nlen != sizeof(BRIX_META_ADVISORY_S3META) - 1
                || strncasecmp(name, BRIX_META_ADVISORY_S3META, nlen) != 0)
            {
                sd_s3_list_meta_emit(name, nlen, buf, cap, &need);
            }
        }
        p = eol + strspn(eol, "\r\n");
    }
    return need;
}

ssize_t
sd_s3_list_meta(sd_s3_file *f, char *buf, size_t cap,
                char *errbuf, size_t errcap)
{
    char              auth[SD_S3_AUTH_HDRS_CAP];
    brix_s3_resp_t    resp;
    const char       *hdrs;
    size_t            need;

    if (f == NULL) {
        sd_s3_set_err(errbuf, errcap, "s3 list-meta: bad parameters");
        errno = EINVAL;
        return -1;
    }
    if (f->transport->resp_headers_raw == NULL) {
        sd_s3_set_err(errbuf, errcap,
                      "s3 list-meta: transport cannot enumerate headers");
        errno = ENOTSUP;
        return -1;
    }
    if (sd_s3_sign(f, "HEAD", "", auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 HEAD: SigV4 sign failed on %s", f->key);
        errno = EIO;
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "HEAD",
                              f->key, auth, NULL, 0, f->timeout_ms, &resp,
                              errbuf, errcap) != 0)
    {
        errno = EIO;
        return -1;
    }
    if (resp.status != 200) {
        int rc = sd_s3_status_err(resp.status, "HEAD", f->key, errbuf, errcap);
        f->transport->resp_free(&resp);
        return rc;   /* -1, errno mapped from the HTTP status */
    }
    hdrs = f->transport->resp_headers_raw(&resp);
    if (hdrs == NULL) {
        f->transport->resp_free(&resp);
        sd_s3_set_err(errbuf, errcap, "s3 list-meta: no raw header block");
        errno = ENOTSUP;
        return -1;
    }

    need = sd_s3_list_meta_scan(hdrs, buf, cap);
    f->transport->resp_free(&resp);

    if (buf == NULL || cap == 0) {
        return (ssize_t) need;   /* listxattr(2) size probe */
    }
    if (need > cap) {
        sd_s3_set_err(errbuf, errcap, "s3 list-meta: buffer too small");
        errno = ERANGE;
        return -1;
    }
    return (ssize_t) need;
}

int
sd_s3_get_unixattr(sd_s3_file *f, brix_meta_advisory_t *out,
                   char *errbuf, size_t errcap)
{
    char           blob[512];
    ssize_t        n;
    sd_s3_meta_buf dst = { blob, sizeof(blob) };

    if (out == NULL) {
        return -1;
    }
    n = sd_s3_get_meta(f, BRIX_META_ADVISORY_S3META, &dst, errbuf, errcap);
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


static int
sd_s3_set_meta_f(sd_s3_file *f, const sd_s3_meta_kv *kv, size_t nkv,
                 char *errbuf, size_t errcap)
{
    char             auth[SD_S3_AUTH_HDRS_CAP];
    sd_s3_sign_hdr_t extra[2 + 32];
    sd_s3_sign_req_t req;
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

    req.method   = "PUT";
    req.canon_qs = "";
    req.extra    = extra;
    req.n_extra  = n_extra;
    if (sd_s3_sign_ext(f, &req, auth, sizeof(auth)) != 0) {
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

/* ---- server-side CopyObject (x-amz-copy-source) ------------------------ */

/* Send the signed CopyObject PUT: the request target is f->key (the destination
 * object), x-amz-copy-source names the source "/bucket/key". Default COPY
 * directive — the source's user metadata rides along. Same signing + status
 * discipline as the set-meta self-copy above. 0 / -1 (errno + errbuf). */
static int
sd_s3_copy_f(sd_s3_file *f, const char *copy_source, char *errbuf, size_t errcap)
{
    char             auth[SD_S3_AUTH_HDRS_CAP];
    sd_s3_sign_hdr_t extra[1];
    sd_s3_sign_req_t req;
    brix_s3_resp_t   resp;

    extra[0].name  = "x-amz-copy-source";
    extra[0].value = copy_source;

    req.method   = "PUT";
    req.canon_qs = "";
    req.extra    = extra;
    req.n_extra  = 1;
    if (sd_s3_sign_ext(f, &req, auth, sizeof(auth)) != 0) {
        sd_s3_set_err(errbuf, errcap, "s3 copy: SigV4 sign failed on %s", f->key);
        errno = EIO;
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "PUT",
                              f->key, auth, NULL, 0, f->timeout_ms, &resp,
                              errbuf, errcap) != 0)
    {
        errno = EIO;
        return -1;
    }
    if (resp.status != 200) {
        int rc = sd_s3_status_err(resp.status, "CopyObject", copy_source,
                                  errbuf, errcap);
        f->transport->resp_free(&resp);
        return rc;   /* -1, errno mapped from the HTTP status */
    }
    f->transport->resp_free(&resp);
    return 0;
}

int
sd_s3_copy(const sd_s3_open_params *p, const char *copy_source,
           char *errbuf, size_t errcap)
{
    sd_s3_file *f;
    int         rc;

    if (p == NULL || copy_source == NULL || copy_source[0] == '\0') {
        sd_s3_set_err(errbuf, errcap, "s3 copy: bad parameters");
        errno = EINVAL;
        return -1;
    }
    f = sd_s3_open_read(p, errbuf, errcap);   /* binds endpoint+creds, no I/O */
    if (f == NULL) {
        errno = ENOMEM;
        return -1;
    }
    rc = sd_s3_copy_f(f, copy_source, errbuf, errcap);
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
