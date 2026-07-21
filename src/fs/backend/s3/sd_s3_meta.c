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
sd_s3_get_meta(sd_s3_file *f, const char *name, const sd_s3_meta_buf *out,
               char *errbuf, size_t errcap)
{
    char             auth[SD_S3_AUTH_HDRS_CAP];
    char             hname[160];
    brix_s3_resp_t resp;
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
    if (f->transport->resp_header(&resp, hname, out->buf, out->cap) != 0) {
        f->transport->resp_free(&resp);
        out->buf[0] = '\0';
        return 0;    /* attribute absent */
    }
    f->transport->resp_free(&resp);
    return (ssize_t) strlen(out->buf);
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

ssize_t
sd_s3_list_meta(sd_s3_file *f, char *buf, size_t cap,
                char *errbuf, size_t errcap)
{
    static const char pfx[] = "x-amz-meta-";
    const size_t      pfxlen = sizeof(pfx) - 1;
    char              auth[SD_S3_AUTH_HDRS_CAP];
    brix_s3_resp_t    resp;
    const char       *hdrs, *p;
    size_t            need = 0;

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

/* One header for the extended SigV4 signer (name lowercase, value verbatim). */
typedef struct { const char *name; const char *value; } sd_s3_sign_hdr_t;

/* What to sign: the request identity a caller hands to sd_s3_sign_ext. */
typedef struct {
    const char             *method;    /* HTTP verb */
    const char             *canon_qs;  /* canonical query string (NULL = "") */
    const sd_s3_sign_hdr_t *extra;     /* additional x-amz-* headers */
    size_t                  n_extra;   /* count of extra headers (max 32) */
} sd_s3_sign_req_t;

static int
sd_s3_sign_hdr_cmp(const void *a, const void *b)
{
    return strcmp(((const sd_s3_sign_hdr_t *) a)->name,
                  ((const sd_s3_sign_hdr_t *) b)->name);
}

/*
 * sd_s3_sign_ctx_t — file-local working state for the extended SigV4 signer.
 * Carries the request identity (method / query string / extra headers), the
 * fixed signed-header values (host, x-amz-date, payload hash) and every
 * intermediate the pipeline stages hand to each other (sorted header set,
 * canonical-request hash, credential scope, signed-header list, signature).
 * One struct instead of 7+ loose parameters per helper.
 */
typedef struct {
    const char             *method;        /* HTTP verb being signed */
    const char             *canon_qs;      /* canonical query string ("" ok) */
    const char             *payload_hex;   /* payload hash (UNSIGNED-PAYLOAD) */
    const sd_s3_sign_hdr_t *extra;         /* caller's additional headers */
    size_t                  n_extra;
    sd_s3_sign_hdr_t        all[3 + 32];   /* fixed + extra, sorted for canon */
    size_t                  n_all;
    char                    host[300];     /* Host header value */
    char                    amzdate[20];   /* x-amz-date (ISO8601 basic) */
    char                    datestamp[12]; /* YYYYMMDD for the scope */
    char                    enc_uri[2048]; /* URI-encoded object key */
    char                    signed_list[2048]; /* "a;b;c" SignedHeaders */
    char                    canon_hex[65]; /* SHA-256(canonical request) hex */
    char                    scope[160];    /* date/region/s3/aws4_request */
    char                    sighex[65];    /* final signature, hex */
} sd_s3_sign_ctx_t;

/*
 * sd_s3_sign_prepare — stage 1: bind the request identity into the signing
 * context.  Formats host:port, stamps the current UTC time, URI-encodes the
 * object key, then assembles the full signed-header set (fixed host /
 * x-amz-content-sha256 / x-amz-date plus the caller's extras) sorted by name
 * as SigV4 canonicalization requires.  0 / -1 (key too long to encode).
 */
static int
sd_s3_sign_prepare(const sd_s3_file *f, sd_s3_sign_ctx_t *sx)
{
    size_t  i;

    brix_format_host_port(f->host, (uint16_t) f->port, sx->host,
                          sizeof(sx->host));
    sd_s3_utc_now(sx->amzdate, sx->datestamp);
    if (brix_http_urlencode((const unsigned char *) f->key, strlen(f->key),
                              sx->enc_uri, sizeof(sx->enc_uri), "/") < 0)
    {
        return -1;
    }

    sx->n_all = 0;
    sx->all[sx->n_all].name = "host";
    sx->all[sx->n_all++].value = sx->host;
    sx->all[sx->n_all].name = "x-amz-content-sha256";
    sx->all[sx->n_all++].value = sx->payload_hex;
    sx->all[sx->n_all].name = "x-amz-date";
    sx->all[sx->n_all++].value = sx->amzdate;
    for (i = 0; i < sx->n_extra; i++) {
        sx->all[sx->n_all++] = sx->extra[i];
    }
    qsort(sx->all, sx->n_all, sizeof(sx->all[0]), sd_s3_sign_hdr_cmp);
    return 0;
}

/*
 * sd_s3_canonical_request — stage 2: build the SigV4 canonical request
 * (method \n uri \n qs \n sorted "name:value\n" headers \n signed-list \n
 * payload-hash) and hash it into sx->canon_hex; also accumulates the
 * ";"-joined SignedHeaders list the Authorization line reuses.  The canonical
 * buffer itself never leaves this frame — only its SHA-256 matters.  0 / -1
 * on truncation.
 */
static int
sd_s3_canonical_request(sd_s3_sign_ctx_t *sx)
{
    char    canon[16384];
    size_t  i, sl = 0;
    int     off, cn;

    off = snprintf(canon, sizeof(canon), "%s\n%s\n%s\n", sx->method,
                   sx->enc_uri, sx->canon_qs);
    if (off < 0 || (size_t) off >= sizeof(canon)) {
        return -1;
    }
    for (i = 0; i < sx->n_all; i++) {
        cn = snprintf(canon + off, sizeof(canon) - (size_t) off, "%s:%s\n",
                      sx->all[i].name, sx->all[i].value);
        if (cn < 0 || (size_t) off + (size_t) cn >= sizeof(canon)) {
            return -1;
        }
        off += cn;
        cn = snprintf(sx->signed_list + sl, sizeof(sx->signed_list) - sl,
                      "%s%s", (i ? ";" : ""), sx->all[i].name);
        if (cn < 0 || sl + (size_t) cn >= sizeof(sx->signed_list)) {
            return -1;
        }
        sl += (size_t) cn;
    }
    cn = snprintf(canon + off, sizeof(canon) - (size_t) off, "\n%s\n%s",
                  sx->signed_list, sx->payload_hex);
    if (cn < 0 || (size_t) off + (size_t) cn >= sizeof(canon)) {
        return -1;
    }
    sd_s3_sha256_hex(canon, strlen(canon), sx->canon_hex);
    return 0;
}

/*
 * sd_s3_string_to_sign — stage 3a: derive the credential scope
 * (date/region/s3/aws4_request → sx->scope) and format the SigV4
 * string-to-sign ("AWS4-HMAC-SHA256\n date \n scope \n canon-hash") into the
 * caller's buffer.  0 / -1 on truncation.
 */
static int
sd_s3_string_to_sign(const sd_s3_file *f, sd_s3_sign_ctx_t *sx,
                     char *sts, size_t stscap)
{
    int  cn;

    cn = snprintf(sx->scope, sizeof(sx->scope), "%s/%s/s3/aws4_request",
                  sx->datestamp, f->region);
    if (cn < 0 || (size_t) cn >= sizeof(sx->scope)) {
        return -1;
    }
    cn = snprintf(sts, stscap, "AWS4-HMAC-SHA256\n%s\n%s\n%s", sx->amzdate,
                  sx->scope, sx->canon_hex);
    if (cn < 0 || (size_t) cn >= stscap) {
        return -1;
    }
    return 0;
}

/*
 * sd_s3_derive_key_and_sign — stage 3b: run the SigV4 key-derivation chain
 * (secret → date → region → service → aws4_request) and HMAC the
 * string-to-sign with the derived key, hex-encoding the signature into
 * sx->sighex.  0 / -1 if any crypto primitive fails.
 */
static int
sd_s3_derive_key_and_sign(const sd_s3_file *f, sd_s3_sign_ctx_t *sx,
                          const char *sts)
{
    uint8_t  k4[32], sig[32];

    if (!brix_sigv4_signing_key((const uint8_t *) f->sk, strlen(f->sk),
                                  sx->datestamp, f->region, "s3", k4)
        || !brix_hmac_sha256(k4, 32, (const uint8_t *) sts, strlen(sts), sig))
    {
        return -1;
    }
    brix_hex_encode(sig, 32, sx->sighex);
    return 0;
}

/*
 * sd_s3_emit_auth_header — stage 4: write the complete request header block
 * the transport sends: x-amz-date, x-amz-content-sha256, every extra header
 * verbatim (in caller order — the sorted set was for canonicalization only),
 * then the Authorization line carrying credential scope, SignedHeaders and
 * the signature.  0 / -1 on truncation.
 */
static int
sd_s3_emit_auth_header(const sd_s3_file *f, const sd_s3_sign_ctx_t *sx,
                       char *hdrs, size_t hdrsz)
{
    size_t  i;
    int     off, cn;

    off = snprintf(hdrs, hdrsz,
                   "x-amz-date: %s\r\nx-amz-content-sha256: %s\r\n",
                   sx->amzdate, sx->payload_hex);
    if (off < 0 || (size_t) off >= hdrsz) {
        return -1;
    }
    for (i = 0; i < sx->n_extra; i++) {
        cn = snprintf(hdrs + off, hdrsz - (size_t) off, "%s: %s\r\n",
                      sx->extra[i].name, sx->extra[i].value);
        if (cn < 0 || (size_t) off + (size_t) cn >= hdrsz) {
            return -1;
        }
        off += cn;
    }
    cn = snprintf(hdrs + off, hdrsz - (size_t) off,
                  "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
                  "SignedHeaders=%s, Signature=%s\r\n",
                  f->ak, sx->scope, sx->signed_list, sx->sighex);
    if (cn < 0 || (size_t) off + (size_t) cn >= hdrsz) {
        return -1;
    }
    return 0;
}

/*
 * sd_s3_sign_ext — SigV4 over an arbitrary set of additional x-amz-* headers (on
 * top of the fixed host / x-amz-content-sha256 / x-amz-date). Used by set-meta,
 * whose copy-onto-self carries x-amz-copy-source, x-amz-metadata-directive and
 * the x-amz-meta-* pairs — all of which AWS requires in the signed header set.
 * Emits the complete request header block to send (the extra headers + the
 * Authorization line). 0 / -1. Reuses every kernel sd_s3_sign uses.  Pure
 * pipeline: prepare → canonical request → string-to-sign → sign → emit.
 */
static int
sd_s3_sign_ext(const sd_s3_file *f, const sd_s3_sign_req_t *req,
               char *hdrs, size_t hdrsz)
{
    sd_s3_sign_ctx_t  sx;
    char              sts[640];

    if (req->n_extra > 32) {
        return -1;
    }
    sx.method      = req->method;
    sx.canon_qs    = (req->canon_qs != NULL) ? req->canon_qs : "";
    sx.payload_hex = "UNSIGNED-PAYLOAD";
    sx.extra       = req->extra;
    sx.n_extra     = req->n_extra;

    if (sd_s3_sign_prepare(f, &sx) != 0
        || sd_s3_canonical_request(&sx) != 0
        || sd_s3_string_to_sign(f, &sx, sts, sizeof(sts)) != 0
        || sd_s3_derive_key_and_sign(f, &sx, sts) != 0)
    {
        return -1;
    }
    return sd_s3_emit_auth_header(f, &sx, hdrs, hdrsz);
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
