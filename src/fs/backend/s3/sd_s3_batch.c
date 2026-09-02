/*
 * sd_s3_batch.c - S3 DeleteObjects: one signed POST for up to 1,000 keys.
 *
 * WHAT: sd_s3_delete_many(), the batch twin of sd_s3_delete() (sd_s3.c). Builds
 *       the <Delete> XML body, signs "POST /bucket?delete" with SigV4, sends it
 *       once, and maps the per-key <Error> entries back onto the caller's
 *       result vector.
 * WHY:  Phase-107 C4: a DeleteObjects of 1,000 keys over an s3:// backend was
 *       1,000 signed DELETE round trips whose whole purpose was to avoid
 *       exactly that. The S3 protocol has carried the batch verb since day one;
 *       this driver just never spoke it.
 * HOW:  Quiet mode (<Quiet>true</Quiet>): the origin answers ONLY the failures,
 *       so success is the absence of an <Error> block, and a 1,000-key
 *       all-green response is a few hundred bytes instead of ~100 KB. AWS
 *       requires Content-MD5 on this verb (MinIO enforces it as
 *       MissingContentMD5), so the body digest rides as a SIGNED header via
 *       sd_s3_sign_ext - which also lets an STS session token join the signed
 *       set, unlike the fixed-shape signer. ngx-free (transport-injected) like
 *       every sibling in this directory.
 */
#include "sd_s3.h"
#include "sd_s3_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>   /* MD5 + base64 for the required Content-MD5 header */

/* Bytes the XML wrapper needs per key, beyond the escaped key text itself. */
#define S3_BATCH_PER_KEY_OVERHEAD  (sizeof("<Object><Key></Key></Object>") - 1)

/* Escaped length of one key: '&'->&amp; '<'->&lt; '>'->&gt; '"'->&quot;
 * '\''->&apos;. The five XML predefined entities - a key is client-supplied
 * text and MUST NOT be able to open or close markup in the body we sign. */
static size_t
s3_batch_escape_len(const char *s)
{
    size_t n = 0;

    for (; *s != '\0'; s++) {
        switch (*s) {
        case '&':              n += sizeof("&amp;") - 1;  break;
        case '<':              n += sizeof("&lt;") - 1;   break;
        case '>':              n += sizeof("&gt;") - 1;   break;
        case '"':              n += sizeof("&quot;") - 1; break;
        case '\'':             n += sizeof("&apos;") - 1; break;
        default:               n += 1;                    break;
        }
    }
    return n;
}

/* Append the XML-escaped key at dst; the caller sized dst via
 * s3_batch_escape_len, so this cannot overflow. Returns bytes written. */
static size_t
s3_batch_escape(char *dst, const char *s)
{
    size_t off = 0;

    for (; *s != '\0'; s++) {
        const char *rep = NULL;

        switch (*s) {
        case '&':  rep = "&amp;";  break;
        case '<':  rep = "&lt;";   break;
        case '>':  rep = "&gt;";   break;
        case '"':  rep = "&quot;"; break;
        case '\'': rep = "&apos;"; break;
        default:   dst[off++] = *s; continue;
        }
        memcpy(dst + off, rep, strlen(rep));
        off += strlen(rep);
    }
    return off;
}

/* malloc the <Delete> body for `keys[n]`; *blen_out = body length. NULL on
 * OOM. Quiet mode - the response then carries only the failures. */
static char *
s3_batch_build_body(const char *const *keys, size_t n, size_t *blen_out)
{
    static const char head[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Quiet>true</Quiet>";
    static const char tail[] = "</Delete>";
    char   *body;
    size_t  cap, off, i;

    cap = sizeof(head) - 1 + sizeof(tail) - 1 + 1;
    for (i = 0; i < n; i++) {
        cap += S3_BATCH_PER_KEY_OVERHEAD + s3_batch_escape_len(keys[i]);
    }
    body = malloc(cap);
    if (body == NULL) {
        return NULL;
    }
    memcpy(body, head, sizeof(head) - 1);
    off = sizeof(head) - 1;
    for (i = 0; i < n; i++) {
        memcpy(body + off, "<Object><Key>", sizeof("<Object><Key>") - 1);
        off += sizeof("<Object><Key>") - 1;
        off += s3_batch_escape(body + off, keys[i]);
        memcpy(body + off, "</Key></Object>", sizeof("</Key></Object>") - 1);
        off += sizeof("</Key></Object>") - 1;
    }
    memcpy(body + off, tail, sizeof(tail) - 1);
    off += sizeof(tail) - 1;
    body[off] = '\0';
    *blen_out = off;
    return body;
}

/* base64(MD5(body)) -> out[25] ("" on failure): the RFC 1864 Content-MD5 value
 * AWS requires on DeleteObjects. Same EVP shape as sd_http_content_md5. */
static void
s3_batch_content_md5(const void *buf, size_t len, char out[25])
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  mdlen = 0;

    out[0] = '\0';
    if (EVP_Digest(buf, len, md, &mdlen, EVP_md5(), NULL) != 1 || mdlen != 16) {
        return;
    }
    EVP_EncodeBlock((unsigned char *) out, md, 16);   /* 16 -> 24 chars + NUL */
}

/* One S3 <Error><Code> -> errno. AccessDenied is the security-relevant one
 * (the caller answers it per key, never for the whole batch); NoSuchKey stays
 * ENOENT verbatim - the CALLER decides idempotency (sd_batch_types.h). */
static int
s3_batch_errno_from_code(const char *code, size_t len)
{
    if (len == sizeof("AccessDenied") - 1
        && memcmp(code, "AccessDenied", len) == 0)
    {
        return EACCES;
    }
    if ((len == sizeof("NoSuchKey") - 1
         && memcmp(code, "NoSuchKey", len) == 0)
        || (len == sizeof("NoSuchBucket") - 1
            && memcmp(code, "NoSuchBucket", len) == 0))
    {
        return ENOENT;
    }
    return EIO;
}

/* Decode the XML-escaped `src[len]` into dst[dstcap] (NUL-terminated); the
 * origin echoes each failed key exactly as escaped in our request body. */
static void
s3_batch_unescape(const char *src, size_t len, char *dst, size_t dstcap)
{
    static const struct { const char *ent; size_t n; char ch; } tab[] = {
        { "&amp;",  5, '&'  }, { "&lt;",   4, '<'  }, { "&gt;",   4, '>'  },
        { "&quot;", 6, '"'  }, { "&apos;", 6, '\'' },
    };
    size_t i = 0, o = 0, t;

    while (i < len && o + 1 < dstcap) {
        if (src[i] == '&') {
            for (t = 0; t < sizeof(tab) / sizeof(tab[0]); t++) {
                if (len - i >= tab[t].n
                    && memcmp(src + i, tab[t].ent, tab[t].n) == 0)
                {
                    break;
                }
            }
            if (t < sizeof(tab) / sizeof(tab[0])) {
                dst[o++] = tab[t].ch;
                i += tab[t].n;
                continue;
            }
        }
        dst[o++] = src[i++];
    }
    dst[o] = '\0';
}

/* Pull the text of `<tag>` out of the error block [blk, blk_end). Returns the
 * start and sets *tlen, or NULL when the tag is absent. */
static const char *
s3_batch_block_tag(const char *blk, const char *blk_end, const char *open,
    const char *close, size_t *tlen)
{
    const char *s, *e;

    s = strstr(blk, open);
    if (s == NULL || s >= blk_end) {
        return NULL;
    }
    s += strlen(open);
    e = strstr(s, close);
    if (e == NULL || e > blk_end) {
        return NULL;
    }
    *tlen = (size_t) (e - s);
    return s;
}

/* Walk the quiet-mode <DeleteResult> and set errs[i] for every <Error> block
 * whose <Key> matches one of ours. An unmatched or malformed block is a
 * response-integrity failure worth surfacing on the WHOLE batch (-1/EIO):
 * a per-key verdict we cannot attribute must not be silently dropped. */
static int
s3_batch_apply_errors(const char *xml, const char *const *keys, size_t n,
    int *errs)
{
    const char *p = xml, *blk, *blk_end, *k, *c;
    char        raw[SD_S3_KEY_MAX];
    size_t      klen, clen, i;

    while ((blk = strstr(p, "<Error>")) != NULL) {
        blk_end = strstr(blk, "</Error>");
        if (blk_end == NULL) {
            return -1;
        }
        k = s3_batch_block_tag(blk, blk_end, "<Key>", "</Key>", &klen);
        c = s3_batch_block_tag(blk, blk_end, "<Code>", "</Code>", &clen);
        if (k == NULL || c == NULL) {
            return -1;
        }
        s3_batch_unescape(k, klen, raw, sizeof(raw));
        for (i = 0; i < n; i++) {
            if (strcmp(raw, keys[i]) == 0) {
                errs[i] = s3_batch_errno_from_code(c, clen);
                break;
            }
        }
        if (i == n) {
            return -1;              /* a verdict for a key we never sent */
        }
        p = blk_end + sizeof("</Error>") - 1;
    }
    return 0;
}

/*
 * sd_s3_delete_many - delete up to 1,000 object keys in ONE signed request.
 *
 * p->key is the "/bucket" request target (no object part); keys[i] are the
 * object keys WITHIN the bucket (no leading '/'). errs[n] receives 0 or a
 * positive errno per key - S3 DeleteObjects is idempotent, so an absent key
 * comes back deleted (errs 0), while AccessDenied stays per-key. On success
 * *done = n (the origin attempted every key). On a batch-level failure (sign /
 * transport / non-200 / unparseable response) *done = 0, errno is set, errbuf
 * describes it, and errs is untouched: the caller pre-filled it, and no key
 * was verifiably attempted. Returns 0 / -1.
 */
/* Build, MD5-seal, SigV4-sign, and POST the <Delete> body for keys[0..n)
 * over f's transport. On success the response (whatever its status) is handed
 * back in *resp for the caller to judge and free; -1 with errno set on an
 * alloc, sign, or transport failure (errbuf describes it, *resp untouched). */
static int
s3_batch_post(sd_s3_file *f, const char *const *keys, size_t n,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    sd_s3_sign_hdr_t   extra[2];
    sd_s3_sign_req_t   req = { "POST", "delete=", extra, 1 };
    char               auth[SD_S3_AUTH_HDRS_CAP];
    char               wire[SD_S3_KEY_MAX + 16];
    char               md5b64[25];
    char              *body;
    size_t             blen = 0;
    int                pn;

    body = s3_batch_build_body(keys, n, &blen);
    if (body == NULL) {
        errno = ENOMEM;
        return -1;
    }
    s3_batch_content_md5(body, blen, md5b64);
    extra[0].name  = "content-md5";
    extra[0].value = md5b64;
    if (f->session_token[0] != '\0') {
        extra[1].name  = "x-amz-security-token";
        extra[1].value = f->session_token;
        req.n_extra    = 2;
    }
    pn = snprintf(wire, sizeof(wire), "%s?delete", f->key);
    if (pn < 0 || (size_t) pn >= sizeof(wire) || md5b64[0] == '\0'
        || sd_s3_sign_ext(f, &req, auth, sizeof(auth)) != 0)
    {
        sd_s3_set_err(errbuf, errcap, "s3 DeleteObjects: SigV4 sign failed");
        free(body);
        errno = EIO;
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "POST", wire,
                              auth, body, blen, f->timeout_ms, resp,
                              errbuf, errcap) != 0)
    {
        if (errno == 0) { errno = EIO; }
        free(body);
        return -1;
    }
    free(body);
    return 0;
}

int
sd_s3_delete_many(const sd_s3_open_params *p, const char *const *keys,
    size_t n, int *errs, size_t *done, char *errbuf, size_t errcap)
{
    sd_s3_file        *f;
    const void        *rbody;
    size_t             rlen = 0, i;
    brix_s3_resp_t     resp;
    int                rc;

    *done = 0;
    if (n == 0) {
        return 0;
    }
    f = sd_s3_open_read(p, errbuf, errcap);      /* handle only; no I/O */
    if (f == NULL) {
        errno = ENOMEM;
        return -1;
    }
    if (s3_batch_post(f, keys, n, &resp, errbuf, errcap) != 0) {
        sd_s3_close(f);
        return -1;
    }
    if (resp.status != 200) {
        rc = sd_s3_status_err(resp.status, "DeleteObjects", f->key,
                              errbuf, errcap);
        f->transport->resp_free(&resp);
        sd_s3_close(f);
        return rc;
    }
    for (i = 0; i < n; i++) {
        errs[i] = 0;
    }
    rbody = f->transport->resp_body(&resp, &rlen);
    if (rbody != NULL && rlen > 0
        && s3_batch_apply_errors((const char *) rbody, keys, n, errs) != 0)
    {
        sd_s3_set_err(errbuf, errcap,
            "s3 DeleteObjects: unattributable <Error> in response");
        f->transport->resp_free(&resp);
        sd_s3_close(f);
        errno = EIO;
        return -1;
    }
    f->transport->resp_free(&resp);
    sd_s3_close(f);
    *done = n;
    return 0;
}
