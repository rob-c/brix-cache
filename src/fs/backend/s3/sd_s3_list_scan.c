/*
 * sd_s3_list_scan.c — shared XML scanner and signed-request plumbing for the
 *                     S3 ListObjectsV2 listers.
 *
 * WHAT: the pieces both listing shapes need — a bounded memmem, XML entity
 *       unescaping, first-tag text bracketing, the canonical-query builder and
 *       the signed GET itself, plus IsTruncated/NextContinuationToken.
 * WHY:  S3 answers "what is in this directory" (delimited, sd_s3_list.c) and
 *       "what objects does this export hold" (flat, sd_s3_list_flat.c) with the
 *       SAME request differing only in one query parameter. Sharing the request
 *       and scanner here keeps the SigV4 canonicalisation — where a one-byte
 *       divergence surfaces as an opaque SignatureDoesNotMatch — in exactly one
 *       place, and keeps each lister under the file-size cap.
 * HOW:  ngx-free and transport-injected, like the rest of the S3 driver. The
 *       scanner is deliberately a bounded tag walk rather than an XML parser:
 *       the response schema is fixed and small, and libxml2 has no business in
 *       the object read path.
 */

#include "sd_s3_list_internal.h"
#include "core/compat/uri.h"           /* brix_http_urlencode */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Locate `needle` in [hay, hay+hlen); NULL when absent. A tiny memmem so the TU
 * does not depend on _GNU_SOURCE. */
const char *
sd_s3l_find(const char *hay, size_t hlen, const char *needle)
{
    size_t nlen = strlen(needle);
    size_t i;

    if (nlen == 0 || nlen > hlen) {
        return NULL;
    }
    for (i = 0; i + nlen <= hlen; i++) {
        if (hay[i] == needle[0] && memcmp(hay + i, needle, nlen) == 0) {
            return hay + i;
        }
    }
    return NULL;
}

/* Append the UTF-8 encoding of code point `v` to out[o..cap). Returns the new
 * length, or (size_t)-1 on overflow. */
static size_t
s3l_utf8_put(char *out, size_t o, size_t cap, long v)
{
    static const unsigned lead[5] = { 0, 0x00, 0xC0, 0xE0, 0xF0 };
    size_t n = (v < 0x80) ? 1 : (v < 0x800) ? 2 : (v < 0x10000) ? 3 : 4;
    size_t i;

    if (o + n >= cap) {
        return (size_t) -1;
    }
    out[o] = (char) (lead[n] | (v >> (6 * (n - 1))));
    for (i = 1; i < n; i++) {
        out[o + i] = (char) (0x80 | ((v >> (6 * (n - 1 - i))) & 0x3F));
    }
    return o + n;
}

/* The named entities an S3 ListObjects answer may carry. */
static const struct { const char *name; size_t len; char ch; } S3L_ENTS[] = {
    { "amp",  3, '&'  },
    { "lt",   2, '<'  },
    { "gt",   2, '>'  },
    { "quot", 4, '"'  },
    { "apos", 4, '\'' },
};

/* Map an entity body (the bytes between '&' and ';') to its character, or '\0'
 * when the name is not one we know. */
static char
s3l_entity_char(const char *ent, size_t elen)
{
    size_t i;

    for (i = 0; i < sizeof(S3L_ENTS) / sizeof(S3L_ENTS[0]); i++) {
        if (elen == S3L_ENTS[i].len && memcmp(ent, S3L_ENTS[i].name, elen) == 0) {
            return S3L_ENTS[i].ch;
        }
    }
    return '\0';
}

/* Decode a numeric character reference (&#NN; or &#xHH;) into out[cap] at `o`.
 * Returns the new offset, or (size_t) -1 on a malformed reference, an
 * out-of-range code point, or overflow. */
static size_t
s3l_numeric_ref(const char *ent, const char *semi, char *out, size_t o,
                size_t cap)
{
    char *endp;
    long  v = (ent[1] == 'x' || ent[1] == 'X') ? strtol(ent + 2, &endp, 16)
                                               : strtol(ent + 1, &endp, 10);

    if (endp != semi || v < 0 || v > 0x10FFFF) {
        return (size_t) -1;
    }
    return s3l_utf8_put(out, o, cap, v);
}

/* Append one literal byte, keeping room for the terminator. -1 when full. */
static int
s3l_put(char *out, size_t *o, size_t cap, char c)
{
    if (*o + 1 >= cap) {
        return -1;
    }
    out[(*o)++] = c;
    return 0;
}

/* Unescape XML text [s,e) (named + numeric entities) into out[cap], NUL-
 * terminated. Returns the byte length, or -1 on overflow or a malformed numeric
 * entity. */
int
sd_s3l_xml_unescape(const char *s, const char *e, char *out, size_t cap)
{
    size_t o = 0;

    while (s < e) {
        const char *semi;
        const char *ent;
        size_t      elen;
        char        ch;

        if (*s != '&') {
            if (s3l_put(out, &o, cap, *s++) != 0) { return -1; }
            continue;
        }
        semi = memchr(s, ';', (size_t) (e - s));
        if (semi == NULL) {                 /* stray '&' — pass through */
            if (s3l_put(out, &o, cap, *s++) != 0) { return -1; }
            continue;
        }
        ent  = s + 1;
        elen = (size_t) (semi - ent);
        if (elen >= 2 && ent[0] == '#') {
            o = s3l_numeric_ref(ent, semi, out, o, cap);
            if (o == (size_t) -1) { return -1; }
            s = semi + 1;
            continue;
        }
        ch = s3l_entity_char(ent, elen);
        if (ch == '\0') {                   /* unknown entity — pass through */
            if (s3l_put(out, &o, cap, *s++) != 0) { return -1; }
            continue;
        }
        if (s3l_put(out, &o, cap, ch) != 0) { return -1; }
        s = semi + 1;
    }
    if (o >= cap) { return -1; }
    out[o] = '\0';
    return (int) o;
}

/* Bracket the text of the FIRST <tag>…</tag> within [scan,end) as [*out_s,*out_e)
 * (raw bytes, unescaped by the caller). Returns 1 when found, 0 otherwise. */
int
sd_s3l_first_text(const char *scan, const char *end, const char *open_tag,
    const char *close_tag, const char **out_s, const char **out_e)
{
    const char *o = sd_s3l_find(scan, (size_t) (end - scan), open_tag);
    const char *c;

    if (o == NULL) {
        return 0;
    }
    o += strlen(open_tag);
    c = sd_s3l_find(o, (size_t) (end - o), close_tag);
    if (c == NULL) {
        return 0;
    }
    *out_s = o;
    *out_e = c;
    return 1;
}

/* Build the canonical query string for one page: params sorted by name, values
 * RFC-3986 encoded (continuation-token < delimiter < list-type < max-keys <
 * prefix). The same bytes are the SigV4 canonical query AND the wire query.
 * `delimited` picks the shape: with it, one directory level (delimiter=%2F, so
 * S3 folds deeper keys into <CommonPrefixes>); without it, the flat recursive
 * listing the catalog verb wants — every key under the prefix, at any depth,
 * with no CommonPrefixes at all. Sort order is unaffected: dropping the
 * `delimiter` param removes a whole element rather than reordering any.
 * Returns 0, or -1 with errno + errbuf set. */
int
sd_s3l_build_query(const char *prefix, size_t plen, const char *cont_in,
    int delimited, char *qs, size_t qscap, char *errbuf, size_t errcap)
{
    char enc_prefix[3072];
    char enc_cont[3072];
    int  qn;

    if (brix_http_urlencode((const unsigned char *) prefix, plen,
            enc_prefix, sizeof(enc_prefix), NULL) < 0)
    {
        errno = ENAMETOOLONG;
        sd_s3_set_err(errbuf, errcap, "s3 list: prefix too long");
        return -1;
    }
    enc_cont[0] = '\0';
    if (cont_in != NULL && cont_in[0] != '\0'
        && brix_http_urlencode((const unsigned char *) cont_in,
               strlen(cont_in), enc_cont, sizeof(enc_cont), NULL) < 0)
    {
        errno = ENAMETOOLONG;
        sd_s3_set_err(errbuf, errcap, "s3 list: continuation token too long");
        return -1;
    }
    qn = snprintf(qs, qscap,
            "%s%s%s%slist-type=2&max-keys=1000&prefix=%s",
            enc_cont[0] ? "continuation-token=" : "",
            enc_cont,
            enc_cont[0] ? "&" : "",
            delimited ? "delimiter=%2F&" : "",
            enc_prefix);
    if (qn < 0 || (size_t) qn >= qscap) {
        errno = ENAMETOOLONG;
        sd_s3_set_err(errbuf, errcap, "s3 list: query too long");
        return -1;
    }
    return 0;
}

/* Run one signed ListObjectsV2 GET. On success returns 0 with *f_out bound and
 * *resp filled (the caller releases both); on failure returns -1 with errno and
 * errbuf set and nothing left to release. */
int
sd_s3l_fetch(const sd_s3_open_params *p, const char *qs, sd_s3_file **f_out,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    char        wire[SD_S3_KEY_MAX + S3L_QS_CAP + 2];
    char        auth[SD_S3_AUTH_HDRS_CAP];
    sd_s3_file *f;
    int         qn, rc;

    f = sd_s3_open_read(p, errbuf, errcap);   /* no I/O; binds endpoint + creds */
    if (f == NULL) {
        errno = ENOMEM;
        return -1;
    }
    if (sd_s3_sign(f, "GET", qs, auth, sizeof(auth)) != 0) {
        sd_s3_close(f);
        errno = EIO;
        sd_s3_set_err(errbuf, errcap, "s3 list: SigV4 sign failed");
        return -1;
    }
    qn = snprintf(wire, sizeof(wire), "%s?%s", f->key, qs);
    if (qn < 0 || (size_t) qn >= sizeof(wire)) {
        sd_s3_close(f);
        errno = ENAMETOOLONG;
        sd_s3_set_err(errbuf, errcap, "s3 list: request line too long");
        return -1;
    }
    if (f->transport->request(f->tctx, f->host, f->port, f->tls, "GET", wire,
            auth, NULL, 0, f->timeout_ms, resp, errbuf, errcap) != 0)
    {
        sd_s3_close(f);
        errno = EIO;
        return -1;
    }
    if (resp->status != 200) {
        rc = sd_s3_status_err(resp->status, "ListObjectsV2", f->key,
                              errbuf, errcap);
        f->transport->resp_free(resp);
        sd_s3_close(f);
        return rc;                            /* -1, errno set by status_err */
    }
    *f_out = f;
    return 0;
}

/* IsTruncated / NextContinuationToken (best-effort; a page with neither is a
 * complete, final page). */
void
sd_s3l_page_meta(const char *body, const char *end, int *truncated,
    char *cont_out, size_t cont_cap)
{
    const char *ts;
    const char *te;

    if (sd_s3l_first_text(body, end, "<IsTruncated>", "</IsTruncated>", &ts, &te)) {
        *truncated = ((size_t) (te - ts) == 4 && memcmp(ts, "true", 4) == 0);
    }
    if (*truncated
        && sd_s3l_first_text(body, end, "<NextContinuationToken>",
               "</NextContinuationToken>", &ts, &te))
    {
        size_t tl = (size_t) (te - ts);

        if (tl >= cont_cap) { tl = cont_cap - 1; }
        memcpy(cont_out, ts, tl);
        cont_out[tl] = '\0';
    }
}
