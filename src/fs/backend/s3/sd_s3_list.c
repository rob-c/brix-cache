/*
 * sd_s3_list.c — S3 ListObjectsV2 (delimited, paged) for the shared S3 driver.
 *
 * WHAT: sd_s3_list_page() — one signed GET against the bucket root asking for a
 *       single directory level (delimiter '/'): <Contents> under the prefix are
 *       files, <CommonPrefixes> are sub-directories. Drives the sd_remote
 *       opendir/readdir namespace slots (finding #4).
 * WHY:  S3 has no readdir; a "directory listing" is a prefix+delimiter LIST. The
 *       logic lives here (once, ngx-free) rather than in the remote adapter so a
 *       future server-side lister reuses it.
 * HOW:  Build the sorted, RFC-3986-encoded canonical query once and use it both
 *       for the SigV4 signature and as the wire query, run it through the
 *       injected transport, and walk the XML body with a bounded scanner (no
 *       libxml2 dependency in the object path — the response schema is fixed and
 *       small). Keys are XML-unescaped (named + numeric entities, UTF-8).
 */

#include "sd_s3_internal.h"
#include "core/compat/uri.h"           /* brix_http_urlencode */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Locate `needle` in [hay, hay+hlen); NULL when absent. A tiny memmem so the TU
 * does not depend on _GNU_SOURCE. */
static const char *
s3l_find(const char *hay, size_t hlen, const char *needle)
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
    if (v < 0x80) {
        if (o + 1 >= cap) { return (size_t) -1; }
        out[o++] = (char) v;
    } else if (v < 0x800) {
        if (o + 2 >= cap) { return (size_t) -1; }
        out[o++] = (char) (0xC0 | (v >> 6));
        out[o++] = (char) (0x80 | (v & 0x3F));
    } else if (v < 0x10000) {
        if (o + 3 >= cap) { return (size_t) -1; }
        out[o++] = (char) (0xE0 | (v >> 12));
        out[o++] = (char) (0x80 | ((v >> 6) & 0x3F));
        out[o++] = (char) (0x80 | (v & 0x3F));
    } else {
        if (o + 4 >= cap) { return (size_t) -1; }
        out[o++] = (char) (0xF0 | (v >> 18));
        out[o++] = (char) (0x80 | ((v >> 12) & 0x3F));
        out[o++] = (char) (0x80 | ((v >> 6) & 0x3F));
        out[o++] = (char) (0x80 | (v & 0x3F));
    }
    return o;
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
static int
s3l_xml_unescape(const char *s, const char *e, char *out, size_t cap)
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

/* Emit one entry from a raw <Key>/<Prefix> value [vs,ve) to cb, stripping the
 * request prefix and (for dirs) the trailing '/'. Skips the directory-marker
 * object and anything that does not sit directly under the prefix. Returns cb's
 * stop signal (non-zero) or 0. */
static int
s3l_emit(const char *vs, const char *ve, const char *prefix, size_t plen,
    int is_dir, sd_s3_list_cb cb, void *ud)
{
    char   name[256];
    char   base[256];
    int    n;
    size_t blen;

    n = s3l_xml_unescape(vs, ve, name, sizeof(name));
    if (n < 0) {
        return 0;                            /* unrepresentable name — skip */
    }
    if ((size_t) n < plen || memcmp(name, prefix, plen) != 0) {
        return 0;                            /* not under the request prefix */
    }
    blen = (size_t) n - plen;                 /* basename (dirs keep trailing /) */
    if (is_dir) {
        if (blen == 0 || name[n - 1] != '/') {
            return 0;
        }
        blen--;                               /* drop the trailing '/' */
    }
    if (blen == 0) {
        return 0;                            /* the directory-marker object */
    }
    if (blen >= sizeof(base)) {
        return 0;                            /* longer than a dirent can hold */
    }
    memcpy(base, name + plen, blen);
    base[blen] = '\0';
    if (memchr(base, '/', blen) != NULL) {
        return 0;                            /* not a direct child (defensive) */
    }
    return cb(ud, base, is_dir);
}

/* The canonical-query buffer size; also bounds the request line. */
#define S3L_QS_CAP 4096

/* Build the canonical query string for one page: params sorted by name, values
 * RFC-3986 encoded (continuation-token < delimiter < list-type < max-keys <
 * prefix). The same bytes are the SigV4 canonical query AND the wire query.
 * Returns 0, or -1 with errno + errbuf set. */
static int
s3l_build_query(const char *prefix, size_t plen, const char *cont_in,
    char *qs, size_t qscap, char *errbuf, size_t errcap)
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
            "%s%s%sdelimiter=%%2F&list-type=2&max-keys=1000&prefix=%s",
            enc_cont[0] ? "continuation-token=" : "",
            enc_cont,
            enc_cont[0] ? "&" : "",
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
static int
s3l_fetch(const sd_s3_open_params *p, const char *qs, sd_s3_file **f_out,
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

/* Bracket the text of the FIRST <tag>…</tag> within [scan,end) as [*out_s,*out_e)
 * (raw bytes, unescaped by the caller). Returns 1 when found, 0 otherwise. */
static int
s3l_first_text(const char *scan, const char *end, const char *open_tag,
    const char *close_tag, const char **out_s, const char **out_e)
{
    const char *o = s3l_find(scan, (size_t) (end - scan), open_tag);
    const char *c;

    if (o == NULL) {
        return 0;
    }
    o += strlen(open_tag);
    c = s3l_find(o, (size_t) (end - o), close_tag);
    if (c == NULL) {
        return 0;
    }
    *out_s = o;
    *out_e = c;
    return 1;
}

/* IsTruncated / NextContinuationToken (best-effort; a page with neither is a
 * complete, final page). */
static void
s3l_page_meta(const char *body, const char *end, int *truncated,
    char *cont_out, size_t cont_cap)
{
    const char *ts;
    const char *te;

    if (s3l_first_text(body, end, "<IsTruncated>", "</IsTruncated>", &ts, &te)) {
        *truncated = ((size_t) (te - ts) == 4 && memcmp(ts, "true", 4) == 0);
    }
    if (*truncated
        && s3l_first_text(body, end, "<NextContinuationToken>",
               "</NextContinuationToken>", &ts, &te))
    {
        size_t tl = (size_t) (te - ts);

        if (tl >= cont_cap) { tl = cont_cap - 1; }
        memcpy(cont_out, ts, tl);
        cont_out[tl] = '\0';
    }
}

/* Walk <Contents>/<CommonPrefixes> in document order; the top-level <Prefix>
 * precedes both, so per-block extraction never mistakes it for an entry. */
static void
s3l_walk(const char *body, const char *end, const char *prefix, size_t plen,
    sd_s3_list_cb cb, void *ud)
{
    const char *scan = body;
    int         stopped = 0;

    while (!stopped && scan < end) {
        const char *c  = s3l_find(scan, (size_t) (end - scan), "<Contents>");
        const char *cp = s3l_find(scan, (size_t) (end - scan),
                                  "<CommonPrefixes>");
        const char *ts;
        const char *te;
        const char *block;
        const char *tag;
        const char *open_tag;
        const char *close_tag;
        int         is_dir;

        if (c == NULL && cp == NULL) {
            break;
        }
        is_dir    = (c == NULL) || (cp != NULL && cp < c);
        block     = is_dir ? cp : c;
        tag       = is_dir ? "<CommonPrefixes>" : "<Contents>";
        open_tag  = is_dir ? "<Prefix>" : "<Key>";
        close_tag = is_dir ? "</Prefix>" : "</Key>";

        if (s3l_first_text(block, end, open_tag, close_tag, &ts, &te)) {
            stopped = s3l_emit(ts, te, prefix, plen, is_dir, cb, ud);
            scan    = te;
        } else {
            scan = block + strlen(tag);
        }
    }
}

int
sd_s3_list_page(const sd_s3_open_params *p, const char *prefix,
    const char *cont_in, sd_s3_list_cb cb, void *ud, int *truncated,
    char *cont_out, size_t cont_cap, char *errbuf, size_t errcap)
{
    char             qs[S3L_QS_CAP];
    brix_s3_resp_t   resp;
    sd_s3_file      *f = NULL;
    const char      *body;
    size_t           blen = 0;
    size_t           plen;
    int              rc;

    if (p == NULL || prefix == NULL || cb == NULL || truncated == NULL
        || cont_out == NULL || cont_cap == 0)
    {
        errno = EINVAL;
        sd_s3_set_err(errbuf, errcap, "s3 list: bad parameters");
        return -1;
    }
    *truncated  = 0;
    cont_out[0] = '\0';
    plen = strlen(prefix);

    if (s3l_build_query(prefix, plen, cont_in, qs, sizeof(qs),
            errbuf, errcap) != 0) {
        return -1;
    }
    rc = s3l_fetch(p, qs, &f, &resp, errbuf, errcap);
    if (rc != 0) {
        return rc;
    }

    body = f->transport->resp_body(&resp, &blen);
    if (body == NULL) {
        blen = 0;
        body = "";
    }
    s3l_page_meta(body, body + blen, truncated, cont_out, cont_cap);
    s3l_walk(body, body + blen, prefix, plen, cb, ud);

    f->transport->resp_free(&resp);
    sd_s3_close(f);
    return 0;
}
