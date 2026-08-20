/*
 * rpm_repomd.c — the warm-set extractor for a repository index.
 *
 * See rpm_repomd.h for WHAT/WHY/HOW. The shape this file reads is the one
 * createrepo writes:
 *
 *     <repomd …>
 *       <data type="primary">
 *         <checksum type="sha256">…</checksum>
 *         <location href="repodata/<hex>-primary.xml.gz"/>
 *       </data>
 *       <data type="filelists"> … </data>
 *     </repomd>
 *
 * It is deliberately NOT a general XML reader. Everything it takes out of the
 * document is one attribute value, and that value is then re-checked by the
 * request grammar before it can turn into a fetch — so the parser's job is to
 * be conservative and finite, not complete. A document it does not recognise
 * yields an empty warm set, which costs a cold client exactly what it costs
 * today.
 */

#include "rpm_repomd.h"

#include <stdio.h>
#include <string.h>

/* The `type=` values worth warming, in the order dnf asks for them. */
static const char *rpm_repomd_warm_types[] = { "primary", "filelists" };


static const char *
rpm_mem_find(const char *hay, size_t n, const char *needle)
{
    size_t nl = strlen(needle);
    size_t i;

    if (nl == 0 || nl > n) {
        return NULL;
    }
    for (i = 0; i + nl <= n; i++) {
        if (hay[i] == needle[0] && memcmp(hay + i, needle, nl) == 0) {
            return hay + i;
        }
    }
    return NULL;
}


/* The value of attribute `name` inside the span [p, p+n), double-quoted the
 * way every createrepo release writes it. Single quotes are legal XML and are
 * not accepted: a repomd this mirror cannot read is one it declines to
 * speculate on, and that is a cache miss rather than a wrong fetch. */
static int
rpm_attr(const char *p, size_t n, const char *name, const char **val,
    size_t *val_len)
{
    char        pat[32];
    const char *at, *end;
    size_t      used;

    used = (size_t) snprintf(pat, sizeof(pat), "%s=\"", name);
    if (used >= sizeof(pat)) {
        return -1;
    }
    at = rpm_mem_find(p, n, pat);
    if (at == NULL) {
        return -1;
    }
    at += used;
    end = memchr(at, '"', (size_t) (p + n - at));
    if (end == NULL) {
        return -1;
    }
    *val     = at;
    *val_len = (size_t) (end - at);
    return 0;
}


/* An href this mirror is willing to turn into a fetch. The composition below
 * cannot make an unsafe path safe, so everything that could make one is
 * refused here: an absolute path or a scheme would leave the repository, a
 * `..` would leave it upwards, and an XML entity would mean the byte the
 * client resolves is not the byte this fetched. */
static int
rpm_href_ok(const char *p, size_t n)
{
    size_t i;

    if (n == 0 || n >= BRIX_RPM_REPOMD_HREF_MAX || p[0] == '/') {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (p[i] == ':' || p[i] == '&' || p[i] == '\\' || p[i] == '%'
            || (unsigned char) p[i] <= 0x20 || (unsigned char) p[i] >= 0x7f)
        {
            return 0;
        }
        if (p[i] == '.' && i + 1 < n && p[i + 1] == '.') {
            return 0;
        }
    }
    return 1;
}


static int
rpm_type_is_warm(const char *p, size_t n)
{
    size_t i;

    for (i = 0; i < sizeof(rpm_repomd_warm_types) / sizeof(char *); i++) {
        if (strlen(rpm_repomd_warm_types[i]) == n
            && memcmp(p, rpm_repomd_warm_types[i], n) == 0)
        {
            return 1;
        }
    }
    return 0;
}


/* One <data> element: its span ends at the closing tag, or — for a document
 * that never closes it — at the next element or the end of the buffer, so a
 * truncated repomd cannot make the reader run past what it has. */
static size_t
rpm_data_span(const char *p, size_t n)
{
    const char *close = rpm_mem_find(p, n, "</data>");
    const char *next  = rpm_mem_find(p + 1, n - 1, "<data");

    if (close != NULL && (next == NULL || close < next)) {
        return (size_t) (close - p);
    }
    return (next != NULL) ? (size_t) (next - p) : n;
}


/* The location href inside one <data> element, or -1. The href is read from
 * the <location> tag alone rather than from the element as a whole: a
 * <checksum> carries no href, but a future sibling element might, and the
 * warm set must name the file this data block publishes and nothing else. */
static int
rpm_data_href(const char *p, size_t n, const char **href, size_t *href_len)
{
    const char *loc = rpm_mem_find(p, n, "<location");

    if (loc == NULL) {
        return -1;
    }
    return rpm_attr(loc, n - (size_t) (loc - p), "href", href, href_len);
}


size_t
brix_rpm_repomd_warm_set(const char *xml, size_t len,
    brix_rpm_repomd_ref_t *out, size_t max)
{
    const char *p = xml;
    size_t      left = len, found = 0;

    if (xml == NULL || out == NULL || max == 0 || len == 0) {
        return 0;
    }

    while (found < max) {
        const char *data, *type, *href;
        size_t      span, type_len, href_len;

        data = rpm_mem_find(p, left, "<data");
        if (data == NULL) {
            break;
        }
        left -= (size_t) (data - p);
        p     = data;
        span  = rpm_data_span(p, left);

        if (rpm_attr(p, span, "type", &type, &type_len) == 0
            && rpm_type_is_warm(type, type_len)
            && rpm_data_href(p, span, &href, &href_len) == 0
            && rpm_href_ok(href, href_len))
        {
            out[found].href     = href;
            out[found].href_len = href_len;
            found++;
        }

        p    += span;
        left -= span;
        if (left == 0) {
            break;
        }
    }
    return found;
}


int
brix_rpm_repomd_sibling_key(const char *repomd_key, size_t key_len,
    const char *href, size_t href_len, char *out, size_t out_size)
{
    static const char  marker[] = "/repodata/";
    const char        *at;
    size_t             base;

    if (repomd_key == NULL || href == NULL || out == NULL || out_size == 0) {
        return -1;
    }
    /* The href is relative to the repository ROOT, which is the parent of the
     * repodata/ directory the index lives in — so the base is everything up
     * to and including the slash before "repodata". A key with more than one
     * "/repodata/" in it is anchored on the LAST, the one that holds this
     * index. */
    at = NULL;
    for (base = 0; base + sizeof(marker) - 1 <= key_len; base++) {
        if (memcmp(repomd_key + base, marker, sizeof(marker) - 1) == 0) {
            at = repomd_key + base;
        }
    }
    if (at == NULL) {
        return -1;
    }
    base = (size_t) (at - repomd_key) + 1;    /* keep the leading slash */

    if (base + href_len + 1 > out_size) {
        return -1;
    }
    memcpy(out, repomd_key, base);
    memcpy(out + base, href, href_len);
    out[base + href_len] = '\0';
    return 0;
}
