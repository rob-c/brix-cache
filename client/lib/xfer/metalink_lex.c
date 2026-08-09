/*
 * metalink_lex.c — bounded XML lexing for the metalink parser (phase-100).
 *
 * WHAT: The tag / attribute / element-text extractors and the XML character
 *       entity decoder that metalink.c builds its document semantics on.
 * WHY:  Split from metalink.c on the 600-line file gate (see
 *       metalink_internal.h): the lexer knows nothing about mirrors, ranks or
 *       digests, so it is one concept with its own hostile-input rules — the
 *       11-byte entity cap, the ASCII-only numeric range, and the name-boundary
 *       check that stops "<url" matching "<urlfoo".
 * HOW:  Every routine is bounded by an explicit end/gt pointer, allocates
 *       nothing, and recurses nowhere. Unknown or malformed entities are copied
 *       verbatim (lenient, like browsers) so a stray '&' never kills a mirror.
 */
#include "copy_internal.h"
#include "metalink.h"
#include "metalink_internal.h"

#include <ctype.h>


/* ---- Case-insensitive bounded substring search ----
 *
 * WHAT: Return the first occurrence of NUL-terminated `needle` in [p,end),
 *       comparing ASCII case-insensitively, or NULL when absent.
 *
 * WHY: XML tag/attribute names are matched case-insensitively so hand-written
 *      v3 documents ("<Metalink>", "MD5") parse the same as canonical ones.
 *
 * HOW: 1. Walk each start position with enough room for the needle.
 *      2. Compare byte-wise through tolower().
 */
const char *
ml_find_ci(const char *p, const char *end, const char *needle)
{
    size_t nlen = strlen(needle);

    if (nlen == 0 || p == NULL || end - p < (ptrdiff_t) nlen) {
        return NULL;
    }
    for (; p + nlen <= end; p++) {
        size_t i;
        for (i = 0; i < nlen; i++) {
            if (tolower((unsigned char) p[i])
                != tolower((unsigned char) needle[i])) {
                break;
            }
        }
        if (i == nlen) {
            return p;
        }
    }
    return NULL;
}


/* ---- Locate the next opening tag `<name` with a real name boundary ----
 *
 * WHAT: Find the next `<name` in [p,end) whose following byte terminates the
 *       tag name (whitespace, '>', or '/'), so "<url" never matches "<urlfoo".
 *       Returns the position of '<', or NULL. attrs_out / gt_out (may be NULL)
 *       get the attribute region start (after the name) and the closing '>'.
 *
 * WHY: The attribute extractor and text extractor both need the exact
 *      attribute window and element-body start; computing them here keeps every
 *      caller a one-liner and the bounds checked in one place.
 *
 * HOW: 1. Compose "<name" (bounded) and ml_find_ci it, retrying on false
 *         name-prefix hits. 2. Scan to the tag's '>' (bounded by `end`).
 */
const char *
ml_tag_open(const char *p, const char *end, const char *name,
            const char **attrs_out, const char **gt_out)
{
    char tag[32];
    size_t nlen = strlen(name);

    if (nlen + 2 > sizeof(tag)) {
        return NULL;
    }
    tag[0] = '<';
    memcpy(tag + 1, name, nlen + 1);

    for (;;) {
        const char *hit = ml_find_ci(p, end, tag);
        const char *after, *gt;

        if (hit == NULL) {
            return NULL;
        }
        after = hit + 1 + nlen;
        if (after >= end
            || !(isspace((unsigned char) *after) || *after == '>'
                 || *after == '/')) {
            p = hit + 1;   /* name-prefix false positive, e.g. <urls> */
            continue;
        }
        for (gt = after; gt < end && *gt != '>'; gt++) { }
        if (gt >= end) {
            return NULL;   /* unterminated tag */
        }
        if (attrs_out != NULL) {
            *attrs_out = after;
        }
        if (gt_out != NULL) {
            *gt_out = gt;
        }
        return hit;
    }
}


/*
 * WHAT: One named XML entity — its literal spelling (including '&' and ';')
 *       and the byte it decodes to.
 * WHY:  The five predefined entities differ only in spelling and result, so
 *       they belong in a table rather than a strncasecmp ladder
 *       (coding-standards §8.6).
 * HOW:  `len` is precomputed so the match is a length test before the compare.
 */
typedef struct {
    const char *name;
    size_t      len;
    char        ch;
} ml_entity_t;

static const ml_entity_t  ml_named_entities[] = {
    { "&amp;",  5, '&'  },
    { "&lt;",   4, '<'  },
    { "&gt;",   4, '>'  },
    { "&quot;", 6, '"'  },
    { "&apos;", 6, '\'' },
};


/* ---- Match one of the five predefined entities ----
 *
 * WHAT: Returns the number of bytes consumed and stores the decoded byte, or 0
 *       when `s` (an '&'…';' run of `elen` bytes) is not a named entity.
 *
 * WHY:  Length-first matching means a truncated or over-long run can never be
 *       mistaken for a shorter entity that happens to share a prefix.
 *
 * HOW:  1. Walk the table, requiring an exact length match.
 *       2. Compare case-insensitively — real-world metalinks emit &AMP;.
 */
static size_t
ml_entity_named(const char *s, size_t elen, char *out)
{
    size_t  n;

    for (n = 0; n < sizeof(ml_named_entities) / sizeof(ml_named_entities[0]); n++) {
        if (elen == ml_named_entities[n].len
            && strncasecmp(s, ml_named_entities[n].name, elen) == 0)
        {
            *out = ml_named_entities[n].ch;
            return elen;
        }
    }

    return 0;
}


/* ---- Match a numeric &#NN; / &#xNN; entity ----
 *
 * WHAT: Returns the number of bytes consumed and stores the decoded byte, or 0
 *       when the run is not a numeric entity in the representable range.
 *
 * WHY:  Only ASCII is decoded: this buffer is a byte string handed to the
 *       transport, so emitting a multi-byte codepoint here would produce a URL
 *       the server never issued.  Anything else is left verbatim rather than
 *       being lossily folded.
 *
 * HOW:  1. Require "&#" and at least one digit before the ';'.
 *       2. Pick base 16 for an x/X prefix, else base 10.
 *       3. Accept only 0 < cp < 128.
 */
static size_t
ml_entity_numeric(const char *s, size_t elen, char *out)
{
    int   base;
    long  cp;

    if (elen <= 3 || s[1] != '#') {
        return 0;
    }

    base = (s[2] == 'x' || s[2] == 'X') ? 16 : 10;
    cp = strtol(s + (base == 16 ? 3 : 2), NULL, base);
    if (cp <= 0 || cp >= 128) {   /* ASCII only; else verbatim */
        return 0;
    }

    *out = (char) cp;
    return elen;
}


/* ---- Decode the entity starting at `s`, if there is one ----
 *
 * WHAT: Returns the bytes consumed and stores the decoded byte, or 0 when the
 *       run is not a recognised entity.
 *
 * WHY:  An entity is at most 11 bytes to the ';'; capping the search means a
 *       stray '&' in a long URL costs a bounded scan instead of walking to the
 *       end of the value.
 *
 * HOW:  1. Find the ';' within the cap; no ';' means no entity.
 *       2. Try the named table, then the numeric forms.
 */
static size_t
ml_entity_at(const char *s, size_t avail, char *out)
{
    const char  *semi = memchr(s, ';', avail < 12 ? avail : 12);
    size_t       elen, adv;

    if (semi == NULL) {
        return 0;
    }

    elen = (size_t) (semi - s) + 1;

    adv = ml_entity_named(s, elen, out);
    if (adv != 0) {
        return adv;
    }

    return ml_entity_numeric(s, elen, out);
}


/* ---- Decode XML character entities into a bounded buffer ----
 *
 * WHAT: Copy [src,src+len) into out[outsz], decoding &amp; &lt; &gt; &quot;
 *       &apos; and numeric &#NN;/&#xNN; forms. Returns 0, or -1 when the
 *       decoded text would not fit (out is always NUL-terminated).
 *
 * WHY: Metalink URLs legally carry '&' query separators as &amp;; skipping
 *      decoding would hand the transport a URL the server never issued.
 *
 * HOW: 1. Byte copy, branching on '&'. 2. An entity is at most 11 bytes to the
 *         ';'; unknown/malformed entities are copied verbatim (lenient, like
 *         browsers) so a stray '&' does not kill the mirror.
 */
static int
ml_entity_decode(const char *src, size_t len, char *out, size_t outsz)
{
    size_t si = 0, oi = 0;

    while (si < len) {
        char decoded = 0;
        size_t adv = 0;

        if (src[si] == '&') {
            adv = ml_entity_at(src + si, len - si, &decoded);
        }
        if (adv == 0) {           /* plain byte or unrecognized entity */
            decoded = src[si];
            adv = 1;
        }
        if (oi + 1 >= outsz) {
            out[oi] = '\0';
            return -1;
        }
        out[oi++] = decoded;
        si += adv;
    }
    out[oi] = '\0';
    return 0;
}


/* ---- Extract one attribute value from a tag's attribute window ----
 *
 * WHAT: Find `name="value"` (or '...') inside [attrs,gt) and entity-decode the
 *       value into out[outsz]. Returns 0 when found and fits, -1 otherwise.
 *
 * WHY: priority/preference/type live in attributes; a bounded scanner beats a
 *      full XML attribute grammar for these three fixed names.
 *
 * HOW: 1. ml_find_ci the name with a boundary check (preceded by whitespace).
 *         2. Skip spaces, require '=', skip spaces, require a quote. 3. The
 *         value runs to the matching quote (bounded by gt).
 */
int
ml_attr(const char *attrs, const char *gt, const char *name,
        char *out, size_t outsz)
{
    const char *p = attrs;
    size_t nlen = strlen(name);

    while ((p = ml_find_ci(p, gt, name)) != NULL) {
        const char *v = p + nlen;
        char quote;
        const char *vend;

        if (p > attrs && !isspace((unsigned char) p[-1])) {
            p += 1;   /* substring of a longer attribute name */
            continue;
        }
        while (v < gt && isspace((unsigned char) *v)) { v++; }
        if (v >= gt || *v != '=') {
            p += 1;
            continue;
        }
        v++;
        while (v < gt && isspace((unsigned char) *v)) { v++; }
        if (v >= gt || (*v != '"' && *v != '\'')) {
            p += 1;
            continue;
        }
        quote = *v++;
        vend = memchr(v, quote, (size_t) (gt - v));
        if (vend == NULL) {
            return -1;
        }
        return ml_entity_decode(v, (size_t) (vend - v), out, outsz);
    }
    return -1;
}


/* ---- Extract an element's text body ----
 *
 * WHAT: Given the '>' of an opening <name ...> tag, find `</name` and
 *       entity-decode the text between (whitespace-trimmed) into out[outsz].
 *       Returns 0, or -1 (missing close tag / does not fit).
 *
 * WHY: <url>, <size> and <hash> all carry their payload as element text.
 *
 * HOW: 1. Compose "</name" and ml_find_ci from just after '>'. 2. Trim ASCII
 *         whitespace off both ends. 3. Entity-decode the middle.
 */
int
ml_elem_text(const char *gt, const char *end, const char *name,
             char *out, size_t outsz)
{
    char close_tag[32];
    const char *text = gt + 1, *close, *tend;
    size_t nlen = strlen(name);

    if (nlen + 3 > sizeof(close_tag)) {
        return -1;
    }
    close_tag[0] = '<';
    close_tag[1] = '/';
    memcpy(close_tag + 2, name, nlen + 1);

    close = ml_find_ci(text, end, close_tag);
    if (close == NULL) {
        return -1;
    }
    tend = close;
    while (text < tend && isspace((unsigned char) *text)) { text++; }
    while (tend > text && isspace((unsigned char) tend[-1])) { tend--; }
    return ml_entity_decode(text, (size_t) (tend - text), out, outsz);
}
