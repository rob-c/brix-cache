/*
 * metalink.c — pure metalink v4 (RFC 5854) / v3 document parser (phase-100).
 *
 * WHAT: brix_metalink_is_name() suffix detection and brix_metalink_parse(),
 *       which turns one metalink XML document into a ranked mirror list plus
 *       the optional size and strongest client-supported digest.
 * WHY:  Metalink is the client's virtual-redirector input: copy_metalink.c
 *       fails over across the ranked mirrors and hands them to the extreme-copy
 *       engine. Keeping the parser pure (bytes in, struct out, no I/O and no
 *       allocation) makes hostile-input behavior unit-testable in isolation
 *       (client/tests/c/metalink_unit.c).
 * HOW:  A single bounded forward scan with a tiny case-insensitive tag finder —
 *       no libxml dependency, no recursion. Only the FIRST <file> element is
 *       resolved (a copy resolves one logical file, matching XrdCl's virtual
 *       redirector). Sibling copy_metalink.c owns fetching + failover.
 */
#include "copy_internal.h"
#include "metalink.h"

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
static const char *
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
static const char *
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
            const char *semi = memchr(src + si, ';', (len - si) < 12 ? (len - si) : 12);
            if (semi != NULL) {
                size_t elen = (size_t) (semi - (src + si)) + 1;
                if (elen == 5 && strncasecmp(src + si, "&amp;", 5) == 0) {
                    decoded = '&';  adv = 5;
                } else if (elen == 4 && strncasecmp(src + si, "&lt;", 4) == 0) {
                    decoded = '<';  adv = 4;
                } else if (elen == 4 && strncasecmp(src + si, "&gt;", 4) == 0) {
                    decoded = '>';  adv = 4;
                } else if (elen == 6 && strncasecmp(src + si, "&quot;", 6) == 0) {
                    decoded = '"';  adv = 6;
                } else if (elen == 6 && strncasecmp(src + si, "&apos;", 6) == 0) {
                    decoded = '\''; adv = 6;
                } else if (elen > 3 && src[si + 1] == '#') {
                    int  base = (src[si + 2] == 'x' || src[si + 2] == 'X') ? 16 : 10;
                    long cp = strtol(src + si + (base == 16 ? 3 : 2), NULL, base);
                    if (cp > 0 && cp < 128) {   /* ASCII only; else verbatim */
                        decoded = (char) cp;
                        adv = elen;
                    }
                }
            }
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
static int
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
static int
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


/* ---- Is this mirror URL a scheme the copy engine may pull from? ----
 *
 * WHAT: 1 for the remote pull schemes (root/roots/xroot/xroots + http/https/
 *       dav/davs, case-insensitive), 0 for everything else.
 *
 * WHY: SECURITY — a hostile remote metalink must not steer the copy at a local
 *      file (file:///etc/… exfiltrates via an upload destination) or at a
 *      credentialed transport the user never selected (s3 SigV4). Skipped
 *      mirrors are counted, never fatal, so a mixed document still works.
 *
 * HOW: Prefix table over the accepted scheme spellings.
 */
static int
ml_scheme_allowed(const char *mirror_url)
{
    static const char *const allowed[] = {
        "root://", "roots://", "xroot://", "xroots://",
        "http://", "https://", "dav://", "davs://",
    };
    size_t i;

    for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        if (strncasecmp(mirror_url, allowed[i], strlen(allowed[i])) == 0) {
            return 1;
        }
    }
    return 0;
}


/* ---- Insert one mirror into the ranked list (stable, bounded) ----
 *
 * WHAT: Insertion-sort `url` (rank ascending, ties keep arrival order) into
 *       ml->urls. When full, a better-than-worst rank evicts the worst entry
 *       (counted in n_skipped); otherwise the newcomer is skipped.
 *
 * WHY: Consumers walk urls[] best-first; sorting on insert keeps the parser
 *      single-pass and the eviction rule keeps a 1000-mirror hostile document
 *      bounded without dropping a best-ranked mirror listed last.
 *
 * HOW: 1. Full + not-better → skip. 2. Full + better → drop the tail. 3. Shift
 *         strictly-worse entries up one and place the newcomer.
 */
static void
ml_insert_url(brix_metalink *ml, const char *url, int rank)
{
    size_t pos, k;

    if (ml->n_urls == XRDC_METALINK_MAX_URLS) {
        if (rank >= ml->urls[ml->n_urls - 1].rank) {
            ml->n_skipped++;
            return;
        }
        ml->n_urls--;          /* evict the current worst */
        ml->n_skipped++;
    }
    for (pos = 0; pos < ml->n_urls; pos++) {
        if (ml->urls[pos].rank > rank) {
            break;
        }
    }
    for (k = ml->n_urls; k > pos; k--) {
        ml->urls[k] = ml->urls[k - 1];
    }
    snprintf(ml->urls[pos].rank_url, sizeof(ml->urls[pos].rank_url), "%s", url);
    ml->urls[pos].rank = rank;
    ml->n_urls++;
}


/* ---- Fold one <hash type="...">hex</hash> into the strongest supported ----
 *
 * WHAT: If `algo`/`hex` name a digest the --cksum machinery can verify
 *       (md5 > crc32c > adler32) and beat the currently-held one, record them
 *       (hex validated and lowercased). Unsupported/malformed digests are
 *       ignored.
 *
 * WHY: The metalink digest rides into the transfer as "--cksum algo:hex"
 *      (literal compare); a non-hex "digest" from a hostile document must not
 *      reach that path.
 *
 * HOW: 1. Strength table lookup (0 = unsupported). 2. Validate 8..128 hex
 *         chars. 3. Keep only a strict upgrade.
 */
static void
ml_fold_hash(brix_metalink *ml, const char *algo, const char *hex)
{
    static const struct { const char *name; int strength; } table[] = {
        { "md5", 3 }, { "crc32c", 2 }, { "adler32", 1 },
    };
    int strength = 0, held = 0;
    size_t i, hlen = strlen(hex);

    for (i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcasecmp(algo, table[i].name) == 0) {
            strength = table[i].strength;
        }
        if (strcasecmp(ml->hash_algo, table[i].name) == 0) {
            held = table[i].strength;
        }
    }
    if (strength == 0 || strength <= held) {
        return;
    }
    if (hlen < 8 || hlen >= XRDC_METALINK_HEX_MAX) {
        return;
    }
    for (i = 0; i < hlen; i++) {
        if (!isxdigit((unsigned char) hex[i])) {
            return;
        }
    }
    snprintf(ml->hash_algo, sizeof(ml->hash_algo), "%s", algo);
    for (i = 0; i < hlen; i++) {
        ml->hash_hex[i] = (char) tolower((unsigned char) hex[i]);
    }
    ml->hash_hex[hlen] = '\0';
}


/* ---- Rank one <url> element from its attributes ----
 *
 * WHAT: Map v4 priority (ascending, 1 = best) and v3 preference (descending,
 *       100 = best) onto one ascending rank; absent both → 500 (after every
 *       explicitly-ranked mirror, before nothing).
 *
 * WHY: One comparable rank lets v3 and v4 documents share the sorted list.
 *
 * HOW: priority wins when both appear; values are clamped to [1,100] before
 *      mapping (v3: rank = 101 - preference).
 */
static int
ml_rank_of(const char *attrs, const char *gt)
{
    char val[16];

    if (ml_attr(attrs, gt, "priority", val, sizeof(val)) == 0) {
        int prio = atoi(val);
        if (prio < 1)   { prio = 1; }
        if (prio > 100) { prio = 100; }
        return prio;
    }
    if (ml_attr(attrs, gt, "preference", val, sizeof(val)) == 0) {
        int pref = atoi(val);
        if (pref < 1)   { pref = 1; }
        if (pref > 100) { pref = 100; }
        return 101 - pref;
    }
    return 500;
}


/* ---- Collect every <url>, <size> and <hash> inside the <file> scope ----
 *
 * WHAT: Walk [p,fend) once, folding each element kind into *ml.
 *
 * WHY: Keeps brix_metalink_parse a flat sequence: locate scope, collect,
 *      validate. All three element kinds share the open-tag/text machinery.
 *
 * HOW: 1. Find the next '<'-led candidate for each kind from the cursor;
 *         advance by the earliest hit so the scan stays single-pass. 2. <url>:
 *         rank + scheme-gate + insert. 3. <size>: first valid wins. 4. <hash>:
 *         strongest supported wins (v3's <verification> wrapper needs no
 *         special casing — its <hash> children match the same scan).
 */
static void
ml_collect_file_scope(brix_metalink *ml, const char *p, const char *fend)
{
    for (;;) {
        const char *attrs = NULL, *gt = NULL;
        const char *hit = ml_tag_open(p, fend, "url", &attrs, &gt);
        const char *shit = ml_tag_open(p, fend, "size", NULL, NULL);
        const char *hhit = ml_tag_open(p, fend, "hash", NULL, NULL);
        char text[XRDC_METALINK_URL_MAX];

        /* earliest of the three candidates drives this iteration */
        if (hit == NULL || (shit != NULL && shit < hit)
            || (hhit != NULL && hhit < hit)) {
            if (shit != NULL && (hit == NULL || shit < hit)
                && (hhit == NULL || shit < hhit)) {
                const char *sgt;
                if (ml_tag_open(shit, fend, "size", NULL, &sgt) != NULL
                    && ml_elem_text(sgt, fend, "size", text, sizeof(text)) == 0
                    && ml->size < 0) {
                    long long parsed = atoll(text);
                    if (parsed >= 0) {
                        ml->size = (int64_t) parsed;
                    }
                }
                p = shit + 1;
                continue;
            }
            if (hhit != NULL) {
                const char *hattrs, *hgt;
                char algo[XRDC_METALINK_ALGO_MAX];
                char hex[XRDC_METALINK_HEX_MAX];
                if (ml_tag_open(hhit, fend, "hash", &hattrs, &hgt) != NULL
                    && ml_attr(hattrs, hgt, "type", algo, sizeof(algo)) == 0
                    && ml_elem_text(hgt, fend, "hash", hex, sizeof(hex)) == 0) {
                    ml_fold_hash(ml, algo, hex);
                }
                p = hhit + 1;
                continue;
            }
            return;   /* no candidates left in scope */
        }

        /* <url ...>text</url> */
        if (ml_elem_text(gt, fend, "url", text, sizeof(text)) != 0
            || text[0] == '\0') {
            ml->n_skipped++;         /* unterminated/oversized/empty URL */
        } else if (!ml_scheme_allowed(text)) {
            ml->n_skipped++;         /* local/credentialed/unknown scheme */
        } else {
            ml_insert_url(ml, text, ml_rank_of(attrs, gt));
        }
        p = gt + 1;
    }
}


int
brix_metalink_is_name(const char *s)
{
    const char *q, *path_end, *dot;
    size_t plen;

    if (s == NULL) {
        return 0;
    }
    q = strchr(s, '?');
    path_end = (q != NULL) ? q : s + strlen(s);
    for (dot = path_end; dot > s && dot[-1] != '.' && dot[-1] != '/'; dot--) { }
    if (dot == s || dot[-1] != '.') {
        return 0;
    }
    plen = (size_t) (path_end - dot);
    return (plen == 5 && strncasecmp(dot, "meta4", 5) == 0)
        || (plen == 8 && strncasecmp(dot, "metalink", 8) == 0);
}


/*
 * WHAT: Parse one metalink v4/v3 document into *out — ranked mirrors, optional
 *       size, strongest supported digest. 0 with >=1 usable mirror, else -1
 *       (st set, XRDC_EPROTO class).
 *
 * WHY: Single entry point for both dialects keeps copy_metalink.c free of any
 *      XML knowledge and the hostile-input surface behind one tested door.
 *
 * HOW: 1. Bound the document (empty / >4 MiB refused). 2. Require a <metalink
 *         root tag. 3. Scope to the FIRST <file> element (self-closing or
 *         missing → error; an unterminated scope clamps to end-of-document,
 *         lenient). 4. Collect url/size/hash. 5. Zero usable mirrors → error
 *         naming how many candidates were skipped.
 */
int
brix_metalink_parse(const char *xml, size_t len, brix_metalink *out,
                    brix_status *st)
{
    const char *end, *fgt = NULL, *fscope, *fend;

    memset(out, 0, sizeof(*out));
    out->size = -1;

    if (xml == NULL || len == 0 || len > XRDC_METALINK_MAX_BYTES) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "metalink: empty or oversized document (%zu bytes, cap %u)",
                        len, XRDC_METALINK_MAX_BYTES);
        return -1;
    }
    end = xml + len;

    if (ml_tag_open(xml, end, "metalink", NULL, NULL) == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "not a metalink document");
        return -1;
    }
    if (ml_tag_open(xml, end, "file", NULL, &fgt) == NULL || fgt == NULL
        || fgt[-1] == '/') {
        brix_status_set(st, XRDC_EPROTO, 0, "metalink: no <file> entry");
        return -1;
    }
    fscope = fgt + 1;
    fend = ml_find_ci(fscope, end, "</file");
    if (fend == NULL) {
        fend = end;   /* unterminated scope: clamp, stay lenient */
    }

    ml_collect_file_scope(out, fscope, fend);

    if (out->n_urls == 0) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "metalink: no usable mirror URLs "
                        "(%zu candidate(s) skipped: bad scheme/length)",
                        out->n_skipped);
        return -1;
    }
    return 0;
}
