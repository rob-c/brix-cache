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
 * HOW:  A single bounded forward scan over the lexing primitives in
 *       metalink_lex.c (see metalink_internal.h) — no libxml dependency, no
 *       recursion. Only the FIRST <file> element is resolved (a copy resolves
 *       one logical file, matching XrdCl's virtual redirector). Sibling
 *       copy_metalink.c owns fetching + failover.
 */
#include "copy_internal.h"
#include "metalink.h"
#include "metalink_internal.h"

#include <ctype.h>


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


/* ---- Earlier of two scan candidates ----
 *
 * WHAT: Returns whichever of `a`/`b` points earlier into the scope, or the
 *       non-NULL one, or NULL when neither matched.
 *
 * WHY:  The scan must stay single-pass, so each iteration has to consume the
 *       earliest element regardless of kind.  Folding the NULL cases in here
 *       is what lets the caller pick a winner with one expression instead of
 *       the nested "is it before the others" ladder this replaces.
 *
 * HOW:  NULL means "this kind does not occur again", so it always loses.
 */
static const char *
ml_earliest(const char *a, const char *b)
{
    if (a == NULL) {
        return b;
    }
    if (b == NULL) {
        return a;
    }

    return (a < b) ? a : b;
}


/* ---- Fold one <size> element into the parse ----
 *
 * WHAT: Sets ml->size from the element at `hit` when it is the first valid one
 *       seen; malformed or repeated elements are ignored.
 *
 * WHY:  First valid wins: a metalink that declares the size twice is
 *       inconsistent, and honouring the later value would let a trailing
 *       element silently resize a transfer already sized from the first.
 *
 * HOW:  1. Re-open the tag to get its '>' and read the element text.
 *       2. Ignore it if a size is already set or the text is negative.
 */
static void
ml_take_size(brix_metalink *ml, const char *hit, const char *fend)
{
    const char  *sgt;
    char         text[XRDC_METALINK_URL_MAX];
    long long    parsed;

    if (ml_tag_open(hit, fend, "size", NULL, &sgt) == NULL
        || ml_elem_text(sgt, fend, "size", text, sizeof(text)) != 0
        || ml->size >= 0)
    {
        return;
    }

    parsed = atoll(text);
    if (parsed >= 0) {
        ml->size = (int64_t) parsed;
    }
}


/* ---- Fold one <hash> element into the parse ----
 *
 * WHAT: Offers the element's type + hex digest to ml_fold_hash, which keeps
 *       the strongest supported algorithm.
 *
 * WHY:  v3's <verification> wrapper needs no special casing — its <hash>
 *       children match the same scan, so the wrapper is simply scanned through.
 *
 * HOW:  1. Re-open the tag for its attribute window and '>'.
 *       2. Require both a type attribute and element text; a hash missing
 *          either is unusable, not a weaker hash.
 */
static void
ml_take_hash(brix_metalink *ml, const char *hit, const char *fend)
{
    const char  *hattrs, *hgt;
    char         algo[XRDC_METALINK_ALGO_MAX];
    char         hex[XRDC_METALINK_HEX_MAX];

    if (ml_tag_open(hit, fend, "hash", &hattrs, &hgt) != NULL
        && ml_attr(hattrs, hgt, "type", algo, sizeof(algo)) == 0
        && ml_elem_text(hgt, fend, "hash", hex, sizeof(hex)) == 0)
    {
        ml_fold_hash(ml, algo, hex);
    }
}


/* ---- Fold one <url ...>text</url> element into the parse ----
 *
 * WHAT: Inserts the mirror at its computed rank, or counts it as skipped.
 *
 * WHY:  A rejected mirror is counted rather than dropped silently, so a
 *       metalink whose mirrors are all unusable is distinguishable from one
 *       that listed none.  The scheme gate is a security boundary: local and
 *       credentialed URLs must never reach the transport (§ml_scheme_allowed).
 *
 * HOW:  1. Read the element text; unterminated/oversized/empty is a skip.
 *       2. Reject a disallowed scheme.
 *       3. Otherwise insert at the priority/preference-derived rank.
 */
static void
ml_take_url(brix_metalink *ml, const char *attrs, const char *gt,
            const char *fend)
{
    char  text[XRDC_METALINK_URL_MAX];

    if (ml_elem_text(gt, fend, "url", text, sizeof(text)) != 0
        || text[0] == '\0') {
        ml->n_skipped++;         /* unterminated/oversized/empty URL */
    } else if (!ml_scheme_allowed(text)) {
        ml->n_skipped++;         /* local/credentialed/unknown scheme */
    } else {
        ml_insert_url(ml, text, ml_rank_of(attrs, gt));
    }
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
        const char *uhit = ml_tag_open(p, fend, "url", &attrs, &gt);
        const char *shit = ml_tag_open(p, fend, "size", NULL, NULL);
        const char *hhit = ml_tag_open(p, fend, "hash", NULL, NULL);

        /* earliest of the three candidates drives this iteration */
        const char *first = ml_earliest(ml_earliest(uhit, shit), hhit);

        if (first == NULL) {
            return;   /* no candidates left in scope */
        }

        if (first == shit) {
            ml_take_size(ml, shit, fend);
            p = shit + 1;

        } else if (first == hhit) {
            ml_take_hash(ml, hhit, fend);
            p = hhit + 1;

        } else {
            ml_take_url(ml, attrs, gt, fend);
            p = gt + 1;
        }
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
