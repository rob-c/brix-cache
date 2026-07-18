#include "opaque_validate.h"

#include <stddef.h>

/*
 * opaque_validate.c — byte-hygiene gate for the XRootD CGI opaque string
 * (hyper-hardening-plan §D-2, CWE-88/CWE-93/CWE-117 injection at the parse edge).
 *
 * WHAT: brix_opaque_illegal_byte() scans a NUL-terminated opaque query string
 *       (everything after '?' in a wire path: oss.* / tpc.* / auth.* / xrd.* /
 *       xrdcl.* key=value pairs) and reports the first byte outside the set a
 *       well-formed opaque needs. The caller rejects the request (kXR_ArgInvalid)
 *       before any handler parses, logs, or forwards the string.
 *
 * WHY:  The opaque is consumed by several handlers (TPC source/dest URLs,
 *       delegated-token modes, compression negotiation, ZIP member selection)
 *       and is logged and, for TPC, spliced into an OUTBOUND request. A raw
 *       control byte is a log/CRLF-injection and request-smuggling primitive; a
 *       shell/quoting metacharacter is a command-injection primitive if any value
 *       ever reaches a shell; a high-bit byte is non-conforming and a mojibake /
 *       filter-evasion vector. None of these appear in a legitimate opaque — real
 *       clients percent-encode anything outside the unreserved/structural set — so
 *       rejecting them at the single parse edge is a zero-false-positive gate that
 *       stops the whole class before it fans out to the handlers.
 *
 * HOW:  A 256-entry permit table, built once from an explicit allow string, is
 *       consulted per byte. Permitted = URL-unreserved (alnum . - _ ~),
 *       path/authority (/ : @), percent-encoding (% +), and CGI structure
 *       (= & ; , ?). ';' is the legacy CGI pair separator (equivalent to '&');
 *       stock XRootD accepts "k=v;other=z", so rejecting it would break parity
 *       and is not an injection concern here — the opaque is parsed, never handed
 *       to a shell. Everything else — 0x00-0x1F, 0x7F, 0x80-0xFF, and the printable
 *       metacharacters space ! " # $ ' ( ) * < > [ \ ] ^ ` { | } — is rejected.
 *       Pure C, no nginx/libc string deps: safe to call from the wire edge.
 */

/* The bytes a legitimate XRootD CGI opaque is built from. Anything else is an
 * injection primitive that a conforming client would percent-encode. Note '?'
 * is permitted because a tpc.src value may carry a nested URL query. */
static const char BRIX_OPAQUE_ALLOWED[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    ".-_~"      /* URL unreserved */
    "/:@"       /* path / authority */
    "%+"        /* percent-encoding, plus-as-space */
    "=&;,?";    /* CGI structure + list separators (& and legacy ;) + nested-query */

static unsigned char brix_opaque_permit[256];
static int           brix_opaque_permit_ready;

static void
brix_opaque_permit_init(void)
{
    const char *p;

    for (p = BRIX_OPAQUE_ALLOWED; *p != '\0'; p++) {
        brix_opaque_permit[(unsigned char) *p] = 1;
    }
    brix_opaque_permit_ready = 1;
}

/*
 * Scan opaque[] for the first byte outside the permitted set. Returns 1 and
 * writes the offending byte to *bad (if non-NULL) on rejection; returns 0 when
 * every byte is permitted (including the empty string).
 *
 * The permit table has no mutable state after the one-time fill, so the lazy
 * init is race-benign under nginx's per-worker single-threaded event loop: a
 * concurrent init would recompute the identical table. (TPC pull threads never
 * reach here — validation runs on the main-loop open edge before dispatch.)
 */
int
brix_opaque_illegal_byte(const char *opaque, unsigned char *bad)
{
    const unsigned char *s;

    if (opaque == NULL) {
        return 0;
    }
    if (!brix_opaque_permit_ready) {
        brix_opaque_permit_init();
    }

    for (s = (const unsigned char *) opaque; *s != '\0'; s++) {
        if (!brix_opaque_permit[*s]) {
            if (bad != NULL) {
                *bad = *s;
            }
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- *
 * Tier 2 — opt-in schema validation (brix_opaque_strict).
 *
 * XRootD opaque keys are namespaced "<ns>.<name>" (plus a couple of bare keys
 * a stock client sends). Strict mode recognizes the known namespaces and bare
 * keys and rejects anything else, and type-enforces the keys brix assigns a
 * type to. It is OFF by default; stock accepts these unchecked, so this only
 * bites a deployment that deliberately opts into the stricter posture.
 *
 * SCOPE (documented, not a bug): the walk splits on top-level '&'. A value that
 * embeds a nested URL query (a tpc.src / tpc.dst carrying "root://h//p?a=b&c=d")
 * would have its nested '&c=d' seen as a sibling pair. Conforming clients
 * percent-encode a nested query, and TPC endpoints pass source/dest CGI in the
 * dedicated tpc.scgi / tpc.dcgi keys, so this does not arise in practice — but
 * it is why strict mode is opt-in rather than always-on.
 * ------------------------------------------------------------------------- */

/* Namespace prefixes a key may legitimately carry (each includes its dot so a
 * bare "xrd" cannot masquerade as the "xrd." namespace). "xrdcl." is listed
 * separately because it does not share the "xrd." prefix (no dot after "xrd"). */
static const char *const BRIX_OPAQUE_NAMESPACES[] = {
    "oss.", "tpc.", "xrd.", "xrdcl.", "cms.", "scitag.", NULL
};

/* Whole keys a stock client sends without a namespace. */
static const char *const BRIX_OPAQUE_BARE_KEYS[] = {
    "authz", NULL
};

/* Length of key (up to '=' or the segment end), and offset of the value. */
static size_t
brix_opaque_key_len(const char *seg, size_t seg_len)
{
    size_t i;

    for (i = 0; i < seg_len; i++) {
        if (seg[i] == '=') {
            return i;
        }
    }
    return seg_len;
}

/* Does key[0..key_len) exactly equal the NUL-terminated cand? */
static int
brix_opaque_key_eq(const char *key, size_t key_len, const char *cand)
{
    size_t i;

    for (i = 0; i < key_len; i++) {
        if (cand[i] == '\0' || key[i] != cand[i]) {
            return 0;
        }
    }
    return cand[key_len] == '\0';
}

/* Does key[0..key_len) begin with the NUL-terminated prefix? */
static int
brix_opaque_key_has_prefix(const char *key, size_t key_len, const char *prefix)
{
    size_t i;

    for (i = 0; prefix[i] != '\0'; i++) {
        if (i >= key_len || key[i] != prefix[i]) {
            return 0;
        }
    }
    return 1;
}

/* A value that is a non-empty run of ASCII digits (an unsigned decimal int). */
static int
brix_opaque_is_uint(const char *val, size_t val_len)
{
    size_t i;

    if (val_len == 0) {
        return 0;
    }
    for (i = 0; i < val_len; i++) {
        if (val[i] < '0' || val[i] > '9') {
            return 0;
        }
    }
    return 1;
}

static void
brix_opaque_copy_key(const char *key, size_t key_len, char *keybuf,
    size_t keybuf_len)
{
    size_t i;

    if (keybuf == NULL || keybuf_len == 0) {
        return;
    }
    for (i = 0; i < key_len && i + 1 < keybuf_len; i++) {
        keybuf[i] = key[i];
    }
    keybuf[i] = '\0';
}

/*
 * Validate one "key=value" segment[0..seg_len). Returns a verdict and, on a
 * violation, copies the offending key into keybuf. An empty segment (from a
 * stray "&&" / trailing '&') is vacuously OK.
 */
static int
brix_opaque_check_segment(const char *seg, size_t seg_len, char *keybuf,
    size_t keybuf_len)
{
    size_t      key_len;
    const char *val;
    size_t      val_len;
    size_t      i;

    if (seg_len == 0) {
        return BRIX_OPAQUE_SCHEMA_OK;
    }

    key_len = brix_opaque_key_len(seg, seg_len);
    val     = seg + key_len + (key_len < seg_len ? 1 : 0);
    val_len = seg_len - key_len - (key_len < seg_len ? 1 : 0);

    /* Typed keys: brix assigns oss.asize an unsigned-integer type. A typed key
     * is by definition recognized, so this also satisfies the namespace rule. */
    if (brix_opaque_key_eq(seg, key_len, "oss.asize")) {
        if (!brix_opaque_is_uint(val, val_len)) {
            brix_opaque_copy_key(seg, key_len, keybuf, keybuf_len);
            return BRIX_OPAQUE_SCHEMA_BAD_TYPE;
        }
        return BRIX_OPAQUE_SCHEMA_OK;
    }

    for (i = 0; BRIX_OPAQUE_NAMESPACES[i] != NULL; i++) {
        if (brix_opaque_key_has_prefix(seg, key_len,
                                       BRIX_OPAQUE_NAMESPACES[i])) {
            return BRIX_OPAQUE_SCHEMA_OK;
        }
    }
    for (i = 0; BRIX_OPAQUE_BARE_KEYS[i] != NULL; i++) {
        if (brix_opaque_key_eq(seg, key_len, BRIX_OPAQUE_BARE_KEYS[i])) {
            return BRIX_OPAQUE_SCHEMA_OK;
        }
    }

    brix_opaque_copy_key(seg, key_len, keybuf, keybuf_len);
    return BRIX_OPAQUE_SCHEMA_UNKNOWN_KEY;
}

int
brix_opaque_schema_check(const char *opaque, char *keybuf, size_t keybuf_len)
{
    const char *seg;
    size_t      remaining;

    if (keybuf != NULL && keybuf_len > 0) {
        keybuf[0] = '\0';
    }
    if (opaque == NULL) {
        return BRIX_OPAQUE_SCHEMA_OK;
    }
    if (*opaque == '?') {                    /* tolerate a stray leading '?' */
        opaque++;
    }

    seg = opaque;
    for (remaining = 0; seg[remaining] != '\0'; remaining++) { /* strlen */ }

    while (remaining > 0) {
        const char *amp = NULL;
        size_t      seg_len;
        size_t      i;
        int         verdict;

        for (i = 0; i < remaining; i++) {
            if (seg[i] == '&' || seg[i] == ';') {   /* '&' and legacy ';' both split */
                amp = seg + i;
                break;
            }
        }
        seg_len = (amp != NULL) ? (size_t) (amp - seg) : remaining;

        verdict = brix_opaque_check_segment(seg, seg_len, keybuf, keybuf_len);
        if (verdict != BRIX_OPAQUE_SCHEMA_OK) {
            return verdict;
        }

        if (amp == NULL) {
            break;
        }
        remaining -= seg_len + 1;
        seg = amp + 1;
    }

    return BRIX_OPAQUE_SCHEMA_OK;
}
