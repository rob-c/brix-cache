/* oci_classify.c — the `/v2/` route classifier (phase-104 D0.2).
 *
 * WHAT: parse a decoded request URI into brix_oci_req_t: which §0.7.1 endpoint
 *       it names plus the validated name/reference/digest/session spans.
 * WHY:  see oci_classify.h — one validating parse at the edge is the whole
 *       traversal defense for every path this module later composes.
 * HOW:  the API prefix is located by the literal "/v2/", which is
 *       component-boundary-safe on its own (no other byte sequence contains
 *       it across a boundary). What follows is matched RIGHT-TO-LEFT on the
 *       five reserved terminals, so a repository actually named "blobs" or
 *       "v2" still classifies: only the last two or three components decide
 *       the route, and everything left of them is the name. That needs just the
 *       final three slash positions — no component array, no bound to overflow.
 */

#include "oci_classify.h"

#include "oci/name.h"

#include <string.h>

/* One slash-delimited span of the post-prefix path. */
typedef struct {
    const char *p;
    size_t      n;
} oci_span_t;

/* The last three slash offsets of [s, s+n), newest first; absent ones are -1.
 * Three is exactly what the terminal grammar needs (`<name>/blobs/uploads/<id>`
 * is the deepest form), so the scan is bounded by the grammar, not by a cap. */
static void
oci_tail_slashes(const char *s, size_t n, long *p1, long *p2, long *p3)
{
    long i;

    *p1 = *p2 = *p3 = -1;
    for (i = (long) n - 1; i >= 0; i--) {
        if (s[i] != '/') {
            continue;
        }
        if (*p1 < 0) {
            *p1 = i;
        } else if (*p2 < 0) {
            *p2 = i;
        } else {
            *p3 = i;
            return;
        }
    }
}

/* The span between two slash offsets (`from` is the slash BEFORE the span, or
 * -1 for "start of string"; `to` is the slash after it, or n for "end"). */
static oci_span_t
oci_seg(const char *s, long from, long to)
{
    oci_span_t sp;

    sp.p = s + from + 1;
    sp.n = (size_t) (to - from - 1);
    return sp;
}

static int
oci_seg_is(oci_span_t sp, const char *lit)
{
    size_t n = strlen(lit);

    return sp.n == n && memcmp(sp.p, lit, n) == 0;
}

/* Session identifiers become a staged-file basename: [A-Za-z0-9_-]{1,128}. */
static int
oci_session_valid(const char *s, size_t n)
{
    size_t i;

    if (n == 0 || n > BRIX_OCI_SESSION_MAX) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        char c = s[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || c == '_' || c == '-'))
        {
            return -1;
        }
    }
    return 0;
}

static int
oci_bad(brix_oci_req_t *out, brix_oci_err_t err)
{
    out->cls = BRIX_OCI_REQ_BAD;
    out->err = err;
    return -1;
}

/* Record a validated repository name on the result. */
static int
oci_set_name(brix_oci_req_t *out, const char *p, size_t n)
{
    if (brix_oci_name_valid(p, n) != 0) {
        return oci_bad(out, BRIX_OCI_ERR_NAME_INVALID);
    }
    out->name             = p;
    out->name_len         = n;
    out->name_components  = brix_oci_name_components(p, n);
    return 0;
}

/* `manifests/<ref>`: a reference is a digest or a tag, and which one it is
 * decides the cache policy downstream (immutable vs revalidated), so the
 * classifier records it rather than making every consumer re-guess. */
static int
oci_route_manifest(brix_oci_req_t *out, const char *rest, long p2,
    oci_span_t last)
{
    brix_oci_digest_t d;

    if (oci_set_name(out, rest, (size_t) p2) != 0) {
        return -1;
    }
    out->cls     = BRIX_OCI_REQ_MANIFEST;
    out->ref     = last.p;
    out->ref_len = last.n;

    if (brix_oci_digest_parse(last.p, last.n, &d) == 0) {
        out->ref_is_digest = 1;
        out->digest = d;
        return 0;
    }
    /* A reference that is neither a valid digest nor a valid tag is a grammar
     * violation, not a missing manifest — 400, so a client cannot probe the
     * store with malformed references and read 404 vs 400 as an oracle. */
    if (brix_oci_tag_valid(last.p, last.n) != 0) {
        return oci_bad(out, BRIX_OCI_ERR_NAME_INVALID);
    }
    return 0;
}

/* `blobs/<digest>` and the two upload forms that share the `blobs/` prefix. */
static int
oci_route_blobs(brix_oci_req_t *out, const char *rest, long p2,
    oci_span_t last)
{
    brix_oci_digest_t d;

    if (oci_seg_is(last, "uploads")) {
        if (oci_set_name(out, rest, (size_t) p2) != 0) {
            return -1;
        }
        out->cls = BRIX_OCI_REQ_UPLOAD_START;
        return 0;
    }
    if (oci_set_name(out, rest, (size_t) p2) != 0) {
        return -1;
    }
    if (brix_oci_digest_parse(last.p, last.n, &d) != 0) {
        return oci_bad(out, BRIX_OCI_ERR_DIGEST_INVALID);
    }
    out->cls = BRIX_OCI_REQ_BLOB;
    out->digest = d;
    return 0;
}

/* `referrers/<digest>` — the reference here is the SUBJECT, the manifest that
 * others point at, and only a digest may name it: a tag would make the answer
 * depend on where that tag pointed when each referrer was pushed, which is the
 * mutability the referrers graph exists to escape. */
static int
oci_route_referrers(brix_oci_req_t *out, const char *rest, long p2,
    oci_span_t last)
{
    brix_oci_digest_t  subject;

    if (oci_set_name(out, rest, (size_t) p2) != 0) {
        return -1;
    }
    if (brix_oci_digest_parse(last.p, last.n, &subject) != 0) {
        return oci_bad(out, BRIX_OCI_ERR_DIGEST_INVALID);
    }
    out->cls = BRIX_OCI_REQ_REFERRERS;
    out->digest = subject;
    return 0;
}


/* `blobs/uploads/<session>` — the only three-terminal form. */
static int
oci_route_upload_session(brix_oci_req_t *out, const char *rest, long p3,
    oci_span_t last)
{
    if (oci_set_name(out, rest, (size_t) p3) != 0) {
        return -1;
    }
    if (oci_session_valid(last.p, last.n) != 0) {
        return oci_bad(out, BRIX_OCI_ERR_BLOB_UPLOAD_INVALID);
    }
    out->cls         = BRIX_OCI_REQ_UPLOAD_SESSION;
    out->session     = last.p;
    out->session_len = last.n;
    return 0;
}

/* Locate the API prefix and return the offset just past it, or -1.
 * "/v2/" cannot straddle a component boundary — the leading slash IS the
 * boundary — so a plain substring search is already boundary-correct, and a
 * location-prefixed mount ("/local/v2/…") needs no special case. */
static long
oci_api_prefix_end(const char *uri, size_t len)
{
    size_t i;

    for (i = 0; i + 4 <= len; i++) {
        if (memcmp(uri + i, "/v2/", 4) == 0) {
            return (long) (i + 4);
        }
    }
    /* Only when nothing deeper matched: the bare, slashless "/v2" ping. Tried
     * second so "/v2/library/v2" is a manifest-space path, not an API root. */
    if (len >= 3 && memcmp(uri + len - 3, "/v2", 3) == 0) {
        return (long) len;
    }
    return -1;
}

/* The terminal half of the grammar: after "/v2/" has been stripped and one
 * trailing slash normalised away, what is left is
 * "<name>/<terminal>[/<reference>]" and the only remaining question is which
 * terminal it names. Split out of brix_oci_classify so the normalisation
 * rules and the route table each read as a single decision.
 */
static int
oci_route_terminal(brix_oci_req_t *out, const char *rest, size_t rest_len)
{
    long        p1, p2, p3;
    oci_span_t  last, seg2, seg3;

    oci_tail_slashes(rest, rest_len, &p1, &p2, &p3);
    if (p1 < 0 || p2 < 0) {
        /* Fewer than two slashes cannot spell any terminal — a name with no
         * endpoint after it. */
        return oci_bad(out, BRIX_OCI_ERR_NAME_UNKNOWN);
    }
    last = oci_seg(rest, p1, (long) rest_len);
    seg2 = oci_seg(rest, p2, p1);
    seg3 = (p3 >= 0) ? oci_seg(rest, p3, p2) : oci_seg(rest, -1, p2);

    if (oci_seg_is(seg2, "manifests")) {
        return oci_route_manifest(out, rest, p2, last);
    }
    if (oci_seg_is(seg2, "blobs")) {
        return oci_route_blobs(out, rest, p2, last);
    }
    if (oci_seg_is(seg2, "uploads") && oci_seg_is(seg3, "blobs")) {
        /* p3 < 0 means "blobs/uploads/<id>" with no name at all. */
        if (p3 < 0) {
            return oci_bad(out, BRIX_OCI_ERR_NAME_INVALID);
        }
        return oci_route_upload_session(out, rest, p3, last);
    }
    if (oci_seg_is(seg2, "referrers")) {
        return oci_route_referrers(out, rest, p2, last);
    }
    if (oci_seg_is(seg2, "tags") && oci_seg_is(last, "list")) {
        if (oci_set_name(out, rest, (size_t) p2) != 0) {
            return -1;
        }
        out->cls = BRIX_OCI_REQ_TAGS_LIST;
        return 0;
    }
    return oci_bad(out, BRIX_OCI_ERR_NAME_UNKNOWN);
}

int
brix_oci_classify(const char *uri, size_t len, brix_oci_req_t *out)
{
    const char *rest;
    size_t      rest_len;
    long        end;

    memset(out, 0, sizeof(*out));

    end = oci_api_prefix_end(uri, len);
    if (end < 0) {
        return oci_bad(out, BRIX_OCI_ERR_NAME_UNKNOWN);
    }
    rest     = uri + end;
    rest_len = len - (size_t) end;

    /* One trailing slash is the canonical spelling of the upload-start route
     * and harmless noise everywhere else; strip it so the terminal match sees
     * a single shape. A second one is a malformed path, not a spelling. */
    if (rest_len > 0 && rest[rest_len - 1] == '/') {
        rest_len--;
    }
    if (rest_len == 0) {
        out->cls = BRIX_OCI_REQ_API_ROOT;
        return 0;
    }
    if (rest[rest_len - 1] == '/') {
        return oci_bad(out, BRIX_OCI_ERR_NAME_INVALID);
    }

    return oci_route_terminal(out, rest, rest_len);
}

const char *
brix_oci_class_str(brix_oci_class_t cls)
{
    switch (cls) {
    case BRIX_OCI_REQ_API_ROOT:       return "api";
    case BRIX_OCI_REQ_MANIFEST:       return "manifest";
    case BRIX_OCI_REQ_BLOB:           return "blob";
    case BRIX_OCI_REQ_UPLOAD_START:   return "upload";
    case BRIX_OCI_REQ_UPLOAD_SESSION: return "upload";
    case BRIX_OCI_REQ_TAGS_LIST:      return "tags";
    case BRIX_OCI_REQ_REFERRERS:      return "referrers";
    default:                          return "bad";
    }
}
