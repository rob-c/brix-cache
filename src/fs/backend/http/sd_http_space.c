/*
 * sd_http_space.c — the `space` vtable slot for the http origin driver.
 *
 * WHAT: Answers "how big is this backend, and how much of it is left?" from the
 *       ORIGIN's own RFC-4331 quota properties, over one Depth:0 PROPFIND on the
 *       export root.
 *
 * WHY:  Without this slot kXR_statvfs / kXR_Qspace / kXR_QFSinfo / SRR fall back
 *       to a statvfs(2) of the gateway's own export directory — for an http
 *       origin that directory holds nothing at all, so a client sizing a
 *       transfer against it is reading the gateway's spool, not the storage it
 *       is about to write to. This is the http sibling of sd_xroot_space, which
 *       closed exactly the same wrong answer for root:// origins.
 *
 * HOW:  RFC 4331 defines a pair of live properties, `DAV:quota-available-bytes`
 *       (what THIS principal may still write) and `DAV:quota-used-bytes`. They
 *       are live properties outside RFC 4918, so an empty ("allprop") PROPFIND
 *       is not required to return them — the request therefore carries an
 *       explicit named-prop body, which is why sd_http_req_t grew an optional
 *       entity. The 207 is read with the same bounded, namespace-agnostic tag
 *       scanner the directory listing uses; nothing here parses XML generally.
 *
 *       There is no `total` property: RFC 4331 §3 makes used+available the only
 *       defined derivation, and it is the one every WebDAV client makes. A
 *       missing or unparsable half means the origin does not report quota, which
 *       is NGX_ERROR here so the caller falls back to the local statvfs — a
 *       fabricated total would be worse than no answer.
 */

#include "sd_http_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The named-prop request. Kept to the two properties actually consulted: an
 * allprop would be shorter to write but is not obliged to carry either of them,
 * and asking for more than is read invites an origin to do more work than the
 * answer needs. */
static const char sd_http_quota_body[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
    "<D:propfind xmlns:D=\"DAV:\"><D:prop>"
    "<D:quota-available-bytes/><D:quota-used-bytes/>"
    "</D:prop></D:propfind>";

/* A quota multistatus is a few hundred bytes. Anything past this is not the
 * reply this reader understands, and copying it to NUL-terminate it (the tag
 * scanner walks a C string) would be unbounded work on a driver thread. */
#define SD_HTTP_QUOTA_XML_MAX  (64u * 1024u)

/* XML S production (RFC 4918 bodies are XML 1.0): the only bytes allowed to sit
 * between a start tag and its character data, or after it. */
static int
sd_http_quota_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static const char *
sd_http_quota_skip_ws(const char *p, const char *end)
{
    while (p < end && sd_http_quota_ws(*p)) {
        p++;
    }
    return p;
}

/*
 * WHAT: Accumulate one unsigned decimal run at *pp, advancing it past the run.
 * WHY:  strtoull would take a sign, whitespace and a base prefix, and reports
 *       overflow only through errno — none of which is wanted for a value this
 *       server republishes as a capacity.
 * HOW:  Digits only, with a pre-multiply ceiling so an over-wide value is
 *       refused rather than wrapped; an empty run is a refusal, not a zero.
 */
static int
sd_http_quota_u64(const char **pp, const char *end, uint64_t *out)
{
    const char *p = *pp;
    uint64_t    v = 0;
    int         digits = 0;

    while (p < end && *p >= '0' && *p <= '9') {
        if (v > (UINT64_MAX - (uint64_t) (*p - '0')) / 10) {
            return -1;                   /* not a size we can represent */
        }
        v = v * 10 + (uint64_t) (*p - '0');
        digits++;
        p++;
    }
    *pp  = p;
    *out = v;
    return (digits > 0) ? 0 : -1;
}

/*
 * WHAT: Read the unsigned decimal text of element `local` into *out.
 * WHY:  Both quota properties are "a single non-negative integer" (RFC 4331 §3);
 *       an origin that does not support one still lists it, as an EMPTY element
 *       inside a 404 propstat, so "the tag is present" is not "there is a value"
 *       and must not be read as a zero.
 * HOW:  Locate the start tag with the shared scanner, refuse the self-closing
 *       form (`<…/>`), then accumulate digits with an overflow ceiling and
 *       require the run to end on markup or whitespace — so `12x` is rejected
 *       whole rather than read as 12.
 */
static int
sd_http_quota_prop(const char *xml, const char *end, const char *local,
    uint64_t *out)
{
    const char *p = sd_http_xml_open(xml, end, local);
    const char *gt;
    uint64_t    v = 0;

    if (p == NULL) {
        return -1;
    }
    /* p is the '<' itself, so the '>' that ends the start tag is always past it
     * and gt[-1] is always readable. */
    gt = memchr(p, '>', (size_t) (end - p));
    if (gt == NULL || gt[-1] == '/') {
        return -1;                       /* empty element: no value at all */
    }
    p = sd_http_quota_skip_ws(gt + 1, end);
    if (sd_http_quota_u64(&p, end, &v) != 0) {
        return -1;
    }
    if (p < end && *p != '<' && !sd_http_quota_ws(*p)) {
        return -1;                       /* trailing junk: not a bare integer */
    }
    *out = v;
    return 0;
}

/*
 * WHAT: Turn one 207 quota body into the space triple.
 * WHY:  Split from the request leg so the wire handling and the arithmetic are
 *       separately readable, and so the NUL-terminated copy the tag scanner
 *       needs has one owner.
 * HOW:  Bounded malloc + copy, both properties or nothing, total = used +
 *       available with an overflow refusal.
 */
static int
sd_http_quota_parse(const void *body, size_t blen, brix_sd_space_t *out)
{
    char       *xml;
    uint64_t    avail = 0, used = 0;
    int         rc;

    if (body == NULL || blen == 0 || blen > SD_HTTP_QUOTA_XML_MAX) {
        return -1;
    }
    xml = malloc(blen + 1);
    if (xml == NULL) {
        return -1;
    }
    memcpy(xml, body, blen);
    xml[blen] = '\0';

    rc = sd_http_quota_prop(xml, xml + blen, "quota-available-bytes", &avail);
    if (rc == 0) {
        rc = sd_http_quota_prop(xml, xml + blen, "quota-used-bytes", &used);
    }
    free(xml);
    if (rc != 0) {
        return -1;
    }
    if (avail > UINT64_MAX - used) {
        return -1;
    }
    out->free_bytes  = avail;
    out->used_bytes  = used;
    out->total_bytes = avail + used;
    return 0;
}

ngx_int_t
sd_http_space(brix_sd_instance_t *inst, brix_sd_space_t *out)
{
    sd_http_inst_state *is;
    brix_s3_resp_t      resp;
    sd_http_pf_t        pf;
    const void         *body;
    size_t              blen = 0;
    int                 err = 0, rc;

    if (inst == NULL || inst->state == NULL || out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    is = inst->state;

    pf.key           = "/";
    pf.auth          = (is->auth_hdr[0] != '\0') ? is->auth_hdr : NULL;
    pf.cert_pem      = NULL;   /* instance scope: no per-open user proxy here */
    pf.depth         = 0;
    pf.force_primary = 0;      /* a capacity read may fail over like a listing */
    pf.body          = sd_http_quota_body;

    if (sd_http_propfind_issue(is, &pf, &resp, &err) != 0) {
        errno = err;
        return NGX_ERROR;
    }
    body = is->transport->resp_body(&resp, &blen);
    rc = sd_http_quota_parse(body, blen, out);
    is->transport->resp_free(&resp);
    if (rc != 0) {
        errno = ENOTSUP;       /* this origin reports no quota; use the fallback */
        return NGX_ERROR;
    }
    return NGX_OK;
}
