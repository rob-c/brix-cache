/*
 * sd_http_xattr.c — reading extended attributes on an http origin, out of the
 * WebDAV dead properties that carry them.
 *
 * WHAT: The getxattr/listxattr vtable slots and their credential-scoped twins,
 *       over a named-prop PROPFIND Depth:0 (one attribute) and a propname
 *       PROPFIND Depth:0 (the whole set). The write half is sd_http_xattr_write.c.
 *
 * WHY:  `http` was the only namespace-capable driver in the tree with NO xattr
 *       support at all, and everything the gateway layers on top of a per-object
 *       key/value store went dark behind an http origin: WebDAV LOCK tokens,
 *       WebDAV PROPPATCH dead properties, S3 object tagging, S3 user metadata,
 *       and root:// kXR_fattr. Each of those already has one storage-neutral
 *       spelling — an xattr on the object — so closing the slot re-lights all of
 *       them at once rather than teaching five features about HTTP.
 *
 * HOW:  RFC 4918 §15 dead properties are exactly the primitive wanted: arbitrary
 *       server-preserved name/value pairs on a resource. One xattr becomes one
 *       element in the BriX xattr XML namespace, named `bxa` + lowercase hex of
 *       the xattr name; the value is lowercase hex too.
 *
 *       Hex on BOTH halves is a security property, not a style: an xattr name or
 *       value is arbitrary bytes chosen by a remote client, and interpolating
 *       those into a request body is how markup injection happens. Hex has no
 *       XML metacharacters and no NUL problem, so a value of `]]></D:prop>` is
 *       just eighteen more hex digits on the wire. It also makes the mapping
 *       total and reversible, which a "translate to the natural dead property"
 *       scheme cannot be: keys like `user.s3.tagging` have no namespace/local
 *       pair to translate INTO, and the webdav dead-prop codec that owns the
 *       other direction is ngx_pool_t-based, so calling it from ngx-free backend
 *       code would invert the layering. The cost is that these properties are
 *       opaque to a native WebDAV client — recorded, deliberate, and the reason
 *       the element carries a BriX-specific namespace rather than squatting DAV:.
 *
 *       Every read goes through ONE propfind helper and every write through ONE
 *       proppatch helper (sd_http_xattr_write.c), so the credential gate, the
 *       endpoint pinning and the multistatus verdict have a single spelling
 *       across the four ops. The wire spelling itself — namespace, element
 *       marker, size ceilings — lives in sd_http_xattr_internal.h so the reader
 *       and the writer cannot drift apart.
 */

#include "sd_http_xattr_internal.h"

#include "core/compat/hex.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
 * WHAT: Encode one xattr name as the element local name `bxa<hex(name)>`.
 * WHY:  The name is remote-chosen bytes; it must never reach a request body in a
 *       form that could close a tag or open one.
 * HOW:  Reject empty (EINVAL) and over-long (ERANGE, matching Linux setxattr),
 *       then hex the bytes after the fixed `bxa` marker that tells a scan which
 *       properties on a resource are ours.
 */
int
sd_http_xattr_elem(const char *name, char *out, size_t cap)
{
    size_t nlen;

    if (name == NULL || name[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    nlen = strlen(name);
    if (nlen > SD_HTTP_XATTR_NAME_MAX || 3 + 2 * nlen + 1 > cap) {
        errno = ERANGE;
        return -1;
    }
    memcpy(out, "bxa", 3);
    brix_hex_encode((const uint8_t *) name, nlen, out + 3);
    return 0;
}


/*
 * WHAT: Decode `n` hex digits at `p` into out[cap], returning the byte count.
 * WHY:  Both halves of the mapping travel as hex, so exactly one decoder is
 *       needed — and it must refuse rather than salvage: a half-decoded value
 *       handed to a caller as if it were the stored one is a silent corruption.
 * HOW:  Odd length or any non-hex digit is -1; an over-long run is -1 too, so a
 *       short destination never sees a partial write.
 */
static ssize_t
sd_http_xattr_unhex(const char *p, size_t n, unsigned char *out, size_t cap)
{
    size_t i;

    if ((n & 1u) != 0 || n / 2 > cap) {
        return -1;
    }
    for (i = 0; i < n; i += 2) {
        int hi = brix_hex_from_char((unsigned char) p[i]);
        int lo = brix_hex_from_char((unsigned char) p[i + 1]);

        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i / 2] = (unsigned char) ((hi << 4) | lo);
    }
    return (ssize_t) (n / 2);
}


/*
 * WHAT: Resolve the credential for one xattr request into an auth header line
 *       and an optional per-user x509 proxy path.
 * WHY:  All four ops present the requesting user's identity the same way, and
 *       the deny-mode refusal (a proxy-only cred the transport cannot present)
 *       must happen BEFORE any request leaves this host.
 * HOW:  The shared cred gate, then the shared open-cred resolver; the per-user
 *       bearer wins over the instance static header, "" means anonymous.
 */
int
sd_http_xattr_auth(sd_http_inst_state *is, const brix_sd_cred_t *cred,
    char *open_auth, size_t cap, const char **auth_out, const char **cert_out)
{
    if (sd_http_cred_gate(is, cred) != 0) {
        return -1;                          /* errno = EACCES (set by the gate) */
    }
    *cert_out = sd_http_resolve_open_cred(is, cred, open_auth, cap);
    *auth_out = open_auth[0] ? open_auth
                             : (is->auth_hdr[0] ? is->auth_hdr : NULL);
    return 0;
}


/*
 * WHAT: Issue one Depth:0 named-prop PROPFIND and hand back its body as a
 *       NUL-terminated, bounded, malloc'd copy the caller frees.
 * WHY:  get and list differ only in the request body and what they scan for;
 *       sharing the request leg keeps one credential path and one size ceiling.
 * HOW:  The shared propfind issuer, pinned to the primary endpoint — a property
 *       read must see the same replica the matching write acts on — then a
 *       bounded copy, because the tag scanners walk a C string.
 */
static int
sd_http_xattr_propfind(sd_http_inst_state *is, const char *path,
    const char *body, const brix_sd_cred_t *cred, char **xml_out,
    size_t *len_out)
{
    char            open_auth[SD_HTTP_AUTH_MAX];
    const char     *auth, *cert;
    brix_s3_resp_t  resp;
    sd_http_pf_t    pf;
    const void     *rbody;
    size_t          blen = 0;
    char           *xml = NULL;
    int             err = 0;

    if (sd_http_xattr_auth(is, cred, open_auth, sizeof(open_auth),
                           &auth, &cert) != 0)
    {
        return -1;
    }
    pf.key           = path;
    pf.auth          = auth;
    pf.cert_pem      = (cert != NULL && cert[0] != '\0') ? cert : NULL;
    pf.depth         = 0;
    pf.force_primary = 1;
    pf.body          = body;

    if (sd_http_propfind_issue(is, &pf, &resp, &err) != 0) {
        errno = err;
        return -1;
    }
    rbody = is->transport->resp_body(&resp, &blen);
    if (rbody == NULL || blen == 0 || blen > SD_HTTP_XATTR_XML_MAX) {
        is->transport->resp_free(&resp);
        errno = EIO;                        /* not a multistatus we can read */
        return -1;
    }
    xml = malloc(blen + 1);
    if (xml == NULL) {
        is->transport->resp_free(&resp);
        errno = ENOMEM;
        return -1;
    }
    memcpy(xml, rbody, blen);
    xml[blen] = '\0';
    is->transport->resp_free(&resp);

    *xml_out = xml;
    *len_out = blen;
    return 0;
}


/*
 * WHAT: 1 iff the first `<…status>` element at or after `p` reads 2xx.
 * WHY:  A named-prop PROPFIND for an ABSENT property still returns the element —
 *       inside a 404 propstat. Reading the element without reading the propstat
 *       status is how "no such attribute" becomes "an empty attribute".
 * HOW:  RFC 4918 orders `propstat = prop, status`, so the first status after our
 *       element is the one that judges it; its text is a status-line, and the
 *       code is the token after the HTTP version.
 */
int
sd_http_xattr_status_ok(const char *p, const char *end)
{
    const char *st = sd_http_xml_open(p, end, "status");
    const char *gt, *te;

    if (st == NULL) {
        return 0;
    }
    gt = memchr(st, '>', (size_t) (end - st));
    if (gt == NULL || gt[-1] == '/') {
        return 0;
    }
    te = memchr(gt + 1, '<', (size_t) (end - (gt + 1)));
    if (te == NULL) {
        te = end;
    }
    while (gt + 1 < te && *gt != ' ') {
        gt++;                               /* skip the HTTP-version token */
    }
    return (te - gt >= 4 && gt[1] == '2');
}


/*
 * WHAT: Read one property's hex text out of a 207 body into `buf`.
 * WHY:  Split from the request leg so the POSIX buffer contract (bufsz 0 = ask
 *       the size, short buffer = ERANGE with nothing written) is stated once.
 * HOW:  Locate our element, refuse the self-closing form and a non-2xx propstat
 *       as ENODATA, decode the hex text, and only then decide whether it fits.
 */
static ssize_t
sd_http_xattr_extract(const char *xml, size_t xlen, const char *elem,
    void *buf, size_t bufsz)
{
    const char    *end = xml + xlen;
    const char    *p   = sd_http_xml_open(xml, end, elem);
    const char    *gt, *te;
    unsigned char  val[SD_HTTP_XATTR_VALUE_MAX];
    ssize_t        vlen;

    if (p == NULL) {
        errno = ENODATA;
        return -1;
    }
    gt = memchr(p, '>', (size_t) (end - p));
    if (gt == NULL || gt[-1] == '/' || !sd_http_xattr_status_ok(gt, end)) {
        errno = ENODATA;                    /* empty element or 404 propstat */
        return -1;
    }
    te = memchr(gt + 1, '<', (size_t) (end - (gt + 1)));
    if (te == NULL) {
        errno = EIO;
        return -1;
    }
    vlen = sd_http_xattr_unhex(gt + 1, (size_t) (te - (gt + 1)), val,
                               sizeof(val));
    if (vlen < 0) {
        errno = EIO;                        /* not a value this driver wrote */
        return -1;
    }
    if (bufsz == 0) {
        return vlen;                        /* size enquiry */
    }
    if ((size_t) vlen > bufsz) {
        errno = ERANGE;                     /* refuse; never truncate */
        return -1;
    }
    memcpy(buf, val, (size_t) vlen);
    return vlen;
}


ssize_t
sd_http_getxattr_common(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t bufsz, const brix_sd_cred_t *cred)
{
    sd_http_inst_state *is;
    char                elem[SD_HTTP_XATTR_ELEM_MAX];
    char                body[SD_HTTP_XATTR_ELEM_MAX + 256];
    char               *xml = NULL;
    size_t              xlen = 0;
    ssize_t             rc;

    if (inst == NULL || inst->state == NULL || path == NULL
        || (buf == NULL && bufsz != 0))
    {
        errno = EINVAL;
        return -1;
    }
    is = inst->state;
    if (sd_http_xattr_elem(name, elem, sizeof(elem)) != 0) {
        return -1;                          /* errno set by the encoder */
    }
    snprintf(body, sizeof(body),
             "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
             "<D:propfind xmlns:D=\"DAV:\" xmlns:B=\"%s\">"
             "<D:prop><B:%s/></D:prop></D:propfind>",
             SD_HTTP_XATTR_NS, elem);

    if (sd_http_xattr_propfind(is, path, body, cred, &xml, &xlen) != 0) {
        return -1;
    }
    rc = sd_http_xattr_extract(xml, xlen, elem, buf, bufsz);
    free(xml);
    return rc;
}


/*
 * WHAT: Length of the element local name starting at `p` (after the '<'), with
 *       any namespace prefix already stripped.
 * WHY:  listxattr enumerates properties by PATTERN (`bxa…`), which the shared
 *       exact-name tag scanner cannot express.
 * HOW:  Skip a `prefix:` if one is present, then run to the first byte that can
 *       end a name; 0 means this was not a name-shaped tag.
 */
static size_t
sd_http_xattr_local(const char **pp, const char *end)
{
    const char *p = *pp;
    const char *colon = NULL;
    const char *s;

    for (s = p; s < end && *s != '>' && *s != '/' && *s != ' ' && *s != '\t'
                && *s != '\r' && *s != '\n'; s++)
    {
        if (*s == ':') {
            colon = s;
        }
    }
    if (colon != NULL) {
        p = colon + 1;
    }
    *pp = p;
    return (size_t) (s - p);
}


/*
 * WHAT: Append every `bxa…` property name found in a propname 207 to `buf` as
 *       NUL-terminated strings, returning the total size the answer needs.
 * WHY:  listxattr's contract is "how many bytes would this take" when bufsz is
 *       0, and ERANGE — not a truncated list — when the buffer is too small.
 * HOW:  Walk start tags, decode the hex after the `bxa` marker, and account for
 *       the size on EVERY name even after the buffer is known to be short, so
 *       the enquiry and the fill agree.
 */
static ssize_t
sd_http_xattr_collect(const char *xml, size_t xlen, void *dst, size_t bufsz)
{
    const char *end  = xml + xlen;
    const char *p    = xml;
    char       *buf  = dst;
    size_t      need = 0;
    int         over = 0;

    while (p < end && (p = memchr(p, '<', (size_t) (end - p))) != NULL) {
        unsigned char nm[SD_HTTP_XATTR_NAME_MAX + 1];
        const char   *lp = ++p;
        size_t        llen;
        ssize_t       nlen;

        if (lp >= end || *lp == '/' || *lp == '!' || *lp == '?') {
            continue;
        }
        llen = sd_http_xattr_local(&lp, end);
        if (llen <= 3 || memcmp(lp, "bxa", 3) != 0) {
            continue;
        }
        nlen = sd_http_xattr_unhex(lp + 3, llen - 3, nm, sizeof(nm) - 1);
        if (nlen <= 0) {
            continue;                       /* not a property this driver wrote */
        }
        if (bufsz != 0 && need + (size_t) nlen + 1 <= bufsz) {
            memcpy(buf + need, nm, (size_t) nlen);
            buf[need + (size_t) nlen] = '\0';
        } else if (bufsz != 0) {
            over = 1;
        }
        need += (size_t) nlen + 1;
    }
    if (over) {
        errno = ERANGE;
        return -1;
    }
    return (ssize_t) need;
}


static ssize_t
sd_http_listxattr_common(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t bufsz, const brix_sd_cred_t *cred)
{
    static const char propname[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<D:propfind xmlns:D=\"DAV:\"><D:propname/></D:propfind>";
    char   *xml = NULL;
    size_t  xlen = 0;
    ssize_t rc;

    if (inst == NULL || inst->state == NULL || path == NULL
        || (buf == NULL && bufsz != 0))
    {
        errno = EINVAL;
        return -1;
    }
    if (sd_http_xattr_propfind(inst->state, path, propname, cred, &xml,
                               &xlen) != 0)
    {
        return -1;
    }
    rc = sd_http_xattr_collect(xml, xlen, buf, bufsz);
    free(xml);
    return rc;
}


ssize_t
sd_http_getxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    void *buf, size_t bufsz)
{
    return sd_http_getxattr_common(inst, path, name, buf, bufsz, NULL);
}

ssize_t
sd_http_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t bufsz, const brix_sd_cred_t *cred)
{
    return sd_http_getxattr_common(inst, path, name, buf, bufsz, cred);
}

ssize_t
sd_http_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t bufsz)
{
    return sd_http_listxattr_common(inst, path, buf, bufsz, NULL);
}

ssize_t
sd_http_listxattr_cred(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t bufsz, const brix_sd_cred_t *cred)
{
    return sd_http_listxattr_common(inst, path, buf, bufsz, cred);
}
