/*
 * sd_http_dir.c — directory enumeration for the HTTP/WebDAV-origin driver.
 *
 * WHAT: The opendir/readdir/closedir vtable slots (+ the credential-scoped
 *       opendir_cred), implemented over a single WebDAV PROPFIND Depth:1 request
 *       against the collection URL. The 207 Multistatus response lists the
 *       collection itself plus its immediate children in ONE reply, so opendir
 *       fetches once and readdir simply cursors the buffered children.
 *
 * WHY:  A plain HTTP origin has no LIST verb, but a WebDAV origin (the common
 *       cvmfs / dCache / stock-nginx-dav shape sd_http already reads and stages
 *       against) enumerates a collection via PROPFIND (RFC 4918 §9.1). Wiring it
 *       here lets the VFS walk / kXR_dirlist / WebDAV PROPFIND-through and
 *       recursive TPC drive an HTTP-origin export the same way they drive the S3
 *       and POSIX backends — the last read-facing namespace gap on this driver.
 *
 * HOW:  PROPFIND with an EMPTY body is "allprop" (RFC 4918 §9.1), so the request
 *       reuses sd_http_request_fo unchanged (it always sends a NULL body) with
 *       method="PROPFIND" and a "Depth: 1" header. The 207 XML is parsed by a
 *       bounded, namespace-agnostic hand scanner (no libxml2 in the object path):
 *       each <D:response> yields an <D:href> and an is-collection flag from a
 *       <D:resourcetype><D:collection/>. The self entry (the collection itself)
 *       is the shallowest href by '/'-segment count; children are exactly one
 *       segment deeper — that depth rule skips self without needing to know the
 *       endpoint's base_path, and works at the export root too.
 */

#include "sd_http_internal.h"    /* endpoint + inst_state + req_t layout */

#include <ctype.h>
#include <dirent.h>              /* DT_DIR / DT_REG */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SD_HTTP_DIR_HREF_MAX  1024   /* one decoded href path */

typedef struct {
    char           name[256];
    unsigned char  d_type;
} sd_http_dirent;

/* Per-open directory state: the whole child listing, fetched once by opendir
 * (PROPFIND returns it in a single reply), cursored by readdir. malloc-owned —
 * no ngx pool off the event loop, matching the sd_remote dir state. */
typedef struct {
    sd_http_dirent *ents;
    size_t          n;
    size_t          cap;
    size_t          cursor;
} sd_http_dir_state;

/* ---- bounded, namespace-agnostic XML scanning ---------------------------- */

/* 1 iff the tag body at `q` (just past '<') has local name `local` (any "prefix:"
 * ignored) terminated by '>', '/', or whitespace. */
static int
sd_http_xml_tag_is(const char *q, const char *local, size_t llen)
{
    const char *s = q;
    const char *r = q;

    while (*r != '\0'
           && (isalnum((unsigned char) *r) || *r == '-' || *r == '_'))
    {
        r++;
    }
    if (*r == ':') {
        s = r + 1;                       /* skip "prefix:" */
    }
    if (ngx_strncasecmp((u_char *) s, (u_char *) local, llen) != 0) {
        return 0;
    }
    char after = s[llen];

    return after == '>' || after == '/' || after == ' '
        || after == '\t' || after == '\r' || after == '\n';
}

/* Next start-tag whose local name is `local`, in [p, end); returns the '<' or
 * NULL. Skips close/comment/PI tags ("</", "<!", "<?"). Shared with the write
 * path's resourcetype probe (sd_http_write.c) — declared in
 * sd_http_internal.h so both PROPFIND readers use ONE namespace-prefix-aware
 * tag scanner rather than a substring search that a filename could spoof. */
const char *
sd_http_xml_open(const char *p, const char *end, const char *local)
{
    size_t llen = strlen(local);

    while (p < end && (p = memchr(p, '<', (size_t) (end - p))) != NULL) {
        if (p + 1 < end && p[1] != '/' && p[1] != '!' && p[1] != '?'
            && sd_http_xml_tag_is(p + 1, local, llen))
        {
            return p;
        }
        p++;
    }
    return NULL;
}

static int
sd_http_hexval(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/* Percent-decode [s, s+slen) into out[cap] (NUL-terminated). '+' is left as-is
 * (WebDAV hrefs are path-encoded, not form-encoded). */
static void
sd_http_url_decode(const char *s, size_t slen, char *out, size_t cap)
{
    size_t o = 0;
    size_t i;

    for (i = 0; i < slen && o + 1 < cap; i++) {
        int hi, lo;

        if (s[i] == '%' && i + 2 < slen
            && (hi = sd_http_hexval(s[i + 1])) >= 0
            && (lo = sd_http_hexval(s[i + 2])) >= 0)
        {
            out[o++] = (char) ((hi << 4) | lo);
            i += 2;
        } else {
            out[o++] = s[i];
        }
    }
    out[o] = '\0';
}

/* From a decoded href, derive the basename into name[namecap] and the '/'-segment
 * depth into *depth. Any scheme://authority prefix and trailing slashes are
 * stripped first; the depth is a listing-relative ordinate (self vs child differ
 * by exactly 1) so the caller never needs the endpoint base_path. */
static void
sd_http_href_split(const char *dec, char *name, size_t namecap, int *depth)
{
    const char *p = dec;
    const char *sc = strstr(dec, "://");
    size_t len, bs, blen, i;
    int d = 0;

    if (sc != NULL) {
        p = strchr(sc + 3, '/');
        if (p == NULL) { p = dec + strlen(dec); }
    }
    len = strlen(p);
    while (len > 0 && p[len - 1] == '/') { len--; }
    for (i = 0; i < len; i++) {
        if (p[i] == '/') { d++; }
    }
    *depth = d;
    bs = len;
    while (bs > 0 && p[bs - 1] != '/') { bs--; }
    blen = len - bs;
    if (blen >= namecap) { blen = namecap - 1; }
    memcpy(name, p + bs, blen);
    name[blen] = '\0';
}

/* Raw pre-classification entry: name + kind + listing depth, before the self
 * (shallowest) entry is dropped. */
typedef struct {
    char           name[256];
    unsigned char  d_type;
    int            depth;
} sd_http_raw_ent;

static int
sd_http_raw_push(sd_http_raw_ent **rv, size_t *rn, size_t *rc,
    const char *name, unsigned char dt, int depth)
{
    if (*rn == *rc) {
        size_t nc = (*rc != 0) ? *rc * 2 : 32;
        void  *nb = realloc(*rv, nc * sizeof(**rv));

        if (nb == NULL) {
            return -1;
        }
        *rv = nb;
        *rc = nc;
    }
    snprintf((*rv)[*rn].name, sizeof((*rv)[*rn].name), "%s", name);
    (*rv)[*rn].d_type = dt;
    (*rv)[*rn].depth  = depth;
    (*rn)++;
    return 0;
}

/* Extract one <response> block's decoded child name, '/'-segment depth and
 * d_type. Returns 1 when the block yielded a usable HREF, 0 otherwise (no href
 * or an unterminated tag). `name` may come back EMPTY — that is the listing of
 * the export root, whose self href is "/" and therefore has no basename. The
 * caller must still count that response's depth: dropping it entirely made the
 * shallowest surviving entry a CHILD, so min_depth came out one too deep and
 * `dirlist /` on an http-backed export returned nothing at all. */
static int
sd_http_response_ent(const char *blk, const char *stop, char *name, size_t nsz,
    int *depth, unsigned char *dt)
{
    const char *h = sd_http_xml_open(blk, stop, "href");
    const char *gt;
    const char *he;
    char        dec[SD_HTTP_DIR_HREF_MAX];

    if (h == NULL) {
        return 0;
    }
    gt = memchr(h, '>', (size_t) (stop - h));
    if (gt == NULL) {
        return 0;
    }
    he = memchr(gt + 1, '<', (size_t) (stop - (gt + 1)));
    if (he == NULL) {
        he = stop;
    }
    sd_http_url_decode(gt + 1, (size_t) (he - (gt + 1)), dec, sizeof(dec));
    sd_http_href_split(dec, name, nsz, depth);
    *dt = (sd_http_xml_open(blk, stop, "collection") != NULL) ? DT_DIR : DT_REG;
    return 1;
}


/* Collect every <response> in the body into the raw vector, tracking the
 * minimum depth seen (the self entry). 0 / -1 with errno set. */
static int
sd_http_collect_responses(const char *xml, const char *end,
    sd_http_raw_ent **rv, size_t *rn, size_t *rc, int *min_depth)
{
    const char *blk = sd_http_xml_open(xml, end, "response");

    while (blk != NULL) {
        const char   *nxt  = sd_http_xml_open(blk + 1, end, "response");
        const char   *stop = (nxt != NULL) ? nxt : end;
        char          name[256];
        int           depth;
        unsigned char dt;

        if (sd_http_response_ent(blk, stop, name, sizeof(name), &depth, &dt)) {
            /* Depth is counted for EVERY response, including the nameless root
             * self entry; only named responses can become listing entries. */
            if (*min_depth < 0 || depth < *min_depth) {
                *min_depth = depth;
            }
            if (name[0] != '\0'
                && sd_http_raw_push(rv, rn, rc, name, dt, depth) != 0)
            {
                errno = ENOMEM;
                return -1;
            }
        }
        blk = nxt;
    }
    return 0;
}


/* Emit only the immediate children (depth == self_depth + 1) into ds, growing
 * its entry vector as needed. 0 / -1 with errno set. */
static int
sd_http_emit_children(const sd_http_raw_ent *rv, size_t rn, int min_depth,
    sd_http_dir_state *ds)
{
    size_t i;

    for (i = 0; i < rn; i++) {
        if (rv[i].depth != min_depth + 1) {
            continue;
        }
        if (ds->n == ds->cap) {
            size_t nc = (ds->cap != 0) ? ds->cap * 2 : 32;
            void  *nb = realloc(ds->ents, nc * sizeof(*ds->ents));

            if (nb == NULL) {
                errno = ENOMEM;
                return -1;
            }
            ds->ents = nb;
            ds->cap  = nc;
        }
        snprintf(ds->ents[ds->n].name, sizeof(ds->ents[ds->n].name), "%s",
                 rv[i].name);
        ds->ents[ds->n].d_type = rv[i].d_type;
        ds->n++;
    }
    return 0;
}


/* Parse a 207 Multistatus body into ds->ents (the immediate children only). The
 * self entry is the response with the minimum '/'-segment depth; children are
 * min+1. Returns 0 (ds populated, possibly empty), -1/ENOMEM on allocation
 * failure. A body with no <response> is a well-formed empty listing. */
static int
sd_http_parse_multistatus(const char *xml, size_t xlen, sd_http_dir_state *ds)
{
    sd_http_raw_ent *rv = NULL;
    size_t           rn = 0, rc = 0;
    int              min_depth = -1;
    int              rv_rc;

    if (sd_http_collect_responses(xml, xml + xlen, &rv, &rn, &rc,
                                  &min_depth) != 0)
    {
        free(rv);
        return -1;
    }
    rv_rc = sd_http_emit_children(rv, rn, min_depth, ds);
    free(rv);
    return rv_rc;
}

/* ---- PROPFIND request + slot wiring -------------------------------------- */

/* Build the export-relative collection key: leading '/', exactly one trailing
 * '/' (so the origin lists THIS collection's children; root -> "/"). */
static void
sd_http_dir_key(const char *path, char *key, size_t cap)
{
    size_t kl;

    kl = (size_t) snprintf(key, cap, "%s%s",
                           (path != NULL && path[0] == '/') ? "" : "/",
                           (path != NULL && path[0] != '\0') ? path : "");
    if (kl >= cap) { kl = cap - 1; }
    while (kl > 0 && key[kl - 1] == '/') { kl--; }
    if (kl + 1 < cap) { key[kl++] = '/'; }
    key[kl] = '\0';
}

/* sd_http_pf_t is declared in sd_http_internal.h: the quota reader
 * (sd_http_space.c) is a third PROPFIND caller and shares this request identity
 * and the issue helper below, so neither may be private to this file. */

/* sd_http_propfind_errno — the one PROPFIND status→errno verdict.
 *
 * WHAT: 0 iff `status` is a usable 207 multistatus; otherwise the errno the
 *       driver reports.
 * WHY:  Both PROPFIND readers (the Depth:1 listing and the Depth:0 type probe)
 *       must answer an origin's refusal identically — a 405/501 is "this origin
 *       speaks no WebDAV" for a listing exactly as it is for a type question, and
 *       a divergence there would make a path appear to exist to one caller and
 *       not the other.
 * HOW:  Pure mapping: 404/409 (absent, or a path that cannot exist under a
 *       non-collection parent) ⇒ ENOENT; 401/403 ⇒ EACCES; 405/501 ⇒ ENOTSUP;
 *       anything else non-207 ⇒ EIO. */
static int
sd_http_propfind_errno(int status)
{
    if (status == 207)                     { return 0; }
    if (status == 404 || status == 409)    { return ENOENT; }
    if (status == 401 || status == 403)    { return EACCES; }
    if (status == 405 || status == 501)    { return ENOTSUP; }
    return EIO;
}

/* sd_http_propfind_issue — send ONE PROPFIND and hand back a usable 207.
 *
 * WHAT: Composes the Depth + credential headers, runs the request, and returns 0
 *       with `resp` holding a 207 the caller must free — or -1 with *err_out set
 *       (the response is already freed).
 * WHY:  The listing (Depth:1) and the type probe (Depth:0) differ only in the
 *       depth, the endpoint pinning and what they do with the body; sharing the
 *       issue+verdict keeps one wire spelling and one refusal map for both.
 * HOW:  `pf` carries the whole request identity so the parameter list stays
 *       small; force_primary is the caller's because a type verdict must pin the
 *       endpoint the mutation will act on while a listing may fail over. A
 *       non-NULL pf->body is a NAMED-PROP request and needs its own
 *       `Content-Type: application/xml`; a NULL body is the allprop spelling and
 *       must send neither the header nor an entity. */
int
sd_http_propfind_issue(sd_http_inst_state *is, const sd_http_pf_t *pf,
    brix_s3_resp_t *resp, int *err_out)
{
    char          hdrs[SD_HTTP_AUTH_MAX + 96];
    sd_http_req_t rq = { is, "PROPFIND", pf->key, hdrs, pf->cert_pem, resp,
                         pf->force_primary, NULL /* auth_failed */,
                         NULL, 0 /* body: filled below when named-prop */ };
    int           rc;

    snprintf(hdrs, sizeof(hdrs), "Depth: %d\r\n%s%s", pf->depth,
             (pf->body != NULL) ? "Content-Type: application/xml\r\n" : "",
             (pf->auth != NULL) ? pf->auth : "");
    if (pf->body != NULL) {
        rq.body     = pf->body;
        rq.body_len = strlen(pf->body);
    }

    if (sd_http_request_fo(&rq, NULL) != 0) {
        *err_out = EIO;
        return -1;
    }
    rc = sd_http_propfind_errno(resp->status);
    if (rc != 0) {
        is->transport->resp_free(resp);
        *err_out = rc;
        return -1;
    }
    return 0;
}

/* Issue the PROPFIND Depth:1 and parse its 207 body into `ds`. 0 on success,
 * -1 with *err_out set (ENOENT/EACCES/ENOTSUP/EIO/ENOMEM). */
static int
sd_http_propfind(sd_http_inst_state *is, const char *key,
    const char *auth_hdr, const char *cert_pem, sd_http_dir_state *ds,
    int *err_out)
{
    brix_s3_resp_t resp;
    sd_http_pf_t   pf = { key, auth_hdr, cert_pem, 1 /* children */,
                          g_sd_http_force_primary, NULL /* allprop */ };
    const void    *body;
    size_t         blen = 0;
    char          *xml;
    int            rc;

    if (sd_http_propfind_issue(is, &pf, &resp, err_out) != 0) {
        return -1;
    }

    body = is->transport->resp_body(&resp, &blen);
    if (body == NULL || blen == 0) {
        is->transport->resp_free(&resp);
        return 0;                          /* well-formed empty collection */
    }
    /* The transport body is not guaranteed NUL-terminated; copy it so the scanner
     * can bound on a length AND a terminator. */
    xml = malloc(blen + 1);
    if (xml == NULL) {
        is->transport->resp_free(&resp);
        *err_out = ENOMEM;
        return -1;
    }
    memcpy(xml, body, blen);
    xml[blen] = '\0';
    is->transport->resp_free(&resp);

    rc = sd_http_parse_multistatus(xml, blen, ds);
    free(xml);
    if (rc != 0) {
        *err_out = ENOMEM;
        return -1;
    }
    return 0;
}

/* sd_http_probe_type — "does this path exist, and is it a collection?"
 *
 * WHAT: PROPFIND Depth:0 against ONE path. Returns 0 with *is_coll set, or -1
 *       with *err_out = ENOENT (absent), EACCES, ENOTSUP (the origin speaks no
 *       WebDAV) or EIO.
 * WHY:  HTTP has one spelling for both kinds of resource — a HEAD of a
 *       collection and a HEAD of an empty file are the same 200 with
 *       Content-Length 0 — so every caller that must not confuse the two needs
 *       this extra round trip. Two did, and both were wrong without it: DELETE
 *       is one method for files and collections, so `sd_http_unlink` ignored its
 *       `is_dir` argument and an rmdir of a regular FILE destroyed it; and
 *       `sd_http_stat` reported EVERY path as a regular file, so a collection
 *       stat'd as a 0-byte object — which made `mkdir -p` over an existing
 *       directory fail EEXIST once the mkpath walk started checking the type.
 * HOW:  PROPFIND with an empty (allprop) body and "Depth: 0", carrying whatever
 *       credential the caller resolved, pinned to the primary endpoint (a type
 *       verdict must describe the same origin the mutation or stat will act on).
 *       A 207 body containing <resourcetype><collection/> is a collection; the
 *       tag scan is the namespace-aware sd_http_xml_open the listing parser
 *       uses, so a file NAMED "collection" cannot spoof it. */
int
sd_http_probe_type(sd_http_inst_state *is, const char *key, const char *auth,
    const char *cert_pem, int *is_coll, int *err_out)
{
    brix_s3_resp_t resp;
    sd_http_pf_t   pf = { key, auth, cert_pem, 0 /* this resource only */,
                          1 /* force_primary: pin the endpoint the caller acts on */,
                          NULL /* allprop */ };
    const void    *body;
    size_t         blen = 0;

    if (sd_http_propfind_issue(is, &pf, &resp, err_out) != 0) {
        return -1;
    }

    body = is->transport->resp_body(&resp, &blen);
    *is_coll = (body != NULL && blen > 0
                && sd_http_xml_open((const char *) body,
                                    (const char *) body + blen,
                                    "collection") != NULL) ? 1 : 0;
    is->transport->resp_free(&resp);
    return 0;
}

/* Shared opendir path: gate + resolve the (optional) credential exactly like the
 * read open, PROPFIND the collection, and buffer the children. cred==NULL is the
 * plain (service/anonymous) slot. */
static brix_sd_dir_t *
sd_http_opendir_common(brix_sd_instance_t *inst, const char *path,
    const brix_sd_cred_t *cred, int *err_out)
{
    sd_http_inst_state *is = inst->state;
    sd_http_dir_state  *ds;
    brix_sd_dir_t      *dir;
    char                key[SD_HTTP_PATH_MAX];
    char                open_auth[SD_HTTP_AUTH_MAX];
    const char         *open_cert;
    const char         *auth_hdr;
    int                 err = EIO;

    if (sd_http_cred_gate(is, cred) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    open_cert = sd_http_resolve_open_cred(is, cred, open_auth,
                                          sizeof(open_auth));
    auth_hdr = open_auth[0] ? open_auth
                            : (is->auth_hdr[0] ? is->auth_hdr : NULL);

    ds  = calloc(1, sizeof(*ds));
    dir = calloc(1, sizeof(*dir));
    if (ds == NULL || dir == NULL) {
        free(ds);
        free(dir);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    sd_http_dir_key(path, key, sizeof(key));
    if (sd_http_propfind(is, key, auth_hdr, open_cert, ds, &err) != 0) {
        free(ds->ents);
        free(ds);
        free(dir);
        if (err_out != NULL) { *err_out = err; }
        return NULL;
    }

    dir->inst  = inst;
    dir->state = ds;
    return dir;
}

brix_sd_dir_t *
sd_http_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    return sd_http_opendir_common(inst, path, NULL, err_out);
}

/* Credential-scoped opendir: presents the requesting user's bearer / x509 proxy
 * to the origin for the enumeration, exactly as sd_http_open_cred / stat_cred do
 * for reads (phase-70 §5.1 — an https backend leg authorizes every request). */
brix_sd_dir_t *
sd_http_opendir_cred(brix_sd_instance_t *inst, const char *path, int *err_out,
    const brix_sd_cred_t *cred)
{
    return sd_http_opendir_common(inst, path, cred, err_out);
}

ngx_int_t
sd_http_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    sd_http_dir_state *ds = d->state;

    if (ds->cursor >= ds->n) {
        return NGX_DONE;
    }
    snprintf(out->name, sizeof(out->name), "%s", ds->ents[ds->cursor].name);
    out->d_type = ds->ents[ds->cursor].d_type;
    ds->cursor++;
    return NGX_OK;
}

ngx_int_t
sd_http_closedir(brix_sd_dir_t *d)
{
    sd_http_dir_state *ds;

    if (d == NULL || d->state == NULL) {
        return NGX_OK;
    }
    ds = d->state;
    free(ds->ents);
    free(ds);
    d->state = NULL;
    free(d);              /* malloc-owned shell (no pool off the event loop) */
    return NGX_OK;
}
