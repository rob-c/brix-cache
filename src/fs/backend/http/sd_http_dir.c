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
 * NULL. Skips close/comment/PI tags ("</", "<!", "<?"). */
static const char *
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

/* Parse a 207 Multistatus body into ds->ents (the immediate children only). The
 * self entry is the response with the minimum '/'-segment depth; children are
 * min+1. Returns 0 (ds populated, possibly empty), -1/ENOMEM on allocation
 * failure. A body with no <response> is a well-formed empty listing. */
static int
sd_http_parse_multistatus(const char *xml, size_t xlen, sd_http_dir_state *ds)
{
    const char      *end = xml + xlen;
    const char      *blk = sd_http_xml_open(xml, end, "response");
    sd_http_raw_ent *rv = NULL;
    size_t           rn = 0, rc = 0, i;
    int              min_depth = -1;

    while (blk != NULL) {
        const char *nxt = sd_http_xml_open(blk + 1, end, "response");
        const char *stop = (nxt != NULL) ? nxt : end;
        const char *h = sd_http_xml_open(blk, stop, "href");

        if (h != NULL) {
            const char *gt = memchr(h, '>', (size_t) (stop - h));

            if (gt != NULL) {
                const char *he = memchr(gt + 1, '<',
                                        (size_t) (stop - (gt + 1)));
                char        dec[SD_HTTP_DIR_HREF_MAX];
                char        name[256];
                int         depth;
                unsigned char dt;

                if (he == NULL) { he = stop; }
                sd_http_url_decode(gt + 1, (size_t) (he - (gt + 1)),
                                   dec, sizeof(dec));
                sd_http_href_split(dec, name, sizeof(name), &depth);
                dt = (sd_http_xml_open(blk, stop, "collection") != NULL)
                     ? DT_DIR : DT_REG;
                if (name[0] != '\0') {
                    if (sd_http_raw_push(&rv, &rn, &rc, name, dt, depth) != 0) {
                        free(rv);
                        errno = ENOMEM;
                        return -1;
                    }
                    if (min_depth < 0 || depth < min_depth) {
                        min_depth = depth;
                    }
                }
            }
        }
        blk = nxt;
    }

    /* Emit only the immediate children (depth == self_depth + 1). */
    for (i = 0; i < rn; i++) {
        if (rv[i].depth != min_depth + 1) {
            continue;
        }
        if (ds->n == ds->cap) {
            size_t nc = (ds->cap != 0) ? ds->cap * 2 : 32;
            void  *nb = realloc(ds->ents, nc * sizeof(*ds->ents));

            if (nb == NULL) {
                free(rv);
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
    free(rv);
    return 0;
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

/* Issue the PROPFIND Depth:1 and parse its 207 body into `ds`. 0 on success,
 * -1 with *err_out set (ENOENT/EACCES/ENOTSUP/EIO/ENOMEM). */
static int
sd_http_propfind(sd_http_inst_state *is, const char *key,
    const char *auth_hdr, const char *cert_pem, sd_http_dir_state *ds,
    int *err_out)
{
    brix_s3_resp_t resp;
    char           hdrs[SD_HTTP_AUTH_MAX + 32];
    sd_http_req_t  rq = { is, "PROPFIND", key, hdrs, cert_pem, &resp,
                          g_sd_http_force_primary };
    const void    *body;
    size_t         blen = 0;
    char          *xml;
    int            rc;

    snprintf(hdrs, sizeof(hdrs), "Depth: 1\r\n%s",
             (auth_hdr != NULL) ? auth_hdr : "");

    if (sd_http_request_fo(&rq, NULL) != 0) {
        *err_out = EIO;
        return -1;
    }
    if (resp.status == 404) {
        is->transport->resp_free(&resp);
        *err_out = ENOENT;
        return -1;
    }
    if (resp.status == 401 || resp.status == 403) {
        is->transport->resp_free(&resp);
        *err_out = EACCES;
        return -1;
    }
    /* 405 Method Not Allowed / 501 Not Implemented ⇒ the origin is a plain HTTP
     * source with no WebDAV: report "no directory support", never guess. */
    if (resp.status == 405 || resp.status == 501) {
        is->transport->resp_free(&resp);
        *err_out = ENOTSUP;
        return -1;
    }
    if (resp.status != 207) {
        is->transport->resp_free(&resp);
        *err_out = EIO;
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
