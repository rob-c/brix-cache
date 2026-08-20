/* reg_verbs.c — registry verbs over the reg_client core: manifest GET /
 * platform resolve / PUT / DELETE and tags listing (see reg_client.h). */
#include "oci/reg_internal.h"

#include "oci/digest.h"
#include "oci/mediatypes.h"
#include "core/compat/json_iter.h"
#include "core/compat/json_min.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

/* Media-type equality up to parameters ("; charset=…"). */
static int
mt_is(const char *mt, const char *want)
{
    size_t n = strlen(want);

    return strncmp(mt, want, n) == 0 && (mt[n] == '\0' || mt[n] == ';');
}

static int
mt_is_index(const char *mt)
{
    return mt_is(mt, OCI_MT_INDEX) || mt_is(mt, D2_MT_LIST);
}

/* The algorithm a ref pins, and — when it pins one — the digest the fetched
 * body has to equal. A by-tag ref pins neither: there is nothing to compare
 * against, so the desc reports the only algorithm this project produces.
 * Returns 0, or -1 if the ref carries a digest that will not parse. */
static int
regc_ref_alg(const brix_oci_ref_t *ref, brix_oci_alg_t *alg,
             brix_oci_digest_t *want)
{
    *alg = BRIX_OCI_ALG_SHA256;
    if (!ref->has_digest) {
        return 0;
    }
    if (brix_oci_digest_parse(ref->digest, strlen(ref->digest), want) != 0) {
        return -1;
    }
    *alg = want->alg;
    return 0;
}

int
brix_oci_reg_manifest(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                      const char *accept, brix_oci_desc_t *out, char *err,
                      size_t errlen)
{
    brix_http_resp    resp;
    brix_oci_digest_t d, want;
    brix_oci_alg_t    alg;
    char              name[512], path[1024], scope[600], extra[640];
    const char       *reference;
    int               rc;

    memset(out, 0, sizeof(*out));
    if (regc_ref_alg(ref, &alg, &want) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "ref carries an invalid digest \"%s\"",
                         ref->digest);
    }
    if (regc_eff_name(r, ref->name, name, sizeof(name)) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "repository name too long");
    }
    reference = ref->has_digest ? ref->digest : ref->tag;
    if (snprintf(path, sizeof(path), "/v2/%s/manifests/%s", name,
                 reference) >= (int) sizeof(path)) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "manifest path too long");
    }
    snprintf(scope, sizeof(scope), "repository:%s:pull", name);
    snprintf(extra, sizeof(extra), "Accept: %s\r\n",
             accept != NULL ? accept : OCI_ACCEPT_MANIFEST);

    rc = regc_call(r, "GET", path, scope, extra, NULL, 0, &resp, err,
                   errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (resp.status != 200) {
        rc = regc_status_fail_resp(&resp, "manifest GET", err, errlen);
        brix_http_resp_free(&resp);
        return rc;
    }
    if (resp.body == NULL || resp.body_len == 0) {
        brix_http_resp_free(&resp);
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "manifest GET returned an empty body");
    }
    if (!brix_http_header(&resp, "Content-Type", out->mediatype,
                          sizeof(out->mediatype))) {
        /* header absent — fall back to the body's own mediaType field */
        brix_json_get_str(resp.body, resp.body_len, "mediaType",
                          out->mediatype, sizeof(out->mediatype));
    }
    if (brix_oci_digest_hash(alg, resp.body, resp.body_len, &d) != 0
        || brix_oci_digest_format(&d, out->digest,
                                  sizeof(out->digest)) < 0)
    {
        brix_http_resp_free(&resp);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "%s of manifest body failed",
                         brix_oci_alg_name(alg));
    }
    if (ref->has_digest && !brix_oci_digest_eq(&d, &want)) {
        rc = regc_fail(err, errlen, BRIX_OCI_REG_EVERIFY,
                       "manifest digest mismatch: got %s want %s",
                       out->digest, ref->digest);
        brix_http_resp_free(&resp);
        memset(out, 0, sizeof(*out));
        return rc;
    }
    out->body = resp.body;
    out->body_len = resp.body_len;
    resp.body = NULL;    /* ownership moved to the desc */
    brix_http_resp_free(&resp);
    return BRIX_OCI_REG_OK;
}

/* "os/arch[/variant]"; NULL selects this host (linux + normalized uname). */
static int
plat_parse(const char *p, char *os, size_t osn, char *arch, size_t an,
           char *var, size_t vn)
{
    const char *s1, *s2;
    size_t      n;

    var[0] = '\0';
    if (p == NULL) {
        struct utsname u;

        snprintf(os, osn, "linux");
        if (uname(&u) != 0 || strcmp(u.machine, "x86_64") == 0) {
            snprintf(arch, an, "amd64");
        } else if (strcmp(u.machine, "aarch64") == 0) {
            snprintf(arch, an, "arm64");
        } else {
            snprintf(arch, an, "%.32s", u.machine);
        }
        return 0;
    }
    s1 = strchr(p, '/');
    if (s1 == NULL || s1 == p || s1[1] == '\0') {
        return -1;
    }
    n = (size_t) (s1 - p);
    if (n >= osn) {
        return -1;
    }
    memcpy(os, p, n);
    os[n] = '\0';
    s2 = strchr(s1 + 1, '/');
    n = s2 != NULL ? (size_t) (s2 - s1 - 1) : strlen(s1 + 1);
    if (n == 0 || n >= an) {
        return -1;
    }
    memcpy(arch, s1 + 1, n);
    arch[n] = '\0';
    if (s2 != NULL) {
        if (s2[1] == '\0' || strlen(s2 + 1) >= vn) {
            return -1;
        }
        memcpy(var, s2 + 1, strlen(s2 + 1) + 1);
    }
    return 0;
}

/* Walk manifests[] for the platform; on a miss, *avail collects what the
 * index offers so the error can list it. 0 found / -1 not. */
static int
index_pick(const char *body, size_t len, const char *os, const char *arch,
           const char *var, char *digest, size_t dlen, char *avail,
           size_t availlen)
{
    const char *arr, *el;
    size_t      alen, elen, cur = 0, used = 0;

    avail[0] = '\0';
    if (brix_json_get_raw(body, len, "manifests", &arr, &alen) != 1) {
        return -1;
    }
    while (brix_json_arr_next(arr, alen, &cur, &el, &elen) == 1) {
        char        eos[64] = "", earch[64] = "", evar[64] = "";
        char        edig[BRIX_OCI_DIGEST_STRLEN] = "";
        const char *pl;
        size_t      pln;

        if (brix_json_get_raw(el, elen, "platform", &pl, &pln) == 1) {
            brix_json_get_str(pl, pln, "os", eos, sizeof(eos));
            brix_json_get_str(pl, pln, "architecture", earch,
                              sizeof(earch));
            brix_json_get_str(pl, pln, "variant", evar, sizeof(evar));
        }
        if (!brix_json_get_str(el, elen, "digest", edig, sizeof(edig)) ||
            eos[0] == '\0' || strcmp(eos, "unknown") == 0) {
            continue;    /* attestation / malformed entry */
        }
        if (used + strlen(eos) + strlen(earch) + strlen(evar) + 4 <
            availlen) {
            used += (size_t) snprintf(avail + used, availlen - used,
                                      " %s/%s%s%s", eos, earch,
                                      evar[0] != '\0' ? "/" : "", evar);
        }
        if (strcmp(eos, os) != 0 || strcmp(earch, arch) != 0) {
            continue;
        }
        if (var[0] != '\0' && strcmp(evar, var) != 0) {
            continue;
        }
        if (snprintf(digest, dlen, "%s", edig) >= (int) dlen) {
            continue;
        }
        return 0;
    }
    return -1;
}

int
brix_oci_reg_resolve(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                     const char *platform, brix_oci_desc_t *out, char *err,
                     size_t errlen)
{
    brix_oci_ref_t    sub;
    brix_oci_digest_t d;
    char              os[64], arch[64], var[64], avail[512];
    char              dig[BRIX_OCI_DIGEST_STRLEN];
    int               rc;

    rc = brix_oci_reg_manifest(r, ref, NULL, out, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (!mt_is_index(out->mediatype)) {
        return BRIX_OCI_REG_OK;
    }
    if (plat_parse(platform, os, sizeof(os), arch, sizeof(arch), var,
                   sizeof(var)) != 0) {
        brix_oci_desc_free(out);
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "bad platform \"%s\" (want os/arch[/variant])",
                         platform);
    }
    if (index_pick(out->body, out->body_len, os, arch, var, dig,
                   sizeof(dig), avail, sizeof(avail)) != 0) {
        rc = regc_fail(err, errlen, BRIX_OCI_REG_ENOTFOUND,
                       "no manifest for platform %s/%s%s%s; available:%s",
                       os, arch, var[0] != '\0' ? "/" : "", var,
                       avail[0] != '\0' ? avail : " (none)");
        brix_oci_desc_free(out);
        return rc;
    }
    if (brix_oci_digest_parse(dig, strlen(dig), &d) != 0) {
        brix_oci_desc_free(out);
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "index carries invalid digest \"%s\"", dig);
    }
    brix_oci_desc_free(out);
    sub = *ref;
    if (brix_oci_digest_format(&d, sub.digest, sizeof(sub.digest)) < 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "index digest too long");
    }
    sub.has_digest = 1;
    rc = brix_oci_reg_manifest(r, &sub, NULL, out, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (mt_is_index(out->mediatype)) {
        brix_oci_desc_free(out);
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "index points at another index — refusing");
    }
    return BRIX_OCI_REG_OK;
}

int
regc_buf_append(char **buf, size_t *len, size_t *cap, const char *s,
                size_t n)
{
    if (*len + n + 1 > *cap) {
        size_t ncap = *cap == 0 ? 512 : *cap * 2;
        char  *nb;

        while (ncap < *len + n + 1) {
            ncap *= 2;
        }
        nb = realloc(*buf, ncap);
        if (nb == NULL) {
            return -1;
        }
        *buf = nb;
        *cap = ncap;
    }
    memcpy(*buf + *len, s, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

/* Link: </v2/…?last=x&n=2>; rel="next" → the bracketed target. */
static int
link_next(const char *link, char *out, size_t outlen)
{
    const char *lt = strchr(link, '<');
    const char *gt = lt != NULL ? strchr(lt, '>') : NULL;
    size_t      n;

    if (gt == NULL || strstr(gt, "rel=\"next\"") == NULL) {
        return 0;
    }
    n = (size_t) (gt - lt - 1);
    if (n == 0 || n >= outlen) {
        return 0;
    }
    memcpy(out, lt + 1, n);
    out[n] = '\0';
    return 1;
}

/* Append the string members of one tags/list response to the CLI buffer. */
static int
tags_append_page(const brix_http_resp *resp, char **acc, size_t *alen,
                 size_t *acap, char *err, size_t errlen)
{
    const char *arr, *el;
    size_t      an, en, cur = 0;

    if (resp->body == NULL ||
        brix_json_get_raw(resp->body, resp->body_len, "tags", &arr, &an) != 1) {
        return BRIX_OCI_REG_OK;
    }
    while (brix_json_arr_next(arr, an, &cur, &el, &en) == 1) {
        if (en >= 2 && el[0] == '"' && el[en - 1] == '"' &&
            (regc_buf_append(acc, alen, acap, el + 1, en - 2) != 0 ||
             regc_buf_append(acc, alen, acap, "\n", 1) != 0)) {
            return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                             "out of memory");
        }
    }
    return BRIX_OCI_REG_OK;
}

/* Read and validate the next-page target before retaining only its path. */
static int
tags_next_path(const brix_oci_reg_t *r, const brix_http_resp *resp,
               char *path, size_t pathlen, int *have_next, char *err,
               size_t errlen)
{
    char link[1024], next[1024], host[256], next_path[2048];
    int  port, tls;

    *have_next = brix_http_header(resp, "Link", link, sizeof(link)) &&
                 link_next(link, next, sizeof(next));
    if (!*have_next) {
        return BRIX_OCI_REG_OK;
    }
    if (regc_url_split(next, r->host, r->port, !r->plain_http, host,
                       sizeof(host), &port, &tls, next_path,
                       sizeof(next_path)) != 0 ||
        strcmp(host, r->host) != 0 || port != r->port) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "refusing cross-host tags pagination");
    }
    snprintf(path, pathlen, "%s", next_path);
    return BRIX_OCI_REG_OK;
}

int
brix_oci_reg_tags(brix_oci_reg_t *r, const char *name, char **out,
                  char *err, size_t errlen)
{
    char   ename[512], path[2048], scope[600];
    char  *acc = NULL;
    size_t alen = 0, acap = 0;
    int    page, rc;

    *out = NULL;
    if (regc_eff_name(r, name, ename, sizeof(ename)) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "repository name too long");
    }
    snprintf(path, sizeof(path), "/v2/%s/tags/list", ename);
    snprintf(scope, sizeof(scope), "repository:%s:pull", ename);

    for (page = 0; page < 64; page++) {
        brix_http_resp resp;
        int            have_next;

        rc = regc_call(r, "GET", path, scope, NULL, NULL, 0, &resp, err,
                       errlen);
        if (rc != BRIX_OCI_REG_OK) {
            free(acc);
            return rc;
        }
        if (resp.status != 200) {
            rc = regc_status_fail_resp(&resp, "tags list", err, errlen);
            brix_http_resp_free(&resp);
            free(acc);
            return rc;
        }
        rc = tags_append_page(&resp, &acc, &alen, &acap, err, errlen);
        if (rc == BRIX_OCI_REG_OK) {
            rc = tags_next_path(r, &resp, path, sizeof(path), &have_next,
                                err, errlen);
        }
        brix_http_resp_free(&resp);
        if (rc != BRIX_OCI_REG_OK) {
            free(acc);
            return rc;
        }
        if (!have_next) break;
    }
    if (acc == NULL) {
        acc = calloc(1, 1);
        if (acc == NULL) {
            return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                             "out of memory");
        }
    }
    *out = acc;
    return BRIX_OCI_REG_OK;
}

int
brix_oci_reg_manifest_put(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                          const char *mt, const void *body, size_t len,
                          char *err, size_t errlen)
{
    brix_http_resp resp;
    char           name[512], path[1024], scope[600], extra[256];
    const char    *reference;
    int            rc;

    if (regc_eff_name(r, ref->name, name, sizeof(name)) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "repository name too long");
    }
    reference = ref->has_digest ? ref->digest : ref->tag;
    if (snprintf(path, sizeof(path), "/v2/%s/manifests/%s", name,
                 reference) >= (int) sizeof(path)) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "manifest path too long");
    }
    snprintf(scope, sizeof(scope), "repository:%s:push,pull", name);
    if (snprintf(extra, sizeof(extra), "Content-Type: %s\r\n", mt) >=
        (int) sizeof(extra)) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "media type too long");
    }
    rc = regc_call(r, "PUT", path, scope, extra, body, len, &resp, err,
                   errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (resp.status < 200 || resp.status >= 300) {
        rc = regc_status_fail_resp(&resp, "manifest PUT", err, errlen);
        brix_http_resp_free(&resp);
        return rc;
    }
    brix_http_resp_free(&resp);
    return BRIX_OCI_REG_OK;
}

int
brix_oci_reg_manifest_del(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                          char *err, size_t errlen)
{
    brix_http_resp resp;
    char           name[512], path[1024], scope[600];
    char           dig[BRIX_OCI_DIGEST_STRLEN];
    int            rc;

    if (regc_eff_name(r, ref->name, name, sizeof(name)) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "repository name too long");
    }
    if (ref->has_digest) {
        snprintf(dig, sizeof(dig), "%s", ref->digest);
    } else {
        /* registries delete by digest — resolve the tag first */
        brix_oci_desc_t desc;

        rc = brix_oci_reg_manifest(r, ref, NULL, &desc, err, errlen);
        if (rc != BRIX_OCI_REG_OK) {
            return rc;
        }
        snprintf(dig, sizeof(dig), "%s", desc.digest);
        brix_oci_desc_free(&desc);
    }
    snprintf(path, sizeof(path), "/v2/%s/manifests/%s", name, dig);
    snprintf(scope, sizeof(scope), "repository:%s:push,pull", name);
    rc = regc_call(r, "DELETE", path, scope, NULL, NULL, 0, &resp, err,
                   errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (resp.status != 202 && resp.status != 200 && resp.status != 204) {
        rc = regc_status_fail_resp(&resp, "manifest DELETE", err, errlen);
        brix_http_resp_free(&resp);
        return rc;
    }
    brix_http_resp_free(&resp);
    return BRIX_OCI_REG_OK;
}
