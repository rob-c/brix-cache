/* layout_index.c — index.json half of the OCI image-layout store: bind /
 * look up / list the manifest entries (see layout.h). Raw spans of
 * surviving entries are copied through a rebuild, so fields we do not
 * model are preserved. */
#include "oci/layout_internal.h"

#include "oci/reg_internal.h"
#include "oci/digest.h"
#include "oci/name.h"
#include "core/compat/json_iter.h"
#include "core/compat/json_min.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* JSON-safe check for a media type we are about to embed verbatim. */
static int
lay_mt_safe(const char *mt)
{
    for (; *mt != '\0'; mt++) {
        if (*mt < 0x20 || *mt == '"' || *mt == '\\' ||
            (unsigned char) *mt > 0x7e) {
            return 0;
        }
    }
    return 1;
}

static int
lay_index_load(brix_oci_layout_t *l, char **buf, size_t *blen, char *err,
               size_t errlen)
{
    char p[1200];

    snprintf(p, sizeof(p), "%s/index.json", l->dir);
    if (layx_read_file(p, LAY_INDEX_CAP, buf, blen) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "%s: %s", p, strerror(errno));
    }
    return BRIX_OCI_REG_OK;
}

static int
lay_elem_refname(const char *el, size_t en, char *out, size_t outlen)
{
    const char *an;
    size_t      ann;

    out[0] = '\0';
    if (brix_json_get_raw(el, en, "annotations", &an, &ann) == 1) {
        brix_json_get_str(an, ann, "org.opencontainers.image.ref.name",
                          out, outlen);
    }
    return out[0] != '\0';
}

/* Keep one old manifest unless the binding being written replaces it. */
static int
lay_index_keep_entry(char **acc, size_t *alen, size_t *acap, int *first,
                     const char *el, size_t en, const char *refname,
                     const char *digest)
{
    char eref[160], edig[80] = "";

    lay_elem_refname(el, en, eref, sizeof(eref));
    brix_json_get_str(el, en, "digest", edig, sizeof(edig));
    if ((refname != NULL && strcmp(eref, refname) == 0) ||
        (refname == NULL && eref[0] == '\0' &&
         strcmp(edig, digest) == 0)) {
        return 0;
    }
    if (!*first && regc_buf_append(acc, alen, acap, ",", 1) != 0) {
        return -1;
    }
    if (regc_buf_append(acc, alen, acap, el, en) != 0) {
        return -1;
    }
    *first = 0;
    return 0;
}

/* Copy retained raw entries so unfamiliar fields survive an index rewrite. */
static int
lay_index_keep_old(char **acc, size_t *alen, size_t *acap, int *first,
                   const char *old, size_t olen, const char *refname,
                   const char *digest)
{
    const char *arr, *el;
    size_t      an, en, cur = 0;

    if (brix_json_get_raw(old, olen, "manifests", &arr, &an) != 1) {
        return 0;
    }
    while (brix_json_arr_next(arr, an, &cur, &el, &en) == 1) {
        if (lay_index_keep_entry(acc, alen, acap, first, el, en, refname,
                                 digest) != 0) {
            return -1;
        }
    }
    return 0;
}

/* Format the new manifest and the closing JSON delimiters in one buffer. */
static int
lay_index_new_entry(char *entry, size_t elen, int first, const char *refname,
                    const char *dg, const char *mt, size_t size)
{
    int n;

    n = snprintf(entry, elen,
                 "%s{\"mediaType\":\"%s\",\"digest\":\"%s\","
                 "\"size\":%zu", first ? "" : ",", mt, dg, size);
    if (refname != NULL && n > 0 && (size_t) n < elen) {
        n += snprintf(entry + n, elen - (size_t) n,
                      ",\"annotations\":{\"org.opencontainers.image."
                      "ref.name\":\"%s\"}", refname);
    }
    if (n < 0 || (size_t) n + 3 >= elen) {
        return -1;
    }
    memcpy(entry + n, "}]}\n", 4);
    return n + 4;
}

/* Rebuild index.json text: the surviving old entries (raw spans, unknown
 * fields preserved) + the new binding. 0 with a malloc'd *acc_out / -1
 * (everything freed). */
static int
lay_index_rebuild(const char *old, size_t olen, const char *refname,
                  const char *digest, const char *dg, const char *mt,
                  size_t size, char **acc_out, size_t *alen_out)
{
    static const char head[] = "{\"schemaVersion\":2,\"manifests\":[";
    char       *acc = NULL;
    size_t      alen = 0, acap = 0;
    char        entry[1024];
    int         n, first = 1;

    if (regc_buf_append(&acc, &alen, &acap, head, sizeof(head) - 1) != 0 ||
        lay_index_keep_old(&acc, &alen, &acap, &first, old, olen, refname,
                           digest) != 0) {
        free(acc);
        return -1;
    }
    n = lay_index_new_entry(entry, sizeof(entry), first, refname, dg, mt,
                            size);
    if (n < 0 || regc_buf_append(&acc, &alen, &acap, entry, (size_t) n) != 0) {
        free(acc);
        return -1;
    }
    *acc_out = acc;
    *alen_out = alen;
    return 0;
}

int
brix_oci_layout_index_set(brix_oci_layout_t *l, const char *refname,
                          const char *digest, const char *mt, size_t size,
                          char *err, size_t errlen)
{
    brix_oci_digest_t d;
    char              dg[BRIX_OCI_DIGEST_STRLEN];
    char             *old = NULL, *acc = NULL;
    size_t            olen, alen = 0;
    int               rc;

    /* The entry carries the canonical "<alg>:<hex>" the parser produced,
     * not the caller's spelling and not a hardcoded prefix — the index is
     * what another runtime reads the algorithm back out of. */
    if (brix_oci_digest_parse(digest, strlen(digest), &d) != 0
        || brix_oci_digest_format(&d, dg, sizeof(dg)) < 0)
    {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "invalid digest \"%s\"", digest);
    }
    if (refname != NULL &&
        brix_oci_tag_valid(refname, strlen(refname)) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "invalid ref name \"%s\"", refname);
    }
    if (!lay_mt_safe(mt)) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "unsafe media type");
    }
    rc = lay_index_load(l, &old, &olen, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (lay_index_rebuild(old, olen, refname, digest, dg, mt, size,
                          &acc, &alen) != 0) {
        free(old);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "index rebuild failed");
    }
    free(old);
    rc = layx_write_atomic(l->dir, "index.json", acc, alen, err, errlen);
    free(acc);
    return rc;
}

int
brix_oci_layout_index_get(brix_oci_layout_t *l, const char *refname,
                          char *digest, size_t dlen, char *mt,
                          size_t mtlen, char *err, size_t errlen)
{
    char       *buf;
    size_t      blen;
    const char *arr, *el;
    size_t      an, en, cur = 0;
    int         rc;

    rc = lay_index_load(l, &buf, &blen, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (brix_json_get_raw(buf, blen, "manifests", &arr, &an) == 1) {
        while (brix_json_arr_next(arr, an, &cur, &el, &en) == 1) {
            char eref[160];

            lay_elem_refname(el, en, eref, sizeof(eref));
            if (refname != NULL && strcmp(eref, refname) != 0) {
                continue;
            }
            if (!brix_json_get_str(el, en, "digest", digest, dlen)) {
                continue;
            }
            mt[0] = '\0';
            brix_json_get_str(el, en, "mediaType", mt, mtlen);
            free(buf);
            return BRIX_OCI_REG_OK;
        }
    }
    free(buf);
    return regc_fail(err, errlen, BRIX_OCI_REG_ENOTFOUND,
                     refname != NULL ? "no entry \"%s\" in the layout index"
                                     : "layout index is empty",
                     refname);
}

int
brix_oci_layout_ls(brix_oci_layout_t *l, char **out, char *err,
                   size_t errlen)
{
    char       *buf, *acc = NULL;
    size_t      blen, alen = 0, acap = 0;
    const char *arr, *el;
    size_t      an, en, cur = 0;
    int         rc;

    *out = NULL;
    rc = lay_index_load(l, &buf, &blen, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (brix_json_get_raw(buf, blen, "manifests", &arr, &an) == 1) {
        while (brix_json_arr_next(arr, an, &cur, &el, &en) == 1) {
            char eref[160], edig[80] = "", emt[128] = "", line[420];
            int  n;

            if (!lay_elem_refname(el, en, eref, sizeof(eref))) {
                snprintf(eref, sizeof(eref), "-");
            }
            brix_json_get_str(el, en, "digest", edig, sizeof(edig));
            brix_json_get_str(el, en, "mediaType", emt, sizeof(emt));
            n = snprintf(line, sizeof(line), "%s %s %s\n", eref, edig,
                         emt);
            if (n < 0 || (size_t) n >= sizeof(line) ||
                regc_buf_append(&acc, &alen, &acap, line,
                                (size_t) n) != 0) {
                free(buf);
                free(acc);
                return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                                 "listing build failed");
            }
        }
    }
    free(buf);
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
