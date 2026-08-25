/* brixoci_copy.c — the one pump behind pull/push/copy (phase-104 D5.4):
 * source manifest → every referenced blob → manifest binding, over the
 * four endpoint combinations (registry/layout × registry/layout). Blob
 * integrity is owned by the libs (reg fetch hash-on-stream, layout
 * read-verify); this file only orders the moves and dedupes. */
#include "brixoci_internal.h"

#include "oci/mediatypes.h"
#include "core/compat/json_iter.h"
#include "core/compat/json_min.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OCI_COPY_MANIFEST_CAP (8u << 20)
#define OCI_COPY_IOBUF        (256 * 1024)

int
brixoci_is_index(const brix_oci_desc_t *m)
{
    const char *ign;
    size_t      ignlen;

    return strncmp(m->mediatype, OCI_MT_INDEX, strlen(OCI_MT_INDEX)) == 0 ||
           strncmp(m->mediatype, D2_MT_LIST, strlen(D2_MT_LIST)) == 0 ||
           (m->body != NULL &&
            brix_json_get_raw(m->body, m->body_len, "manifests", &ign,
                              &ignlen) == 1);
}

/* Source manifest into *m. Registry: platform-resolved fetch. Layout:
 * index lookup by seltag (single-image layouts fall back to the first
 * entry) + verified blob load. */
int
brixoci_src_manifest(brixoci_end_t *s, const char *seltag,
                  const brixoci_opts_t *o, brix_oci_desc_t *m, char *err,
                  size_t errlen)
{
    char  *body;
    size_t blen;
    int    rc;

    memset(m, 0, sizeof(*m));
    if (!s->is_layout) {
        return brix_oci_reg_resolve(&s->reg, &s->ref, o->platform, m, err,
                                    errlen);
    }
    rc = brix_oci_layout_index_get(&s->lay, seltag, m->digest,
                                   sizeof(m->digest), m->mediatype,
                                   sizeof(m->mediatype), err, errlen);
    if (rc == BRIX_OCI_REG_ENOTFOUND && seltag != NULL) {
        rc = brix_oci_layout_index_get(&s->lay, NULL, m->digest,
                                       sizeof(m->digest), m->mediatype,
                                       sizeof(m->mediatype), err, errlen);
    }
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    rc = brix_oci_layout_blob_load(&s->lay, m->digest,
                                   OCI_COPY_MANIFEST_CAP, &body, &blen,
                                   err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    m->body = body;
    m->body_len = blen;
    if (m->mediatype[0] == '\0' &&
        !brix_json_get_str(body, blen, "mediaType", m->mediatype,
                           sizeof(m->mediatype))) {
        snprintf(m->mediatype, sizeof(m->mediatype), "%s", OCI_MT_MANIFEST);
    }
    return BRIX_OCI_REG_OK;
}

/* Sequential fd → fd copy. 0 / -1 with errno-flavored err. */
int
brixoci_fd_pump(int in_fd, int out_fd, char *err, size_t errlen)
{
    char   *buf = malloc(OCI_COPY_IOBUF);
    ssize_t n;
    int     ok = buf != NULL;

    while (ok && (n = read(in_fd, buf, OCI_COPY_IOBUF)) != 0) {
        ssize_t off = 0;

        if (n < 0) {
            ok = errno == EINTR;
            continue;
        }
        while (ok && off < n) {
            ssize_t w = write(out_fd, buf + off, (size_t) (n - off));

            if (w < 0) {
                ok = errno == EINTR;
            } else {
                off += w;
            }
        }
    }
    if (!ok) {
        snprintf(err, errlen, "blob copy: %s",
                 buf == NULL ? "out of memory" : strerror(errno));
    }
    free(buf);
    return ok ? 0 : -1;
}

/* Land one blob in a layout: registry fetch (hash-on-stream) or local
 * layout-to-layout copy, staged + committed. */
static int
copy_blob_to_layout(brixoci_end_t *s, brixoci_end_t *d, const char *digest,
                    char *err, size_t errlen)
{
    char      tmppath[1200];
    long long sz;
    int       out_fd, in_fd = -1, rc;

    if (s->is_layout) {
        rc = brix_oci_layout_blob_verify(&s->lay, digest, &sz, err, errlen);
        if (rc != BRIX_OCI_REG_OK) {
            return rc;
        }
        in_fd = brix_oci_layout_blob_open(&s->lay, digest, err, errlen);
        if (in_fd < 0) {
            return in_fd;
        }
    }
    out_fd = brix_oci_layout_stage(&d->lay, tmppath, sizeof(tmppath), err,
                                   errlen);
    if (out_fd < 0) {
        if (in_fd >= 0) {
            close(in_fd);
        }
        return out_fd;
    }
    if (s->is_layout) {
        rc = brixoci_fd_pump(in_fd, out_fd, err, errlen) == 0
                 ? BRIX_OCI_REG_OK
                 : BRIX_OCI_REG_ETRANSPORT;
        close(in_fd);
    } else {
        rc = brix_oci_reg_blob_fetch(&s->reg, s->name, digest, out_fd, err,
                                     errlen);
    }
    close(out_fd);
    if (rc == BRIX_OCI_REG_OK) {
        rc = brix_oci_layout_commit(&d->lay, tmppath, digest, err, errlen);
    }
    if (rc != BRIX_OCI_REG_OK) {
        unlink(tmppath);
    }
    return rc;
}

/* Land one blob in a registry: layout push (verified first) or a
 * registry-to-registry pump through an anonymous verified temp. */
static int
copy_blob_to_reg(brixoci_end_t *s, brixoci_end_t *d, const char *digest,
                 char *err, size_t errlen)
{
    long long   sz;
    struct stat st;
    FILE       *tf;
    int         fd, rc;

    if (s->is_layout) {
        rc = brix_oci_layout_blob_verify(&s->lay, digest, &sz, err, errlen);
        if (rc != BRIX_OCI_REG_OK) {
            return rc;
        }
        fd = brix_oci_layout_blob_open(&s->lay, digest, err, errlen);
        if (fd < 0) {
            return fd;
        }
        rc = brix_oci_reg_blob_push(&d->reg, d->name, digest, fd,
                                    (size_t) sz, err, errlen);
        close(fd);
        return rc;
    }
    tf = tmpfile();
    if (tf == NULL) {
        snprintf(err, errlen, "tmpfile: %s", strerror(errno));
        return BRIX_OCI_REG_ETRANSPORT;
    }
    fd = fileno(tf);
    rc = brix_oci_reg_blob_fetch(&s->reg, s->name, digest, fd, err, errlen);
    if (rc == BRIX_OCI_REG_OK) {
        rc = fstat(fd, &st) == 0
                 ? brix_oci_reg_blob_push(&d->reg, d->name, digest, fd,
                                          (size_t) st.st_size, err, errlen)
                 : BRIX_OCI_REG_ETRANSPORT;
    }
    fclose(tf);
    return rc;
}

static int
copy_one_blob(brixoci_end_t *s, brixoci_end_t *d, const char *digest,
              char *err, size_t errlen)
{
    if (d->is_layout) {
        char      scratch[128];
        long long sz;

        /* Dedupe: an existing blob that VERIFIES is done; a corrupt one
         * is treated as absent and re-landed (commit renames over it). */
        if (brix_oci_layout_blob_verify(&d->lay, digest, &sz, scratch,
                                        sizeof(scratch)) ==
            BRIX_OCI_REG_OK) {
            return BRIX_OCI_REG_OK;
        }
        return copy_blob_to_layout(s, d, digest, err, errlen);
    }
    /* Registry dedupe lives in the push itself (HEAD probe). */
    return copy_blob_to_reg(s, d, digest, err, errlen);
}

/* Read the "digest" string out of the JSON object [el,en) and land that blob;
 * `what` names the object in the error message ("config"/"layer"). Returns
 * BRIX_OCI_REG_OK, BRIX_OCI_REG_EPROTO (no digest present), or copy_one_blob's
 * transfer error. */
static int
copy_digest_blob(brixoci_end_t *s, brixoci_end_t *d, const char *el, size_t en,
                 const char *what, char *err, size_t errlen)
{
    char dig[BRIX_OCI_DIGEST_STRLEN];

    if (!brix_json_get_str(el, en, "digest", dig, sizeof(dig))) {
        snprintf(err, errlen, "manifest %s has no digest", what);
        return BRIX_OCI_REG_EPROTO;
    }
    return copy_one_blob(s, d, dig, err, errlen);
}

/* Walk config.digest + layers[].digest and land each blob. */
static int
copy_blobs(brixoci_end_t *s, brixoci_end_t *d, const char *body,
           size_t blen, char *err, size_t errlen)
{
    const char *arr, *el;
    size_t      an, en, cur = 0;
    int         rc;

    if (brix_json_get_raw(body, blen, "config", &el, &en) == 1) {
        rc = copy_digest_blob(s, d, el, en, "config", err, errlen);
        if (rc != BRIX_OCI_REG_OK) {
            return rc;
        }
    }
    if (brix_json_get_raw(body, blen, "layers", &arr, &an) != 1) {
        return BRIX_OCI_REG_OK;                 /* config-only artifact */
    }
    while (brix_json_arr_next(arr, an, &cur, &el, &en) == 1) {
        rc = copy_digest_blob(s, d, el, en, "layer", err, errlen);
        if (rc != BRIX_OCI_REG_OK) {
            return rc;
        }
    }
    return BRIX_OCI_REG_OK;
}

/* Bind the manifest at the destination; digest_out gets the canonical
 * "<alg>:<hex>" that was bound/pushed. */
int
brixoci_put_manifest(brixoci_end_t *d, const char *bindtag,
                  const brix_oci_desc_t *m, char *digest_out, size_t dlen,
                  char *err, size_t errlen)
{
    char dig[BRIX_OCI_DIGEST_STRLEN];
    int  rc;

    if (!d->is_layout) {
        rc = brix_oci_reg_manifest_put(&d->reg, &d->ref, m->mediatype,
                                       m->body, m->body_len, err, errlen);
        snprintf(dig, sizeof(dig), "%s", m->digest);
    } else {
        rc = brix_oci_layout_blob_put_mem(&d->lay, m->body, m->body_len,
                                          dig, sizeof(dig), err, errlen);
        if (rc == BRIX_OCI_REG_OK && m->digest[0] != '\0' &&
            strcmp(dig, m->digest) != 0) {
            snprintf(err, errlen, "manifest bytes hash to %s, expected %s",
                     dig, m->digest);
            rc = BRIX_OCI_REG_EVERIFY;
        }
        if (rc == BRIX_OCI_REG_OK) {
            rc = brix_oci_layout_index_set(&d->lay, bindtag, dig,
                                           m->mediatype, m->body_len, err,
                                           errlen);
        }
    }
    if (rc == BRIX_OCI_REG_OK && digest_out != NULL) {
        snprintf(digest_out, dlen, "%s", dig);
    }
    return rc;
}

void
brixoci_xfer_tags(const brixoci_end_t *src, const brixoci_end_t *dst,
                  const char **seltag, const char **bindtag)
{
    /* Layout-source lookup tag: the registry side of the transfer names
     * it; layout→layout falls back to the first entry, bound untagged. */
    *seltag = *bindtag = NULL;
    if (!dst->is_layout) {
        *seltag = dst->ref.tag;
    } else if (!src->is_layout) {
        *seltag = src->ref.tag;
        *bindtag = src->ref.tag;
    }
}

int
brixoci_copy_run(brixoci_end_t *src, brixoci_end_t *dst,
                 const brixoci_opts_t *o, char *digest_out, size_t dlen,
                 char *err, size_t errlen)
{
    brix_oci_desc_t m;
    const char     *seltag = NULL, *bindtag = NULL;
    int             rc;

    brixoci_xfer_tags(src, dst, &seltag, &bindtag);
    rc = brixoci_src_manifest(src, seltag, o, &m, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (brixoci_is_index(&m)) {
        brix_oci_desc_free(&m);
        snprintf(err, errlen, "source manifest is an image index — pull "
                 "it with --platform to select one image");
        return BRIX_OCI_REG_EPROTO;
    }
    rc = copy_blobs(src, dst, m.body, m.body_len, err, errlen);
    if (rc == BRIX_OCI_REG_OK) {
        rc = brixoci_put_manifest(dst, bindtag, &m, digest_out, dlen, err,
                               errlen);
    }
    brix_oci_desc_free(&m);
    return rc;
}
