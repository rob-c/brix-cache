/* brixoci_convert.c — `brixoci convert --estargz` (phase-104 D15.8): every
 * layer of one image re-encoded into eStargz, with the config's
 * rootfs.diff_ids and the manifest descriptors rebuilt around the new
 * blobs. The reframe is the writer's job (shared/oci/stargz.c); this file
 * moves the bytes and keeps the three documents honest about them —
 * reusing the copy pump's endpoint seams so both verbs resolve, refuse and
 * bind identically. */
#include "brixoci_internal.h"

#include "oci/digest.h"
#include "oci/mediatypes.h"
#include "oci/stargz.h"
#include "core/compat/json_iter.h"
#include "core/compat/json_min.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CONV_BLOB_CAP   (8u << 20)   /* config blobs are ~1 KiB; cap is slack */
#define CONV_DOC_CAP    (8u << 20)   /* rewritten config / manifest scratch */
#define CONV_MAX_LAYERS 512          /* far past any real image's layer count */

/* What one converted layer contributes to the two rewritten documents. */
typedef struct {
    char      digest[BRIX_OCI_DIGEST_STRLEN];
    char      diffid[BRIX_OCI_DIGEST_STRLEN];
    char      toc[BRIX_OCI_DIGEST_STRLEN];
    char      mediatype[128];
    long long size;
} conv_layer_t;

typedef struct {
    conv_layer_t *lay;
    int           n;
    char         *doc;          /* JSON under construction */
    size_t        len;
    int           over;         /* doc outgrew CONV_DOC_CAP */
} conv_t;

/* ---- JSON scratch -------------------------------------------------------- */

static void
conv_emit(conv_t *c, const char *fmt, ...)
{
    va_list ap;
    int     n;

    if (c->over) {
        return;
    }
    va_start(ap, fmt);
    n = vsnprintf(c->doc + c->len, CONV_DOC_CAP - c->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t) n >= CONV_DOC_CAP - c->len) {
        c->over = 1;
        return;
    }
    c->len += (size_t) n;
}

static void
conv_emit_raw(conv_t *c, const char *p, size_t n)
{
    if (c->over) {
        return;
    }
    if (n >= CONV_DOC_CAP - c->len) {
        c->over = 1;
        return;
    }
    memcpy(c->doc + c->len, p, n);
    c->len += n;
    c->doc[c->len] = '\0';
}

/* ---- blob movement ------------------------------------------------------- */

/* An unlinked scratch file: the converted layer has to be pread-able for
 * the registry push, and must not survive a crash. */
static int
conv_tmpfd(char *err, size_t errlen)
{
    const char *dir = getenv("TMPDIR");
    char        path[1100];
    int         fd;

    snprintf(path, sizeof(path), "%s/brixoci-convert-XXXXXX",
             dir != NULL && dir[0] != '\0' ? dir : "/tmp");
    fd = mkstemp(path);
    if (fd < 0) {
        snprintf(err, errlen, "scratch file: %s", strerror(errno));
        return BRIX_OCI_REG_ETRANSPORT;
    }
    unlink(path);
    return fd;
}

/* The source layer as a readable fd positioned at byte 0. Layout blobs are
 * verified against their path digest first; registry blobs are hashed on
 * the way in by the fetch itself. */
static int
conv_src_fd(brixoci_end_t *s, const char *digest, char *err, size_t errlen)
{
    long long sz;
    int       fd, rc;

    if (s->is_layout) {
        rc = brix_oci_layout_blob_verify(&s->lay, digest, &sz, err, errlen);
        return rc != BRIX_OCI_REG_OK
                   ? rc
                   : brix_oci_layout_blob_open(&s->lay, digest, err, errlen);
    }
    fd = conv_tmpfd(err, errlen);
    if (fd < 0) {
        return fd;
    }
    rc = brix_oci_reg_blob_fetch(&s->reg, s->name, digest, fd, err, errlen);
    if (rc != BRIX_OCI_REG_OK || lseek(fd, 0, SEEK_SET) != 0) {
        close(fd);
        return rc != BRIX_OCI_REG_OK ? rc : BRIX_OCI_REG_ETRANSPORT;
    }
    return fd;
}

/* Land [fd, size) at the destination under `digest`. The caller vouches
 * for the digest — it came from the writer that produced the bytes. */
static int
conv_put_fd(brixoci_end_t *d, const char *digest, int fd, long long size,
            char *err, size_t errlen)
{
    char tmppath[1200];
    int  out_fd, rc;

    if (lseek(fd, 0, SEEK_SET) != 0) {
        snprintf(err, errlen, "converted layer: %s", strerror(errno));
        return BRIX_OCI_REG_ETRANSPORT;
    }
    if (!d->is_layout) {
        return brix_oci_reg_blob_push(&d->reg, d->name, digest, fd,
                                      (size_t) size, err, errlen);
    }
    out_fd = brix_oci_layout_stage(&d->lay, tmppath, sizeof(tmppath), err,
                                   errlen);
    if (out_fd < 0) {
        return out_fd;
    }
    rc = brixoci_fd_pump(fd, out_fd, err, errlen) == 0
             ? BRIX_OCI_REG_OK
             : BRIX_OCI_REG_ETRANSPORT;
    close(out_fd);
    if (rc == BRIX_OCI_REG_OK) {
        rc = brix_oci_layout_commit(&d->lay, tmppath, digest, err, errlen);
    }
    if (rc != BRIX_OCI_REG_OK) {
        unlink(tmppath);
    }
    return rc;
}

/* Land an in-memory document (the rewritten config) at the destination,
 * reporting the digest it hashed to. */
static int
conv_put_mem(brixoci_end_t *d, const void *body, size_t len, char *dig,
             size_t diglen, char *err, size_t errlen)
{
    brix_oci_digest_t h;
    ssize_t           w;
    int               fd, rc;

    if (d->is_layout) {
        return brix_oci_layout_blob_put_mem(&d->lay, body, len, dig, diglen,
                                            err, errlen);
    }
    if (brix_oci_sha256(body, len, &h) != 0 ||
        brix_oci_digest_format(&h, dig, diglen) < 0) {
        snprintf(err, errlen, "sha256 of rewritten document failed");
        return BRIX_OCI_REG_EPROTO;
    }
    fd = conv_tmpfd(err, errlen);
    if (fd < 0) {
        return fd;
    }
    w = write(fd, body, len);
    rc = (w < 0 || (size_t) w != len)
             ? BRIX_OCI_REG_ETRANSPORT
             : brix_oci_reg_blob_push(&d->reg, d->name, dig, fd, len, err,
                                      errlen);
    if (rc == BRIX_OCI_REG_ETRANSPORT && w != (ssize_t) len) {
        snprintf(err, errlen, "rewritten document: %s", strerror(errno));
    }
    close(fd);
    return rc;
}

/* The source config blob, whole, into a malloc'd buffer. */
static int
conv_load(brixoci_end_t *s, const char *digest, char **out, size_t *outlen,
          char *err, size_t errlen)
{
    char   *buf;
    off_t   end;
    ssize_t got;
    int     fd;

    if (s->is_layout) {
        return brix_oci_layout_blob_load(&s->lay, digest, CONV_BLOB_CAP, out,
                                         outlen, err, errlen);
    }
    fd = conv_src_fd(s, digest, err, errlen);
    if (fd < 0) {
        return fd;
    }
    end = lseek(fd, 0, SEEK_END);
    if (end < 0 || (size_t) end > CONV_BLOB_CAP) {
        snprintf(err, errlen, "config blob %s is %lld bytes", digest,
                 (long long) end);
        close(fd);
        return BRIX_OCI_REG_EPROTO;
    }
    buf = malloc((size_t) end + 1);
    got = buf == NULL ? -1 : pread(fd, buf, (size_t) end, 0); /* vfs-seam-allow: OCI layout blob or anonymous registry staging fd, never an export VFS object */
    close(fd);
    if (got < 0 || (size_t) got != (size_t) end) {
        free(buf);
        snprintf(err, errlen, "config blob %s: short read", digest);
        return BRIX_OCI_REG_ETRANSPORT;
    }
    buf[end] = '\0';
    *out = buf;
    *outlen = (size_t) end;
    return BRIX_OCI_REG_OK;
}

/* ---- the layers ---------------------------------------------------------- */

/* The converted layer is always gzip-framed, whatever the source was, so
 * the descriptor must say so — in the source manifest's own dialect. */
static const char *
conv_layer_mt(const char *src_mt)
{
    return strstr(src_mt, "docker") != NULL ? D2_MT_LAYER_GZ : OCI_MT_LAYER_GZ;
}

static int
conv_one_layer(brixoci_end_t *s, brixoci_end_t *d, const char *digest,
               conv_layer_t *out, char *err, size_t errlen)
{
    brix_stargz_stats_t st;
    int                 in_fd, out_fd, rc;

    in_fd = conv_src_fd(s, digest, err, errlen);
    if (in_fd < 0) {
        return in_fd;
    }
    out_fd = conv_tmpfd(err, errlen);
    if (out_fd < 0) {
        close(in_fd);
        return out_fd;
    }
    rc = brix_stargz_convert(in_fd, out_fd, &st, err, errlen) == 0
             ? BRIX_OCI_REG_OK
             : BRIX_OCI_REG_EPROTO;
    close(in_fd);
    if (rc == BRIX_OCI_REG_OK) {
        snprintf(out->digest, sizeof(out->digest), "%s", st.blob_digest);
        snprintf(out->diffid, sizeof(out->diffid), "%s", st.diffid);
        snprintf(out->toc, sizeof(out->toc), "%s", st.toc_digest);
        out->size = st.blob_size;
        rc = conv_put_fd(d, out->digest, out_fd, st.blob_size, err, errlen);
    }
    close(out_fd);
    return rc;
}

/* One manifest layer element → one converted layer. Foreign layers are
 * refused: their bytes live on a URL the registry does not hold, so there
 * is nothing here to reframe. */
static int
conv_layer_el(brixoci_end_t *s, brixoci_end_t *d, const char *el, size_t en,
              conv_layer_t *out, char *err, size_t errlen)
{
    char dig[BRIX_OCI_DIGEST_STRLEN], mt[128];

    if (!brix_json_get_str(el, en, "digest", dig, sizeof(dig))) {
        snprintf(err, errlen, "manifest layer has no digest");
        return BRIX_OCI_REG_EPROTO;
    }
    if (!brix_json_get_str(el, en, "mediaType", mt, sizeof(mt))) {
        snprintf(mt, sizeof(mt), "%s", OCI_MT_LAYER_GZ);
    }
    if (strstr(mt, "foreign") != NULL) {
        snprintf(err, errlen, "layer %s is a foreign layer (%s) — its bytes "
                 "are not in this registry", dig, mt);
        return BRIX_OCI_REG_EPROTO;
    }
    snprintf(out->mediatype, sizeof(out->mediatype), "%s", conv_layer_mt(mt));
    return conv_one_layer(s, d, dig, out, err, errlen);
}

static int
conv_layers(brixoci_end_t *s, brixoci_end_t *d, const brix_oci_desc_t *m,
            conv_t *c, char *err, size_t errlen)
{
    const char *arr, *el;
    size_t      an, en, cur = 0;
    int         rc;

    if (brix_json_get_raw(m->body, m->body_len, "layers", &arr, &an) != 1) {
        snprintf(err, errlen, "source manifest has no layers to convert");
        return BRIX_OCI_REG_EPROTO;
    }
    while (brix_json_arr_next(arr, an, &cur, &el, &en) == 1) {
        if (c->n >= CONV_MAX_LAYERS) {
            snprintf(err, errlen, "source manifest has more than %d layers",
                     CONV_MAX_LAYERS);
            return BRIX_OCI_REG_EPROTO;
        }
        rc = conv_layer_el(s, d, el, en, &c->lay[c->n], err, errlen);
        if (rc != BRIX_OCI_REG_OK) {
            return rc;
        }
        c->n++;
    }
    if (c->n == 0) {
        snprintf(err, errlen, "source manifest has no layers to convert");
        return BRIX_OCI_REG_EPROTO;
    }
    return BRIX_OCI_REG_OK;
}

/* ---- the config ---------------------------------------------------------- */

static int
conv_count_diffids(const char *rootfs, size_t rn)
{
    const char *arr, *el;
    size_t      an, en, cur = 0;
    int         n = 0;

    if (brix_json_get_raw(rootfs, rn, "diff_ids", &arr, &an) != 1) {
        return -1;
    }
    while (brix_json_arr_next(arr, an, &cur, &el, &en) == 1) {
        n++;
    }
    return n;
}

/* The rewritten config: the source document with its rootfs object
 * replaced. rootfs carries exactly two spec fields, so rebuilding it and
 * splicing it over the original's raw span leaves every other field —
 * history, env, entrypoint — byte-identical. */
static int
conv_rewrite_config(conv_t *c, const char *body, size_t blen, char *err,
                    size_t errlen)
{
    const char *rootfs;
    size_t      rn, head;
    char        type[64];
    int         i, count;

    if (brix_json_get_raw(body, blen, "rootfs", &rootfs, &rn) != 1) {
        snprintf(err, errlen, "image config has no rootfs");
        return BRIX_OCI_REG_EPROTO;
    }
    count = conv_count_diffids(rootfs, rn);
    if (count != c->n) {
        snprintf(err, errlen, "image config lists %d diff_ids for %d layers",
                 count, c->n);
        return BRIX_OCI_REG_EPROTO;
    }
    if (!brix_json_get_str(rootfs, rn, "type", type, sizeof(type))) {
        snprintf(type, sizeof(type), "layers");
    }
    head = (size_t) (rootfs - body);
    c->len = 0;
    c->over = 0;
    c->doc[0] = '\0';
    conv_emit_raw(c, body, head);
    conv_emit(c, "{\"type\":\"%s\",\"diff_ids\":[", type);
    for (i = 0; i < c->n; i++) {
        conv_emit(c, "%s\"%s\"", i ? "," : "", c->lay[i].diffid);
    }
    conv_emit(c, "]}");
    conv_emit_raw(c, rootfs + rn, blen - head - rn);
    if (c->over) {
        snprintf(err, errlen, "rewritten image config exceeds %u bytes",
                 (unsigned) CONV_DOC_CAP);
        return BRIX_OCI_REG_EPROTO;
    }
    return BRIX_OCI_REG_OK;
}

static int
conv_config(brixoci_end_t *s, brixoci_end_t *d, const brix_oci_desc_t *m,
            conv_t *c, brix_oci_desc_t *cfg, char *err, size_t errlen)
{
    const char *el;
    size_t      en, blen;
    char        dig[BRIX_OCI_DIGEST_STRLEN], *body;
    int         rc;

    if (brix_json_get_raw(m->body, m->body_len, "config", &el, &en) != 1 ||
        !brix_json_get_str(el, en, "digest", dig, sizeof(dig))) {
        snprintf(err, errlen, "source manifest has no config descriptor");
        return BRIX_OCI_REG_EPROTO;
    }
    if (!brix_json_get_str(el, en, "mediaType", cfg->mediatype,
                           sizeof(cfg->mediatype))) {
        snprintf(cfg->mediatype, sizeof(cfg->mediatype), "%s", OCI_MT_CONFIG);
    }
    rc = conv_load(s, dig, &body, &blen, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    rc = conv_rewrite_config(c, body, blen, err, errlen);
    free(body);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    cfg->body_len = c->len;
    return conv_put_mem(d, c->doc, c->len, cfg->digest, sizeof(cfg->digest),
                        err, errlen);
}

/* ---- the manifest -------------------------------------------------------- */

static const char *
conv_manifest_mt(const char *src_mt)
{
    return strncmp(src_mt, D2_MT_MANIFEST, strlen(D2_MT_MANIFEST)) == 0
               ? D2_MT_MANIFEST
               : OCI_MT_MANIFEST;
}

/* The rewritten manifest: new config descriptor, new layer descriptors,
 * and per layer the annotation a stargz snapshotter reads the TOC digest
 * from before it fetches anything else. */
static int
conv_manifest(conv_t *c, const brix_oci_desc_t *src, brix_oci_desc_t *out,
              const brix_oci_desc_t *cfg, char *err, size_t errlen)
{
    int i;

    snprintf(out->mediatype, sizeof(out->mediatype), "%s",
             conv_manifest_mt(src->mediatype));
    c->len = 0;
    c->over = 0;
    c->doc[0] = '\0';
    conv_emit(c, "{\"schemaVersion\":2,\"mediaType\":\"%s\","
              "\"config\":{\"mediaType\":\"%s\",\"digest\":\"%s\","
              "\"size\":%lld},\"layers\":[",
              out->mediatype, cfg->mediatype, cfg->digest,
              (long long) cfg->body_len);
    for (i = 0; i < c->n; i++) {
        conv_emit(c, "%s{\"mediaType\":\"%s\",\"digest\":\"%s\","
                  "\"size\":%lld,\"annotations\":{\"%s\":\"%s\"}}",
                  i ? "," : "", c->lay[i].mediatype, c->lay[i].digest,
                  c->lay[i].size, BRIX_STARGZ_TOC_ANNOTATION, c->lay[i].toc);
    }
    conv_emit(c, "]}");
    if (c->over) {
        snprintf(err, errlen, "rewritten manifest exceeds %u bytes",
                 (unsigned) CONV_DOC_CAP);
        return BRIX_OCI_REG_EPROTO;
    }
    out->body = c->doc;
    out->body_len = c->len;
    return BRIX_OCI_REG_OK;
}

/* ---- the verb ------------------------------------------------------------ */

static int
conv_run(brixoci_end_t *src, brixoci_end_t *dst, conv_t *c,
         const char *bindtag, brix_oci_desc_t *m, char *digest_out,
         size_t dlen, char *err, size_t errlen)
{
    brix_oci_desc_t cfg, out;
    int             rc;

    memset(&cfg, 0, sizeof(cfg));
    memset(&out, 0, sizeof(out));
    rc = conv_layers(src, dst, m, c, err, errlen);
    if (rc == BRIX_OCI_REG_OK) {
        rc = conv_config(src, dst, m, c, &cfg, err, errlen);
    }
    if (rc == BRIX_OCI_REG_OK) {
        rc = conv_manifest(c, m, &out, &cfg, err, errlen);
    }
    if (rc == BRIX_OCI_REG_OK) {
        /* out.body aliases the scratch document; the binding copies it. */
        rc = brixoci_put_manifest(dst, bindtag, &out, digest_out, dlen, err,
                                  errlen);
    }
    return rc;
}

int
brixoci_convert_run(brixoci_end_t *src, brixoci_end_t *dst,
                    const brixoci_opts_t *o, char *digest_out, size_t dlen,
                    char *err, size_t errlen)
{
    brix_oci_desc_t m;
    conv_t          c;
    const char     *seltag, *bindtag;
    int             rc;

    memset(&c, 0, sizeof(c));
    c.lay = calloc(CONV_MAX_LAYERS, sizeof(*c.lay));
    c.doc = malloc(CONV_DOC_CAP);
    if (c.lay == NULL || c.doc == NULL) {
        free(c.lay);
        free(c.doc);
        snprintf(err, errlen, "out of memory");
        return BRIX_OCI_REG_ETRANSPORT;
    }
    brixoci_xfer_tags(src, dst, &seltag, &bindtag);
    if (o->tag != NULL) {
        /* Layout → layout has no reference to carry over, and an untagged
         * entry is one podman/skopeo cannot name. --tag is how the caller
         * says what the converted image is called at the destination. */
        bindtag = o->tag;
    }
    rc = brixoci_src_manifest(src, seltag, o, &m, err, errlen);
    if (rc == BRIX_OCI_REG_OK && brixoci_is_index(&m)) {
        snprintf(err, errlen, "source manifest is an image index — convert "
                 "one image at a time with --platform");
        rc = BRIX_OCI_REG_EPROTO;
    } else if (rc == BRIX_OCI_REG_OK) {
        rc = conv_run(src, dst, &c, bindtag, &m, digest_out, dlen, err,
                      errlen);
    }
    brix_oci_desc_free(&m);
    free(c.lay);
    free(c.doc);
    return rc;
}
