/* layout.c — the OCI image-layout store on disk (see layout.h). */
#include "oci/layout_internal.h"

#include "oci/reg_internal.h"
#include "oci/digest.h"
#include "oci/name.h"
#include "core/compat/json_iter.h"
#include "core/compat/json_min.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int
lay_write_full(int fd, const void *body, size_t len)
{
    const char *p = body;
    size_t      off = 0;

    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t) n;
    }
    return 0;
}

int
layx_read_file(const char *path, size_t cap, char **out, size_t *outlen)
{
    struct stat stt;
    char       *buf;
    size_t      off = 0;
    int         fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &stt) != 0 || !S_ISREG(stt.st_mode) ||
        (size_t) stt.st_size > cap) {
        close(fd);
        errno = EFBIG;
        return -1;
    }
    buf = malloc((size_t) stt.st_size + 1);
    if (buf == NULL) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    while (off < (size_t) stt.st_size) {
        ssize_t n = read(fd, buf + off, (size_t) stt.st_size - off);

        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            free(buf);
            close(fd);
            errno = EIO;
            return -1;
        }
        off += (size_t) n;
    }
    close(fd);
    buf[off] = '\0';
    *out = buf;
    *outlen = off;
    return 0;
}

int
layx_write_atomic(const char *dir, const char *name, const void *body,
                 size_t len, char *err, size_t errlen)
{
    char tmp[1200], fin[1200];
    int  fd;

    if (snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", dir, name) >=
            (int) sizeof(tmp) ||
        snprintf(fin, sizeof(fin), "%s/%s", dir, name) >=
            (int) sizeof(fin)) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "layout path too long");
    }
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "create %s: %s", tmp, strerror(errno));
    }
    if (lay_write_full(fd, body, len) != 0 || fsync(fd) != 0) {
        int saved = errno;

        close(fd);
        unlink(tmp);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "write %s: %s", tmp, strerror(saved));
    }
    close(fd);
    if (rename(tmp, fin) != 0) {
        int saved = errno;

        unlink(tmp);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "rename %s: %s", fin, strerror(saved));
    }
    return BRIX_OCI_REG_OK;
}

/* "<dir>/blobs/<alg>/<hex>" for a PARSED digest (the parse is the traversal
 * defense — a digest that parses cannot escape the store, and the algorithm
 * component comes from the grammar, never from caller text). */
static int
lay_blob_path(const brix_oci_layout_t *l, const char *digest,
              brix_oci_digest_t *d, char *out, size_t outlen, char *err,
              size_t errlen)
{
    if (brix_oci_digest_parse(digest, strlen(digest), d) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "invalid digest \"%s\"", digest);
    }
    if (snprintf(out, outlen, "%s/blobs/%s/%s", l->dir,
                 brix_oci_alg_name(d->alg), d->hex) >= (int) outlen) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "layout path too long");
    }
    return BRIX_OCI_REG_OK;
}

/* Materialize "<dir>/blobs/<alg>" just before a blob of that algorithm
 * lands. Created on demand rather than up front so a store only ever grows
 * the algorithm directories it actually holds — an empty blobs/sha512 in
 * every layout would be a lie an image-layout consumer has to read past. */
static int
lay_alg_dir(const brix_oci_layout_t *l, const brix_oci_digest_t *d,
            char *err, size_t errlen)
{
    char p[1200];

    if (snprintf(p, sizeof(p), "%s/blobs/%s", l->dir,
                 brix_oci_alg_name(d->alg)) >= (int) sizeof(p)) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "layout path too long");
    }
    if (mkdir(p, 0755) != 0 && errno != EEXIST) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "mkdir %s: %s", p, strerror(errno));
    }
    return BRIX_OCI_REG_OK;
}

int
brix_oci_layout_open(brix_oci_layout_t *l, const char *dir, int create,
                     char *err, size_t errlen)
{
    char        p[1200];
    char       *buf;
    size_t      blen;
    struct stat stt;

    if (snprintf(l->dir, sizeof(l->dir), "%s", dir) >=
        (int) sizeof(l->dir)) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "layout directory path too long");
    }
    if (create) {
        static const char *subs[] = { "", "/blobs" };
        size_t             i;

        for (i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
            snprintf(p, sizeof(p), "%s%s", l->dir, subs[i]);
            if (mkdir(p, 0755) != 0 && errno != EEXIST) {
                return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                                 "mkdir %s: %s", p, strerror(errno));
            }
        }
    }
    if (stat(l->dir, &stt) != 0 || !S_ISDIR(stt.st_mode)) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ENOTFOUND,
                         "no layout at %s", l->dir);
    }
    snprintf(p, sizeof(p), "%s/oci-layout", l->dir);
    if (layx_read_file(p, 4096, &buf, &blen) == 0) {
        char ver[32] = "";

        brix_json_get_str(buf, blen, "imageLayoutVersion", ver,
                          sizeof(ver));
        free(buf);
        if (strncmp(ver, "1.", 2) != 0) {
            return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                             "%s: unsupported imageLayoutVersion \"%s\"",
                             p, ver);
        }
    } else if (create && errno == ENOENT) {
        static const char marker[] = "{\"imageLayoutVersion\":\"1.0.0\"}\n";
        static const char empty[] =
            "{\"schemaVersion\":2,\"manifests\":[]}\n";
        int rc = layx_write_atomic(l->dir, "oci-layout", marker,
                                  sizeof(marker) - 1, err, errlen);

        if (rc != BRIX_OCI_REG_OK) {
            return rc;
        }
        snprintf(p, sizeof(p), "%s/index.json", l->dir);
        if (stat(p, &stt) != 0) {
            return layx_write_atomic(l->dir, "index.json", empty,
                                    sizeof(empty) - 1, err, errlen);
        }
    } else {
        return regc_fail(err, errlen, BRIX_OCI_REG_ENOTFOUND,
                         "%s is not an OCI layout (no oci-layout file)",
                         l->dir);
    }
    return BRIX_OCI_REG_OK;
}

int
brix_oci_layout_stage(brix_oci_layout_t *l, char *tmppath, size_t plen,
                      char *err, size_t errlen)
{
    int fd;

    /* Staged in blobs/ itself, not in an algorithm subdirectory: the
     * staging fd is opened before the digest is known, and blobs/ is the
     * nearest ancestor every blobs/<alg>/ shares, so the commit rename is
     * still same-filesystem and therefore atomic. */
    if (snprintf(tmppath, plen, "%s/blobs/.stage.XXXXXX", l->dir) >=
        (int) plen) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "layout path too long");
    }
    fd = mkstemp(tmppath);
    if (fd < 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "stage in %s: %s", l->dir, strerror(errno));
    }
    return fd;
}

int
brix_oci_layout_commit(brix_oci_layout_t *l, const char *tmppath,
                       const char *digest, char *err, size_t errlen)
{
    brix_oci_digest_t d;
    char              fin[1200];
    int               fd, rc;

    rc = lay_blob_path(l, digest, &d, fin, sizeof(fin), err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        unlink(tmppath);
        return rc;
    }
    rc = lay_alg_dir(l, &d, err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        unlink(tmppath);
        return rc;
    }
    fd = open(tmppath, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fsync(fd) != 0 || fchmod(fd, 0644) != 0) {
        int saved = errno;

        if (fd >= 0) {
            close(fd);
        }
        unlink(tmppath);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "commit %s: %s", tmppath, strerror(saved));
    }
    close(fd);
    if (rename(tmppath, fin) != 0) {
        int saved = errno;

        unlink(tmppath);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "commit %s: %s", fin, strerror(saved));
    }
    return BRIX_OCI_REG_OK;
}

int
brix_oci_layout_blob_put_mem(brix_oci_layout_t *l, const void *body,
                             size_t len, char *digest_out, size_t dlen,
                             char *err, size_t errlen)
{
    brix_oci_digest_t d;
    char              tmp[1200];
    int               fd, rc;

    /* We PRODUCE sha256 — reading back any registered algorithm is the
     * asymmetry the grammar exists for. */
    if (brix_oci_sha256(body, len, &d) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "sha256 failed");
    }
    if (brix_oci_digest_format(&d, digest_out, dlen) < 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "digest buffer too small");
    }
    fd = brix_oci_layout_stage(l, tmp, sizeof(tmp), err, errlen);
    if (fd < 0) {
        return fd;
    }
    if (lay_write_full(fd, body, len) != 0) {
        rc = regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                       "write %s: %s", tmp, strerror(errno));
        close(fd);
        unlink(tmp);
        return rc;
    }
    close(fd);
    return brix_oci_layout_commit(l, tmp, digest_out, err, errlen);
}

int
brix_oci_layout_blob_load(brix_oci_layout_t *l, const char *digest,
                          size_t cap, char **out, size_t *outlen,
                          char *err, size_t errlen)
{
    brix_oci_digest_t d, got;
    char              p[1200];
    int               rc;

    *out = NULL;
    rc = lay_blob_path(l, digest, &d, p, sizeof(p), err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    if (layx_read_file(p, cap, out, outlen) != 0) {
        return regc_fail(err, errlen,
                         errno == ENOENT ? BRIX_OCI_REG_ENOTFOUND
                                         : BRIX_OCI_REG_ETRANSPORT,
                         "blob %s: %s", digest, strerror(errno));
    }
    if (brix_oci_digest_hash(d.alg, *out, *outlen, &got) != 0 ||
        !brix_oci_digest_eq(&got, &d)) {
        free(*out);
        *out = NULL;
        return regc_fail(err, errlen, BRIX_OCI_REG_EVERIFY,
                         "stored blob %s fails its digest", digest);
    }
    return BRIX_OCI_REG_OK;
}

int
brix_oci_layout_blob_verify(brix_oci_layout_t *l, const char *digest,
                            long long *size, char *err, size_t errlen)
{
    brix_oci_hash_ctx_t c;
    brix_oci_digest_t   d, got;
    struct stat         stt;
    unsigned char       buf[65536];
    char                p[1200];
    ssize_t             n;
    int                 fd, rc;

    rc = lay_blob_path(l, digest, &d, p, sizeof(p), err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return regc_fail(err, errlen,
                         errno == ENOENT ? BRIX_OCI_REG_ENOTFOUND
                                         : BRIX_OCI_REG_ETRANSPORT,
                         "blob %s: %s", digest, strerror(errno));
    }
    if (fstat(fd, &stt) != 0 || brix_oci_hash_init(&c, d.alg) != 0) {
        close(fd);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "blob %s: verify setup failed", digest);
    }
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (brix_oci_hash_update(&c, buf, (size_t) n) != 0) {
            n = -1;
            break;
        }
    }
    close(fd);
    if (n < 0) {
        brix_oci_hash_abort(&c);
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "blob %s: read failed", digest);
    }
    if (brix_oci_hash_final(&c, &got) != 0 ||
        !brix_oci_digest_eq(&got, &d)) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EVERIFY,
                         "stored blob %s fails its digest", digest);
    }
    if (size != NULL) {
        *size = (long long) stt.st_size;
    }
    return BRIX_OCI_REG_OK;
}

int
brix_oci_layout_blob_open(brix_oci_layout_t *l, const char *digest,
                          char *err, size_t errlen)
{
    brix_oci_digest_t d;
    char              p[1200];
    int               fd, rc;

    rc = lay_blob_path(l, digest, &d, p, sizeof(p), err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return regc_fail(err, errlen,
                         errno == ENOENT ? BRIX_OCI_REG_ENOTFOUND
                                         : BRIX_OCI_REG_ETRANSPORT,
                         "blob %s: %s", digest, strerror(errno));
    }
    return fd;
}
