/*
 * pblock_xform.c — Phase-83 F12/F13 per-block transform seam (see pblock_xform.h).
 *
 * Config parse (crypt keyfile / zstd availability), the whole-block encode/decode,
 * and the headered block-file load/store the packed-block engine calls when an
 * export has a transform configured. ngx-free; gated by BRIX_HAVE_SQLITE via its
 * only includer's build unit (the file itself needs no sqlite, but it ships with
 * the sqlite-gated backend so it is compiled under the same condition).
 */
#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_xform.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#if BRIX_HAVE_ZSTD
#include <zstd.h>
#endif

/* ---- config ---------------------------------------------------------------- */

int
pblock_xform_active(const pblock_xform_t *xf)
{
    return xf != NULL && xf->kind != PBLOCK_XFORM_NONE;
}

const char *
pblock_xform_name(pblock_xform_kind kind)
{
    switch (kind) {
    case PBLOCK_XFORM_CRYPT: return "crypt";
    case PBLOCK_XFORM_ZSTD:  return "zstd";
    default:                 return "";
    }
}

pblock_xform_kind
pblock_xform_kind_from_name(const char *name)
{
    if (name == NULL) {
        return PBLOCK_XFORM_NONE;
    }
    if (strcmp(name, "crypt") == 0) {
        return PBLOCK_XFORM_CRYPT;
    }
    if (strcmp(name, "zstd") == 0) {
        return PBLOCK_XFORM_ZSTD;
    }
    return PBLOCK_XFORM_NONE;
}

/* Derive a 32-byte key from a keyfile: FNV-1a fold of the file bytes expanded
 * with a small mix. NOT a KDF — a lab keyed transform, per the phase non-goals. */
static int
xform_load_key(const char *keyfile, unsigned char key[32])
{
    unsigned char buf[4096];
    uint64_t      h = 1469598103934665603ULL;
    ssize_t       n;
    int           fd, i, got = 0;

    fd = open(keyfile, O_RDONLY);
    if (fd < 0) {
        return -1;                               /* errno = ENOENT/EACCES */
    }
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (i = 0; i < n; i++) {
            h ^= buf[i];
            h *= 1099511628211ULL;
        }
        got += (int) n;
    }
    close(fd);
    if (n < 0 || got == 0) {
        errno = n < 0 ? errno : EINVAL;          /* empty keyfile ⇒ EINVAL */
        return -1;
    }
    for (i = 0; i < 32; i++) {
        h ^= (uint64_t) (i + 1) * 0x9E3779B97F4A7C15ULL;
        h *= 1099511628211ULL;
        key[i] = (unsigned char) (h >> 29);
    }
    return 0;
}

int
pblock_xform_config(pblock_xform_t *xf, const char *spec, size_t len)
{
    memset(xf, 0, sizeof(*xf));
    if (spec == NULL || len == 0) {
        return 0;                                /* kind NONE */
    }
    if (len == 4 && memcmp(spec, "zstd", 4) == 0) {
#if BRIX_HAVE_ZSTD
        xf->kind = PBLOCK_XFORM_ZSTD;
        return 0;
#else
        errno = ENOTSUP;                         /* config error: no libzstd */
        return -1;
#endif
    }
    if (len > 6 && memcmp(spec, "crypt:", 6) == 0) {
        char kf[4096];

        if (len - 6 >= sizeof(kf)) {
            errno = EINVAL;
            return -1;
        }
        memcpy(kf, spec + 6, len - 6);
        kf[len - 6] = '\0';
        if (xform_load_key(kf, xf->key) != 0) {
            return -1;                           /* errno from xform_load_key */
        }
        xf->kind = PBLOCK_XFORM_CRYPT;
        return 0;
    }
    errno = EINVAL;
    return -1;
}

/* ---- whole-block encode/decode -------------------------------------------- */

/* Keyed XOR keystream over one block: seed an LCG from the export key folded with
 * the block index, XOR len bytes in place. Reversible; NOT cryptographic. */
static void
xform_crypt_xor(const unsigned char key[32], int64_t idx, unsigned char *p,
    size_t len)
{
    uint64_t seed = 1469598103934665603ULL ^ ((uint64_t) idx * 0x9E3779B97F4A7C15ULL);
    size_t   i;

    for (i = 0; i < 32; i++) {
        seed ^= key[i];
        seed *= 1099511628211ULL;
    }
    for (i = 0; i < len; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        p[i] ^= (unsigned char) (seed >> 33);
    }
}

/* Encode logical[0..llen) into out[0..outcap); returns phys_len or -1/errno. */
static ssize_t
xform_encode(const pblock_xform_t *xf, int64_t idx, const unsigned char *logical,
    uint32_t llen, unsigned char *out, size_t outcap)
{
    if (xf->kind == PBLOCK_XFORM_CRYPT) {
        if (llen > outcap) {
            errno = ERANGE;
            return -1;
        }
        memcpy(out, logical, llen);
        xform_crypt_xor(xf->key, idx, out, llen);
        return (ssize_t) llen;
    }
#if BRIX_HAVE_ZSTD
    if (xf->kind == PBLOCK_XFORM_ZSTD) {
        size_t z = ZSTD_compress(out, outcap, logical, llen, 3);

        if (ZSTD_isError(z)) {
            errno = EIO;
            return -1;
        }
        return (ssize_t) z;
    }
#endif
    errno = ENOTSUP;
    return -1;
}

/* Decode phys[0..plen) (block idx) into out[0..llen); returns 0 or -1/errno. */
static int
xform_decode(const pblock_xform_t *xf, int64_t idx, const unsigned char *phys,
    uint32_t plen, unsigned char *out, uint32_t llen)
{
    if (xf->kind == PBLOCK_XFORM_CRYPT) {
        if (plen != llen) {
            errno = EIO;
            return -1;
        }
        memcpy(out, phys, llen);
        xform_crypt_xor(xf->key, idx, out, llen);
        return 0;
    }
#if BRIX_HAVE_ZSTD
    if (xf->kind == PBLOCK_XFORM_ZSTD) {
        size_t d = ZSTD_decompress(out, llen, phys, plen);

        if (ZSTD_isError(d) || d != llen) {
            errno = EIO;
            return -1;
        }
        return 0;
    }
#endif
    errno = ENOTSUP;
    return -1;
}

/* ---- headered block-file I/O ---------------------------------------------- */

static ssize_t
read_full(int fd, void *buf, size_t len, off_t off)
{
    size_t done = 0;

    while (done < len) {
        ssize_t r = pread(fd, (char *) buf + done, len - done, off + (off_t) done);

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r == 0) {
            break;
        }
        done += (size_t) r;
    }
    return (ssize_t) done;
}

static int
write_full(int fd, const void *buf, size_t len)
{
    size_t done = 0;

    while (done < len) {
        ssize_t w = write(fd, (const char *) buf + done, len - done);

        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        done += (size_t) w;
    }
    return 0;
}

int
pblock_xform_block_load(const pblock_xform_t *xf, int64_t idx, const char *path,
    unsigned char *out, int64_t bs, uint32_t *llen_out)
{
    unsigned char  hdr[PBLOCK_XFORM_HDR];
    unsigned char *phys;
    uint32_t       llen, plen;
    ssize_t        r;
    int            fd, rc = 0;

    memset(out, 0, (size_t) bs);
    *llen_out = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return errno == ENOENT ? 0 : -1;         /* missing block = hole */
    }
    r = read_full(fd, hdr, sizeof(hdr), 0);
    if (r == 0) {                                 /* freshly-created empty block */
        close(fd);
        return 0;
    }
    if (r != (ssize_t) sizeof(hdr)) {
        close(fd);
        errno = EIO;
        return -1;
    }
    llen = (uint32_t) hdr[0] | (uint32_t) hdr[1] << 8
         | (uint32_t) hdr[2] << 16 | (uint32_t) hdr[3] << 24;
    plen = (uint32_t) hdr[4] | (uint32_t) hdr[5] << 8
         | (uint32_t) hdr[6] << 16 | (uint32_t) hdr[7] << 24;
    if (llen > (uint32_t) bs || plen > (uint32_t) bs + PBLOCK_XFORM_HDR + 512) {
        close(fd);
        errno = EIO;                              /* corrupt header */
        return -1;
    }
    phys = malloc(plen ? plen : 1);
    if (phys == NULL) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    r = read_full(fd, phys, plen, PBLOCK_XFORM_HDR);
    close(fd);
    if (r != (ssize_t) plen) {
        free(phys);
        errno = EIO;
        return -1;
    }
    if (xform_decode(xf, idx, phys, plen, out, llen) != 0) {
        rc = -1;                                  /* errno set by decode */
    } else {
        *llen_out = llen;
    }
    free(phys);
    return rc;
}

int
pblock_xform_block_store(const pblock_xform_t *xf, int64_t idx, const char *path,
    const unsigned char *logical, uint32_t llen, int64_t bs)
{
    unsigned char  hdr[PBLOCK_XFORM_HDR];
    unsigned char *out;
    size_t         outcap;
    ssize_t        plen;
    int            fd;
    (void) bs;

#if BRIX_HAVE_ZSTD
    outcap = xf->kind == PBLOCK_XFORM_ZSTD ? ZSTD_compressBound(llen) : llen;
#else
    outcap = llen;
#endif
    out = malloc(outcap ? outcap : 1);
    if (out == NULL) {
        errno = ENOMEM;
        return -1;
    }
    plen = xform_encode(xf, idx, logical, llen, out, outcap);
    if (plen < 0) {
        free(out);
        return -1;
    }
    hdr[0] = (unsigned char) (llen);
    hdr[1] = (unsigned char) (llen >> 8);
    hdr[2] = (unsigned char) (llen >> 16);
    hdr[3] = (unsigned char) (llen >> 24);
    hdr[4] = (unsigned char) ((uint32_t) plen);
    hdr[5] = (unsigned char) ((uint32_t) plen >> 8);
    hdr[6] = (unsigned char) ((uint32_t) plen >> 16);
    hdr[7] = (unsigned char) ((uint32_t) plen >> 24);

    /* In place (not temp+rename) so the block-0 fd the caller holds open stays
     * valid; a transformed export is single-writer per block. */
    fd = open(path, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) {
        free(out);
        return -1;
    }
    if (write_full(fd, hdr, sizeof(hdr)) != 0
        || write_full(fd, out, (size_t) plen) != 0
        || ftruncate(fd, (off_t) (PBLOCK_XFORM_HDR + plen)) != 0)
    {
        int e = errno;

        close(fd);
        free(out);
        errno = e;
        return -1;
    }
    close(fd);
    free(out);
    return 0;
}

#else  /* !BRIX_HAVE_SQLITE */

typedef int brix_sd_pblock_xform_disabled_t;   /* avoid an empty translation unit */

#endif /* BRIX_HAVE_SQLITE */
