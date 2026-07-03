/*
 * checksum_core.c — pure (ngx-free) whole-file checksum compute kernels.
 *
 * WHAT: brix_cksum_u32_fd() (Adler-32/CRC-32/CRC-32c) and
 *       brix_cksum_digest_fd() (MD5/SHA-1/SHA-256) stream a file descriptor and
 *       return the result; no nginx, no logging.
 * WHY:  Single source for fd→checksum compute, shared by the nginx module
 *       (src/compat/checksum.c delegates here, keeping its ngx logging) and the
 *       native client (client/lib/checksum.c), via libxrdproto build-in-place.
 * HOW:  read the whole file in 64 KiB chunks through the SD driver vtable
 *       (obj.driver->pread, EINTR-retried) so the kernel reads whatever backend
 *       the wrapped object carries; zlib adler32/crc32, brix_crc32c_extend for
 *       crc32c, OpenSSL EVP for digests. No goto (per coding-standards): the EVP
 *       path uses an init-at-edge helper.
 */
#include "checksum_core.h"
#include "fs/backend/sd.h"   /* phase-55: route raw fd I/O through the SD seam */
#include "crc32c.h"
#include "crc64.h"

#include <errno.h>
#include <unistd.h>
#include <zlib.h>
#include <openssl/evp.h>

#define BRIX_CK_BUFSZ (64 * 1024)

int
brix_cksum_u32_obj(int kind, brix_sd_obj_t *obj, uint32_t *out)
{
    unsigned char buf[BRIX_CK_BUFSZ];
    off_t         offset = 0;
    uint32_t      crc32c = 0;
    uLong         zcrc;

    /* "zcrc32" is XRootD's name for the zlib CRC-32 (== CRC32/ISO-HDLC); fold it
     * onto the CRC32 kernel path so there is one implementation. */
    if (kind == BRIX_CK_ZCRC32) {
        kind = BRIX_CK_CRC32;
    }

    if (out == NULL || obj == NULL || obj->driver == NULL
        || (kind != BRIX_CK_ADLER32 && kind != BRIX_CK_CRC32
            && kind != BRIX_CK_CRC32C)) {
        return -1;
    }

    zcrc = (kind == BRIX_CK_ADLER32) ? adler32(0L, Z_NULL, 0)
         : (kind == BRIX_CK_CRC32)   ? crc32(0L, Z_NULL, 0)
                                       : 0;

    for (;;) {
        ssize_t n = obj->driver->pread(obj, buf, sizeof(buf), offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            break;
        }
        offset += (off_t) n;
        if (kind == BRIX_CK_ADLER32) {
            zcrc = adler32(zcrc, buf, (uInt) n);
        } else if (kind == BRIX_CK_CRC32) {
            zcrc = crc32(zcrc, buf, (uInt) n);
        } else {
            crc32c = brix_crc32c_extend(crc32c, buf, (size_t) n);
        }
    }

    *out = (kind == BRIX_CK_CRC32C) ? crc32c : (uint32_t) zcrc;
    return 0;
}

int
brix_cksum_u32_fd(int kind, int fd, uint32_t *out)
{
    brix_sd_obj_t obj;

    brix_sd_posix_wrap(&obj, fd);   /* default POSIX read via the SD seam */
    return brix_cksum_u32_obj(kind, &obj, out);
}

int
brix_cksum_u64_obj(int kind, brix_sd_obj_t *obj, uint64_t *out)
{
    unsigned char          buf[BRIX_CK_BUFSZ];
    off_t                  offset = 0;
    uint64_t               crc = 0;
    brix_crc64_variant_t variant;

    if (out == NULL || obj == NULL || obj->driver == NULL) {
        return -1;
    }
    if (kind == BRIX_CK_CRC64) {
        variant = BRIX_CRC64_XZ;
    } else if (kind == BRIX_CK_CRC64NVME) {
        variant = BRIX_CRC64_NVME;
    } else {
        return -1;
    }

    for (;;) {
        ssize_t n = obj->driver->pread(obj, buf, sizeof(buf), offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            break;
        }
        offset += (off_t) n;
        crc = brix_crc64_extend(variant, crc, buf, (size_t) n);
    }

    *out = crc;
    return 0;
}

int
brix_cksum_u64_fd(int kind, int fd, uint64_t *out)
{
    brix_sd_obj_t obj;

    brix_sd_posix_wrap(&obj, fd);   /* default POSIX read via the SD seam */
    return brix_cksum_u64_obj(kind, &obj, out);
}

static const EVP_MD *
md_for(int kind)
{
    switch (kind) {
    case BRIX_CK_MD5:    return EVP_md5();
    case BRIX_CK_SHA1:   return EVP_sha1();
    case BRIX_CK_SHA256: return EVP_sha256();
    default:               return NULL;
    }
}

/* Drive an initialised ctx over the whole object; caller owns/frees ctx. 0/-1. */
static int
digest_drive(EVP_MD_CTX *ctx, const EVP_MD *md, brix_sd_obj_t *obj,
             unsigned char *out, unsigned int *outlen)
{
    unsigned char buf[BRIX_CK_BUFSZ];
    off_t         offset = 0;

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        return -1;
    }
    for (;;) {
        ssize_t n = obj->driver->pread(obj, buf, sizeof(buf), offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            break;
        }
        offset += (off_t) n;
        if (EVP_DigestUpdate(ctx, buf, (size_t) n) != 1) {
            return -1;
        }
    }
    return (EVP_DigestFinal_ex(ctx, out, outlen) == 1) ? 0 : -1;
}

int
brix_cksum_digest_obj(int kind, brix_sd_obj_t *obj, unsigned char *out,
                        unsigned int *outlen)
{
    const EVP_MD *md = md_for(kind);
    EVP_MD_CTX   *ctx;
    int           rc;

    if (md == NULL || obj == NULL || obj->driver == NULL
        || out == NULL || outlen == NULL) {
        return -1;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    rc = digest_drive(ctx, md, obj, out, outlen);
    EVP_MD_CTX_free(ctx);
    return rc;
}

int
brix_cksum_digest_fd(int kind, int fd, unsigned char *out, unsigned int *outlen)
{
    brix_sd_obj_t obj;

    brix_sd_posix_wrap(&obj, fd);   /* default POSIX read via the SD seam */
    return brix_cksum_digest_obj(kind, &obj, out, outlen);
}
