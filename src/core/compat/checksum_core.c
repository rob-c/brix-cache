/*
 * checksum_core.c — pure (ngx-free) whole-file checksum compute kernels.
 *
 * WHAT: brix_cksum_u32_fd() (Adler-32/CRC-32/CRC-32c) and
 *       brix_cksum_digest_fd() (MD5/SHA-1/SHA-256/SHA-512) stream a file descriptor and
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
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */

#define BRIX_CK_BUFSZ (64 * 1024)

/* ---- Is a normalized u32 checksum kind supported by the u32 kernel? ----
 *
 * WHAT: Returns non-zero when kind is one of the three u32 checksum families
 *       this kernel computes (Adler-32, CRC-32, CRC-32c), zero otherwise.
 *
 * WHY:  Keeps the argument-validation predicate in brix_cksum_u32_obj() a single
 *       named call instead of an inline chain of inequalities, so the orchestrator
 *       reads as one guard and the accepted-kind set lives in exactly one place.
 *
 * HOW:  1. Compare kind against each accepted constant and OR the results.
 *       Callers must fold BRIX_CK_ZCRC32 to BRIX_CK_CRC32 before calling.
 */
static int
u32_kind_ok(int kind)
{
    return kind == BRIX_CK_ADLER32 || kind == BRIX_CK_CRC32
        || kind == BRIX_CK_CRC32C;
}

/* ---- Initial running value (seed) for a u32 checksum kind ----
 *
 * WHAT: Returns the identity seed for the running accumulator: the zlib
 *       adler32/crc32 identity for those kinds, or 0 for the CRC-32c path.
 *
 * WHY:  The zlib CRC-32 and Adler-32 identities are obtained by calling the
 *       library with a NULL buffer (their canonical init); folding that choice
 *       into a helper keeps brix_cksum_u32_obj() flat while preserving the exact
 *       seeds. CRC-32c is seeded to 0 because brix_crc32c_extend() owns its init.
 *
 * HOW:  1. Adler-32 -> adler32(0L, Z_NULL, 0).
 *       2. CRC-32    -> crc32(0L, Z_NULL, 0).
 *       3. otherwise (CRC-32c) -> 0.
 */
static uLong
u32_seed(int kind)
{
    if (kind == BRIX_CK_ADLER32) {
        return adler32(0L, Z_NULL, 0);
    }
    if (kind == BRIX_CK_CRC32) {
        return crc32(0L, Z_NULL, 0);
    }
    return 0;
}

/* ---- Fold one chunk into the running u32 checksum for the selected kind ----
 *
 * WHAT: Extends the running accumulator over n bytes of buf. Adler-32 and CRC-32
 *       update the zlib accumulator via *zcrc; CRC-32c updates *crc32c. No return.
 *
 * WHY:  Isolates the per-kind arithmetic (the one place bit-exactness matters)
 *       from the read/EINTR loop, so the loop stays a plain drain and the
 *       accumulation is a single-responsibility, independently reviewable step.
 *
 * HOW:  1. Adler-32 -> zcrc = adler32(zcrc, buf, (uInt) n).
 *       2. CRC-32    -> zcrc = crc32(zcrc, buf, (uInt) n).
 *       3. otherwise (CRC-32c) -> crc32c = brix_crc32c_extend(crc32c, buf, n).
 *       Casts match the by-value original exactly so the folded bytes are identical.
 */
static void
u32_update(int kind, const unsigned char *buf, size_t n,
           uLong *zcrc, uint32_t *crc32c)
{
    if (kind == BRIX_CK_ADLER32) {
        *zcrc = adler32(*zcrc, buf, (uInt) n);
    } else if (kind == BRIX_CK_CRC32) {
        *zcrc = crc32(*zcrc, buf, (uInt) n);
    } else {
        *crc32c = brix_crc32c_extend(*crc32c, buf, n);
    }
}

/* ---- Bytes to request this read given the remaining range budget ----
 *
 * WHAT: For a bounded range (len >= 0) returns min(bufsz, remaining), clamping
 *       the final read so the sum stops exactly at start+len; for an unbounded
 *       range (len < 0, "to EOF") always returns bufsz.
 *
 * WHY:  All three ranged kernels (u32/u64/digest) share the same last-read clamp;
 *       naming it keeps each read loop a flat drain and puts the boundary
 *       arithmetic — the one place an off-by-one would corrupt a partial-range
 *       checksum — in a single reviewable spot.
 */
static size_t
range_want(off_t len, off_t remaining, size_t bufsz)
{
    if (len < 0) {
        return bufsz;
    }
    if (remaining <= 0) {
        return 0;
    }
    return (remaining < (off_t) bufsz) ? (size_t) remaining : bufsz;
}

/* ck_chunk_fn — fold one freshly read chunk into the caller's accumulator
 * state; return 0 to keep draining, -1 to abort the walk as failed. */
typedef int (*ck_chunk_fn)(const unsigned char *buf, size_t n, void *st);

/* ---- Drain the byte extent [start, start+len) of obj through `fold` ----
 *
 * WHAT: The one ranged pread loop all three checksum kernels (u32/u64/digest)
 *       share: reads BRIX_CK_BUFSZ chunks via the SD driver seam, retries
 *       EINTR, stops at EOF or when the bounded range (len >= 0) is exhausted
 *       (len < 0 means "to EOF"), and hands every chunk to `fold`. Returns 0,
 *       or -1 on a read error or a failing fold.
 *
 * WHY:  The drain — EINTR retry, EOF stop, range bookkeeping — is where a
 *       divergence between kernels would silently checksum different bytes;
 *       one loop keeps the three kernels bit-identical by construction and
 *       leaves each kernel only its arithmetic.
 */
static int
ck_pread_walk(brix_sd_obj_t *obj, off_t start, off_t len, ck_chunk_fn fold,
              void *st)
{
    unsigned char buf[BRIX_CK_BUFSZ];
    off_t         offset = start;
    off_t         remaining = len;

    while (len < 0 || remaining > 0) {
        size_t  want = range_want(len, remaining, sizeof(buf));
        ssize_t n = obj->driver->pread(obj, buf, want, offset);
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
        if (len >= 0) {
            remaining -= (off_t) n;
        }
        if (fold(buf, (size_t) n, st) != 0) {
            return -1;
        }
    }
    return 0;
}

/* u32_walk_t / u32_fold — ck_pread_walk state+fold for the u32 kernel: the
 * selected kind plus both accumulators (zlib uLong and CRC-32c). */
typedef struct {
    int      kind;
    uLong    zcrc;
    uint32_t crc32c;
} u32_walk_t;

static int
u32_fold(const unsigned char *buf, size_t n, void *st)
{
    u32_walk_t *w = st;

    u32_update(w->kind, buf, n, &w->zcrc, &w->crc32c);
    return 0;
}

int
brix_cksum_u32_obj_range(int kind, brix_sd_obj_t *obj, off_t start, off_t len,
                         uint32_t *out)
{
    u32_walk_t w;

    /* "zcrc32" is XRootD's name for the zlib CRC-32 (== CRC32/ISO-HDLC); fold it
     * onto the CRC32 kernel path so there is one implementation. */
    if (kind == BRIX_CK_ZCRC32) {
        kind = BRIX_CK_CRC32;
    }

    if (out == NULL || obj == NULL || obj->driver == NULL
        || !u32_kind_ok(kind) || start < 0) {
        return -1;
    }

    w.kind = kind;
    w.zcrc = u32_seed(kind);
    w.crc32c = 0;
    if (ck_pread_walk(obj, start, len, u32_fold, &w) != 0) {
        return -1;
    }

    *out = (kind == BRIX_CK_CRC32C) ? w.crc32c : (uint32_t) w.zcrc;
    return 0;
}

int
brix_cksum_u32_obj(int kind, brix_sd_obj_t *obj, uint32_t *out)
{
    return brix_cksum_u32_obj_range(kind, obj, 0, -1, out);
}

int
brix_cksum_u32_fd(int kind, int fd, uint32_t *out)
{
    brix_sd_obj_t obj;

    brix_sd_posix_wrap(&obj, fd);   /* default POSIX read via the SD seam */
    return brix_cksum_u32_obj(kind, &obj, out);
}

/* u64_walk_t / u64_fold — ck_pread_walk state+fold for the CRC-64 kernel:
 * the resolved polynomial variant plus the running crc. */
typedef struct {
    brix_crc64_variant_t variant;
    uint64_t             crc;
} u64_walk_t;

static int
u64_fold(const unsigned char *buf, size_t n, void *st)
{
    u64_walk_t *w = st;

    w->crc = brix_crc64_extend(w->variant, w->crc, buf, n);
    return 0;
}

int
brix_cksum_u64_obj_range(int kind, brix_sd_obj_t *obj, off_t start, off_t len,
                         uint64_t *out)
{
    u64_walk_t w;

    if (out == NULL || obj == NULL || obj->driver == NULL || start < 0) {
        return -1;
    }
    if (kind == BRIX_CK_CRC64) {
        w.variant = BRIX_CRC64_XZ;
    } else if (kind == BRIX_CK_CRC64NVME) {
        w.variant = BRIX_CRC64_NVME;
    } else {
        return -1;
    }

    w.crc = 0;
    if (ck_pread_walk(obj, start, len, u64_fold, &w) != 0) {
        return -1;
    }

    *out = w.crc;
    return 0;
}

int
brix_cksum_u64_obj(int kind, brix_sd_obj_t *obj, uint64_t *out)
{
    return brix_cksum_u64_obj_range(kind, obj, 0, -1, out);
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
    case BRIX_CK_SHA512: return EVP_sha512();
    default:               return NULL;
    }
}

/* Drive an initialised ctx over the byte extent [start, start+len) of the object
 * (len < 0 ⇒ to EOF); caller owns/frees ctx. 0/-1. */
static int
digest_fold(const unsigned char *buf, size_t n, void *st)
{
    return (EVP_DigestUpdate((EVP_MD_CTX *) st, buf, n) == 1) ? 0 : -1;
}

static int
digest_drive(EVP_MD_CTX *ctx, const EVP_MD *md, brix_sd_obj_t *obj,
             off_t start, off_t len, unsigned char *out, unsigned int *outlen)
{
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        return -1;
    }
    if (ck_pread_walk(obj, start, len, digest_fold, ctx) != 0) {
        return -1;
    }
    return (EVP_DigestFinal_ex(ctx, out, outlen) == 1) ? 0 : -1;
}

int
brix_cksum_digest_obj_range(int kind, brix_sd_obj_t *obj, off_t start,
                            off_t len, unsigned char *out, unsigned int *outlen)
{
    const EVP_MD *md = md_for(kind);
    EVP_MD_CTX   *ctx;
    int           rc;

    if (md == NULL || obj == NULL || obj->driver == NULL
        || out == NULL || outlen == NULL || start < 0) {
        return -1;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    rc = digest_drive(ctx, md, obj, start, len, out, outlen);
    brix_evp_md_ctx_free(ctx);
    return rc;
}

int
brix_cksum_digest_obj(int kind, brix_sd_obj_t *obj, unsigned char *out,
                        unsigned int *outlen)
{
    return brix_cksum_digest_obj_range(kind, obj, 0, -1, out, outlen);
}

int
brix_cksum_digest_fd(int kind, int fd, unsigned char *out, unsigned int *outlen)
{
    brix_sd_obj_t obj;

    brix_sd_posix_wrap(&obj, fd);   /* default POSIX read via the SD seam */
    return brix_cksum_digest_obj(kind, &obj, out, outlen);
}
