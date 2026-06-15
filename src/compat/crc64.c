/*
 * crc64.c - parameterized 64-bit CRC kernel (pure, ngx-free).
 *
 * WHAT: CRC-64/XZ and CRC-64/NVME, both reflected with init/xorout all-FF, via a
 *       256-entry reflected lookup table per variant; plus a zlib-style GF(2)
 *       combine for deriving a whole-object CRC from per-part CRCs (S3 multipart
 *       FULL_OBJECT). See crc64.h for the variant/polynomial/encoding contract.
 * WHY:  Stock XRootD ships no crc64 calculator; this is the single shared engine
 *       behind kXR_Qcksum, WebDAV Digest, S3 x-amz-checksum-crc64nvme and the
 *       native client — the crc32c.c analogue for 64-bit checksums.
 * HOW:  Tables are filled once at load by a constructor (single-threaded, before
 *       any worker thread forks, like crc32c's hw-table init), so the hot path is
 *       table lookups + XORs. No goto; no hardware path (x86 baseline has no
 *       CRC64 instruction). Correctness of each table is asserted in the unit
 *       test tests/unit/test_crc64.c against the published check constants
 *       (XZ 0x995DC9BBDF1939FA, NVME 0xAE8B14860A799888).
 */
#include "crc64.h"

/*
 * Reflected (bit-reversed) polynomials. The CRC catalogue lists the NORMAL
 * (MSB-first) forms — XZ 0x42F0E1EBA9EA3693, NVME 0xAD93D23594C93659 — but a
 * reflected (right-shifting) table-driven implementation uses the bit-reversed
 * constant. XZ's reflected form is identical to Go's crc64.ECMA; NVME's matches
 * the Linux kernel crc64_rocksoft polynomial.
 */
#define XROOTD_CRC64_XZ_POLY_REFL   0xC96C5795D7870F42ULL
#define XROOTD_CRC64_NVME_POLY_REFL 0x9A6C9329AC4BC9B5ULL

#define XROOTD_CRC64_TABLE_SIZE 256
#define XROOTD_CRC64_GF2_DIM    64

static uint64_t xrootd_crc64_xz_tab[XROOTD_CRC64_TABLE_SIZE];
static uint64_t xrootd_crc64_nvme_tab[XROOTD_CRC64_TABLE_SIZE];

/* Build the 256-entry reflected table for one reflected polynomial. */
static void
xrootd_crc64_build_table(uint64_t *tab, uint64_t poly_refl)
{
    int i, j;

    for (i = 0; i < XROOTD_CRC64_TABLE_SIZE; i++) {
        uint64_t crc = (uint64_t) i;

        for (j = 0; j < 8; j++) {
            crc = (crc & 1) ? (crc >> 1) ^ poly_refl : (crc >> 1);
        }
        tab[i] = crc;
    }
}

__attribute__((constructor))
static void
xrootd_crc64_tables_init(void)
{
    xrootd_crc64_build_table(xrootd_crc64_xz_tab,   XROOTD_CRC64_XZ_POLY_REFL);
    xrootd_crc64_build_table(xrootd_crc64_nvme_tab, XROOTD_CRC64_NVME_POLY_REFL);
}

static const uint64_t *
xrootd_crc64_table_for(xrootd_crc64_variant_t variant)
{
    switch (variant) {
    case XROOTD_CRC64_XZ:   return xrootd_crc64_xz_tab;
    case XROOTD_CRC64_NVME: return xrootd_crc64_nvme_tab;
    default:                return NULL;
    }
}

static uint64_t
xrootd_crc64_poly_for(xrootd_crc64_variant_t variant)
{
    switch (variant) {
    case XROOTD_CRC64_XZ:   return XROOTD_CRC64_XZ_POLY_REFL;
    case XROOTD_CRC64_NVME: return XROOTD_CRC64_NVME_POLY_REFL;
    default:                return 0;
    }
}

uint64_t
xrootd_crc64_extend(xrootd_crc64_variant_t variant, uint64_t crc,
    const void *buf, size_t len)
{
    const unsigned char *p;
    const uint64_t      *tab;

    tab = xrootd_crc64_table_for(variant);
    if (tab == NULL) {
        return crc;
    }
    if (buf == NULL && len != 0) {
        return crc;
    }

    p = (const unsigned char *) buf;

    crc = ~crc;                              /* init = all-FF (rolling-safe) */
    while (len--) {
        crc = tab[(crc ^ *p++) & 0xFFu] ^ (crc >> 8);
    }
    return ~crc;                             /* xorout = all-FF */
}

uint64_t
xrootd_crc64_value(xrootd_crc64_variant_t variant, const void *buf, size_t len)
{
    return xrootd_crc64_extend(variant, 0, buf, len);
}

/*
 * GF(2) linear-algebra combine (the zlib crc32_combine construction at 64-bit
 * width). A CRC register update over a run of zero bytes is a linear operator on
 * the 64-bit state; combining crc(A) with crc(B) means advancing crc(A) across
 * |B| zero bytes, then XORing crc(B). Operators are 64x64 bit-matrices stored as
 * uint64_t[64] (column n = image of basis vector e_n).
 */
static uint64_t
xrootd_crc64_gf2_times(const uint64_t *mat, uint64_t vec)
{
    uint64_t sum = 0;

    while (vec) {
        if (vec & 1) {
            sum ^= *mat;
        }
        vec >>= 1;
        mat++;
    }
    return sum;
}

/* square = mat * mat over GF(2). */
static void
xrootd_crc64_gf2_square(uint64_t *square, const uint64_t *mat)
{
    int n;

    for (n = 0; n < XROOTD_CRC64_GF2_DIM; n++) {
        square[n] = xrootd_crc64_gf2_times(mat, mat[n]);
    }
}

uint64_t
xrootd_crc64_combine(xrootd_crc64_variant_t variant, uint64_t crc1,
    uint64_t crc2, uint64_t len2)
{
    uint64_t even[XROOTD_CRC64_GF2_DIM];   /* even-power-of-two zeros operator */
    uint64_t odd[XROOTD_CRC64_GF2_DIM];    /* odd-power-of-two zeros operator  */
    uint64_t poly_refl;
    uint64_t row;
    int      n;

    poly_refl = xrootd_crc64_poly_for(variant);
    if (poly_refl == 0 || len2 == 0) {
        return crc1;
    }

    /* Operator for a single shifted-in zero bit. */
    odd[0] = poly_refl;
    row = 1;
    for (n = 1; n < XROOTD_CRC64_GF2_DIM; n++) {
        odd[n] = row;
        row <<= 1;
    }

    xrootd_crc64_gf2_square(even, odd);    /* two zero bits  */
    xrootd_crc64_gf2_square(odd, even);    /* four zero bits */

    /* Apply len2 zero BYTES to crc1: the first square below yields the operator
     * for one zero byte (eight zero bits) in `even`, then each loop iteration
     * doubles the zero-run, consuming one bit of len2 per half-iteration. */
    do {
        xrootd_crc64_gf2_square(even, odd);
        if (len2 & 1) {
            crc1 = xrootd_crc64_gf2_times(even, crc1);
        }
        len2 >>= 1;
        if (len2 == 0) {
            break;
        }
        xrootd_crc64_gf2_square(odd, even);
        if (len2 & 1) {
            crc1 = xrootd_crc64_gf2_times(odd, crc1);
        }
        len2 >>= 1;
    } while (len2 != 0);

    return crc1 ^ crc2;
}
