/*
 * crc32c_hw.c - SSE4.2 hardware-accelerated CRC-32c paths.
 *
 * WHAT: The x86_64 hardware half of the CRC-32c engine — SSE4.2 feature
 *       detection plus the serial and 3-way-parallel _mm_crc32_u64/u32/u8
 *       extend and copy+checksum implementations. Split verbatim from crc32c.c;
 *       the public dispatch (brix_crc32c_extend / _value / _copy_value) and the
 *       software fallback remain there and call in through crc32c_internal.h.
 *
 * WHY: XRootD pgread/pgwrite per-page CRC32c validation (Invariant #1) and TPC
 *      copy+checksum need the fast hardware path on modern x86_64 servers. The
 *      3-way-parallel construction (Mark Adler's public-domain scheme) hides the
 *      _mm_crc32_u64 latency chain for a ~3x speedup on large buffers; the wire
 *      CRC value is bit-identical to the serial/software paths.
 *
 * HOW: brix_crc32c_sse42_available() caches __builtin_cpu_supports("sse4.2").
 *      hw_extend/copy_hw are the serial paths; hw3_extend/copy_hw3 the parallel
 *      ones, recombined over GF(2) with byte-indexed "apply N zero bytes" tables
 *      filled once at load time by a constructor.
 */
#include "crc32c.h"
#include "crc32c_internal.h"

#include <string.h>

#ifdef __x86_64__

#include <nmmintrin.h>

static int brix_crc32c_has_sse42 = -1;

/*
 * brix_crc32c_sse42_available - detect SSE4.2 CPU feature with lazy caching.
 *
 * WHAT: Returns 1 if the CPU supports SSE4.2 (needed for _mm_crc32_u64 intrinsics),
 *       0 if not. Caches result in brix_crc32c_has_sse42 to avoid repeated detection.
 *
 * WHY: CRC-32c hardware path uses Intel SSE4.2 intrinsics (_mm_crc32_u64/u32/u8).
 *      This function determines whether to use the fast hw_extend() or sw_extend().
 *
 * HOW: First call uses __builtin_cpu_supports("sse4.2") (GCC/Clang builtin). Result
 *      cached in brix_crc32c_has_sse42 (initialized to -1 = unknown). Subsequent
 *      calls return cached value.
 */

int
brix_crc32c_sse42_available(void)
{
    if (brix_crc32c_has_sse42 < 0) {
        brix_crc32c_has_sse42 =
            __builtin_cpu_supports("sse4.2") ? 1 : 0;
    }

    return brix_crc32c_has_sse42;
}

__attribute__((target("sse4.2")))
/*
 * brix_crc32c_hw_extend - SSE4.2 hardware CRC-32c increment.
 *
 * WHAT: Computes CRC-32c over p[0..len] using Intel _mm_crc32_u64/u32/u8 intrinsics.
 *       Processes 8-byte chunks at a time, then 4-byte and byte tail. Returns
 *       extended checksum from initial crc value.
 *
 * WHY: Fast path for CRC-32c on x86_64 CPUs with SSE4.2 (most modern servers).
 *      Used by brix_crc32c_extend() when SSE4.2 is available. ~100x faster than
 *      software path for large buffers.
 *
 * HOW: XOR crc with 0xFFFFFFFF → uint64_t state. Loop: memcpy 8 bytes, _mm_crc32_u64;
 *      then 4-byte chunk if remaining >= 4; then byte-by-byte tail via _mm_crc32_u8.
 *      Final XOR complement. __attribute__((target("sse4.2")) ensures correct codegen.
 */

uint32_t
brix_crc32c_hw_extend(uint32_t crc, const unsigned char *p, size_t len)
{
    uint64_t state;

    state = (uint64_t) (crc ^ 0xFFFFFFFFu);

    while (len >= 8) {
        uint64_t v;

        memcpy(&v, p, 8);
        state = _mm_crc32_u64(state, v);
        p += 8;
        len -= 8;
    }

    if (len >= 4) {
        uint32_t v;

        memcpy(&v, p, 4);
        state = _mm_crc32_u32((uint32_t) state, v);
        p += 4;
        len -= 4;
    }

    while (len--) {
        state = _mm_crc32_u8((uint32_t) state, *p++);
    }

    return (uint32_t) state ^ 0xFFFFFFFFu;
}

__attribute__((target("sse4.2")))
/*
 * brix_crc32c_copy_hw - SSE4.2 hardware copy + CRC-32c in single pass.
 *
 * WHAT: Copies src[0..len] into dst while computing CRC-32c using _mm_crc32_u64/u32/u8
 *       intrinsics. Processes 8-byte chunks at a time, then 4-byte and byte tail.
 *
 * WHY: TPC data transfer on SSE4.2 CPUs — copy + checksum in one pass with hardware
 *      acceleration. Used by brix_crc32c_copy_value() when SSE4.2 available.
 *
 * HOW: Same loop structure as hw_extend but interleaves memcpy(dst, &v, N) after each
 *      _mm_crc32_uXX operation. Final XOR complement returns checksum result.
 */

uint32_t
brix_crc32c_copy_hw(const unsigned char *src, unsigned char *dst, size_t len)
{
    uint64_t state = 0xFFFFFFFFu;

    while (len >= 8) {
        uint64_t v;

        memcpy(&v, src, 8);
        state = _mm_crc32_u64(state, v);
        memcpy(dst, &v, 8);
        src += 8;
        dst += 8;
        len -= 8;
    }

    if (len >= 4) {
        uint32_t v;

        memcpy(&v, src, 4);
        state = _mm_crc32_u32((uint32_t) state, v);
        memcpy(dst, &v, 4);
        src += 4;
        dst += 4;
        len -= 4;
    }

    while (len--) {
        unsigned char b;

        b = *src++;
        state = _mm_crc32_u8((uint32_t) state, b);
        *dst++ = b;
    }

    return (uint32_t) state ^ 0xFFFFFFFFu;
}

/*
 * 3-way parallel hardware CRC-32c (Mark Adler's public-domain construction).
 *
 * WHAT: Computes CRC-32c over three interleaved streams of the buffer
 *       concurrently using independent _mm_crc32_u64 accumulators, then
 *       recombines the partial CRCs over GF(2) with precomputed "apply N zero
 *       bytes" operator tables.  Returns a value bit-identical to the serial
 *       brix_crc32c_hw_extend / software paths.
 *
 * WHY: The serial _mm_crc32_u64 loop is latency-bound — each instruction
 *      depends on the previous result (~3-cycle latency), capping it at roughly
 *      one 8-byte word per 3 cycles.  Three independent streams hide that
 *      latency behind the instruction's 1/cycle throughput for a ~3x speedup on
 *      the large buffers that dominate pgread/pgwrite and checksum scans.  This
 *      is a pure scheduling win: the wire CRC value is unchanged (Invariant #1).
 *
 * HOW: gf2_matrix_* build the linear operator that advances a CRC across a fixed
 *      power-of-two run of zero bytes; brix_crc32c_zeros() bakes that operator
 *      into byte-indexed lookup tables; brix_crc32c_shift() applies it.  The
 *      tables for the LONG (8192-byte) and SHORT (256-byte) block sizes are
 *      filled once at load time by a constructor (single-threaded, before any
 *      worker thread runs), so the hot path is table lookups + XORs only.
 */

#define BRIX_CRC32C_LONG  8192    /* must be a power of two */

static uint32_t brix_crc32c_long_tab[4][256];
static uint32_t brix_crc32c_short_tab[4][256];

/* Multiply the GF(2) vector `vec` by the 32x32 bit-matrix `mat`. */
static uint32_t
brix_gf2_matrix_times(const uint32_t *mat, uint32_t vec)
{
    uint32_t sum = 0;

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
brix_gf2_matrix_square(uint32_t *square, const uint32_t *mat)
{
    int n;

    for (n = 0; n < 32; n++) {
        square[n] = brix_gf2_matrix_times(mat, mat[n]);
    }
}

/*
 * Build, in `even`, the operator that advances a CRC across `len` zero bytes.
 * `len` must be a power of two (LONG and SHORT are).
 */
static void
brix_crc32c_zeros_op(uint32_t *even, size_t len)
{
    int      n;
    uint32_t row;
    uint32_t odd[32];

    /* Operator for a single shifted-in zero bit. */
    odd[0] = BRIX_CRC32C_POLY;
    row = 1;
    for (n = 1; n < 32; n++) {
        odd[n] = row;
        row <<= 1;
    }

    brix_gf2_matrix_square(even, odd);   /* two zero bits */
    brix_gf2_matrix_square(odd, even);   /* four zero bits */

    /* Square repeatedly (doubling the zero-run) until `len` is consumed. */
    do {
        brix_gf2_matrix_square(even, odd);
        len >>= 1;
        if (len == 0) {
            return;                         /* answer already in `even` */
        }
        brix_gf2_matrix_square(odd, even);
        len >>= 1;
    } while (len);

    for (n = 0; n < 32; n++) {
        even[n] = odd[n];                   /* answer ended up in `odd` */
    }
}

/* Bake a zeros-operator for `len` bytes into byte-indexed combine tables. */
static void
brix_crc32c_zeros(uint32_t zeros[][256], size_t len)
{
    uint32_t op[32];
    int      n;

    brix_crc32c_zeros_op(op, len);
    for (n = 0; n < 256; n++) {
        zeros[0][n] = brix_gf2_matrix_times(op, (uint32_t) n);
        zeros[1][n] = brix_gf2_matrix_times(op, (uint32_t) n << 8);
        zeros[2][n] = brix_gf2_matrix_times(op, (uint32_t) n << 16);
        zeros[3][n] = brix_gf2_matrix_times(op, (uint32_t) n << 24);
    }
}

/* Advance `crc` across the block length the tables were built for. */
static uint32_t
brix_crc32c_shift(uint32_t zeros[][256], uint32_t crc)
{
    return zeros[0][crc & 0xff]
         ^ zeros[1][(crc >> 8) & 0xff]
         ^ zeros[2][(crc >> 16) & 0xff]
         ^ zeros[3][(crc >> 24) & 0xff];
}

__attribute__((constructor))
static void
brix_crc32c_hw_tables_init(void)
{
    brix_crc32c_zeros(brix_crc32c_long_tab, BRIX_CRC32C_LONG);
    brix_crc32c_zeros(brix_crc32c_short_tab, BRIX_CRC32C_SHORT);
}

__attribute__((target("sse4.2")))
uint32_t
brix_crc32c_hw3_extend(uint32_t crc, const unsigned char *p, size_t len)
{
    uint64_t crc0, crc1, crc2;

    crc0 = (uint64_t) (crc ^ 0xFFFFFFFFu);

    /* Byte-by-byte until `p` is 8-byte aligned (aligned 64-bit loads below). */
    while (len != 0 && ((uintptr_t) p & 7u) != 0) {
        crc0 = _mm_crc32_u8((uint32_t) crc0, *p++);
        len--;
    }

    /* LONG blocks: three 8192-byte streams in parallel. */
    while (len >= BRIX_CRC32C_LONG * 3) {
        const unsigned char *end = p + BRIX_CRC32C_LONG;
        uint64_t             v0, v1, v2;

        crc1 = 0;
        crc2 = 0;
        do {
            memcpy(&v0, p, 8);
            memcpy(&v1, p + BRIX_CRC32C_LONG, 8);
            memcpy(&v2, p + BRIX_CRC32C_LONG * 2, 8);
            crc0 = _mm_crc32_u64(crc0, v0);
            crc1 = _mm_crc32_u64(crc1, v1);
            crc2 = _mm_crc32_u64(crc2, v2);
            p += 8;
        } while (p < end);

        crc0 = brix_crc32c_shift(brix_crc32c_long_tab, (uint32_t) crc0) ^ crc1;
        crc0 = brix_crc32c_shift(brix_crc32c_long_tab, (uint32_t) crc0) ^ crc2;
        p += BRIX_CRC32C_LONG * 2;
        len -= BRIX_CRC32C_LONG * 3;
    }

    /* SHORT blocks: three 256-byte streams in parallel. */
    while (len >= BRIX_CRC32C_SHORT * 3) {
        const unsigned char *end = p + BRIX_CRC32C_SHORT;
        uint64_t             v0, v1, v2;

        crc1 = 0;
        crc2 = 0;
        do {
            memcpy(&v0, p, 8);
            memcpy(&v1, p + BRIX_CRC32C_SHORT, 8);
            memcpy(&v2, p + BRIX_CRC32C_SHORT * 2, 8);
            crc0 = _mm_crc32_u64(crc0, v0);
            crc1 = _mm_crc32_u64(crc1, v1);
            crc2 = _mm_crc32_u64(crc2, v2);
            p += 8;
        } while (p < end);

        crc0 = brix_crc32c_shift(brix_crc32c_short_tab, (uint32_t) crc0) ^ crc1;
        crc0 = brix_crc32c_shift(brix_crc32c_short_tab, (uint32_t) crc0) ^ crc2;
        p += BRIX_CRC32C_SHORT * 2;
        len -= BRIX_CRC32C_SHORT * 3;
    }

    /* Serial tail. */
    while (len >= 8) {
        uint64_t v;

        memcpy(&v, p, 8);
        crc0 = _mm_crc32_u64(crc0, v);
        p += 8;
        len -= 8;
    }

    while (len--) {
        crc0 = _mm_crc32_u8((uint32_t) crc0, *p++);
    }

    return (uint32_t) crc0 ^ 0xFFFFFFFFu;
}

__attribute__((target("sse4.2")))
/*
 * brix_crc32c_copy_hw3 - SSE4.2 3-way-parallel copy + CRC-32c, single pass.
 *
 * WHAT: Copies src[0..len) into dst[0..len) and returns the CRC-32c of those
 *       bytes, computing the checksum with three independent _mm_crc32_u64
 *       accumulators recombined over GF(2). The copy+checksum analogue of
 *       brix_crc32c_hw3_extend.
 *
 * WHY: The serial brix_crc32c_copy_hw loop is latency-bound (~one 8-byte word
 *      per 3 cycles — the _mm_crc32_u64 dependency chain), so the pgread/pgwrite
 *      data plane, which fuses CRC with the copy on every 4 KiB page, spent a
 *      large share of CPU there (flame-graph profiling, docs/09-developer-guide).
 *      Three interleaved streams hide that latency behind the instruction's
 *      1/cycle throughput (~3x on the CRC compute). Pure scheduling win: returned
 *      checksum and copied bytes are bit-identical to the serial path
 *      (Invariant #1), so the wire value never changes.
 *
 * HOW: Identical block structure to brix_crc32c_hw3_extend (byte-align
 *      prologue, LONG then SHORT parallel triples, 8-byte then 1-byte serial
 *      tail) but a dst cursor advances in lockstep with src and every loaded word
 *      is written through to dst at its matching offset. dst alignment is
 *      irrelevant (unaligned word stores via memcpy). Buffers must not overlap;
 *      a fresh CRC is started (no incoming crc) to match brix_crc32c_copy_hw.
 */
uint32_t
brix_crc32c_copy_hw3(const unsigned char *src, unsigned char *dst, size_t len)
{
    uint64_t crc0, crc1, crc2;

    crc0 = (uint64_t) 0xFFFFFFFFu;

    /* Byte-by-byte until `src` is 8-byte aligned (aligned 64-bit loads below). */
    while (len != 0 && ((uintptr_t) src & 7u) != 0) {
        unsigned char b;

        b = *src++;
        *dst++ = b;
        crc0 = _mm_crc32_u8((uint32_t) crc0, b);
        len--;
    }

    /* LONG blocks: three 8192-byte streams copied + checksummed in parallel. */
    while (len >= BRIX_CRC32C_LONG * 3) {
        const unsigned char *end = src + BRIX_CRC32C_LONG;
        uint64_t             v0, v1, v2;

        crc1 = 0;
        crc2 = 0;
        do {
            memcpy(&v0, src, 8);
            memcpy(&v1, src + BRIX_CRC32C_LONG, 8);
            memcpy(&v2, src + BRIX_CRC32C_LONG * 2, 8);
            crc0 = _mm_crc32_u64(crc0, v0);
            crc1 = _mm_crc32_u64(crc1, v1);
            crc2 = _mm_crc32_u64(crc2, v2);
            memcpy(dst, &v0, 8);
            memcpy(dst + BRIX_CRC32C_LONG, &v1, 8);
            memcpy(dst + BRIX_CRC32C_LONG * 2, &v2, 8);
            src += 8;
            dst += 8;
        } while (src < end);

        crc0 = brix_crc32c_shift(brix_crc32c_long_tab, (uint32_t) crc0) ^ crc1;
        crc0 = brix_crc32c_shift(brix_crc32c_long_tab, (uint32_t) crc0) ^ crc2;
        src += BRIX_CRC32C_LONG * 2;
        dst += BRIX_CRC32C_LONG * 2;
        len -= BRIX_CRC32C_LONG * 3;
    }

    /* SHORT blocks: three 256-byte streams copied + checksummed in parallel. */
    while (len >= BRIX_CRC32C_SHORT * 3) {
        const unsigned char *end = src + BRIX_CRC32C_SHORT;
        uint64_t             v0, v1, v2;

        crc1 = 0;
        crc2 = 0;
        do {
            memcpy(&v0, src, 8);
            memcpy(&v1, src + BRIX_CRC32C_SHORT, 8);
            memcpy(&v2, src + BRIX_CRC32C_SHORT * 2, 8);
            crc0 = _mm_crc32_u64(crc0, v0);
            crc1 = _mm_crc32_u64(crc1, v1);
            crc2 = _mm_crc32_u64(crc2, v2);
            memcpy(dst, &v0, 8);
            memcpy(dst + BRIX_CRC32C_SHORT, &v1, 8);
            memcpy(dst + BRIX_CRC32C_SHORT * 2, &v2, 8);
            src += 8;
            dst += 8;
        } while (src < end);

        crc0 = brix_crc32c_shift(brix_crc32c_short_tab, (uint32_t) crc0) ^ crc1;
        crc0 = brix_crc32c_shift(brix_crc32c_short_tab, (uint32_t) crc0) ^ crc2;
        src += BRIX_CRC32C_SHORT * 2;
        dst += BRIX_CRC32C_SHORT * 2;
        len -= BRIX_CRC32C_SHORT * 3;
    }

    /* Serial 8-byte tail. */
    while (len >= 8) {
        uint64_t v;

        memcpy(&v, src, 8);
        crc0 = _mm_crc32_u64(crc0, v);
        memcpy(dst, &v, 8);
        src += 8;
        dst += 8;
        len -= 8;
    }

    /* Serial single-byte tail. */
    while (len--) {
        unsigned char b;

        b = *src++;
        *dst++ = b;
        crc0 = _mm_crc32_u8((uint32_t) crc0, b);
    }

    return (uint32_t) crc0 ^ 0xFFFFFFFFu;
}

#endif /* __x86_64__ */
