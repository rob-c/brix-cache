/* xorf.c — xor-8 negative-lookup filter (phase-87 G1). See xorf.h. */
#include "cvmfs/filter/xorf.h"
#include "core/fnv.h"

#include <stdlib.h>
#include <string.h>

/* ---- hashing ------------------------------------------------------------- */

uint64_t cvmfs_xorf_key(const char *path) {
    uint64_t h = BRIX_FNV1A64_OFFSET_BASIS;
    for (const unsigned char *p = (const unsigned char *) path; *p; p++)
        h = (h ^ *p) * BRIX_FNV1A64_PRIME;
    return h;
}

/* splitmix64 finalizer: spreads the (possibly weak) FNV key across all 64 bits
 * per seed attempt so the three block positions + fingerprint are independent. */
static uint64_t mix64(uint64_t x) {
    x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27; x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

static uint32_t reduce32(uint32_t x, uint32_t n) {
    return (uint32_t) (((uint64_t) x * n) >> 32);   /* fast unbiased-enough mod */
}

static uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

/* One cell per block for `key` under `seed`; also its 8-bit fingerprint. */
static void key_cells(uint64_t key, uint64_t seed, uint32_t block_len,
                      uint32_t idx[3], unsigned char *fp) {
    uint64_t h = mix64(key ^ seed);
    idx[0] = reduce32((uint32_t) h, block_len);
    idx[1] = block_len + reduce32((uint32_t) rotl64(h, 21), block_len);
    idx[2] = 2 * block_len + reduce32((uint32_t) rotl64(h, 42), block_len);
    *fp = (unsigned char) ((h ^ (h >> 32) ^ (h >> 16)) & 0xff);
}

/* ---- build --------------------------------------------------------------- */

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *) a, y = *(const uint64_t *) b;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* Sort + strip duplicate keys in place (FNV collisions between distinct paths
 * collapse to one membership entry — harmless: same key, same answer). */
static size_t dedup_keys(uint64_t *keys, size_t n) {
    if (n < 2) return n;
    qsort(keys, n, sizeof(*keys), cmp_u64);
    size_t out = 1;
    for (size_t i = 1; i < n; i++)
        if (keys[i] != keys[out - 1]) keys[out++] = keys[i];
    return out;
}

/* Peel-construction scratch: per-cell xor-of-keys + degree, a queue of
 * degree-1 cells, and the placement stack (cell + key, in peel order). */
typedef struct {
    uint64_t *cell_xor;
    uint32_t *cell_deg;
    uint32_t *queue;
    uint32_t *stack_cell;
    uint64_t *stack_key;
} peel_t;

static void peel_free(peel_t *p) {
    free(p->cell_xor); free(p->cell_deg); free(p->queue);
    free(p->stack_cell); free(p->stack_key);
    memset(p, 0, sizeof(*p));
}

static int peel_alloc(peel_t *p, uint32_t total, size_t n) {
    p->cell_xor   = calloc(total, sizeof(*p->cell_xor));
    p->cell_deg   = calloc(total, sizeof(*p->cell_deg));
    p->queue      = malloc((size_t) total * sizeof(*p->queue));
    p->stack_cell = malloc(n ? n * sizeof(*p->stack_cell) : sizeof(*p->stack_cell));
    p->stack_key  = malloc(n ? n * sizeof(*p->stack_key) : sizeof(*p->stack_key));
    if (p->cell_xor && p->cell_deg && p->queue && p->stack_cell && p->stack_key)
        return 0;
    peel_free(p);
    return -1;
}

/* One construction attempt under `seed`: returns the number of keys peeled
 * (== n means success) and leaves the placement stack filled that far. */
static size_t peel_attempt(peel_t *p, const uint64_t *keys, size_t n,
                           uint64_t seed, uint32_t block_len) {
    uint32_t total = 3 * block_len;
    memset(p->cell_xor, 0, (size_t) total * sizeof(*p->cell_xor));
    memset(p->cell_deg, 0, (size_t) total * sizeof(*p->cell_deg));

    uint32_t idx[3]; unsigned char fp;
    for (size_t i = 0; i < n; i++) {
        key_cells(keys[i], seed, block_len, idx, &fp);
        for (int j = 0; j < 3; j++) {
            p->cell_xor[idx[j]] ^= keys[i];
            p->cell_deg[idx[j]]++;
        }
    }

    size_t qn = 0;
    for (uint32_t c = 0; c < total; c++)
        if (p->cell_deg[c] == 1) p->queue[qn++] = c;

    size_t placed = 0;
    while (qn > 0) {
        uint32_t cell = p->queue[--qn];
        if (p->cell_deg[cell] != 1) continue;      /* went to 0 since queued */
        uint64_t key = p->cell_xor[cell];
        p->stack_cell[placed] = cell;
        p->stack_key[placed]  = key;
        placed++;
        key_cells(key, seed, block_len, idx, &fp);
        for (int j = 0; j < 3; j++) {
            p->cell_xor[idx[j]] ^= key;
            if (--p->cell_deg[idx[j]] == 1) p->queue[qn++] = idx[j];
        }
    }
    return placed;
}

int cvmfs_xorf_build(cvmfs_xorf_t *f, uint64_t *keys, size_t n) {
    memset(f, 0, sizeof(*f));
    if (n > CVMFS_XORF_MAX_KEYS) return -1;
    n = dedup_keys(keys, n);

    /* capacity ~1.23n + slack; /3 rounded up so 3 equal blocks cover it */
    uint64_t cap = 32 + n + n / 4 + n / 50;
    uint32_t block_len = (uint32_t) ((cap + 2) / 3);
    uint32_t total = 3 * block_len;

    peel_t p;
    if (peel_alloc(&p, total, n) != 0) return -1;

    uint64_t seed = 0;
    size_t placed = 0;
    for (int attempt = 0; attempt < 64; attempt++) {
        seed = mix64(0x9e3779b97f4a7c15ULL * (uint64_t) (attempt + 1));
        placed = peel_attempt(&p, keys, n, seed, block_len);
        if (placed == n) break;
    }
    if (placed != n) { peel_free(&p); return -1; }

    unsigned char *fparr = calloc(total, 1);
    if (fparr == NULL) { peel_free(&p); return -1; }

    /* assign in reverse peel order: the peeled cell is untouched by every later
     * (= earlier-peeled) key, so setting it fixes this key's xor equation */
    uint32_t idx[3]; unsigned char kfp;
    for (size_t i = placed; i > 0; i--) {
        uint32_t cell = p.stack_cell[i - 1];
        uint64_t key  = p.stack_key[i - 1];
        key_cells(key, seed, block_len, idx, &kfp);
        fparr[cell] = (unsigned char)
            (kfp ^ fparr[idx[0]] ^ fparr[idx[1]] ^ fparr[idx[2]] ^ fparr[cell]);
    }
    peel_free(&p);

    f->seed = seed;
    f->block_len = block_len;
    f->nkeys = (uint32_t) n;
    f->fp = fparr;
    return 0;
}

int cvmfs_xorf_query(const cvmfs_xorf_t *f, uint64_t key) {
    if (f->fp == NULL || f->block_len == 0) return 1;   /* no filter: maybe */
    uint32_t idx[3]; unsigned char fp;
    key_cells(key, f->seed, f->block_len, idx, &fp);
    return (f->fp[idx[0]] ^ f->fp[idx[1]] ^ f->fp[idx[2]]) == fp;
}

void cvmfs_xorf_reset(cvmfs_xorf_t *f) {
    free(f->fp);
    memset(f, 0, sizeof(*f));
}

/* ---- serialized form ----------------------------------------------------- *
 * Little-endian, hand-packed (arch-independent):
 *   0  magic "BXF1"            4
 *   4  u32 block_len
 *   8  u32 nkeys
 *  12  u32 root-hash algo
 *  16  u64 seed
 *  24  root-hash bytes         20
 *  44  fingerprints            3*block_len
 *   +  u64 FNV-1a64 checksum over everything above
 */

static void put_u32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char) v;         p[1] = (unsigned char) (v >> 8);
    p[2] = (unsigned char) (v >> 16); p[3] = (unsigned char) (v >> 24);
}

static void put_u64(unsigned char *p, uint64_t v) {
    put_u32(p, (uint32_t) v);
    put_u32(p + 4, (uint32_t) (v >> 32));
}

static uint32_t get_u32(const unsigned char *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static uint64_t get_u64(const unsigned char *p) {
    return (uint64_t) get_u32(p) | ((uint64_t) get_u32(p + 4) << 32);
}

static uint64_t fnv1a64(const unsigned char *p, size_t n) {
    uint64_t h = BRIX_FNV1A64_OFFSET_BASIS;
    for (size_t i = 0; i < n; i++)
        h = (h ^ p[i]) * BRIX_FNV1A64_PRIME;
    return h;
}

size_t cvmfs_xorf_size(const cvmfs_xorf_t *f) {
    return CVMFS_XORF_HEADER_LEN + (size_t) 3 * f->block_len + 8;
}

int cvmfs_xorf_serialize(const cvmfs_xorf_t *f, const cvmfs_hash_t *root,
                         unsigned char *out, size_t cap, size_t *outlen) {
    size_t need = cvmfs_xorf_size(f);
    if (f->fp == NULL || cap < need) return -1;
    memcpy(out, CVMFS_XORF_MAGIC, 4);
    put_u32(out + 4, f->block_len);
    put_u32(out + 8, f->nkeys);
    put_u32(out + 12, (uint32_t) root->algo);
    put_u64(out + 16, f->seed);
    memcpy(out + 24, root->bytes, 20);
    memcpy(out + CVMFS_XORF_HEADER_LEN, f->fp, (size_t) 3 * f->block_len);
    put_u64(out + need - 8, fnv1a64(out, need - 8));
    *outlen = need;
    return 0;
}

int cvmfs_xorf_deserialize(cvmfs_xorf_t *f, cvmfs_hash_t *root,
                           const unsigned char *in, size_t len) {
    memset(f, 0, sizeof(*f));
    if (len < CVMFS_XORF_HEADER_LEN + 8) return -1;
    if (memcmp(in, CVMFS_XORF_MAGIC, 4) != 0) return -1;

    uint32_t block_len = get_u32(in + 4);
    uint32_t nkeys     = get_u32(in + 8);
    uint32_t algo      = get_u32(in + 12);
    if (block_len == 0 || block_len > CVMFS_XORF_MAX_KEYS
        || nkeys > CVMFS_XORF_MAX_KEYS || algo > CVMFS_HASH_SHAKE128)
        return -1;
    size_t need = CVMFS_XORF_HEADER_LEN + (size_t) 3 * block_len + 8;
    if (len != need) return -1;
    if (get_u64(in + need - 8) != fnv1a64(in, need - 8)) return -1;

    unsigned char *fp = malloc((size_t) 3 * block_len);
    if (fp == NULL) return -1;
    memcpy(fp, in + CVMFS_XORF_HEADER_LEN, (size_t) 3 * block_len);

    if (cvmfs_hash_from_bytes((cvmfs_hash_algo_e) algo, in + 24, 20, root) != 0) {
        free(fp);
        return -1;
    }
    f->seed = get_u64(in + 16);
    f->block_len = block_len;
    f->nkeys = nkeys;
    f->fp = fp;
    return 0;
}
