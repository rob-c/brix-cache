/*
 * test_cinfo.c — standalone unit tests for the .cinfo block-present bitmap
 * sidecar (src/cache/cinfo.c), Phase-58 §9.
 *
 * Links against the real compiled cinfo.o (no running server, no nginx
 * runtime).  cinfo.o references only libc, so no stubs are needed; this file
 * mirrors the on-disk struct layout and the public prototypes exactly (the
 * struct is read/written verbatim, so the mirror MUST stay byte-compatible with
 * src/cache/cinfo.h).
 *
 * Build/run via tests/c/run_cinfo_tests.sh (compiled into tests/test_slice_cache.py).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef uintptr_t ngx_uint_t;
typedef intptr_t  ngx_int_t;

#define NGX_OK        0
#define NGX_ERROR    -1
#define NGX_DECLINED -5

#define META_ETAG_MAX 55
#define CINFO_MAGIC   0x58434931u
#define CINFO_VERSION 3
#define F_COMPLETE 0x0001u
#define F_PARTIAL  0x0002u
#define F_VERIFIED 0x0004u
#define F_DIRTY    0x0008u

/* Mirror of xrootd_cache_meta_t (only the fields from_meta reads). The trailing
 * layout must match src/cache/meta.h for the struct passed by value. */
typedef struct {
    uint64_t mtime;
    uint64_t size;
    uint8_t  etag_len;
    char     etag[META_ETAG_MAX];
    uint8_t  version;
    uint64_t access_count;
    uint64_t last_access;
    uint64_t bytes_served;
    uint8_t  cks_alg_len;
    char     cks_alg[16];
    uint8_t  cks_len;
    char     cks_hex[129];
} xrootd_cache_meta_t;

/* Mirror of xrootd_cache_cinfo_t (layout must match src/cache/cinfo.h). */
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t block_size;
    uint32_t mode;
    uint64_t size;
    uint64_t mtime;
    uint64_t nblocks;
    uint64_t access_count;
    uint64_t bytes_served;
    uint64_t last_access;
    uint64_t dirty_lo;
    uint64_t dirty_hi;
    uint64_t dirty_since;
    uint64_t flush_gen;
    uint64_t last_flush;
    uint64_t bytes_flushed;
    uint8_t  etag_len;
    char     etag[META_ETAG_MAX];
    uint8_t  cks_alg_len;
    char     cks_alg[16];
    uint8_t  cks_len;
    char     cks_hex[129];
} xrootd_cache_cinfo_t;

/* Frozen v2 mirror (no write-back fields) for the upgrade test. */
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t block_size;
    uint32_t reserved;
    uint64_t size;
    uint64_t mtime;
    uint64_t nblocks;
    uint64_t access_count;
    uint64_t bytes_served;
    uint64_t last_access;
    uint8_t  etag_len;
    char     etag[META_ETAG_MAX];
    uint8_t  cks_alg_len;
    char     cks_alg[16];
    uint8_t  cks_len;
    char     cks_hex[129];
} xrootd_cache_cinfo_v2_t;

/* ---- prototypes (defined in cinfo.o) ---- */
uint64_t xrootd_cache_cinfo_nblocks(uint64_t size, uint32_t block_size);
size_t   xrootd_cache_cinfo_bitmap_len(uint64_t nblocks);
void     xrootd_cache_cinfo_mark_block(uint8_t *bitmap, uint64_t blk);
int      xrootd_cache_cinfo_block_present(const uint8_t *bitmap, uint64_t blk);
uint64_t xrootd_cache_cinfo_present_count(const uint8_t *bitmap, uint64_t nblocks);
void     xrootd_cache_cinfo_refresh_flags(xrootd_cache_cinfo_t *hdr,
             const uint8_t *bitmap);
int      xrootd_cache_cinfo_path(char *dst, size_t dstsz, const char *cache_path);
ngx_int_t xrootd_cache_cinfo_load(const char *cache_path,
             xrootd_cache_cinfo_t *hdr, uint8_t **bitmap, size_t *bitmap_len);
ngx_int_t xrootd_cache_cinfo_store(const char *cache_path,
             const xrootd_cache_cinfo_t *hdr, const uint8_t *bitmap,
             size_t bitmap_len);
ngx_int_t xrootd_cache_cinfo_from_meta(const xrootd_cache_meta_t *m,
             uint32_t block_size, xrootd_cache_cinfo_t *out);
ngx_int_t xrootd_cache_cinfo_record_block(const char *cache_path, uint64_t size,
             uint32_t block_size, uint64_t mtime, uint32_t mode, uint64_t blk,
             void *log);
ngx_int_t xrootd_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size,
             uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len,
             void *log);
ngx_int_t xrootd_cache_cinfo_mark_clean(const char *cache_path, uint64_t bytes,
             void *log);
ngx_int_t xrootd_cache_cinfo_dirty_extent(const char *cache_path, uint64_t *lo,
             uint64_t *hi, uint64_t *dirty_since);

/* ---- harness ---- */
static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do {                                              \
        if (cond) { g_pass++; }                                            \
        else { g_fail++; printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

static char g_dir[PATH_MAX];
static char g_cache[PATH_MAX];   /* a cache-file path inside g_dir */

static void
setup_tmp(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/test_cinfo.XXXXXX");
    if (mkdtemp(g_dir) == NULL) { perror("mkdtemp"); exit(2); }
    snprintf(g_cache, sizeof(g_cache), "%s/file.bin", g_dir);
}

static const uint32_t BS = 1024 * 1024;   /* 1 MiB block granule */

/* ---- pure math + bit ops ---- */
static void
test_math(void)
{
    CHECK(xrootd_cache_cinfo_nblocks(0, BS) == 0, "nblocks(0)=0");
    CHECK(xrootd_cache_cinfo_nblocks(100, 0) == 0, "nblocks(bs=0)=0");
    CHECK(xrootd_cache_cinfo_nblocks(BS, BS) == 1, "exact 1 block");
    CHECK(xrootd_cache_cinfo_nblocks(BS + 1, BS) == 2, "+1 byte -> 2 blocks");
    CHECK(xrootd_cache_cinfo_nblocks(16 * (uint64_t) BS, BS) == 16, "16 blocks");
    CHECK(xrootd_cache_cinfo_bitmap_len(0) == 0, "bitmap_len(0)=0");
    CHECK(xrootd_cache_cinfo_bitmap_len(1) == 1, "bitmap_len(1)=1");
    CHECK(xrootd_cache_cinfo_bitmap_len(8) == 1, "bitmap_len(8)=1");
    CHECK(xrootd_cache_cinfo_bitmap_len(9) == 2, "bitmap_len(9)=2");
    CHECK(xrootd_cache_cinfo_bitmap_len(16) == 2, "bitmap_len(16)=2");
}

static void
test_bitops(void)
{
    uint8_t bm[4];
    memset(bm, 0, sizeof(bm));
    xrootd_cache_cinfo_mark_block(bm, 0);
    xrootd_cache_cinfo_mark_block(bm, 7);
    xrootd_cache_cinfo_mark_block(bm, 12);
    CHECK(xrootd_cache_cinfo_block_present(bm, 0), "bit 0 set");
    CHECK(xrootd_cache_cinfo_block_present(bm, 7), "bit 7 set");
    CHECK(xrootd_cache_cinfo_block_present(bm, 12), "bit 12 set");
    CHECK(!xrootd_cache_cinfo_block_present(bm, 1), "bit 1 clear");
    CHECK(!xrootd_cache_cinfo_block_present(bm, 8), "bit 8 clear");
    CHECK(xrootd_cache_cinfo_present_count(bm, 32) == 3, "present_count=3");
}

static void
test_refresh_flags(void)
{
    xrootd_cache_cinfo_t h;
    uint8_t bm[2];

    memset(&h, 0, sizeof(h));
    h.nblocks = 16;
    memset(bm, 0, sizeof(bm));
    xrootd_cache_cinfo_refresh_flags(&h, bm);
    CHECK(!(h.flags & F_COMPLETE) && !(h.flags & F_PARTIAL), "empty -> no flags");

    xrootd_cache_cinfo_mark_block(bm, 3);
    xrootd_cache_cinfo_refresh_flags(&h, bm);
    CHECK((h.flags & F_PARTIAL) && !(h.flags & F_COMPLETE), "some -> PARTIAL");

    memset(bm, 0xff, sizeof(bm));
    xrootd_cache_cinfo_refresh_flags(&h, bm);
    CHECK((h.flags & F_COMPLETE) && !(h.flags & F_PARTIAL), "all -> COMPLETE");

    h.nblocks = 0;
    xrootd_cache_cinfo_refresh_flags(&h, bm);
    CHECK(h.flags & F_COMPLETE, "0 blocks -> COMPLETE");
}

static void
test_path(void)
{
    char out[PATH_MAX];
    CHECK(xrootd_cache_cinfo_path(out, sizeof(out), "/a/b.bin") == 0
          && strcmp(out, "/a/b.bin.cinfo") == 0, "path appends .cinfo");
    CHECK(xrootd_cache_cinfo_path(out, 4, "/aaa/bbb.bin") == -1, "path overflow -> -1");
}

/* ---- store/load roundtrip + corruption handling ---- */
static void
test_store_load(void)
{
    xrootd_cache_cinfo_t h, r;
    uint8_t *rbm = NULL;
    size_t   rlen = 0, blen;
    uint8_t  bm[2];

    memset(&h, 0, sizeof(h));
    h.block_size = BS;
    h.size = 16 * (uint64_t) BS;
    h.mtime = 123456;
    h.nblocks = 16;
    h.access_count = 5;
    h.bytes_served = 999;
    blen = xrootd_cache_cinfo_bitmap_len(h.nblocks);
    memset(bm, 0, sizeof(bm));
    xrootd_cache_cinfo_mark_block(bm, 2);
    xrootd_cache_cinfo_mark_block(bm, 9);
    xrootd_cache_cinfo_refresh_flags(&h, bm);

    CHECK(xrootd_cache_cinfo_store(g_cache, &h, bm, blen) == NGX_OK, "store ok");
    CHECK(xrootd_cache_cinfo_load(g_cache, &r, &rbm, &rlen) == NGX_OK, "load ok");
    CHECK(r.magic == CINFO_MAGIC && r.version == CINFO_VERSION, "magic/version");
    CHECK(r.block_size == BS && r.size == h.size && r.nblocks == 16, "header validity");
    CHECK(r.mtime == 123456 && r.access_count == 5 && r.bytes_served == 999, "stats");
    CHECK(rlen == blen, "bitmap len matches");
    CHECK(rbm && xrootd_cache_cinfo_block_present(rbm, 2)
          && xrootd_cache_cinfo_block_present(rbm, 9)
          && !xrootd_cache_cinfo_block_present(rbm, 0), "bitmap bits roundtrip");
    CHECK(r.flags & F_PARTIAL, "PARTIAL persisted");
    free(rbm);

    /* on-disk size is exactly header + bitmap */
    {
        char p[PATH_MAX];
        struct stat st;
        xrootd_cache_cinfo_path(p, sizeof(p), g_cache);
        CHECK(stat(p, &st) == 0
              && (size_t) st.st_size == sizeof(xrootd_cache_cinfo_t) + blen,
              "file size == header+bitmap");
    }
}

static void
test_load_missing(void)
{
    xrootd_cache_cinfo_t r;
    uint8_t *rbm = NULL;
    size_t   rlen = 0;
    char     p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/nope.bin", g_dir);
    CHECK(xrootd_cache_cinfo_load(p, &r, &rbm, &rlen) == NGX_DECLINED,
          "absent -> DECLINED");
    CHECK(rbm == NULL, "no bitmap allocated on miss");
}

static void
test_load_garbage(void)
{
    xrootd_cache_cinfo_t r;
    uint8_t *rbm = NULL;
    size_t   rlen = 0;
    char     p[PATH_MAX], cp[PATH_MAX];
    int      fd;

    snprintf(p, sizeof(p), "%s/garbage.bin", g_dir);
    xrootd_cache_cinfo_path(cp, sizeof(cp), p);

    /* truncated (a few bytes) */
    fd = open(cp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    (void) !write(fd, "XX", 2);
    close(fd);
    CHECK(xrootd_cache_cinfo_load(p, &r, &rbm, &rlen) == NGX_DECLINED,
          "truncated -> DECLINED");

    /* full-size header but wrong magic */
    {
        xrootd_cache_cinfo_t bad;
        memset(&bad, 0, sizeof(bad));
        bad.magic = 0xdeadbeef;
        bad.block_size = BS;
        bad.size = BS;
        bad.nblocks = 1;
        fd = open(cp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        (void) !write(fd, &bad, sizeof(bad));
        (void) !write(fd, "\0", 1);
        close(fd);
        CHECK(xrootd_cache_cinfo_load(p, &r, &rbm, &rlen) == NGX_DECLINED,
              "bad magic -> DECLINED");
    }
}

static void
test_from_meta(void)
{
    xrootd_cache_meta_t m;
    xrootd_cache_cinfo_t out;
    memset(&m, 0, sizeof(m));
    m.size = 10 * (uint64_t) BS;
    m.mtime = 777;
    m.access_count = 3;
    m.bytes_served = 42;
    CHECK(xrootd_cache_cinfo_from_meta(&m, BS, &out) == NGX_OK, "from_meta ok");
    CHECK(out.flags & F_COMPLETE, "migrated -> COMPLETE");
    CHECK(out.size == m.size && out.mtime == 777 && out.nblocks == 10, "validity carried");
    CHECK(out.access_count == 3 && out.bytes_served == 42, "stats carried");
    CHECK(xrootd_cache_cinfo_from_meta(&m, 0, &out) == NGX_ERROR, "bs=0 -> ERROR");
}

/* ---- record_block: the record-keeping entry point ---- */
static void
test_record_block(void)
{
    xrootd_cache_cinfo_t r;
    uint8_t *rbm = NULL;
    size_t   rlen = 0;
    uint64_t size = 16 * (uint64_t) BS;
    char     rc_cache[PATH_MAX];
    snprintf(rc_cache, sizeof(rc_cache), "%s/rec.bin", g_dir);

    /* fresh record of one block -> PARTIAL, only that bit */
    CHECK(xrootd_cache_cinfo_record_block(rc_cache, size, BS, 0, 0, 2, NULL) == NGX_OK,
          "record block 2");
    CHECK(xrootd_cache_cinfo_load(rc_cache, &r, &rbm, &rlen) == NGX_OK, "load after record");
    CHECK((r.flags & F_PARTIAL) && xrootd_cache_cinfo_block_present(rbm, 2)
          && xrootd_cache_cinfo_present_count(rbm, 16) == 1, "one block present");
    free(rbm);

    /* a second, different block accumulates (read-modify-write merge) */
    CHECK(xrootd_cache_cinfo_record_block(rc_cache, size, BS, 0, 0, 9, NULL) == NGX_OK,
          "record block 9");
    CHECK(xrootd_cache_cinfo_load(rc_cache, &r, &rbm, &rlen) == NGX_OK, "load 2");
    CHECK(xrootd_cache_cinfo_block_present(rbm, 2)
          && xrootd_cache_cinfo_block_present(rbm, 9)
          && xrootd_cache_cinfo_present_count(rbm, 16) == 2, "both blocks present");
    free(rbm);

    /* out-of-range block -> ERANGE/ERROR, record unchanged */
    CHECK(xrootd_cache_cinfo_record_block(rc_cache, size, BS, 0, 0, 99, NULL) == NGX_ERROR,
          "out-of-range -> ERROR");

    /* recording all blocks -> COMPLETE */
    {
        uint64_t b;
        for (b = 0; b < 16; b++) {
            xrootd_cache_cinfo_record_block(rc_cache, size, BS, 0, 0, b, NULL);
        }
        CHECK(xrootd_cache_cinfo_load(rc_cache, &r, &rbm, &rlen) == NGX_OK, "load full");
        CHECK((r.flags & F_COMPLETE) && xrootd_cache_cinfo_present_count(rbm, 16) == 16,
              "all blocks -> COMPLETE");
        free(rbm);
    }

    /* a non-zero mode is recorded in the header; 0 leaves it unchanged. */
    {
        char m_cache[PATH_MAX];
        snprintf(m_cache, sizeof(m_cache), "%s/mode.bin", g_dir);
        CHECK(xrootd_cache_cinfo_record_block(m_cache, size, BS, 0, 0644, 0, NULL)
              == NGX_OK, "record block with mode 0644");
        CHECK(xrootd_cache_cinfo_load(m_cache, &r, &rbm, &rlen) == NGX_OK, "load mode");
        CHECK(r.mode == 0644, "origin mode persisted in cinfo header");
        free(rbm);
    }
}

static void
test_record_block_stale_reset(void)
{
    xrootd_cache_cinfo_t r;
    uint8_t *rbm = NULL;
    size_t   rlen = 0;
    char     c[PATH_MAX];
    snprintf(c, sizeof(c), "%s/stale.bin", g_dir);

    /* record a block for a 16-block file */
    xrootd_cache_cinfo_record_block(c, 16 * (uint64_t) BS, BS, 100, 0, 5, NULL);
    /* the origin file changed (new size + mtime): the old bitmap is stale and
     * must be reset, leaving only the freshly-recorded block. */
    CHECK(xrootd_cache_cinfo_record_block(c, 8 * (uint64_t) BS, BS, 200, 0, 1, NULL) == NGX_OK,
          "record after origin change");
    CHECK(xrootd_cache_cinfo_load(c, &r, &rbm, &rlen) == NGX_OK, "load reset");
    CHECK(r.size == 8 * (uint64_t) BS && r.mtime == 200 && r.nblocks == 8,
          "validity updated to new origin");
    CHECK(xrootd_cache_cinfo_block_present(rbm, 1)
          && xrootd_cache_cinfo_present_count(rbm, 8) == 1,
          "stale bitmap reset; only new block present");
    free(rbm);
}

/* ---- v3 write-back (dirty) state ---- */
static void
test_v3_dirty_fields_roundtrip(void)
{
    xrootd_cache_cinfo_t h, r;
    uint8_t *rbm = NULL;
    size_t   rlen = 0;
    uint8_t  bm[1] = { 0x03 };
    char     c[PATH_MAX];
    snprintf(c, sizeof(c), "%s/v3.bin", g_dir);

    memset(&h, 0, sizeof(h));
    h.block_size = BS; h.size = 2 * (uint64_t) BS; h.mtime = 1000;
    h.nblocks = xrootd_cache_cinfo_nblocks(h.size, h.block_size);
    h.flags |= F_DIRTY;
    h.dirty_lo = 100; h.dirty_hi = 500; h.dirty_since = 1700000000ULL;
    h.flush_gen = 7; h.last_flush = 1700000001ULL; h.bytes_flushed = BS;

    CHECK(xrootd_cache_cinfo_store(c, &h, bm, 1) == NGX_OK, "store v3 record");
    CHECK(xrootd_cache_cinfo_load(c, &r, &rbm, &rlen) == NGX_OK, "load v3 record");
    CHECK(r.version == CINFO_VERSION, "version is 3");
    CHECK((r.flags & F_DIRTY) && r.dirty_lo == 100 && r.dirty_hi == 500,
          "dirty flag + extent survive");
    CHECK(r.dirty_since == 1700000000ULL && r.flush_gen == 7
          && r.last_flush == 1700000001ULL && r.bytes_flushed == BS,
          "write-back fields survive");
    free(rbm);
}

static void
test_v2_loads_present_only(void)
{
    xrootd_cache_cinfo_t r;
    uint8_t *rbm = NULL;
    size_t   rlen = 0;
    xrootd_cache_cinfo_v2_t v2;
    char     c[PATH_MAX], sc[PATH_MAX];
    int      fd;
    uint8_t  b = 0x03;
    snprintf(c, sizeof(c), "%s/old.bin", g_dir);
    CHECK(xrootd_cache_cinfo_path(sc, sizeof(sc), c) == 0, "v2 sidecar path");

    memset(&v2, 0, sizeof(v2));
    v2.magic = CINFO_MAGIC; v2.version = 2;
    v2.block_size = BS; v2.size = 2 * (uint64_t) BS; v2.mtime = 1000;
    v2.nblocks = 2;
    fd = open(sc, O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0, "open v2 sidecar");
    CHECK(write(fd, &v2, sizeof(v2)) == (ssize_t) sizeof(v2), "write v2 header");
    CHECK(write(fd, &b, 1) == 1, "write v2 bitmap");
    close(fd);

    CHECK(xrootd_cache_cinfo_load(c, &r, &rbm, &rlen) == NGX_OK, "load v2 record");
    CHECK(r.version == CINFO_VERSION, "v2 promoted to v3");
    CHECK(!(r.flags & F_DIRTY) && r.dirty_since == 0, "upgraded record is clean");
    CHECK(rlen == 1 && rbm != NULL && xrootd_cache_cinfo_block_present(rbm, 0)
          && xrootd_cache_cinfo_block_present(rbm, 1), "present bitmap preserved");
    free(rbm);
}

static void
test_dirty_lifecycle(void)
{
    xrootd_cache_cinfo_t r;
    uint8_t *rbm = NULL;
    size_t   rlen = 0;
    uint64_t lo, hi, ds, first_since;
    char     c[PATH_MAX];
    snprintf(c, sizeof(c), "%s/w.bin", g_dir);

    CHECK(xrootd_cache_cinfo_dirty_extent(c, &lo, &hi, &ds) == NGX_DECLINED,
          "no record -> DECLINED");

    CHECK(xrootd_cache_cinfo_mark_dirty(c, 2 * (uint64_t) BS, BS, 1000, 100, 200, NULL) == NGX_OK,
          "first dirty [100,300)");
    CHECK(xrootd_cache_cinfo_dirty_extent(c, &lo, &hi, &ds) == NGX_OK
          && lo == 100 && hi == 300 && ds != 0, "extent + dirty_since set");
    first_since = ds;

    CHECK(xrootd_cache_cinfo_mark_dirty(c, 2 * (uint64_t) BS, BS, 1000, 500, 100, NULL) == NGX_OK,
          "widen to [100,600)");
    CHECK(xrootd_cache_cinfo_dirty_extent(c, &lo, &hi, &ds) == NGX_OK
          && lo == 100 && hi == 600 && ds == first_since,
          "widened; dirty_since unchanged");

    CHECK(xrootd_cache_cinfo_mark_clean(c, 500, NULL) == NGX_OK, "mark clean");
    CHECK(xrootd_cache_cinfo_dirty_extent(c, &lo, &hi, &ds) == NGX_DECLINED,
          "clean -> DECLINED");
    CHECK(xrootd_cache_cinfo_load(c, &r, &rbm, &rlen) == NGX_OK, "load after clean");
    CHECK(r.flush_gen == 1 && r.bytes_flushed == 500 && r.last_flush != 0,
          "flush_gen/bytes/last_flush updated");
    free(rbm);
}

static void
test_present_and_dirty_coexist(void)
{
    xrootd_cache_cinfo_t r;
    uint8_t *rbm = NULL;
    size_t   rlen = 0;
    char     c[PATH_MAX];
    snprintf(c, sizeof(c), "%s/coex.bin", g_dir);

    CHECK(xrootd_cache_cinfo_record_block(c, 2 * (uint64_t) BS, BS, 1000, 0, 0, NULL) == NGX_OK,
          "record present block 0");
    CHECK(xrootd_cache_cinfo_mark_dirty(c, 2 * (uint64_t) BS, BS, 1000, 0, 100, NULL) == NGX_OK,
          "mark dirty");
    CHECK(xrootd_cache_cinfo_record_block(c, 2 * (uint64_t) BS, BS, 1000, 0, 1, NULL) == NGX_OK,
          "record present block 1");
    CHECK(xrootd_cache_cinfo_load(c, &r, &rbm, &rlen) == NGX_OK, "load coexist");
    CHECK(xrootd_cache_cinfo_block_present(rbm, 0)
          && xrootd_cache_cinfo_block_present(rbm, 1), "both present bits survive");
    CHECK((r.flags & F_DIRTY) && r.dirty_lo == 0 && r.dirty_hi == 100,
          "dirty extent survived two block records");
    free(rbm);
}

int
main(void)
{
    setup_tmp();
    test_math();
    test_bitops();
    test_refresh_flags();
    test_path();
    test_store_load();
    test_load_missing();
    test_load_garbage();
    test_from_meta();
    test_record_block();
    test_record_block_stale_reset();
    test_v3_dirty_fields_roundtrip();
    test_v2_loads_present_only();
    test_dirty_lifecycle();
    test_present_and_dirty_coexist();

    printf("cinfo unit tests: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
