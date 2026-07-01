/*
 * cephfs_layout_unittest.c — unit tests for the CephFS metadata decoders.
 *
 * Two kinds of test:
 *  1. REAL fixtures — byte-exact reef-18.2.4 dentry omap values captured from a
 *     live cluster (the fixtures/reef-18.2.4 .bin files). Asserts the decoder
 *     recovers the known seed values (ino / mode / size / layout).
 *  2. SYNTHETIC inodes — hand-built inode_t buffers at older struct_v (2, 4) to
 *     prove the version guards (dir_layout @ v>=4, truncate_pending @ v>=5) are
 *     honoured, i.e. multi-version decoding works without an old cluster.
 *
 *   cc -I src/fs/backend/rados tests/ceph/cephfs_layout_unittest.c \
 *      src/fs/backend/rados/cephfs_layout.c src/fs/backend/rados/cephfs_denc.c \
 *      -o /tmp/layout_test && /tmp/layout_test [fixture_dir]
 */
#include "cephfs_layout.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);           \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* ---- a tiny Ceph-encoder, just for building synthetic test buffers ------- */
typedef struct { uint8_t b[512]; size_t n; } buf_t;

static void put8 (buf_t *o, uint8_t v)  { o->b[o->n++] = v; }
static void put32(buf_t *o, uint32_t v) { int i; for (i=0;i<4;i++) put8(o,(uint8_t)(v>>(8*i))); }
static void put64(buf_t *o, uint64_t v) { int i; for (i=0;i<8;i++) put8(o,(uint8_t)(v>>(8*i))); }
static void pututime(buf_t *o, uint32_t s, uint32_t ns) { put32(o,s); put32(o,ns); }

/* write a frame header with a placeholder length, return the offset of the len
 * field so it can be patched once the payload is written */
static size_t frame_begin(buf_t *o, uint8_t v, uint8_t compat)
{
    size_t lenpos;
    put8(o, v); put8(o, compat);
    lenpos = o->n;
    put32(o, 0);            /* placeholder */
    return lenpos;
}
static void frame_end(buf_t *o, size_t lenpos)
{
    uint32_t len = (uint32_t) (o->n - (lenpos + 4));
    int i;
    for (i = 0; i < 4; i++) o->b[lenpos + i] = (uint8_t) (len >> (8 * i));
}

/* a framed file_layout_t (v2): stripe_unit, stripe_count, object_size, pool_id, ns */
static void put_file_layout(buf_t *o, uint32_t su, uint32_t sc, uint32_t os, int64_t pool)
{
    size_t lp = frame_begin(o, 2, 2);
    put32(o, su); put32(o, sc); put32(o, os);
    put64(o, (uint64_t) pool);
    put32(o, 0);               /* pool_ns: empty string */
    frame_end(o, lp);
}

/* a synthetic inode_t at a given struct_v with the fields up to mtime. */
static void put_inode(buf_t *o, uint8_t struct_v, uint64_t ino, uint32_t mode,
                      uint64_t size, uint32_t mt_sec)
{
    size_t lp = frame_begin(o, struct_v, 6);
    put64(o, ino);             /* ino   */
    put32(o, 0);               /* rdev  */
    pututime(o, 100, 0);       /* ctime */
    put32(o, mode);            /* mode  */
    put32(o, 0);               /* uid   */
    put32(o, 0);               /* gid   */
    put32(o, 1);               /* nlink */
    put8(o, 0);                /* anchored (bool) */
    if (struct_v >= 4) {
        int i; for (i = 0; i < 8; i++) put8(o, 0);   /* dir_layout */
    }
    put_file_layout(o, 0x400000, 1, 0x400000, 7);    /* layout */
    put64(o, size);            /* size           */
    put32(o, 1);               /* truncate_seq   */
    put64(o, ~0ull);           /* truncate_size  */
    put64(o, 0);               /* truncate_from  */
    if (struct_v >= 5) {
        put32(o, 0);           /* truncate_pending */
    }
    pututime(o, mt_sec, 0);    /* mtime */
    /* trailing fields a real inode has; the decoder must frame-skip them */
    put64(o, 0); put64(o, 0);
    frame_end(o, lp);
}

/* ---- synthetic version-guard tests --------------------------------------- */
static void
test_inode_versions(void)
{
    uint8_t versions[] = { 2, 3, 4, 5, 11, 14, 19 };
    size_t  i;

    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        buf_t          o = { {0}, 0 };
        cephfs_denc_t  d;
        cephfs_inode_t in;

        put_inode(&o, versions[i], 0x1234, CEPHFS_S_IFREG | 0644, 4096, 555);
        cephfs_denc_init(&d, o.b, o.n);
        CHECK(cephfs_decode_inode(&d, &in) == 0);
        CHECK(in.struct_v == versions[i]);
        CHECK(in.ino == 0x1234);
        CHECK(cephfs_mode_is_reg(in.mode));
        CHECK(in.size == 4096);
        CHECK(in.mtime_sec == 555);
        CHECK(in.layout.object_size == 0x400000);
        CHECK(in.layout.stripe_count == 1);
        CHECK(in.layout.pool_id == 7);
        if (failures) { printf("  (failed at struct_v=%u)\n", versions[i]); break; }
    }
}

/* ---- fragtree leaf computation (synthetic split maps) -------------------- */
static void
test_fragtree(void)
{
    /* empty split map -> single leaf 0 ("00000000") */
    {
        buf_t o = { {0}, 0 }; cephfs_denc_t d; uint32_t leaves[16], n; int tr;
        put32(&o, 0);
        cephfs_denc_init(&d, o.b, o.n);
        CHECK(cephfs_decode_fragtree(&d, leaves, 16, &n, &tr) == 0);
        CHECK(n == 1 && leaves[0] == 0 && tr == 0);
    }
    /* root split into 2 (1 bit): leaves are frag(1,0) and frag(1,1):
     * enc = (bits<<24)|value -> 0x01000000 and 0x01000001 */
    {
        buf_t o = { {0}, 0 }; cephfs_denc_t d; uint32_t leaves[16], n; int tr;
        uint32_t got0 = 0, got1 = 0, i;
        put32(&o, 1);              /* one split entry */
        put32(&o, 0);             /* frag_t _enc = 0 (root) */
        put32(&o, 1);             /* nway = 1 bit */
        cephfs_denc_init(&d, o.b, o.n);
        CHECK(cephfs_decode_fragtree(&d, leaves, 16, &n, &tr) == 0);
        CHECK(n == 2 && tr == 0);
        for (i = 0; i < n; i++) {
            if (leaves[i] == 0x01000000u) got0 = 1;
            if (leaves[i] == 0x01000001u) got1 = 1;
        }
        CHECK(got0 && got1);
    }
}

/* ---- xattr map (synthetic) ----------------------------------------------- */
static void
put_str(buf_t *o, const char *s)
{
    uint32_t n = (uint32_t) strlen(s), i;
    put32(o, n);
    for (i = 0; i < n; i++) put8(o, (uint8_t) s[i]);
}
static void
test_xattrs_synth(void)
{
    buf_t o = { {0}, 0 }; cephfs_denc_t d;
    cephfs_xattr_t xs[8]; uint32_t n; int tr;

    put32(&o, 2);                 /* count */
    put_str(&o, "user.a"); put_str(&o, "1");
    put_str(&o, "user.bb"); put_str(&o, "22");
    cephfs_denc_init(&d, o.b, o.n);
    CHECK(cephfs_decode_xattrs(&d, xs, 8, &n, &tr) == 0);
    CHECK(n == 2 && tr == 0);
    CHECK(xs[0].name_len == 6 && memcmp(xs[0].name, "user.a", 6) == 0);
    CHECK(xs[0].val_len == 1 && memcmp(xs[0].val, "1", 1) == 0);
    CHECK(xs[1].name_len == 7 && memcmp(xs[1].name, "user.bb", 7) == 0);
    CHECK(xs[1].val_len == 2 && memcmp(xs[1].val, "22", 2) == 0);
}

/* ---- real reef fixtures -------------------------------------------------- */
static size_t
load(const char *dir, const char *name, uint8_t *out, size_t cap)
{
    char   path[512];
    FILE  *f;
    size_t n;

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "rb");
    if (f == NULL) { printf("  SKIP (no fixture %s)\n", path); return 0; }
    n = fread(out, 1, cap, f);
    fclose(f);
    return n;
}

static void
test_fixture(const char *dir, const char *name, uint64_t ino, int is_dir,
             uint64_t size)
{
    uint8_t         buf[4096];
    size_t          n = load(dir, name, buf, sizeof(buf));
    cephfs_dentry_t dn;

    if (n == 0) { return; }
    CHECK(cephfs_decode_dentry(buf, n, &dn) == 0);
    CHECK(dn.kind == CEPHFS_DENTRY_PRIMARY);
    CHECK(dn.inode.ino == ino);
    if (is_dir) {
        CHECK(cephfs_mode_is_dir(dn.inode.mode));
    } else {
        CHECK(cephfs_mode_is_reg(dn.inode.mode));
        CHECK(dn.inode.size == size);
        /* default CephFS layout */
        CHECK(dn.inode.layout.object_size == 0x400000);
        CHECK(dn.inode.layout.stripe_count == 1);
    }
    if (failures) { printf("  (failed on fixture %s)\n", name); }
}

/* symlink fixture: /dir1/link -> "hello.txt" (cephfs_seed2.c) */
static void
test_symlink_fixture(const char *dir)
{
    uint8_t         buf[4096];
    size_t          n = load(dir, "fx_link_symlink.bin", buf, sizeof(buf));
    cephfs_dentry_t dn;

    if (n == 0) { return; }
    CHECK(cephfs_decode_dentry(buf, n, &dn) == 0);
    CHECK(dn.kind == CEPHFS_DENTRY_PRIMARY);
    CHECK(dn.inode.ino == 0x10000000003ull);
    CHECK(cephfs_mode_is_link(dn.inode.mode));
    CHECK(dn.symlink != NULL && dn.symlink_len == 9
          && memcmp(dn.symlink, "hello.txt", 9) == 0);
    if (failures) { printf("  (failed on symlink fixture)\n"); }
}

/* xattr fixture: hello.txt now carries user.color=blue, user.shape=round */
static void
test_xattr_fixture(const char *dir)
{
    uint8_t         buf[4096];
    size_t          n = load(dir, "fx_hello_xattr.bin", buf, sizeof(buf));
    cephfs_dentry_t dn;
    uint32_t        i;
    int             got_color = 0, got_shape = 0;

    if (n == 0) { return; }
    CHECK(cephfs_decode_dentry(buf, n, &dn) == 0);
    CHECK(dn.kind == CEPHFS_DENTRY_PRIMARY);
    CHECK(dn.inode.size == 27);              /* data unchanged */
    CHECK(dn.nxattrs == 2 && dn.xattrs_truncated == 0);
    for (i = 0; i < dn.nxattrs; i++) {
        if (dn.xattrs[i].name_len == 10
            && memcmp(dn.xattrs[i].name, "user.color", 10) == 0) {
            got_color = (dn.xattrs[i].val_len == 4
                         && memcmp(dn.xattrs[i].val, "blue", 4) == 0);
        }
        if (dn.xattrs[i].name_len == 10
            && memcmp(dn.xattrs[i].name, "user.shape", 10) == 0) {
            got_shape = (dn.xattrs[i].val_len == 5
                         && memcmp(dn.xattrs[i].val, "round", 5) == 0);
        }
    }
    CHECK(got_color && got_shape);
    if (failures) { printf("  (failed on xattr fixture)\n"); }
}

int
main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : "tests/ceph/fixtures/reef-18.2.4";

    test_inode_versions();
    test_fragtree();
    test_xattrs_synth();

    /* seeded tree (cephfs_seed.c): inodes + sizes are known ground truth */
    test_fixture(dir, "fx_dir1_hello.bin", 0x100000001f7ull, 0, 27);
    test_fixture(dir, "fx_root_top.bin",   0x10000000002ull,  0, 15);
    test_fixture(dir, "fx_root_dir1.bin",  0x10000000000ull,  1, 0);
    test_fixture(dir, "fx_dir1_sub.bin",   0x10000000001ull,  1, 0);
    test_symlink_fixture(dir);
    test_xattr_fixture(dir);

    if (failures == 0) {
        printf("cephfs_layout_unittest: ALL PASS\n");
        return 0;
    }
    printf("cephfs_layout_unittest: %d FAILURE(S)\n", failures);
    return 1;
}
