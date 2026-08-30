/*
 * sd_pblock_unittest_block.c — block-striping slice of the pblock driver unit
 * test (split from sd_pblock_unittest.c). Owns the on-disk block-scan helpers
 * and the shared open_block_export() factory; prototypes come from
 * sd_pblock_unittest_internal.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* nftw(3) + FTW_PHYS for the on-disk block scan */
#endif

#include "fs/backend/sd.h"
#include "sd_pblock_catalog.h"
#include "sd_pblock_unittest_internal.h"

#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- block striping ------------------------------------------------------- */

static long g_blk_count, g_blk_total, g_blk_max;

static int
blk_walk_cb(const char *path, const struct stat *sb, int type, struct FTW *ftw)
{
    (void) path;
    (void) ftw;
    if (type == FTW_F) {
        g_blk_count++;
        g_blk_total += (long) sb->st_size;
        if ((long) sb->st_size > g_blk_max) {
            g_blk_max = (long) sb->st_size;
        }
    }
    return 0;
}

/* scan_blocks — tally the on-disk block files under <root>/data: count, total
 * bytes, and the largest single block (which must never exceed block_size). */
static void
scan_blocks(const char *root)
{
    char data[512];

    snprintf(data, sizeof(data), "%s/data", root);
    g_blk_count = g_blk_total = g_blk_max = 0;
    nftw(data, blk_walk_cb, 16, FTW_PHYS);
}

/* pblock_open_block_export — fresh export with a small block size so striping is
 * exercised with a handful of bytes. Returns 0/-1 and fills *inst + *root. */
int
open_block_export(brix_sd_instance_t *inst, char *root, int64_t block_size)
{
    static brix_sd_pblock_conf_t conf;   /* root must outlive the instance */

    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = block_size;
    memset(inst, 0, sizeof(*inst));
    inst->driver = D;
    return D->init(inst, &conf) == NGX_OK ? 0 : -1;
}

/* seed_block_export — mkdtemp + open_block_export(bs=16) + a `len`-byte
 * repeating pattern written to `path`. Every striping test starts from exactly
 * this state; each passes its own pattern base/span so a stray cross-test read
 * is still visible in the bytes. Fills `data` with what was written. */
static void
seed_block_export(brix_sd_instance_t *inst, char *root, const char *path,
    char *data, size_t len, char base, int span)
{
    size_t i;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    CHECK(open_block_export(inst, root, 16) == 0, "init bs=16");
    for (i = 0; i < len; i++) {
        data[i] = (char) (base + (int) (i % (size_t) span));
    }
    CHECK(write_file(inst, path, data, len) == 0, "seed %zu bytes", len);
}

/* A 40-byte file with a 16-byte block size lands as three block files
 * (16 + 16 + 8); reads (incl. across a block boundary) are byte-exact. */
void
test_block_striping(void)
{
    char                 root[] = "/tmp/pb_blk.XXXXXX";
    brix_sd_instance_t inst;
    brix_sd_obj_t     *o;
    brix_sd_stat_t     st;
    char                 data[40], buf[40], part[20];
    int                  i, err = 0;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    CHECK(open_block_export(&inst, root, 16) == 0, "init bs=16");
    for (i = 0; i < 40; i++) {
        data[i] = (char) ('A' + (i % 26));
    }

    CHECK(write_file(&inst, "/big", data, 40) == 0, "write 40");
    CHECK(D->stat(&inst, "/big", &st) == NGX_OK && st.size == 40, "size 40");
    CHECK(read_file(&inst, "/big", buf, sizeof(buf)) == 40
          && memcmp(buf, data, 40) == 0, "read back 40 byte-exact");

    o = D->open(&inst, "/big", BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "reopen read");
    if (o != NULL) {
        CHECK(D->pread(o, part, 20, 10) == 20
              && memcmp(part, data + 10, 20) == 0, "cross-boundary read");
        pb_close(o);
    }

    scan_blocks(root);
    CHECK(g_blk_count == 3, "expected 3 block files, got %ld", g_blk_count);
    CHECK(g_blk_max <= 16, "a block exceeded block_size: %ld", g_blk_max);
    CHECK(g_blk_total == 40, "block bytes total %ld != 40", g_blk_total);

    D->cleanup(&inst);
}

/* The block size is per-export configurable: the same 40 bytes with an 8-byte
 * block size lands as five blocks. */
void
test_block_size_configurable(void)
{
    char                 root[] = "/tmp/pb_blk8.XXXXXX";
    brix_sd_instance_t inst;
    char                 data[40];
    int                  i;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    CHECK(open_block_export(&inst, root, 8) == 0, "init bs=8");
    for (i = 0; i < 40; i++) {
        data[i] = (char) ('a' + (i % 26));
    }
    CHECK(write_file(&inst, "/f", data, 40) == 0, "write 40 @ bs=8");

    scan_blocks(root);
    CHECK(g_blk_count == 5, "expected 5 block files, got %ld", g_blk_count);
    CHECK(g_blk_max <= 8, "block exceeded 8: %ld", g_blk_max);
    CHECK(g_blk_total == 40, "total %ld", g_blk_total);
    D->cleanup(&inst);
}

/* Sparse writes leave holes that read back as zeros, and only the touched
 * blocks materialize on disk. */
void
test_block_sparse(void)
{
    char                 root[] = "/tmp/pb_sps.XXXXXX";
    brix_sd_instance_t inst;
    brix_sd_obj_t     *o;
    brix_sd_stat_t     st;
    char                 buf[64];
    int                  i, err = 0;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    CHECK(open_block_export(&inst, root, 16) == 0, "init bs=16");

    o = D->open(&inst, "/sparse",
                BRIX_SD_O_WRITE | BRIX_SD_O_READ | BRIX_SD_O_CREATE,
                0644, &err);
    CHECK(o != NULL, "open sparse");
    if (o != NULL) {
        CHECK(D->pwrite(o, "XY", 2, 33) == 2, "sparse write at 33");
        pb_close(o);
    }
    CHECK(D->stat(&inst, "/sparse", &st) == NGX_OK && st.size == 35,
          "sparse size 35");

    CHECK(read_file(&inst, "/sparse", buf, sizeof(buf)) == 35, "read 35");
    for (i = 0; i < 33; i++) {
        CHECK(buf[i] == 0, "hole byte %d not zero", i);
    }
    CHECK(buf[33] == 'X' && buf[34] == 'Y', "sparse payload");

    /* block 0 (empty) + block 2 (3 bytes) exist; block 1 is a hole */
    scan_blocks(root);
    CHECK(g_blk_count == 2, "sparse blocks %ld != 2", g_blk_count);
    D->cleanup(&inst);
}

/* ftruncate drops whole blocks past the new size and trims the boundary block. */
void
test_block_truncate(void)
{
    char                 root[] = "/tmp/pb_trc.XXXXXX";
    brix_sd_instance_t inst;
    brix_sd_obj_t     *o;
    brix_sd_stat_t     st;
    char                 data[40], buf[40];
    int                  err = 0;

    seed_block_export(&inst, root, "/t", data, sizeof(data), '0', 10);

    o = D->open(&inst, "/t", BRIX_SD_O_WRITE | BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "reopen rw");
    if (o != NULL) {
        CHECK(D->ftruncate(o, 10) == NGX_OK, "truncate to 10");
        CHECK(D->fstat(o, &st) == NGX_OK && st.size == 10, "size 10");
        pb_close(o);
    }
    CHECK(read_file(&inst, "/t", buf, sizeof(buf)) == 10
          && memcmp(buf, data, 10) == 0, "read back 10");

    scan_blocks(root);
    CHECK(g_blk_count == 1, "after trunc blocks %ld != 1", g_blk_count);
    CHECK(g_blk_total == 10, "after trunc bytes %ld != 10", g_blk_total);
    D->cleanup(&inst);
}

/* advise_ok — read_advise over [off,len) on an open handle, asserting the
 * advisory contract (NGX_OK) under the caller's label. */
static void
advise_ok(brix_sd_obj_t *o, off_t off, size_t len, int advice, const char *what)
{
    CHECK(D->read_advise(o, off, len, advice) == NGX_OK, "read_advise %s", what);
}

/* read_advise spans every block of a striped object, is a no-op outside it, and
 * never touches the object: contents, size and the on-disk block set are
 * unchanged (a hole must NOT be materialised by a hint). */
void
test_block_read_advise(void)
{
    char                 root[] = "/tmp/pb_adv.XXXXXX";
    brix_sd_instance_t inst;
    brix_sd_obj_t     *o;
    brix_sd_stat_t     st;
    char                 data[40], buf[40];
    long                 blocks_before;
    int                  err = 0;

    seed_block_export(&inst, root, "/adv", data, sizeof(data), 'a', 13);

    /* A sparse neighbour: block 1 is a hole the hint must leave alone. */
    o = D->open(&inst, "/hole",
                BRIX_SD_O_WRITE | BRIX_SD_O_READ | BRIX_SD_O_CREATE,
                0644, &err);
    CHECK(o != NULL, "open hole");
    if (o != NULL) {
        CHECK(D->pwrite(o, "XY", 2, 33) == 2, "hole write at 33");
        pb_close(o);
    }
    scan_blocks(root);
    blocks_before = g_blk_count;

    o = D->open(&inst, "/adv", BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "open adv for read");
    if (o != NULL) {
        /* success: whole object (len 0), a boundary-crossing slice, and each
         * advice value — all three blocks are described. */
        advise_ok(o, 0, 0, BRIX_SD_ADV_SEQUENTIAL, "whole object");
        advise_ok(o, 10, 20, BRIX_SD_ADV_WILLNEED, "boundary-crossing slice");
        advise_ok(o, 0, 40, BRIX_SD_ADV_RANDOM, "random over all blocks");
        /* edge: at/after EOF and an over-long length are no-ops, not errors. */
        advise_ok(o, 40, 16, BRIX_SD_ADV_WILLNEED, "at EOF");
        advise_ok(o, 100, 16, BRIX_SD_ADV_WILLNEED, "past EOF");
        advise_ok(o, -1, 16, BRIX_SD_ADV_WILLNEED, "negative offset");
        advise_ok(o, 32, 4096, BRIX_SD_ADV_SEQUENTIAL, "length past EOF");
        pb_close(o);
    }

    o = D->open(&inst, "/hole", BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "open hole for read");
    if (o != NULL) {
        advise_ok(o, 0, 0, BRIX_SD_ADV_WILLNEED, "over a hole block");
        pb_close(o);
    }

    /* security-neg: an advisory hint must never mutate state — no block file
     * created (the hole stays a hole), no size change, no content change. */
    scan_blocks(root);
    CHECK(g_blk_count == blocks_before,
          "read_advise changed the block set: %ld != %ld",
          g_blk_count, blocks_before);
    CHECK(D->stat(&inst, "/adv", &st) == NGX_OK && st.size == 40,
          "size unchanged after advise");
    CHECK(read_file(&inst, "/adv", buf, sizeof(buf)) == 40
          && memcmp(buf, data, 40) == 0, "contents unchanged after advise");
    D->cleanup(&inst);
}

/* server_copy reproduces a multi-block file byte-exactly; unlink removes every
 * block file. */
void
test_block_copy_and_unlink(void)
{
    char                 root[] = "/tmp/pb_cu.XXXXXX";
    brix_sd_instance_t inst;
    brix_sd_stat_t     st;
    char                 data[40], buf[40];
    off_t                bytes = 0;

    seed_block_export(&inst, root, "/src", data, sizeof(data), 'A', 7);

    CHECK(D->server_copy(&inst, "/src", "/dst", &bytes) == NGX_OK, "copy");
    CHECK(bytes == 40, "copy bytes %lld", (long long) bytes);
    CHECK(read_file(&inst, "/dst", buf, sizeof(buf)) == 40
          && memcmp(buf, data, 40) == 0, "copy byte-exact");
    CHECK(D->stat(&inst, "/dst", &st) == NGX_OK && st.size == 40, "dst size");

    CHECK(D->unlink(&inst, "/src", 0) == NGX_OK, "unlink src");
    CHECK(D->unlink(&inst, "/dst", 0) == NGX_OK, "unlink dst");
    scan_blocks(root);
    CHECK(g_blk_count == 0, "blocks remain after unlink: %ld", g_blk_count);
    D->cleanup(&inst);
}
