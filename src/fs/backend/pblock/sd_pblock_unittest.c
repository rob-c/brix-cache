/*
 * sd_pblock_unittest.c — standalone unit test for the pblock storage driver,
 * driven through the real brix_sd_driver_t vtable function pointers. No nginx,
 * no running server: it builds a throwaway export root under /tmp and exercises
 * every slot plus multi-thread and multi-process concurrency.
 *
 * Build & run (the data plane is real POSIX + SQLite, so it needs libsqlite3 and
 * the ngx-free shim surface in sd.h):
 *   cc -Wall -Wextra -DBRIX_HAVE_SQLITE=1 -DXRDPROTO_NO_NGX -I. \
 *      sd_pblock_unittest.c sd_pblock.c sd_pblock_catalog.c \
 *      -lsqlite3 -lpthread -o /tmp/pb_ut && /tmp/pb_ut
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* nftw(3) + FTW_PHYS for the on-disk block scan */
#endif

#include "fs/backend/sd.h"
#include "sd_pblock_catalog.h"

#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <pthread.h>
#include <sqlite3.h>   /* Phase-83 lab tests drive the ctl table directly */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: ", __func__, __LINE__);              \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static const brix_sd_driver_t *D;   /* = &brix_sd_pblock_driver */

/* pb_close — close an object and free its malloc'd shell. driver->close frees the
 * per-open state + fd but not the obj struct (the VFS adopts that by value), so a
 * direct caller owns the shell. */
static ngx_int_t
pb_close(brix_sd_obj_t *o)
{
    ngx_int_t rc = D->close(o);

    free(o);
    return rc;
}

/* ---- small helpers over the vtable ---------------------------------------- */

/* write_file — create `path`, write `data`, close. Returns 0 or -1. */
static int
write_file(brix_sd_instance_t *inst, const char *path, const char *data,
    size_t len)
{
    int              err = 0;
    brix_sd_obj_t *o;
    ssize_t          n;

    o = D->open(inst, path,
                BRIX_SD_O_WRITE | BRIX_SD_O_READ | BRIX_SD_O_CREATE,
                0644, &err);
    if (o == NULL) {
        return -1;
    }
    n = D->pwrite(o, data, len, 0);
    pb_close(o);
    return (n == (ssize_t) len) ? 0 : -1;
}

/* read_file — open `path` read-only, read up to cap bytes at 0. Returns bytes
 * read or -1. */
static ssize_t
read_file(brix_sd_instance_t *inst, const char *path, char *buf, size_t cap)
{
    int              err = 0;
    brix_sd_obj_t *o;
    ssize_t          n;

    o = D->open(inst, path, BRIX_SD_O_READ, 0, &err);
    if (o == NULL) {
        errno = err;
        return -1;
    }
    n = D->pread(o, buf, cap, 0);
    pb_close(o);
    return n;
}

/* ---- tests ---------------------------------------------------------------- */

static void
test_write_read_fstat(brix_sd_instance_t *inst)
{
    int               err = 0;
    brix_sd_obj_t  *o;
    brix_sd_stat_t  st;
    char              buf[64];

    o = D->open(inst, "/hello",
                BRIX_SD_O_WRITE | BRIX_SD_O_READ | BRIX_SD_O_CREATE,
                0644, &err);
    CHECK(o != NULL, "open create failed: %s", strerror(err));
    if (o == NULL) { return; }

    CHECK(D->pwrite(o, "hello world", 11, 0) == 11, "pwrite short");
    CHECK(D->fstat(o, &st) == NGX_OK, "fstat failed");
    CHECK(st.size == 11, "fstat size %lld", (long long) st.size);
    CHECK(st.is_reg, "fstat not regular");
    CHECK(D->pread(o, buf, sizeof(buf), 0) == 11, "pread back");
    CHECK(memcmp(buf, "hello world", 11) == 0, "pread content");

    /* zero-copy parity: a real blob fd is sendfile-able */
    CHECK(D->read_sendfile_fd(o, 0, 11, 1) != NGX_INVALID_FILE,
          "read_sendfile_fd should expose the blob fd");
    pb_close(o);

    CHECK(read_file(inst, "/hello", buf, sizeof(buf)) == 11, "reopen read");
}

static void
test_truncate_and_stat(brix_sd_instance_t *inst)
{
    int               err = 0;
    brix_sd_obj_t  *o;
    brix_sd_stat_t  st;

    CHECK(write_file(inst, "/trunc", "0123456789", 10) == 0, "seed write");
    o = D->open(inst, "/trunc", BRIX_SD_O_WRITE | BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "reopen rw: %s", strerror(err));
    if (o == NULL) { return; }
    CHECK(D->ftruncate(o, 4) == NGX_OK, "ftruncate");
    CHECK(D->fstat(o, &st) == NGX_OK && st.size == 4, "size after trunc %lld",
          (long long) st.size);
    pb_close(o);

    CHECK(D->stat(inst, "/trunc", &st) == NGX_OK, "stat-by-path");
    CHECK(st.size == 4, "stat size %lld", (long long) st.size);
    errno = 0;
    CHECK(D->stat(inst, "/ghost", &st) == NGX_ERROR && errno == ENOENT,
          "stat ghost should ENOENT");
}

static void
test_preadv(brix_sd_instance_t *inst)
{
    int              err = 0;
    brix_sd_obj_t *o;
    char             a[4], b[4];
    struct iovec     iov[2];

    CHECK(write_file(inst, "/vec", "ABCDEFGH", 8) == 0, "seed");
    o = D->open(inst, "/vec", BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "open vec");
    if (o == NULL) { return; }
    iov[0].iov_base = a; iov[0].iov_len = 4;
    iov[1].iov_base = b; iov[1].iov_len = 4;
    CHECK(D->preadv(o, iov, 2, 0) == 8, "preadv total");
    CHECK(memcmp(a, "ABCD", 4) == 0 && memcmp(b, "EFGH", 4) == 0, "preadv data");
    pb_close(o);
}

static void
test_dirs(brix_sd_instance_t *inst)
{
    int               err = 0;
    brix_sd_dir_t  *dir;
    brix_sd_dirent_t de;
    int               seen_a = 0, seen_b = 0, n = 0, rc;

    CHECK(D->mkdir(inst, "/dir", 0755) == NGX_OK, "mkdir");
    CHECK(write_file(inst, "/dir/a", "x", 1) == 0, "a");
    CHECK(write_file(inst, "/dir/b", "y", 1) == 0, "b");

    dir = D->opendir(inst, "/dir", &err);
    CHECK(dir != NULL, "opendir: %s", strerror(err));
    if (dir == NULL) { return; }
    while ((rc = D->readdir(dir, &de)) == NGX_OK) {
        if (strcmp(de.name, "a") == 0) { seen_a = 1; }
        if (strcmp(de.name, "b") == 0) { seen_b = 1; }
        n++;
    }
    CHECK(rc == NGX_DONE, "readdir end rc=%d", rc);
    D->closedir(dir);
    CHECK(seen_a && seen_b && n == 2, "dir entries a=%d b=%d n=%d", seen_a,
          seen_b, n);
}

static void
test_rename(brix_sd_instance_t *inst)
{
    brix_sd_stat_t st;
    char             buf[16];

    CHECK(write_file(inst, "/r1", "keepme", 6) == 0, "seed r1");
    CHECK(D->rename(inst, "/r1", "/r2", 0) == NGX_OK, "rename file");
    errno = 0;
    CHECK(D->stat(inst, "/r1", &st) == NGX_ERROR && errno == ENOENT,
          "old name gone");
    CHECK(D->stat(inst, "/r2", &st) == NGX_OK, "new name present");
    CHECK(read_file(inst, "/r2", buf, sizeof(buf)) == 6
          && memcmp(buf, "keepme", 6) == 0, "content followed rename");

    /* directory subtree rename */
    CHECK(D->mkdir(inst, "/sub", 0755) == NGX_OK, "mkdir sub");
    CHECK(D->mkdir(inst, "/sub/inner", 0755) == NGX_OK, "mkdir inner");
    CHECK(write_file(inst, "/sub/inner/deep", "D", 1) == 0, "deep");
    CHECK(D->rename(inst, "/sub", "/moved", 0) == NGX_OK, "rename subtree");
    CHECK(D->stat(inst, "/moved/inner/deep", &st) == NGX_OK,
          "descendant reparented");
}

static void
test_server_copy(brix_sd_instance_t *inst)
{
    brix_sd_stat_t st;
    char             buf[16];
    off_t            bytes = 0;

    CHECK(write_file(inst, "/cpsrc", "copydata", 8) == 0, "seed");
    CHECK(D->server_copy(inst, "/cpsrc", "/cpdst", &bytes) == NGX_OK, "copy");
    CHECK(bytes == 8, "copy bytes %lld", (long long) bytes);
    CHECK(D->stat(inst, "/cpsrc", &st) == NGX_OK, "src still there");
    CHECK(read_file(inst, "/cpdst", buf, sizeof(buf)) == 8
          && memcmp(buf, "copydata", 8) == 0, "copy content");
}

static void
test_xattr(brix_sd_instance_t *inst)
{
    char    buf[64];
    ssize_t n;

    CHECK(write_file(inst, "/xa", "z", 1) == 0, "seed");
    CHECK(D->setxattr(inst, "/xa", "user.tag", "v1", 2, 0) == NGX_OK, "set");
    n = D->getxattr(inst, "/xa", "user.tag", buf, sizeof(buf));
    CHECK(n == 2 && memcmp(buf, "v1", 2) == 0, "get n=%zd", n);
    n = D->listxattr(inst, "/xa", buf, sizeof(buf));
    CHECK(n == (ssize_t) sizeof("user.tag"), "list n=%zd", n);
    CHECK(D->removexattr(inst, "/xa", "user.tag") == NGX_OK, "remove");
    errno = 0;
    n = D->getxattr(inst, "/xa", "user.tag", buf, sizeof(buf));
    CHECK(n == -1 && errno == ENODATA, "get after remove");
}

static void
test_staged(brix_sd_instance_t *inst)
{
    int                 err = 0;
    brix_sd_staged_t *s;
    brix_sd_stat_t    st;
    char                buf[16];

    s = D->staged_open(inst, "/staged", 0644, &err);
    CHECK(s != NULL, "staged_open: %s", strerror(err));
    if (s != NULL) {
        CHECK(D->staged_write(s, "atomic", 6, 0) == 6, "staged_write");
        /* not visible before commit */
        CHECK(D->stat(inst, "/staged", &st) == NGX_ERROR, "visible pre-commit");
        CHECK(D->staged_commit(s, 0) == NGX_OK, "commit");
        CHECK(D->stat(inst, "/staged", &st) == NGX_OK && st.size == 6,
              "visible post-commit");
        CHECK(read_file(inst, "/staged", buf, sizeof(buf)) == 6
              && memcmp(buf, "atomic", 6) == 0, "committed content");
    }

    s = D->staged_open(inst, "/aborted", 0644, &err);
    CHECK(s != NULL, "staged_open 2");
    if (s != NULL) {
        CHECK(D->staged_write(s, "gone", 4, 0) == 4, "write");
        D->staged_abort(s);
        CHECK(D->stat(inst, "/aborted", &st) == NGX_ERROR, "aborted invisible");
    }
}

static void
test_unlink(brix_sd_instance_t *inst)
{
    brix_sd_stat_t st;

    CHECK(write_file(inst, "/del", "bye", 3) == 0, "seed");
    CHECK(D->unlink(inst, "/del", 0) == NGX_OK, "unlink file");
    errno = 0;
    CHECK(D->stat(inst, "/del", &st) == NGX_ERROR && errno == ENOENT, "gone");

    CHECK(D->mkdir(inst, "/ed", 0755) == NGX_OK, "mkdir ed");
    CHECK(write_file(inst, "/ed/c", "c", 1) == 0, "child");
    errno = 0;
    CHECK(D->unlink(inst, "/ed", 1) == NGX_ERROR && errno == ENOTEMPTY,
          "rmdir non-empty");
    CHECK(D->unlink(inst, "/ed/c", 0) == NGX_OK, "rm child");
    CHECK(D->unlink(inst, "/ed", 1) == NGX_OK, "rmdir empty");
}

/* fsync persists dirty metadata: a fresh instance on the same root sees the
 * flushed size. */
static void
test_fsync_durability(const char *root)
{
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = { root, 2000, 0 };
    int                     err = 0;
    brix_sd_obj_t        *o;
    brix_sd_stat_t        st;

    inst.driver = D;
    CHECK(D->init(&inst, &conf) == NGX_OK, "second init");
    o = D->open(&inst, "/durable",
                BRIX_SD_O_WRITE | BRIX_SD_O_READ | BRIX_SD_O_CREATE,
                0644, &err);
    CHECK(o != NULL, "open durable");
    if (o != NULL) {
        CHECK(D->pwrite(o, "persist", 7, 0) == 7, "write");
        CHECK(D->fsync(o) == NGX_OK, "fsync");
        pb_close(o);
    }
    CHECK(D->stat(&inst, "/durable", &st) == NGX_OK && st.size == 7,
          "durable size after fsync");
    D->cleanup(&inst);

    /* brand-new instance, brand-new SQLite connection on the same db */
    memset(&inst, 0, sizeof(inst));
    inst.driver = D;
    CHECK(D->init(&inst, &conf) == NGX_OK, "third init");
    CHECK(D->stat(&inst, "/durable", &st) == NGX_OK && st.size == 7,
          "durable visible to a fresh handle");
    D->cleanup(&inst);
}

/* ---- concurrency ---------------------------------------------------------- */

typedef struct {
    brix_sd_instance_t *inst;
    int                   id;
    int                   ops;
    int                   ok;
} thread_arg;

/* Each thread writes + reads back its own private files through the SHARED
 * instance (shared SQLite connection + blob dir), proving the per-worker handle
 * is safe across a thread pool and that blob I/O runs in parallel. */
static void *
thread_body(void *p)
{
    thread_arg *a = p;
    int         i;

    for (i = 0; i < a->ops; i++) {
        char path[64];
        char buf[32];
        char want[32];
        int  wn = snprintf(want, sizeof(want), "t%d-op%d", a->id, i);

        snprintf(path, sizeof(path), "/conc/t%d-%d", a->id, i);
        if (write_file(a->inst, path, want, (size_t) wn) != 0) {
            return NULL;
        }
        if (read_file(a->inst, path, buf, sizeof(buf)) != wn
            || memcmp(buf, want, (size_t) wn) != 0)
        {
            return NULL;
        }
    }
    a->ok = 1;
    return NULL;
}

static void
test_threads(brix_sd_instance_t *inst)
{
    enum { NTHREADS = 8, NOPS = 40 };
    pthread_t  tids[NTHREADS];
    thread_arg args[NTHREADS];
    int        i;

    CHECK(D->mkdir(inst, "/conc", 0755) == NGX_OK, "mkdir conc");
    for (i = 0; i < NTHREADS; i++) {
        args[i].inst = inst;
        args[i].id = i;
        args[i].ops = NOPS;
        args[i].ok = 0;
        CHECK(pthread_create(&tids[i], NULL, thread_body, &args[i]) == 0,
              "pthread_create %d", i);
    }
    for (i = 0; i < NTHREADS; i++) {
        pthread_join(tids[i], NULL);
        CHECK(args[i].ok == 1, "thread %d failed", i);
    }
}

/* Each forked child opens its OWN instance on the same root and writes a batch;
 * the parent then verifies every child's files landed. Exercises cross-process
 * WAL locking + the busy-timeout retry path. */
static void
test_processes(const char *root, brix_sd_instance_t *inst)
{
    enum { NPROC = 4, NOPS = 25 };
    pid_t pids[NPROC];
    int   i, total = 0, rc;
    brix_sd_dir_t   *dir;
    brix_sd_dirent_t de;
    int                err = 0;

    CHECK(D->mkdir(inst, "/mp", 0755) == NGX_OK, "mkdir mp");

    for (i = 0; i < NPROC; i++) {
        pid_t pid = fork();

        if (pid == 0) {
            brix_sd_instance_t    cinst = {0};
            brix_sd_pblock_conf_t conf = { root, 5000, 0 };
            int                     j, bad = 0;

            cinst.driver = D;
            if (D->init(&cinst, &conf) != NGX_OK) {
                _exit(2);
            }
            for (j = 0; j < NOPS; j++) {
                char path[64];

                snprintf(path, sizeof(path), "/mp/p%d-%d", (int) getpid(), j);
                if (write_file(&cinst, path, "x", 1) != 0) {
                    bad = 1;
                    break;
                }
            }
            D->cleanup(&cinst);
            _exit(bad ? 1 : 0);
        }
        CHECK(pid > 0, "fork %d", i);
        pids[i] = pid;
    }

    for (i = 0; i < NPROC; i++) {
        int status = 0;

        waitpid(pids[i], &status, 0);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
              "child %d exit status %d", i, status);
    }

    dir = D->opendir(inst, "/mp", &err);
    CHECK(dir != NULL, "opendir mp");
    if (dir != NULL) {
        while ((rc = D->readdir(dir, &de)) == NGX_OK) {
            total++;
        }
        D->closedir(dir);
    }
    CHECK(total == NPROC * NOPS, "expected %d files, found %d", NPROC * NOPS,
          total);
}

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
static int
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

/* A 40-byte file with a 16-byte block size lands as three block files
 * (16 + 16 + 8); reads (incl. across a block boundary) are byte-exact. */
static void
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
static void
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
static void
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
static void
test_block_truncate(void)
{
    char                 root[] = "/tmp/pb_trc.XXXXXX";
    brix_sd_instance_t inst;
    brix_sd_obj_t     *o;
    brix_sd_stat_t     st;
    char                 data[40], buf[40];
    int                  i, err = 0;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    CHECK(open_block_export(&inst, root, 16) == 0, "init bs=16");
    for (i = 0; i < 40; i++) {
        data[i] = (char) ('0' + (i % 10));
    }
    CHECK(write_file(&inst, "/t", data, 40) == 0, "seed 40");

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

/* server_copy reproduces a multi-block file byte-exactly; unlink removes every
 * block file. */
static void
test_block_copy_and_unlink(void)
{
    char                 root[] = "/tmp/pb_cu.XXXXXX";
    brix_sd_instance_t inst;
    brix_sd_stat_t     st;
    char                 data[40], buf[40];
    off_t                bytes = 0;
    int                  i;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    CHECK(open_block_export(&inst, root, 16) == 0, "init bs=16");
    for (i = 0; i < 40; i++) {
        data[i] = (char) ('A' + (i % 7));
    }
    CHECK(write_file(&inst, "/src", data, 40) == 0, "seed src");

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

/* ---- identity enforcement (the *_cred slots) ------------------------------- *
 * alice + carol share VO "atlas"; bob is VO "cms"; a zeroed principal is the
 * service (bypasses every check). Ownership is catalog-internal synthetic ids,
 * so all assertions compare ids read back via stat — never fixed numbers. */

static const brix_sd_cred_t CRED_ALICE = { .principal = "alice",
                                           .vos = "atlas" };
static const brix_sd_cred_t CRED_BOB   = { .principal = "bob",
                                           .vos = "cms" };
static const brix_sd_cred_t CRED_CAROL = { .principal = "carol",
                                           .vos = "atlas" };

/* cred_write_file — open_cred-create `path` as `who` with `mode`, write a few
 * bytes, close. 0 or -1/errno. */
static int
cred_write_file(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *who)
{
    int              err = 0;
    brix_sd_obj_t *o;
    ssize_t          n;

    o = D->open_cred(inst, path,
                     BRIX_SD_O_WRITE | BRIX_SD_O_READ | BRIX_SD_O_CREATE,
                     mode, who, &err);
    if (o == NULL) {
        errno = err;
        return -1;
    }
    n = D->pwrite(o, "data", 4, 0);
    pb_close(o);
    return n == 4 ? 0 : -1;
}

/* creation records the requester as owner; mode bits gate other users by
 * class (owner / VO-group / other); the service bypasses everything. */
static void
test_ident_ownership(brix_sd_instance_t *inst)
{
    brix_sd_stat_t  st;
    brix_sd_obj_t  *o;
    int             err = 0;

    /* 0640: owner rw, VO-group r, other none */
    CHECK(cred_write_file(inst, "/a.dat", 0640, &CRED_ALICE) == 0,
          "alice create: %s", strerror(errno));
    CHECK(D->stat(inst, "/a.dat", &st) == NGX_OK, "stat a.dat");
    CHECK(st.uid >= PBLOCK_ID_BASE && st.gid >= PBLOCK_ID_BASE,
          "synthetic owner not recorded: %u/%u",
          (unsigned) st.uid, (unsigned) st.gid);

    /* same user re-opens rw (owner class) */
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_WRITE | BRIX_SD_O_READ, 0,
                     &CRED_ALICE, &err);
    CHECK(o != NULL, "owner reopen rw: %s", strerror(err));
    if (o != NULL) { pb_close(o); }

    /* carol shares VO atlas: group class grants read, denies write */
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_READ, 0, &CRED_CAROL, &err);
    CHECK(o != NULL, "same-VO read: %s", strerror(err));
    if (o != NULL) { pb_close(o); }
    err = 0;
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_WRITE, 0, &CRED_CAROL, &err);
    CHECK(o == NULL && err == EACCES, "same-VO write allowed (err %d)", err);

    /* bob (VO cms) is other class: no bits at all — neither read nor write */
    err = 0;
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_READ, 0, &CRED_BOB, &err);
    CHECK(o == NULL && err == EACCES, "foreign-VO read allowed (err %d)", err);
    err = 0;
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_WRITE, 0, &CRED_BOB, &err);
    CHECK(o == NULL && err == EACCES, "foreign-VO write allowed (err %d)",
          err);

    /* the service (NULL cred) bypasses the gate entirely */
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_WRITE | BRIX_SD_O_READ, 0,
                     NULL, &err);
    CHECK(o != NULL, "service bypass: %s", strerror(err));
    if (o != NULL) { pb_close(o); }

    /* a group-WRITABLE file (0660) really is shared within the VO: carol may
     * write to alice's file and read alice's bytes back — bob still may not */
    CHECK(cred_write_file(inst, "/shared.dat", 0660, &CRED_ALICE) == 0,
          "alice create shared: %s", strerror(errno));
    o = D->open_cred(inst, "/shared.dat", BRIX_SD_O_WRITE | BRIX_SD_O_READ,
                     0, &CRED_CAROL, &err);
    CHECK(o != NULL, "same-VO group write: %s", strerror(err));
    if (o != NULL) {
        char buf[8];

        CHECK(D->pread(o, buf, 4, 0) == 4 && memcmp(buf, "data", 4) == 0,
              "same-VO read of alice's bytes");
        CHECK(D->pwrite(o, "EDIT", 4, 0) == 4, "same-VO pwrite");
        pb_close(o);
    }
    err = 0;
    o = D->open_cred(inst, "/shared.dat", BRIX_SD_O_WRITE, 0, &CRED_BOB,
                     &err);
    CHECK(o == NULL && err == EACCES,
          "foreign-VO write on group file allowed (err %d)", err);
}

/* per-VO shared directories: group-writable dir admits VO members and no one
 * else, for mkdir, staged publish and opendir alike. */
static void
test_ident_vo_dir(brix_sd_instance_t *inst)
{
    brix_sd_staged_t *sh;
    brix_sd_stat_t    st, sub;
    brix_sd_dir_t    *dir;
    int               err = 0;

    /* alice's VO-shared dir: 0770 — atlas members rwx, others nothing */
    CHECK(D->mkdir_cred(inst, "/atlas", 0770, &CRED_ALICE) == NGX_OK,
          "mkdir /atlas: %s", strerror(errno));
    CHECK(D->stat(inst, "/atlas", &st) == NGX_OK
          && st.uid >= PBLOCK_ID_BASE, "dir owner missing");

    CHECK(D->mkdir_cred(inst, "/atlas/carol", 0770, &CRED_CAROL) == NGX_OK,
          "same-VO mkdir: %s", strerror(errno));
    CHECK(D->stat(inst, "/atlas/carol", &sub) == NGX_OK
          && sub.uid != st.uid, "subdir not owned by carol");

    errno = 0;
    CHECK(D->mkdir_cred(inst, "/atlas/bob", 0770, &CRED_BOB) == NGX_ERROR
          && errno == EACCES, "foreign-VO mkdir allowed (errno %d)", errno);

    /* staged publish obeys the same parent gate and records the requester */
    err = 0;
    sh = D->staged_open_cred(inst, "/atlas/stage.dat", 0640, &CRED_BOB, &err);
    CHECK(sh == NULL && err == EACCES, "foreign-VO staged (err %d)", err);
    sh = D->staged_open_cred(inst, "/atlas/stage.dat", 0640, &CRED_CAROL,
                             &err);
    CHECK(sh != NULL, "same-VO staged: %s", strerror(err));
    if (sh != NULL) {
        CHECK(D->staged_write(sh, "zz", 2, 0) == 2, "staged write");
        CHECK(D->staged_commit(sh, 0) == NGX_OK, "staged commit");
        CHECK(D->stat(inst, "/atlas/stage.dat", &st) == NGX_OK
              && st.uid == sub.uid, "staged row not owned by carol");
    }

    /* listing = reading the directory */
    errno = 0;
    dir = D->opendir_cred(inst, "/atlas", &err, &CRED_BOB);
    CHECK(dir == NULL && err == EACCES, "foreign-VO opendir (err %d)", err);
    dir = D->opendir_cred(inst, "/atlas", &err, &CRED_CAROL);
    CHECK(dir != NULL, "same-VO opendir: %s", strerror(err));
    if (dir != NULL) { D->closedir(dir); }
}

/* directory traverse: the parent's X bit gates every access to entries inside
 * it — a world-readable file in a 0770 group dir stays invisible to
 * non-members (runs after test_ident_vo_dir; reuses its /atlas dir). */
static void
test_ident_traverse(brix_sd_instance_t *inst)
{
    brix_sd_obj_t *o;
    char           v[8];
    int            err = 0;

    /* 0644 would grant bob other-read — but /atlas (0770) must block him */
    CHECK(cred_write_file(inst, "/atlas/pub.dat", 0644, &CRED_ALICE) == 0,
          "alice create in /atlas: %s", strerror(errno));

    o = D->open_cred(inst, "/atlas/pub.dat", BRIX_SD_O_READ, 0, &CRED_CAROL,
                     &err);
    CHECK(o != NULL, "same-VO traverse+read: %s", strerror(err));
    if (o != NULL) { pb_close(o); }

    err = 0;
    o = D->open_cred(inst, "/atlas/pub.dat", BRIX_SD_O_READ, 0, &CRED_BOB,
                     &err);
    CHECK(o == NULL && err == EACCES,
          "no-traverse read allowed (err %d)", err);
    err = 0;
    o = D->open_cred(inst, "/atlas/new.dat",
                     BRIX_SD_O_WRITE | BRIX_SD_O_CREATE, 0644, &CRED_BOB,
                     &err);
    CHECK(o == NULL && err == EACCES,
          "no-traverse create allowed (err %d)", err);
    errno = 0;
    CHECK(D->getxattr_cred(inst, "/atlas/pub.dat", "user.k", v, sizeof(v),
                           &CRED_BOB) < 0 && errno == EACCES,
          "no-traverse getxattr allowed (errno %d)", errno);
    errno = 0;
    CHECK(D->unlink_cred(inst, "/atlas/pub.dat", 0, &CRED_BOB) == NGX_ERROR
          && errno == EACCES,
          "no-traverse unlink allowed (errno %d)", errno);

    /* the service still bypasses traverse like every other gate */
    o = D->open_cred(inst, "/atlas/pub.dat", BRIX_SD_O_READ, 0, NULL, &err);
    CHECK(o != NULL, "service traverse bypass: %s", strerror(err));
    if (o != NULL) { pb_close(o); }
}

/* chmod/chown policy: owner-only chmod; no giving files away; chgrp only into
 * a VO the owner belongs to. */
static void
test_ident_setattr(brix_sd_instance_t *inst)
{
    brix_sd_setattr_t attr;
    brix_sd_stat_t    st, bobst;

    CHECK(cred_write_file(inst, "/chown.me", 0640, &CRED_ALICE) == 0,
          "seed chown.me");
    CHECK(cred_write_file(inst, "/bob.dat", 0640, &CRED_BOB) == 0,
          "seed bob.dat");
    CHECK(D->stat(inst, "/chown.me", &st) == NGX_OK, "stat chown.me");
    CHECK(D->stat(inst, "/bob.dat", &bobst) == NGX_OK, "stat bob.dat");

    /* chmod: owner yes, non-owner EPERM */
    memset(&attr, 0, sizeof(attr));
    attr.set_mode = 1;
    attr.mode = 0664;
    CHECK(D->setattr_cred(inst, "/chown.me", &attr, &CRED_ALICE) == NGX_OK,
          "owner chmod: %s", strerror(errno));
    errno = 0;
    CHECK(D->setattr_cred(inst, "/chown.me", &attr, &CRED_BOB) == NGX_ERROR
          && errno == EPERM, "non-owner chmod allowed (errno %d)", errno);

    /* chown to another uid is service-only */
    memset(&attr, 0, sizeof(attr));
    attr.set_owner = 1;
    attr.uid = (uid_t) bobst.uid;
    attr.gid = (gid_t) -1;
    errno = 0;
    CHECK(D->setattr_cred(inst, "/chown.me", &attr, &CRED_ALICE) == NGX_ERROR
          && errno == EPERM, "give-away chown allowed (errno %d)", errno);
    CHECK(D->setattr_cred(inst, "/chown.me", &attr, NULL) == NGX_OK,
          "service chown: %s", strerror(errno));
    CHECK(D->stat(inst, "/chown.me", &st) == NGX_OK && st.uid == bobst.uid,
          "service chown not applied");

    /* chgrp: owner may move into own VO, not a foreign one */
    memset(&attr, 0, sizeof(attr));
    attr.set_owner = 1;
    attr.uid = (uid_t) -1;
    attr.gid = (gid_t) bobst.gid;            /* cms — bob's VO */
    CHECK(D->setattr_cred(inst, "/bob.dat", &attr, &CRED_BOB) == NGX_OK,
          "chgrp into own VO: %s", strerror(errno));
    CHECK(D->stat(inst, "/atlas", &st) == NGX_OK, "stat /atlas");
    attr.gid = (gid_t) st.gid;               /* atlas — NOT bob's VO */
    errno = 0;
    CHECK(D->setattr_cred(inst, "/bob.dat", &attr, &CRED_BOB) == NGX_ERROR
          && errno == EPERM, "chgrp into foreign VO allowed (errno %d)",
          errno);
}

/* xattr mode gates (R to read, W to write) and the sticky top level: users
 * cannot delete or rename each other's root entries, owners can. */
static void
test_ident_xattr_sticky(brix_sd_instance_t *inst)
{
    char    buf[16];
    ssize_t n;
    int     alice_err = 0;

    /* /a.dat is alice's, 0640 (VO atlas may read) */
    CHECK(D->setxattr_cred(inst, "/a.dat", "user.t", "1", 1, 0,
                           &CRED_ALICE) == NGX_OK,
          "owner setxattr: %s", strerror(errno));
    n = D->getxattr_cred(inst, "/a.dat", "user.t", buf, sizeof(buf),
                         &CRED_CAROL);
    CHECK(n == 1 && buf[0] == '1', "same-VO getxattr n=%zd", n);
    errno = 0;
    CHECK(D->setxattr_cred(inst, "/a.dat", "user.t", "2", 1, 0,
                           &CRED_CAROL) == NGX_ERROR && errno == EACCES,
          "read-only VO member setxattr allowed (errno %d)", errno);
    errno = 0;
    n = D->listxattr_cred(inst, "/a.dat", buf, sizeof(buf), &CRED_BOB);
    CHECK(n == -1 && errno == EACCES, "foreign-VO listxattr n=%zd", n);
    errno = 0;
    CHECK(D->removexattr_cred(inst, "/a.dat", "user.t",
                              &CRED_BOB) == NGX_ERROR && errno == EACCES,
          "foreign-VO removexattr allowed (errno %d)", errno);

    /* the denials are symmetric: alice cannot write to or delete bob's file
     * either (/bob.dat is 0640, gid cms — alice is other class) */
    errno = 0;
    CHECK(D->open_cred(inst, "/bob.dat", BRIX_SD_O_WRITE, 0, &CRED_ALICE,
                       &alice_err) == NULL && alice_err == EACCES,
          "alice write on bob's file allowed (err %d)", alice_err);
    errno = 0;
    CHECK(D->unlink_cred(inst, "/bob.dat", 0, &CRED_ALICE) == NGX_ERROR
          && errno == EPERM, "alice unlink of bob's file allowed (errno %d)",
          errno);

    /* sticky synthetic root: only the owner removes/renames a root entry */
    errno = 0;
    CHECK(D->unlink_cred(inst, "/a.dat", 0, &CRED_BOB) == NGX_ERROR
          && errno == EPERM, "cross-user root unlink allowed (errno %d)",
          errno);
    errno = 0;
    CHECK(D->rename_cred(inst, "/a.dat", "/stolen.dat", 0,
                         &CRED_BOB) == NGX_ERROR && errno == EPERM,
          "cross-user root rename allowed (errno %d)", errno);
    CHECK(D->rename_cred(inst, "/a.dat", "/a2.dat", 0,
                         &CRED_ALICE) == NGX_OK,
          "owner root rename: %s", strerror(errno));
    CHECK(D->unlink_cred(inst, "/a2.dat", 0, &CRED_ALICE) == NGX_OK,
          "owner root unlink: %s", strerror(errno));

    /* server_copy: source readability is enforced */
    errno = 0;
    CHECK(D->server_copy_cred(inst, "/bob.dat", "/copy.dat", NULL,
                              &CRED_CAROL) == NGX_ERROR && errno == EACCES,
          "unreadable-source copy allowed (errno %d)", errno);
    CHECK(D->server_copy_cred(inst, "/bob.dat", "/copy.dat", NULL,
                              &CRED_BOB) == NGX_OK,
          "owner copy: %s", strerror(errno));
}

/* fresh export so the sticky synthetic root + registry start empty. */
static void
test_identity(void)
{
    char                 root[] = "/tmp/pb_id.XXXXXX";
    brix_sd_instance_t inst;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    CHECK(open_block_export(&inst, root, 0) == 0, "init identity export");
    CHECK((D->cred_accept & BRIX_SD_CRED_IDENTITY) != 0,
          "driver does not advertise IDENTITY");

    test_ident_ownership(&inst);
    test_ident_vo_dir(&inst);
    test_ident_traverse(&inst);
    test_ident_setattr(&inst);
    test_ident_xattr_sticky(&inst);

    D->cleanup(&inst);
}

/* ---- Phase-83 lab features (F0/F1/F2/F8/F14) ------------------------------ *
 * Driven the way a real test drives them: the static opts sidecar selects the
 * fail-closed gate + caps mask, and ctl-table rows (written here through a second
 * SQLite connection, exactly as a pytest would via the sqlite3 CLI) carry the
 * runtime fault/shape rules. */

static void
lab_write_sidecar(const char *root, const char *line)
{
    char  path[PATH_MAX];
    FILE *f;

    snprintf(path, sizeof(path), "%s/pblock.opts", root);
    f = fopen(path, "we");
    CHECK(f != NULL, "sidecar create");
    if (f != NULL) {
        fputs(line, f);
        fputc('\n', f);
        fclose(f);
    }
}

static void
lab_ctl_set(const char *root, const char *key, const char *val, long epoch)
{
    char      db[PATH_MAX];
    sqlite3  *h = NULL;
    char     *sql;

    snprintf(db, sizeof(db), "%s/catalog.db", root);
    CHECK(sqlite3_open(db, &h) == SQLITE_OK, "ctl db open");
    (void) sqlite3_exec(h,
        "CREATE TABLE IF NOT EXISTS ctl(key TEXT PRIMARY KEY,"
        " value TEXT NOT NULL DEFAULT '', epoch INTEGER NOT NULL DEFAULT 0);",
        NULL, NULL, NULL);
    sql = sqlite3_mprintf(
        "INSERT OR REPLACE INTO ctl(key,value,epoch) VALUES(%Q,%Q,%ld);",
        key, val, epoch);
    CHECK(sqlite3_exec(h, sql, NULL, NULL, NULL) == SQLITE_OK, "ctl insert");
    sqlite3_free(sql);
    sqlite3_close(h);
}

/* F1: a fault.pread rule injects EIO on read for handles opened after it is set;
 * a read on a handle opened with no rule succeeds (success + error). */
static void
test_lab_fault_inject(void)
{
    char                  root[] = "/tmp/pb_lab.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};   /* zero enforce_unprivileged: never drop in the unit test */
    char                  buf[32];
    int                   err = 0;
    brix_sd_obj_t        *o;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    lab_write_sidecar(root, "lab=1");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 0;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "lab init");

    CHECK(write_file(&inst, "/f", "hello", 5) == 0, "seed write");

    /* SUCCESS: no read fault yet → clean read. */
    o = D->open(&inst, "/f", BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "open read (clean)");
    if (o != NULL) {
        CHECK(D->pread(o, buf, sizeof(buf), 0) == 5, "clean pread");
        pb_close(o);
    }

    /* ERROR: set a read fault, reopen → the new handle's snapshot injects EIO. */
    lab_ctl_set(root, "fault.pread", "errno=EIO", 1);
    o = D->open(&inst, "/f", BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "open read (faulted)");
    if (o != NULL) {
        errno = 0;
        CHECK(D->pread(o, buf, sizeof(buf), 0) == -1 && errno == EIO,
              "faulted pread → EIO");
        pb_close(o);
    }
    D->cleanup(&inst);
}

/* SECURITY-NEG: with the master gate OFF (no sidecar) a ctl fault rule is
 * completely inert — pblock stays byte-for-byte the production driver. */
static void
test_lab_gate_closed(void)
{
    char                  root[] = "/tmp/pb_laboff.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};
    char                  buf[32];
    int                   err = 0;
    brix_sd_obj_t        *o;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    /* deliberately NO sidecar → lab OFF */
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 0;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "laboff init");

    CHECK(write_file(&inst, "/f", "hello", 5) == 0, "seed write");
    lab_ctl_set(root, "fault.pread", "errno=EIO", 1);   /* must be ignored */

    o = D->open(&inst, "/f", BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "open read");
    if (o != NULL) {
        CHECK(D->pread(o, buf, sizeof(buf), 0) == 5, "gate-off pread ignores fault");
        pb_close(o);
    }
    CHECK(inst.caps == D->caps, "gate-off leaves caps unmasked");
    D->cleanup(&inst);
}

/* F2: caps=-sendfile in the sidecar masks SENDFILE out of the instance's
 * effective caps while leaving unrelated bits intact. */
static void
test_lab_caps_mask(void)
{
    char                  root[] = "/tmp/pb_caps.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    lab_write_sidecar(root, "lab=1&caps=-sendfile");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 0;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "caps init");
    CHECK(!(inst.caps & BRIX_SD_CAP_SENDFILE), "sendfile masked out");
    CHECK(inst.caps & BRIX_SD_CAP_FD, "fd retained");
    CHECK(inst.caps & BRIX_SD_CAP_CATALOG, "catalog retained");
    D->cleanup(&inst);
}

/* F14: catalog enumeration is a flat scan reporting every stored file (never a
 * directory) at any depth in one pass — three independent oracles (enumerate
 * count, enumerate size-sum, a recursive namespace walk) must agree. The scan is
 * UNCONFINED: a nested object comes back by its full path with no subtree gate,
 * which is precisely why enumeration is a service-plane inventory verb — there is
 * no cred-scoped variant, so it is unreachable from user protocols. An aborting
 * callback stops the walk early yet the slot still returns NGX_OK. */
typedef struct {
    int     files;       /* non-directory rows reported                 */
    int64_t bytes;       /* summed size (valid only when want_stat)     */
    int     saw_nested;  /* the nested /d/c path was reported           */
    int     stop_after;  /* 0 = run to completion, else abort after N   */
} enum_probe_t;

static int
enum_probe_cb(void *ctx, const brix_sd_catalog_ent_t *ent)
{
    enum_probe_t *p = ctx;

    if (ent->key == NULL) {
        return 0;
    }
    p->files++;
    if (ent->have_stat) {
        p->bytes += (int64_t) ent->size;
    }
    if (ent->path != NULL && strcmp(ent->path, "/d/c") == 0) {
        p->saw_nested = 1;
    }
    return (p->stop_after && p->files >= p->stop_after) ? 1 : 0;
}

/* Independent oracle: recursively walk the namespace, counting regular files and
 * summing their stat sizes. opendir/readdir/stat only — no catalog SELECT. */
static void
enum_walk(brix_sd_instance_t *inst, const char *dir, int *files, int64_t *bytes)
{
    brix_sd_dir_t   *d;
    brix_sd_dirent_t de;
    int              err = 0;

    d = D->opendir(inst, dir, &err);
    if (d == NULL) {
        return;
    }
    while (D->readdir(d, &de) == NGX_OK) {
        char           child[512];
        brix_sd_stat_t st;

        (void) snprintf(child, sizeof(child), "%s%s%s", dir,
                        (strcmp(dir, "/") == 0) ? "" : "/", de.name);
        if (D->stat(inst, child, &st) != NGX_OK) {
            continue;
        }
        if (st.is_dir) {
            enum_walk(inst, child, files, bytes);
        } else {
            (*files)++;
            *bytes += (int64_t) st.size;
        }
    }
    D->closedir(d);
}

static void
test_lab_enumerate(void)
{
    char                  root[] = "/tmp/pb_enum.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};
    enum_probe_t          p;
    int                   walk_files = 0;
    int64_t               walk_bytes = 0;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 0;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "enum init");

    /* three files (distinct sizes 1/3/5 = 9 bytes) + one directory. */
    CHECK(write_file(&inst, "/a", "x", 1) == 0, "a");
    CHECK(write_file(&inst, "/b", "yyy", 3) == 0, "b");
    CHECK(D->mkdir(&inst, "/d", 0755) == NGX_OK, "mkdir d");
    CHECK(write_file(&inst, "/d/c", "zzzzz", 5) == 0, "c");

    /* SUCCESS + THREE-ORACLE AGREEMENT: enumerate (want_stat) reports 3 files
     * summing to 9 bytes, and a recursive namespace walk reports the same — the
     * /d directory is excluded, the nested /d/c is present (unconfined scan). */
    memset(&p, 0, sizeof(p));
    CHECK(D->enumerate(&inst, 1, enum_probe_cb, &p) == NGX_OK, "enumerate ok");
    CHECK(p.files == 3, "enumerate counted %d files (want 3)", p.files);
    CHECK(p.bytes == 9, "enumerate size-sum %lld (want 9)", (long long) p.bytes);
    CHECK(p.saw_nested, "nested /d/c absent — scan must be unconfined");

    enum_walk(&inst, "/", &walk_files, &walk_bytes);
    CHECK(walk_files == p.files && walk_bytes == p.bytes,
          "oracle drift: walk=%d/%lld enumerate=%d/%lld",
          walk_files, (long long) walk_bytes, p.files, (long long) p.bytes);

    /* EARLY-ABORT: cb aborts after one row; slot still NGX_OK. */
    memset(&p, 0, sizeof(p));
    p.stop_after = 1;
    CHECK(D->enumerate(&inst, 0, enum_probe_cb, &p) == NGX_OK, "enumerate abort ok");
    CHECK(p.files == 1, "abort stopped after %d (want 1)", p.files);

    /* SECURITY-NEG: the enumerate verb is service-plane only — there is no
     * cred-scoped enumerate slot in the driver vtable, so an identity/user
     * protocol path can never reach the unconfined catalog scan. */
    CHECK(D->enumerate != NULL, "enumerate advertised");
    CHECK((D->caps & BRIX_SD_CAP_CATALOG) != 0, "CAP_CATALOG advertised");

    D->cleanup(&inst);
}

/* ---- F10 refcounted blobs + dedup ----------------------------------------- *
 * Introspect the catalog directly (a second SQLite connection, as a pytest
 * would) to prove sharing: objects.blob_id tells us which physical blob backs a
 * path, blobs.refcount tells us how many rows share it. */

/* q_blob_id — the blob_id backing `path` (or "" if the row is missing). */
static void
q_blob_id(const char *root, const char *path, char *out, size_t cap)
{
    char          db[PATH_MAX];
    sqlite3      *h = NULL;
    sqlite3_stmt *q = NULL;

    out[0] = '\0';
    snprintf(db, sizeof(db), "%s/catalog.db", root);
    CHECK(sqlite3_open(db, &h) == SQLITE_OK, "blobid db open");
    if (sqlite3_prepare_v2(h,
            "SELECT blob_id FROM objects WHERE path = ?1;", -1, &q, NULL)
        == SQLITE_OK)
    {
        sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
        if (sqlite3_step(q) == SQLITE_ROW) {
            const unsigned char *b = sqlite3_column_text(q, 0);

            snprintf(out, cap, "%s", b ? (const char *) b : "");
        }
    }
    sqlite3_finalize(q);
    sqlite3_close(h);
}

/* q_refcount — a blob's tracked refcount, or -1 if there is no row (which the
 * driver reads as the implicit single reference). */
static int
q_refcount(const char *root, const char *blob_id)
{
    char          db[PATH_MAX];
    sqlite3      *h = NULL;
    sqlite3_stmt *q = NULL;
    int           n = -1;

    snprintf(db, sizeof(db), "%s/catalog.db", root);
    CHECK(sqlite3_open(db, &h) == SQLITE_OK, "refcount db open");
    if (sqlite3_prepare_v2(h,
            "SELECT refcount FROM blobs WHERE blob_id = ?1;", -1, &q, NULL)
        == SQLITE_OK)
    {
        sqlite3_bind_text(q, 1, blob_id, -1, SQLITE_STATIC);
        if (sqlite3_step(q) == SQLITE_ROW) {
            n = sqlite3_column_int(q, 0);
        }
    }
    sqlite3_finalize(q);
    sqlite3_close(h);
    return n;
}

/* q_count — evaluate a literal single-value COUNT query against the catalog.
 * -1 on any error. The SQL is a test constant, never attacker-derived. */
static int
q_count(const char *root, const char *sql)
{
    char          db[PATH_MAX];
    sqlite3      *h = NULL;
    sqlite3_stmt *q = NULL;
    int           n = -1;

    snprintf(db, sizeof(db), "%s/catalog.db", root);
    CHECK(sqlite3_open(db, &h) == SQLITE_OK, "count db open");
    if (sqlite3_prepare_v2(h, sql, -1, &q, NULL) == SQLITE_OK
        && sqlite3_step(q) == SQLITE_ROW)
    {
        n = sqlite3_column_int(q, 0);
    }
    sqlite3_finalize(q);
    sqlite3_close(h);
    return n;
}

/* staged_put — publish `data` at `path` through the atomic staged path (the same
 * path a wire PUT takes), so an overwrite fires F11 version capture / F10 dedup.
 * 0 or -1. */
static int
staged_put(brix_sd_instance_t *inst, const char *path, const char *data,
    size_t len)
{
    int               err = 0;
    brix_sd_staged_t *s = D->staged_open(inst, path, 0644, &err);

    if (s == NULL) {
        errno = err;
        return -1;
    }
    if (D->staged_write(s, data, len, 0) != (ssize_t) len) {
        D->staged_abort(s);
        return -1;
    }
    return D->staged_commit(s, 0) == NGX_OK ? 0 : -1;
}

/* trunc_write — O_TRUNC-create `path` (breaks any share), write `data`, close. */
static int
trunc_write(brix_sd_instance_t *inst, const char *path, const char *data,
    size_t len)
{
    int            err = 0;
    brix_sd_obj_t *o;
    ssize_t        n;

    o = D->open(inst, path,
                BRIX_SD_O_WRITE | BRIX_SD_O_READ | BRIX_SD_O_CREATE
                    | BRIX_SD_O_TRUNC,
                0644, &err);
    if (o == NULL) {
        return -1;
    }
    n = D->pwrite(o, data, len, 0);
    pb_close(o);
    return (n == (ssize_t) len) ? 0 : -1;
}

struct break_arg {
    brix_sd_instance_t *inst;
    const char         *path;
    const char         *data;
    size_t              len;
    int                 rc;
};

static void *
break_body(void *p)
{
    struct break_arg *a = p;

    a->rc = trunc_write(a->inst, a->path, a->data, a->len);
    return NULL;
}

static void
test_dedup_refs(void)
{
    char                  root[] = "/tmp/pb_dedup.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};
    char                  ba[PBLOCK_BLOB_ID_CAP], bb[PBLOCK_BLOB_ID_CAP];
    char                  buf[64];
    /* 10 bytes over a 4-byte stripe ⇒ 3 blocks: byte-verify walks real blocks. */
    const char           *DATA = "abcdefghij";
    off_t                 bytes = 0;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    lab_write_sidecar(root, "dedup=1");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 4;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "dedup init");

    /* SUCCESS: two identical PUTs fold onto one blob (refcount 2). */
    CHECK(write_file(&inst, "/d1", DATA, 10) == 0, "seed d1");
    CHECK(write_file(&inst, "/d2", DATA, 10) == 0, "seed d2");
    q_blob_id(root, "/d1", ba, sizeof(ba));
    q_blob_id(root, "/d2", bb, sizeof(bb));
    CHECK(ba[0] && strcmp(ba, bb) == 0, "identical content shares blob");
    CHECK(q_refcount(root, ba) == 2, "shared blob refcount 2 (got %d)",
          q_refcount(root, ba));
    CHECK(read_file(&inst, "/d1", buf, sizeof(buf)) == 10
          && memcmp(buf, DATA, 10) == 0, "d1 reads back");
    CHECK(read_file(&inst, "/d2", buf, sizeof(buf)) == 10
          && memcmp(buf, DATA, 10) == 0, "d2 reads back");

    /* Unlinking one sharer decrements, never removes the shared blocks. */
    CHECK(D->unlink(&inst, "/d1", 0) == NGX_OK, "unlink d1");
    CHECK(q_refcount(root, bb) == 1, "refcount 1 after one unlink (got %d)",
          q_refcount(root, bb));
    CHECK(read_file(&inst, "/d2", buf, sizeof(buf)) == 10
          && memcmp(buf, DATA, 10) == 0, "survivor d2 intact");

    /* server_copy = O(metadata) CoW: dst shares the src blob, refcount 2. */
    CHECK(D->server_copy(&inst, "/d2", "/d3", &bytes) == NGX_OK, "cow copy");
    q_blob_id(root, "/d3", ba, sizeof(ba));
    CHECK(strcmp(ba, bb) == 0, "cow copy shares src blob");
    CHECK(q_refcount(root, bb) == 2, "cow refcount 2 (got %d)",
          q_refcount(root, bb));

    /* ERROR/CoW break: overwriting a shared path forks a private blob; the
     * sibling is untouched and the two blob_ids diverge. */
    CHECK(trunc_write(&inst, "/d3", "ZZZ", 3) == 0, "overwrite d3");
    q_blob_id(root, "/d3", ba, sizeof(ba));
    CHECK(strcmp(ba, bb) != 0, "overwrite broke the share");
    CHECK(read_file(&inst, "/d2", buf, sizeof(buf)) == 10
          && memcmp(buf, DATA, 10) == 0, "d2 unchanged after d3 overwrite");
    CHECK(read_file(&inst, "/d3", buf, sizeof(buf)) == 3
          && memcmp(buf, "ZZZ", 3) == 0, "d3 has new content");
    CHECK(q_refcount(root, bb) == 1, "src refcount back to 1 (got %d)",
          q_refcount(root, bb));

    /* CONCURRENCY (the plan's critical-correctness item): two threads break the
     * share on the same source blob at once — each must end with its own private
     * content, and neither may see the other's bytes. */
    CHECK(write_file(&inst, "/c1", DATA, 10) == 0, "seed c1");
    CHECK(D->server_copy(&inst, "/c1", "/c2", &bytes) == NGX_OK, "share c1→c2");
    {
        pthread_t        t1, t2;
        struct break_arg a1 = { &inst, "/c1", "11111", 5, -1 };
        struct break_arg a2 = { &inst, "/c2", "222222", 6, -1 };

        CHECK(pthread_create(&t1, NULL, break_body, &a1) == 0, "spawn t1");
        CHECK(pthread_create(&t2, NULL, break_body, &a2) == 0, "spawn t2");
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        CHECK(a1.rc == 0 && a2.rc == 0, "both concurrent breaks succeeded");
    }
    CHECK(read_file(&inst, "/c1", buf, sizeof(buf)) == 5
          && memcmp(buf, "11111", 5) == 0, "c1 has its own content");
    CHECK(read_file(&inst, "/c2", buf, sizeof(buf)) == 6
          && memcmp(buf, "222222", 6) == 0, "c2 has its own content");
    q_blob_id(root, "/c1", ba, sizeof(ba));
    q_blob_id(root, "/c2", bb, sizeof(bb));
    CHECK(strcmp(ba, bb) != 0, "concurrent breaks produced distinct blobs");

    D->cleanup(&inst);
}

/* SECURITY-NEG: a forged blobs.content_hash must NOT let differing content
 * alias — dedup byte-verifies the candidate and rejects the mismatch. */
static void
test_dedup_forged_hash(void)
{
    char                  root[] = "/tmp/pb_forge.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};
    char                  bvictim[PBLOCK_BLOB_ID_CAP];
    char                  battack[PBLOCK_BLOB_ID_CAP];
    char                  hash[64];
    char                  db[PATH_MAX], buf[64];
    sqlite3              *h = NULL;
    sqlite3_stmt         *q = NULL;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    lab_write_sidecar(root, "dedup=1");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 4;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "forge init");

    /* Victim blob with a genuine hash; attacker file of the SAME size but
     * DIFFERENT bytes. */
    CHECK(write_file(&inst, "/victim", "AAAAAAAA", 8) == 0, "seed victim");
    CHECK(write_file(&inst, "/attack", "BBBBBBBB", 8) == 0, "seed attack");
    q_blob_id(root, "/victim", bvictim, sizeof(bvictim));
    q_blob_id(root, "/attack", battack, sizeof(battack));
    CHECK(strcmp(bvictim, battack) != 0, "different content keeps blobs apart");

    /* Forge the attacker row's hash to equal the victim's — a same-size,
     * same-block-size candidate the SELECT will now return. */
    hash[0] = '\0';
    snprintf(db, sizeof(db), "%s/catalog.db", root);
    CHECK(sqlite3_open(db, &h) == SQLITE_OK, "forge db open");
    if (sqlite3_prepare_v2(h,
            "SELECT content_hash FROM blobs WHERE blob_id = ?1;", -1, &q, NULL)
        == SQLITE_OK)
    {
        sqlite3_bind_text(q, 1, bvictim, -1, SQLITE_STATIC);
        if (sqlite3_step(q) == SQLITE_ROW) {
            const unsigned char *b = sqlite3_column_text(q, 0);

            snprintf(hash, sizeof(hash), "%s", b ? (const char *) b : "");
        }
    }
    sqlite3_finalize(q);
    q = NULL;
    if (sqlite3_prepare_v2(h,
            "UPDATE blobs SET content_hash = ?2 WHERE blob_id = ?1;", -1, &q,
            NULL) == SQLITE_OK)
    {
        sqlite3_bind_text(q, 1, battack, -1, SQLITE_STATIC);
        sqlite3_bind_text(q, 2, hash, -1, SQLITE_STATIC);
        CHECK(sqlite3_step(q) == SQLITE_DONE, "forge update");
    }
    sqlite3_finalize(q);
    sqlite3_close(h);

    /* Re-publish a THIRD identical-to-victim file: its only forged-hash
     * candidate is the attacker blob, whose bytes differ — byte-verify must
     * reject it, so the new file shares the genuine victim blob, never the
     * attacker's. Content stays correct regardless. */
    CHECK(write_file(&inst, "/probe", "AAAAAAAA", 8) == 0, "seed probe");
    CHECK(read_file(&inst, "/probe", buf, sizeof(buf)) == 8
          && memcmp(buf, "AAAAAAAA", 8) == 0, "probe content honest");
    {
        char bprobe[PBLOCK_BLOB_ID_CAP];

        q_blob_id(root, "/probe", bprobe, sizeof(bprobe));
        CHECK(strcmp(bprobe, battack) != 0, "probe did NOT alias attacker blob");
    }
    /* The attacker blob is unchanged — no reference was ever redirected to it. */
    CHECK(read_file(&inst, "/attack", buf, sizeof(buf)) == 8
          && memcmp(buf, "BBBBBBBB", 8) == 0, "attacker content untouched");

    D->cleanup(&inst);
}

/* SECURITY-NEG (gate off): with no dedup opt, identical PUTs stay physically
 * distinct — no blobs table, no sharing — so pblock is the production driver. */
static void
test_dedup_gate_closed(void)
{
    char                  root[] = "/tmp/pb_dedupoff.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};
    char                  ba[PBLOCK_BLOB_ID_CAP], bb[PBLOCK_BLOB_ID_CAP];
    char                  buf[64];

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    /* deliberately NO dedup opt → refs OFF */
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 4;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "dedupoff init");

    CHECK(write_file(&inst, "/g1", "abcdefgh", 8) == 0, "seed g1");
    CHECK(write_file(&inst, "/g2", "abcdefgh", 8) == 0, "seed g2");
    q_blob_id(root, "/g1", ba, sizeof(ba));
    q_blob_id(root, "/g2", bb, sizeof(bb));
    CHECK(ba[0] && strcmp(ba, bb) != 0, "gate-off keeps identical PUTs distinct");
    CHECK(D->unlink(&inst, "/g1", 0) == NGX_OK, "unlink g1");
    CHECK(read_file(&inst, "/g2", buf, sizeof(buf)) == 8
          && memcmp(buf, "abcdefgh", 8) == 0, "g2 intact after g1 unlink");
    D->cleanup(&inst);
}

/* F6 snapshots — take/restore via the reserved-namespace control paths, exactly
 * as the wire reaches them: mkdir /.pblock/snap/<n> takes, mkdir
 * /.pblock/restore/<n> restores, rmdir /.pblock/snap/<n> drops. snap=1 auto-arms
 * F10 refs (a snapshot pins shared blobs so a delete-between-take-and-restore
 * decrements rather than physically removes). Three legs:
 *   SUCCESS      — snapshot, delete everything, restore, byte-identical reads.
 *   ERROR        — restore refused (EBUSY, not corruption) while a handle is open.
 *   SECURITY-NEG — a hostile snapshot name (SQL/traversal metachars) is rejected;
 *                  the name is only ever a bound column, so injection is out. */
static void
test_snapshot(void)
{
    char                  root[] = "/tmp/pb_snap.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};
    char                  buf[64];

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    lab_write_sidecar(root, "snap=1");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 4;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "snap init");

    /* SUCCESS: seed two files (b spans >1 block), snapshot, delete everything,
     * restore, and read back byte-identical content. */
    CHECK(write_file(&inst, "/a", "alpha", 5) == 0, "seed a");
    CHECK(write_file(&inst, "/b", "bravodata", 9) == 0, "seed b");
    CHECK(D->mkdir(&inst, "/.pblock/snap/fix", 0755) == NGX_OK, "take snapshot");

    CHECK(D->unlink(&inst, "/a", 0) == NGX_OK, "delete a");
    CHECK(D->unlink(&inst, "/b", 0) == NGX_OK, "delete b");
    errno = 0;
    CHECK(read_file(&inst, "/a", buf, sizeof(buf)) == -1 && errno == ENOENT,
          "a gone before restore");

    CHECK(D->mkdir(&inst, "/.pblock/restore/fix", 0755) == NGX_OK, "restore");
    CHECK(read_file(&inst, "/a", buf, sizeof(buf)) == 5
          && memcmp(buf, "alpha", 5) == 0, "a restored byte-identical");
    CHECK(read_file(&inst, "/b", buf, sizeof(buf)) == 9
          && memcmp(buf, "bravodata", 9) == 0, "b restored byte-identical");

    /* ERROR: a live regular-file handle bumps open_files; restore must refuse
     * with EBUSY (never swap the namespace out from under an open fd) and leave
     * the namespace untouched. */
    {
        int             err = 0;
        brix_sd_obj_t *o = D->open(&inst, "/a", BRIX_SD_O_READ, 0, &err);

        CHECK(o != NULL, "open handle for EBUSY: %s", strerror(err));
        errno = 0;
        CHECK(D->mkdir(&inst, "/.pblock/restore/fix", 0755) == NGX_ERROR
              && errno == EBUSY, "restore refused while a handle is open");
        CHECK(read_file(&inst, "/a", buf, sizeof(buf)) == 5
              && memcmp(buf, "alpha", 5) == 0, "a intact after refused restore");
        if (o != NULL) { pb_close(o); }
    }

    /* SECURITY-NEG: a snapshot name carrying SQL/traversal metacharacters is
     * rejected at the charset gate (EINVAL); the snapshots table is unharmed, so
     * a subsequent legitimate snapshot still succeeds. */
    errno = 0;
    CHECK(D->mkdir(&inst, "/.pblock/snap/x';DROP TABLE snapshots;--", 0755)
              == NGX_ERROR && errno == EINVAL,
          "hostile snapshot name rejected");
    CHECK(D->mkdir(&inst, "/.pblock/snap/second", 0755) == NGX_OK,
          "legit snapshot still works after the injection attempt");
    /* drop it again via rmdir on the reserved control path. */
    CHECK(D->unlink(&inst, "/.pblock/snap/second", 1) == NGX_OK,
          "drop snapshot via rmdir");

    D->cleanup(&inst);
}

/* F11 versioning + trash/undelete — versions=N holds the prior blob on each
 * overwrite-publish (trimmed to N generations); trash=1 moves an unlink into the
 * trash (blob held) and mkdir /.pblock/undelete/<path> pops it back. Both build
 * ON F10 refs (a held blob is a live reference, decremented not freed). Legs:
 *   SUCCESS      — three overwrites keep exactly N=2 versions (the oldest is
 *                  trimmed and its blob freed); a trashed file undeletes
 *                  byte-identical through the reserved control path.
 *   ERROR        — undelete of a never-trashed name is ENOENT; undelete over a
 *                  live object is EEXIST.
 *   SECURITY-NEG — a hostile undelete path (SQL metachars) is a bound column, so
 *                  it can only miss (ENOENT); the trash table is unharmed and a
 *                  legitimate undelete still works. */
static void
test_versioning(void)
{
    char                  root[] = "/tmp/pb_ver.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};
    char                  a0[PBLOCK_BLOB_ID_CAP], b1[PBLOCK_BLOB_ID_CAP];
    char                  c2[PBLOCK_BLOB_ID_CAP], g0[PBLOCK_BLOB_ID_CAP];
    char                  buf[64];

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    lab_write_sidecar(root, "versions=2&trash=1");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 4;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "versioning init");

    /* SUCCESS (versions + trim). Each overwrite captures the prior blob as a new
     * generation; the blob is held (refcount 1), not freed. */
    CHECK(staged_put(&inst, "/f", "AAAA", 4) == 0, "seed v1");
    q_blob_id(root, "/f", a0, sizeof(a0));
    CHECK(staged_put(&inst, "/f", "BBBBBB", 6) == 0, "overwrite v2");
    q_blob_id(root, "/f", b1, sizeof(b1));
    CHECK(q_count(root, "SELECT COUNT(*) FROM versions WHERE path='/f'") == 1,
          "one version after first overwrite");
    CHECK(q_refcount(root, a0) == 1, "prior blob held by the version (got %d)",
          q_refcount(root, a0));

    CHECK(staged_put(&inst, "/f", "CCCCCCCC", 8) == 0, "overwrite v3");
    q_blob_id(root, "/f", c2, sizeof(c2));
    CHECK(q_count(root, "SELECT COUNT(*) FROM versions WHERE path='/f'") == 2,
          "two versions after second overwrite");

    /* The fourth publish trims to N=2: the oldest generation (a0) is dropped and
     * its blob — referenced nowhere else — is freed. */
    CHECK(staged_put(&inst, "/f", "DD", 2) == 0, "overwrite v4 (trims oldest)");
    CHECK(q_count(root, "SELECT COUNT(*) FROM versions WHERE path='/f'") == 2,
          "still exactly N=2 versions after trim");
    CHECK(q_count(root, "SELECT COUNT(*) FROM versions WHERE blob_id='' ") == 0,
          "no version row lost its blob reference");
    CHECK(q_refcount(root, a0) == -1, "trimmed blob freed (got %d)",
          q_refcount(root, a0));
    CHECK(q_refcount(root, b1) == 1, "retained version b1 still held");
    CHECK(q_refcount(root, c2) == 1, "retained version c2 still held");
    CHECK(read_file(&inst, "/f", buf, sizeof(buf)) == 2
          && memcmp(buf, "DD", 2) == 0, "live /f is the newest content");

    /* SUCCESS (trash + undelete): unlink moves /g into the trash (blob held);
     * mkdir /.pblock/undelete/g pops it back byte-identical. */
    CHECK(staged_put(&inst, "/g", "hello", 5) == 0, "seed /g");
    q_blob_id(root, "/g", g0, sizeof(g0));
    CHECK(D->unlink(&inst, "/g", 0) == NGX_OK, "unlink /g to trash");
    errno = 0;
    CHECK(read_file(&inst, "/g", buf, sizeof(buf)) == -1 && errno == ENOENT,
          "/g gone from the namespace");
    CHECK(q_refcount(root, g0) == 1, "trashed blob held (got %d)",
          q_refcount(root, g0));
    CHECK(D->mkdir(&inst, "/.pblock/undelete/g", 0755) == NGX_OK, "undelete /g");
    CHECK(read_file(&inst, "/g", buf, sizeof(buf)) == 5
          && memcmp(buf, "hello", 5) == 0, "/g undeleted byte-identical");

    /* ERROR: undelete of a never-trashed name is ENOENT; undelete over the now
     * live /g is EEXIST (never clobber a live object). */
    errno = 0;
    CHECK(D->mkdir(&inst, "/.pblock/undelete/nope", 0755) == NGX_ERROR
          && errno == ENOENT, "undelete of a never-trashed name is ENOENT");
    errno = 0;
    CHECK(D->mkdir(&inst, "/.pblock/undelete/g", 0755) == NGX_ERROR
          && errno == EEXIST, "undelete over a live object is EEXIST");

    /* SECURITY-NEG: a hostile undelete path is only ever a bound column — it can
     * only miss (ENOENT), never inject. The trash table survives, so a real
     * trashed file still undeletes. */
    errno = 0;
    CHECK(D->mkdir(&inst, "/.pblock/undelete/x';DROP TABLE trash;--", 0755)
              == NGX_ERROR && errno == ENOENT,
          "hostile undelete path only misses");
    CHECK(staged_put(&inst, "/h", "safe", 4) == 0, "seed /h");
    CHECK(D->unlink(&inst, "/h", 0) == NGX_OK, "trash /h");
    CHECK(D->mkdir(&inst, "/.pblock/undelete/h", 0755) == NGX_OK,
          "trash table intact — legit undelete still works");
    CHECK(read_file(&inst, "/h", buf, sizeof(buf)) == 4
          && memcmp(buf, "safe", 4) == 0, "/h undeleted after injection attempt");

    D->cleanup(&inst);
}

int
main(void)
{
    char                    root[] = "/tmp/pb_ut.XXXXXX";
    brix_sd_pblock_conf_t conf = {0};
    brix_sd_instance_t    inst = {0};

    D = &brix_sd_pblock_driver;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 0;                 /* 0 ⇒ PBLOCK_DEFAULT_BLOCK_SIZE (was
                                          * left uninitialised — stack garbage) */

    inst.driver = D;
    CHECK(D->init(&inst, &conf) == NGX_OK, "init failed: %s", strerror(errno));
    if (failures) { return 1; }

    test_write_read_fstat(&inst);
    test_truncate_and_stat(&inst);
    test_preadv(&inst);
    test_dirs(&inst);
    test_rename(&inst);
    test_server_copy(&inst);
    test_xattr(&inst);
    test_staged(&inst);
    test_unlink(&inst);
    test_threads(&inst);
    test_processes(root, &inst);

    D->cleanup(&inst);
    test_fsync_durability(root);

    test_block_striping();
    test_block_size_configurable();
    test_block_sparse();
    test_block_truncate();
    test_block_copy_and_unlink();
    test_identity();

    /* Phase-83 lab features */
    test_lab_fault_inject();
    test_lab_gate_closed();
    test_lab_caps_mask();
    test_lab_enumerate();
    test_dedup_refs();          /* F10 */
    test_dedup_forged_hash();   /* F10 security-neg */
    test_dedup_gate_closed();   /* F10 gate-off inertness */
    test_snapshot();            /* F6 snapshots take/restore + EBUSY + injection */
    test_versioning();          /* F11 versions trim + trash/undelete + injection */

    if (failures == 0) {
        printf("sd_pblock_unittest: ALL PASS\n");
        return 0;
    }
    fprintf(stderr, "sd_pblock_unittest: %d FAILURE(S)\n", failures);
    return 1;
}
