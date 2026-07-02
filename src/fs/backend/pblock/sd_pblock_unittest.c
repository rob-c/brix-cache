/*
 * sd_pblock_unittest.c — standalone unit test for the pblock storage driver,
 * driven through the real xrootd_sd_driver_t vtable function pointers. No nginx,
 * no running server: it builds a throwaway export root under /tmp and exercises
 * every slot plus multi-thread and multi-process concurrency.
 *
 * Build & run (the data plane is real POSIX + SQLite, so it needs libsqlite3 and
 * the ngx-free shim surface in sd.h):
 *   cc -Wall -Wextra -DXROOTD_HAVE_SQLITE=1 -DXRDPROTO_NO_NGX -I. \
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
#include <pthread.h>
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

static const xrootd_sd_driver_t *D;   /* = &xrootd_sd_pblock_driver */

/* pb_close — close an object and free its malloc'd shell. driver->close frees the
 * per-open state + fd but not the obj struct (the VFS adopts that by value), so a
 * direct caller owns the shell. */
static ngx_int_t
pb_close(xrootd_sd_obj_t *o)
{
    ngx_int_t rc = D->close(o);

    free(o);
    return rc;
}

/* ---- small helpers over the vtable ---------------------------------------- */

/* write_file — create `path`, write `data`, close. Returns 0 or -1. */
static int
write_file(xrootd_sd_instance_t *inst, const char *path, const char *data,
    size_t len)
{
    int              err = 0;
    xrootd_sd_obj_t *o;
    ssize_t          n;

    o = D->open(inst, path,
                XROOTD_SD_O_WRITE | XROOTD_SD_O_READ | XROOTD_SD_O_CREATE,
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
read_file(xrootd_sd_instance_t *inst, const char *path, char *buf, size_t cap)
{
    int              err = 0;
    xrootd_sd_obj_t *o;
    ssize_t          n;

    o = D->open(inst, path, XROOTD_SD_O_READ, 0, &err);
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
test_write_read_fstat(xrootd_sd_instance_t *inst)
{
    int               err = 0;
    xrootd_sd_obj_t  *o;
    xrootd_sd_stat_t  st;
    char              buf[64];

    o = D->open(inst, "/hello",
                XROOTD_SD_O_WRITE | XROOTD_SD_O_READ | XROOTD_SD_O_CREATE,
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
test_truncate_and_stat(xrootd_sd_instance_t *inst)
{
    int               err = 0;
    xrootd_sd_obj_t  *o;
    xrootd_sd_stat_t  st;

    CHECK(write_file(inst, "/trunc", "0123456789", 10) == 0, "seed write");
    o = D->open(inst, "/trunc", XROOTD_SD_O_WRITE | XROOTD_SD_O_READ, 0, &err);
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
test_preadv(xrootd_sd_instance_t *inst)
{
    int              err = 0;
    xrootd_sd_obj_t *o;
    char             a[4], b[4];
    struct iovec     iov[2];

    CHECK(write_file(inst, "/vec", "ABCDEFGH", 8) == 0, "seed");
    o = D->open(inst, "/vec", XROOTD_SD_O_READ, 0, &err);
    CHECK(o != NULL, "open vec");
    if (o == NULL) { return; }
    iov[0].iov_base = a; iov[0].iov_len = 4;
    iov[1].iov_base = b; iov[1].iov_len = 4;
    CHECK(D->preadv(o, iov, 2, 0) == 8, "preadv total");
    CHECK(memcmp(a, "ABCD", 4) == 0 && memcmp(b, "EFGH", 4) == 0, "preadv data");
    pb_close(o);
}

static void
test_dirs(xrootd_sd_instance_t *inst)
{
    int               err = 0;
    xrootd_sd_dir_t  *dir;
    xrootd_sd_dirent_t de;
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
test_rename(xrootd_sd_instance_t *inst)
{
    xrootd_sd_stat_t st;
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
test_server_copy(xrootd_sd_instance_t *inst)
{
    xrootd_sd_stat_t st;
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
test_xattr(xrootd_sd_instance_t *inst)
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
test_staged(xrootd_sd_instance_t *inst)
{
    int                 err = 0;
    xrootd_sd_staged_t *s;
    xrootd_sd_stat_t    st;
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
test_unlink(xrootd_sd_instance_t *inst)
{
    xrootd_sd_stat_t st;

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
    xrootd_sd_instance_t    inst = {0};
    xrootd_sd_pblock_conf_t conf = { root, 2000, 0 };
    int                     err = 0;
    xrootd_sd_obj_t        *o;
    xrootd_sd_stat_t        st;

    inst.driver = D;
    CHECK(D->init(&inst, &conf) == NGX_OK, "second init");
    o = D->open(&inst, "/durable",
                XROOTD_SD_O_WRITE | XROOTD_SD_O_READ | XROOTD_SD_O_CREATE,
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
    xrootd_sd_instance_t *inst;
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
test_threads(xrootd_sd_instance_t *inst)
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
test_processes(const char *root, xrootd_sd_instance_t *inst)
{
    enum { NPROC = 4, NOPS = 25 };
    pid_t pids[NPROC];
    int   i, total = 0, rc;
    xrootd_sd_dir_t   *dir;
    xrootd_sd_dirent_t de;
    int                err = 0;

    CHECK(D->mkdir(inst, "/mp", 0755) == NGX_OK, "mkdir mp");

    for (i = 0; i < NPROC; i++) {
        pid_t pid = fork();

        if (pid == 0) {
            xrootd_sd_instance_t    cinst = {0};
            xrootd_sd_pblock_conf_t conf = { root, 5000, 0 };
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
open_block_export(xrootd_sd_instance_t *inst, char *root, int64_t block_size)
{
    static xrootd_sd_pblock_conf_t conf;   /* root must outlive the instance */

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
    xrootd_sd_instance_t inst;
    xrootd_sd_obj_t     *o;
    xrootd_sd_stat_t     st;
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

    o = D->open(&inst, "/big", XROOTD_SD_O_READ, 0, &err);
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
    xrootd_sd_instance_t inst;
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
    xrootd_sd_instance_t inst;
    xrootd_sd_obj_t     *o;
    xrootd_sd_stat_t     st;
    char                 buf[64];
    int                  i, err = 0;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    CHECK(open_block_export(&inst, root, 16) == 0, "init bs=16");

    o = D->open(&inst, "/sparse",
                XROOTD_SD_O_WRITE | XROOTD_SD_O_READ | XROOTD_SD_O_CREATE,
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
    xrootd_sd_instance_t inst;
    xrootd_sd_obj_t     *o;
    xrootd_sd_stat_t     st;
    char                 data[40], buf[40];
    int                  i, err = 0;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    CHECK(open_block_export(&inst, root, 16) == 0, "init bs=16");
    for (i = 0; i < 40; i++) {
        data[i] = (char) ('0' + (i % 10));
    }
    CHECK(write_file(&inst, "/t", data, 40) == 0, "seed 40");

    o = D->open(&inst, "/t", XROOTD_SD_O_WRITE | XROOTD_SD_O_READ, 0, &err);
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
    xrootd_sd_instance_t inst;
    xrootd_sd_stat_t     st;
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

int
main(void)
{
    char                    root[] = "/tmp/pb_ut.XXXXXX";
    xrootd_sd_pblock_conf_t conf;
    xrootd_sd_instance_t    inst = {0};

    D = &xrootd_sd_pblock_driver;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    conf.root = root;
    conf.busy_timeout_ms = 2000;

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

    if (failures == 0) {
        printf("sd_pblock_unittest: ALL PASS\n");
        return 0;
    }
    fprintf(stderr, "sd_pblock_unittest: %d FAILURE(S)\n", failures);
    return 1;
}
