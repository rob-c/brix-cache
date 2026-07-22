/*
 * sd_pblock_unittest_core.c — core POSIX-op + concurrency slice of the pblock
 * driver unit test (split from sd_pblock_unittest.c). Shared harness (CHECK,
 * failures, D, pb_close, write_file, read_file) lives in the primary translation
 * unit; prototypes come from sd_pblock_unittest_internal.h.
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
#include <sqlite3.h>   /* Phase-83 lab tests drive the ctl table directly */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- tests ---------------------------------------------------------------- */

void
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

void
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

void
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

void
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

void
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

void
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

void
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

void
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

void
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
void
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

void
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
void
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
