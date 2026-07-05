/*
 * cas_store_unittest.c — standalone tests for the content-addressed POSIX store.
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/cas_ut \
 *       shared/cache/cas_store_unittest.c shared/cache/cas_store.c && /tmp/cas_ut
 * Exit 0 = all checks pass.
 */
#include "cache/cas_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <utime.h>

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

static void rm_rf(const char *p) {
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    if (system(cmd) != 0) { /* best effort */ }
}

int main(void) {
    char root[] = "/tmp/brix_cas_ut.XXXXXX";
    if (mkdtemp(root) == NULL) { perror("mkdtemp"); return 2; }

    brix_cas_store_t s;
    CHECK(brix_cas_init(&s, root, 0) == 0, "store init");

    const char *k1 = "abcdef0123456789abcdef0123456789abcdef01";
    CHECK(brix_cas_has(&s, k1) == 0, "miss before put");

    const char payload[] = "hello content-addressed world";
    CHECK(brix_cas_put(&s, k1, payload, sizeof(payload) - 1) == 0, "put ok");
    CHECK(brix_cas_has(&s, k1) == 1, "hit after put");

    char path[640];
    brix_cas_path(&s, k1, path, sizeof(path));
    CHECK(strstr(path, "/ab/cdef0123") != NULL, "2-hex fan-out layout");

    int fd = brix_cas_open(&s, k1);
    char buf[64] = {0};
    ssize_t r = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : -1;
    if (fd >= 0) close(fd);
    CHECK(r == (ssize_t)(sizeof(payload) - 1) && strcmp(buf, payload) == 0,
          "read back byte-exact");

    /* idempotent re-put keeps the object */
    CHECK(brix_cas_put(&s, k1, "different", 9) == 0 && brix_cas_has(&s, k1) == 1,
          "idempotent re-put");

    /* size accounting */
    CHECK(brix_cas_size(&s) == (long)(sizeof(payload) - 1), "size accounted");

    /* LRU reap: add a second, older-accessed object; reap to keep only newest */
    const char *k2 = "0011223344556677889900112233445566778899";
    brix_cas_put(&s, k2, "0123456789", 10);              /* +10 bytes */
    brix_cas_path(&s, k2, path, sizeof(path));
    struct utimbuf ut = { .actime = 1000, .modtime = 1000 };  /* very old atime */
    utime(path, &ut);
    long before = brix_cas_size(&s);
    int  removed = brix_cas_reap(&s, before - 10);       /* must drop the old one */
    CHECK(removed == 1 && brix_cas_has(&s, k2) == 0 && brix_cas_has(&s, k1) == 1,
          "LRU reap evicts oldest first");

    rm_rf(root);

    /* ---- dirfd (overlay) mode ---- */
    char droot[] = "/tmp/brix_cas_at.XXXXXX";
    if (mkdtemp(droot) == NULL) { perror("mkdtemp"); return 2; }
    int dfd = open(droot, O_RDONLY | O_DIRECTORY);
    brix_cas_store_t sa;
    CHECK(dfd >= 0 && brix_cas_init_at(&sa, dfd, 0) == 0, "dirfd store init");
    const char *dk = "aabbccddeeff00112233445566778899aabbccdd";
    CHECK(brix_cas_put(&sa, dk, "over-the-overlay", 16) == 0 && brix_cas_has(&sa, dk) == 1,
          "dirfd put+has");
    int dfd2 = brix_cas_open(&sa, dk);
    char db[32] = {0}; ssize_t dr = dfd2 >= 0 ? read(dfd2, db, sizeof(db) - 1) : -1;
    if (dfd2 >= 0) close(dfd2);
    CHECK(dr == 16 && strcmp(db, "over-the-overlay") == 0, "dirfd read back");
    /* object is physically present under the real dir path */
    char check[600]; snprintf(check, sizeof(check), "%s/aa/bbccddeeff00112233445566778899aabbccdd", droot);
    struct stat cst;
    CHECK(stat(check, &cst) == 0, "dirfd object on disk at <2>/<rest>");
    close(dfd);
    rm_rf(droot);

    /* ---- quota fill-guard (auto-reap on put) ---- */
    char qroot[] = "/tmp/brix_cas_q.XXXXXX";
    if (mkdtemp(qroot) == NULL) { perror("mkdtemp"); return 2; }
    brix_cas_store_t sq;
    brix_cas_init(&sq, qroot, 100);                 /* quota 100 bytes */
    char lastk[41];
    for (int i = 0; i < 6; i++) {
        char k[41];
        snprintf(k, sizeof(k), "%02d00000000000000000000000000000000000000", i);
        brix_cas_put(&sq, k, "0123456789012345678901234567890123456789", 40);  /* 40B */
        snprintf(lastk, sizeof(lastk), "%s", k);
    }
    CHECK(brix_cas_size(&sq) <= 100, "quota fill-guard keeps store <= quota");
    CHECK(sq.cur_bytes <= 100, "cur_bytes tracked under quota");
    CHECK(brix_cas_has(&sq, lastk) == 1, "most-recent object survives reap");
    rm_rf(qroot);

    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
