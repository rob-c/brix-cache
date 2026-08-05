/*
 * object_write_unittest.c — standalone tests for the CAS object writer,
 * verified with the read path (object.c inflate/hash) as the oracle.
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_objw_ut \
 *       shared/cvmfs/object/object_write_unittest.c shared/cvmfs/object/object_write.c \
 *       shared/cvmfs/object/object.c shared/cvmfs/grammar/hash.c \
 *       shared/cache/cas_store.c shared/cache/cas_pack.c -lcrypto -lz \
 *       && /tmp/cvmfs_objw_ut
 * Exit 0 = all checks pass.
 */
#include "cvmfs/object/object_write.h"
#include "cvmfs/object/object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

static void obj_disk_path(const char *repo, const cvmfs_hash_t *h, char suffix,
                          char *buf, size_t cap) {
    char sub[80];
    cvmfs_hash_to_object_path(h, suffix, sub, sizeof(sub));
    snprintf(buf, cap, "%s/data/%s", repo, sub);
}

int main(void) {
    char repo[128];
    snprintf(repo, sizeof(repo), "/tmp/cvmfs_objw_ut.%d", getpid());
    mkdir(repo, 0755);

    cvmfs_objstore_t s;
    CHECK(cvmfs_objstore_open(&s, repo) == 0, "objstore_open creates <repo>/data");

    static const char PLAIN[] = "the quick brown fox jumps over the lazy dog\n";
    size_t plen = sizeof(PLAIN) - 1;

    /* compressed store: identity is the hash of the STORED bytes */
    cvmfs_hash_t h;
    size_t stored_len = 0;
    CHECK(cvmfs_object_store(&s, (const unsigned char *) PLAIN, plen, 0, 1,
                             &h, &stored_len) == 0, "compressed store");
    CHECK(stored_len > 0 && stored_len != plen, "stored form is compressed");
    CHECK(cvmfs_object_present(&s, &h, 0) == 1, "object present");
    CHECK(cvmfs_object_present(&s, &h, 'C') == 0, "wrong suffix absent");

    unsigned char stored[4096], back[4096];
    long got = cvmfs_object_read_stored(&s, &h, 0, stored, sizeof(stored));
    CHECK(got == (long) stored_len, "read_stored returns the stored bytes");
    CHECK(got > 0 && cvmfs_object_verify(stored, (size_t) got, &h) == 1,
          "name hash covers the stored bytes");
    size_t backlen = 0;
    CHECK(got > 0 && cvmfs_object_inflate(stored, (size_t) got,
                                          back, sizeof(back), &backlen) == 0
          && backlen == plen && memcmp(back, PLAIN, plen) == 0,
          "reader inflates back to the plaintext");

    /* uncompressed store: stored form == plain form */
    cvmfs_hash_t hu;
    size_t ulen = 0;
    CHECK(cvmfs_object_store(&s, (const unsigned char *) PLAIN, plen, 'P', 0,
                             &hu, &ulen) == 0 && ulen == plen, "verbatim store");
    got = cvmfs_object_read_stored(&s, &hu, 'P', stored, sizeof(stored));
    CHECK(got == (long) plen && memcmp(stored, PLAIN, plen) == 0,
          "verbatim bytes round-trip");

    /* suffixed catalogs coexist with content objects */
    cvmfs_hash_t hc;
    CHECK(cvmfs_object_store(&s, (const unsigned char *) PLAIN, plen, 'C', 1,
                             &hc, NULL) == 0
          && cvmfs_object_present(&s, &hc, 'C') == 1, "'C' suffix store");
    CHECK(cvmfs_hash_eq(&h, &hc), "same content, same hash, distinct suffix objects");

    /* idempotent re-store of identical content */
    cvmfs_hash_t h2;
    CHECK(cvmfs_object_store(&s, (const unsigned char *) PLAIN, plen, 0, 1,
                             &h2, NULL) == 0 && cvmfs_hash_eq(&h, &h2),
          "re-store of same content is idempotent");

    /* errors */
    CHECK(cvmfs_object_read_stored(&s, &h, 0, stored, 4) == -1,
          "read overflow refused");
    cvmfs_hash_t absent;
    memset(&absent, 0, sizeof(absent));
    absent.algo = CVMFS_HASH_SHA1;
    absent.len = 20;
    memset(absent.bytes, 0xEE, 20);
    CHECK(cvmfs_object_read_stored(&s, &absent, 0, stored, sizeof(stored)) == -1,
          "read of absent object fails");
    cvmfs_objstore_t bad;
    CHECK(cvmfs_objstore_open(&bad, "/proc/nope") != 0,
          "objstore_open on unwritable root fails");

    /* security-negative: on-disk tamper is caught by the stored-bytes hash */
    char path[512];
    obj_disk_path(repo, &h, 0, path, sizeof(path));
    FILE *f = fopen(path, "r+b");
    CHECK(f != NULL, "stored object at the CVMFS data path");
    if (f != NULL) {
        int c0 = fgetc(f);
        fseek(f, 0, SEEK_SET);
        fputc(c0 ^ 0x01, f);
        fclose(f);
    }
    got = cvmfs_object_read_stored(&s, &h, 0, stored, sizeof(stored));
    CHECK(got > 0 && cvmfs_object_verify(stored, (size_t) got, &h) == 0,
          "tampered object fails hash verify");

    /* delete: gone + idempotent */
    CHECK(cvmfs_object_delete(&s, &h, 0) == 0
          && cvmfs_object_present(&s, &h, 0) == 0, "delete removes the object");
    CHECK(cvmfs_object_delete(&s, &h, 0) == 0, "delete of absent object is a no-op");

    cvmfs_objstore_close(&s);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", repo);
    if (system(cmd) != 0) fprintf(stderr, "cleanup failed\n");
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
