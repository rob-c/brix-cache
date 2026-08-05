/*
 * reflog_unittest.c — standalone tests for the reflog + history (tag) DBs.
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_reflog_ut \
 *       shared/cvmfs/reflog/reflog_unittest.c shared/cvmfs/reflog/reflog.c \
 *       shared/cvmfs/history/history.c shared/cvmfs/object/object.c \
 *       shared/cvmfs/grammar/hash.c -lsqlite3 -lcrypto -lz && /tmp/cvmfs_reflog_ut
 * Exit 0 = all checks pass.
 */
#include "cvmfs/reflog/reflog.h"
#include "cvmfs/history/history.h"
#include "cvmfs/object/object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

static cvmfs_hash_t mkhash(unsigned char seed) {
    cvmfs_hash_t h;
    unsigned char b[20];
    memset(b, seed, 20);
    cvmfs_hash_from_bytes(CVMFS_HASH_SHA1, b, 20, &h);
    return h;
}

static void collect_cb(const cvmfs_hash_t *hash, cvmfs_reflog_type_e type,
                       int64_t timestamp, void *ud) {
    (void) type; (void) timestamp;
    unsigned char *first = ud;
    if (*first == 0) *first = hash->bytes[0];      /* newest-first head */
}

static void test_reflog(const char *path) {
    cvmfs_reflog_t *r = cvmfs_reflog_open(path);
    CHECK(r != NULL, "reflog opens (creates schema)");
    if (r == NULL) return;

    cvmfs_hash_t c1 = mkhash(0x11), c2 = mkhash(0x22), x1 = mkhash(0x33);
    CHECK(cvmfs_reflog_add(r, &c1, CVMFS_REFLOG_CATALOG, 100) == 0, "add catalog ref");
    CHECK(cvmfs_reflog_add(r, &c2, CVMFS_REFLOG_CATALOG, 200) == 0, "add newer catalog ref");
    CHECK(cvmfs_reflog_add(r, &x1, CVMFS_REFLOG_CERTIFICATE, 100) == 0, "add cert ref");
    CHECK(cvmfs_reflog_add(r, &c1, CVMFS_REFLOG_CATALOG, 150) == 0, "re-add refreshes");

    CHECK(cvmfs_reflog_list(r, -1, NULL, NULL) == 3, "list all sees 3 refs");
    unsigned char head = 0;
    CHECK(cvmfs_reflog_list(r, CVMFS_REFLOG_CATALOG, collect_cb, &head) == 2
          && head == 0x22, "type filter + newest-first order");

    CHECK(cvmfs_reflog_del(r, &c1, CVMFS_REFLOG_CATALOG) == 0
          && cvmfs_reflog_list(r, CVMFS_REFLOG_CATALOG, NULL, NULL) == 1,
          "del prunes one ref");
    CHECK(cvmfs_reflog_close(r) == 0, "reflog closes");

    /* persistence across open */
    r = cvmfs_reflog_open(path);
    CHECK(r != NULL && cvmfs_reflog_list(r, -1, NULL, NULL) == 2,
          "refs persist across reopen");
    if (r != NULL) cvmfs_reflog_close(r);

    /* checksum = sha1 of the file bytes (the manifest 'Y' binding) */
    cvmfs_hash_t sum1, sum2;
    CHECK(cvmfs_reflog_checksum(path, &sum1) == 0 && sum1.len == 20,
          "checksum computes");
    /* security-negative: any byte change to the reflog must change 'Y' */
    FILE *f = fopen(path, "r+b");
    if (f != NULL) {
        fseek(f, -1, SEEK_END);
        int c0 = fgetc(f);
        fseek(f, -1, SEEK_END);
        fputc(c0 ^ 0x01, f);
        fclose(f);
    }
    CHECK(cvmfs_reflog_checksum(path, &sum2) == 0 && !cvmfs_hash_eq(&sum1, &sum2),
          "tampered reflog changes the checksum");
    CHECK(cvmfs_reflog_checksum("/nonexistent/reflog", &sum1) == -1,
          "checksum of missing file fails");
    CHECK(cvmfs_reflog_open("/nonexistent/dir/reflog") == NULL,
          "open on unwritable path fails");
}

static void list_tags_cb(const cvmfs_history_tag_t *tag, void *ud) {
    char *first = ud;
    if (*first == '\0') snprintf(first, 128, "%s", tag->name);
}

static void test_history(const char *path) {
    cvmfs_history_t *h = cvmfs_history_open(path, "unit.brix.io");
    CHECK(h != NULL, "history opens (creates schema)");
    if (h == NULL) return;

    cvmfs_history_tag_t t;
    memset(&t, 0, sizeof(t));
    snprintf(t.name, sizeof(t.name), "prod");
    t.root_hash = mkhash(0x44);
    t.revision = 3;
    t.timestamp = 100;
    snprintf(t.description, sizeof(t.description), "known good");
    CHECK(cvmfs_history_tag_add(h, &t) == 0, "tag add");

    cvmfs_history_tag_t t2 = t;
    snprintf(t2.name, sizeof(t2.name), "testing");
    t2.root_hash = mkhash(0x55);
    t2.revision = 4;
    t2.timestamp = 200;
    CHECK(cvmfs_history_tag_add(h, &t2) == 0, "second tag add");

    cvmfs_history_tag_t got;
    CHECK(cvmfs_history_tag_get(h, "prod", &got) == 1
          && got.revision == 3 && got.root_hash.bytes[0] == 0x44
          && strcmp(got.description, "known good") == 0, "tag round-trips");
    CHECK(cvmfs_history_tag_get(h, "nope", &got) == 0, "absent tag reports 0");

    char first[128] = "";
    CHECK(cvmfs_history_list(h, list_tags_cb, first) == 2
          && strcmp(first, "testing") == 0, "list newest-first");

    /* replace-in-place (same tag name moves to a new root) */
    t.root_hash = mkhash(0x66);
    t.revision = 5;
    CHECK(cvmfs_history_tag_add(h, &t) == 0
          && cvmfs_history_tag_get(h, "prod", &got) == 1 && got.revision == 5,
          "tag re-add replaces");

    CHECK(cvmfs_history_tag_del(h, "prod") == 0
          && cvmfs_history_tag_get(h, "prod", &got) == 0, "tag delete");
    CHECK(cvmfs_history_tag_del(h, "prod") == 0, "delete of absent tag is a no-op");
    CHECK(cvmfs_history_close(h) == 0, "history closes");

    /* persistence */
    h = cvmfs_history_open(path, NULL);
    CHECK(h != NULL && cvmfs_history_tag_get(h, "testing", &got) == 1,
          "tags persist across reopen");
    if (h != NULL) cvmfs_history_close(h);

    CHECK(cvmfs_history_open("/nonexistent/dir/history", NULL) == NULL,
          "open on unwritable path fails");
}

int main(void) {
    char reflog[128], history[128];
    snprintf(reflog, sizeof(reflog), "/tmp/cvmfs_reflog_ut.%d.db", getpid());
    snprintf(history, sizeof(history), "/tmp/cvmfs_history_ut.%d.db", getpid());
    unlink(reflog);
    unlink(history);

    test_reflog(reflog);
    test_history(history);

    unlink(reflog);
    unlink(history);
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
