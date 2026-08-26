/*
 * sd_pblock_unittest_dedup_slot.c — phase-88 W1 driver->dedup_publish slot
 * (the pblock leg of the G13 commit-time-dedup seam), split from
 * sd_pblock_unittest_dedup.c for the file-size cap. Three legs:
 *   SUCCESS      — an object whose overlapping-write history cleared its
 *                  commit-time hash is folded by the slot (on-demand CRC +
 *                  byte-verified candidate) onto its byte-identical sibling.
 *   ERROR        — a missing path is a clean ENOENT; a refs-off export is a
 *                  clean ENOTSUP (never a silent wrong success).
 *   SECURITY-NEG — a forged blobs.content_hash cannot make the slot alias
 *                  differing content (byte-verify rejects the candidate).
 * Shared harness + q_blob_id/q_refcount-style catalog introspection are local
 * (a second SQLite connection, as a pytest would).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"
#include "sd_pblock_catalog.h"
#include "sd_pblock_unittest_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* slot_blob_id — the blob_id backing `path` ("" when the row is missing). */
static void
slot_blob_id(const char *root, const char *path, char *out, size_t cap)
{
    pbut_query_text(root, "SELECT blob_id FROM objects WHERE path = ?1;",
                    path, out, cap);
}

/* slot_refcount — a blob's tracked refcount (-1 = no row: the implicit single
 * reference). */
static int
slot_refcount(const char *root, const char *blob_id)
{
    return pbut_query_int(root,
        "SELECT refcount FROM blobs WHERE blob_id = ?1;", blob_id);
}

/* slot_set_hash — overwrite a blob's content_hash (the forgery primitive). */
static void
slot_set_hash(const char *root, const char *blob_id, const char *hash)
{
    pbut_exec(root, "UPDATE blobs SET content_hash = ?2 WHERE blob_id = ?1;",
              blob_id, hash);
}

/* slot_get_hash — read a blob's recorded content_hash ("" when none). */
static void
slot_get_hash(const char *root, const char *blob_id, char *out, size_t cap)
{
    pbut_query_text(root,
        "SELECT content_hash FROM blobs WHERE blob_id = ?1;", blob_id, out, cap);
}

/* write_file_overlap — create `path` and write `data` with a deliberate
 * OVERLAP (whole body, then the first byte again): final content == data, but
 * the wverify accumulator degrades, so the close-time publish records the blob
 * with a CLEARED hash — exactly the "commit-time fold missed" state the slot
 * exists to repair. Returns 0 or -1. */
static int
write_file_overlap(brix_sd_instance_t *inst, const char *path,
    const char *data, size_t len)
{
    int              err = 0;
    brix_sd_obj_t *o;
    int              ok;

    o = D->open(inst, path,
                BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC, 0644,
                &err);
    if (o == NULL) {
        return -1;
    }
    ok = D->pwrite(o, data, len, 0) == (ssize_t) len
         && D->pwrite(o, data, 1, 0) == 1;          /* the overlap */
    return pb_close(o) == NGX_OK && ok ? 0 : -1;
}

void
test_dedup_slot(void)
{
    char                  root[] = "/tmp/pb_dslot.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};
    char                  ba[PBLOCK_BLOB_ID_CAP], bb[PBLOCK_BLOB_ID_CAP];
    char                  hash[80], buf[64];
    /* 10 bytes over a 4-byte stripe ⇒ 3 blocks: the on-demand CRC and the
     * byte-verify both walk real striped blocks. */
    const char           *DATA = "abcdefghij";

    CHECK(D->dedup_publish != NULL, "pblock advertises dedup_publish");
    CHECK(D->dedup_gc == NULL, "pblock needs no alias GC (refcount-driven)");

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    lab_write_sidecar(root, "dedup=1");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 4;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "slot init");

    /* SUCCESS: /s1 committed cleanly (hash recorded); /s2 written with an
     * overlap — same bytes, cleared hash, so commit-time dedup missed it and
     * the blobs stay distinct. The slot computes the hash on demand,
     * byte-verifies, and folds. */
    CHECK(write_file(&inst, "/s1", DATA, 10) == 0, "seed s1");
    CHECK(write_file_overlap(&inst, "/s2", DATA, 10) == 0, "seed s2 (overlap)");
    slot_blob_id(root, "/s1", ba, sizeof(ba));
    slot_blob_id(root, "/s2", bb, sizeof(bb));
    CHECK(ba[0] && bb[0] && strcmp(ba, bb) != 0,
          "cleared-hash commit left the blobs distinct");
    slot_get_hash(root, bb, hash, sizeof(hash));
    CHECK(hash[0] == '\0', "overlap history cleared s2's hash (got \"%s\")",
          hash);

    CHECK(D->dedup_publish(&inst, "/s2", "/.gcas/ab/cdef") == NGX_OK,
          "slot publish folds");
    slot_blob_id(root, "/s2", bb, sizeof(bb));
    CHECK(strcmp(ba, bb) == 0, "slot folded s2 onto s1's blob");
    CHECK(slot_refcount(root, ba) == 2, "folded blob refcount 2 (got %d)",
          slot_refcount(root, ba));
    CHECK(read_file(&inst, "/s1", buf, sizeof(buf)) == 10
          && memcmp(buf, DATA, 10) == 0, "s1 reads back");
    CHECK(read_file(&inst, "/s2", buf, sizeof(buf)) == 10
          && memcmp(buf, DATA, 10) == 0, "s2 reads back");

    /* Idempotence: publishing an already-shared object is a benign no-op. */
    CHECK(D->dedup_publish(&inst, "/s2", "/.gcas/ab/cdef") == NGX_OK,
          "re-publish is benign");
    CHECK(slot_refcount(root, ba) == 2, "refcount unchanged (got %d)",
          slot_refcount(root, ba));

    /* ERROR: a missing path is a clean ENOENT. */
    errno = 0;
    CHECK(D->dedup_publish(&inst, "/absent", "/.gcas/ab/cdef") == NGX_ERROR
          && errno == ENOENT, "missing path is ENOENT (errno %d)", errno);

    /* SECURITY-NEG (legacy tier): pin both same-size different-content blobs
     * onto ONE colliding "crc32:" hash — a non-sha256 candidate must be
     * byte-verified, so the slot refuses the alias. */
    CHECK(write_file(&inst, "/v1", "AAAAAAAA", 8) == 0, "seed v1");
    CHECK(write_file_overlap(&inst, "/v2", "BBBBBBBB", 8) == 0, "seed v2");
    slot_blob_id(root, "/v1", ba, sizeof(ba));
    slot_blob_id(root, "/v2", bb, sizeof(bb));
    slot_set_hash(root, ba, "crc32:00c0ffee");
    slot_set_hash(root, bb, "crc32:00c0ffee");
    CHECK(D->dedup_publish(&inst, "/v2", "/.gcas/ff/0000") == NGX_OK,
          "legacy publish completes");
    {
        char b2[PBLOCK_BLOB_ID_CAP];

        slot_blob_id(root, "/v2", b2, sizeof(b2));
        CHECK(strcmp(b2, ba) != 0,
              "colliding crc32 hash did NOT alias content");
    }
    CHECK(read_file(&inst, "/v2", buf, sizeof(buf)) == 8
          && memcmp(buf, "BBBBBBBB", 8) == 0, "v2 content honest");
    CHECK(read_file(&inst, "/v1", buf, sizeof(buf)) == 8
          && memcmp(buf, "AAAAAAAA", 8) == 0, "v1 content honest");

    /* W3 (sha tier): an in-order commit records a "sha256:" identity; two
     * identical commits share it; the OUT-OF-ORDER twin records the legacy
     * "crc32:" tier instead (no combine exists for SHA), so the tiers are
     * exactly the write-order split the design names. */
    CHECK(write_file(&inst, "/h1", DATA, 10) == 0, "seed h1");
    slot_blob_id(root, "/h1", ba, sizeof(ba));
    slot_get_hash(root, ba, hash, sizeof(hash));
    CHECK(strncmp(hash, "sha256:", 7) == 0 && strlen(hash) == 7 + 64,
          "in-order commit recorded a sha256 identity (got \"%s\")", hash);
    {
        /* Out-of-order but complete: tail then head — CRC combines, SHA
         * cannot, so the recorded hash falls back to the legacy tier. */
        int              err = 0;
        brix_sd_obj_t *o = D->open(&inst, "/h2",
                                     BRIX_SD_O_WRITE | BRIX_SD_O_CREATE
                                     | BRIX_SD_O_TRUNC, 0644, &err);

        CHECK(o != NULL, "open h2 (err %d)", err);
        if (o != NULL) {
            CHECK(D->pwrite(o, "FGHIJ", 5, 5) == 5, "h2 tail first");
            CHECK(D->pwrite(o, "ABCDE", 5, 0) == 5, "h2 head second");
            CHECK(pb_close(o) == NGX_OK, "close h2");
        }
        slot_blob_id(root, "/h2", bb, sizeof(bb));
        slot_get_hash(root, bb, hash, sizeof(hash));
        CHECK(strncmp(hash, "crc32:", 6) == 0,
              "out-of-order commit fell back to the crc tier (got \"%s\")",
              hash);
    }

    D->cleanup(&inst);

    /* ERROR (gate off): a refs-off export answers ENOTSUP, never a silent
     * wrong success — the config layer keys brix_cache_global_cas off this. */
    {
        char                  root2[] = "/tmp/pb_dslotoff.XXXXXX";
        brix_sd_instance_t    inst2 = {0};
        brix_sd_pblock_conf_t conf2 = {0};

        CHECK(mkdtemp(root2) != NULL, "mkdtemp off");
        conf2.root = root2;                 /* deliberately NO dedup opt */
        conf2.busy_timeout_ms = 2000;
        conf2.block_size = 4;
        inst2.driver = D;
        inst2.caps = D->caps;
        CHECK(D->init(&inst2, &conf2) == NGX_OK, "off init");
        CHECK(write_file(&inst2, "/x", DATA, 10) == 0, "seed x");
        errno = 0;
        CHECK(D->dedup_publish(&inst2, "/x", "/.gcas/ab/cdef") == NGX_ERROR
              && errno == ENOTSUP, "refs-off is ENOTSUP (errno %d)", errno);
        D->cleanup(&inst2);
    }
}
