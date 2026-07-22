/*
 * sd_pblock_unittest_dedup.c — F10 refcounted-blob/dedup, F6 snapshot and F11
 * versioning slice of the pblock driver unit test (split from
 * sd_pblock_unittest.c). Catalog-introspection + publish helpers stay
 * file-local; the group entry points are driven by main(). Shared harness +
 * lab_write_sidecar() come via sd_pblock_unittest_internal.h.
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

void
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
void
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
void
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
void
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
void
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
