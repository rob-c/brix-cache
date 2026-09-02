/*
 * sd_pblock_unittest_pack.c — phase-88 W2 packed small-blob arena. Legs:
 *   SUCCESS      — a small staged commit comes to rest as ONE segment record
 *                  (no per-object block file), reads back byte-identical
 *                  through the driver (memfd serving), and unlinking every
 *                  packed blob reaps the segment file itself.
 *   ERROR        — a write-intent open materialises the blob back to the
 *                  striped layout (row gone, block file back, content
 *                  preserved, writable); an oversized commit never packs.
 *   SECURITY-NEG — a bit-flipped record fails the open with EIO — a packed
 *                  blob is served crc-verified or not at all.
 *   INTERPLAY    — pack=1&dedup=1: the second identical commit folds onto the
 *                  first PACKED blob (pack-aware byte-verify) and the packed
 *                  copy survives until its last reference goes.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"
#include "sd_pblock_catalog.h"
#include "sd_pblock_unittest_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* pk_staged_put — full staged write of `data` under `path` (the admission
 * road: only staged commits pack). Returns 0 or -1. */
static int
pk_staged_put(brix_sd_instance_t *inst, const char *path, const char *data,
    size_t len)
{
    brix_sd_staged_t *h;
    int                 err = 0;

    h = D->staged_open(inst, path, 0644, 0, &err);
    if (h == NULL) {
        return -1;
    }
    if (len > 0 && D->staged_write(h, data, len, 0) != (ssize_t) len) {
        D->staged_abort(h);
        return -1;
    }
    if (D->staged_commit(h, NULL) != NGX_OK) {
        D->staged_abort(h);
        return -1;
    }
    return 0;
}

/* pk_pack_row — the pack row for `path`'s blob: 1 found (the seg, off and len
 * outparams set), 0 absent, -1 no object row. */
static int
pk_pack_row(const char *root, const char *path, long long *seg,
    long long *off, long long *len)
{
    char          db[PATH_MAX];
    sqlite3      *h = NULL;
    sqlite3_stmt *q = NULL;
    char          blob[PBLOCK_BLOB_ID_CAP];
    int           found = -1;

    blob[0] = '\0';
    snprintf(db, sizeof(db), "%s/catalog.db", root);
    CHECK(sqlite3_open(db, &h) == SQLITE_OK, "pack db open");
    if (sqlite3_prepare_v2(h,
            "SELECT blob_id FROM objects WHERE path = ?1;", -1, &q, NULL)
        == SQLITE_OK)
    {
        sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
        if (sqlite3_step(q) == SQLITE_ROW) {
            const unsigned char *b = sqlite3_column_text(q, 0);

            snprintf(blob, sizeof(blob), "%s", b ? (const char *) b : "");
        }
    }
    sqlite3_finalize(q);
    q = NULL;
    if (blob[0] != '\0') {
        found = 0;
        if (sqlite3_prepare_v2(h,
                "SELECT seg, off, len FROM pack WHERE blob_id = ?1;", -1, &q,
                NULL) == SQLITE_OK)
        {
            sqlite3_bind_text(q, 1, blob, -1, SQLITE_STATIC);
            if (sqlite3_step(q) == SQLITE_ROW) {
                found = 1;
                if (seg != NULL) { *seg = sqlite3_column_int64(q, 0); }
                if (off != NULL) { *off = sqlite3_column_int64(q, 1); }
                if (len != NULL) { *len = sqlite3_column_int64(q, 2); }
            }
        }
        sqlite3_finalize(q);
    }
    sqlite3_close(h);
    return found;
}

/* pk_data_files — regular files under <root>/data (block files remaining). */
static int
pk_data_files_walk(const char *dir)
{
    DIR           *d = opendir(dir);
    struct dirent *ent;
    int            files = 0;

    if (d == NULL) {
        return 0;
    }
    while ((ent = readdir(d)) != NULL) {
        char sub[PATH_MAX];
        struct stat stx;

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        if (snprintf(sub, sizeof(sub), "%s/%s", dir, ent->d_name)
            >= (int) sizeof(sub))
        {
            continue;
        }
        if (lstat(sub, &stx) != 0) {
            continue;
        }
        if (S_ISDIR(stx.st_mode)) {
            files += pk_data_files_walk(sub);
        } else if (S_ISREG(stx.st_mode)) {
            files++;
        }
    }
    closedir(d);
    return files;
}

static int
pk_data_files(const char *root)
{
    char dirp[PATH_MAX];

    snprintf(dirp, sizeof(dirp), "%s/data", root);
    return pk_data_files_walk(dirp);
}

/* pk_read_back — open read-only + pread + close; bytes read or -1. */
static ssize_t
pk_read_back(brix_sd_instance_t *inst, const char *path, char *buf, size_t cap)
{
    int              err = 0;
    brix_sd_obj_t *o = D->open(inst, path, BRIX_SD_O_READ, 0, &err);
    ssize_t          n;

    if (o == NULL) {
        errno = err;
        return -1;
    }
    n = D->pread(o, buf, cap, 0);
    if (pb_close(o) != NGX_OK) {
        return -1;
    }
    return n;
}

void
test_pack_arena(void)
{
    char                  root[] = "/tmp/pb_pack.XXXXXX";
    brix_sd_instance_t    inst = {0};
    brix_sd_pblock_conf_t conf = {0};
    char                  buf[256], segp[PATH_MAX];
    long long             seg = 0, off = 0, len = 0;
    const char           *DATA = "packed-arena-payload-0123456789";
    const size_t          DLEN = strlen("packed-arena-payload-0123456789");

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    lab_write_sidecar(root, "pack=1&pack_max=1k");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 4096;
    inst.driver = D;
    inst.caps = D->caps;
    CHECK(D->init(&inst, &conf) == NGX_OK, "pack init");

    /* SUCCESS: two small staged commits pack — no block files remain, both
     * records land in segment 1, both read back byte-identical (memfd). */
    CHECK(pk_staged_put(&inst, "/p1", DATA, DLEN) == 0, "staged put p1");
    CHECK(pk_staged_put(&inst, "/p2", "second-object", 13) == 0,
          "staged put p2");
    CHECK(pk_pack_row(root, "/p1", &seg, &off, &len) == 1
          && len == (long long) DLEN, "p1 packed (seg %lld len %lld)",
          seg, len);
    CHECK(pk_pack_row(root, "/p2", NULL, NULL, NULL) == 1, "p2 packed");
    CHECK(pk_data_files(root) == 0,
          "no block files remain (got %d)", pk_data_files(root));
    snprintf(segp, sizeof(segp), "%s/pack/seg-%lld.dat", root, seg);
    CHECK(access(segp, F_OK) == 0, "segment file exists");
    CHECK(pk_read_back(&inst, "/p1", buf, sizeof(buf)) == (ssize_t) DLEN
          && memcmp(buf, DATA, DLEN) == 0, "p1 reads back from the arena");
    CHECK(pk_read_back(&inst, "/p2", buf, sizeof(buf)) == 13
          && memcmp(buf, "second-object", 13) == 0, "p2 reads back");

    /* ERROR (oversize): above pack_max stays striped. */
    {
        char big[2048];

        memset(big, 'B', sizeof(big));
        CHECK(pk_staged_put(&inst, "/big", big, sizeof(big)) == 0,
              "staged put big");
        CHECK(pk_pack_row(root, "/big", NULL, NULL, NULL) == 0,
              "oversize object stayed striped");
        CHECK(pk_data_files(root) == 1, "big's block file exists");
        CHECK(pk_read_back(&inst, "/big", buf, 8) == 8
              && memcmp(buf, "BBBBBBBB", 8) == 0, "big reads back");
    }

    /* ERROR (materialise): a write-intent open brings p1 back to the striped
     * layout — row gone, block file back, content preserved and writable. */
    {
        int              err = 0;
        brix_sd_obj_t *o = D->open(&inst, "/p1",
                                     BRIX_SD_O_READ | BRIX_SD_O_WRITE, 0,
                                     &err);

        CHECK(o != NULL, "write open of packed p1 (err %d)", err);
        if (o != NULL) {
            CHECK(pk_pack_row(root, "/p1", NULL, NULL, NULL) == 0,
                  "write open materialised p1 out of the arena");
            CHECK(D->pread(o, buf, sizeof(buf), 0) == (ssize_t) DLEN
                  && memcmp(buf, DATA, DLEN) == 0,
                  "materialised content preserved");
            CHECK(D->pwrite(o, "X", 1, 0) == 1, "materialised blob writable");
            CHECK(pb_close(o) == NGX_OK, "close materialised p1");
        }
        CHECK(pk_read_back(&inst, "/p1", buf, sizeof(buf)) == (ssize_t) DLEN
              && buf[0] == 'X', "overwrite persisted");
    }

    /* SUCCESS (reap): dropping every packed blob reaps the segment file. */
    CHECK(D->unlink(&inst, "/p2", 0) == NGX_OK, "unlink p2");
    CHECK(access(segp, F_OK) != 0,
          "segment reaped once its last record died");

    /* SECURITY-NEG: re-pack an object, flip one payload byte in the segment,
     * and the read-open must fail EIO — never serve unverified bytes. */
    CHECK(pk_staged_put(&inst, "/evil", DATA, DLEN) == 0, "staged put evil");
    CHECK(pk_pack_row(root, "/evil", &seg, &off, &len) == 1, "evil packed");
    snprintf(segp, sizeof(segp), "%s/pack/seg-%lld.dat", root, seg);
    {
        int fd = open(segp, O_RDWR);
        /* record: 28-byte header + 32-char blob-id key, then the payload */
        off_t flip = (off_t) off + 28 + 32 + 3;
        char  byte;

        CHECK(fd >= 0, "open segment for corruption");
        CHECK(pread(fd, &byte, 1, flip) == 1, "read corruption target");
        byte ^= 0x40;
        CHECK(pwrite(fd, &byte, 1, flip) == 1, "flip payload byte");
        close(fd);
    }
    {
        int              err = 0;
        brix_sd_obj_t *o = D->open(&inst, "/evil", BRIX_SD_O_READ, 0, &err);

        CHECK(o == NULL && err == EIO,
              "corrupt record refused with EIO (obj %p err %d)",
              (void *) o, err);
        if (o != NULL) {
            pb_close(o);
        }
    }
    D->cleanup(&inst);

    /* INTERPLAY: pack + dedup — the second identical commit byte-verifies
     * against the PACKED first copy and folds; the survivor stays packed and
     * outlives the first name. */
    {
        char                  root2[] = "/tmp/pb_packdd.XXXXXX";
        brix_sd_instance_t    inst2 = {0};
        brix_sd_pblock_conf_t conf2 = {0};

        CHECK(mkdtemp(root2) != NULL, "mkdtemp dd");
        lab_write_sidecar(root2, "pack=1&dedup=1");
        conf2.root = root2;
        conf2.busy_timeout_ms = 2000;
        conf2.block_size = 4096;
        inst2.driver = D;
        inst2.caps = D->caps;
        CHECK(D->init(&inst2, &conf2) == NGX_OK, "dd init");

        CHECK(pk_staged_put(&inst2, "/a", DATA, DLEN) == 0, "dd put a");
        CHECK(pk_staged_put(&inst2, "/b", DATA, DLEN) == 0, "dd put b");
        CHECK(pk_pack_row(root2, "/a", NULL, NULL, NULL) == 1, "a packed");
        CHECK(pk_pack_row(root2, "/b", NULL, NULL, NULL) == 1,
              "b folded onto the packed blob");
        CHECK(pk_data_files(root2) == 0, "dd left no block files");
        CHECK(D->unlink(&inst2, "/a", 0) == NGX_OK, "dd unlink a");
        CHECK(pk_read_back(&inst2, "/b", buf, sizeof(buf)) == (ssize_t) DLEN
              && memcmp(buf, DATA, DLEN) == 0,
              "survivor b still reads from the arena");
        D->cleanup(&inst2);
    }
}
