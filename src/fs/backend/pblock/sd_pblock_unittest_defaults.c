/*
 * sd_pblock_unittest_defaults.c — phase-88 W5: the standard-on features.
 *
 * A BARE export (no opts sidecar at all) now arms the always-safe integrity/
 * performance features: F3 per-block CRC32c (csi) and the W4 shared namespace
 * cache (nsidx). Everything else stays opt-in. Legs:
 *   SUCCESS/integrity — a bare export advertises CAP_FSCS, and a byte of
 *                       on-disk rot is EIO at read time, never served.
 *   SUCCESS/perf      — a bare export creates catalog.bxi, and a lookup is
 *                       served from the shared table (proven: a raw-SQL
 *                       mutation behind the API is not seen).
 *   ERROR/opt-out     — csi=0&nsidx=0 restores the legacy behaviour exactly:
 *                       no CAP_FSCS, rot is served silently, no catalog.bxi
 *                       (the defaults are overridable, not hard-wired).
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

/* def_blob_id — the blob_id backing `path` ("" when the row is missing). */
static void
def_blob_id(const char *root, const char *path, char *out, size_t cap)
{
    pbut_query_text(root, "SELECT blob_id FROM objects WHERE path = ?1;",
                    path, out, cap);
}

/* def_raw_set_size — mutate a row BEHIND the catalog API so shared-cache
 * serving becomes observable (the nsidx proof from the catalog unittest). */
static void
def_raw_set_size(const char *root, const char *path, long long size)
{
    char          db[PATH_MAX];
    sqlite3      *h = NULL;
    sqlite3_stmt *q = NULL;

    snprintf(db, sizeof(db), "%s/catalog.db", root);
    CHECK(sqlite3_open(db, &h) == SQLITE_OK, "def raw db open");
    if (sqlite3_prepare_v2(h,
            "UPDATE objects SET size = ?2 WHERE path = ?1;", -1, &q, NULL)
        == SQLITE_OK)
    {
        sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
        sqlite3_bind_int64(q, 2, size);
        CHECK(sqlite3_step(q) == SQLITE_DONE, "def raw update");
    }
    sqlite3_finalize(q);
    sqlite3_close(h);
}

/* def_flip_block0 — flip one byte of a blob's block-0 file (on-disk rot). */
static void
def_flip_block0(const char *root, const char *blob, long off)
{
    char p[PATH_MAX];
    int  fd;
    char byte;

    snprintf(p, sizeof(p), "%s/data/%c%c/%c%c/%s/0", root,
             blob[0], blob[1], blob[2], blob[3], blob);
    fd = open(p, O_RDWR);
    CHECK(fd >= 0, "open block 0 for rot (%s)", p);
    CHECK(pread(fd, &byte, 1, off) == 1, "read rot target");
    byte = (char) (byte ^ 0x20);
    CHECK(pwrite(fd, &byte, 1, off) == 1, "write rot");
    close(fd);
}

void
test_standard_defaults(void)
{
    const char *DATA = "standard-defaults-payload-0123456789";
    const size_t DLEN = strlen("standard-defaults-payload-0123456789");
    char        buf[128], blob[PBLOCK_BLOB_ID_CAP], bxi[PATH_MAX];
    ssize_t     n;

    /* SUCCESS: a bare export (NO sidecar) arms csi + nsidx. */
    {
        char                  root[] = "/tmp/pb_defs.XXXXXX";
        brix_sd_instance_t    inst = {0};
        brix_sd_pblock_conf_t conf = {0};

        CHECK(mkdtemp(root) != NULL, "mkdtemp");
        conf.root = root;                    /* deliberately no pblock.opts */
        conf.busy_timeout_ms = 2000;
        conf.block_size = 4096;
        inst.driver = D;
        inst.caps = D->caps;
        CHECK(D->init(&inst, &conf) == NGX_OK, "bare init");

        CHECK((inst.caps & BRIX_SD_CAP_FSCS) != 0,
              "bare export advertises CAP_FSCS (csi standard)");
        snprintf(bxi, sizeof(bxi), "%s/catalog.bxi", root);
        CHECK(access(bxi, F_OK) == 0,
              "bare export created the shared namespace cache sidecar");

        /* Integrity: on-disk rot is EIO at read, never served. */
        CHECK(write_file(&inst, "/f", DATA, DLEN) == 0, "seed f");
        def_blob_id(root, "/f", blob, sizeof(blob));
        CHECK(blob[0] != '\0', "blob resolved");
        def_flip_block0(root, blob, 5);
        errno = 0;
        n = read_file(&inst, "/f", buf, sizeof(buf));
        CHECK(n < 0 && errno == EIO,
              "rot must be EIO, got n=%zd errno=%d", n, errno);

        /* Performance/coherence: a lookup is served from the shared table —
         * a mutation smuggled past the API is (correctly) not seen. */
        CHECK(write_file(&inst, "/g", DATA, DLEN) == 0, "seed g");
        {
            brix_sd_stat_t stx;

            CHECK(D->stat(&inst, "/g", &stx) == NGX_OK
                  && stx.size == (off_t) DLEN, "stat fills the cache");
            def_raw_set_size(root, "/g", 999);
            CHECK(D->stat(&inst, "/g", &stx) == NGX_OK
                  && stx.size == (off_t) DLEN,
                  "lookup served from the shared cache (size %lld)",
                  (long long) stx.size);
        }
        D->cleanup(&inst);
    }

    /* ERROR/opt-out: csi=0&nsidx=0 restores the legacy behaviour exactly. */
    {
        char                  root[] = "/tmp/pb_defsoff.XXXXXX";
        brix_sd_instance_t    inst = {0};
        brix_sd_pblock_conf_t conf = {0};

        CHECK(mkdtemp(root) != NULL, "mkdtemp off");
        lab_write_sidecar(root, "csi=0&nsidx=0");
        conf.root = root;
        conf.busy_timeout_ms = 2000;
        conf.block_size = 4096;
        inst.driver = D;
        inst.caps = D->caps;
        CHECK(D->init(&inst, &conf) == NGX_OK, "opt-out init");

        CHECK((inst.caps & BRIX_SD_CAP_FSCS) == 0,
              "csi=0 must not advertise CAP_FSCS");
        snprintf(bxi, sizeof(bxi), "%s/catalog.bxi", root);
        CHECK(access(bxi, F_OK) != 0,
              "nsidx=0 must not create the shared cache sidecar");

        CHECK(write_file(&inst, "/f", DATA, DLEN) == 0, "seed f (off)");
        def_blob_id(root, "/f", blob, sizeof(blob));
        def_flip_block0(root, blob, 5);
        n = read_file(&inst, "/f", buf, sizeof(buf));
        CHECK(n == (ssize_t) DLEN && memcmp(buf, DATA, DLEN) != 0,
              "opt-out serves the (rotten) bytes unverified — the legacy "
              "contract (n=%zd)", n);
        D->cleanup(&inst);
    }
}
