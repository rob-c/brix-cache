/*
 * sd_pblock_unittest_lab.c — Phase-83 lab-feature slice (F0/F1/F2/F8/F14) of the
 * pblock driver unit test (split from sd_pblock_unittest.c). Owns the shared
 * lab_write_sidecar() sidecar writer; lab_ctl_set() + the enumerate oracles stay
 * file-local. Shared harness comes via sd_pblock_unittest_internal.h.
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

/* ---- Phase-83 lab features (F0/F1/F2/F8/F14) ------------------------------ *
 * Driven the way a real test drives them: the static opts sidecar selects the
 * fail-closed gate + caps mask, and ctl-table rows (written here through a second
 * SQLite connection, exactly as a pytest would via the sqlite3 CLI) carry the
 * runtime fault/shape rules. */

void
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
void
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
void
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
void
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

void
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
