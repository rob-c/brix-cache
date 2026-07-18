/*
 * pblock_nearline.c — F4 nearline/tape residency simulation for pblock.
 *
 * WHAT: Implements pblock_nearline.h: the `nearline(path, res)` table, the
 *       pure residency read, the bounded synchronous recall (ctl-driven
 *       latency/failure), and namespace row maintenance.
 *
 * HOW:  The table stores only demoted paths — absence means ONLINE, so a
 *       production-shaped export (nothing demoted) costs one indexed miss per
 *       gated open and the write path never touches it. All work happens at
 *       metadata boundaries. ngx-free (libc + sqlite3); BRIX_HAVE_SQLITE-gated.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_store.h"
#include "pblock_ctl.h"
#include "pblock_nearline.h"
#include "sd_pblock_catalog_internal.h"   /* cat_exec / cat_prepare */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3.h>

#define NL_RECALL_MS_CAP 30000   /* ceiling on the simulated recall latency */

int
pblock_nearline_init(pblock_state_t *st)
{
    return cat_exec(st->cat,
        "CREATE TABLE IF NOT EXISTS nearline("
        "  path TEXT PRIMARY KEY, res INTEGER NOT NULL);");
}

int
pblock_nearline_res(const pblock_state_t *st, const char *path,
    brix_sd_residency_t *out)
{
    sqlite3_stmt *q;

    *out = BRIX_SD_RES_ONLINE;
    q = cat_prepare(st->cat, "SELECT res FROM nearline WHERE path = ?1;");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    if (sqlite3_step(q) == SQLITE_ROW) {
        int64_t r = sqlite3_column_int64(q, 0);

        *out = (r >= BRIX_SD_RES_ONLINE && r <= BRIX_SD_RES_LOST)
               ? (brix_sd_residency_t) r : BRIX_SD_RES_LOST;
    }
    sqlite3_finalize(q);
    return 0;
}

/* Set (or clear, res == ONLINE — absence IS online) the residency row. */
static int
nearline_set(const pblock_state_t *st, const char *path,
    brix_sd_residency_t res)
{
    sqlite3_stmt *q;
    int           rc;

    if (res == BRIX_SD_RES_ONLINE) {
        q = cat_prepare(st->cat, "DELETE FROM nearline WHERE path = ?1;");
    } else {
        q = cat_prepare(st->cat,
            "INSERT INTO nearline VALUES(?1, ?2)"
            " ON CONFLICT(path) DO UPDATE SET res = excluded.res;");
    }
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    if (res != BRIX_SD_RES_ONLINE) {
        sqlite3_bind_int64(q, 2, (int64_t) res);
    }
    rc = sqlite3_step(q) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(q);
    return rc;
}

int
pblock_nearline_recall(const pblock_state_t *st, const char *path)
{
    brix_sd_residency_t res;
    char                val[64], failkey[1088];
    int64_t             ms = 0;

    if (pblock_nearline_res(st, path, &res) != 0) {
        return 0;                       /* fail-open: an unreadable simulation
                                         * table must not take the export down */
    }
    if (res == BRIX_SD_RES_ONLINE) {
        return 0;
    }
    if (res == BRIX_SD_RES_LOST) {
        errno = ENOENT;
        return -1;
    }

    /* NEARLINE/OFFLINE: simulate the tape robot — sleep the configured
     * latency, then land the outcome. */
    if (pblock_ctl_get(st->cat, "nearline.recall_ms", val, sizeof(val)) == 1) {
        ms = strtoll(val, NULL, 10);
        if (ms < 0) {
            ms = 0;
        }
        if (ms > NL_RECALL_MS_CAP) {
            ms = NL_RECALL_MS_CAP;
        }
    }
    if (ms > 0) {
        struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

        while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
            /* resume the remainder */
        }
    }

    snprintf(failkey, sizeof(failkey), "nearline.fail.%s", path);
    if (pblock_ctl_get(st->cat, failkey, val, sizeof(val)) == 1) {
        (void) nearline_set(st, path, BRIX_SD_RES_LOST);
        errno = EIO;
        return -1;
    }
    if (nearline_set(st, path, BRIX_SD_RES_ONLINE) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

void
pblock_nearline_rename(const pblock_state_t *st, const char *src,
    const char *dst)
{
    sqlite3_stmt *q;

    q = cat_prepare(st->cat,
        "UPDATE OR REPLACE nearline SET path = ?2 WHERE path = ?1;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, src, -1, SQLITE_STATIC);
    sqlite3_bind_text(q, 2, dst, -1, SQLITE_STATIC);
    (void) sqlite3_step(q);
    sqlite3_finalize(q);
}

void
pblock_nearline_drop(const pblock_state_t *st, const char *path)
{
    sqlite3_stmt *q;

    q = cat_prepare(st->cat, "DELETE FROM nearline WHERE path = ?1;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    (void) sqlite3_step(q);
    sqlite3_finalize(q);
}

#endif /* BRIX_HAVE_SQLITE */
