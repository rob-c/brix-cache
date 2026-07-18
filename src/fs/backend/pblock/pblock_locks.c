/*
 * pblock_locks.c — F15 mandatory lease enforcement for pblock.
 *
 * WHAT: Implements pblock_locks.h: the `locks` table, the open-time and
 *       namespace gates, the per-handle range-lease snapshot and its pure
 *       hot-path overlap check, and lease-row maintenance.
 *
 * HOW:  Liveness = `expires_at > now` (unix seconds via pblock_now); expired
 *       rows are ignored, never deleted in the read path (the table is
 *       lease-scoped and tiny). Foreign = `owner != uid`. Unknown modes are
 *       treated as 'X' — the strictest reading of a row we don't understand.
 *       ngx-free (libc + sqlite3); BRIX_HAVE_SQLITE-gated.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_store.h"
#include "sd_pblock_internal.h"
#include "pblock_locks.h"
#include "sd_pblock_catalog_internal.h"   /* cat_exec / cat_prepare */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

int
pblock_locks_init(pblock_state_t *st)
{
    return cat_exec(st->cat,
        "CREATE TABLE IF NOT EXISTS locks("
        "  path TEXT NOT NULL,"
        "  off INTEGER NOT NULL DEFAULT 0,"
        "  len INTEGER NOT NULL DEFAULT 0,"
        "  mode TEXT NOT NULL DEFAULT 'W',"
        "  owner INTEGER NOT NULL DEFAULT 0,"
        "  expires_at INTEGER NOT NULL DEFAULT 0);");
}

/* Scan the live foreign leases on `path`. Reports whether any exists at all
 * (the namespace gate), whether any is exclusive, and whether any is a
 * whole-file write lease (len == 0). Range rows are counted but conflict
 * only at the pwrite boundary. Returns 0 on a clean scan, -1 on DB error. */
static int
locks_scan(const pblock_state_t *st, const char *path, uint32_t uid,
    int *any, int *excl, int *whole_w)
{
    sqlite3_stmt *q;

    *any = *excl = *whole_w = 0;
    q = cat_prepare(st->cat,
        "SELECT len, mode FROM locks"
        " WHERE path = ?1 AND owner != ?2 AND expires_at > ?3;");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, (int64_t) uid);
    sqlite3_bind_int64(q, 3, pblock_now());
    while (sqlite3_step(q) == SQLITE_ROW) {
        int64_t              len = sqlite3_column_int64(q, 0);
        const unsigned char *mode = sqlite3_column_text(q, 1);

        *any = 1;
        if (mode == NULL || mode[0] != 'W') {
            *excl = 1;
        } else if (len == 0) {
            *whole_w = 1;
        }
    }
    sqlite3_finalize(q);
    return 0;
}

int
pblock_locks_open_check(const pblock_state_t *st, const char *path,
    int want_write, uint32_t uid)
{
    int any, excl, whole_w;

    if (locks_scan(st, path, uid, &any, &excl, &whole_w) != 0) {
        return 0;                       /* fail-open: an unreadable simulation
                                         * table must not take the export down */
    }
    if (excl || (want_write && whole_w)) {
        errno = EBUSY;
        return -1;
    }
    return 0;
}

int
pblock_locks_ns_check(const pblock_state_t *st, const char *path,
    uint32_t uid)
{
    int any, excl, whole_w;

    if (locks_scan(st, path, uid, &any, &excl, &whole_w) != 0) {
        return 0;
    }
    if (any) {
        errno = EBUSY;
        return -1;
    }
    return 0;
}

void
pblock_locks_snapshot(const pblock_state_t *st, pblock_obj_t *os,
    uint32_t uid)
{
    sqlite3_stmt      *q;
    pblock_lock_rng_t *rng = NULL;
    uint32_t           n = 0, cap = 0;

    q = cat_prepare(st->cat,
        "SELECT off, len, expires_at FROM locks"
        " WHERE path = ?1 AND owner != ?2 AND expires_at > ?3 AND len > 0;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, os->path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, (int64_t) uid);
    sqlite3_bind_int64(q, 3, pblock_now());
    while (sqlite3_step(q) == SQLITE_ROW) {
        if (n == cap) {
            pblock_lock_rng_t *grown;

            cap = cap == 0 ? 4 : cap * 2;
            grown = realloc(rng, cap * sizeof(*rng));
            if (grown == NULL) {
                free(rng);
                sqlite3_finalize(q);
                return;
            }
            rng = grown;
        }
        rng[n].off        = sqlite3_column_int64(q, 0);
        rng[n].len        = sqlite3_column_int64(q, 1);
        rng[n].expires_at = sqlite3_column_int64(q, 2);
        n++;
    }
    sqlite3_finalize(q);
    if (n == 0) {
        free(rng);
        return;
    }
    os->lock_rng = rng;
    os->lock_n   = n;
}

int
pblock_locks_range_denied(const pblock_obj_t *os, off_t off, size_t len)
{
    const pblock_lock_rng_t *rng = os->lock_rng;
    int64_t                  now = pblock_now();
    uint32_t                 i;

    for (i = 0; i < os->lock_n; i++) {
        if (rng[i].expires_at <= now) {
            continue;
        }
        if ((int64_t) off < rng[i].off + rng[i].len
            && rng[i].off < (int64_t) off + (int64_t) len)
        {
            return 1;
        }
    }
    return 0;
}

void
pblock_locks_rename(const pblock_state_t *st, const char *src,
    const char *dst)
{
    sqlite3_stmt *q;

    q = cat_prepare(st->cat, "UPDATE locks SET path = ?2 WHERE path = ?1;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, src, -1, SQLITE_STATIC);
    sqlite3_bind_text(q, 2, dst, -1, SQLITE_STATIC);
    (void) sqlite3_step(q);
    sqlite3_finalize(q);
}

void
pblock_locks_drop(const pblock_state_t *st, const char *path)
{
    sqlite3_stmt *q;

    q = cat_prepare(st->cat, "DELETE FROM locks WHERE path = ?1;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    (void) sqlite3_step(q);
    sqlite3_finalize(q);
}

#endif /* BRIX_HAVE_SQLITE */
