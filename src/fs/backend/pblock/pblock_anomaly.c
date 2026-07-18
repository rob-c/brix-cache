/*
 * pblock_anomaly.c — F9 eventual-consistency anomaly emulation for pblock.
 *
 * WHAT: Implements pblock_anomaly.h: the `recent` event table, event
 *       recording at create/update boundaries, and the pure-read anomaly
 *       consultations (visibility lag, stale stat, list lag).
 *
 * HOW:  Wall-clock milliseconds via CLOCK_REALTIME (simulated lag is a
 *       human-scale test knob, not a monotonic-critical deadline). Rules are
 *       read from ctl at each metadata boundary and clamped to a sane cap so
 *       a fat-fingered ctl row cannot make an export unusable for hours.
 *       Rows are only written while a matching rule is armed and expire
 *       logically — the read side never mutates. ngx-free (libc + sqlite3);
 *       BRIX_HAVE_SQLITE-gated.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_store.h"
#include "pblock_ctl.h"
#include "pblock_anomaly.h"
#include "sd_pblock_catalog_internal.h"   /* cat_exec / cat_prepare */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3.h>

#define AN_MS_CAP 60000   /* ceiling on any simulated consistency window */

static int64_t
anomaly_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000L;
}

/* The armed window for `key` in ms, clamped to [0, AN_MS_CAP]. 0 = off. */
static int64_t
anomaly_rule(const pblock_state_t *st, const char *key)
{
    char    val[64];
    int64_t ms;

    if (pblock_ctl_get(st->cat, key, val, sizeof(val)) != 1) {
        return 0;
    }
    ms = strtoll(val, NULL, 10);
    if (ms < 0) {
        ms = 0;
    }
    if (ms > AN_MS_CAP) {
        ms = AN_MS_CAP;
    }
    return ms;
}

int
pblock_anomaly_init(pblock_state_t *st)
{
    return cat_exec(st->cat,
        "CREATE TABLE IF NOT EXISTS recent("
        "  path TEXT PRIMARY KEY,"
        "  created_ms INTEGER NOT NULL DEFAULT 0,"
        "  updated_ms INTEGER NOT NULL DEFAULT 0,"
        "  old_size INTEGER NOT NULL DEFAULT 0,"
        "  old_mtime INTEGER NOT NULL DEFAULT 0);");
}

void
pblock_anomaly_created(pblock_state_t *st, const char *path)
{
    sqlite3_stmt *q;

    if (anomaly_rule(st, "anomaly.visibility_ms") <= 0
        && anomaly_rule(st, "anomaly.list_lag_ms") <= 0)
    {
        return;
    }
    /* A re-create (after unlink) starts a fresh history: the update snapshot
     * of the previous incarnation must not leak into stale stats. */
    q = cat_prepare(st->cat,
        "INSERT INTO recent VALUES(?1, ?2, 0, 0, 0)"
        " ON CONFLICT(path) DO UPDATE SET created_ms = excluded.created_ms,"
        " updated_ms = 0, old_size = 0, old_mtime = 0;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, anomaly_now_ms());
    (void) sqlite3_step(q);
    sqlite3_finalize(q);
}

void
pblock_anomaly_updated(pblock_state_t *st, const char *path,
    int64_t old_size, int64_t old_mtime)
{
    sqlite3_stmt *q;

    if (anomaly_rule(st, "anomaly.stale_stat_ms") <= 0) {
        return;
    }
    q = cat_prepare(st->cat,
        "INSERT INTO recent VALUES(?1, 0, ?2, ?3, ?4)"
        " ON CONFLICT(path) DO UPDATE SET updated_ms = excluded.updated_ms,"
        " old_size = excluded.old_size, old_mtime = excluded.old_mtime;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, anomaly_now_ms());
    sqlite3_bind_int64(q, 3, old_size);
    sqlite3_bind_int64(q, 4, old_mtime);
    (void) sqlite3_step(q);
    sqlite3_finalize(q);
}

/* The recorded event row, or created_ms = updated_ms = 0 when absent. */
static void
anomaly_row(const pblock_state_t *st, const char *path, int64_t *created_ms,
    int64_t *updated_ms, int64_t *old_size, int64_t *old_mtime)
{
    sqlite3_stmt *q;

    *created_ms = *updated_ms = 0;
    q = cat_prepare(st->cat,
        "SELECT created_ms, updated_ms, old_size, old_mtime"
        " FROM recent WHERE path = ?1;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    if (sqlite3_step(q) == SQLITE_ROW) {
        *created_ms = sqlite3_column_int64(q, 0);
        *updated_ms = sqlite3_column_int64(q, 1);
        if (old_size != NULL) {
            *old_size = sqlite3_column_int64(q, 2);
        }
        if (old_mtime != NULL) {
            *old_mtime = sqlite3_column_int64(q, 3);
        }
    }
    sqlite3_finalize(q);
}

int
pblock_anomaly_hidden(pblock_state_t *st, const char *path)
{
    int64_t rule, created_ms, updated_ms;

    rule = anomaly_rule(st, "anomaly.visibility_ms");
    if (rule <= 0) {
        return 0;
    }
    anomaly_row(st, path, &created_ms, &updated_ms, NULL, NULL);
    return created_ms > 0 && anomaly_now_ms() - created_ms < rule;
}

int
pblock_anomaly_stale(pblock_state_t *st, const char *path,
    int64_t *size_io, int64_t *mtime_io)
{
    int64_t rule, created_ms, updated_ms, old_size, old_mtime;

    rule = anomaly_rule(st, "anomaly.stale_stat_ms");
    if (rule <= 0) {
        return 0;
    }
    anomaly_row(st, path, &created_ms, &updated_ms, &old_size, &old_mtime);
    if (updated_ms <= 0 || anomaly_now_ms() - updated_ms >= rule) {
        return 0;
    }
    *size_io  = old_size;
    *mtime_io = old_mtime;
    return 1;
}

int
pblock_anomaly_list_hidden(pblock_state_t *st, const char *dir,
    const char *name)
{
    char    full[1088];
    int64_t rule, created_ms, updated_ms;

    rule = anomaly_rule(st, "anomaly.list_lag_ms");
    if (rule <= 0) {
        return 0;
    }
    snprintf(full, sizeof(full), "%s/%s",
             strcmp(dir, "/") == 0 ? "" : dir, name);
    anomaly_row(st, full, &created_ms, &updated_ms, NULL, NULL);
    return created_ms > 0 && anomaly_now_ms() - created_ms < rule;
}

void
pblock_anomaly_rename(pblock_state_t *st, const char *src, const char *dst)
{
    sqlite3_stmt *q;

    q = cat_prepare(st->cat,
        "UPDATE OR REPLACE recent SET path = ?2 WHERE path = ?1;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, src, -1, SQLITE_STATIC);
    sqlite3_bind_text(q, 2, dst, -1, SQLITE_STATIC);
    (void) sqlite3_step(q);
    sqlite3_finalize(q);
}

void
pblock_anomaly_drop(pblock_state_t *st, const char *path)
{
    sqlite3_stmt *q;

    q = cat_prepare(st->cat, "DELETE FROM recent WHERE path = ?1;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    (void) sqlite3_step(q);
    sqlite3_finalize(q);
}

#endif /* BRIX_HAVE_SQLITE */
