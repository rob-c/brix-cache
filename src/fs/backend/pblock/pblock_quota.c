/*
 * pblock_quota.c — F5 usage rollup + quota admission for the pblock driver.
 *
 * WHAT: Implements pblock_quota.h: trigger-maintained `usage` rollup (see the
 *       header for why triggers — transactional by construction) plus the
 *       admission checks the driver calls at catalog boundaries.
 *
 * HOW:  The three triggers mirror insert/delete/update of `objects` rows into
 *       per-scope UPSERTs. Directory rows count as inodes but contribute zero
 *       bytes. The rebuild at init recomputes the rollup from `objects` so
 *       enabling quota on a populated export starts honest. ngx-free
 *       (libc + sqlite3); gated by BRIX_HAVE_SQLITE.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_store.h"
#include "pblock_ctl.h"
#include "pblock_quota.h"
#include "sd_pblock_catalog_internal.h"   /* cat_prepare / cat_exec */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sqlite3.h>

/* One UPSERT per scope; `B` is the byte contribution expression. */
#define Q_UPS(scope_lit, id_expr, B) \
    "INSERT INTO usage VALUES(" scope_lit "," id_expr "," B ",1)" \
    " ON CONFLICT(scope,id) DO UPDATE SET" \
    " bytes=bytes+excluded.bytes, inodes=inodes+excluded.inodes;"
#define Q_DEC(scope_lit, id_expr, B) \
    "UPDATE usage SET bytes=bytes-(" B "), inodes=inodes-1" \
    " WHERE scope=" scope_lit " AND id=" id_expr ";"

#define NEW_B "CASE WHEN NEW.is_dir=0 THEN NEW.size ELSE 0 END"
#define OLD_B "CASE WHEN OLD.is_dir=0 THEN OLD.size ELSE 0 END"

int
pblock_quota_init(pblock_state_t *st)
{
    static const char *ddl[] = {
        "CREATE TABLE IF NOT EXISTS usage("
        "  scope TEXT NOT NULL, id INTEGER NOT NULL,"
        "  bytes INTEGER NOT NULL, inodes INTEGER NOT NULL,"
        "  PRIMARY KEY(scope, id));",

        "CREATE TRIGGER IF NOT EXISTS usage_ai AFTER INSERT ON objects BEGIN "
        Q_UPS("'total'", "0",       NEW_B)
        Q_UPS("'uid'",   "NEW.uid", NEW_B)
        Q_UPS("'gid'",   "NEW.gid", NEW_B)
        "END;",

        "CREATE TRIGGER IF NOT EXISTS usage_ad AFTER DELETE ON objects BEGIN "
        Q_DEC("'total'", "0",       OLD_B)
        Q_DEC("'uid'",   "OLD.uid", OLD_B)
        Q_DEC("'gid'",   "OLD.gid", OLD_B)
        "END;",

        "CREATE TRIGGER IF NOT EXISTS usage_au AFTER UPDATE OF size, uid, gid "
        "ON objects BEGIN "
        Q_DEC("'total'", "0",       OLD_B)
        Q_DEC("'uid'",   "OLD.uid", OLD_B)
        Q_DEC("'gid'",   "OLD.gid", OLD_B)
        Q_UPS("'total'", "0",       NEW_B)
        Q_UPS("'uid'",   "NEW.uid", NEW_B)
        Q_UPS("'gid'",   "NEW.gid", NEW_B)
        "END;",

        /* rebuild: honest rollup even when quota is enabled on a populated
         * export (or after a run without quota). */
        "DELETE FROM usage;",
        "INSERT INTO usage SELECT 'total', 0,"
        " COALESCE(SUM(CASE WHEN is_dir=0 THEN size ELSE 0 END),0), COUNT(*)"
        " FROM objects;",
        "INSERT INTO usage SELECT 'uid', uid,"
        " SUM(CASE WHEN is_dir=0 THEN size ELSE 0 END), COUNT(*)"
        " FROM objects GROUP BY uid;",
        "INSERT INTO usage SELECT 'gid', gid,"
        " SUM(CASE WHEN is_dir=0 THEN size ELSE 0 END), COUNT(*)"
        " FROM objects GROUP BY gid;",
    };
    size_t i;

    if (cat_exec(st->cat, "BEGIN;") != 0) {
        return -1;
    }
    for (i = 0; i < sizeof(ddl) / sizeof(ddl[0]); i++) {
        if (cat_exec(st->cat, ddl[i]) != 0) {
            (void) cat_exec(st->cat, "ROLLBACK;");
            return -1;
        }
    }
    return cat_exec(st->cat, "COMMIT;");
}

int
pblock_quota_usage(const pblock_state_t *st, const char *scope, int64_t id,
    int64_t *bytes, int64_t *inodes)
{
    sqlite3_stmt *q;

    *bytes  = 0;
    *inodes = 0;
    q = cat_prepare(st->cat,
        "SELECT bytes, inodes FROM usage WHERE scope = ?1 AND id = ?2;");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, scope, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, id);
    if (sqlite3_step(q) == SQLITE_ROW) {
        *bytes  = sqlite3_column_int64(q, 0);
        *inodes = sqlite3_column_int64(q, 1);
    }
    sqlite3_finalize(q);
    return 0;
}

/* Per-uid runtime limit from the ctl table (`quota.uid.<n>`), 0 = none set. */
static int64_t
quota_uid_limit(const pblock_state_t *st, uint32_t uid)
{
    char key[48], val[64];

    snprintf(key, sizeof(key), "quota.uid.%u", uid);
    if (pblock_ctl_get(st->cat, key, val, sizeof(val)) != 1) {
        return 0;                        /* absent row or error ⇒ no uid limit */
    }
    return pblock_parse_size(val, strlen(val));
}

int
pblock_quota_admit(const pblock_state_t *st, uint32_t uid,
    int64_t add_bytes, int64_t add_inodes)
{
    int64_t bytes, inodes, limit;

    if (!st->quota) {
        return 0;
    }
    if (pblock_quota_usage(st, "total", 0, &bytes, &inodes) != 0) {
        return 0;                        /* fail-open on a rollup read error */
    }
    if ((st->quota_bytes > 0 && add_bytes > 0
         && bytes + add_bytes > st->quota_bytes)
        || (st->quota_inodes > 0 && add_inodes > 0
            && inodes + add_inodes > st->quota_inodes))
    {
        errno = EDQUOT;
        return -1;
    }

    limit = quota_uid_limit(st, uid);
    if (limit > 0 && add_bytes > 0) {
        if (pblock_quota_usage(st, "uid", (int64_t) uid, &bytes, &inodes) != 0) {
            return 0;
        }
        if (bytes + add_bytes > limit) {
            errno = EDQUOT;
            return -1;
        }
    }
    return 0;
}

int64_t
pblock_quota_max_size(const pblock_state_t *st, uint32_t uid, int64_t cur_size)
{
    int64_t bytes, inodes, room = INT64_MAX, limit;

    if (!st->quota) {
        return INT64_MAX;
    }
    if (st->quota_bytes > 0
        && pblock_quota_usage(st, "total", 0, &bytes, &inodes) == 0)
    {
        room = st->quota_bytes - bytes;
    }
    limit = quota_uid_limit(st, uid);
    if (limit > 0
        && pblock_quota_usage(st, "uid", (int64_t) uid, &bytes, &inodes) == 0
        && limit - bytes < room)
    {
        room = limit - bytes;
    }
    if (room == INT64_MAX) {
        return INT64_MAX;                    /* no byte limit in play */
    }
    if (room < 0) {
        room = 0;
    }
    return cur_size + room;
}

int
pblock_quota_touch_admit(const pblock_state_t *st, const char *path,
    uint32_t uid, int64_t newsize)
{
    pblock_meta m;

    if (!st->quota) {
        return 0;
    }
    if (pblock_catalog_lookup(st->cat, path, &m) != 0) {
        return 0;                        /* fresh row: admitted at create time */
    }
    return pblock_quota_admit(st, uid, newsize - m.size, 0);
}

#endif /* BRIX_HAVE_SQLITE */
