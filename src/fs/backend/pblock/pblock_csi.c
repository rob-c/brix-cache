/*
 * pblock_csi.c — F3 per-block CRC32c integrity for the pblock driver.
 *
 * WHAT: The read-verify / close-flush engine behind `csi=1`. One CRC-32c per
 *       pblock block (the block granule IS the CSI granule, so "fully covered
 *       block" maps exactly onto one block file), stored in the
 *       `csi(blob_id, block_no, crc)` catalog table keyed by the rename-stable
 *       blob id.
 *
 * WHY:  pblock owns its at-rest integrity in its own store rather than the
 *       posix xmeta tagstore (which carries tags at a real POSIX path that does
 *       not exist for a sharded-blob backend). See pblock_csi.h.
 *
 * HOW:  Verify is a pure function over the open-time snapshot (no DB, no locks
 *       on the hot path). Flush recomputes the written block extent from disk
 *       and UPSERTs in one transaction at close. Reuses the shared crc32c
 *       helper (INVARIANT 1/9 — never reimplement the checksum). 0 is the
 *       "unset" sentinel (a genuine CRC of 0 is skipped — a ~1/2^32 benign
 *       miss, the same convention the xmeta tagstore uses).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_store.h"
#include "pblock_csi.h"
#include "sd_pblock_catalog_internal.h"   /* cat_prepare / cat_exec + struct */
#include "core/compat/crc32c.h"           /* brix_crc32c_value (INVARIANT 1/9) */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include <sqlite3.h>

int
pblock_csi_init(pblock_catalog *cat)
{
    return cat_exec(cat,
        "CREATE TABLE IF NOT EXISTS csi("
        "  blob_id TEXT NOT NULL,"
        "  block_no INTEGER NOT NULL,"
        "  crc INTEGER NOT NULL,"
        "  PRIMARY KEY(blob_id, block_no));");
}

int
pblock_csi_load(pblock_catalog *cat, const char *blob_id, int64_t nblocks,
    uint32_t **out, uint64_t *out_n)
{
    sqlite3_stmt *st;
    uint32_t     *arr;
    uint64_t      cap = nblocks > 0 ? (uint64_t) nblocks : 1;

    *out   = NULL;
    *out_n = 0;
    arr = calloc(cap, sizeof(*arr));
    if (arr == NULL) {
        return -1;
    }
    st = cat_prepare(cat, "SELECT block_no, crc FROM csi WHERE blob_id = ?1;");
    if (st != NULL) {
        sqlite3_bind_text(st, 1, blob_id, -1, SQLITE_STATIC);
        while (sqlite3_step(st) == SQLITE_ROW) {
            int64_t bno = sqlite3_column_int64(st, 0);

            if (bno >= 0 && (uint64_t) bno < cap) {
                arr[bno] = (uint32_t) sqlite3_column_int64(st, 1);
            }
        }
        sqlite3_finalize(st);
    }
    *out   = arr;
    *out_n = cap;
    return 0;
}

int
pblock_csi_verify(const uint32_t *crc, uint64_t n, int64_t bs, int64_t size,
    const unsigned char *buf, off_t off, size_t len, int64_t dlo, int64_t dhi)
{
    int64_t b, first, last;
    off_t   end = off + (off_t) len;

    if (crc == NULL || n == 0 || bs <= 0 || len == 0) {
        return 0;
    }
    first = off / bs;
    last  = (end - 1) / bs;
    for (b = first; b <= last; b++) {
        int64_t  bstart = b * bs;
        int64_t  bend   = bstart + bs;
        uint32_t got;

        if (bend > size) {
            bend = size;                 /* short last block */
        }
        if (bend <= bstart) {
            continue;                    /* block at/after EOF */
        }
        if (bstart < off || (off_t) bend > end) {
            continue;                    /* not fully covered by this buffer */
        }
        if ((uint64_t) b >= n || crc[b] == 0) {
            continue;                    /* unrecorded / unset slot */
        }
        if (b >= dlo && b < dhi) {
            continue;                    /* written this handle: snapshot stale */
        }
        got = brix_crc32c_value(buf + (bstart - off), (size_t) (bend - bstart));
        if (got != crc[b]) {
            errno = EIO;
            return -1;
        }
    }
    return 0;
}

int
pblock_csi_flush(const pblock_state_t *st, const char *blob_id, int64_t size,
    int64_t bs, int64_t dlo, int64_t dhi)
{
    unsigned char *buf;
    int64_t        b, last;
    int            rc = 0;

    if (bs <= 0 || dlo >= dhi) {
        return 0;                        /* nothing written through this handle */
    }
    last = size > 0 ? pblock_last_block(size, bs) : -1;
    if (dhi > last + 1) {
        dhi = last + 1;                  /* clamp to EOF (a truncate may shrink) */
    }
    if (dlo < 0) {
        dlo = 0;
    }
    if (dlo >= dhi) {
        return 0;
    }
    buf = malloc((size_t) bs);
    if (buf == NULL) {
        return -1;
    }
    (void) cat_exec(st->cat, "BEGIN;");
    for (b = dlo; b < dhi; b++) {
        int64_t       bstart = b * bs;
        int64_t       blen   = bs;
        ssize_t       r;
        sqlite3_stmt *ins;

        if (bstart >= size) {
            continue;
        }
        if (bstart + blen > size) {
            blen = size - bstart;        /* short last block */
        }
        r = pblock_read_blocks(st, blob_id, bs, -1, buf, (size_t) blen, bstart);
        if (r != (ssize_t) blen) {
            rc = -1;
            continue;
        }
        ins = cat_prepare(st->cat,
            "INSERT OR REPLACE INTO csi(blob_id, block_no, crc) "
            "VALUES(?1, ?2, ?3);");
        if (ins != NULL) {
            sqlite3_bind_text(ins, 1, blob_id, -1, SQLITE_STATIC);
            sqlite3_bind_int64(ins, 2, b);
            sqlite3_bind_int64(ins, 3,
                (sqlite3_int64) brix_crc32c_value(buf, (size_t) blen));
            (void) sqlite3_step(ins);
            sqlite3_finalize(ins);
        } else {
            rc = -1;
        }
    }
    (void) cat_exec(st->cat, "COMMIT;");
    free(buf);
    return rc;
}

void
pblock_csi_drop(pblock_catalog *cat, const char *blob_id)
{
    sqlite3_stmt *st = cat_prepare(cat, "DELETE FROM csi WHERE blob_id = ?1;");

    if (st != NULL) {
        sqlite3_bind_text(st, 1, blob_id, -1, SQLITE_STATIC);
        (void) sqlite3_step(st);
        sqlite3_finalize(st);
    }
}

#endif /* BRIX_HAVE_SQLITE */
