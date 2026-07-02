/*
 * src/write/pgw_fob.c — kXR_pgwrite CSE uncorrected-page registry (see pgw_fob.h).
 *
 * A fixed-size set of pages that failed CRC32c and await a kXR_pgRetry
 * correction.  Keyed exactly like stock XrdXrootdPgwFob so partial last pages
 * are distinct from full pages at the same file offset.  Linear scan, no heap,
 * single-threaded per connection.
 */

#include "core/ngx_xrootd_module.h"
#include "pgw_fob.h"
#include "protocol/flags.h"   /* kXR_pgPageBL, kXR_pgPageSZ */
#include <string.h>

/* Encode (offset,dlen) the way stock does: shift the offset up by the page-bit
 * count and fold a short (unaligned) page's length into the low bits.  A full
 * page contributes 0 in the low bits. */
static int64_t
pgw_fob_key(int64_t off, uint32_t dlen)
{
    int64_t key = off << kXR_pgPageBL;

    if (dlen < (uint32_t) kXR_pgPageSZ) {
        key |= (int64_t) dlen;
    }
    return key;
}

void
xrootd_pgw_fob_open(xrootd_file_t *f)
{
    if (f->pgw_fob_enabled) {
        return;
    }
    f->pgw_fob_enabled = 1;
    f->pgw_fob_count   = 0;
    f->pgw_fob_errs    = 0;
    f->pgw_fob_fixes   = 0;
    memset(f->pgw_fob, 0, sizeof(f->pgw_fob));
}

int
xrootd_pgw_fob_add(xrootd_file_t *f, int64_t off, uint32_t dlen)
{
    int64_t  key = pgw_fob_key(off, dlen);
    uint32_t i;
    int      free_slot = -1;

    f->pgw_fob_errs++;

    /* Already registered → idempotent (a page re-failing keeps one entry). */
    for (i = 0; i < XROOTD_PGW_FOB_SLOTS; i++) {
        if (f->pgw_fob[i].used) {
            if (f->pgw_fob[i].key == key) {
                return 1;
            }
        } else if (free_slot < 0) {
            free_slot = (int) i;
        }
    }

    if (free_slot < 0) {
        return 0;   /* registry full → caller replies kXR_TooManyErrs */
    }

    f->pgw_fob[free_slot].key  = key;
    f->pgw_fob[free_slot].used = 1;
    f->pgw_fob_count++;
    return 1;
}

int
xrootd_pgw_fob_del(xrootd_file_t *f, int64_t off, uint32_t dlen)
{
    int64_t  key = pgw_fob_key(off, dlen);
    uint32_t i;

    for (i = 0; i < XROOTD_PGW_FOB_SLOTS; i++) {
        if (f->pgw_fob[i].used && f->pgw_fob[i].key == key) {
            f->pgw_fob[i].used = 0;
            f->pgw_fob[i].key  = 0;
            if (f->pgw_fob_count > 0) {
                f->pgw_fob_count--;
            }
            f->pgw_fob_fixes++;
            return 1;
        }
    }
    return 0;
}

int
xrootd_pgw_fob_has(const xrootd_file_t *f, int64_t off, uint32_t dlen)
{
    int64_t  key = pgw_fob_key(off, dlen);
    uint32_t i;

    for (i = 0; i < XROOTD_PGW_FOB_SLOTS; i++) {
        if (f->pgw_fob[i].used && f->pgw_fob[i].key == key) {
            return 1;
        }
    }
    return 0;
}

uint32_t
xrootd_pgw_fob_count(const xrootd_file_t *f)
{
    return f->pgw_fob_count;
}

void
xrootd_pgw_fob_reset(xrootd_file_t *f)
{
    f->pgw_fob_enabled = 0;
    f->pgw_fob_count   = 0;
    f->pgw_fob_errs    = 0;
    f->pgw_fob_fixes   = 0;
    memset(f->pgw_fob, 0, sizeof(f->pgw_fob));
}
