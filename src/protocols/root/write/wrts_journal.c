/*
 * src/write/wrts_journal.c — kXR_recoverWrts per-handle write-recovery journal.
 *
 * WHAT: Fixed-size ring buffer (BRIX_WRTS_JOURNAL_SLOTS entries per handle)
 *       recording committed (offset, length) write ranges.  A replayed write
 *       whose range is fully covered by a journal entry is short-circuited:
 *       the pwrite() is skipped and kXR_ok is returned to the client.
 *
 * WHY:  When kXR_recoverWrts is advertised, XrdCl replays in-flight writes
 *       after a TCP disconnect.  Without this guard the server writes the bytes
 *       twice — data corruption.  The journal makes the replay idempotent.
 *
 * HOW:  Ring is indexed by (wrts_head % BRIX_WRTS_JOURNAL_SLOTS).
 *       brix_wrts_is_replay() does a linear O(N) scan over at most
 *       BRIX_WRTS_JOURNAL_SLOTS (64) entries — acceptable for all practical
 *       HEP workloads where write burst sizes are bounded.
 *
 * Thread safety: all callers run on the nginx event-loop thread for a single
 * connection; no locking needed.
 */

#include "core/ngx_brix_module.h"
#include "wrts_journal.h"
#include <string.h>

/* brix_wrts_open */
void
brix_wrts_open(brix_file_t *f)
{
    f->wrts_enabled = 1;
    f->wrts_head    = 0;
    f->wrts_count   = 0;
    f->wrts_gen     = 0;
    memset(f->wrts_journal, 0, sizeof(f->wrts_journal));
}

/* brix_wrts_record */
void
brix_wrts_record(brix_file_t *f, int64_t offset, uint32_t length)
{
    brix_wrts_entry_t *e;
    uint32_t             slot;

    if (!f->wrts_enabled || length == 0) {
        return;
    }

    slot = f->wrts_head % BRIX_WRTS_JOURNAL_SLOTS;
    e    = &f->wrts_journal[slot];

    e->offset = offset;
    e->length = length;
    e->gen    = f->wrts_gen++;

    f->wrts_head++;
    if (f->wrts_count < BRIX_WRTS_JOURNAL_SLOTS) {
        f->wrts_count++;
    }
}

/* brix_wrts_is_replay */
int
brix_wrts_is_replay(const brix_file_t *f, int64_t offset, uint32_t length)
{
    uint32_t i;
    uint32_t limit;
    int64_t  req_end;

    if (!f->wrts_enabled || f->wrts_count == 0 || length == 0) {
        return 0;
    }

    req_end = offset + (int64_t) length;
    limit   = f->wrts_count < BRIX_WRTS_JOURNAL_SLOTS
              ? f->wrts_count
              : BRIX_WRTS_JOURNAL_SLOTS;

    for (i = 0; i < limit; i++) {
        const brix_wrts_entry_t *e = &f->wrts_journal[i];

        /* A replayed write has exactly the same offset and length.
         * Range-coverage would incorrectly skip legitimate overwrites of
         * a sub-range (e.g. writing 512 B after having written 4096 B at
         * the same offset with different content). */
        if (e->length > 0
            && e->offset == offset
            && e->length == (uint32_t) length)
        {
            return 1;
        }
    }

    (void) req_end;

    return 0;
}

/* brix_wrts_flush */
void
brix_wrts_flush(brix_file_t *f)
{
    if (!f->wrts_enabled) {
        return;
    }

    f->wrts_head  = 0;
    f->wrts_count = 0;
    f->wrts_gen   = 0;
    memset(f->wrts_journal, 0, sizeof(f->wrts_journal));
}
