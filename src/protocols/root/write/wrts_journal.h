/*
 * src/write/wrts_journal.h — kXR_recoverWrts per-handle write-recovery journal.
 *
 * WHAT: A fixed-size ring buffer (BRIX_WRTS_JOURNAL_SLOTS entries) embedded
 *       in brix_file_t that records the offset+length of every pwrite() that
 *       has been committed to disk.  When a client reconnects and replays an
 *       in-flight write, brix_wrts_is_replay() detects the overlap and the
 *       write handler short-circuits the pwrite() — preventing double-writes
 *       that would corrupt the file.
 *
 * WHY:  Advertising kXR_recoverWrts in kXR_protocol tells XrdCl that it may
 *       replay in-flight writes after a TCP disconnect.  Without this journal
 *       the server cannot distinguish a fresh write from a recovery replay,
 *       so advertising the flag without the journal would silently double-write.
 *
 * HOW:  Four public functions:
 *   brix_wrts_open()      — initialise journal fields on kXR_open (writable)
 *   brix_wrts_record()    — append a committed write to the ring
 *   brix_wrts_is_replay() — return 1 if (offset,len) is already journalled
 *   brix_wrts_flush()     — clear the ring on kXR_sync / kXR_close
 *
 * The ring is O(BRIX_WRTS_JOURNAL_SLOTS) to scan; 64 slots covers normal
 * HEP streaming workloads without heap allocation.
 */

#ifndef BRIX_WRITE_WRTS_JOURNAL_H
#define BRIX_WRITE_WRTS_JOURNAL_H

#include "core/types/file.h"

/*
 * brix_wrts_open — initialise the write-recovery journal for a newly opened
 * writable file handle.  Call immediately after the fd is stored in the slot.
 */
void brix_wrts_open(brix_file_t *f);

/*
 * brix_wrts_record — record a committed write in the ring buffer.
 *
 * Call after a successful pwrite() (both sync and AIO paths).
 * offset  — file offset of the write
 * length  — byte count written (must be > 0)
 */
void brix_wrts_record(brix_file_t *f, int64_t offset, uint32_t length);

/*
 * brix_wrts_is_replay — return 1 if the incoming (offset, length) range is
 * fully covered by any existing journal entry.
 *
 * A "covered" entry satisfies:
 *   entry.offset <= offset  AND
 *   entry.offset + entry.length >= offset + length
 *
 * Returns 0 if the journal is empty, wrts_enabled is 0, or no entry covers
 * the incoming range.
 */
int brix_wrts_is_replay(const brix_file_t *f,
                           int64_t offset, uint32_t length);

/*
 * brix_wrts_flush — clear the journal.
 *
 * Called on kXR_sync (writes committed to stable storage — new generation
 * starts) and on kXR_close (handle going away).  After flush, any subsequent
 * write with the same offset is treated as a fresh write, not a replay.
 */
void brix_wrts_flush(brix_file_t *f);

#endif /* BRIX_WRITE_WRTS_JOURNAL_H */
