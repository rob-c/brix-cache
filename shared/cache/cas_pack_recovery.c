/* cas_pack_recovery.c — packed-CAS journal and active-tail recovery.
 * This implementation unit is included by cas_pack.c so recovery can reuse
 * its private table and codec helpers without publishing internal APIs. */
#ifndef __CAS_PACK_C_COMPILED__
#include "cache/cas_pack.h"

#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define SEG_MAGIC 0x31535842u
#define IDX_MAGIC 0x31495842u
#define SEG_HDR 28u
#define IDX_HDR 40u
#define OP_PUT 1u
#define OP_DEL 2u
#endif

typedef struct {
    int         op;
    uint8_t     fmt;
    uint32_t    seg;
    uint64_t    off;
    uint64_t    stored;
    uint64_t    raw;
    uint64_t    end;
    size_t      klen;
    const char *key;
    size_t      next;
} replay_record_t;

/*
 * WHAT: Decode and authenticate one packed-CAS journal record.
 * WHY:  Recovery must stop exactly at the first incomplete or corrupt record.
 * HOW:  Bound the key, verify the record CRC, and reject length overflow.
 */
static int replay_record_decode(unsigned char *buf, size_t size, size_t pos,
                                replay_record_t *record) {
    unsigned char *raw;
    uint64_t       fixed;
    uint32_t       expected;
    uint32_t       actual;

    if (pos > size || size - pos < IDX_HDR)
        return 0;
    raw = buf + pos;
    record->klen = (size_t) raw[6] | ((size_t) raw[7] << 8);
    if (get32(raw) != IDX_MAGIC || record->klen == 0 ||
        record->klen > BRIX_PACK_KMAX || record->klen > size - pos - IDX_HDR)
        return 0;
    expected = get32(raw + 12);
    put32(raw + 12, 0);
    actual = crc_of(raw, IDX_HDR + record->klen);
    put32(raw + 12, expected);
    if (actual != expected)
        return 0;

    record->op = raw[4];
    record->fmt = raw[5];
    record->seg = get32(raw + 8);
    record->off = get64(raw + 16);
    record->stored = get64(raw + 24);
    record->raw = get64(raw + 32);
    record->key = (const char *) raw + IDX_HDR;
    record->next = pos + IDX_HDR + record->klen;
    fixed = SEG_HDR + record->klen;
    if (record->off > UINT64_MAX - fixed ||
        record->stored > UINT64_MAX - record->off - fixed)
        return 0;
    record->end = record->off + fixed + record->stored;
    return 1;
}

/*
 * WHAT: Apply a verified journal put to the in-memory packed-CAS index.
 * WHY:  Replayed replacements must adjust live-byte accounting atomically.
 * HOW:  Find or allocate the key slot, subtract the old value, and replace it.
 */
static int replay_put(brix_cas_pack_t *pack, const replay_record_t *record) {
    brix_pack_ent_t *entry;
    int              existed = 0;

    entry = tab_insert(pack, record->key, record->klen, &existed);
    if (entry == NULL)
        return -1;
    if (existed)
        pack->live_bytes -= (long) entry->stored_len;
    entry->seg = record->seg;
    entry->off = record->off;
    entry->fmt = record->fmt;
    entry->stored_len = record->stored;
    entry->raw_len = record->raw;
    pack->live_bytes += (long) record->stored;
    return 0;
}

/*
 * WHAT: Apply a verified journal delete to the in-memory index.
 * WHY:  Deleted objects must not be resurrected during orphan-tail adoption.
 * HOW:  Tombstone a live matching entry and update live-byte accounting.
 */
static void replay_delete(brix_cas_pack_t *pack,
                          const replay_record_t *record) {
    brix_pack_ent_t *entry = tab_find(pack, record->key, record->klen);

    if (entry == NULL)
        return;
    pack->live_bytes -= (long) entry->stored_len;
    entry->state = 2;
    pack->tab_live--;
}

/*
 * WHAT: Apply a journal record whose referenced segment range still exists.
 * WHY:  Torn compaction can leave authenticated records naming stale segments.
 * HOW:  Validate the segment bounds, advance the active HWM, then dispatch op.
 */
static int replay_apply(brix_cas_pack_t *pack, const uint64_t *segment_sizes,
                        const replay_record_t *record, uint64_t *high_water) {
    if (record->seg < pack->seg_lo || record->seg > pack->seg_hi ||
        record->end > segment_sizes[record->seg - pack->seg_lo])
        return 0;
    if (record->seg == pack->seg_hi && record->end > *high_water)
        *high_water = record->end;
    if (record->op == OP_PUT)
        return replay_put(pack, record);
    if (record->op == OP_DEL)
        replay_delete(pack, record);
    return 0;
}

/*
 * WHAT: Replay the durable journal and truncate its invalid suffix.
 * WHY:  Startup needs a trustworthy index and the active segment adoption HWM.
 * HOW:  Decode records in order, ignore stale references, and retain good bytes.
 */
static int replay(brix_cas_pack_t *pack, const uint64_t *segment_sizes,
                  uint64_t *high_water) {
    struct stat     status;
    unsigned char  *buffer;
    size_t          size;
    size_t          position = 0;
    size_t          good = 0;
    replay_record_t record;

    *high_water = 0;
    if (fstat(pack->idxfd, &status) != 0 || status.st_size < 0)
        return -1;
    size = (size_t) status.st_size;
    buffer = malloc(size ? size : 1);
    if (buffer == NULL)
        return -1;
    if (size > 0 && pread_full(pack->idxfd, buffer, size, 0) != 0) {
        free(buffer);
        return -1;
    }
    while (replay_record_decode(buffer, size, position, &record)) {
        good = record.next;
        position = record.next;
        if (replay_apply(pack, segment_sizes, &record, high_water) != 0) {
            free(buffer);
            return -1;
        }
    }
    free(buffer);
    if (good < size && ftruncate(pack->idxfd, (off_t) good) != 0)
        return -1;
    return lseek(pack->idxfd, (off_t) good, SEEK_SET) < 0 ? -1 : 0;
}

typedef struct {
    unsigned char header[SEG_HDR + BRIX_PACK_KMAX];
    size_t        klen;
    uint8_t       fmt;
    uint32_t      crc;
    uint64_t      stored;
    uint64_t      raw;
    uint64_t      end;
} tail_record_t;

/*
 * WHAT: Decode the structural metadata for one orphan active-segment record.
 * WHY:  Tail adoption must never allocate from unchecked on-disk lengths.
 * HOW:  Read the header, validate format and overflow, then load the key bytes.
 */
static int tail_record_decode(brix_cas_pack_t *pack, uint64_t position,
                              uint64_t file_size, tail_record_t *record) {
    uint64_t fixed;

    if (position > file_size || file_size - position < SEG_HDR ||
        pread_full(pack->segfd, record->header, SEG_HDR, position) != 0)
        return 0;
    record->klen = (size_t) record->header[4] |
                   ((size_t) record->header[5] << 8);
    record->fmt = record->header[6];
    record->crc = get32(record->header + 8);
    record->stored = get64(record->header + 12);
    record->raw = get64(record->header + 20);
    fixed = SEG_HDR + record->klen;
    if (get32(record->header) != SEG_MAGIC || record->klen == 0 ||
        record->klen > BRIX_PACK_KMAX || record->fmt > 1 ||
        fixed > file_size - position || record->stored > file_size - position - fixed)
        return 0;
    record->end = position + fixed + record->stored;
    return pread_full(pack->segfd, record->header + SEG_HDR, record->klen,
                      position + SEG_HDR) == 0;
}

/*
 * WHAT: Verify the stored payload checksum of an orphan tail record.
 * WHY:  A structurally intact but partially written body is not adoptable.
 * HOW:  Read the bounded payload, calculate CRC32, and release the scratch copy.
 */
static int tail_payload_valid(brix_cas_pack_t *pack, uint64_t position,
                              const tail_record_t *record) {
    unsigned char *data = malloc(record->stored ? (size_t) record->stored : 1);
    int            valid;

    if (data == NULL)
        return -1;
    valid = pread_full(pack->segfd, data, (size_t) record->stored,
                       position + SEG_HDR + record->klen) == 0 &&
            crc_of(data, (size_t) record->stored) == record->crc;
    free(data);
    return valid;
}

/*
 * WHAT: Add one authenticated orphan record to the live index and journal.
 * WHY:  A crash after data append must not discard a complete immutable object.
 * HOW:  Replace any matching slot, update accounting, and append its put record.
 */
static int tail_record_adopt(brix_cas_pack_t *pack, uint64_t position,
                             const tail_record_t *record) {
    brix_pack_ent_t *entry;
    int              existed = 0;

    entry = tab_insert(pack, (const char *) record->header + SEG_HDR,
                       record->klen, &existed);
    if (entry == NULL)
        return -1;
    if (existed)
        pack->live_bytes -= (long) entry->stored_len;
    entry->seg = pack->seg_hi;
    entry->off = position;
    entry->fmt = record->fmt;
    entry->stored_len = record->stored;
    entry->raw_len = record->raw;
    pack->live_bytes += (long) record->stored;
    return idx_append(pack, OP_PUT, entry, ent_key(pack, entry));
}

/*
 * WHAT: Adopt complete active-segment records not yet named by the journal.
 * WHY:  Data can reach disk immediately before a crash prevents journal append.
 * HOW:  Decode and verify each tail record, journal it, then trim the torn suffix.
 */
static int adopt_tail(brix_cas_pack_t *pack, uint64_t high_water) {
    struct stat   status;
    uint64_t      file_size;
    uint64_t      position = high_water;
    tail_record_t record;
    int           valid;

    if (fstat(pack->segfd, &status) != 0 || status.st_size < 0)
        return -1;
    file_size = (uint64_t) status.st_size;
    while (tail_record_decode(pack, position, file_size, &record)) {
        valid = tail_payload_valid(pack, position, &record);
        if (valid < 0)
            return -1;
        if (!valid)
            break;
        if (tail_record_adopt(pack, position, &record) != 0)
            return -1;
        position = record.end;
    }
    if (position < file_size && ftruncate(pack->segfd, (off_t) position) != 0)
        return -1;
    pack->seg_off = position;
    return lseek(pack->segfd, (off_t) position, SEEK_SET) < 0 ? -1 : 0;
}
