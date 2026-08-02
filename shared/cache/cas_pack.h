/* cas_pack.h — packed (log-structured) backend for the CAS cache (pure C).
 *
 * WHAT: phase-87 G4/G5 `-o cache_format=packed`: objects append into large
 *       segment files (`pack/seg-<n>.dat`) indexed by an append-only journal
 *       (`pack/index.log`) replayed into an in-memory hash at open. G5
 *       tiering (opt-in) zstd-compresses records when smaller and promotes
 *       hot entries back to raw form on repeated reads.
 * WHY:  the flat store costs one file + one fsync per object — small-file
 *       heavy repos burn inodes and IOPS. Packing amortizes both: batched
 *       data fsyncs, no per-object inode, whole-segment eviction (no unlink
 *       storms). Safe because the fetch layer re-verifies every cache hit
 *       against its integrity sidecar: a torn/unsynced tail can only produce
 *       a MISS or a purge+refetch, never a wrong serving.
 * HOW:  consumed exclusively through the brix_cas_* dispatch (cas_store.h) —
 *       `brix_cas_open` returns an ANONYMOUS fd (platform shim) pre-filled
 *       with the object bytes, so read-to-EOF callers work unchanged. Crash
 *       recovery: journal replay stops at the first corrupt record (tail
 *       truncated); intact orphan records at the ACTIVE segment's tail —
 *       beyond the journal's high-water mark, so deleted records are never
 *       resurrected — are re-adopted. Eviction drops whole oldest segments
 *       (log-structured FIFO; G5 promotion rewrites hot entries into the
 *       active segment, so FIFO approximates LRU) and compacts the journal.
 *       Format is host-endian and cache-local (never interchanged). One
 *       mutex serializes all ops (FUSE loop + prefetch worker share the
 *       handle). libc + zlib(crc32) + zstd + pthread only.
 */
#ifndef BRIX_CAS_PACK_H
#define BRIX_CAS_PACK_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define BRIX_PACK_KMAX        128           /* longest key incl. suffixes */
#define BRIX_PACK_SEG_DEFAULT (64L * 1024 * 1024)
#define BRIX_PACK_PROMOTE_HITS 4            /* G5: zstd → raw after this many reads */

typedef struct {
    uint32_t koff;        /* offset into the key arena */
    uint64_t off;         /* record start offset inside its segment */
    uint64_t stored_len;  /* bytes on disk (compressed when fmt=1) */
    uint64_t raw_len;     /* plaintext length handed back to callers */
    uint32_t seg;
    uint32_t hits;        /* G5 read counter */
    uint16_t klen;
    uint8_t  fmt;         /* 0 = raw, 1 = zstd */
    uint8_t  state;       /* 0 empty · 1 live · 2 tombstone */
} brix_pack_ent_t;

typedef struct brix_cas_pack {
    pthread_mutex_t  mu;
    int              basefd;      /* *at base for pack/…; owned iff owns_base */
    int              owns_base;
    int              segfd;       /* active segment (read/append) */
    int              idxfd;       /* journal (append; replayed at open) */
    int              tiering;     /* G5 gate */
    uint32_t         seg_lo, seg_hi;
    uint64_t         seg_off;     /* active segment append offset */
    long             quota_bytes; /* 0 = unbounded */
    long             seg_max;
    long             live_bytes;  /* sum of live stored_len */
    long             unsynced;    /* data bytes since last segment fsync */
    char             spill[512];  /* anon-fd fallback dir ("" in dirfd mode) */
    brix_pack_ent_t *tab;
    uint32_t         tab_cap, tab_live, tab_used;   /* used counts tombstones */
    char            *keys;
    uint32_t         keys_len, keys_cap;
} brix_cas_pack_t;

/* Open (creating as needed) the packed store under `root` (absolute; dirfd<0)
 * or relative to `dirfd`. `seg_bytes<=0` → BRIX_PACK_SEG_DEFAULT. Replays the
 * journal, adopts the active segment's intact orphan tail, truncates any torn
 * remainder. Returns 0 (out set) or -1 (errno set). */
int brix_cas_pack_open(brix_cas_pack_t **out, const char *root, int dirfd,
                       long quota_bytes, long seg_bytes, int tiering);

/* Flush + close + free. NULL-safe. */
void brix_cas_pack_close(brix_cas_pack_t *p);

int  brix_cas_pack_has(brix_cas_pack_t *p, const char *key);

/* Anonymous fd holding the object's RAW bytes, offset 0 (caller closes), or
 * -1. Any structural mismatch (magic/key/crc) fails the lookup — callers
 * treat it as a miss/purge, corrupt bytes are never served. */
int  brix_cas_pack_get_fd(brix_cas_pack_t *p, const char *key);

int  brix_cas_pack_put(brix_cas_pack_t *p, const char *key,
                       const void *data, size_t len);
int  brix_cas_pack_del(brix_cas_pack_t *p, const char *key);
long brix_cas_pack_size(brix_cas_pack_t *p);

/* Drop whole oldest segments until live bytes <= target (rolls the active
 * segment first when it is the only one). Returns entries dropped, or -1. */
int  brix_cas_pack_reap(brix_cas_pack_t *p, long target_bytes);
int  brix_cas_pack_enforce_quota(brix_cas_pack_t *p);

/* Deep verify every live record (magic/key/crc); drops failures. Returns the
 * number dropped, or -1. */
int  brix_cas_pack_fsck(brix_cas_pack_t *p);

#endif /* BRIX_CAS_PACK_H */
