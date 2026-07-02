#ifndef XROOTD_CACHE_CINFO_H
#define XROOTD_CACHE_CINFO_H

/*
 * cinfo.h — block-present bitmap sidecar (the ".cinfo" record), Phase-58 §9.
 *
 * WHAT: A per-cached-file companion record, "<cachefile>.cinfo", carrying a
 *       fixed header (origin validity + cache access stats + optional origin
 *       digest) followed by a BLOCK-PRESENT BITMAP: one bit per fixed-size block
 *       (the slice granule), set when that block has been fetched from the
 *       origin and committed to the cache.  This is the durable, inspectable
 *       record of *which parts of a file are cached* — XrdPfc's cinfo state
 *       vector, in this module's own versioned format.
 *
 * WHY:  The slice cache stores each touched window as a separate file
 *       ("<cachefile>.__xrds_<k>_<idx>"); presence was therefore implicit (the
 *       file exists) and known only by scanning the directory.  The .cinfo
 *       gives a single authoritative record so that: partial fills survive a
 *       restart (no re-fetch of windows already on disk), eviction can score by
 *       age/usage, and operators/tests can read exactly what a node holds.  This
 *       header is *record-keeping*: it does not by itself change how reads are
 *       served (the per-slice files remain the served bytes).
 *
 * HOW:  The header is a fixed-layout POD written/read verbatim (native byte
 *       order on the x86-64 target, exactly like meta.c); the bitmap of
 *       ceil(size/block_size) bits is appended immediately after it.  A loader
 *       that finds the sidecar absent, short, or inconsistent returns
 *       NGX_DECLINED so the caller treats the file as un-recorded (safe: blocks
 *       simply look absent and would be refetched).  Block bits are recorded by
 *       xrootd_cache_cinfo_record_block(), which serialises the
 *       read-modify-write with flock(2) so concurrent slice-fill workers never
 *       lose each other's bits.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>

#include "meta.h"   /* XROOTD_CACHE_META_ETAG_MAX + xrootd_cache_meta_t */

#define XROOTD_CACHE_CINFO_MAGIC   0x58434931u   /* "XCI1", little-endian */
#define XROOTD_CACHE_CINFO_VERSION 3

/* cinfo.flags */
#define XROOTD_CINFO_F_COMPLETE 0x0001u   /* every block present */
#define XROOTD_CINFO_F_PARTIAL  0x0002u   /* some, not all, blocks present */
#define XROOTD_CINFO_F_VERIFIED 0x0004u   /* contents checked vs the origin digest */
#define XROOTD_CINFO_F_DIRTY    0x0008u   /* local writes pending write-back */
#define XROOTD_CINFO_F_EXPIRES  0x0010u   /* expires_at present+valid
                                             (phase-68 manifest TTL) */

/* Block granule used to key a DIRTY record's validity (size/mtime/block_size).
 * The dirty extent is file-level (dirty_lo/dirty_hi), so this granule is only the
 * validity key, not a per-block dirty bitmap. */
#define XROOTD_CACHE_DIRTY_BLOCK  (1024u * 1024u)

/*
 * On-disk header.  Field order is largest-alignment-first with an explicit
 * `reserved` pad so the layout is stable across compilers; the record is zeroed
 * before population so the trailing struct padding is deterministic on disk.
 * The bitmap (xrootd_cache_cinfo_bitmap_len(nblocks) bytes) follows on disk
 * immediately after sizeof(xrootd_cache_cinfo_t) bytes of header.
 */
typedef struct {
    uint32_t magic;          /* XROOTD_CACHE_CINFO_MAGIC */
    uint16_t version;        /* XROOTD_CACHE_CINFO_VERSION */
    uint16_t flags;          /* XROOTD_CINFO_F_* */
    uint32_t block_size;     /* bytes per block (the slice granule); must be > 0 */
    uint32_t mode;           /* origin st_mode perm bits (0777); 0 = not recorded
                              * (pre-mode cinfos) — serve falls back to the store
                              * object's own bits. Was the 8-byte-align pad. */
    uint64_t size;           /* origin file size in bytes (validity) */
    uint64_t mtime;          /* origin mtime (validity) */
    uint64_t nblocks;        /* ceil(size/block_size) == bitmap bit count */
    uint64_t access_count;   /* cache hits served (stats parity with .meta) */
    uint64_t bytes_served;   /* cumulative bytes served from cache */
    uint64_t last_access;    /* unix secs of the most recent hit */
    /* ---- write-back state (v3) — file-level, alongside the present bitmap ---- */
    uint64_t dirty_lo;       /* dirty byte-extent start (incl); lo==hi ⇒ clean */
    uint64_t dirty_hi;       /* dirty byte-extent end (excl) */
    uint64_t dirty_since;    /* unix secs the file first went dirty this episode */
    uint64_t flush_gen;      /* bumped on each successful write-back */
    uint64_t last_flush;     /* unix secs of the last successful write-back */
    uint64_t bytes_flushed;  /* cumulative mirrored bytes */
    uint8_t  etag_len;
    char     etag[XROOTD_CACHE_META_ETAG_MAX];      /* origin etag, not NUL-term */
    uint8_t  cks_alg_len;
    char     cks_alg[16];                           /* origin checksum algo name */
    uint8_t  cks_len;
    char     cks_hex[129];                          /* origin checksum, hex */
    /* ---- phase-68 trailer (appended LAST; version stays 3: readers accept
     * files written without it — see cinfo.c's tolerant layout probe) ---- */
    uint64_t expires_at;     /* unix secs; entry stale when now >= expires_at
                                and F_EXPIRES is set. 0 + no flag = no TTL. */
    uint64_t filled_at;      /* unix secs the fill published this entry; keys
                                the bounded stale-if-error window (10x TTL). */
} xrootd_cache_cinfo_t;

#define XROOTD_CACHE_CINFO_HDR_SIZE (sizeof(xrootd_cache_cinfo_t))
/* Pre-phase-68 v3 header (no expires_at/filled_at trailer): 16 bytes shorter. */
#define XROOTD_CACHE_CINFO_HDR_SIZE_PRE68 (sizeof(xrootd_cache_cinfo_t) - 16)

/* ---- pure helpers (no I/O; safe on any thread) ------------------------- */

/* Number of blocks a `size`-byte file occupies at `block_size`. 0 if either is 0. */
uint64_t xrootd_cache_cinfo_nblocks(uint64_t size, uint32_t block_size);

/* Bytes needed to hold `nblocks` bits: ceil(nblocks/8). */
size_t xrootd_cache_cinfo_bitmap_len(uint64_t nblocks);

/* Set / test bit `blk` (LSB-first within each byte). Caller bounds blk<nblocks. */
void xrootd_cache_cinfo_mark_block(uint8_t *bitmap, uint64_t blk);
int  xrootd_cache_cinfo_block_present(const uint8_t *bitmap, uint64_t blk);

/* Count set bits in the first `nblocks` bits of `bitmap`. */
uint64_t xrootd_cache_cinfo_present_count(const uint8_t *bitmap, uint64_t nblocks);

/*
 * Recompute and store the COMPLETE/PARTIAL flags from the bitmap (VERIFIED is
 * left untouched). A 0-block file (size 0) is COMPLETE.
 */
void xrootd_cache_cinfo_refresh_flags(xrootd_cache_cinfo_t *hdr,
    const uint8_t *bitmap);

/* Stamp an expiry (sets F_EXPIRES) — phase-68 manifest TTL. */
void xrootd_cache_cinfo_set_expires(xrootd_cache_cinfo_t *ci, time_t when);

/* 0 = fresh, 1 = expired, -1 = no expiry recorded (immutable entry). */
int  xrootd_cache_cinfo_expired(const xrootd_cache_cinfo_t *ci, time_t now);

/* ---- sidecar path ------------------------------------------------------- */

/* Build "<cache_path>.cinfo" into dst[dstsz]. 0 on success, -1 if too long. */
int xrootd_cache_cinfo_path(char *dst, size_t dstsz, const char *cache_path);

/* ---- load / store ------------------------------------------------------- */

/*
 * Load the sidecar for cache_path. On NGX_OK *hdr is filled and *bitmap is a
 * freshly malloc()'d buffer of *bitmap_len bytes (caller free()s; *bitmap is
 * NULL with *bitmap_len 0 for a 0-block file). Returns NGX_DECLINED when the
 * sidecar is absent, short, or inconsistent (treat as "nothing recorded"), and
 * NGX_ERROR on a hard I/O failure.
 */
ngx_int_t xrootd_cache_cinfo_load(const char *cache_path,
    xrootd_cache_cinfo_t *hdr, uint8_t **bitmap, size_t *bitmap_len);

/*
 * Persist *hdr followed by `bitmap` (bitmap_len bytes) to the sidecar,
 * truncating to exactly header+bitmap and fdatasync'ing. *hdr is borrowed; its
 * magic/version are forced. Returns NGX_OK or NGX_ERROR (errno set).
 */
ngx_int_t xrootd_cache_cinfo_store(const char *cache_path,
    const xrootd_cache_cinfo_t *hdr, const uint8_t *bitmap, size_t bitmap_len);

/*
 * Build a COMPLETE header from a legacy .meta record (migration): copies
 * validity/stats/digest and marks every block present via the flags. The caller
 * supplies the block granule and, if it wants the bitmap materialised too, uses
 * xrootd_cache_cinfo_bitmap_len()+memset(0xff). Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t xrootd_cache_cinfo_from_meta(const xrootd_cache_meta_t *m,
    uint32_t block_size, xrootd_cache_cinfo_t *out);

/* ---- record-keeping entry point ---------------------------------------- */

/*
 * Mark block `blk` present for the file cached at cache_path. flock-serialised
 * read-modify-write: loads the existing sidecar (or starts fresh, or resets it
 * if the recorded origin size/mtime/block_size no longer match — a changed
 * origin file), sets the bit, refreshes COMPLETE/PARTIAL, and writes it back.
 * Best-effort and self-contained — the caller passes the origin validity it
 * already knows. Returns NGX_OK on a recorded bit, NGX_ERROR on I/O failure.
 */
ngx_int_t xrootd_cache_cinfo_record_block(const char *cache_path, uint64_t size,
    uint32_t block_size, uint64_t mtime, uint32_t mode, uint64_t blk,
    ngx_log_t *log);

/* ---- write-back (dirty) record-keeping (v3) ---------------------------- */

/*
 * Mark [off,off+len) dirty for the file cached at cache_path. Sets
 * XROOTD_CINFO_F_DIRTY and widens [dirty_lo,dirty_hi); dirty_since is stamped
 * ONLY on the clean→dirty transition (a widen of an already-dirty record leaves
 * it, so age reflects the oldest pending write). Resets validity if
 * size/mtime/block_size changed. flock-serialised RMW that preserves the present
 * bitmap. Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t xrootd_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size,
    uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len,
    ngx_log_t *log);

/*
 * Clear the dirty extent for cache_path: drop XROOTD_CINFO_F_DIRTY, zero the
 * extent + dirty_since, bump flush_gen, set last_flush=now, add bytes to
 * bytes_flushed. flock-serialised RMW preserving the present bitmap. Returns
 * NGX_OK, NGX_DECLINED when no record exists, NGX_ERROR on I/O failure.
 */
ngx_int_t xrootd_cache_cinfo_mark_clean(const char *cache_path, uint64_t bytes,
    ngx_log_t *log);

/*
 * Report the dirty extent + dirty_since for cache_path. NGX_OK with the out
 * params filled when the record is DIRTY, NGX_DECLINED when no record / clean,
 * NGX_ERROR on a hard I/O failure. Any out pointer may be NULL.
 */
ngx_int_t xrootd_cache_cinfo_dirty_extent(const char *cache_path, uint64_t *lo,
    uint64_t *hi, uint64_t *dirty_since);

/*
 * The write-back state the stale-dirty reaper needs to classify WHY a file is
 * reaped (see xrootd_cache_reap_reason_t):
 *   is_dirty   — XROOTD_CINFO_F_DIRTY set AND dirty_lo<dirty_hi (un-flushed data)
 *   flush_gen  — >0 iff the file was EVER written back (distinguishes a
 *                write-back staging copy from a read-through fill, which is 0)
 *   last_flush — unix secs of the last successful write-back (0 if never)
 * Reports the present record regardless of clean/dirty. NGX_OK with *out filled,
 * NGX_DECLINED when no record exists, NGX_ERROR on a hard I/O failure.
 */
typedef struct {
    int      is_dirty;
    uint64_t dirty_lo;
    uint64_t dirty_hi;
    uint64_t dirty_since;
    uint64_t flush_gen;
    uint64_t last_flush;
} xrootd_cache_cinfo_state_t;

ngx_int_t xrootd_cache_cinfo_state(const char *cache_path,
    xrootd_cache_cinfo_state_t *out);

#endif /* XROOTD_CACHE_CINFO_H */
