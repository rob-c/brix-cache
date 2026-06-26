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
#define XROOTD_CACHE_CINFO_VERSION 2

/* cinfo.flags */
#define XROOTD_CINFO_F_COMPLETE 0x0001u   /* every block present */
#define XROOTD_CINFO_F_PARTIAL  0x0002u   /* some, not all, blocks present */
#define XROOTD_CINFO_F_VERIFIED 0x0004u   /* contents checked vs the origin digest */

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
    uint32_t reserved;       /* 0; keeps the uint64 block 8-byte aligned */
    uint64_t size;           /* origin file size in bytes (validity) */
    uint64_t mtime;          /* origin mtime (validity) */
    uint64_t nblocks;        /* ceil(size/block_size) == bitmap bit count */
    uint64_t access_count;   /* cache hits served (stats parity with .meta) */
    uint64_t bytes_served;   /* cumulative bytes served from cache */
    uint64_t last_access;    /* unix secs of the most recent hit */
    uint8_t  etag_len;
    char     etag[XROOTD_CACHE_META_ETAG_MAX];      /* origin etag, not NUL-term */
    uint8_t  cks_alg_len;
    char     cks_alg[16];                           /* origin checksum algo name */
    uint8_t  cks_len;
    char     cks_hex[129];                          /* origin checksum, hex */
} xrootd_cache_cinfo_t;

#define XROOTD_CACHE_CINFO_HDR_SIZE (sizeof(xrootd_cache_cinfo_t))

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
    uint32_t block_size, uint64_t mtime, uint64_t blk, ngx_log_t *log);

#endif /* XROOTD_CACHE_CINFO_H */
