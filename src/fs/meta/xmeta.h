#ifndef XROOTD_FS_META_XMETA_H
#define XROOTD_FS_META_XMETA_H

#include <stddef.h>
#include <stdint.h>

/*
 * fs/meta/xmeta.h — unified per-file metadata record codec (xmeta P1).
 *
 * WHAT: One record per file replacing the .cinfo(XCI1)/.xrdt/.cks metadata
 *       zoo. The leading bytes are BYTE-IDENTICAL to a stock XrdPfc cinfo v4
 *       file (version + Store POD + crc + present bitmap + AStat[] + crc), so
 *       stock tools (xrdpfc_print) read the prefix as a normal cinfo. Our
 *       extra state rides in TLV sections appended AFTER the stock trailing
 *       crc — stock readers consume sequentially and never see them.
 *
 * WHY:  One form of metadata on disk per file (spec
 *       docs/superpowers/specs/2026-07-02-xmeta-unified-metadata-design.md):
 *       cache present-bitmap, dirty/write-back state, whole-file digests and
 *       block-granule CSI CRCs live together, carried in the user.xrd.cinfo
 *       xattr when they fit and as a stock-readable "<file>.cinfo" sidecar
 *       when they don't (see xmeta_carrier.h).
 *
 * HOW:  Pure C, ngx-free, malloc-based (standalone-testable like
 *       csi_unittest.c). Stock PODs are emitted verbatim (native x86-64
 *       layout, the same portability contract as stock XrdPfc); extension
 *       sections are {type, len, payload, crc32c} TLVs — unknown types are
 *       skipped on decode (forward compat), a bad section crc rejects the
 *       record (torn write).
 */

/* ---- stock XrdPfc cinfo v4 wire PODs (native layout, verbatim) ---------- */

#define XROOTD_XMETA_STOCK_VERSION  4

typedef struct {
    int64_t   buffer_size;       /* Store.m_buffer_size (block granule)      */
    int64_t   file_size;         /* Store.m_file_size                        */
    int64_t   creation_time;     /* Store.m_creationTime (time_t)            */
    int64_t   no_cksum_time;     /* Store.m_noCkSumTime (time_t; 0 = none)   */
    uint64_t  access_cnt;        /* Store.m_accessCnt (size_t)               */
    uint32_t  status_raw;        /* Store.m_status union raw                 */
    int32_t   astat_size;        /* Store.m_astatSize (AStat record count)   */
} xrootd_xmeta_stock_store_t;

typedef struct {
    int64_t   attach_time;       /* AStat.AttachTime (time_t)                */
    int64_t   detach_time;       /* AStat.DetachTime (time_t)                */
    int32_t   num_ios;
    int32_t   duration;
    int32_t   num_merged;
    int32_t   reserved;
    int64_t   bytes_hit;
    int64_t   bytes_missed;
    int64_t   bytes_bypassed;
} xrootd_xmeta_astat_t;

/* ---- extension wire constants ------------------------------------------- */

#define XROOTD_XMETA_EXT_MAGIC      0x31584358u  /* "XCX1" little-endian     */
#define XROOTD_XMETA_EXT_VERSION    1

#define XROOTD_XMETA_SEC_STATE      0x0001
#define XROOTD_XMETA_SEC_DIGEST     0x0002
#define XROOTD_XMETA_SEC_BLOCKCRC   0x0003
#define XROOTD_XMETA_SEC_ORIGIN     0x0004

/* STATE section flags */
#define XROOTD_XMETA_F_VERIFIED     0x0001u  /* contents checked vs digest */
#define XROOTD_XMETA_F_EXPIRES      0x0002u  /* expires_at is armed        */

/* BLOCKCRC crc slot value meaning "not computed / invalidated by a write"
 * (paired with stock Store.m_noCkSumTime, exactly stock's convention). */
#define XROOTD_XMETA_CRC_UNSET      0u

/* sanity caps for decode (a 64TiB file at 1MiB blocks = 2^26 blocks) */
#define XROOTD_XMETA_MAX_BLOCKS     (1ull << 26)
#define XROOTD_XMETA_MAX_SECTION    (XROOTD_XMETA_MAX_BLOCKS * 4 + 64)

/* digest algorithm ids (DIGEST section entries) */
#define XROOTD_XMETA_ALG_ADLER32    1
#define XROOTD_XMETA_ALG_CRC32C     2
#define XROOTD_XMETA_ALG_MD5        3
#define XROOTD_XMETA_ALG_SHA256     4
#define XROOTD_XMETA_ALG_CRC64XZ    5
#define XROOTD_XMETA_ALG_CRC64NVME  6
#define XROOTD_XMETA_ALG_CRC32      7
#define XROOTD_XMETA_ALG_SHA1       8
#define XROOTD_XMETA_ALG_ZCRC32     9

/* ---- in-memory record ---------------------------------------------------- */

typedef struct {
    /* stock prefix fields */
    int64_t   buffer_size;       /* block granule, bytes (> 0)               */
    int64_t   file_size;         /* bytes                                    */
    int64_t   creation_time;
    int64_t   no_cksum_time;
    uint64_t  access_cnt;
    uint32_t  status_raw;
    xrootd_xmeta_astat_t astat;  /* one folded access record                 */
    int32_t   astat_count;       /* 0 or 1 as written by us; decoded records
                                    with more keep the FIRST + true count    */
    uint64_t  nblocks;           /* ceil(file_size/buffer_size)              */
    uint8_t  *bitmap;            /* (nblocks+7)/8 bytes, owned; bit i =
                                    byte i/8 & (1 << i%8) — stock cfiBIT     */

    /* STATE section (write-back + validity fields with no stock slot) */
    unsigned  have_state:1;
    unsigned  have_blockcrc:1;
    uint64_t  origin_mtime;      /* origin validity                          */
    uint64_t  dirty_lo;          /* dirty byte extent [lo,hi); lo==hi=clean  */
    uint64_t  dirty_hi;
    uint64_t  flush_gen;         /* bumped per successful write-back         */
    uint64_t  dirty_since;
    uint64_t  last_flush;        /* unix secs of last successful write-back  */
    uint64_t  bytes_flushed;     /* cumulative mirrored bytes                */
    uint64_t  expires_at;        /* stale when now >= this and F_EXPIRES     */
    uint64_t  filled_at;         /* unix secs the fill published this entry  */
    uint32_t  mode;              /* origin st_mode perm bits; 0=unrecorded   */
    uint32_t  state_flags;       /* XROOTD_XMETA_F_*                         */

    /* ORIGIN section (validity strings; empty lengths when unrecorded) */
    uint8_t   etag_len;
    char      etag[128];         /* origin etag, not NUL-terminated          */
    uint8_t   cks_alg_len;
    char      cks_alg[16];       /* origin checksum algorithm name           */
    uint8_t   cks_len;
    char      cks_hex[129];      /* origin checksum, hex                     */

    /* DIGEST section: raw payload of {u16 alg, u16 len, u8[len]} entries */
    uint8_t  *digests;           /* owned; NULL when absent                  */
    uint32_t  digests_len;

    /* BLOCKCRC section: one crc32c per block, granule == buffer_size */
    uint32_t *blockcrc;          /* nblocks entries, owned; NULL if absent   */
} xrootd_xmeta_t;

/* return codes */
#define XROOTD_XMETA_OK        0
#define XROOTD_XMETA_ERR     (-1)   /* hard error (errno set)                */
#define XROOTD_XMETA_FOREIGN (-2)   /* not an xmeta/cinfo record (treat as
                                       "nothing recorded")                   */

/* Initialize *m for a file: zeroed bitmap + BLOCKCRC table sized from
 * file_size/buffer_size, creation_time = now, everything else zero.
 * buffer_size must be > 0. Returns OK / ERR (ENOMEM, EINVAL). */
int  xrootd_xmeta_init(xrootd_xmeta_t *m, int64_t file_size,
    int64_t buffer_size);

/* Free owned allocations and zero the struct (safe on a zeroed struct). */
void xrootd_xmeta_free(xrootd_xmeta_t *m);

/* Encode *m into a malloc'd buffer (*out, *out_len): stock v4 prefix +
 * extension sections (STATE always; DIGEST/BLOCKCRC when present).
 * Returns OK / ERR. Caller frees *out. */
int  xrootd_xmeta_encode(const xrootd_xmeta_t *m, uint8_t **out,
    size_t *out_len);

/* Decode buf[0..len) into *m (owned allocations; call xrootd_xmeta_free).
 * A stock cinfo v4 with no extension decodes fine (have_state == 0,
 * digests/blockcrc NULL). Returns OK / FOREIGN (wrong version, short,
 * bad magic) / ERR (crc mismatch = torn record, or ENOMEM). */
int  xrootd_xmeta_decode(const uint8_t *buf, size_t len, xrootd_xmeta_t *m);

/* present-bitmap ops (stock bit order) */
void xrootd_xmeta_block_set(xrootd_xmeta_t *m, uint64_t i);
int  xrootd_xmeta_block_test(const xrootd_xmeta_t *m, uint64_t i);
int  xrootd_xmeta_complete(const xrootd_xmeta_t *m);   /* all blocks set?   */

/* DIGEST list ops. add appends one entry; get returns entry idx (0-based)
 * into borrowed pointers, XROOTD_XMETA_OK or FOREIGN when idx is past the
 * end / the payload is malformed. */
int  xrootd_xmeta_digest_add(xrootd_xmeta_t *m, uint16_t alg,
    const void *val, uint16_t len);
/* set replaces any existing entries for `alg` with one new entry. */
int  xrootd_xmeta_digest_set(xrootd_xmeta_t *m, uint16_t alg,
    const void *val, uint16_t len);
int  xrootd_xmeta_digest_get(const xrootd_xmeta_t *m, uint32_t idx,
    uint16_t *alg, const uint8_t **val, uint16_t *len);

#endif /* XROOTD_FS_META_XMETA_H */
