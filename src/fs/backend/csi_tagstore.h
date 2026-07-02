#ifndef XROOTD_FS_BACKEND_CSI_TAGSTORE_H
#define XROOTD_FS_BACKEND_CSI_TAGSTORE_H

#include <stdint.h>
#include <sys/types.h>

/*
 * fs/backend/csi_tagstore.h — persistent per-page CRC32C tagstore (phase-59 W2).
 *
 * Adds XRootD-OssCsi-style filesystem checksum integrity: one CRC32C per
 * XROOTD_CSI_PAGE (4096-byte) data page, stored in a sidecar ".xrdt" file under
 * a prefix directory (or inline). All tag-file byte I/O lives in this backend
 * module (INVARIANT 11: zero data-POSIX outside src/fs/backend/).
 *
 * On-disk format (v1, host byte order; see docs/refactor/phase-59 §FMT):
 *   [0]  u32 magic      0x58435349 "XCSI"
 *   [4]  u16 version    1
 *   [6]  u16 page_log2  12  (4096)
 *   [8]  u64 tracked_len
 *   [16] u32 flags      bit0 = fill holes
 *   [20] u32 header_crc crc32c(bytes[0..20))
 *   [24] u32 crc[]      one per data page
 */

#define XROOTD_CSI_MAGIC    0x58435349u
#define XROOTD_CSI_HDR_LEN  24
#define XROOTD_CSI_PAGE     4096u
#define XROOTD_CSI_BATCH    1024            /* pages per read/write batch */

#define XROOTD_CSI_OK         0
#define XROOTD_CSI_MISMATCH  (-1)
#define XROOTD_CSI_NOTAGS    (-2)
#define XROOTD_CSI_ERR       (-3)

typedef struct {
    int      tfd;                /* tag-file fd (owned here)                 */
    unsigned strict:1;           /* verify-before-write on partial pages     */
    unsigned fill:1;             /* tag implied-zero hole pages              */
    unsigned require:1;          /* missing tags ⇒ error                     */
    unsigned loose:1;            /* accept retried interrupted writes        */
    unsigned trust_fs:1;         /* backing fs is self-checksumming: skip
                                    read-verify (writes still tag)           */
    uint64_t tracked_len;        /* cached header value                      */
} xrootd_csi_t;

/*
 * Open (or create) the tag file for a data object given the export rootfd and
 * the data object's root-relative path. prefix = directory for tag files
 * ("/.xrdt" default; "" = inline alongside data). create != 0 makes a fresh
 * header when absent. Returns XROOTD_CSI_OK / _NOTAGS / _ERR.
 */
int xrootd_csi_open(xrootd_csi_t *c, int rootfd, const char *rel_data_path,
    const char *prefix, int create);

/* Read n CRC32C tags starting at page0 into tags[]; returns count or _ERR. */
ssize_t xrootd_csi_read_tags(xrootd_csi_t *c, uint32_t *tags, off_t page0,
    size_t n);

/* Write n CRC32C tags starting at page0; returns count or _ERR. */
ssize_t xrootd_csi_write_tags(xrootd_csi_t *c, const uint32_t *tags,
    off_t page0, size_t n);

/* Truncate the tag array to cover new_len bytes and sync the header. */
int xrootd_csi_truncate(xrootd_csi_t *c, off_t new_len);

/* Flush the cached tracked_len into the on-disk header. */
int xrootd_csi_sync_header(xrootd_csi_t *c);

void xrootd_csi_close(xrootd_csi_t *c);

/* ---- verify / update (csi_verify.c) ------------------------------------- */

/* Verify [off,off+len) of `buf` against stored tags. OK / MISMATCH / NOTAGS. */
int xrootd_csi_verify_read(xrootd_csi_t *c, const unsigned char *buf,
    off_t off, size_t len);

/* Update tags for a fully page-aligned write. */
int xrootd_csi_update_aligned(xrootd_csi_t *c, const unsigned char *buf,
    off_t off, size_t len);

/* Store a client-supplied per-page CRC directly (kXR_pgwrite fast path). */
int xrootd_csi_store_pgcrc(xrootd_csi_t *c, off_t page, uint32_t crc);

#endif /* XROOTD_FS_BACKEND_CSI_TAGSTORE_H */
