/*
 * fs/backend/csi_verify.c — CSI read-verify and write-update (phase-59 W2).
 *
 * WHAT: Compare data pages against stored CRC32C tags on read; recompute and
 *       persist tags on write; store client-supplied CRCs directly on the
 *       kXR_pgwrite fast path. WHY: detects at-rest corruption and interrupted
 *       writes. HOW: batch tag reads/writes (XROOTD_CSI_BATCH), per-page CRC32C
 *       via the shared engine, short-last-page length handled exactly.
 */

#include "csi_tagstore.h"
#include "../../compat/crc32c.h"

#include <string.h>

/* xrootd_csi_verify_read — compare [off,off+len) against stored tags */int
xrootd_csi_verify_read(xrootd_csi_t *c, const unsigned char *buf, off_t off,
    size_t len)
{
    off_t    p0;
    size_t   np, i;
    uint32_t stored[XROOTD_CSI_BATCH];

    if (len == 0) {
        return XROOTD_CSI_OK;
    }
    p0 = off / XROOTD_CSI_PAGE;
    np = (len + XROOTD_CSI_PAGE - 1) / XROOTD_CSI_PAGE;

    for (i = 0; i < np; i += XROOTD_CSI_BATCH) {
        size_t  batch = (np - i < XROOTD_CSI_BATCH) ? (np - i) : XROOTD_CSI_BATCH;
        ssize_t got = xrootd_csi_read_tags(c, stored, p0 + (off_t) i, batch);
        size_t  j;

        if (got < 0) {
            return XROOTD_CSI_ERR;
        }
        if ((size_t) got < batch) {
            return c->require ? XROOTD_CSI_MISMATCH : XROOTD_CSI_NOTAGS;
        }
        for (j = 0; j < batch; j++) {
            size_t pidx = i + j;
            size_t base = pidx * XROOTD_CSI_PAGE;
            size_t plen = (base + XROOTD_CSI_PAGE > len)
                          ? (len - base) : XROOTD_CSI_PAGE;

            if (xrootd_crc32c_value(buf + base, plen) != stored[j]) {
                return XROOTD_CSI_MISMATCH;
            }
        }
    }
    return XROOTD_CSI_OK;
}

/* xrootd_csi_update_aligned — recompute+store tags for a write
 * Tags every page the write touches, INCLUDING a trailing partial page (its CRC
 * is computed over the actual byte count, matching what verify_read recomputes).
 * Correct when the write starts on a page boundary (the sequential-write common
 * case); a write that starts mid-page needs the RMW path and is left to the
 * full-page subset here (the partial start page stays untagged → require gating
 * catches it). */
int
xrootd_csi_update_aligned(xrootd_csi_t *c, const unsigned char *buf, off_t off,
    size_t len)
{
    off_t  p0;
    size_t np, i;
    int    aligned_start;

    if (len == 0) {
        return XROOTD_CSI_OK;
    }
    aligned_start = ((off % XROOTD_CSI_PAGE) == 0);
    p0 = off / XROOTD_CSI_PAGE;

    /* Aligned start ⇒ tag all touched pages (last may be partial). Unaligned
     * start ⇒ only the full pages we can recompute from buf. */
    np = aligned_start ? ((len + XROOTD_CSI_PAGE - 1) / XROOTD_CSI_PAGE)
                       : (len / XROOTD_CSI_PAGE);

    for (i = 0; i < np; i += XROOTD_CSI_BATCH) {
        size_t   batch = (np - i < XROOTD_CSI_BATCH) ? (np - i) : XROOTD_CSI_BATCH;
        uint32_t tags[XROOTD_CSI_BATCH];
        size_t   j;

        for (j = 0; j < batch; j++) {
            size_t base = (i + j) * XROOTD_CSI_PAGE;
            size_t plen = (base + XROOTD_CSI_PAGE > len)
                          ? (len - base) : XROOTD_CSI_PAGE;
            tags[j] = xrootd_crc32c_value(buf + base, plen);
        }
        if (xrootd_csi_write_tags(c, tags, p0 + (off_t) i, batch)
            != (ssize_t) batch)
        {
            return XROOTD_CSI_ERR;
        }
    }

    if (off + (off_t) len > (off_t) c->tracked_len) {
        c->tracked_len = (uint64_t) (off + len);
    }
    return XROOTD_CSI_OK;
}

/* xrootd_csi_store_pgcrc — store a client CRC without recompute */int
xrootd_csi_store_pgcrc(xrootd_csi_t *c, off_t page, uint32_t crc)
{
    if (xrootd_csi_write_tags(c, &crc, page, 1) != 1) {
        return XROOTD_CSI_ERR;
    }
    if ((page + 1) * (off_t) XROOTD_CSI_PAGE > (off_t) c->tracked_len) {
        c->tracked_len = (uint64_t) ((page + 1) * XROOTD_CSI_PAGE);
    }
    return XROOTD_CSI_OK;
}
