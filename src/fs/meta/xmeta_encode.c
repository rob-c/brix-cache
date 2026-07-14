/*
 * fs/meta/xmeta_encode.c — encode a per-file metadata record to its wire form.
 *
 * WHAT: brix_xmeta_encode() and its helpers: serialize a brix_xmeta_t into a
 *       malloc'd buffer — a byte-identical stock XrdPfc cinfo v4 prefix
 *       (version + Store POD + crc + bitmap + AStat[] + crc) followed by the
 *       "XCX1" extension header and the STATE / ORIGIN / DIGEST / BLOCKCRC TLV
 *       sections. WHY: split out of xmeta.c (942 lines) so the encode half and
 *       the decode half (xmeta_decode.c) each stay under the 500-line cap and
 *       can be reviewed as a matched pair. HOW: capacity is computed once by
 *       xmeta_encode_plan(), the buffer is malloc'd at exact size, then each
 *       region is appended by a cursor-tracked helper — every variable-length
 *       region is guarded by a crc32c, matching stock's Store/bitmap checksum
 *       convention.
 */

#include "xmeta.h"
#include "xmeta_internal.h"
#include "core/compat/crc32c.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Pin the persisted STATE layout at compile time so a drift from
 * xmeta_state_wire_t (shared with the decode side) cannot ship silently. */
typedef char xmeta_state_size_check[
    sizeof(xmeta_state_wire_t) == 80 ? 1 : -1];

/* ---- encode ---------------------------------------------------------------- */

/* append raw bytes into a cursor-tracked buffer (capacity computed upfront) */
static void
xmeta_put(uint8_t *buf, size_t *off, const void *src, size_t len)
{
    memcpy(buf + *off, src, len);
    *off += len;
}

/* one TLV section: {u16 type, u16 reserved, u32 len, payload, u32 crc32c},
 * crc computed over the 8-byte section header + payload */
static void
xmeta_put_section(uint8_t *buf, size_t *off, uint16_t type,
    const void *payload, uint32_t plen)
{
    size_t   hdr_off = *off;
    uint16_t reserved = 0;
    uint32_t crc;

    xmeta_put(buf, off, &type, 2);
    xmeta_put(buf, off, &reserved, 2);
    xmeta_put(buf, off, &plen, 4);
    xmeta_put(buf, off, payload, plen);
    crc = brix_crc32c_value(buf + hdr_off, 8 + (size_t) plen);
    xmeta_put(buf, off, &crc, 4);
}

/* encode layout plan: presence flags, payload lengths and total capacity,
 * computed once before any bytes are written */
typedef struct {
    size_t   blen;             /* stock bitmap length in bytes */
    unsigned have_origin;      /* ORIGIN section present */
    unsigned have_blockcrc;    /* BLOCKCRC section present */
    size_t   origin_plen;      /* ORIGIN payload length */
    size_t   blockcrc_plen;    /* BLOCKCRC payload length (0 = absent) */
    uint16_t nsec;             /* extension section count */
    size_t   cap;              /* total encoded record capacity */
} xmeta_encode_plan_t;

/* ---- Compute the encode layout for a record ----
 *
 * WHAT: Fills *plan with section presence flags, per-section payload lengths,
 *       the extension section count and the exact output buffer capacity for
 *       encoding m. Cannot fail.
 *
 * WHY: brix_xmeta_encode mallocs the output buffer once at exact capacity;
 *      keeping the capacity formula and the section presence decisions in one
 *      place guarantees the emit helpers below stay within the buffer.
 *
 * HOW: 1. Derive the bitmap byte length from nblocks.
 *      2. ORIGIN is present iff any of etag/cks-alg/cks is non-empty.
 *      3. BLOCKCRC is present iff tracked AND the table is allocated.
 *      4. Count present sections, then sum stock prefix + extension header
 *         + 12-byte TLV overhead per section + payload lengths into cap.
 */
static void
xmeta_encode_plan(const brix_xmeta_t *m, xmeta_encode_plan_t *plan)
{
    plan->blen = xmeta_bitmap_len(m->nblocks);
    plan->have_origin = (m->etag_len > 0 || m->cks_len > 0
                         || m->cks_alg_len > 0);
    plan->origin_plen = XMETA_ORIGIN_FIXED + m->etag_len
                        + m->cks_alg_len + m->cks_len;
    plan->have_blockcrc = (m->have_blockcrc && m->blockcrc != NULL);
    plan->blockcrc_plen = plan->have_blockcrc
                          ? 16 + (size_t) m->nblocks * 4 : 0;

    plan->nsec = (uint16_t) ((m->have_state ? 1 : 0)
                             + (m->digests != NULL ? 1 : 0)
                             + (plan->have_blockcrc ? 1 : 0)
                             + (plan->have_origin ? 1 : 0));

    plan->cap = 4 + sizeof(brix_xmeta_stock_store_t) + 4 /* version+store+crc */
                + plan->blen
                + (m->astat_count > 0 ? sizeof(m->astat) : 0) + 4
                + 8                                      /* ext magic+ver+cnt */
                + (m->have_state ? 12 + sizeof(xmeta_state_wire_t) : 0)
                + (m->digests != NULL ? 12 + (size_t) m->digests_len : 0)
                + (plan->blockcrc_plen ? 12 + plan->blockcrc_plen : 0)
                + (plan->have_origin ? 12 + plan->origin_plen : 0);
}

/* ---- Emit the stock XrdPfc cinfo v4 prefix ----
 *
 * WHAT: Writes version + Store POD + crc, then bitmap + optional AStat
 *       records + their shared crc, advancing *off. Cannot fail (capacity
 *       was reserved by xmeta_encode_plan).
 *
 * WHY: The prefix must be byte-identical to what XrdPfc::Info::Write emits
 *      so stock tools can read the front of the record; isolating it keeps
 *      that compatibility contract in one reviewable block.
 *
 * HOW: 1. Build the Store POD from the in-memory record (astat_size is
 *         clamped to 0/1 — we keep at most one AStat).
 *      2. Emit version, Store, crc32c(Store).
 *      3. Emit the bitmap, then extend its crc over the AStat record if
 *         present, and emit the combined crc.
 */
static void
xmeta_encode_stock_prefix(const brix_xmeta_t *m, uint8_t *buf, size_t *off,
    size_t blen)
{
    brix_xmeta_stock_store_t store;
    int32_t  version = BRIX_XMETA_STOCK_VERSION;
    uint32_t crc;

    /* stock prefix — exactly what XrdPfc::Info::Write emits */
    memset(&store, 0, sizeof(store));
    store.buffer_size   = m->buffer_size;
    store.file_size     = m->file_size;
    store.creation_time = m->creation_time;
    store.no_cksum_time = m->no_cksum_time;
    store.access_cnt    = m->access_cnt;
    store.status_raw    = m->status_raw;
    store.astat_size    = (m->astat_count > 0) ? 1 : 0;

    xmeta_put(buf, off, &version, 4);
    xmeta_put(buf, off, &store, sizeof(store));
    crc = brix_crc32c_value(&store, sizeof(store));
    xmeta_put(buf, off, &crc, 4);
    xmeta_put(buf, off, m->bitmap, blen);
    crc = brix_crc32c_value(m->bitmap, blen);
    if (store.astat_size > 0) {
        xmeta_put(buf, off, &m->astat, sizeof(m->astat));
        crc = brix_crc32c_extend(crc, &m->astat, sizeof(m->astat));
    }
    xmeta_put(buf, off, &crc, 4);
}

/* ---- Emit the STATE extension section ----
 *
 * WHAT: Packs the write-back/lifecycle fields into the fixed 80-byte
 *       xmeta_state_wire_t and emits it as a STATE TLV section at *off.
 *
 * WHY: STATE is a persisted wire layout (size pinned by the static assert
 *      above); building it in a dedicated helper pairs it with
 *      xmeta_decode_state so the field order can be audited side by side.
 *
 * HOW: 1. Zero the wire struct, copy each field explicitly.
 *      2. Emit via xmeta_put_section (TLV header + payload + crc32c).
 */
static void
xmeta_encode_state_section(const brix_xmeta_t *m, uint8_t *buf, size_t *off)
{
    xmeta_state_wire_t state;

    memset(&state, 0, sizeof(state));
    state.origin_mtime  = m->origin_mtime;
    state.dirty_lo      = m->dirty_lo;
    state.dirty_hi      = m->dirty_hi;
    state.flush_gen     = m->flush_gen;
    state.dirty_since   = m->dirty_since;
    state.last_flush    = m->last_flush;
    state.bytes_flushed = m->bytes_flushed;
    state.expires_at    = m->expires_at;
    state.filled_at     = m->filled_at;
    state.mode          = m->mode;
    state.state_flags   = m->state_flags;
    xmeta_put_section(buf, off, BRIX_XMETA_SEC_STATE,
                      &state, sizeof(state));
}

/* ---- Emit the ORIGIN extension section ----
 *
 * WHAT: Packs the origin validators (etag, checksum algorithm name, checksum
 *       hex) into the {u8 lens, strings...} ORIGIN payload and emits it as a
 *       TLV section at *off.
 *
 * WHY: ORIGIN is variable-length with three length-prefixed strings; the
 *      payload is staged in a stack buffer sized for the struct maxima so a
 *      single xmeta_put_section call covers header + payload + crc. Pairs
 *      with xmeta_decode_origin.
 *
 * HOW: 1. Write the 4-byte fixed header {etag_len, alg_len, cks_len, pad}.
 *      2. Append the three strings back to back.
 *      3. Emit via xmeta_put_section with the accumulated payload length.
 */
static void
xmeta_encode_origin_section(const brix_xmeta_t *m, uint8_t *buf, size_t *off)
{
    uint8_t hdr4[XMETA_ORIGIN_FIXED] = {
        m->etag_len, m->cks_alg_len, m->cks_len, 0
    };
    uint8_t payload[XMETA_ORIGIN_FIXED + sizeof(m->etag)
                    + sizeof(m->cks_alg) + sizeof(m->cks_hex)];
    size_t  poff = 0;

    memcpy(payload, hdr4, XMETA_ORIGIN_FIXED);  poff = XMETA_ORIGIN_FIXED;
    memcpy(payload + poff, m->etag, m->etag_len);       poff += m->etag_len;
    memcpy(payload + poff, m->cks_alg, m->cks_alg_len); poff += m->cks_alg_len;
    memcpy(payload + poff, m->cks_hex, m->cks_len);     poff += m->cks_len;
    xmeta_put_section(buf, off, BRIX_XMETA_SEC_ORIGIN,
                      payload, (uint32_t) poff);
}

/* ---- Emit the BLOCKCRC extension section ----
 *
 * WHAT: Emits the per-block crc32c table as a BLOCKCRC TLV section at *off.
 *       Only called when the plan marked the section present.
 *
 * WHY: The payload (16-byte header + nblocks*4 crc words) can be large, so
 *      it is built in place in the output buffer instead of staging a second
 *      nblocks*4 allocation like xmeta_put_section would require. Pairs with
 *      xmeta_decode_blockcrc.
 *
 * HOW: 1. Emit the TLV header (type, reserved, payload length) by hand.
 *      2. Emit payload: u32 granule, u32 reserved, u64 nblocks, u32 crc[].
 *      3. Compute crc32c over header+payload directly from the buffer and
 *         emit it (same coverage as xmeta_put_section).
 */
static void
xmeta_encode_blockcrc_section(const brix_xmeta_t *m, uint8_t *buf, size_t *off)
{
    /* payload: u32 granule, u32 reserved, u64 nblocks, u32 crc[] — built
     * in place to avoid a second nblocks*4 allocation */
    size_t   blockcrc_plen = 16 + (size_t) m->nblocks * 4;
    size_t   sec_hdr = *off;
    uint16_t type = BRIX_XMETA_SEC_BLOCKCRC, rsv = 0;
    uint32_t plen32 = (uint32_t) blockcrc_plen;
    uint32_t granule = (uint32_t) m->buffer_size;
    uint32_t zero = 0;
    uint64_t nb = m->nblocks;
    uint32_t crc;

    xmeta_put(buf, off, &type, 2);
    xmeta_put(buf, off, &rsv, 2);
    xmeta_put(buf, off, &plen32, 4);
    xmeta_put(buf, off, &granule, 4);
    xmeta_put(buf, off, &zero, 4);
    xmeta_put(buf, off, &nb, 8);
    xmeta_put(buf, off, m->blockcrc, (size_t) m->nblocks * 4);
    crc = brix_crc32c_value(buf + sec_hdr, 8 + blockcrc_plen);
    xmeta_put(buf, off, &crc, 4);
}

int
brix_xmeta_encode(const brix_xmeta_t *m, uint8_t **out, size_t *out_len)
{
    xmeta_encode_plan_t plan;
    uint32_t  ext_magic = BRIX_XMETA_EXT_MAGIC;
    uint16_t  ext_version = BRIX_XMETA_EXT_VERSION;
    size_t    off = 0;
    uint8_t  *buf;

    if (m == NULL || out == NULL || out_len == NULL || m->buffer_size <= 0
        || m->bitmap == NULL)
    {
        errno = EINVAL;
        return BRIX_XMETA_ERR;
    }

    xmeta_encode_plan(m, &plan);
    buf = malloc(plan.cap);
    if (buf == NULL) {
        errno = ENOMEM;
        return BRIX_XMETA_ERR;
    }

    xmeta_encode_stock_prefix(m, buf, &off, plan.blen);

    /* extension */
    xmeta_put(buf, &off, &ext_magic, 4);
    xmeta_put(buf, &off, &ext_version, 2);
    xmeta_put(buf, &off, &plan.nsec, 2);

    if (m->have_state) {
        xmeta_encode_state_section(m, buf, &off);
    }
    if (plan.have_origin) {
        xmeta_encode_origin_section(m, buf, &off);
    }
    if (m->digests != NULL) {
        xmeta_put_section(buf, &off, BRIX_XMETA_SEC_DIGEST,
                          m->digests, m->digests_len);
    }
    if (plan.blockcrc_plen > 0) {
        xmeta_encode_blockcrc_section(m, buf, &off);
    }

    *out = buf;
    *out_len = off;
    return BRIX_XMETA_OK;
}
