/*
 * fs/meta/xmeta.c — unified per-file metadata record codec (xmeta P1).
 *
 * WHAT: Encode/decode the one-record-per-file metadata blob: a byte-identical
 *       stock XrdPfc cinfo v4 prefix followed by "XCX1" TLV extension
 *       sections (STATE / DIGEST / BLOCKCRC). WHY: one form of metadata on
 *       disk, readable by stock tools up front, extended at the end (spec
 *       2026-07-02-xmeta-unified-metadata-design.md). HOW: pure C, ngx-free,
 *       malloc-based; every variable-length region is guarded by a crc32c,
 *       matching stock's own Store/bitmap checksum convention.
 */

#include "xmeta.h"
#include "core/compat/crc32c.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The stock PODs are emitted verbatim; pin their layout at compile time so a
 * drift from XrdPfcInfo.hh (x86-64 native layout) cannot ship silently. */
typedef char xmeta_store_size_check[
    sizeof(brix_xmeta_stock_store_t) == 48 ? 1 : -1];
typedef char xmeta_astat_size_check[
    sizeof(brix_xmeta_astat_t) == 56 ? 1 : -1];

/* ---- small helpers ------------------------------------------------------- */

static uint64_t
xmeta_nblocks(int64_t file_size, int64_t buffer_size)
{
    if (file_size <= 0) {
        return 0;
    }
    return ((uint64_t) file_size + (uint64_t) buffer_size - 1)
           / (uint64_t) buffer_size;
}

static size_t
xmeta_bitmap_len(uint64_t nblocks)
{
    return (size_t) ((nblocks + 7) / 8);
}

/* append raw bytes into a cursor-tracked buffer (capacity computed upfront) */
static void
xmeta_put(uint8_t *buf, size_t *off, const void *src, size_t len)
{
    memcpy(buf + *off, src, len);
    *off += len;
}

/* bounded sequential read from the decode buffer; 0 = ok, -1 = short */
static int
xmeta_get(const uint8_t *buf, size_t len, size_t *off, void *dst, size_t n)
{
    if (len - *off < n) {
        return -1;
    }
    memcpy(dst, buf + *off, n);
    *off += n;
    return 0;
}

/* ---- lifecycle ------------------------------------------------------------ */

int
brix_xmeta_init(brix_xmeta_t *m, int64_t file_size, int64_t buffer_size)
{
    uint64_t nb;

    if (m == NULL || buffer_size <= 0 || file_size < 0) {
        errno = EINVAL;
        return BRIX_XMETA_ERR;
    }
    nb = xmeta_nblocks(file_size, buffer_size);
    if (nb > BRIX_XMETA_MAX_BLOCKS) {
        errno = EFBIG;
        return BRIX_XMETA_ERR;
    }

    memset(m, 0, sizeof(*m));
    m->buffer_size   = buffer_size;
    m->file_size     = file_size;
    m->creation_time = (int64_t) time(NULL);
    m->nblocks       = nb;
    m->have_state    = 1;

    m->bitmap = calloc(1, xmeta_bitmap_len(nb) ? xmeta_bitmap_len(nb) : 1);
    m->blockcrc = calloc(nb ? (size_t) nb : 1, sizeof(uint32_t));
    if (m->bitmap == NULL || m->blockcrc == NULL) {
        brix_xmeta_free(m);
        errno = ENOMEM;
        return BRIX_XMETA_ERR;
    }
    m->have_blockcrc = 1;
    return BRIX_XMETA_OK;
}

void
brix_xmeta_free(brix_xmeta_t *m)
{
    if (m == NULL) {
        return;
    }
    free(m->bitmap);
    free(m->digests);
    free(m->blockcrc);
    memset(m, 0, sizeof(*m));
}

/* ---- bitmap ops (stock cfiBIT order: bit i = byte i/8, 1 << i%8) --------- */

void
brix_xmeta_block_set(brix_xmeta_t *m, uint64_t i)
{
    if (m->bitmap != NULL && i < m->nblocks) {
        m->bitmap[i / 8] |= (uint8_t) (1u << (i % 8));
    }
}

int
brix_xmeta_block_test(const brix_xmeta_t *m, uint64_t i)
{
    if (m->bitmap == NULL || i >= m->nblocks) {
        return 0;
    }
    return (m->bitmap[i / 8] & (uint8_t) (1u << (i % 8))) != 0;
}

int
brix_xmeta_complete(const brix_xmeta_t *m)
{
    uint64_t i;

    for (i = 0; i < m->nblocks; i++) {
        if (!brix_xmeta_block_test(m, i)) {
            return 0;
        }
    }
    return 1;
}

/* ---- DIGEST list ---------------------------------------------------------- */

int
brix_xmeta_digest_add(brix_xmeta_t *m, uint16_t alg, const void *val,
    uint16_t len)
{
    size_t   need = 4 + (size_t) len;
    uint8_t *grown;

    if (m == NULL || (val == NULL && len != 0)) {
        errno = EINVAL;
        return BRIX_XMETA_ERR;
    }
    grown = realloc(m->digests, m->digests_len + need);
    if (grown == NULL) {
        errno = ENOMEM;
        return BRIX_XMETA_ERR;
    }
    m->digests = grown;
    memcpy(m->digests + m->digests_len, &alg, 2);
    memcpy(m->digests + m->digests_len + 2, &len, 2);
    if (len > 0) {
        memcpy(m->digests + m->digests_len + 4, val, len);
    }
    m->digests_len += (uint32_t) need;
    return BRIX_XMETA_OK;
}

int
brix_xmeta_digest_set(brix_xmeta_t *m, uint16_t alg, const void *val,
    uint16_t len)
{
    uint8_t *kept = NULL;
    uint32_t kept_len = 0;
    size_t   off = 0;

    if (m == NULL) {
        errno = EINVAL;
        return BRIX_XMETA_ERR;
    }
    if (m->digests != NULL) {
        kept = malloc(m->digests_len ? m->digests_len : 1);
        if (kept == NULL) {
            errno = ENOMEM;
            return BRIX_XMETA_ERR;
        }
        while (off + 4 <= m->digests_len) {
            uint16_t a, l;

            memcpy(&a, m->digests + off, 2);
            memcpy(&l, m->digests + off + 2, 2);
            if (off + 4 + l > m->digests_len) {
                break;                      /* malformed tail: drop it */
            }
            if (a != alg) {
                memcpy(kept + kept_len, m->digests + off, 4 + (size_t) l);
                kept_len += 4 + (uint32_t) l;
            }
            off += 4 + (size_t) l;
        }
        free(m->digests);
        m->digests = kept;
        m->digests_len = kept_len;
        if (kept_len == 0) {
            free(m->digests);
            m->digests = NULL;
            m->digests_len = 0;
        }
    }
    return brix_xmeta_digest_add(m, alg, val, len);
}

int
brix_xmeta_digest_get(const brix_xmeta_t *m, uint32_t idx, uint16_t *alg,
    const uint8_t **val, uint16_t *len)
{
    size_t   off = 0;
    uint32_t i = 0;

    if (m == NULL || m->digests == NULL) {
        return BRIX_XMETA_FOREIGN;
    }
    while (off + 4 <= m->digests_len) {
        uint16_t a, l;

        memcpy(&a, m->digests + off, 2);
        memcpy(&l, m->digests + off + 2, 2);
        if (off + 4 + l > m->digests_len) {
            return BRIX_XMETA_FOREIGN;            /* malformed payload */
        }
        if (i == idx) {
            *alg = a;
            *len = l;
            *val = m->digests + off + 4;
            return BRIX_XMETA_OK;
        }
        off += 4 + (size_t) l;
        i++;
    }
    return BRIX_XMETA_FOREIGN;                    /* past the end */
}

/* ---- STATE section wire layout (80 bytes) --------------------------------- */

typedef struct {
    uint64_t origin_mtime;
    uint64_t dirty_lo;
    uint64_t dirty_hi;
    uint64_t flush_gen;
    uint64_t dirty_since;
    uint64_t last_flush;
    uint64_t bytes_flushed;
    uint64_t expires_at;
    uint64_t filled_at;
    uint32_t mode;
    uint32_t state_flags;
} xmeta_state_wire_t;

typedef char xmeta_state_size_check[
    sizeof(xmeta_state_wire_t) == 80 ? 1 : -1];

/* ORIGIN section: {u8 etag_len, u8 alg_len, u8 cks_len, u8 pad, strings...} */
#define XMETA_ORIGIN_FIXED 4

/* ---- encode ---------------------------------------------------------------- */

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

/* ---- decode ---------------------------------------------------------------- */

/* ---- Decode a STATE section payload ----
 *
 * WHAT: Unpacks the fixed 80-byte xmeta_state_wire_t from p into m's
 *       write-back/lifecycle fields. Returns BRIX_XMETA_OK, or
 *       BRIX_XMETA_ERR if the payload is shorter than the wire struct.
 *
 * WHY: Pairs with xmeta_encode_state_section — the two field-copy lists must
 *      mirror each other exactly for the persisted format to round-trip.
 *
 * HOW: 1. Reject payloads shorter than the wire struct (crc already checked
 *         by the section loop; this guards the struct read itself).
 *      2. Copy the struct out and assign each field to m; set have_state.
 */
static int
xmeta_decode_state(brix_xmeta_t *m, const uint8_t *p, uint32_t plen)
{
    xmeta_state_wire_t state;

    if (plen < sizeof(state)) {
        return BRIX_XMETA_ERR;
    }
    memcpy(&state, p, sizeof(state));
    m->have_state    = 1;
    m->origin_mtime  = state.origin_mtime;
    m->dirty_lo      = state.dirty_lo;
    m->dirty_hi      = state.dirty_hi;
    m->flush_gen     = state.flush_gen;
    m->dirty_since   = state.dirty_since;
    m->last_flush    = state.last_flush;
    m->bytes_flushed = state.bytes_flushed;
    m->expires_at    = state.expires_at;
    m->filled_at     = state.filled_at;
    m->mode          = state.mode;
    m->state_flags   = state.state_flags;
    return BRIX_XMETA_OK;
}

/* ---- Decode an ORIGIN section payload ----
 *
 * WHAT: Unpacks the origin validators (etag, checksum algorithm name,
 *       checksum hex) from the {u8 lens, strings...} payload into m. Returns
 *       BRIX_XMETA_OK, or BRIX_XMETA_ERR on a short payload or a length
 *       byte exceeding the in-memory field capacity.
 *
 * WHY: Pairs with xmeta_encode_origin_section. The length bytes come from
 *      disk, so each is bounds-checked against its destination buffer before
 *      any copy — a corrupt record must never overflow m's fixed arrays.
 *
 * HOW: 1. Require the 4-byte fixed header.
 *      2. Validate all three lengths against the struct field sizes AND the
 *         payload length before copying anything.
 *      3. Copy the three strings back to back into m.
 */
static int
xmeta_decode_origin(brix_xmeta_t *m, const uint8_t *p, uint32_t plen)
{
    uint8_t el, al, cl;

    if (plen < XMETA_ORIGIN_FIXED) {
        return BRIX_XMETA_ERR;
    }
    el = p[0]; al = p[1]; cl = p[2];
    if (el > sizeof(m->etag) || al > sizeof(m->cks_alg)
        || cl > sizeof(m->cks_hex)
        || plen < (uint32_t) XMETA_ORIGIN_FIXED + el + al + cl)
    {
        return BRIX_XMETA_ERR;
    }
    m->etag_len = el;
    memcpy(m->etag, p + XMETA_ORIGIN_FIXED, el);
    m->cks_alg_len = al;
    memcpy(m->cks_alg, p + XMETA_ORIGIN_FIXED + el, al);
    m->cks_len = cl;
    memcpy(m->cks_hex, p + XMETA_ORIGIN_FIXED + el + al, cl);
    return BRIX_XMETA_OK;
}

/* ---- Decode a DIGEST section payload ----
 *
 * WHAT: Takes an owned copy of the raw digest TLV list into m->digests.
 *       Returns BRIX_XMETA_OK, or BRIX_XMETA_ERR (ENOMEM) on allocation
 *       failure.
 *
 * WHY: The digest list is stored opaquely and parsed lazily by
 *      brix_xmeta_digest_get, which re-validates entry framing on every
 *      access — so the decode side only needs to own the bytes.
 *
 * HOW: 1. Allocate plen bytes (1 minimum so an empty list stays non-NULL).
 *      2. Copy the payload, replace any previous list.
 */
static int
xmeta_decode_digest(brix_xmeta_t *m, const uint8_t *p, uint32_t plen)
{
    uint8_t *copy = malloc(plen ? plen : 1);

    if (copy == NULL) {
        errno = ENOMEM;
        return BRIX_XMETA_ERR;
    }
    memcpy(copy, p, plen);
    free(m->digests);
    m->digests = copy;
    m->digests_len = plen;
    return BRIX_XMETA_OK;
}

/* ---- Decode a BLOCKCRC section payload ----
 *
 * WHAT: Loads the per-block crc32c table from the {u32 granule, u32 rsv,
 *       u64 nblocks, u32 crc[]} payload into m->blockcrc. Returns
 *       BRIX_XMETA_OK, or BRIX_XMETA_ERR on a short payload, a block count
 *       that does not match the file, or allocation failure (ENOMEM).
 *
 * WHY: Pairs with xmeta_encode_blockcrc_section. The table is only usable if
 *      it describes exactly this file's block count, so a mismatch is
 *      treated as corruption, not skipped.
 *
 * HOW: 1. Require the 16-byte payload header.
 *      2. Cross-check the embedded nblocks against m->nblocks and the
 *         payload length (also bounds the crc[] read).
 *      3. Allocate and copy the table, replacing any previous one.
 */
static int
xmeta_decode_blockcrc(brix_xmeta_t *m, const uint8_t *p, uint32_t plen)
{
    uint64_t nb;

    if (plen < 16) {
        return BRIX_XMETA_ERR;
    }
    memcpy(&nb, p + 8, 8);
    if (nb != m->nblocks || plen != 16 + nb * 4) {
        return BRIX_XMETA_ERR;        /* table doesn't match the file */
    }
    free(m->blockcrc);
    m->blockcrc = malloc(nb ? (size_t) nb * 4 : 4);
    if (m->blockcrc == NULL) {
        errno = ENOMEM;
        return BRIX_XMETA_ERR;
    }
    memcpy(m->blockcrc, p + 16, (size_t) nb * 4);
    m->have_blockcrc = 1;
    return BRIX_XMETA_OK;
}

/* ---- Dispatch one extension section to its codec pair's decoder ----
 *
 * WHAT: Routes a crc-verified section payload to the per-type decoder.
 *       Returns the decoder's result; unknown types return BRIX_XMETA_OK.
 *
 * WHY: Unknown section types are skipped rather than rejected so newer
 *      writers stay readable by older code (forward compatibility).
 *
 * HOW: switch on the section type; one case per known section.
 */
static int
xmeta_decode_section(brix_xmeta_t *m, uint16_t type, const uint8_t *p,
    uint32_t plen)
{
    switch (type) {

    case BRIX_XMETA_SEC_STATE:
        return xmeta_decode_state(m, p, plen);

    case BRIX_XMETA_SEC_ORIGIN:
        return xmeta_decode_origin(m, p, plen);

    case BRIX_XMETA_SEC_DIGEST:
        return xmeta_decode_digest(m, p, plen);

    case BRIX_XMETA_SEC_BLOCKCRC:
        return xmeta_decode_blockcrc(m, p, plen);

    default:
        return BRIX_XMETA_OK;         /* unknown type: skipped (fwd compat) */
    }
}

/* ---- Decode the stock Store POD and populate the fixed fields ----
 *
 * WHAT: Reads version + Store + crc from the front of the record, validates
 *       them, and fills m's fixed fields (sizes, times, counters, nblocks).
 *       Returns BRIX_XMETA_OK; BRIX_XMETA_FOREIGN for a record we don't
 *       recognize as ours; BRIX_XMETA_ERR (EBADMSG) for a crc mismatch.
 *       Allocates nothing, so failure needs no cleanup.
 *
 * WHY: The FOREIGN/ERR distinction is load-bearing: a wrong version or
 *      insane sizes mean "not our record — leave it alone", while a crc
 *      mismatch on a recognized layout means "our record, torn".
 *
 * HOW: 1. Read + check the stock version (FOREIGN on mismatch/short).
 *      2. Read Store + crc; verify crc32c(Store) (ERR on mismatch).
 *      3. Sanity-check sizes and astat count (FOREIGN if insane).
 *      4. Copy the fields into m; derive nblocks and bound it.
 */
static int
xmeta_decode_stock_store(const uint8_t *buf, size_t len, size_t *off,
    brix_xmeta_t *m)
{
    brix_xmeta_stock_store_t store;
    int32_t  version;
    uint32_t crc;

    if (xmeta_get(buf, len, off, &version, 4) != 0
        || version != BRIX_XMETA_STOCK_VERSION)
    {
        return BRIX_XMETA_FOREIGN;
    }
    if (xmeta_get(buf, len, off, &store, sizeof(store)) != 0
        || xmeta_get(buf, len, off, &crc, 4) != 0)
    {
        return BRIX_XMETA_FOREIGN;
    }
    if (crc != brix_crc32c_value(&store, sizeof(store))) {
        errno = EBADMSG;
        return BRIX_XMETA_ERR;
    }
    if (store.buffer_size <= 0 || store.file_size < 0
        || store.astat_size < 0)
    {
        return BRIX_XMETA_FOREIGN;
    }

    m->buffer_size   = store.buffer_size;
    m->file_size     = store.file_size;
    m->creation_time = store.creation_time;
    m->no_cksum_time = store.no_cksum_time;
    m->access_cnt    = store.access_cnt;
    m->status_raw    = store.status_raw;
    m->astat_count   = store.astat_size;
    m->nblocks       = xmeta_nblocks(store.file_size, store.buffer_size);
    if (m->nblocks > BRIX_XMETA_MAX_BLOCKS) {
        return BRIX_XMETA_FOREIGN;
    }
    return BRIX_XMETA_OK;
}

/* ---- Decode the stock bitmap + AStat records and verify their crc ----
 *
 * WHAT: Allocates and reads the present-block bitmap, consumes the AStat
 *       records (keeping the first), and verifies the shared trailing crc.
 *       Returns BRIX_XMETA_OK; BRIX_XMETA_FOREIGN on truncation;
 *       BRIX_XMETA_ERR (EBADMSG/ENOMEM) on crc mismatch or allocation
 *       failure. Frees m itself on any failure after the bitmap exists.
 *
 * WHY: Stock cinfo covers bitmap and AStat records with ONE crc32c, so they
 *      must be consumed and checksummed together; splitting them apart would
 *      break the coverage. Requires m->astat_count/nblocks from
 *      xmeta_decode_stock_store.
 *
 * HOW: 1. Allocate the bitmap (1 byte minimum for zero-block files) and
 *         read it; start the running crc over it.
 *      2. Read each AStat record, keep the first, extend the crc over all.
 *      3. Read the stored crc and compare against the running value.
 */
static int
xmeta_decode_bitmap_astat(const uint8_t *buf, size_t len, size_t *off,
    brix_xmeta_t *m)
{
    uint32_t crc, want;
    uint16_t i;
    size_t   blen;

    blen = xmeta_bitmap_len(m->nblocks);
    m->bitmap = malloc(blen ? blen : 1);
    if (m->bitmap == NULL) {
        errno = ENOMEM;
        return BRIX_XMETA_ERR;
    }
    if (xmeta_get(buf, len, off, m->bitmap, blen) != 0) {
        brix_xmeta_free(m);
        return BRIX_XMETA_FOREIGN;
    }
    want = brix_crc32c_value(m->bitmap, blen);

    /* AStat records: keep the first, checksum them all */
    for (i = 0; (int32_t) i < m->astat_count; i++) {
        brix_xmeta_astat_t a;

        if (xmeta_get(buf, len, off, &a, sizeof(a)) != 0) {
            brix_xmeta_free(m);
            return BRIX_XMETA_FOREIGN;
        }
        if (i == 0) {
            m->astat = a;
        }
        want = brix_crc32c_extend(want, &a, sizeof(a));
    }
    if (xmeta_get(buf, len, off, &crc, 4) != 0) {
        brix_xmeta_free(m);
        return BRIX_XMETA_FOREIGN;
    }
    if (crc != want) {
        brix_xmeta_free(m);
        errno = EBADMSG;
        return BRIX_XMETA_ERR;
    }
    return BRIX_XMETA_OK;
}

/* ---- Decode the optional XCX1 extension trailer ----
 *
 * WHAT: Consumes the extension header and its TLV sections, dispatching each
 *       crc-verified payload through xmeta_decode_section. Returns
 *       BRIX_XMETA_OK — including when there is no trailer or the trailer is
 *       foreign (the stock part stands) — or BRIX_XMETA_ERR (EBADMSG) for a
 *       truncated/corrupt section, freeing m before returning.
 *
 * WHY: The extension is optional by design: a pure stock cinfo ends at the
 *      prefix, and an unrecognized trailer (e.g. stock's own additions) must
 *      not invalidate the stock data we already decoded. But once the XCX1
 *      magic matched, a bad section means a torn write of OUR record — that
 *      is corruption, not foreignness.
 *
 * HOW: 1. off == len → no trailer, done.
 *      2. Read magic/version/count; any mismatch → foreign trailer, done OK.
 *      3. Per section: read the 8-byte TLV header, bound the payload length,
 *         verify crc32c(header+payload), then dispatch by type.
 */
static int
xmeta_decode_ext_sections(const uint8_t *buf, size_t len, size_t *off,
    brix_xmeta_t *m)
{
    uint32_t crc, ext_magic;
    uint16_t ext_version, nsec, i;

    /* extension (optional: a pure stock cinfo ends here) */
    if (*off == len) {
        return BRIX_XMETA_OK;
    }
    if (xmeta_get(buf, len, off, &ext_magic, 4) != 0
        || ext_magic != BRIX_XMETA_EXT_MAGIC
        || xmeta_get(buf, len, off, &ext_version, 2) != 0
        || xmeta_get(buf, len, off, &nsec, 2) != 0)
    {
        return BRIX_XMETA_OK;         /* foreign trailer: stock part stands */
    }

    for (i = 0; i < nsec; i++) {
        uint16_t type, rsv;
        uint32_t plen;
        size_t   sec_hdr = *off;

        if (xmeta_get(buf, len, off, &type, 2) != 0
            || xmeta_get(buf, len, off, &rsv, 2) != 0
            || xmeta_get(buf, len, off, &plen, 4) != 0
            || plen > BRIX_XMETA_MAX_SECTION
            || len - *off < (size_t) plen + 4)
        {
            brix_xmeta_free(m);
            errno = EBADMSG;
            return BRIX_XMETA_ERR;    /* truncated section = torn record */
        }
        memcpy(&crc, buf + *off + plen, 4);
        if (crc != brix_crc32c_value(buf + sec_hdr, 8 + (size_t) plen)) {
            brix_xmeta_free(m);
            errno = EBADMSG;
            return BRIX_XMETA_ERR;
        }
        if (xmeta_decode_section(m, type, buf + *off, plen)
            != BRIX_XMETA_OK)
        {
            brix_xmeta_free(m);
            errno = EBADMSG;
            return BRIX_XMETA_ERR;
        }
        *off += (size_t) plen + 4;
    }

    return BRIX_XMETA_OK;
}

int
brix_xmeta_decode(const uint8_t *buf, size_t len, brix_xmeta_t *m)
{
    size_t off = 0;
    int    rc;

    if (buf == NULL || m == NULL) {
        errno = EINVAL;
        return BRIX_XMETA_ERR;
    }
    memset(m, 0, sizeof(*m));

    /* stock prefix */
    rc = xmeta_decode_stock_store(buf, len, &off, m);
    if (rc != BRIX_XMETA_OK) {
        return rc;
    }
    rc = xmeta_decode_bitmap_astat(buf, len, &off, m);
    if (rc != BRIX_XMETA_OK) {
        return rc;
    }
    return xmeta_decode_ext_sections(buf, len, &off, m);
}
