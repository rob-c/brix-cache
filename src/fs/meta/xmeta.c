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
    sizeof(xrootd_xmeta_stock_store_t) == 48 ? 1 : -1];
typedef char xmeta_astat_size_check[
    sizeof(xrootd_xmeta_astat_t) == 56 ? 1 : -1];

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
xrootd_xmeta_init(xrootd_xmeta_t *m, int64_t file_size, int64_t buffer_size)
{
    uint64_t nb;

    if (m == NULL || buffer_size <= 0 || file_size < 0) {
        errno = EINVAL;
        return XROOTD_XMETA_ERR;
    }
    nb = xmeta_nblocks(file_size, buffer_size);
    if (nb > XROOTD_XMETA_MAX_BLOCKS) {
        errno = EFBIG;
        return XROOTD_XMETA_ERR;
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
        xrootd_xmeta_free(m);
        errno = ENOMEM;
        return XROOTD_XMETA_ERR;
    }
    m->have_blockcrc = 1;
    return XROOTD_XMETA_OK;
}

void
xrootd_xmeta_free(xrootd_xmeta_t *m)
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
xrootd_xmeta_block_set(xrootd_xmeta_t *m, uint64_t i)
{
    if (m->bitmap != NULL && i < m->nblocks) {
        m->bitmap[i / 8] |= (uint8_t) (1u << (i % 8));
    }
}

int
xrootd_xmeta_block_test(const xrootd_xmeta_t *m, uint64_t i)
{
    if (m->bitmap == NULL || i >= m->nblocks) {
        return 0;
    }
    return (m->bitmap[i / 8] & (uint8_t) (1u << (i % 8))) != 0;
}

int
xrootd_xmeta_complete(const xrootd_xmeta_t *m)
{
    uint64_t i;

    for (i = 0; i < m->nblocks; i++) {
        if (!xrootd_xmeta_block_test(m, i)) {
            return 0;
        }
    }
    return 1;
}

/* ---- DIGEST list ---------------------------------------------------------- */

int
xrootd_xmeta_digest_add(xrootd_xmeta_t *m, uint16_t alg, const void *val,
    uint16_t len)
{
    size_t   need = 4 + (size_t) len;
    uint8_t *grown;

    if (m == NULL || (val == NULL && len != 0)) {
        errno = EINVAL;
        return XROOTD_XMETA_ERR;
    }
    grown = realloc(m->digests, m->digests_len + need);
    if (grown == NULL) {
        errno = ENOMEM;
        return XROOTD_XMETA_ERR;
    }
    m->digests = grown;
    memcpy(m->digests + m->digests_len, &alg, 2);
    memcpy(m->digests + m->digests_len + 2, &len, 2);
    if (len > 0) {
        memcpy(m->digests + m->digests_len + 4, val, len);
    }
    m->digests_len += (uint32_t) need;
    return XROOTD_XMETA_OK;
}

int
xrootd_xmeta_digest_get(const xrootd_xmeta_t *m, uint32_t idx, uint16_t *alg,
    const uint8_t **val, uint16_t *len)
{
    size_t   off = 0;
    uint32_t i = 0;

    if (m == NULL || m->digests == NULL) {
        return XROOTD_XMETA_FOREIGN;
    }
    while (off + 4 <= m->digests_len) {
        uint16_t a, l;

        memcpy(&a, m->digests + off, 2);
        memcpy(&l, m->digests + off + 2, 2);
        if (off + 4 + l > m->digests_len) {
            return XROOTD_XMETA_FOREIGN;            /* malformed payload */
        }
        if (i == idx) {
            *alg = a;
            *len = l;
            *val = m->digests + off + 4;
            return XROOTD_XMETA_OK;
        }
        off += 4 + (size_t) l;
        i++;
    }
    return XROOTD_XMETA_FOREIGN;                    /* past the end */
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
    crc = xrootd_crc32c_value(buf + hdr_off, 8 + (size_t) plen);
    xmeta_put(buf, off, &crc, 4);
}

int
xrootd_xmeta_encode(const xrootd_xmeta_t *m, uint8_t **out, size_t *out_len)
{
    xrootd_xmeta_stock_store_t store;
    xmeta_state_wire_t         state;
    int32_t   version = XROOTD_XMETA_STOCK_VERSION;
    uint32_t  ext_magic = XROOTD_XMETA_EXT_MAGIC;
    uint16_t  ext_version = XROOTD_XMETA_EXT_VERSION;
    uint16_t  nsec;
    size_t    blen, cap, off = 0;
    size_t    blockcrc_plen = 0;
    uint32_t  crc;
    uint8_t  *buf;

    if (m == NULL || out == NULL || out_len == NULL || m->buffer_size <= 0
        || m->bitmap == NULL)
    {
        errno = EINVAL;
        return XROOTD_XMETA_ERR;
    }

    blen = xmeta_bitmap_len(m->nblocks);
    unsigned have_origin = (m->etag_len > 0 || m->cks_len > 0
                            || m->cks_alg_len > 0);
    size_t   origin_plen = XMETA_ORIGIN_FIXED + m->etag_len
                           + m->cks_alg_len + m->cks_len;

    nsec = (uint16_t) ((m->have_state ? 1 : 0)
                       + (m->digests != NULL ? 1 : 0)
                       + (m->have_blockcrc && m->blockcrc != NULL ? 1 : 0)
                       + (have_origin ? 1 : 0));
    if (m->have_blockcrc && m->blockcrc != NULL) {
        blockcrc_plen = 16 + (size_t) m->nblocks * 4;
    }

    cap = 4 + sizeof(store) + 4                         /* version+store+crc */
          + blen + (m->astat_count > 0 ? sizeof(m->astat) : 0) + 4
          + 8                                           /* ext magic+ver+cnt */
          + (m->have_state ? 12 + sizeof(state) : 0)
          + (m->digests != NULL ? 12 + (size_t) m->digests_len : 0)
          + (blockcrc_plen ? 12 + blockcrc_plen : 0)
          + (have_origin ? 12 + origin_plen : 0);

    buf = malloc(cap);
    if (buf == NULL) {
        errno = ENOMEM;
        return XROOTD_XMETA_ERR;
    }

    /* stock prefix — exactly what XrdPfc::Info::Write emits */
    memset(&store, 0, sizeof(store));
    store.buffer_size   = m->buffer_size;
    store.file_size     = m->file_size;
    store.creation_time = m->creation_time;
    store.no_cksum_time = m->no_cksum_time;
    store.access_cnt    = m->access_cnt;
    store.status_raw    = m->status_raw;
    store.astat_size    = (m->astat_count > 0) ? 1 : 0;

    xmeta_put(buf, &off, &version, 4);
    xmeta_put(buf, &off, &store, sizeof(store));
    crc = xrootd_crc32c_value(&store, sizeof(store));
    xmeta_put(buf, &off, &crc, 4);
    xmeta_put(buf, &off, m->bitmap, blen);
    crc = xrootd_crc32c_value(m->bitmap, blen);
    if (store.astat_size > 0) {
        xmeta_put(buf, &off, &m->astat, sizeof(m->astat));
        crc = xrootd_crc32c_extend(crc, &m->astat, sizeof(m->astat));
    }
    xmeta_put(buf, &off, &crc, 4);

    /* extension */
    xmeta_put(buf, &off, &ext_magic, 4);
    xmeta_put(buf, &off, &ext_version, 2);
    xmeta_put(buf, &off, &nsec, 2);

    if (m->have_state) {
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
        xmeta_put_section(buf, &off, XROOTD_XMETA_SEC_STATE,
                          &state, sizeof(state));
    }
    if (have_origin) {
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
        xmeta_put_section(buf, &off, XROOTD_XMETA_SEC_ORIGIN,
                          payload, (uint32_t) poff);
    }
    if (m->digests != NULL) {
        xmeta_put_section(buf, &off, XROOTD_XMETA_SEC_DIGEST,
                          m->digests, m->digests_len);
    }
    if (blockcrc_plen > 0) {
        /* payload: u32 granule, u32 reserved, u64 nblocks, u32 crc[] — built
         * in place to avoid a second nblocks*4 allocation */
        size_t   sec_hdr = off;
        uint16_t type = XROOTD_XMETA_SEC_BLOCKCRC, rsv = 0;
        uint32_t plen32 = (uint32_t) blockcrc_plen;
        uint32_t granule = (uint32_t) m->buffer_size;
        uint32_t zero = 0;
        uint64_t nb = m->nblocks;

        xmeta_put(buf, &off, &type, 2);
        xmeta_put(buf, &off, &rsv, 2);
        xmeta_put(buf, &off, &plen32, 4);
        xmeta_put(buf, &off, &granule, 4);
        xmeta_put(buf, &off, &zero, 4);
        xmeta_put(buf, &off, &nb, 8);
        xmeta_put(buf, &off, m->blockcrc, (size_t) m->nblocks * 4);
        crc = xrootd_crc32c_value(buf + sec_hdr, 8 + blockcrc_plen);
        xmeta_put(buf, &off, &crc, 4);
    }

    *out = buf;
    *out_len = off;
    return XROOTD_XMETA_OK;
}

/* ---- decode ---------------------------------------------------------------- */

static int
xmeta_decode_section(xrootd_xmeta_t *m, uint16_t type, const uint8_t *p,
    uint32_t plen)
{
    switch (type) {

    case XROOTD_XMETA_SEC_STATE: {
        xmeta_state_wire_t state;

        if (plen < sizeof(state)) {
            return XROOTD_XMETA_ERR;
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
        return XROOTD_XMETA_OK;
    }

    case XROOTD_XMETA_SEC_ORIGIN: {
        uint8_t el, al, cl;

        if (plen < XMETA_ORIGIN_FIXED) {
            return XROOTD_XMETA_ERR;
        }
        el = p[0]; al = p[1]; cl = p[2];
        if (el > sizeof(m->etag) || al > sizeof(m->cks_alg)
            || cl > sizeof(m->cks_hex)
            || plen < (uint32_t) XMETA_ORIGIN_FIXED + el + al + cl)
        {
            return XROOTD_XMETA_ERR;
        }
        m->etag_len = el;
        memcpy(m->etag, p + XMETA_ORIGIN_FIXED, el);
        m->cks_alg_len = al;
        memcpy(m->cks_alg, p + XMETA_ORIGIN_FIXED + el, al);
        m->cks_len = cl;
        memcpy(m->cks_hex, p + XMETA_ORIGIN_FIXED + el + al, cl);
        return XROOTD_XMETA_OK;
    }

    case XROOTD_XMETA_SEC_DIGEST: {
        uint8_t *copy = malloc(plen ? plen : 1);

        if (copy == NULL) {
            errno = ENOMEM;
            return XROOTD_XMETA_ERR;
        }
        memcpy(copy, p, plen);
        free(m->digests);
        m->digests = copy;
        m->digests_len = plen;
        return XROOTD_XMETA_OK;
    }

    case XROOTD_XMETA_SEC_BLOCKCRC: {
        uint64_t nb;

        if (plen < 16) {
            return XROOTD_XMETA_ERR;
        }
        memcpy(&nb, p + 8, 8);
        if (nb != m->nblocks || plen != 16 + nb * 4) {
            return XROOTD_XMETA_ERR;    /* table doesn't match the file */
        }
        free(m->blockcrc);
        m->blockcrc = malloc(nb ? (size_t) nb * 4 : 4);
        if (m->blockcrc == NULL) {
            errno = ENOMEM;
            return XROOTD_XMETA_ERR;
        }
        memcpy(m->blockcrc, p + 16, (size_t) nb * 4);
        m->have_blockcrc = 1;
        return XROOTD_XMETA_OK;
    }

    default:
        return XROOTD_XMETA_OK;         /* unknown type: skipped (fwd compat) */
    }
}

int
xrootd_xmeta_decode(const uint8_t *buf, size_t len, xrootd_xmeta_t *m)
{
    xrootd_xmeta_stock_store_t store;
    int32_t   version;
    uint32_t  crc, want, ext_magic;
    uint16_t  ext_version, nsec, i;
    size_t    off = 0, blen;

    if (buf == NULL || m == NULL) {
        errno = EINVAL;
        return XROOTD_XMETA_ERR;
    }
    memset(m, 0, sizeof(*m));

    /* stock prefix */
    if (xmeta_get(buf, len, &off, &version, 4) != 0
        || version != XROOTD_XMETA_STOCK_VERSION)
    {
        return XROOTD_XMETA_FOREIGN;
    }
    if (xmeta_get(buf, len, &off, &store, sizeof(store)) != 0
        || xmeta_get(buf, len, &off, &crc, 4) != 0)
    {
        return XROOTD_XMETA_FOREIGN;
    }
    if (crc != xrootd_crc32c_value(&store, sizeof(store))) {
        errno = EBADMSG;
        return XROOTD_XMETA_ERR;
    }
    if (store.buffer_size <= 0 || store.file_size < 0
        || store.astat_size < 0)
    {
        return XROOTD_XMETA_FOREIGN;
    }

    m->buffer_size   = store.buffer_size;
    m->file_size     = store.file_size;
    m->creation_time = store.creation_time;
    m->no_cksum_time = store.no_cksum_time;
    m->access_cnt    = store.access_cnt;
    m->status_raw    = store.status_raw;
    m->astat_count   = store.astat_size;
    m->nblocks       = xmeta_nblocks(store.file_size, store.buffer_size);
    if (m->nblocks > XROOTD_XMETA_MAX_BLOCKS) {
        return XROOTD_XMETA_FOREIGN;
    }

    blen = xmeta_bitmap_len(m->nblocks);
    m->bitmap = malloc(blen ? blen : 1);
    if (m->bitmap == NULL) {
        errno = ENOMEM;
        return XROOTD_XMETA_ERR;
    }
    if (xmeta_get(buf, len, &off, m->bitmap, blen) != 0) {
        xrootd_xmeta_free(m);
        return XROOTD_XMETA_FOREIGN;
    }
    want = xrootd_crc32c_value(m->bitmap, blen);

    /* AStat records: keep the first, checksum them all */
    for (i = 0; (int32_t) i < store.astat_size; i++) {
        xrootd_xmeta_astat_t a;

        if (xmeta_get(buf, len, &off, &a, sizeof(a)) != 0) {
            xrootd_xmeta_free(m);
            return XROOTD_XMETA_FOREIGN;
        }
        if (i == 0) {
            m->astat = a;
        }
        want = xrootd_crc32c_extend(want, &a, sizeof(a));
    }
    if (xmeta_get(buf, len, &off, &crc, 4) != 0) {
        xrootd_xmeta_free(m);
        return XROOTD_XMETA_FOREIGN;
    }
    if (crc != want) {
        xrootd_xmeta_free(m);
        errno = EBADMSG;
        return XROOTD_XMETA_ERR;
    }

    /* extension (optional: a pure stock cinfo ends here) */
    if (off == len) {
        return XROOTD_XMETA_OK;
    }
    if (xmeta_get(buf, len, &off, &ext_magic, 4) != 0
        || ext_magic != XROOTD_XMETA_EXT_MAGIC
        || xmeta_get(buf, len, &off, &ext_version, 2) != 0
        || xmeta_get(buf, len, &off, &nsec, 2) != 0)
    {
        return XROOTD_XMETA_OK;         /* foreign trailer: stock part stands */
    }

    for (i = 0; i < nsec; i++) {
        uint16_t type, rsv;
        uint32_t plen;
        size_t   sec_hdr = off;

        if (xmeta_get(buf, len, &off, &type, 2) != 0
            || xmeta_get(buf, len, &off, &rsv, 2) != 0
            || xmeta_get(buf, len, &off, &plen, 4) != 0
            || plen > XROOTD_XMETA_MAX_SECTION
            || len - off < (size_t) plen + 4)
        {
            xrootd_xmeta_free(m);
            errno = EBADMSG;
            return XROOTD_XMETA_ERR;    /* truncated section = torn record */
        }
        memcpy(&crc, buf + off + plen, 4);
        if (crc != xrootd_crc32c_value(buf + sec_hdr, 8 + (size_t) plen)) {
            xrootd_xmeta_free(m);
            errno = EBADMSG;
            return XROOTD_XMETA_ERR;
        }
        if (xmeta_decode_section(m, type, buf + off, plen)
            != XROOTD_XMETA_OK)
        {
            xrootd_xmeta_free(m);
            errno = EBADMSG;
            return XROOTD_XMETA_ERR;
        }
        off += (size_t) plen + 4;
    }

    return XROOTD_XMETA_OK;
}
