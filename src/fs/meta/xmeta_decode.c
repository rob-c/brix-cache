/*
 * fs/meta/xmeta_decode.c — decode a per-file metadata record from its wire form.
 *
 * WHAT: brix_xmeta_decode() and its helpers: parse a wire buffer into a
 *       brix_xmeta_t — the byte-identical stock XrdPfc cinfo v4 prefix
 *       (version + Store POD + crc + bitmap + AStat[] + crc) followed by the
 *       optional "XCX1" extension header and its STATE / ORIGIN / DIGEST /
 *       BLOCKCRC TLV sections. WHY: split out of xmeta.c (942 lines) so the
 *       decode half and the encode half (xmeta_encode.c) each stay under the
 *       500-line cap and can be reviewed as a matched pair. HOW: every
 *       variable-length region is crc-verified before use; a wrong version or
 *       insane sizes yield BRIX_XMETA_FOREIGN ("not our record"), while a crc
 *       mismatch on a recognized layout yields BRIX_XMETA_ERR ("torn write").
 *       Unknown extension section types are skipped for forward compat.
 */

#include "xmeta.h"
#include "xmeta_internal.h"
#include "core/compat/crc32c.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ---- decode ---------------------------------------------------------------- */

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
