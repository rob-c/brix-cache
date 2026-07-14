/*
 * fs/meta/xmeta.c — per-file metadata record: lifecycle, bitmap and digest ops.
 *
 * WHAT: Owns the in-memory brix_xmeta_t record — init/free, the present-block
 *       bitmap accessors, and the DIGEST-list add/set/get operations — plus the
 *       block-geometry helpers (xmeta_nblocks / xmeta_bitmap_len) shared with
 *       the codec halves. WHY: the wire encode (xmeta_encode.c) and decode
 *       (xmeta_decode.c) were split out so this file, the record's data model,
 *       stays under the 500-line cap (spec 2026-07-02-xmeta-unified-metadata-
 *       design.md). HOW: pure C, ngx-free, malloc-based; the DIGEST list is a
 *       flat {u16 alg, u16 len, u8[len]} TLV blob re-validated on every access.
 */

#include "xmeta.h"
#include "xmeta_internal.h"

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

/* ---- shared block-geometry helpers (declared in xmeta_internal.h) -------- */

uint64_t
xmeta_nblocks(int64_t file_size, int64_t buffer_size)
{
    if (file_size <= 0) {
        return 0;
    }
    return ((uint64_t) file_size + (uint64_t) buffer_size - 1)
           / (uint64_t) buffer_size;
}

size_t
xmeta_bitmap_len(uint64_t nblocks)
{
    return (size_t) ((nblocks + 7) / 8);
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
