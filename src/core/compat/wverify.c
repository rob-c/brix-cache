/*
 * wverify.c — self-computed write-integrity accumulator (see wverify.h).
 *
 * Offset-sorted extent list; each update CRC-32's its buffer and coalesces with
 * any extent it is now adjacent to, combining CRCs with zlib crc32_combine. A
 * complete write leaves exactly one extent {0, size, crc}; anything else (gap,
 * overlap, degraded) makes brix_wverify_expected fail closed.
 */
#include "core/compat/wverify.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Cap the live extent count. An in-order stream stays at 1; an out-of-order
 * writer (MODE E) holds at most one extent per not-yet-adjacent stream, far
 * below this. Exceeding it marks the accumulator degraded (fails closed) rather
 * than growing unbounded on a pathological arrival pattern. */
#define BRIX_WVERIFY_MAX_EXTENTS 4096

typedef struct {
    off_t    lo;
    off_t    hi;        /* exclusive */
    uint32_t crc;       /* CRC-32 of bytes [lo, hi) */
} wv_extent_t;

struct brix_wverify_s {
    wv_extent_t *ext;
    size_t       n;
    size_t       cap;
    int          degraded;   /* an update failed; expected() must fail closed */
};

brix_wverify_t *
brix_wverify_begin(void)
{
    brix_wverify_t *w = calloc(1, sizeof(*w));
    return w;   /* NULL on OOM propagates to the caller */
}

void
brix_wverify_free(brix_wverify_t *w)
{
    if (w == NULL) {
        return;
    }
    free(w->ext);
    free(w);
}

/* Ensure room for one more extent. 0 / -1 (cap or OOM). */
static int
wv_reserve(brix_wverify_t *w)
{
    size_t       want;
    wv_extent_t *grown;

    if (w->n < w->cap) {
        return 0;
    }
    if (w->n >= BRIX_WVERIFY_MAX_EXTENTS) {
        return -1;
    }
    want = w->cap ? w->cap * 2 : 16;
    if (want > BRIX_WVERIFY_MAX_EXTENTS) {
        want = BRIX_WVERIFY_MAX_EXTENTS;
    }
    grown = realloc(w->ext, want * sizeof(*grown));
    if (grown == NULL) {
        return -1;
    }
    w->ext = grown;
    w->cap = want;
    return 0;
}

/* Merge extent i with i+1 when they abut (ext[i].hi == ext[i+1].lo). */
static void
wv_merge_at(brix_wverify_t *w, size_t i)
{
    wv_extent_t *a = &w->ext[i];
    wv_extent_t *b = &w->ext[i + 1];

    a->crc = (uint32_t) crc32_combine((uLong) a->crc, (uLong) b->crc,
                                      (z_off_t) (b->hi - b->lo));
    a->hi  = b->hi;
    memmove(b, b + 1, (w->n - i - 2) * sizeof(*b));
    w->n--;
}

int
brix_wverify_update(brix_wverify_t *w, const void *buf, off_t off, size_t len)
{
    off_t  hi;
    size_t pos;

    if (w == NULL || off < 0 || (buf == NULL && len != 0)) {
        if (w != NULL) { w->degraded = 1; }
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if ((off_t) len < 0 || off > (off_t) (((uint64_t) 1 << 62)) - (off_t) len) {
        w->degraded = 1;
        return -1;                          /* off + len would overflow */
    }
    hi = off + (off_t) len;

    /* Insertion point: first extent whose lo >= off. Reject any overlap with the
     * neighbours on either side (a fresh write must not restate committed bytes). */
    for (pos = 0; pos < w->n && w->ext[pos].lo < off; pos++) {
        /* nothing */
    }
    if (pos > 0 && w->ext[pos - 1].hi > off) {
        w->degraded = 1;
        return -1;                          /* overlaps the extent to the left  */
    }
    if (pos < w->n && w->ext[pos].lo < hi) {
        w->degraded = 1;
        return -1;                          /* overlaps the extent to the right */
    }

    if (wv_reserve(w) != 0) {
        w->degraded = 1;
        return -1;
    }
    memmove(&w->ext[pos + 1], &w->ext[pos], (w->n - pos) * sizeof(w->ext[0]));
    w->ext[pos].lo  = off;
    w->ext[pos].hi  = hi;
    w->ext[pos].crc = (uint32_t) crc32(crc32(0L, Z_NULL, 0),
                                       (const Bytef *) buf, (uInt) len);
    w->n++;

    /* Coalesce with an abutting right neighbour, then the left, so the list stays
     * minimal (a contiguous stream collapses to a single extent). */
    if (pos + 1 < w->n && w->ext[pos].hi == w->ext[pos + 1].lo) {
        wv_merge_at(w, pos);
    }
    if (pos > 0 && w->ext[pos - 1].hi == w->ext[pos].lo) {
        wv_merge_at(w, pos - 1);
    }

    return 0;
}

int
brix_wverify_expected(const brix_wverify_t *w, uint32_t *crc, off_t *total)
{
    if (w == NULL || crc == NULL || total == NULL) {
        return -1;
    }
    if (w->degraded || w->n != 1 || w->ext[0].lo != 0) {
        return -1;                          /* gap / overlap / nothing / degraded */
    }
    *crc   = w->ext[0].crc;
    *total = w->ext[0].hi;
    return 0;
}
