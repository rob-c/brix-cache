/*
 * aio_buffers.c - extracted concern
 * Phase-38 split of aio.c; behavior-identical.
 */
#include "aio_internal.h"

int
xbuf_reserve(xbuf *b, size_t need)
{
    if (b->len + need <= b->cap) {
        return 0;
    }
    size_t ncap = (b->cap == 0) ? 4096 : b->cap;
    while (ncap < b->len + need) {
        ncap *= 2;
    }
    uint8_t *nb = (uint8_t *) realloc(b->buf, ncap);
    if (nb == NULL) {
        return -1;
    }
    b->buf = nb;
    b->cap = ncap;
    return 0;
}


int
xbuf_append(xbuf *b, const void *data, size_t n)
{
    if (n == 0) {
        return 0;
    }
    if (xbuf_reserve(b, n) != 0) {
        return -1;
    }
    memcpy(b->buf + b->len, data, n);
    b->len += n;
    return 0;
}


/* Drop the consumed prefix [0,start) so the live bytes sit at the front. */
void
xbuf_compact(xbuf *b)
{
    if (b->start == 0) {
        return;
    }
    if (b->start >= b->len) {
        b->start = b->len = 0;
        return;
    }
    memmove(b->buf, b->buf + b->start, b->len - b->start);
    b->len -= b->start;
    b->start = 0;
}


void
xbuf_free(xbuf *b)
{
    free(b->buf);
    b->buf = NULL;
    b->cap = b->start = b->len = 0;
}


/* request *//*
 * One in-flight request. The finalized 24-byte header and the (owned) payload are
 * retained so M2/M3 can re-issue the request after a reconnect. Reply bytes from
 * one or more kXR_oksofar frames plus the terminal frame accumulate into `acc`,
 * which is handed to the callback on completion.
 */

void
areq_free(brix_areq *r)
{
    if (r == NULL) {
        return;
    }
    free(r->payload);
    free(r->acc);
    free(r);
}


int
areq_accumulate(brix_areq *r, const uint8_t *body, uint32_t n)
{
    if (n == 0) {
        return 0;
    }
    if (r->acc_len + n > r->acc_cap) {
        uint32_t ncap = (r->acc_cap == 0) ? n : r->acc_cap;
        while (ncap < r->acc_len + n) {
            ncap *= 2;
        }
        uint8_t *na = (uint8_t *) realloc(r->acc, ncap);
        if (na == NULL) {
            return -1;
        }
        r->acc = na;
        r->acc_cap = ncap;
    }
    memcpy(r->acc + r->acc_len, body, n);
    r->acc_len += n;
    return 0;
}


/* Invoke the completion callback exactly once and free the request. On success the
 * accumulated body ownership transfers to the callback; on failure body is NULL. */
void
areq_complete(brix_areq *r, int rc, uint16_t kxr, const brix_status *st)
{
    uint8_t  *body = NULL;
    uint32_t  blen = 0;

    if (rc == 0) {
        body = r->acc;
        blen = r->acc_len;
        r->acc = NULL;          /* ownership moves to the callback */
    }
    r->cb(r->ctx, rc, kxr, body, blen, st);
    areq_free(r);
}


/* reqmap *//*
 * Open-addressing (linear-probe) map from streamid → in-flight request. The key
 * space is dense and the live count is bounded by the pipeline depth, so this stays
 * tiny and fast. Deleted slots are tombstoned and reclaimed on the next rehash.
 */


int
reqmap_rehash(reqmap *m, uint32_t newcap)
{
    brix_areq **ns = (brix_areq **) calloc(newcap, sizeof(*ns));
    if (ns == NULL) {
        return -1;
    }
    for (uint32_t i = 0; i < m->cap; i++) {
        brix_areq *r = m->slots[i];
        if (r == NULL || r == REQMAP_TOMB) {
            continue;
        }
        uint32_t idx = r->sid & (newcap - 1);
        while (ns[idx] != NULL) {
            idx = (idx + 1) & (newcap - 1);
        }
        ns[idx] = r;
    }
    free(m->slots);
    m->slots = ns;
    m->cap = newcap;
    m->tomb = 0;
    return 0;
}


int
reqmap_put(reqmap *m, brix_areq *r)
{
    if (m->cap == 0) {
        if (reqmap_rehash(m, 64) != 0) {
            return -1;
        }
    }
    if ((m->count + m->tomb + 1) * 4 >= m->cap * 3) {
        uint32_t newcap = (m->count * 2 < m->cap) ? m->cap : m->cap * 2;
        if (newcap < 64) {
            newcap = 64;
        }
        if (reqmap_rehash(m, newcap) != 0) {
            return -1;
        }
    }
    uint32_t idx = r->sid & (m->cap - 1);
    while (m->slots[idx] != NULL && m->slots[idx] != REQMAP_TOMB) {
        idx = (idx + 1) & (m->cap - 1);
    }
    if (m->slots[idx] == REQMAP_TOMB) {
        m->tomb--;
    }
    m->slots[idx] = r;
    m->count++;
    return 0;
}


brix_areq *
reqmap_get(reqmap *m, uint16_t sid)
{
    if (m->cap == 0) {
        return NULL;
    }
    uint32_t idx = sid & (m->cap - 1);
    for (uint32_t n = 0; n < m->cap; n++) {
        brix_areq *r = m->slots[idx];
        if (r == NULL) {
            return NULL;
        }
        if (r != REQMAP_TOMB && r->sid == sid) {
            return r;
        }
        idx = (idx + 1) & (m->cap - 1);
    }
    return NULL;
}


void
reqmap_del(reqmap *m, uint16_t sid)
{
    if (m->cap == 0) {
        return;
    }
    uint32_t idx = sid & (m->cap - 1);
    for (uint32_t n = 0; n < m->cap; n++) {
        brix_areq *r = m->slots[idx];
        if (r == NULL) {
            return;
        }
        if (r != REQMAP_TOMB && r->sid == sid) {
            m->slots[idx] = REQMAP_TOMB;
            m->count--;
            m->tomb++;
            return;
        }
        idx = (idx + 1) & (m->cap - 1);
    }
}
