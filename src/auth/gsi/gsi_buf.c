/*
 * gsi_buf.c - extracted concern
 * Phase-38 split of gsi_core.c; behavior-identical.
 */
#include "gsi_core_internal.h"

int
brix_gsi_find_bucket(const uint8_t *buf, size_t len, uint32_t type,
                       const uint8_t **out, size_t *outlen)
{
    const uint8_t *cur = buf;
    const uint8_t *end = buf + len;
    size_t         name_len;

    if (len < 8) {
        return -1;
    }
    name_len = strnlen((const char *) cur, len) + 1;   /* protocol name + NUL */
    if (name_len >= len) {
        return -1;
    }
    cur += name_len;
    if (cur + 4 > end) {                                /* step */
        return -1;
    }
    cur += 4;

    while (cur + 8 <= end) {
        uint32_t btype, blen;
        memcpy(&btype, cur, 4);
        memcpy(&blen, cur + 4, 4);
        btype = ntohl(btype);
        blen = ntohl(blen);
        cur += 8;
        if (btype == (uint32_t) kXRS_none) {
            break;
        }
        if ((size_t) (end - cur) < blen) {
            return -1;
        }
        if (btype == type) {
            *out = cur;
            *outlen = blen;
            return 0;
        }
        cur += blen;
    }
    return -1;
}


void
brix_gbuf_init(brix_gbuf *g)
{
    g->p = NULL;
    g->len = 0;
    g->cap = 0;
    g->err = 0;
}


void
brix_gbuf_free(brix_gbuf *g)
{
    free(g->p);
    g->p = NULL;
    g->len = g->cap = 0;
}


void
brix_gbuf_raw(brix_gbuf *g, const void *data, size_t n)
{
    if (g->err) {
        return;
    }
    if (g->len + n > g->cap) {
        size_t   ncap = g->cap ? g->cap : 256;
        uint8_t *np;
        while (g->len + n > ncap) {
            ncap *= 2;
        }
        np = (uint8_t *) realloc(g->p, ncap);
        if (np == NULL) {
            g->err = 1;
            return;
        }
        g->p = np;
        g->cap = ncap;
    }
    memcpy(g->p + g->len, data, n);
    g->len += n;
}


void
brix_gbuf_u32(brix_gbuf *g, uint32_t v)
{
    uint32_t be = htonl(v);
    brix_gbuf_raw(g, &be, 4);
}


void
brix_gbuf_start(brix_gbuf *g, uint32_t step)
{
    brix_gbuf_raw(g, "gsi\0", 4);
    brix_gbuf_u32(g, step);
}


void
brix_gbuf_bucket(brix_gbuf *g, uint32_t type, const void *d, size_t n)
{
    brix_gbuf_u32(g, type);
    brix_gbuf_u32(g, (uint32_t) n);
    brix_gbuf_raw(g, d, n);
}


void
brix_gbuf_end(brix_gbuf *g)
{
    brix_gbuf_u32(g, (uint32_t) kXRS_none);
}
