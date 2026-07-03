/*
 * respbuf.c — grow-on-append response buffer. See respbuf.h.
 */

#include "respbuf.h"
#include <string.h>

#ifdef SSI_UT_STANDALONE
#include <stdlib.h>
#endif

/* Grow the backing block to hold at least `need` bytes (need <= cap_max).
 * Returns the (possibly new) data pointer, or NULL on allocation failure. */
static unsigned char *
respbuf_grow(brix_ssi_respbuf_t *b, size_t need, size_t cap_max)
{
    size_t         newcap = b->cap ? b->cap : 256;
    unsigned char *nd;

    while (newcap < need) {
        newcap *= 2;
    }
    if (newcap > cap_max) {
        newcap = cap_max;   /* need <= cap_max, so newcap still >= need */
    }

#ifdef SSI_UT_STANDALONE
    nd = realloc(b->data, newcap);
    if (nd == NULL) {
        return NULL;
    }
#else
    nd = ngx_palloc(b->pool, newcap);
    if (nd == NULL) {
        return NULL;
    }
    if (b->data != NULL && b->len > 0) {
        memcpy(nd, b->data, b->len);
    }
#endif
    b->data = nd;
    b->cap  = newcap;
    return nd;
}

int
brix_ssi_respbuf_append(brix_ssi_respbuf_t *b, const unsigned char *p,
                          size_t n, size_t cap_max)
{
    if (b->len + n > cap_max) {
        return -1;
    }
    if (b->len + n > b->cap) {
        if (respbuf_grow(b, b->len + n, cap_max) == NULL) {
            return -1;
        }
    }
    if (n > 0) {
        memcpy(b->data + b->len, p, n);
        b->len += n;
    }
    return 0;
}
