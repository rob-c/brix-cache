#ifndef BRIX_SSI_RESPBUF_H
#define BRIX_SSI_RESPBUF_H

/*
 * respbuf.h — a grow-on-append response byte buffer.
 *
 * WHAT: an append-only byte buffer that grows up to a caller-supplied cap, so a
 *       streaming service can produce its response in chunks over time without
 *       pre-sizing a fixed block.
 * WHY:  replaces the fixed 1 MiB SSI response buffer; a read cursor indexes into
 *       the current backing block, which is stable between grows for the reader.
 * HOW:  copy-grow (doubling, capped). nginx build uses ngx_palloc + copy (the pool
 *       has no realloc); standalone unit tests use realloc.
 */

#include <stddef.h>

#ifdef SSI_UT_STANDALONE
typedef struct ngx_pool_s ngx_pool_t;   /* opaque in unit tests */
#else
#include <ngx_config.h>
#include <ngx_core.h>
#endif

typedef struct {
    unsigned char *data;
    size_t         len;
    size_t         cap;
    ngx_pool_t    *pool;   /* set before the first append (NULL in unit tests) */
} brix_ssi_respbuf_t;

/*
 * Append n bytes; grows the backing block as needed. Returns 0 on success, -1 if
 * appending would exceed cap_max or allocation fails (the buffer is unchanged on
 * failure).
 */
int brix_ssi_respbuf_append(brix_ssi_respbuf_t *b, const unsigned char *p,
                              size_t n, size_t cap_max);

#endif /* BRIX_SSI_RESPBUF_H */
