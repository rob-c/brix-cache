#ifndef BRIX_SHARED_SERVE_OFFLOAD_FILL_H
#define BRIX_SHARED_SERVE_OFFLOAD_FILL_H

/*
 * serve_offload_fill.h — materialise the window an off-loop serve will send.
 *
 * WHAT: copy a remote object into a scratch fd, fetching only the byte window
 *       the response is actually going to carry.
 *
 * WHY:  see serve_offload_fill.c — the off-loop serve fetched the WHOLE object
 *       for every ranged read, which was invisible until phase-115 §P6 routed
 *       gsiftp here and its origin log started saying `ERET P 0 384000` to
 *       serve 256 bytes.
 *
 * HOW:  the size and mtime the response must report come back in the out
 *       struct; the return is 0 or an errno, never a partial success.
 */

#include "fs/backend/sd.h"

typedef struct {
    off_t   size;    /* the size the response must report                     */
    time_t  mtime;   /* the object mtime as seen at materialise time          */
} brix_serve_offload_fill_t;

/* Copy `obj` into `tmp_fd`, narrowed to the window named by the raw Range header
 * `range_hdr`/`range_len` (NULL/0 = the whole object).  Returns 0, or an errno
 * with `*out` unusable. */
int brix_serve_offload_fill(brix_sd_obj_t *obj, int tmp_fd,
    const u_char *range_hdr, size_t range_len,
    brix_serve_offload_fill_t *out);

#endif /* BRIX_SHARED_SERVE_OFFLOAD_FILL_H */
