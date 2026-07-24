/*
 * brix_fault_buf.h — tiny bounded output-buffer append helpers shared by the
 * protocol-surgery modules (TLS record + HTTP smuggling).  Header-only so the
 * one definition is shared, never duplicated per translation unit.
 *
 * Both helpers append into out[*o] within capacity `cap`, advancing *o, and
 * silently stop at the cap (a truncated fault buffer is itself a valid fault).
 */
#ifndef BRIX_FAULT_BUF_H
#define BRIX_FAULT_BUF_H

#include <stddef.h>
#include <string.h>

/* Append up to `n` bytes of `src`; returns the number actually written. */
static inline size_t
fp_bufcat(unsigned char *out, size_t cap, size_t *o, const void *src, size_t n)
{
    if (*o >= cap) {
        return 0;
    }
    size_t room = cap - *o;
    if (n > room) {
        n = room;
    }
    memcpy(out + *o, src, n);
    *o += n;
    return n;
}

/* Append one byte; returns 1 on write, 0 if the buffer is full. */
static inline int
fp_bufputc(unsigned char *out, size_t cap, size_t *o, unsigned char b)
{
    if (*o >= cap) {
        return 0;
    }
    out[(*o)++] = b;
    return 1;
}

/* Append a CRLF, or a bare LF when `lf` is set (naked-LF line-ending fault). */
static inline void
fp_buf_eol(unsigned char *out, size_t cap, size_t *o, int lf)
{
    if (lf) {
        fp_bufputc(out, cap, o, '\n');
    } else {
        fp_bufcat(out, cap, o, "\r\n", 2);
    }
}

#endif /* BRIX_FAULT_BUF_H */
