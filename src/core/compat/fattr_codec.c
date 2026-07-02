/*
 * fattr_codec.c — kXR_fattr nvec entry parser (see fattr_codec.h).
 *
 * Read-only scan of one [int16 BE rc][name\0] entry, shared by the module's
 * request-nvec parse and the native client's reply-nvec parse. ngx-free.
 */
#include "fattr_codec.h"

int
xrdp_fattr_nvec_parse(const uint8_t *buf, size_t len, size_t off,
                      uint16_t *rc, const uint8_t **name, size_t *nlen,
                      size_t *next_off)
{
    const uint8_t *p, *end, *name_start;

    if (buf == NULL || off > len || len - off < 2) {
        return -1;   /* not even room for the 2-byte rc slot */
    }
    p   = buf + off;
    end = buf + len;

    if (rc != NULL) {
        *rc = (uint16_t) ((p[0] << 8) | p[1]);   /* big-endian per-attr status */
    }
    p += 2;

    name_start = p;
    while (p < end && *p != 0) {
        p++;
    }
    if (p >= end) {
        return -1;   /* name not NUL-terminated within the buffer */
    }

    if (name != NULL)     { *name = name_start; }
    if (nlen != NULL)     { *nlen = (size_t) (p - name_start); }
    if (next_off != NULL) { *next_off = (size_t) (p + 1 - buf); }
    return 0;
}
