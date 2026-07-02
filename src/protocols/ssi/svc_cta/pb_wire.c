/*
 * pb_wire.c — minimal protobuf wire primitives. See pb_wire.h.
 *
 * Protobuf binary encoding: a message is a sequence of (tag, value) pairs where
 * tag = (field_number << 3) | wire_type. Varints are little-endian base-128 with
 * the high bit as a continuation flag. All readers are bounds-checked against the
 * cursor end; input is untrusted.
 */

#include "pb_wire.h"
#include <string.h>

int
pb_read_varint(pb_reader *r, uint64_t *out)
{
    uint64_t v = 0;
    int      shift = 0;

    while (r->p < r->end) {
        unsigned char b = *r->p++;
        if (shift <= 63) {
            v |= (uint64_t) (b & 0x7f) << shift;
        }
        if ((b & 0x80) == 0) {
            *out = v;
            return 0;
        }
        shift += 7;
        if (shift >= 70) {
            return -1;   /* varint too long (> 10 bytes) */
        }
    }
    return -1;   /* ran out of input mid-varint */
}

int
pb_read_tag(pb_reader *r, uint32_t *field, int *wiretype)
{
    uint64_t tag;

    if (pb_read_varint(r, &tag) != 0) {
        return -1;
    }
    *wiretype = (int) (tag & 0x7);
    *field    = (uint32_t) (tag >> 3);
    if (*field == 0) {
        return -1;   /* field number 0 is invalid */
    }
    return 0;
}

int
pb_read_len_delim(pb_reader *r, const unsigned char **data, size_t *len)
{
    uint64_t n;

    if (pb_read_varint(r, &n) != 0) {
        return -1;
    }
    if (n > (uint64_t) (r->end - r->p)) {
        return -1;   /* declared length runs past the buffer */
    }
    *data = r->p;
    *len  = (size_t) n;
    r->p += n;
    return 0;
}

int
pb_skip_field(pb_reader *r, int wiretype)
{
    uint64_t              v;
    const unsigned char  *d;
    size_t                n;

    switch (wiretype) {
    case PB_WT_VARINT:
        return pb_read_varint(r, &v);
    case PB_WT_I64:
        if (r->end - r->p < 8) {
            return -1;
        }
        r->p += 8;
        return 0;
    case PB_WT_LEN:
        return pb_read_len_delim(r, &d, &n);
    case PB_WT_I32:
        if (r->end - r->p < 4) {
            return -1;
        }
        r->p += 4;
        return 0;
    default:
        return -1;   /* groups (3,4) unsupported / unknown wire type */
    }
}

int
pb_write_varint(pb_writer *w, uint64_t v)
{
    do {
        unsigned char b = (unsigned char) (v & 0x7f);
        v >>= 7;
        if (v != 0) {
            b |= 0x80;
        }
        if (w->len >= w->cap) {
            return -1;
        }
        w->p[w->len++] = b;
    } while (v != 0);
    return 0;
}

int
pb_write_tag(pb_writer *w, uint32_t field, int wiretype)
{
    return pb_write_varint(w, ((uint64_t) field << 3) | (uint64_t) wiretype);
}

int
pb_write_len_delim(pb_writer *w, uint32_t field, const unsigned char *data,
                   size_t len)
{
    if (pb_write_tag(w, field, PB_WT_LEN) != 0) {
        return -1;
    }
    if (pb_write_varint(w, (uint64_t) len) != 0) {
        return -1;
    }
    if (w->len + len > w->cap) {
        return -1;
    }
    if (len > 0) {
        memcpy(w->p + w->len, data, len);
        w->len += len;
    }
    return 0;
}

int
pb_write_string(pb_writer *w, uint32_t field, const char *s)
{
    return pb_write_len_delim(w, field, (const unsigned char *) s, strlen(s));
}

int
pb_write_varint_field(pb_writer *w, uint32_t field, uint64_t v)
{
    if (pb_write_tag(w, field, PB_WT_VARINT) != 0) {
        return -1;
    }
    return pb_write_varint(w, v);
}
