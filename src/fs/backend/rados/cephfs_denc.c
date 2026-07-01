/*
 * cephfs_denc.c — read-only cursor over a Ceph-encoded buffer (see header).
 *
 * Every accessor is bounds-checked against a sticky error flag: the first
 * overrun sets `err` and from then on each accessor is a no-op returning
 * zero/NULL. Callers decode a whole struct, then test cephfs_denc_ok() once.
 * Integers are little-endian (Ceph's on-disk/wire encoding); reads are assembled
 * byte-by-byte so the code is endian-independent on the host doing the decode.
 */
#include "cephfs_denc.h"

#include <string.h>

void
cephfs_denc_init(cephfs_denc_t *d, const void *buf, size_t len)
{
    d->p   = (const uint8_t *) buf;
    d->end = (const uint8_t *) buf + len;
    d->err = 0;
}

int
cephfs_denc_ok(const cephfs_denc_t *d)
{
    return d->err == 0;
}

size_t
cephfs_denc_remaining(const cephfs_denc_t *d)
{
    if (d->err != 0 || d->p >= d->end) {
        return 0;
    }
    return (size_t) (d->end - d->p);
}

/* have() — true when n more bytes can be read; otherwise trip the sticky error.
 * Centralizing the check keeps every accessor's failure mode identical. */
static int
have(cephfs_denc_t *d, size_t n)
{
    if (d->err != 0) {
        return 0;
    }
    if ((size_t) (d->end - d->p) < n) {
        d->err = 1;
        return 0;
    }
    return 1;
}

uint8_t
cephfs_denc_u8(cephfs_denc_t *d)
{
    if (!have(d, 1)) {
        return 0;
    }
    return *d->p++;
}

uint16_t
cephfs_denc_u16(cephfs_denc_t *d)
{
    uint16_t v;

    if (!have(d, 2)) {
        return 0;
    }
    v = (uint16_t) ((uint16_t) d->p[0]
                    | ((uint16_t) d->p[1] << 8));
    d->p += 2;
    return v;
}

uint32_t
cephfs_denc_u32(cephfs_denc_t *d)
{
    uint32_t v;

    if (!have(d, 4)) {
        return 0;
    }
    v = (uint32_t) d->p[0]
        | ((uint32_t) d->p[1] << 8)
        | ((uint32_t) d->p[2] << 16)
        | ((uint32_t) d->p[3] << 24);
    d->p += 4;
    return v;
}

uint64_t
cephfs_denc_u64(cephfs_denc_t *d)
{
    uint64_t v;
    int      i;

    if (!have(d, 8)) {
        return 0;
    }
    v = 0;
    for (i = 0; i < 8; i++) {
        v |= (uint64_t) d->p[i] << (8 * i);
    }
    d->p += 8;
    return v;
}

int64_t
cephfs_denc_s64(cephfs_denc_t *d)
{
    return (int64_t) cephfs_denc_u64(d);
}

const uint8_t *
cephfs_denc_bytes(cephfs_denc_t *d, size_t n)
{
    const uint8_t *at;

    if (!have(d, n)) {
        return NULL;
    }
    at = d->p;
    d->p += n;
    return at;
}

void
cephfs_denc_skip(cephfs_denc_t *d, size_t n)
{
    if (have(d, n)) {
        d->p += n;
    }
}

int
cephfs_denc_str(cephfs_denc_t *d, const char **s, uint32_t *len)
{
    uint32_t       n;
    const uint8_t *at;

    n  = cephfs_denc_u32(d);
    at = cephfs_denc_bytes(d, n);
    if (!cephfs_denc_ok(d)) {
        return -1;
    }
    if (s != NULL) {
        *s = (const char *) at;
    }
    if (len != NULL) {
        *len = n;
    }
    return 0;
}

uint8_t
cephfs_denc_start(cephfs_denc_t *d, cephfs_denc_frame_t *f)
{
    uint8_t  v, compat;
    uint32_t struct_len;

    v          = cephfs_denc_u8(d);
    compat     = cephfs_denc_u8(d);
    struct_len = cephfs_denc_u32(d);
    if (!cephfs_denc_ok(d)) {
        return 0;
    }
    /* the payload must fit within the remaining buffer */
    if ((size_t) (d->end - d->p) < struct_len) {
        d->err = 1;
        return 0;
    }
    f->struct_v     = v;
    f->struct_compat = compat;
    f->payload_end  = d->p + struct_len;
    return v;
}

void
cephfs_denc_finish(cephfs_denc_t *d, const cephfs_denc_frame_t *f)
{
    if (d->err != 0) {
        return;
    }
    /* forward-compat: a newer encoder may have appended fields we didn't read */
    if (d->p < f->payload_end) {
        d->p = f->payload_end;
    }
}
