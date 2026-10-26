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

/*
 * brix_gsi_bucket_start — locate the first bucket after the GSI preamble.
 * WHAT: Returns the first bucket byte, or NULL for a malformed preamble.
 * WHY: Unique-bucket scanning must validate the protocol name and step once.
 * HOW: 1. Bound the NUL name. 2. Require the step. 3. Advance past both.
 */
static const uint8_t *
brix_gsi_bucket_start(const uint8_t *buf, size_t len)
{
    size_t name_len;

    if (len < 12) {
        return NULL;
    }
    name_len = strnlen((const char *) buf, len);
    if (name_len == len) {
        return NULL;
    }
    if (name_len + 1 > len - sizeof(uint32_t)) {
        return NULL;
    }
    return buf + name_len + 1 + sizeof(uint32_t);
}

/*
 * brix_gsi_next_bucket — decode one bounded bucket header.
 * WHAT: Returns -1 malformed, 1 terminator, or 0 with type/length and payload.
 * WHY: Header bounds and network-order decoding must be identical per bucket.
 * HOW: 1. Decode type. 2. Detect terminator. 3. Bound length and payload.
 */
static int
brix_gsi_next_bucket(const uint8_t **cursor, const uint8_t *end,
    uint32_t *type, size_t *length)
{
    uint32_t encoded_length;

    if ((size_t) (end - *cursor) < sizeof(*type)) {
        return -1;
    }
    memcpy(type, *cursor, sizeof(*type));
    *type = ntohl(*type);
    *cursor += sizeof(*type);
    if (*type == (uint32_t) kXRS_none) {
        return 1;
    }
    if ((size_t) (end - *cursor) < sizeof(encoded_length)) {
        return -1;
    }
    memcpy(&encoded_length, *cursor, sizeof(encoded_length));
    *cursor += sizeof(encoded_length);
    encoded_length = ntohl(encoded_length);
    if ((size_t) (end - *cursor) < (size_t) encoded_length) {
        return -1;
    }
    *length = (size_t) encoded_length;
    return 0;
}

/*
 * brix_gsi_publish_unique_bucket — publish an exactly-once scan result.
 * WHAT: Writes the result and returns 0 for one match, otherwise returns -1.
 * WHY: Explicit and length-delimited termination share the same final rule.
 * HOW: 1. Require one match. 2. Copy its borrowed pointer and bounded length.
 */
static int
brix_gsi_publish_unique_bucket(const uint8_t *found, size_t found_len,
    unsigned matches, const uint8_t **out, size_t *outlen)
{
    if (matches != 1) {
        return -1;
    }
    *out = found;
    *outlen = found_len;
    return 0;
}

/*
 * brix_gsi_find_unique_bucket — find exactly one bucket of a requested type.
 * WHAT: Returns 0 with a borrowed payload, or -1 for absent/duplicate/malformed.
 * WHY: Authentication proof material must be unambiguous and completely bounded.
 * HOW: 1. Validate preamble. 2. Decode buckets. 3. Enforce exact termination.
 */
int
brix_gsi_find_unique_bucket(const uint8_t *buf, size_t len, uint32_t type,
                              const uint8_t **out, size_t *outlen)
{
    const uint8_t *cur;
    const uint8_t *end;
    const uint8_t *found = NULL;
    size_t         found_len = 0;
    unsigned       matches = 0;

    if (buf == NULL || out == NULL || outlen == NULL || len < 12) {
        return -1;
    }
    end = buf + len;
    cur = brix_gsi_bucket_start(buf, len);
    if (cur == NULL) {
        return -1;
    }

    while (cur < end) {
        uint32_t btype;
        size_t   bucket_len;
        int      rc;

        rc = brix_gsi_next_bucket(&cur, end, &btype, &bucket_len);
        if (rc < 0) {
            return -1;
        }
        if (rc > 0) {
            if (cur != end) {
                return -1;
            }
            return brix_gsi_publish_unique_bucket(found, found_len, matches,
                                                   out, outlen);
        }
        if (btype == type) {
            matches++;
            found = cur;
            found_len = bucket_len;
        }
        cur += bucket_len;
    }

    /* XrdSutBuffer has two interoperable encodings in the field: some peers
     * append kXRS_none, while others rely on the enclosing buffer length.  In
     * the latter form, exact exhaustion is the terminator.  A 1--3 byte tail,
     * a truncated header/payload, or anything after an explicit kXRS_none was
     * rejected above and must remain an error. */
    return brix_gsi_publish_unique_bucket(found, found_len, matches,
                                          out, outlen);
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
