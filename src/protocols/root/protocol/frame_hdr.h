/*
 * frame_hdr.h — XRootD response-frame field codecs (single source of truth).
 *
 * WHAT: unaligned-safe big-endian accessors + the small pure codecs both the
 *       module and the native client apply to server response frames:
 *         - xrd_resp_hdr_unpack: ServerResponseHeader (streamid/status/dlen)
 *         - xrd_wait_secs_parse: kXR_wait / kXR_waitresp retry-after seconds
 *         - xrd_error_body_decode: kXR_error [errnum][msg] (msg NOT NUL-guaranteed)
 * WHY:  these layouts were hand-decoded ~6× in the client (with unaligned
 *       `ntohl(*(uint32_t*)p)` casts — UB on non-aligned frame buffers — and two
 *       `%s` over-reads on the non-NUL error message) and parsed again on the
 *       server's proxy/upstream relay paths. One header keeps the wire facts in a
 *       single place and the access UB-free.
 * HOW:  header-only static inlines over the documented wire vocabulary — no ngx,
 *       no allocation, no OpenSSL. The memcpy+ntoh accessors are the exact idiom
 *       the safe server sites (compat/vendor_ext.c) already use.
 *
 * Clean-room: layouts from src/protocol (cross-checked vs XProtocol.hh).
 */
#ifndef BRIX_PROTOCOL_FRAME_HDR_H
#define BRIX_PROTOCOL_FRAME_HDR_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/* ---- unaligned-safe big-endian accessors (memcpy + ntoh) ---- */
static inline uint16_t
xrd_get_u16_be(const void *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return ntohs(v);
}

static inline uint32_t
xrd_get_u32_be(const void *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return ntohl(v);
}

static inline uint64_t
xrd_get_u64_be(const void *p)
{
    uint32_t hi, lo;
    memcpy(&hi, p, 4);
    memcpy(&lo, (const uint8_t *) p + 4, 4);
    return ((uint64_t) ntohl(hi) << 32) | (uint64_t) ntohl(lo);
}

static inline void
xrd_put_u16_be(void *p, uint16_t v)
{
    v = htons(v);
    memcpy(p, &v, sizeof(v));
}

static inline void
xrd_put_u32_be(void *p, uint32_t v)
{
    v = htonl(v);
    memcpy(p, &v, sizeof(v));
}

static inline void
xrd_put_u64_be(void *p, uint64_t v)
{
    uint32_t hi = htonl((uint32_t) (v >> 32));
    uint32_t lo = htonl((uint32_t) (v & 0xffffffffu));
    memcpy(p, &hi, 4);
    memcpy((uint8_t *) p + 4, &lo, 4);
}

/*
 * ServerResponseHeader = streamid[2] + status[2 BE] + dlen[4 BE] (8 bytes).
 * streamid is an opaque 2-byte token echoed back; we read it big-endian so it
 * compares equal to the value the sender wrote. Any of the out-params may be NULL.
 */
static inline void
xrd_resp_hdr_unpack(const uint8_t h[8], uint16_t *streamid, uint16_t *status,
                    uint32_t *dlen)
{
    if (streamid != NULL) { *streamid = xrd_get_u16_be(h); }
    if (status != NULL)   { *status   = xrd_get_u16_be(h + 2); }
    if (dlen != NULL)     { *dlen     = xrd_get_u32_be(h + 4); }
}

/*
 * kXR_wait / kXR_waitresp retry-after body = [int32 BE seconds]. Returns the
 * advised seconds clamped to [1, cap]; uses `fallback` if the body is too short.
 * The cap is caller-supplied on purpose — each role wants a different ceiling
 * (a client honoring an origin's tape-recall vs a proxy absorbing for a client).
 */
static inline uint32_t
xrd_wait_secs_parse(const uint8_t *body, uint32_t blen, uint32_t fallback,
                    uint32_t cap)
{
    uint32_t s = (blen >= 4 && body != NULL) ? xrd_get_u32_be(body) : fallback;
    if (s < 1)   { s = 1; }
    if (s > cap) { s = cap; }
    return s;
}

/*
 * kXR_error body = [int32 BE errnum][message bytes]. The message is NOT
 * NUL-terminated on the wire, so this returns a BOUNDED slice (*msg + *msglen) —
 * callers MUST use the length (e.g. "%.*s"), never treat *msg as a C string.
 * Returns 0 on success, -1 if the body is too short to hold errnum. Out-params
 * other than the return may be NULL.
 */
static inline int
xrd_error_body_decode(const uint8_t *body, uint32_t dlen, int *errnum,
                      const char **msg, size_t *msglen)
{
    if (body == NULL || dlen < 4) {
        return -1;
    }
    if (errnum != NULL) { *errnum = (int) xrd_get_u32_be(body); }
    if (msg != NULL)    { *msg    = (const char *) (body + 4); }
    if (msglen != NULL) { *msglen = (size_t) (dlen - 4); }
    return 0;
}

#endif /* BRIX_PROTOCOL_FRAME_HDR_H */
