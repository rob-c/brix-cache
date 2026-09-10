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

/* ---- client-request frame prologue ---- */
/*
 * Every ClientRequest arm opens with the same four bytes — `kXR_char
 * streamid[2]` then a big-endian `kXR_unt16 requestid` — before the arm's own
 * fields begin.  xrd_creq_begin stamps exactly that prologue: zero the whole
 * struct, tag the request slot in streamid[1], write the opcode.
 *
 * WHY: every outbound request site (the cache origin's auth/read/pgread/write
 * legs, the TPC source and push legs) opened with the identical declare +
 * memzero + streamid + requestid lines.  That is a clone by shape — which is
 * what tools/ci/check_duplication.py reports — but the reason to share it is
 * that a site which forgets the zeroing ships uninitialised stack into a wire
 * frame, and nothing on the wire says so.  The per-op fields stay at the call
 * site: they are the half that legitimately differs.
 *
 * The prologue is layout-identical across every arm, so a void* + size is
 * enough and no arm-specific type has to be named here.  streamid[0] stays 0:
 * callers that need a two-byte tag write it themselves after this call.
 */
static inline void
xrd_creq_begin(void *req, size_t reqsz, uint8_t stream_slot, uint16_t requestid)
{
    uint8_t *p = (uint8_t *) req;

    memset(req, 0, reqsz);
    p[1] = stream_slot;
    xrd_put_u16_be(p + 2, requestid);
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

/*
 * kXR_redirect body = [int32 BE port][host bytes, may end in NUL/CR/LF]. The
 * host field may carry a "?<opaque>" tail: a redirector (notably EOS/cmsd)
 * appends the open CAPABILITY (cap.sym/cap.msg) that the open MUST replay to the
 * chosen data server, else the DS cannot authorize it and bounces the open back
 * (an endless manager<->DS redirect loop). The host and opaque are split into
 * their own bounded, NUL-terminated buffers so a long capability opaque (often
 * >256 B) never truncates the connectable host. Leading '&'/'?' on the opaque
 * are dropped (EOS sends "?&cap.sym="). `opaque` may be NULL (opaque_sz 0) when
 * the caller does not replay capabilities. Returns 0 on success, -1 when the
 * body is too short to hold the port or host/port out-params are missing. An
 * EMPTY decoded host is left to the caller to judge. Shared by the native
 * client's redirect follower and the destination's TPC multihop pull (F7).
 */
/* Host-field length: up to the first NUL, CR or LF, else the whole body. */
static inline size_t
xrd_redirect_field_len(const char *field, size_t flen)
{
    const char *end = memchr(field, '\0', flen);

    if (end == NULL) { end = memchr(field, '\r', flen); }
    if (end == NULL) { end = memchr(field, '\n', flen); }
    return (end != NULL) ? (size_t) (end - field) : flen;
}

/* Copy at most dst_sz-1 bytes of src into dst, always NUL-terminating. */
static inline void
xrd_copy_clipped(char *dst, size_t dst_sz, const char *src, size_t len)
{
    if (len >= dst_sz) {
        len = dst_sz - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* The capability opaque after '?', with the leading '&'/'?' padding some
 * redirectors emit ("?&cap.sym=") dropped before it is clipped in. */
static inline void
xrd_redirect_opaque_copy(char *opaque, size_t opaque_sz, const char *o,
                         size_t olen)
{
    while (olen > 0 && (*o == '&' || *o == '?')) {
        o++;
        olen--;
    }
    xrd_copy_clipped(opaque, opaque_sz, o, olen);
}

static inline int
xrd_redirect_body_decode(const uint8_t *body, uint32_t dlen, char *host,
                         size_t host_sz, int *port, char *opaque,
                         size_t opaque_sz)
{
    const char *field, *qmark;
    size_t      flen, hlen;

    if (body == NULL || dlen < 5 || host == NULL || host_sz == 0
        || port == NULL)
    {
        return -1;
    }
    *port = (int) xrd_get_u32_be(body);

    field = (const char *) body + 4;
    flen  = xrd_redirect_field_len(field, (size_t) dlen - 4);
    qmark = memchr(field, '?', flen);
    hlen  = (qmark != NULL) ? (size_t) (qmark - field) : flen;
    xrd_copy_clipped(host, host_sz, field, hlen);

    if (opaque != NULL && opaque_sz > 0) {
        opaque[0] = '\0';
        if (qmark != NULL) {
            xrd_redirect_opaque_copy(opaque, opaque_sz, qmark + 1,
                                     (size_t) (field + flen - (qmark + 1)));
        }
    }
    return 0;
}

#endif /* BRIX_PROTOCOL_FRAME_HDR_H */
