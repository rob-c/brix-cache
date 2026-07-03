#ifndef BRIX_TAP_TAP_H
#define BRIX_TAP_TAP_H

/*
 * tap.h — protocol observation tap (decoder + sink fan-out).
 *
 * WHAT: turns raw XRootD wire bytes into a decoded frame descriptor and fans each
 *   frame out to registered sinks (audit / metrics / capture / inspection). Fed by
 *   both proxy modes: the terminating proxy (full plaintext) and the transparent
 *   relay (whatever travels in cleartext).
 * WHY:  one decoder + one fan-out, shared, instead of per-consumer frame parsing.
 * HOW:  pure C — no nginx, no allocation, no OpenSSL — so it embeds in any consumer
 *   and unit-tests standalone. Reuses src/protocol/frame_hdr.h + opcodes.h.
 */

#include <stddef.h>
#include <stdint.h>

typedef enum {
    BRIX_TAP_C2U = 0,   /* client → upstream (request side) */
    BRIX_TAP_U2C = 1    /* upstream → client (response side) */
} brix_tap_dir_t;

typedef struct {
    uint16_t       streamid;
    int            is_request;  /* 1 = request frame, 0 = response frame */
    uint16_t       opcode;      /* request: kXR_* requestid; 0 on a response */
    uint16_t       status;      /* response: kXR_* status; 0 on a request */
    uint32_t       errnum;      /* kXR_error response with payload seen: the
                                 * BE errnum (kXR_NotFound, …); else 0 */
    uint32_t       dlen;        /* payload length declared by the header */
    const uint8_t *path;        /* path-bearing request w/ payload present; else NULL */
    size_t         path_len;
} brix_tap_frame_t;

/* Decode the fixed header of a request (24B) / response (8B) frame from buf[0..len).
 * Returns the header byte count consumed (24 / 8) with *out filled, or 0 if len is
 * too short for the fixed header. The payload need not be fully present; `path` is
 * set only for a path-bearing opcode whose payload bytes are available in buf. */
size_t brix_tap_decode_request(const uint8_t *buf, size_t len,
    brix_tap_frame_t *out);
size_t brix_tap_decode_response(const uint8_t *buf, size_t len,
    brix_tap_frame_t *out);

/* True for request opcodes whose data payload is (or begins with) a path —
 * usable before the payload has arrived (the streaming decoder needs this on the
 * header alone). */
int brix_tap_opcode_has_path(uint16_t op);

/* ---- sink fan-out (tap_emit.c) ---- */

typedef void (*brix_tap_sink_fn)(void *ctx, const brix_tap_frame_t *f,
    brix_tap_dir_t dir, const uint8_t *payload, size_t payload_len);

#define BRIX_TAP_MAX_SINKS 8

typedef struct {
    struct { brix_tap_sink_fn fn; void *ctx; } sinks[BRIX_TAP_MAX_SINKS];
    int n;
} brix_tap_ctx_t;

void brix_tap_register_sink(brix_tap_ctx_t *t, brix_tap_sink_fn fn,
    void *ctx);
void brix_tap_emit(brix_tap_ctx_t *t, const brix_tap_frame_t *f,
    brix_tap_dir_t dir, const uint8_t *payload, size_t payload_len);

/* ---- audit JSON formatter (tap_audit.c) ---- */

/* Format one frame as a single-line JSON object into out[0..outsz). Returns bytes
 * written (excluding the NUL), or 0 if it would not fit. Pure — no I/O. */
size_t brix_tap_audit_format(const brix_tap_frame_t *f, brix_tap_dir_t dir,
    char *out, size_t outsz);

/* ---- streaming decoder (tap_stream.c) ----
 * Feeds the byte-relay: one per direction. Reassembles frame headers across
 * arbitrary chunk boundaries, captures the path for path-bearing requests (up to
 * BRIX_TAP_PATH_CAP bytes), and emits each frame to `tap`. Non-path frames
 * (and all responses) emit as soon as the header is complete; the payload is
 * skipped, never buffered whole. */
#define BRIX_TAP_PATH_CAP 1024

/* The client opens with a fixed 20-byte ClientInitHandShake before any request
 * framing (coalesced with the first kXR_protocol in v5); the C2U decoder skips it
 * so request framing stays aligned. The server's reply is a standard-format
 * response, so the U2C decoder needs no preamble skip. */
#define BRIX_TAP_C2U_PREAMBLE 20

typedef struct {
    brix_tap_ctx_t  *tap;
    brix_tap_dir_t   dir;
    size_t             preamble_skip;           /* handshake bytes still to skip */
    size_t             hdr_need;                 /* 24 (C2U) or 8 (U2C) */
    uint8_t            hdr[24];
    size_t             hdr_got;
    int                in_payload;               /* 0 = filling header */
    uint64_t           payload_left;
    brix_tap_frame_t cur;                      /* decoded-from-header frame */
    uint8_t            pathbuf[BRIX_TAP_PATH_CAP];
    size_t             path_cap;                 /* bytes still to capture */
    size_t             path_got;
    int                emitted;                  /* cur already emitted? */

    /* kXR_writev trailing data (stock framing: dlen frames only the 16-byte
     * write_list descriptors; sum(wlen) data bytes stream after the frame).
     * While the descriptor payload passes through, each descriptor's wlen is
     * accumulated so the trailing bytes can be consumed without buffering. */
    int                wv_active;                /* summing writev descriptors */
    uint8_t            wv_desc[16];              /* current descriptor bytes */
    size_t             wv_desc_got;
    uint64_t           wv_extra;                 /* sum(wlen) so far */

    /* kXR_chkpoint/ckpXeq trailing sub-body (stock framing: the frame's dlen
     * covers only the embedded 24-byte sub-request header; the sub-request
     * body streams after it — write/pgwrite data, or writev descriptors then
     * data, the latter consumed via the wv_* machinery above).  The embedded
     * header is captured as it passes so the trailing byte count can be
     * recovered, keeping the stream aligned on the next frame. */
    int                ckp_active;               /* capturing embedded header */
    uint8_t            ckp_hdr[24];
    size_t             ckp_hdr_got;
} brix_tap_stream_t;

void brix_tap_stream_init(brix_tap_stream_t *st, brix_tap_ctx_t *tap,
    brix_tap_dir_t dir);
void brix_tap_stream_feed(brix_tap_stream_t *st, const uint8_t *buf,
    size_t len);

#endif /* BRIX_TAP_TAP_H */
