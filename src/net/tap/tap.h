#ifndef XROOTD_TAP_TAP_H
#define XROOTD_TAP_TAP_H

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
    XROOTD_TAP_C2U = 0,   /* client → upstream (request side) */
    XROOTD_TAP_U2C = 1    /* upstream → client (response side) */
} xrootd_tap_dir_t;

typedef struct {
    uint16_t       streamid;
    int            is_request;  /* 1 = request frame, 0 = response frame */
    uint16_t       opcode;      /* request: kXR_* requestid; 0 on a response */
    uint16_t       status;      /* response: kXR_* status; 0 on a request */
    uint32_t       dlen;        /* payload length declared by the header */
    const uint8_t *path;        /* path-bearing request w/ payload present; else NULL */
    size_t         path_len;
} xrootd_tap_frame_t;

/* Decode the fixed header of a request (24B) / response (8B) frame from buf[0..len).
 * Returns the header byte count consumed (24 / 8) with *out filled, or 0 if len is
 * too short for the fixed header. The payload need not be fully present; `path` is
 * set only for a path-bearing opcode whose payload bytes are available in buf. */
size_t xrootd_tap_decode_request(const uint8_t *buf, size_t len,
    xrootd_tap_frame_t *out);
size_t xrootd_tap_decode_response(const uint8_t *buf, size_t len,
    xrootd_tap_frame_t *out);

/* True for request opcodes whose data payload is (or begins with) a path —
 * usable before the payload has arrived (the streaming decoder needs this on the
 * header alone). */
int xrootd_tap_opcode_has_path(uint16_t op);

/* ---- sink fan-out (tap_emit.c) ---- */

typedef void (*xrootd_tap_sink_fn)(void *ctx, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len);

#define XROOTD_TAP_MAX_SINKS 8

typedef struct {
    struct { xrootd_tap_sink_fn fn; void *ctx; } sinks[XROOTD_TAP_MAX_SINKS];
    int n;
} xrootd_tap_ctx_t;

void xrootd_tap_register_sink(xrootd_tap_ctx_t *t, xrootd_tap_sink_fn fn,
    void *ctx);
void xrootd_tap_emit(xrootd_tap_ctx_t *t, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len);

/* ---- audit JSON formatter (tap_audit.c) ---- */

/* Format one frame as a single-line JSON object into out[0..outsz). Returns bytes
 * written (excluding the NUL), or 0 if it would not fit. Pure — no I/O. */
size_t xrootd_tap_audit_format(const xrootd_tap_frame_t *f, xrootd_tap_dir_t dir,
    char *out, size_t outsz);

/* ---- streaming decoder (tap_stream.c) ----
 * Feeds the byte-relay: one per direction. Reassembles frame headers across
 * arbitrary chunk boundaries, captures the path for path-bearing requests (up to
 * XROOTD_TAP_PATH_CAP bytes), and emits each frame to `tap`. Non-path frames
 * (and all responses) emit as soon as the header is complete; the payload is
 * skipped, never buffered whole. */
#define XROOTD_TAP_PATH_CAP 1024

/* The client opens with a fixed 20-byte ClientInitHandShake before any request
 * framing (coalesced with the first kXR_protocol in v5); the C2U decoder skips it
 * so request framing stays aligned. The server's reply is a standard-format
 * response, so the U2C decoder needs no preamble skip. */
#define XROOTD_TAP_C2U_PREAMBLE 20

typedef struct {
    xrootd_tap_ctx_t  *tap;
    xrootd_tap_dir_t   dir;
    size_t             preamble_skip;           /* handshake bytes still to skip */
    size_t             hdr_need;                 /* 24 (C2U) or 8 (U2C) */
    uint8_t            hdr[24];
    size_t             hdr_got;
    int                in_payload;               /* 0 = filling header */
    uint64_t           payload_left;
    xrootd_tap_frame_t cur;                      /* decoded-from-header frame */
    uint8_t            pathbuf[XROOTD_TAP_PATH_CAP];
    size_t             path_cap;                 /* bytes still to capture */
    size_t             path_got;
    int                emitted;                  /* cur already emitted? */
} xrootd_tap_stream_t;

void xrootd_tap_stream_init(xrootd_tap_stream_t *st, xrootd_tap_ctx_t *tap,
    xrootd_tap_dir_t dir);
void xrootd_tap_stream_feed(xrootd_tap_stream_t *st, const uint8_t *buf,
    size_t len);

#endif /* XROOTD_TAP_TAP_H */
