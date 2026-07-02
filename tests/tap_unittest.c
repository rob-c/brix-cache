/* Standalone unit test for the tap core — gcc, no nginx. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "../src/protocols/root/protocol/opcodes.h"
#include "../src/net/tap/tap.h"

/* Build a request frame: streamid + requestid(BE) + 16B body + dlen(BE) + payload */
static size_t
mk_request(uint8_t *buf, uint16_t sid, uint16_t op, const char *payload)
{
    uint32_t dlen = payload ? (uint32_t) strlen(payload) : 0;
    uint16_t sid_be = htons(sid), op_be = htons(op);
    uint32_t dlen_be = htonl(dlen);
    memcpy(buf, &sid_be, 2);
    memcpy(buf + 2, &op_be, 2);
    memset(buf + 4, 0, 16);
    memcpy(buf + 20, &dlen_be, 4);
    if (dlen) { memcpy(buf + 24, payload, dlen); }
    return 24 + dlen;
}

static size_t
mk_response(uint8_t *buf, uint16_t sid, uint16_t status, uint32_t dlen)
{
    uint16_t sid_be = htons(sid), st_be = htons(status);
    uint32_t dlen_be = htonl(dlen);
    memcpy(buf, &sid_be, 2);
    memcpy(buf + 2, &st_be, 2);
    memcpy(buf + 4, &dlen_be, 4);
    return 8;
}

static void test_decode_request(void)
{
    uint8_t buf[256];
    size_t total = mk_request(buf, 0x0102, kXR_open, "/foo/bar");
    xrootd_tap_frame_t f;
    size_t hdr = xrootd_tap_decode_request(buf, total, &f);
    assert(hdr == 24);
    assert(f.is_request == 1);
    assert(f.streamid == 0x0102);
    assert(f.opcode == kXR_open);
    assert(f.dlen == 8);
    assert(f.path_len == 8 && memcmp(f.path, "/foo/bar", 8) == 0);
}

static void test_decode_request_no_path(void)
{
    uint8_t buf[64];
    /* kXR_ping carries no path even with a payload */
    size_t total = mk_request(buf, 7, kXR_ping, NULL);
    xrootd_tap_frame_t f;
    size_t hdr = xrootd_tap_decode_request(buf, total, &f);
    assert(hdr == 24);
    assert(f.opcode == kXR_ping);
    assert(f.path == NULL && f.path_len == 0);
}

static void test_decode_response(void)
{
    uint8_t buf[16];
    mk_response(buf, 0x0102, kXR_ok, 0);
    xrootd_tap_frame_t f;
    size_t hdr = xrootd_tap_decode_response(buf, 8, &f);
    assert(hdr == 8);
    assert(f.is_request == 0);
    assert(f.streamid == 0x0102);
    assert(f.status == kXR_ok);
    assert(f.dlen == 0);
}

static void test_decode_response_errnum(void)
{
    /* kXR_error with body = errnum[4 BE] + errmsg */
    uint8_t buf[64];
    uint32_t errnum_be = htonl(3011);          /* kXR_NotFound */
    mk_response(buf, 3, kXR_error, 4 + 5);
    memcpy(buf + 8, &errnum_be, 4);
    memcpy(buf + 12, "gone", 5);
    xrootd_tap_frame_t f;
    assert(xrootd_tap_decode_response(buf, 17, &f) == 8);
    assert(f.status == kXR_error);
    assert(f.errnum == 3011);

    /* header-only view: errnum unknown -> 0 */
    assert(xrootd_tap_decode_response(buf, 8, &f) == 8);
    assert(f.errnum == 0);
}

static void test_truncated(void)
{
    uint8_t buf[4] = {0};
    xrootd_tap_frame_t f;
    assert(xrootd_tap_decode_request(buf, 4, &f) == 0);   /* < 24 */
    assert(xrootd_tap_decode_response(buf, 4, &f) == 0);  /* < 8  */
}

struct count_ctx { int n; uint16_t last_op; };
static void count_sink(void *ctx, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len)
{
    struct count_ctx *c = ctx;
    (void) dir; (void) payload; (void) payload_len;
    c->n++;
    c->last_op = f->opcode;
}

static void test_emit_fanout(void)
{
    xrootd_tap_ctx_t tap; memset(&tap, 0, sizeof(tap));
    struct count_ctx a = {0, 0}, b = {0, 0};
    xrootd_tap_register_sink(&tap, count_sink, &a);
    xrootd_tap_register_sink(&tap, count_sink, &b);

    xrootd_tap_frame_t f; memset(&f, 0, sizeof(f));
    f.is_request = 1; f.opcode = kXR_open;
    xrootd_tap_emit(&tap, &f, XROOTD_TAP_C2U, NULL, 0);
    xrootd_tap_emit(&tap, &f, XROOTD_TAP_C2U, NULL, 0);

    assert(a.n == 2 && b.n == 2);
    assert(a.last_op == kXR_open && b.last_op == kXR_open);
}

static void test_audit_format(void)
{
    uint8_t buf[256];
    size_t total = mk_request(buf, 5, kXR_open, "/a/\"b\"");  /* quote → must escape */
    xrootd_tap_frame_t f;
    xrootd_tap_decode_request(buf, total, &f);

    char out[512];
    size_t n = xrootd_tap_audit_format(&f, XROOTD_TAP_C2U, out, sizeof(out));
    assert(n > 0);
    assert(strstr(out, "\"dir\":\"c2u\"") != NULL);
    assert(strstr(out, "\"op\":\"open\"") != NULL);
    assert(strstr(out, "\"streamid\":5") != NULL);
    assert(strstr(out, "\"path\":\"/a/\\\"b\\\"\"") != NULL);  /* escaped quotes */

    /* truncation: a tiny buffer returns 0, never overflows */
    char tiny[8];
    assert(xrootd_tap_audit_format(&f, XROOTD_TAP_C2U, tiny, sizeof(tiny)) == 0);
}

/* records every frame the stream decoder emits */
struct rec_ctx { int n; uint16_t op[16]; uint32_t errnum[16]; char path[16][64]; };
static void rec_sink(void *ctx, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len)
{
    struct rec_ctx *r = ctx;
    (void) dir; (void) payload; (void) payload_len;
    if (r->n >= 16) { return; }
    r->op[r->n] = f->is_request ? f->opcode : f->status;
    r->errnum[r->n] = f->errnum;
    r->path[r->n][0] = '\0';
    if (f->path && f->path_len < 64) {
        memcpy(r->path[r->n], f->path, f->path_len);
        r->path[r->n][f->path_len] = '\0';
    }
    r->n++;
}

static void test_stream_chunked(void)
{
    /* 20-byte handshake, then two requests back-to-back, fed one byte at a time */
    uint8_t a[256], b[256];
    size_t na = mk_request(a, 1, kXR_open, "/x");
    size_t nb = mk_request(b, 2, kXR_stat, "/y/z");
    uint8_t wire[512];
    memset(wire, 0, 20);                                  /* handshake */
    memcpy(wire + 20, a, na); memcpy(wire + 20 + na, b, nb);
    size_t total = 20 + na + nb;

    xrootd_tap_ctx_t tap; memset(&tap, 0, sizeof(tap));
    struct rec_ctx r; memset(&r, 0, sizeof(r));
    xrootd_tap_register_sink(&tap, rec_sink, &r);

    xrootd_tap_stream_t st;
    xrootd_tap_stream_init(&st, &tap, XROOTD_TAP_C2U);
    for (size_t i = 0; i < total; i++) {
        xrootd_tap_stream_feed(&st, wire + i, 1);   /* 1-byte chunks */
    }
    assert(r.n == 2);
    assert(r.op[0] == kXR_open && strcmp(r.path[0], "/x") == 0);
    assert(r.op[1] == kXR_stat && strcmp(r.path[1], "/y/z") == 0);
}

static void test_stream_response_and_skip(void)
{
    /* 20B handshake, then a write request (no path, big payload to skip) */
    uint8_t buf[620]; memset(buf, 0, sizeof(buf));
    uint16_t sid = htons(9), op = htons(kXR_write);
    uint32_t dlen = htonl(500);
    memcpy(buf + 20, &sid, 2); memcpy(buf + 22, &op, 2);
    memcpy(buf + 40, &dlen, 4);           /* 20B handshake + 24B hdr + 500B payload */
    size_t reqlen = 20 + 24 + 500;
    uint8_t resp[8];
    mk_response(resp, 9, kXR_ok, 0);

    xrootd_tap_ctx_t tap; memset(&tap, 0, sizeof(tap));
    struct rec_ctx rq; memset(&rq, 0, sizeof(rq));
    struct rec_ctx rs; memset(&rs, 0, sizeof(rs));
    xrootd_tap_register_sink(&tap, rec_sink, &rq);
    xrootd_tap_stream_t cu; xrootd_tap_stream_init(&cu, &tap, XROOTD_TAP_C2U);
    xrootd_tap_stream_feed(&cu, buf, reqlen);
    assert(rq.n == 1 && rq.op[0] == kXR_write);   /* emitted on header, payload skipped */

    memset(&tap, 0, sizeof(tap));
    xrootd_tap_register_sink(&tap, rec_sink, &rs);
    xrootd_tap_stream_t uc; xrootd_tap_stream_init(&uc, &tap, XROOTD_TAP_U2C);
    xrootd_tap_stream_feed(&uc, resp, 8);
    assert(rs.n == 1 && rs.op[0] == kXR_ok);
}

static void test_stream_writev_trailing_data(void)
{
    /* kXR_writev stock framing: dlen frames only the 16-byte descriptors; the
     * segment data (sum(wlen) bytes) streams after the frame.  The decoder
     * must consume that trailing data or it would misparse it as the next
     * header.  Frame: writev with 2 descriptors (wlen 5 + 7 = 12 data bytes),
     * then a kXR_stat request — fed one byte at a time. */
    uint8_t wire[512]; memset(wire, 0, 20);              /* handshake */
    size_t  off = 20;

    uint16_t sid = htons(4), op = htons(3031 /* kXR_writev */);
    uint32_t dlen = htonl(32);                           /* 2 descriptors */
    memcpy(wire + off, &sid, 2); memcpy(wire + off + 2, &op, 2);
    memcpy(wire + off + 20, &dlen, 4);
    off += 24;
    uint32_t w1 = htonl(5), w2 = htonl(7);
    memset(wire + off, 0, 32);                           /* fhandle+offset zero */
    memcpy(wire + off + 4, &w1, 4);                      /* desc[0].wlen = 5 */
    memcpy(wire + off + 16 + 4, &w2, 4);                 /* desc[1].wlen = 7 */
    off += 32;
    memset(wire + off, 'D', 12);                         /* trailing segment data */
    off += 12;

    uint8_t req[256];
    size_t nreq = mk_request(req, 5, kXR_stat, "/after");
    memcpy(wire + off, req, nreq);
    size_t total = off + nreq;

    xrootd_tap_ctx_t tap; memset(&tap, 0, sizeof(tap));
    struct rec_ctx r; memset(&r, 0, sizeof(r));
    xrootd_tap_register_sink(&tap, rec_sink, &r);
    xrootd_tap_stream_t st;
    xrootd_tap_stream_init(&st, &tap, XROOTD_TAP_C2U);
    for (size_t i = 0; i < total; i++) {
        xrootd_tap_stream_feed(&st, wire + i, 1);        /* 1-byte chunks */
    }

    assert(r.n == 2);
    assert(r.op[0] == 3031);
    assert(r.op[1] == kXR_stat && strcmp(r.path[1], "/after") == 0);
}

static void test_stream_c2u_handshake_skip(void)
{
    /* C2U opens with a 20-byte handshake, then a real kXR_open request */
    uint8_t wire[300]; memset(wire, 0, 20);   /* 20-byte handshake (zeros ok) */
    uint8_t req[256];
    size_t nreq = mk_request(req, 3, kXR_open, "/p/q");
    memcpy(wire + 20, req, nreq);
    size_t total = 20 + nreq;

    xrootd_tap_ctx_t tap; memset(&tap, 0, sizeof(tap));
    struct rec_ctx r; memset(&r, 0, sizeof(r));
    xrootd_tap_register_sink(&tap, rec_sink, &r);
    xrootd_tap_stream_t st;
    xrootd_tap_stream_init(&st, &tap, XROOTD_TAP_C2U);
    xrootd_tap_stream_feed(&st, wire, total);

    assert(r.n == 1);
    assert(r.op[0] == kXR_open && strcmp(r.path[0], "/p/q") == 0);
}

static void test_stream_error_errnum(void)
{
    /* U2C: kXR_ok, then kXR_error(errnum + msg), fed one byte at a time */
    uint8_t wire[64];
    size_t  off = mk_response(wire, 1, kXR_ok, 0);
    uint32_t errnum_be = htonl(3010);          /* kXR_NotAuthorized */
    off += mk_response(wire + off, 2, kXR_error, 4 + 3);
    memcpy(wire + off, &errnum_be, 4); off += 4;
    memcpy(wire + off, "no", 3); off += 3;

    xrootd_tap_ctx_t tap; memset(&tap, 0, sizeof(tap));
    struct rec_ctx r; memset(&r, 0, sizeof(r));
    xrootd_tap_register_sink(&tap, rec_sink, &r);
    xrootd_tap_stream_t uc; xrootd_tap_stream_init(&uc, &tap, XROOTD_TAP_U2C);
    for (size_t i = 0; i < off; i++) {
        xrootd_tap_stream_feed(&uc, wire + i, 1);
    }
    assert(r.n == 2);
    assert(r.op[0] == kXR_ok && r.errnum[0] == 0);
    assert(r.op[1] == kXR_error && r.errnum[1] == 3010);
}

int main(void)
{
    test_decode_request();
    test_decode_request_no_path();
    test_decode_response();
    test_decode_response_errnum();
    test_stream_error_errnum();
    test_truncated();
    test_emit_fanout();
    test_audit_format();
    test_stream_chunked();
    test_stream_response_and_skip();
    test_stream_writev_trailing_data();
    test_stream_c2u_handshake_skip();
    printf("tap_unittest: all checks passed\n");
    return 0;
}
