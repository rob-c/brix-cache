/*
 * kat_carved_parsers.c — deterministic known-answer tests for the pure parser
 * functions carved out for the hyper-hardening C-1/C-2 fuzz targets.
 *
 * WHAT: exercises each carved (data,len) entry point with success, error, and
 *       security-negative inputs — the "3 tests per change" the coding standard
 *       requires — as a fast, deterministic complement to the libFuzzer smoke
 *       (which proves *no* input crashes, but asserts no specific verdict).
 * WHY:  the fuzzers guarantee memory-safety; these KATs pin the *behaviour*:
 *       that the per-opcode dlen cap actually rejects an over-cap frame (C-2),
 *       that SSS/macaroon/GSI framing accepts a well-formed frame and rejects a
 *       malformed or over-long one. A regression that made a check vacuous would
 *       pass the fuzzer but fail here.
 * HOW:  links the same pure TUs the harnesses link; returns the number of failed
 *       assertions (0 = all pass). Driven by tests/test_fuzz_carved_parsers.py.
 */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "protocols/root/connection/recv_frame_bounds.h"
#include "protocols/root/protocol/opcodes.h"
#include "core/types/tunables.h"
#include "auth/sss/sss_framing.h"
#include "protocols/root/protocol/sss.h"
#include "auth/token/macaroon_frame.h"
#include "auth/gsi/gsi_core.h"

static int failures;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);\
            failures++;                                                      \
        }                                                                    \
    } while (0)

/* Build a 24-byte ClientRequestHdr with requestid @2 (BE16) and dlen @20 (BE32). */
static void
make_hdr(unsigned char hdr[24], uint16_t reqid, uint32_t dlen)
{
    memset(hdr, 0, 24);
    hdr[2] = (unsigned char) (reqid >> 8);
    hdr[3] = (unsigned char) (reqid & 0xff);
    hdr[20] = (unsigned char) (dlen >> 24);
    hdr[21] = (unsigned char) (dlen >> 16);
    hdr[22] = (unsigned char) (dlen >> 8);
    hdr[23] = (unsigned char) (dlen & 0xff);
}

/* ---- C-2: root:// request-framing dlen cap ------------------------------- */
static void
test_root_frame(void)
{
    unsigned char hdr[24];
    uint16_t      reqid = 0;
    uint32_t      dlen = 0;

    /* cap table is single-source with recv_process.c */
    CHECK(brix_max_payload_for_request(kXR_write) == BRIX_MAX_WRITE_STREAM,
          "write cap");
    CHECK(brix_max_payload_for_request(kXR_pgwrite) == BRIX_MAX_WRITE_PAYLOAD,
          "pgwrite cap");
    CHECK(brix_max_payload_for_request(kXR_ping) == BRIX_MAX_PATH + 64,
          "default cap");

    /* success: a zero-length ping is within cap */
    make_hdr(hdr, kXR_ping, 0);
    CHECK(brix_root_frame_dlen_ok(hdr, 24, &reqid, &dlen) == 1, "ping accept");
    CHECK(reqid == kXR_ping && dlen == 0, "ping decode");

    /* boundary success: dlen exactly at the write cap */
    make_hdr(hdr, kXR_write, BRIX_MAX_WRITE_STREAM);
    CHECK(brix_root_frame_dlen_ok(hdr, 24, NULL, NULL) == 1, "write at-cap accept");

    /* security-neg: one byte over the write cap must be rejected BEFORE alloc */
    make_hdr(hdr, kXR_write, BRIX_MAX_WRITE_STREAM + 1);
    CHECK(brix_root_frame_dlen_ok(hdr, 24, NULL, NULL) == 0, "write over-cap reject");

    /* error: a short (<24-byte) frame is rejected without reading the tail */
    make_hdr(hdr, kXR_write, 0);
    CHECK(brix_root_frame_dlen_ok(hdr, 23, NULL, NULL) == 0, "short-header reject");
    CHECK(brix_root_frame_dlen_ok(NULL, 24, NULL, NULL) == 0, "null reject");
}

/* ---- C-1 target 3: SSS outer-header framing ------------------------------ */
static void
test_sss_frame(void)
{
    size_t        hdr_len = 0;
    unsigned char buf[64];
    const size_t  minlen = BRIX_SSS_HDR_LEN + BRIX_SSS_DATA_HDR_LEN + 4; /* 60 */

    memset(buf, 0, sizeof(buf));
    buf[0] = 's'; buf[1] = 's'; buf[2] = 's'; buf[3] = '\0';
    buf[6] = 0;                       /* kn_size == 0: no trailing-NUL check */
    buf[7] = BRIX_SSS_ENC_BF32;

    /* success: magic + BF32 marker + zero key-name, full-length datagram */
    CHECK(brix_sss_header_framing_ok(buf, sizeof(buf), &hdr_len) == 1, "sss accept");
    CHECK(hdr_len == BRIX_SSS_HDR_LEN, "sss hdr_len");

    /* security-neg: corrupt magic */
    buf[0] = 'x';
    CHECK(brix_sss_header_framing_ok(buf, sizeof(buf), &hdr_len) == 0, "sss bad-magic reject");
    buf[0] = 's';

    /* security-neg: misaligned / over-long key-name size */
    buf[6] = 3;   /* not a multiple of 8 */
    CHECK(brix_sss_header_framing_ok(buf, sizeof(buf), &hdr_len) == 0, "sss misaligned kn reject");
    buf[6] = (unsigned char) (BRIX_SSS_NAME_MAX + 8); /* > name max, still 8-aligned */
    CHECK(brix_sss_header_framing_ok(buf, sizeof(buf), &hdr_len) == 0, "sss oversized kn reject");
    buf[6] = 0;

    /* error: datagram shorter than the fixed minimum */
    CHECK(brix_sss_header_framing_ok(buf, minlen - 1, &hdr_len) == 0, "sss short reject");
}

/* ---- C-1 target 4: macaroon length-prefixed packet framing --------------- */
static void
test_macaroon_frame(void)
{
    /* length decoder: 4 hex chars -> value, -1 on non-hex */
    CHECK(brix_macaroon_packet_len((const unsigned char *) "000a") == 0x0a, "mac len hex");
    CHECK(brix_macaroon_packet_len((const unsigned char *) "00zz") == -1, "mac len bad-hex");

    /* success: two minimal 4-byte (header-only) packets -> count 2 */
    CHECK(brix_macaroon_scan_frames((const unsigned char *) "00040004", 8) == 2,
          "mac two-frame count");

    /* success: a packet with a body */
    CHECK(brix_macaroon_scan_frames((const unsigned char *) "0006AB", 6) == 1,
          "mac body count");

    /* security-neg: length prefix claims more bytes than remain */
    CHECK(brix_macaroon_scan_frames((const unsigned char *) "0009", 4) == -1,
          "mac over-length reject");

    /* error: non-hex length prefix */
    CHECK(brix_macaroon_scan_frames((const unsigned char *) "00zz", 4) == -1,
          "mac bad-hex reject");
}

/* ---- C-1 target 1: GSI XrdSecBuffer bucket walk -------------------------- */
static void
test_gsi_bucket(void)
{
    brix_gbuf      g;
    const uint8_t *out = NULL;
    size_t         outlen = 0;

    brix_gbuf_init(&g);
    brix_gbuf_start(&g, 0);
    brix_gbuf_bucket(&g, 5, "hello", 5);
    brix_gbuf_end(&g);
    CHECK(g.err == 0, "gsi build");

    /* success: locate the bucket we wrote */
    CHECK(brix_gsi_find_bucket(g.p, g.len, 5, &out, &outlen) == 0, "gsi find");
    CHECK(outlen == 5 && out != NULL && memcmp(out, "hello", 5) == 0, "gsi payload");

    /* error: a type that is not present */
    CHECK(brix_gsi_find_bucket(g.p, g.len, 99, &out, &outlen) == -1, "gsi absent");

    /* security-neg: truncate the buffer INTO the 5-byte bucket body (drop the
     * 4-byte kXRS_none terminator + 4 body bytes); the bucket length field now
     * over-runs the shortened end and must be rejected, not read past. */
    CHECK(brix_gsi_find_bucket(g.p, g.len - 8, 5, &out, &outlen) == -1,
          "gsi truncated reject");

    brix_gbuf_free(&g);
}

int
main(void)
{
    test_root_frame();
    test_sss_frame();
    test_macaroon_frame();
    test_gsi_bucket();

    if (failures == 0) {
        printf("kat_carved_parsers: all checks passed\n");
    } else {
        printf("kat_carved_parsers: %d check(s) FAILED\n", failures);
    }
    return failures;
}
