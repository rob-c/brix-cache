/*
 * wire_codec_unittest.c — standalone unit test for the xrdwire codec.
 *
 * Built and run OUTSIDE the nginx tree (plain gcc), so it verifies the pure
 * pack/unpack contract without the module or client build. Two kinds of check
 * per opcode:
 *   1. round-trip: populate → pack → unpack → assert field equality;
 *   2. golden offsets: assert specific bytes land at the wire-spec offsets (the
 *      contract both sides depend on).
 *
 * Usage:
 *   cd src/protocol/codec
 *   gcc -O2 -Wall -Wextra -Werror -o /tmp/wire_codec_unittest \
 *       wire_codec_meta.c wire_codec_unittest.c
 *   /tmp/wire_codec_unittest
 */
#include "wire_codec.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

#define CHECK(cond, msg) do {                                           \
    if (cond) { printf("ok: %s\n", msg); }                             \
    else      { printf("FAIL: %s\n", msg); g_fail = 1; }              \
} while (0)

/* ---- kXR_stat ---------------------------------------------------------- */
static void test_stat(void)
{
    xrdw_stat_req_t in = { .options = 1, .wants = 0x01020304,
                           .fhandle = { 9, 8, 7, 6 } };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_stat_req_t out;

    CHECK(xrdw_stat_req_pack(&in, body) == XRDW_BODY_LEN, "stat pack returns 16");
    /* golden offsets: options@0, wants@8 (BE), fhandle@12 */
    CHECK(body[0] == 1, "stat options @0");
    CHECK(body[8] == 0x01 && body[9] == 0x02 && body[10] == 0x03 && body[11] == 0x04,
          "stat wants @8 big-endian");
    CHECK(body[12] == 9 && body[15] == 6, "stat fhandle @12");
    CHECK(xrdw_stat_req_unpack(body, &out) == XRDW_OK, "stat unpack ok");
    CHECK(out.options == in.options && out.wants == in.wants
          && memcmp(out.fhandle, in.fhandle, 4) == 0, "stat round-trip identity");
}

/* ---- kXR_statx --------------------------------------------------------- */
static void test_statx(void)
{
    xrdw_statx_req_t in = { .options = 1, .fhandle = { 4, 3, 2, 1 } };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_statx_req_t out;

    CHECK(xrdw_statx_req_pack(&in, body) == XRDW_BODY_LEN, "statx pack returns 16");
    CHECK(body[0] == 1, "statx options @0");
    CHECK(body[12] == 4 && body[15] == 1, "statx fhandle @12");
    CHECK(xrdw_statx_req_unpack(body, &out) == XRDW_OK, "statx unpack ok");
    CHECK(out.options == in.options && memcmp(out.fhandle, in.fhandle, 4) == 0,
          "statx round-trip identity");
}

/* ---- kXR_dirlist ------------------------------------------------------- */
static void test_dirlist(void)
{
    xrdw_dirlist_req_t in = { .options = 0x05 };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_dirlist_req_t out;

    CHECK(xrdw_dirlist_req_pack(&in, body) == XRDW_BODY_LEN, "dirlist pack returns 16");
    /* dirlist options live at the LAST body byte (offset 15), a known quirk. */
    CHECK(body[15] == 0x05, "dirlist options @15");
    CHECK(body[0] == 0, "dirlist body head zeroed");
    CHECK(xrdw_dirlist_req_unpack(body, &out) == XRDW_OK, "dirlist unpack ok");
    CHECK(out.options == in.options, "dirlist round-trip identity");
}

/* ---- kXR_query --------------------------------------------------------- */
static void test_query(void)
{
    xrdw_query_req_t in = { .infotype = 0x1234, .fhandle = { 1, 2, 3, 4 } };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_query_req_t out;

    CHECK(xrdw_query_req_pack(&in, body) == XRDW_BODY_LEN, "query pack returns 16");
    CHECK(body[0] == 0x12 && body[1] == 0x34, "query infotype @0 big-endian");
    CHECK(body[4] == 1 && body[7] == 4, "query fhandle @4");
    CHECK(xrdw_query_req_unpack(body, &out) == XRDW_OK, "query unpack ok");
    CHECK(out.infotype == in.infotype && memcmp(out.fhandle, in.fhandle, 4) == 0,
          "query round-trip identity");
}

/* ---- kXR_locate -------------------------------------------------------- */
static void test_locate(void)
{
    xrdw_locate_req_t in = { .options = 0xBEEF };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_locate_req_t out;

    CHECK(xrdw_locate_req_pack(&in, body) == XRDW_BODY_LEN, "locate pack returns 16");
    CHECK(body[0] == 0xBE && body[1] == 0xEF, "locate options @0 big-endian");
    CHECK(body[2] == 0, "locate reserved zeroed");
    CHECK(xrdw_locate_req_unpack(body, &out) == XRDW_OK, "locate unpack ok");
    CHECK(out.options == in.options, "locate round-trip identity");
}

/* ---- file family ------------------------------------------------------- */
static void test_open(void)
{
    xrdw_open_req_t in = { .mode = 0x01B4, .options = 0x0010, .optiont = 0x0001,
                           .fhtemplt = { 0 } };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_open_req_t out;
    CHECK(xrdw_open_req_pack(&in, body) == XRDW_BODY_LEN, "open pack returns 16");
    CHECK(body[0] == 0x01 && body[1] == 0xB4, "open mode @0 big-endian");
    CHECK(body[2] == 0x00 && body[3] == 0x10, "open options @2 big-endian");
    CHECK(xrdw_open_req_unpack(body, &out) == XRDW_OK, "open unpack ok");
    CHECK(out.mode == in.mode && out.options == in.options
          && out.optiont == in.optiont, "open round-trip identity");
}

static void test_read(void)
{
    xrdw_read_req_t in = { .fhandle = { 1, 2, 3, 4 },
                           .offset = 0x1122334455667788LL, .rlen = 0x00ABCDEF };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_read_req_t out;
    CHECK(xrdw_read_req_pack(&in, body) == XRDW_BODY_LEN, "read pack returns 16");
    CHECK(body[0] == 1 && body[3] == 4, "read fhandle @0");
    CHECK(body[4] == 0x11 && body[11] == 0x88, "read offset @4 big-endian i64");
    CHECK(body[12] == 0x00 && body[15] == 0xEF, "read rlen @12 big-endian i32");
    CHECK(xrdw_read_req_unpack(body, &out) == XRDW_OK, "read unpack ok");
    CHECK(out.offset == in.offset && out.rlen == in.rlen
          && memcmp(out.fhandle, in.fhandle, 4) == 0, "read round-trip identity");
}

static void test_pgwrite(void)
{
    xrdw_pgwrite_req_t in = { .fhandle = { 9, 9, 9, 9 }, .offset = -1,
                              .pathid = 2, .reqflags = 1 };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_pgwrite_req_t out;
    CHECK(xrdw_pgwrite_req_pack(&in, body) == XRDW_BODY_LEN, "pgwrite pack returns 16");
    CHECK(body[12] == 2 && body[13] == 1, "pgwrite pathid@12 reqflags@13");
    CHECK(xrdw_pgwrite_req_unpack(body, &out) == XRDW_OK, "pgwrite unpack ok");
    CHECK(out.offset == in.offset && out.pathid == in.pathid
          && out.reqflags == in.reqflags, "pgwrite round-trip identity (incl -1 offset)");
}

static void test_truncate(void)
{
    xrdw_truncate_req_t in = { .fhandle = { 0 }, .offset = 0x7FFFFFFFFFFFFFFFLL };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_truncate_req_t out;
    CHECK(xrdw_truncate_req_pack(&in, body) == XRDW_BODY_LEN, "truncate pack returns 16");
    CHECK(xrdw_truncate_req_unpack(body, &out) == XRDW_OK, "truncate unpack ok");
    CHECK(out.offset == in.offset, "truncate round-trip identity");
}

static void test_chkpoint(void)
{
    xrdw_chkpoint_req_t in = { .fhandle = { 5, 6, 7, 8 }, .opcode = 3 };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_chkpoint_req_t out;
    CHECK(xrdw_chkpoint_req_pack(&in, body) == XRDW_BODY_LEN, "chkpoint pack returns 16");
    CHECK(body[15] == 3, "chkpoint opcode @15");
    CHECK(xrdw_chkpoint_req_unpack(body, &out) == XRDW_OK, "chkpoint unpack ok");
    CHECK(out.opcode == in.opcode && memcmp(out.fhandle, in.fhandle, 4) == 0,
          "chkpoint round-trip identity");
}

/* ---- namespace family -------------------------------------------------- */
static void test_mkdir(void)
{
    xrdw_mkdir_req_t in = { .options = 1, .mode = 0x01FF };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_mkdir_req_t out;
    CHECK(xrdw_mkdir_req_pack(&in, body) == XRDW_BODY_LEN, "mkdir pack returns 16");
    CHECK(body[0] == 1, "mkdir options @0");
    CHECK(body[14] == 0x01 && body[15] == 0xFF, "mkdir mode @14 big-endian");
    CHECK(xrdw_mkdir_req_unpack(body, &out) == XRDW_OK, "mkdir unpack ok");
    CHECK(out.options == in.options && out.mode == in.mode, "mkdir round-trip identity");
}

static void test_chmod(void)
{
    xrdw_chmod_req_t in = { .mode = 0x01A4 };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_chmod_req_t out;
    CHECK(xrdw_chmod_req_pack(&in, body) == XRDW_BODY_LEN, "chmod pack returns 16");
    CHECK(body[14] == 0x01 && body[15] == 0xA4, "chmod mode @14 big-endian");
    CHECK(xrdw_chmod_req_unpack(body, &out) == XRDW_OK, "chmod unpack ok");
    CHECK(out.mode == in.mode, "chmod round-trip identity");
}

static void test_twopath(void)
{
    xrdw_twopath_req_t in = { .arg1len = 0x1234 };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_twopath_req_t out;
    CHECK(xrdw_twopath_req_pack(&in, body) == XRDW_BODY_LEN, "twopath pack returns 16");
    CHECK(body[14] == 0x12 && body[15] == 0x34, "twopath arg1len @14 big-endian");
    CHECK(xrdw_twopath_req_unpack(body, &out) == XRDW_OK, "twopath unpack ok");
    CHECK(out.arg1len == in.arg1len, "twopath round-trip identity");
}

static void test_empty(void)
{
    uint8_t body[XRDW_BODY_LEN];
    memset(body, 0xFF, sizeof(body));
    CHECK(xrdw_empty_req_pack(body) == XRDW_BODY_LEN, "empty pack returns 16");
    CHECK(body[0] == 0 && body[15] == 0, "empty body zeroed");
    CHECK(xrdw_empty_req_unpack(body) == XRDW_OK, "empty unpack ok");
}

/* ---- session family ---------------------------------------------------- */
static void test_login(void)
{
    xrdw_login_req_t in = { .pid = 0x01020304, .username = "rob\0\0\0\0",
                            .ability2 = 1, .ability = 2, .capver = 3 };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_login_req_t out;
    CHECK(xrdw_login_req_pack(&in, body) == XRDW_BODY_LEN, "login pack returns 16");
    CHECK(body[0] == 0x01 && body[3] == 0x04, "login pid @0 big-endian");
    CHECK(memcmp(body + 4, "rob\0\0\0\0\0", 8) == 0, "login username @4 NUL-padded");
    CHECK(body[12] == 1 && body[13] == 2 && body[14] == 3, "login ability/capver");
    CHECK(xrdw_login_req_unpack(body, &out) == XRDW_OK, "login unpack ok");
    CHECK(out.pid == in.pid && memcmp(out.username, in.username, 8) == 0
          && out.capver == in.capver, "login round-trip identity");
}

static void test_protocol(void)
{
    xrdw_protocol_req_t in = { .clientpv = 0x0500001C, .flags = 0x80, .expect = 0x03 };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_protocol_req_t out;
    CHECK(xrdw_protocol_req_pack(&in, body) == XRDW_BODY_LEN, "protocol pack returns 16");
    CHECK(body[0] == 0x05 && body[3] == 0x1C, "protocol clientpv @0 big-endian");
    CHECK(body[4] == 0x80 && body[5] == 0x03, "protocol flags@4 expect@5");
    CHECK(xrdw_protocol_req_unpack(body, &out) == XRDW_OK, "protocol unpack ok");
    CHECK(out.clientpv == in.clientpv && out.flags == in.flags
          && out.expect == in.expect, "protocol round-trip identity");
}

static void test_sessid(void)
{
    xrdw_sessid_req_t in;
    uint8_t body[XRDW_BODY_LEN];
    xrdw_sessid_req_t out;
    for (int i = 0; i < 16; i++) { in.sessid[i] = (uint8_t) (i + 1); }
    CHECK(xrdw_sessid_req_pack(&in, body) == XRDW_BODY_LEN, "sessid pack returns 16");
    CHECK(body[0] == 1 && body[15] == 16, "sessid @0..15");
    CHECK(xrdw_sessid_req_unpack(body, &out) == XRDW_OK, "sessid unpack ok");
    CHECK(memcmp(out.sessid, in.sessid, 16) == 0, "sessid round-trip identity");
}

static void test_sigver(void)
{
    xrdw_sigver_req_t in = { .expectrid = 0x0BC2, .version = 0, .flags = 1,
                             .seqno = 0x1122334455667788ULL, .crypto = 0x80 };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_sigver_req_t out;
    CHECK(xrdw_sigver_req_pack(&in, body) == XRDW_BODY_LEN, "sigver pack returns 16");
    CHECK(body[0] == 0x0B && body[1] == 0xC2, "sigver expectrid @0 big-endian");
    CHECK(body[4] == 0x11 && body[11] == 0x88, "sigver seqno @4 big-endian u64");
    CHECK(body[12] == 0x80, "sigver crypto @12");
    CHECK(xrdw_sigver_req_unpack(body, &out) == XRDW_OK, "sigver unpack ok");
    CHECK(out.expectrid == in.expectrid && out.seqno == in.seqno
          && out.crypto == in.crypto && out.flags == in.flags,
          "sigver round-trip identity");
}

static void test_prepare(void)
{
    xrdw_prepare_req_t in = { .options = 0x10, .prty = 2, .port = 0x1F90,
                              .optionX = 0x0004 };
    uint8_t body[XRDW_BODY_LEN];
    xrdw_prepare_req_t out;
    CHECK(xrdw_prepare_req_pack(&in, body) == XRDW_BODY_LEN, "prepare pack returns 16");
    CHECK(body[2] == 0x1F && body[3] == 0x90, "prepare port @2 big-endian");
    CHECK(xrdw_prepare_req_unpack(body, &out) == XRDW_OK, "prepare unpack ok");
    CHECK(out.options == in.options && out.port == in.port
          && out.optionX == in.optionX, "prepare round-trip identity");
}

/* ---- argument guards --------------------------------------------------- */
static void test_guards(void)
{
    uint8_t body[XRDW_BODY_LEN];
    xrdw_stat_req_t s;
    xrdw_read_req_t rd;
    CHECK(xrdw_stat_req_pack(NULL, body) == XRDW_EINVAL, "stat pack NULL rejected");
    CHECK(xrdw_stat_req_unpack(NULL, &s) == XRDW_EINVAL, "stat unpack NULL rejected");
    CHECK(xrdw_read_req_pack(NULL, body) == XRDW_EINVAL, "read pack NULL rejected");
    CHECK(xrdw_read_req_unpack(NULL, &rd) == XRDW_EINVAL, "read unpack NULL rejected");
    CHECK(xrdw_empty_req_pack(NULL) == XRDW_EINVAL, "empty pack NULL rejected");
}

int main(void)
{
    test_stat();
    test_statx();
    test_dirlist();
    test_query();
    test_locate();
    test_open();
    test_read();
    test_pgwrite();
    test_truncate();
    test_chkpoint();
    test_mkdir();
    test_chmod();
    test_twopath();
    test_empty();
    test_login();
    test_protocol();
    test_sessid();
    test_sigver();
    test_prepare();
    test_guards();

    if (g_fail) {
        printf("\nWIRE_CODEC UNITTEST FAILED\n");
        return 1;
    }
    printf("\nWIRE_CODEC UNITTEST PASSED\n");
    return 0;
}
