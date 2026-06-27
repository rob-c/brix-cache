/*
 * ssi_rrinfo_unittest.c — standalone unit test for the SSI RRInfo/RRInfoAttn codec.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/ssi_rrinfo_ut \
 *       src/ssi/ssi_rrinfo_unittest.c src/ssi/ssi_rrinfo.c && /tmp/ssi_rrinfo_ut
 *
 * The expected bytes are GOLDEN values generated from the real XrdSsi classes
 * (XrdSsi/XrdSsiRRInfo.hh) — see the inline hex. Exit 0 = all checks pass.
 */

#include "ssi_rrinfo.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* Parse a hex string into bytes. */
static void
hex(const char *s, unsigned char *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (unsigned char) v;
    }
}

static int
bytes_eq(const unsigned char *a, const char *hexstr, size_t n)
{
    unsigned char b[64];
    hex(hexstr, b, n);
    return memcmp(a, b, n) == 0;
}

/* golden RRInfo wire values (from real XrdSsiRRInfo::Info()) */
static void
test_decode_golden(void)
{
    unsigned char off[8];
    int cmd; uint32_t id, sz;

    /* rxq id=5 sz=100 -> 0500000064000000 */
    hex("0500000064000000", off, 8);
    xrootd_ssi_rrinfo_decode(off, &cmd, &id, &sz);
    CHECK(cmd == XROOTD_SSI_CMD_RXQ);
    CHECK(id == 5);
    CHECK(sz == 100);

    /* can id=0x123456 sz=4096 -> 5634120200100000 */
    hex("5634120200100000", off, 8);
    xrootd_ssi_rrinfo_decode(off, &cmd, &id, &sz);
    CHECK(cmd == XROOTD_SSI_CMD_CAN);
    CHECK(id == 0x123456);
    CHECK(sz == 4096);

    /* rwt id=1 sz=0 -> 0100000100000000 */
    hex("0100000100000000", off, 8);
    xrootd_ssi_rrinfo_decode(off, &cmd, &id, &sz);
    CHECK(cmd == XROOTD_SSI_CMD_RWT);
    CHECK(id == 1);
    CHECK(sz == 0);
}

static void
test_encode_golden(void)
{
    unsigned char off[8];

    xrootd_ssi_rrinfo_encode(XROOTD_SSI_CMD_RXQ, 5, 100, off);
    CHECK(bytes_eq(off, "0500000064000000", 8));

    xrootd_ssi_rrinfo_encode(XROOTD_SSI_CMD_CAN, 0x123456, 4096, off);
    CHECK(bytes_eq(off, "5634120200100000", 8));

    xrootd_ssi_rrinfo_encode(XROOTD_SSI_CMD_RWT, 1, 0, off);
    CHECK(bytes_eq(off, "0100000100000000", 8));
}

static void
test_roundtrip(void)
{
    unsigned char off[8];
    int cmd; uint32_t id, sz;

    xrootd_ssi_rrinfo_encode(XROOTD_SSI_CMD_RXQ, 0xABCDEF, 0xDEADBEEF, off);
    xrootd_ssi_rrinfo_decode(off, &cmd, &id, &sz);
    CHECK(cmd == XROOTD_SSI_CMD_RXQ);
    CHECK(id == 0xABCDEF);
    CHECK(sz == 0xDEADBEEF);
}

static void
test_id_masked_to_24_bits(void)
{
    unsigned char off[8];
    int cmd; uint32_t id, sz;
    /* an id beyond 24 bits is masked, matching XrdSsiRRInfo::Id() */
    xrootd_ssi_rrinfo_encode(XROOTD_SSI_CMD_RXQ, 0xFF123456, 0, off);
    xrootd_ssi_rrinfo_decode(off, &cmd, &id, &sz);
    CHECK(id == 0x123456);
}

static void
test_attn_golden(void)
{
    /* fullResp, flags 0, pfx=16, md=0x11223344 ->
     * 3a000010112233440000000000000000 (real XrdSsiRRInfoAttn) */
    unsigned char out[16];
    xrootd_ssi_attn_encode(XROOTD_SSI_ATTN_FULL, 0, 16, 0x11223344, out);
    CHECK(bytes_eq(out, "3a000010112233440000000000000000", 16));
}

static void
test_attn_pend_and_alrt_tags(void)
{
    unsigned char out[16];
    xrootd_ssi_attn_encode(XROOTD_SSI_ATTN_PEND, 0, 16, 0, out);
    CHECK(out[0] == '*');
    xrootd_ssi_attn_encode(XROOTD_SSI_ATTN_ALRT, 0, 16, 7, out);
    CHECK(out[0] == '!');
    CHECK(bytes_eq(out + 4, "00000007", 4));   /* mdLen big-endian */
}

int
main(void)
{
    test_decode_golden();
    test_encode_golden();
    test_roundtrip();
    test_id_masked_to_24_bits();
    test_attn_golden();
    test_attn_pend_and_alrt_tags();

    if (g_fail) { printf("%d check(s) FAILED\n", g_fail); return 1; }
    printf("all ssi_rrinfo checks passed\n");
    return 0;
}
