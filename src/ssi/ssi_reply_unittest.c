/*
 * ssi_reply_unittest.c — standalone unit test for the SSI kXR_query reply layout.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/ssi_reply_ut \
 *       src/ssi/ssi_reply_unittest.c src/ssi/ssi_reply.c src/ssi/ssi_rrinfo.c \
 *       && /tmp/ssi_reply_ut
 */

#include "ssi_reply.h"
#include "ssi_rrinfo.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* Recover (mdLen, pfxLen, dbL) exactly as XrdSsiTaskReal::GetResp does. */
static void
getresp(const unsigned char *buf, size_t n,
        unsigned *pfx, unsigned *md, long *db)
{
    *pfx = ((unsigned) buf[2] << 8) | buf[3];          /* ntohs(pfxLen) */
    *md  = ((unsigned) buf[4] << 24) | ((unsigned) buf[5] << 16)
         | ((unsigned) buf[6] << 8) | buf[7];          /* ntohl(mdLen) */
    *db  = (long) n - (long) *md - (long) *pfx;
}

static void
test_full_response_layout(void)
{
    unsigned char out[64];
    size_t n = xrootd_ssi_reply_build(XROOTD_SSI_ATTN_FULL,
                                      (const unsigned char *) "m", 1,
                                      (const unsigned char *) "hi", 2, out);
    CHECK(n == 19);                              /* 16 prefix + 1 md + 2 data */
    CHECK(xrootd_ssi_reply_len(1, 2) == 19);
    CHECK(out[0] == ':');                        /* fullResp tag */

    unsigned pfx, md; long db;
    getresp(out, n, &pfx, &md, &db);
    CHECK(pfx == 16);
    CHECK(md == 1);
    CHECK(db == 2);                              /* client recovers data len */
    /* metadata at +pfx, data at +md+pfx (GetResp) */
    CHECK(memcmp(out + pfx, "m", 1) == 0);
    CHECK(memcmp(out + md + pfx, "hi", 2) == 0);
}

static void
test_no_metadata(void)
{
    unsigned char out[64];
    size_t n = xrootd_ssi_reply_build(XROOTD_SSI_ATTN_FULL, NULL, 0,
                                      (const unsigned char *) "data", 4, out);
    CHECK(n == 20);
    unsigned pfx, md; long db;
    getresp(out, n, &pfx, &md, &db);
    CHECK(md == 0 && pfx == 16 && db == 4);
    CHECK(memcmp(out + pfx, "data", 4) == 0);
}

static void
test_alert_tag(void)
{
    unsigned char out[32];
    size_t n = xrootd_ssi_reply_build(XROOTD_SSI_ATTN_ALRT,
                                      (const unsigned char *) "go", 2, NULL, 0, out);
    CHECK(out[0] == '!');
    CHECK(n == 18);
}

int
main(void)
{
    test_full_response_layout();
    test_no_metadata();
    test_alert_tag();
    if (g_fail) { printf("%d check(s) FAILED\n", g_fail); return 1; }
    printf("all ssi_reply checks passed\n");
    return 0;
}
