/*
 * respbuf_unittest.c — standalone unit test for the grow-on-append buffer.
 *
 *   gcc -Wall -Wextra -Werror -DSSI_UT_STANDALONE -I src -o /tmp/ssi_respbuf_ut \
 *       src/ssi/respbuf_unittest.c src/ssi/respbuf.c && /tmp/ssi_respbuf_ut
 */
#include "respbuf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static void test_append_concatenates(void)
{
    xrootd_ssi_respbuf_t b;
    memset(&b, 0, sizeof(b));
    CHECK(xrootd_ssi_respbuf_append(&b, (const unsigned char *) "ab", 2, 1024) == 0);
    CHECK(xrootd_ssi_respbuf_append(&b, (const unsigned char *) "cd", 2, 1024) == 0);
    CHECK(b.len == 4);
    CHECK(memcmp(b.data, "abcd", 4) == 0);
    free(b.data);
}

static void test_grows_past_initial_cap(void)
{
    xrootd_ssi_respbuf_t b;
    char chunk[300];
    memset(&b, 0, sizeof(b));
    memset(chunk, 'x', sizeof(chunk));
    /* 300 > the 256 initial cap → forces a grow */
    CHECK(xrootd_ssi_respbuf_append(&b, (const unsigned char *) chunk, 300, 4096) == 0);
    CHECK(b.len == 300);
    CHECK(b.cap >= 300);
    free(b.data);
}

static void test_cap_max_rejects_overflow(void)
{
    xrootd_ssi_respbuf_t b;
    memset(&b, 0, sizeof(b));
    CHECK(xrootd_ssi_respbuf_append(&b, (const unsigned char *) "hello", 5, 8) == 0);
    /* 5 + 5 = 10 > cap_max 8 → reject, leave unchanged */
    CHECK(xrootd_ssi_respbuf_append(&b, (const unsigned char *) "world", 5, 8) == -1);
    CHECK(b.len == 5);
    CHECK(memcmp(b.data, "hello", 5) == 0);
    free(b.data);
}

int main(void)
{
    test_append_concatenates();
    test_grows_past_initial_cap();
    test_cap_max_rejects_overflow();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
