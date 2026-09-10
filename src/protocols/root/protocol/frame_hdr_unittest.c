/*
 * frame_hdr_unittest.c — standalone unit test for the shared kXR_redirect
 * body decoder (xrd_redirect_body_decode, frame_hdr.h).
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/frame_hdr_ut \
 *       src/protocols/root/protocol/frame_hdr_unittest.c && /tmp/frame_hdr_ut
 *
 * Exit 0 = all checks pass. One decoder serves both the native client's
 * redirect follower and the destination's TPC multihop pull (F7), so the
 * truncation and bounds cases here protect both: an over-long host or opaque
 * must be clipped inside the caller's buffers and still NUL-terminated, and a
 * body too short to carry a port must be refused rather than read past.
 */

#include "protocols/root/protocol/frame_hdr.h"

#include <stdio.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* Build a ServerRedirectBody: port[4 BE] + host bytes (no NUL added). */
static uint32_t
mk_body(uint8_t *out, size_t cap, unsigned port, const char *host)
{
    size_t hlen = strlen(host);

    if (hlen + 4 > cap) {
        hlen = cap - 4;
    }
    out[0] = (uint8_t) (port >> 24);
    out[1] = (uint8_t) (port >> 16);
    out[2] = (uint8_t) (port >> 8);
    out[3] = (uint8_t) port;
    memcpy(out + 4, host, hlen);
    return (uint32_t) (hlen + 4);
}

/* One wire body and what the decoder must make of it. `extra` bytes after the
 * host string (an explicit NUL + junk) exercise the NUL-terminated form. */
typedef struct {
    unsigned    port;
    const char *wire;
    const char *extra;       /* appended AFTER a NUL, or NULL */
    const char *want_host;
    const char *want_opaque;
} redirect_case_t;

static const redirect_case_t success_cases[] = {
    { 1094, "ds1.example.org",               NULL,       "ds1.example.org", "" },
    { 2094, "[::1]?cap.sym=abc&cap.msg=def", NULL,       "[::1]",
                                                         "cap.sym=abc&cap.msg=def" },
    {    1, "eos.cern.ch?&cap.sym=x",        NULL,       "eos.cern.ch",     "cap.sym=x" },
    {    7, "h.example\r\njunk",             NULL,       "h.example",       "" },
    {    7, "h2.example",                    "trailing", "h2.example",      "" },
    { 1094, "?&&?",                          NULL,       "",                "" },
};

/* --- success: plain host, host+opaque, EOS "?&cap.sym", CR/LF and NUL tails -- */
static void
test_decode_success(void)
{
    size_t i;

    for (i = 0; i < sizeof(success_cases) / sizeof(success_cases[0]); i++) {
        const redirect_case_t *c = &success_cases[i];
        uint8_t  body[256];
        uint32_t blen = mk_body(body, sizeof(body), c->port, c->wire);
        char     host[64], opaque[128];
        int      port = -1;

        if (c->extra != NULL) {
            body[blen] = '\0';
            memcpy(body + blen + 1, c->extra, strlen(c->extra));
            blen += 1 + (uint32_t) strlen(c->extra);
        }
        CHECK(xrd_redirect_body_decode(body, blen, host, sizeof(host), &port,
                                       opaque, sizeof(opaque)) == 0);
        CHECK(port == (int) c->port);
        CHECK(strcmp(host, c->want_host) == 0);
        CHECK(strcmp(opaque, c->want_opaque) == 0);
    }
}

/* --- the opaque out-params are optional --------------------------------------- */
static void
test_decode_no_opaque(void)
{
    uint8_t  body[64];
    uint32_t blen = mk_body(body, sizeof(body), 3, "h3?x=1");
    char     host[16];
    int      port = 0;

    CHECK(xrd_redirect_body_decode(body, blen, host, sizeof(host), &port,
                                   NULL, 0) == 0);
    CHECK(port == 3 && strcmp(host, "h3") == 0);
}

/* --- error: a body too short for the port, or no room for a host, is refused -- */
static void
test_decode_error(void)
{
    uint8_t body[8] = { 0, 0, 4, 70, 'h', 'o', 's', 't' };
    char    host[16], opaque[16];
    int     port = 0;

    CHECK(xrd_redirect_body_decode(body, 4, host, sizeof(host), &port,
                                   opaque, sizeof(opaque)) == -1);
    CHECK(xrd_redirect_body_decode(body, 0, host, sizeof(host), &port,
                                   opaque, sizeof(opaque)) == -1);
    CHECK(xrd_redirect_body_decode(NULL, 8, host, sizeof(host), &port,
                                   opaque, sizeof(opaque)) == -1);
    CHECK(xrd_redirect_body_decode(body, 8, NULL, sizeof(host), &port,
                                   opaque, sizeof(opaque)) == -1);
    CHECK(xrd_redirect_body_decode(body, 8, host, 0, &port,
                                   opaque, sizeof(opaque)) == -1);
    CHECK(xrd_redirect_body_decode(body, 8, host, sizeof(host), NULL,
                                   opaque, sizeof(opaque)) == -1);
    /* an empty host field decodes (the CALLER decides an empty host is fatal) */
    CHECK(xrd_redirect_body_decode(body, 5, host, sizeof(host), &port,
                                   opaque, sizeof(opaque)) == 0);
    CHECK(host[0] == 'h' && host[1] == '\0');
}

/* --- security-negative: over-long fields are clipped inside the buffers ------- */
static void
test_decode_truncation(void)
{
    uint8_t  body[600];
    uint32_t blen;
    char     longhost[300], host[16], opaque[8];
    int      port = 0;

    memset(longhost, 'a', sizeof(longhost) - 1);
    longhost[sizeof(longhost) - 1] = '\0';
    blen = mk_body(body, sizeof(body), 1094, longhost);
    memset(host, 'X', sizeof(host));
    CHECK(xrd_redirect_body_decode(body, blen, host, sizeof(host), &port,
                                   opaque, sizeof(opaque)) == 0);
    CHECK(strlen(host) == sizeof(host) - 1 && host[sizeof(host) - 1] == '\0');

    blen = mk_body(body, sizeof(body), 1094, "h?cap.sym=0123456789abcdef");
    memset(opaque, 'X', sizeof(opaque));
    CHECK(xrd_redirect_body_decode(body, blen, host, sizeof(host), &port,
                                   opaque, sizeof(opaque)) == 0);
    CHECK(strcmp(host, "h") == 0 && strlen(opaque) == sizeof(opaque) - 1
          && memcmp(opaque, "cap.sym", 7) == 0);
}

int
main(void)
{
    test_decode_success();
    test_decode_no_opaque();
    test_decode_error();
    test_decode_truncation();

    if (g_fail != 0) {
        printf("%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
