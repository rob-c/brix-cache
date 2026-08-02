/*
 * gftp_parse_test.c — unit tests for the outbound gsiftp:// control-channel
 * reply parser (gftp_reply.c) and MLSx fact-line parser (gftp_mlsx.c).
 *
 * Compiled and run directly by tests/cmdscripts/c_regression_units.py
 * (runner "gftp_parse"): pure C, no nginx objects, no live server. Each parser
 * gets a success case, an error/malformed case, and a security-negative case
 * (hostile 227/229 address bytes → the SSRF-relevant reject, MLSx traversal /
 * control-byte names → reject).
 */

#include "gftp_reply.h"
#include "gftp_mlsx.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, msg) do {                                               \
        if (!(cond)) { printf("FAIL: %s\n", (msg)); failures++; }           \
    } while (0)


static void
test_reply_single(void)
{
    gftp_reply_t r;
    const char  *s = "220 GridFTP Server ready.\r\n";
    long         n = gftp_reply_scan(s, strlen(s), &r);
    CHECK(n == (long) strlen(s), "single: consumes whole line");
    CHECK(r.code == 220, "single: code 220");
    CHECK(r.multiline == 0, "single: not multiline");
    CHECK(r.text_len == strlen("GridFTP Server ready.")
          && memcmp(r.text, "GridFTP Server ready.", r.text_len) == 0,
          "single: text extracted without CRLF");
}


static void
test_reply_multiline(void)
{
    gftp_reply_t r;
    /* Intermediate lines (incl. one that itself starts with digits but the
     * wrong code) must not terminate the reply — only "211 " does. */
    const char  *s = "211-Features:\r\n MLST\r\n211-more\r\n211 End\r\n";
    long         n = gftp_reply_scan(s, strlen(s), &r);
    CHECK(n == (long) strlen(s), "multi: consumes through terminator");
    CHECK(r.code == 211, "multi: code 211");
    CHECK(r.multiline == 1, "multi: flagged multiline");
    CHECK(r.text_len == 3 && memcmp(r.text, "End", 3) == 0,
          "multi: final-line text");
}


static void
test_reply_incomplete_and_bad(void)
{
    gftp_reply_t r;
    const char  *part = "220 par";                 /* no CRLF yet */
    CHECK(gftp_reply_scan(part, strlen(part), &r) == 0,
          "incomplete: needs more bytes → 0");
    CHECK(gftp_reply_scan("22", 2, &r) == 0,
          "incomplete: short code → 0");

    /* error: a present non-digit code byte is malformed, not incomplete. */
    CHECK(gftp_reply_scan("2x0 no\r\n", 8, &r) == -1,
          "bad: non-digit code → -1");
    CHECK(gftp_reply_scan("220x bad sep\r\n", 14, &r) == -1,
          "bad: wrong separator → -1");

    /* An unterminated multiline is incomplete, never a false terminate. */
    const char *ml = "211-Features:\r\n MLST\r\n";
    CHECK(gftp_reply_scan(ml, strlen(ml), &r) == 0,
          "multi: unterminated → 0");
}


static void
test_pasv(void)
{
    unsigned char ip[4];
    unsigned      port;
    const char   *ok = "Entering Passive Mode (10,0,0,7,195,80).";
    CHECK(gftp_reply_parse_pasv(ok, strlen(ok), ip, &port) == 0,
          "pasv: parses");
    CHECK(ip[0] == 10 && ip[1] == 0 && ip[2] == 0 && ip[3] == 7,
          "pasv: address octets");
    CHECK(port == 195u * 256 + 80, "pasv: port = p1*256+p2");

    /* error: too few octets. */
    const char *few = "(10,0,0,7,195)";
    CHECK(gftp_reply_parse_pasv(few, strlen(few), ip, &port) == -1,
          "pasv: missing octet → -1");

    /* security-neg: an out-of-range octet (would smuggle a bogus address past
     * a naive parser) must be rejected before it reaches the SSRF screen. */
    const char *evil = "(10,0,0,7,999,80)";
    CHECK(gftp_reply_parse_pasv(evil, strlen(evil), ip, &port) == -1,
          "pasv: octet > 255 → -1");
    const char *evil2 = "(10,0,0,256,1,80)";
    CHECK(gftp_reply_parse_pasv(evil2, strlen(evil2), ip, &port) == -1,
          "pasv: 256 → -1");
}


static void
test_epsv(void)
{
    unsigned    port;
    const char *ok = "Entering Extended Passive Mode (|||6446|)";
    CHECK(gftp_reply_parse_epsv(ok, strlen(ok), &port) == 0
          && port == 6446, "epsv: parses port");

    /* error: too few delimiters. */
    const char *bad = "(||6446|)";
    CHECK(gftp_reply_parse_epsv(bad, strlen(bad), &port) == -1,
          "epsv: short delimiter run → -1");

    /* security-neg: port 0 and overflow are rejected. */
    const char *zero = "(|||0|)";
    CHECK(gftp_reply_parse_epsv(zero, strlen(zero), &port) == -1,
          "epsv: port 0 → -1");
    const char *over = "(|||99999|)";
    CHECK(gftp_reply_parse_epsv(over, strlen(over), &port) == -1,
          "epsv: port > 65535 → -1");
}


static void
test_mlsx(void)
{
    gftp_mlsx_ent_t e;

    /* success: a full file line. */
    const char *f = "type=file;size=1234;modify=20240102030405;perm=r; data.root";
    CHECK(gftp_mlsx_parse(f, strlen(f), &e) == 0, "mlsx: parses file line");
    CHECK(e.is_dir == 0, "mlsx: file not dir");
    CHECK(e.has_size && e.size == 1234ull, "mlsx: size fact");
    CHECK(e.has_mtime && e.mtime == 1704164645LL, "mlsx: modify → UTC epoch");
    CHECK(e.name_len == 9 && memcmp(e.name, "data.root", 9) == 0,
          "mlsx: name after separator");

    /* directory + a name-only line (missing facts tolerated). */
    const char *d = "type=cdir;modify=20240101000000; .";
    CHECK(gftp_mlsx_parse(d, strlen(d), &e) == 0 && e.is_dir == 1,
          "mlsx: cdir is dir");
    const char *nameonly = "; solo";
    CHECK(gftp_mlsx_parse(nameonly, strlen(nameonly), &e) == 0
          && e.name_len == 4 && !e.has_size,
          "mlsx: name-only line ok");

    /* error: no separator → no name. */
    const char *nosep = "type=file;size=1";
    CHECK(gftp_mlsx_parse(nosep, strlen(nosep), &e) == -1,
          "mlsx: no name → -1");

    /* security-neg: a name carrying a path separator (traversal) or a control
     * byte must be rejected — the driver must never trust it as a component. */
    const char *trav = "type=file;size=1; ../../etc/passwd";
    CHECK(gftp_mlsx_parse(trav, strlen(trav), &e) == -1,
          "mlsx: '/' in name → -1");
    char ctl[] = "type=file; a\nb";
    CHECK(gftp_mlsx_parse(ctl, sizeof(ctl) - 1, &e) == -1,
          "mlsx: newline in name → -1");

    /* security-neg: an overflowing size fact is dropped, not wrapped. */
    const char *big = "type=file;size=99999999999999999999999; x";
    CHECK(gftp_mlsx_parse(big, strlen(big), &e) == 0 && !e.has_size,
          "mlsx: overflow size dropped");
}


int
main(void)
{
    test_reply_single();
    test_reply_multiline();
    test_reply_incomplete_and_bad();
    test_pasv();
    test_epsv();
    test_mlsx();
    if (failures) {
        printf("gftp_parse_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("gftp_parse_test: all checks passed\n");
    return 0;
}
