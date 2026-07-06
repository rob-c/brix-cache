/*
 * vo_token_unittest.c — VMS-* VO-name sanitization conformance (ngx-free).
 *
 * Exercises the exact predicate the VOMS collector uses to accept/reject VO
 * and FQAN tokens extracted from an Attribute Certificate.  A forged/self-
 * signed AC is attacker-controlled, so hostile VO names must be rejected at
 * the edge before they reach the VO list, metric labels, or access log.
 *
 * Build/run: tests/c/run_vo_token_tests.sh
 */
#include "auth/voms/vo_token.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;
#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", (msg)); } \
    else { printf("  ok: %s\n", (msg)); }                       \
} while (0)

static int safe(const char *s) { return brix_vo_token_is_safe(s, strlen(s)); }

int
main(void)
{
    printf("VMS VO-name sanitization:\n");

    /* Legitimate VO / FQAN component names. */
    CHECK(safe("cms"),            "VMS-01 plain VO accepted");
    CHECK(safe("atlas.prod"),     "VMS-02 dotted VO accepted");
    CHECK(safe("dteam-2026"),     "VMS-03 hyphen/digits accepted");

    /* Hostile / malformed tokens must be rejected. */
    CHECK(!safe(""),              "VMS-04 empty rejected");
    CHECK(!safe("cms,atlas"),     "VMS-05 comma (list-injection) rejected");
    CHECK(!safe("/cms/Role=X"),   "VMS-06 slash rejected");
    CHECK(!safe("cms\\evil"),     "VMS-07 backslash rejected");
    CHECK(!safe("cms atlas"),     "VMS-08 space rejected");
    CHECK(!safe("cms\tx"),        "VMS-09 tab (control) rejected");
    CHECK(!safe("cms\nx"),        "VMS-10 newline (log-injection) rejected");
    CHECK(!safe("cms\x01"),       "VMS-11 SOH control byte rejected");
    CHECK(!safe("caf\xc3\xa9"),   "VMS-12 non-ASCII (UTF-8) rejected");
    CHECK(!safe("cms\x7f"),       "VMS-13 DEL byte rejected");

    /* Boundary bytes around the reject predicate (<=' ', >=0x7f, ',/\\'). */
    CHECK(!safe("\x1f"),          "VMS-14 0x1F (just below space) rejected");
    CHECK(!safe(" "),             "VMS-15 0x20 space rejected");
    CHECK(safe("!"),              "VMS-16 0x21 '!' accepted (printable)");
    CHECK(safe("a+b"),            "VMS-17 '+' accepted (printable, not special)");
    CHECK(safe("~"),              "VMS-18 0x7E '~' accepted (last printable)");
    CHECK(!safe("\x80"),          "VMS-19 0x80 (high bit) rejected");
    CHECK(!safe("\xff"),          "VMS-20 0xFF rejected");

    /* Allowed structural chars a real FQAN component may carry. */
    CHECK(safe("cms:prod"),       "VMS-21 colon accepted");
    CHECK(safe("Role=NULL"),      "VMS-22 equals accepted");
    CHECK(safe("cms_ops"),        "VMS-23 underscore accepted");
    CHECK(safe("VO-2026.01"),     "VMS-24 hyphen+dot accepted");

    /* Injection vectors that must be rejected. */
    CHECK(!safe("cms\r"),         "VMS-25 carriage return rejected");
    CHECK(!safe("a,b,c"),         "VMS-26 multi-comma rejected");
    CHECK(!safe("../etc"),        "VMS-27 path traversal (slash) rejected");
    CHECK(!safe("a\\b\\c"),       "VMS-28 multi-backslash rejected");
    CHECK(!safe("x\x0b"),         "VMS-29 vertical tab rejected");
    CHECK(!safe("x\x0c"),         "VMS-30 form feed rejected");

    /* A comma anywhere in an otherwise-valid token is fatal (list encoding). */
    CHECK(!safe("atlas,"),        "VMS-31 trailing comma rejected");
    CHECK(safe("atlasproduction"), "VMS-32 long plain token accepted");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
