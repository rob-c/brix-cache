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

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
