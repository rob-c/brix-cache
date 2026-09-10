/*
 * gftp_feat_test.c — the FEAT capability probe, exercised rather than grepped.
 *
 * WHAT: drives gftp_feat() and its whole-token matcher over the reply bodies a
 *       real door sends, including the CRLF terminators RFC 959 §4.2 puts on
 *       every continuation line.
 *
 * WHY:  this replaces a static pin that asserted the SPELLING of the matcher's
 *       terminator test (`line[len] == '\0'`).  That pin was green for the
 *       whole time the matcher was broken — the terminator set was ' ', '\t'
 *       and NUL, so against a conforming origin it matched NOTHING and every
 *       extension was silently skipped — and it went red the moment the defect
 *       was fixed.  A pin that cannot see the bug it is named after, and that
 *       fails on the repair, is worse than no pin: it argues for the defect.
 *
 * HOW:  the matcher is static, so the driver includes the translation unit and
 *       supplies the one symbol it calls.  gftp_command() is stubbed to hand
 *       back a canned reply, which is the only way to drive gftp_feat() itself
 *       without a socket — and driving gftp_feat() matters, because the probe's
 *       other two failure modes (a non-211 code, a body read from the wrong
 *       field) are invisible to a test that only calls the parser.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "fs/backend/gsiftp/gftp_feat.c"

/* The reply the stub hands back, set by each case before it probes. */
static const char *g_cont = "";
static int         g_code = 211;
static int         g_rc;

int
gftp_command(gftp_session_t *session, const char *fmt, ...)
{
    (void) fmt;
    session->code = g_code;
    snprintf(session->cont, sizeof(session->cont), "%s", g_cont);
    return g_rc;
}

static int g_failures;

static void
check(int ok, const char *what)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

static unsigned
probe(const char *cont, int code, int rc)
{
    gftp_session_t session;

    memset(&session, 0, sizeof(session));
    g_cont = cont;
    g_code = code;
    g_rc = rc;
    return gftp_feat(&session);
}

/* The body gftp_reply_scan hands over for a real door: continuation lines
 * only, each one CRLF-terminated, leading space intact. */
#define CONFORMING \
    " EPSV\r\n MLSD\r\n REST STREAM\r\n MODE E\r\n ERET\r\n SPAS\r\n"

int
main(void)
{
    /* The defect: every one of these was 0 before the terminator fix. */
    check(probe(CONFORMING, 211, 0) == (GFTP_FEAT_ERET | GFTP_FEAT_SPAS),
          "T1 a CRLF-terminated advertisement lights both bits");
    check((probe(" ERET\r\n", 211, 0) & GFTP_FEAT_ERET) != 0,
          "T2 CR terminates a feature name");
    check((probe(" ERET\n", 211, 0) & GFTP_FEAT_ERET) != 0,
          "T3 a bare LF terminates one too");
    check((probe(" ERET", 211, 0) & GFTP_FEAT_ERET) != 0,
          "T4 so does the end of the body");
    check((probe(" ERET PARAM\r\n", 211, 0) & GFTP_FEAT_ERET) != 0,
          "T5 and so does a space before this feature's parameters");

    /* Every name in the table is driven through the terminator in its own
     * right: a feature only ever tested inside the blob above would inherit
     * a green from ERET's line rather than earn one. */
    check((probe(" SPAS\r\n", 211, 0) & GFTP_FEAT_SPAS) != 0,
          "T6 the striped-passive name terminates the same way");

    /* The property the terminator set exists to keep: a TOKEN, not a substring.
     * Widening the set is exactly the change that could have lost it. */
    check(probe(" ERETSTAT\r\n", 211, 0) == 0,
          "S1 a longer verb sharing the prefix is not the feature");
    check(probe(" SITE ERET\r\n", 211, 0) == 0,
          "S2 the name as another verb's ARGUMENT is not the feature");
    check(probe(" SPASV\r\n", 211, 0) == 0,
          "S3 the same for the striped extension");
    check(probe(" X-ERET\r\n", 211, 0) == 0,
          "S4 a vendor-prefixed spelling is not the feature");
    check(probe("220 ERET is supported by this door\r\n", 211, 0) == 0,
          "S5 prose that mentions the name is not an advertisement");

    /* The probe's own refusals — invisible to a test of the parser alone. */
    check(probe(CONFORMING, 500, 0) == 0,
          "R1 a non-211 reply advertises nothing");
    check(probe(CONFORMING, 211, -1) == 0,
          "R2 a failed FEAT command advertises nothing");
    check(probe("", 211, 0) == 0, "R3 an empty body advertises nothing");

    printf(g_failures == 0 ? "ALL PASSED\n" : "%d FAILED\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
