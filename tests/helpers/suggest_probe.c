/*
 * suggest_probe.c — test helper: PTY-exercisable probe for WS-3/WS-7 hints.
 *
 * WHAT: a small standalone C binary that exercises the brix_suggest(),
 *       brix_hint_url_double_slash(), and brix_hint_doctor_referral()
 *       functions so Python PTY tests can observe their output without
 *       needing a running XRootD server.
 *
 * WHY:  brix_cli_hints_enabled() gates on isatty(STDERR_FILENO); unit tests
 *       run with pipes so hints are silent there.  The PTY tests must use a
 *       real binary whose stderr is a slave PTY.
 *
 * HOW:  argv[1] selects the subcommand:
 *         "suggest_match"   — brix_suggest("satt", CMDS) → "stat" hint emitted
 *         "suggest_no_match"— brix_suggest("zbot", CMDS) → no hint
 *         "double_slash"    — brix_hint_url_double_slash(url with bit=1) fires
 *         "double_slash_off"— brix_hint_url_double_slash(url with bit=0) silent
 *         "doctor_auth"     — brix_hint_doctor_referral(auth status) fires
 *         "doctor_noauth"   — brix_hint_doctor_referral(non-auth status) silent
 *       All exit 0 on success; emit to stderr only through the hint helpers.
 *
 * Build:
 *   cc -std=c11 -Wall -Ilib -I../src -I../shared -DXRDPROTO_NO_NGX \
 *       tests/helpers/suggest_probe.c libbrix.a ../shared/xrdproto/libxrdproto.a \
 *       -lssl -lcrypto -lz -o bin/suggest_probe
 */
#include "brix.h"
#include "cli/suggest.h"
#include "cli/cli_hint.h"

#include <stdio.h>
#include <string.h>

/* Candidate table identical to xrdfs COMMANDS[] names subset, for suggest tests. */
static const char *const CMDS[] = {
    "stat", "ls", "mkdir", "rm", "cat", "find", NULL
};

static void
cmd_suggest_match(void)
{
    /* "satt" is DL-distance 1 from "stat" (transposition). */
    const char *s = brix_suggest("satt", CMDS);
    if (s != NULL) {
        brix_cli_hint("hint: did you mean '%s'?\n", s);
    }
}

static void
cmd_suggest_no_match(void)
{
    /* "zbot" is DL-distance 3 from "stat" — no suggestion. */
    const char *s = brix_suggest("zbot", CMDS);
    if (s != NULL) {
        brix_cli_hint("hint: did you mean '%s'?\n", s);
    }
    /* Always exit 0 whether or not a suggestion fired. */
}

static void
cmd_double_slash(void)
{
    brix_url url;
    memset(&url, 0, sizeof(url));
    url.scheme           = XRDC_SCHEME_ROOT;
    url.single_slash_path = 1;   /* simulate single-slash URL */
    brix_hint_url_double_slash(&url);
}

static void
cmd_double_slash_off(void)
{
    brix_url url;
    memset(&url, 0, sizeof(url));
    url.scheme            = XRDC_SCHEME_ROOT;
    url.single_slash_path = 0;   /* double-slash URL: bit clear */
    brix_hint_url_double_slash(&url);
}

static void
cmd_doctor_auth(void)
{
    brix_status st;
    memset(&st, 0, sizeof(st));
    st.kxr = kXR_NotAuthorized;
    brix_hint_doctor_referral(&st, "root://test.example.com//data");
}

static void
cmd_doctor_noauth(void)
{
    brix_status st;
    memset(&st, 0, sizeof(st));
    st.kxr = kXR_NotFound;
    brix_hint_doctor_referral(&st, "root://test.example.com//data");
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: suggest_probe <subcommand>\n");
        return 2;
    }
    if (strcmp(argv[1], "suggest_match")    == 0) { cmd_suggest_match();    return 0; }
    if (strcmp(argv[1], "suggest_no_match") == 0) { cmd_suggest_no_match(); return 0; }
    if (strcmp(argv[1], "double_slash")     == 0) { cmd_double_slash();     return 0; }
    if (strcmp(argv[1], "double_slash_off") == 0) { cmd_double_slash_off(); return 0; }
    if (strcmp(argv[1], "doctor_auth")      == 0) { cmd_doctor_auth();      return 0; }
    if (strcmp(argv[1], "doctor_noauth")    == 0) { cmd_doctor_noauth();    return 0; }
    fprintf(stderr, "suggest_probe: unknown subcommand '%s'\n", argv[1]);
    return 2;
}
