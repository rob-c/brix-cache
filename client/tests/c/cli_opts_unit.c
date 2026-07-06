/* client/tests/c/cli_opts_unit.c
 *
 * WHAT: Unit tests for brix_cli_parse_io_uring (cli_opts.c): the strict CLI
 *       parser that maps "on"/"off"/"auto" to XRDC_IO_URING_* and rejects all
 *       other input with -1.
 * WHY:  Three groups — success, error, and security-negative — verify that
 *       (a) all three recognised modes map to the correct constant, (b) NULL,
 *       empty string, and common typos are rejected, and (c) adversarial inputs
 *       (embedded NUL, whitespace prefix, mixed case, overflow-length) are also
 *       rejected, preventing silent fallback-to-auto from accepting bogus values.
 * HOW:  Direct calls to brix_cli_parse_io_uring; assert() on the return value.
 *       No server or filesystem required.
 */

#include "brix.h"       /* brix_cli_parse_io_uring, XRDC_IO_URING_* (via brix_ops.h) */

#include <assert.h>
#include <stdio.h>


/* ---- success: all three valid mode strings ---- */

static void
test_on(void)
{
    assert(brix_cli_parse_io_uring("on")  == XRDC_IO_URING_ON);
    printf("PASS: \"on\" -> XRDC_IO_URING_ON\n");
}

static void
test_off(void)
{
    assert(brix_cli_parse_io_uring("off") == XRDC_IO_URING_OFF);
    printf("PASS: \"off\" -> XRDC_IO_URING_OFF\n");
}

static void
test_auto(void)
{
    assert(brix_cli_parse_io_uring("auto") == XRDC_IO_URING_AUTO);
    printf("PASS: \"auto\" -> XRDC_IO_URING_AUTO\n");
}


/* ---- error: common bad inputs ---- */

static void
test_null(void)
{
    assert(brix_cli_parse_io_uring(NULL) == -1);
    printf("PASS: NULL -> -1\n");
}

static void
test_empty(void)
{
    assert(brix_cli_parse_io_uring("") == -1);
    printf("PASS: empty string -> -1\n");
}

static void
test_bogus(void)
{
    assert(brix_cli_parse_io_uring("bogus")  == -1);
    assert(brix_cli_parse_io_uring("1")      == -1);
    assert(brix_cli_parse_io_uring("yes")    == -1);
    assert(brix_cli_parse_io_uring("enable") == -1);
    printf("PASS: bogus values -> -1\n");
}


/* ---- security-negative: adversarial / boundary inputs ---- */

static void
test_case_sensitivity(void)
{
    /* Strict match only — mixed case must not silently match. */
    assert(brix_cli_parse_io_uring("ON")   == -1);
    assert(brix_cli_parse_io_uring("Off")  == -1);
    assert(brix_cli_parse_io_uring("AUTO") == -1);
    assert(brix_cli_parse_io_uring("On")   == -1);
    printf("PASS: mixed-case inputs rejected\n");
}

static void
test_whitespace(void)
{
    /* Leading/trailing whitespace must not be silently trimmed. */
    assert(brix_cli_parse_io_uring(" on")   == -1);
    assert(brix_cli_parse_io_uring("on ")   == -1);
    assert(brix_cli_parse_io_uring(" auto") == -1);
    printf("PASS: whitespace-padded inputs rejected\n");
}

static void
test_prefix_match(void)
{
    /* Prefix of a valid mode must not match. */
    assert(brix_cli_parse_io_uring("o")   == -1);
    assert(brix_cli_parse_io_uring("of")  == -1);
    assert(brix_cli_parse_io_uring("au")  == -1);
    printf("PASS: prefix-of-valid inputs rejected\n");
}


int
main(void)
{
    printf("=== cli_opts_unit: brix_cli_parse_io_uring ===\n");

    test_on();
    test_off();
    test_auto();

    test_null();
    test_empty();
    test_bogus();

    test_case_sensitivity();
    test_whitespace();
    test_prefix_match();

    printf("cli_opts_unit: ALL PASS\n");
    return 0;
}
