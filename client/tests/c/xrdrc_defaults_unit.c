/*
 * xrdrc_defaults_unit.c — unit test for ~/.xrdrc [defaults] timeout parsing.
 *
 * WHAT: Verifies that brix_xrdrc_default_ms() correctly parses positive integer
 *       values from a [defaults] section, ignores invalid (non-numeric, negative)
 *       values, returns 0 for missing keys, and that brix_tmo_connect_ms() honours
 *       the resolution order (env var beats xrdrc).
 * WHY:  The [defaults] section is a low-friction way for operators/users to tune
 *       timeouts without setting env vars; correct parse semantics (positive-only,
 *       full-string validation) prevent negative values from silently becoming giant
 *       unsigned timeouts.
 * HOW:  Write a temp .xrdrc file, point $XRDRC at it, call the API, verify results.
 *       Each assertion targets one code path; comments explain the expected outcome.
 *
 * Build + run:
 *   cc -std=c11 -I client/lib tests/c/xrdrc_defaults_unit.c \
 *      client/libbrix.a libxrdproto.a -lcrypto -lpthread -lm -o xrdrc_defaults_unit
 *   ./xrdrc_defaults_unit
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "brix.h"
#include "brix_net.h"

int main(void)
{
    const char *path = "/tmp/xrdrc_defaults_unit.rc";
    FILE *f = fopen(path, "w");
    int   v = 0;
    fprintf(f, "[defaults]\n");
    fprintf(f, "connect_timeout_ms = 7000\n");
    fprintf(f, "io_timeout_ms = notanumber\n");        /* ignored */
    fprintf(f, "max_stall_ms = -5\n");                 /* ignored (negative) */
    fprintf(f, "[alias foo]\nurl = root://h:1094//x\n");
    fclose(f);
    setenv("XRDRC", path, 1);

    assert(brix_xrdrc_default_ms("connect_timeout_ms", &v) == 1 && v == 7000);
    assert(brix_xrdrc_default_ms("io_timeout_ms", &v) == 0);      /* error   */
    assert(brix_xrdrc_default_ms("max_stall_ms", &v) == 0);       /* security:
        negative values must not become giant unsigned timeouts */
    assert(brix_xrdrc_default_ms("nosuchkey", &v) == 0);
    /* layering: env var beats the xrdrc default */
    setenv("XRDC_CONNECT_TIMEOUT_MS", "9000", 1);
    assert(brix_tmo_connect_ms() == 9000);
    unlink(path);
    printf("xrdrc_defaults_unit: ALL PASS\n");
    return 0;
}
