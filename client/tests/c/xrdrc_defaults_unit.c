/*
 * xrdrc_defaults_unit.c — unit test for ~/.xrdrc [defaults] timeout parsing.
 *
 * WHAT: Verifies that brix_xrdrc_default_ms() correctly parses positive integer
 *       values from a [defaults] section, ignores invalid (non-numeric, negative)
 *       values, returns 0 for missing keys, and that brix_tmo_{connect,io}_ms()
 *       honour the full resolution order: env > xrdrc [defaults] > compiled default.
 * WHY:  The [defaults] section is a low-friction way for operators/users to tune
 *       timeouts without setting env vars; correct parse semantics (positive-only,
 *       full-string validation) prevent negative values from silently becoming giant
 *       unsigned timeouts.
 * HOW:  Write a temp .xrdrc file, point $XRDRC at it, call the API, verify results.
 *       Each assertion targets one code path; comments explain the expected outcome.
 *
 *       Layering strategy — two resolver slots avoid the per-slot cache:
 *         connect_timeout_ms: proves "xrdrc beats compiled default" (7000 vs 15000).
 *           brix_tmo_connect_ms() is called ONCE before any env var is set; the
 *           cached result is never read again in this process.
 *         io_timeout_ms: proves "env beats xrdrc" (env 9000 vs xrdrc 8000).
 *           XRDC_IO_TIMEOUT_MS is set BEFORE the first brix_tmo_io_ms() call so
 *           the resolver sees the env var first and returns 9000, not the xrdrc 8000.
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
    fprintf(f, "io_timeout_ms = 8000\n");              /* valid: proves env > xrdrc */
    fprintf(f, "bad_numeric = notanumber\n");           /* ignored: non-numeric */
    fprintf(f, "max_stall_ms = -5\n");                 /* ignored (negative) */
    fprintf(f, "[alias foo]\nurl = root://h:1094//x\n");
    fclose(f);
    setenv("XRDRC", path, 1);

    /* --- parse-layer: brix_xrdrc_default_ms semantics --- */
    assert(brix_xrdrc_default_ms("connect_timeout_ms", &v) == 1 && v == 7000);
    assert(brix_xrdrc_default_ms("io_timeout_ms", &v) == 1 && v == 8000);
    assert(brix_xrdrc_default_ms("bad_numeric", &v) == 0);         /* non-numeric rejected */
    assert(brix_xrdrc_default_ms("max_stall_ms", &v) == 0);        /* security:
        negative values must not become giant unsigned timeouts */
    assert(brix_xrdrc_default_ms("nosuchkey", &v) == 0);

    /*
     * XRDRC-BEATS-DEFAULT: no env var is set for connect_timeout_ms at this
     * point, so the resolver falls through to xrdrc and returns 7000 (not the
     * compiled default of 15000).  This proves the xrdrc layer is consulted.
     * NOTE: brix_tmo_connect_ms() caches on the first call (g_connect_ms atomic).
     * Do NOT call it again in this process — it would return the cached 7000
     * regardless of any setenv made afterwards.
     */
    assert(brix_tmo_connect_ms() == 7000);   /* xrdrc 7000 beats compiled default 15000 */

    /*
     * ENV-BEATS-XRDRC: set XRDC_IO_TIMEOUT_MS BEFORE the first brix_tmo_io_ms()
     * call.  xrdrc has io_timeout_ms = 8000; env overrides to 9000.  Using a
     * different resolver slot (g_io_ms) avoids the connect cache above.
     */
    setenv("XRDC_IO_TIMEOUT_MS", "9000", 1);
    assert(brix_tmo_io_ms() == 9000);        /* env 9000 beats xrdrc 8000 */

    unlink(path);
    printf("xrdrc_defaults_unit: ALL PASS\n");
    return 0;
}
