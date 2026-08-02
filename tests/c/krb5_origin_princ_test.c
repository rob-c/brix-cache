/* Offline unit for brix_krb5_origin_princ_from_host() (phase-70 §5.7).
 *
 * Proves the origin service principal is DERIVED correctly from the backend host
 * with the realm taken from the gateway's own principal, and — the security
 * point — that a hostile backend host string cannot smuggle a different realm or
 * principal component into the forwarded GSS target. No KDC or krb5 runtime is
 * needed: the helper is pure string assembly, so this always runs.
 *
 * Usage:  krb5_origin_princ_test <success|overflow|inject>
 * Exit 0 = the case's assertions held; 1 = a mismatch (detail to stderr).
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth/krb5/forward.h"

/* nginx surface stubs: forward.o references these (its GSS path), but the pure
 * string helper under test touches none of them. */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) log;
    return malloc(size);
}

volatile ngx_cycle_t  *ngx_cycle;

#define GW "xrootd/gw.example.org@EXAMPLE.ORG"

static int
case_success(void)
{
    char out[128];

    if (brix_krb5_origin_princ_from_host("origin.example.org", GW,
                                         out, sizeof out) != NGX_OK)
    {
        fprintf(stderr, "success: helper returned error\n");
        return 1;
    }
    if (strcmp(out, "host/origin.example.org@EXAMPLE.ORG") != 0) {
        fprintf(stderr, "success: got \"%s\"\n", out);
        return 1;
    }
    return 0;
}

static int
case_overflow(void)
{
    char out[16];   /* far too small for the full principal */

    ngx_memzero(out, sizeof out);
    if (brix_krb5_origin_princ_from_host("origin.example.org", GW,
                                         out, sizeof out) != NGX_ERROR)
    {
        fprintf(stderr, "overflow: helper unexpectedly succeeded\n");
        return 1;
    }
    /* Fail-closed: nothing written past a rejected build. */
    if (out[sizeof out - 1] != '\0') {
        fprintf(stderr, "overflow: buffer tail was written\n");
        return 1;
    }
    return 0;
}

static int
case_inject(void)
{
    char out[128];

    /* A backend host carrying a realm must not override the derived realm. */
    if (brix_krb5_origin_princ_from_host("evil.example.org@ATTACKER.REALM", GW,
                                         out, sizeof out) != NGX_ERROR)
    {
        fprintf(stderr, "inject: '@' in host was accepted\n");
        return 1;
    }
    /* A backend host carrying a principal component must be rejected too. */
    if (brix_krb5_origin_princ_from_host("a/b.example.org", GW,
                                         out, sizeof out) != NGX_ERROR)
    {
        fprintf(stderr, "inject: '/' in host was accepted\n");
        return 1;
    }
    /* A gateway principal with no realm yields no forwarded realm. */
    if (brix_krb5_origin_princ_from_host("origin.example.org", "no-realm-here",
                                         out, sizeof out) != NGX_ERROR)
    {
        fprintf(stderr, "inject: realmless gateway principal was accepted\n");
        return 1;
    }
    return 0;
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <success|overflow|inject>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "success") == 0) {
        return case_success();
    }
    if (strcmp(argv[1], "overflow") == 0) {
        return case_overflow();
    }
    if (strcmp(argv[1], "inject") == 0) {
        return case_inject();
    }
    fprintf(stderr, "unknown case: %s\n", argv[1]);
    return 2;
}
