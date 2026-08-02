/* Unit test for brix_tpc_proxy_pem_expired (phase-58 §5.8/§5.9 T5): the
 * lifetime gate that refuses a captured delegated proxy before a native-TPC
 * pull downgrades to the gateway identity.
 *
 * Links the REAL credential.o; the tiny nginx pool/log/time surface it drags in
 * (ngx_log_error_core / ngx_pnalloc / ngx_strncasecmp / ngx_cached_time) is
 * stubbed below — no nginx core objects are linked. Fixtures (forged via
 * tests/x509forge.py, whose epoch is FIXED at 2026-01-01) come from the
 * directory in $BRIX_TPC_EXPIRY_FIXTURES:
 *   expired.pem  — proxy leaf whose NotAfter is a 1-day window off the 2026-01-01
 *                  epoch (already in the past in real time) → expect 1
 *   valid.pem    — proxy leaf with a far-future NotAfter                → expect 0
 *   garbage.pem  — not a PEM certificate at all                        → expect -1
 *
 * Ritual: success (a live proxy is not refused), error (garbage yields the
 * -1 parse-failure sentinel, and NULL/zero-length likewise), security-negative
 * (an expired proxy is reported expired so the launcher refuses the pull). */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ---- nginx surface stubs (no nginx core objects are linked) --------------- */

static ngx_log_t   test_log;          /* log_level 0 → ngx_log_error bodies skipped */
static ngx_time_t  test_cached_time;
volatile ngx_time_t *ngx_cached_time = &test_cached_time;

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

ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    return strncasecmp((char *) s1, (char *) s2, n);
}

/* Function under test (credential.h drags in the identity/ngx surface; a bare
 * prototype keeps the harness minimal and matches the C symbol exactly). */
int brix_tpc_proxy_pem_expired(const u_char *pem, size_t len, ngx_log_t *log);

static u_char *
slurp(const char *path, size_t *out_len)
{
    FILE   *f = fopen(path, "rb");
    long    n;
    u_char *buf;

    if (f == NULL) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = malloc((size_t) n + 1);
    if (buf == NULL || fread(buf, 1, (size_t) n, f) != (size_t) n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[n] = '\0';
    fclose(f);
    *out_len = (size_t) n;
    return buf;
}

static int
check_file(const char *dir, const char *name, int want)
{
    char    path[4096];
    size_t  len = 0;
    u_char *blob;
    int     got;

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    blob = slurp(path, &len);
    if (blob == NULL) {
        fprintf(stderr, "FAIL %s: cannot read fixture\n", name);
        return 1;
    }
    got = brix_tpc_proxy_pem_expired(blob, len, &test_log);
    free(blob);
    if (got != want) {
        fprintf(stderr, "FAIL %s: got %d, want %d\n", name, got, want);
        return 1;
    }
    fprintf(stderr, "ok %s -> %d\n", name, got);
    return 0;
}

int
main(void)
{
    const char *dir = getenv("BRIX_TPC_EXPIRY_FIXTURES");
    int         fails = 0;

    if (dir == NULL) {
        fprintf(stderr, "BRIX_TPC_EXPIRY_FIXTURES unset\n");
        return 2;
    }
    test_log.log_level = 0;

    /* security-negative: an expired proxy must be reported expired (→ refuse). */
    fails += check_file(dir, "expired.pem", 1);
    /* success: a live proxy is not refused. */
    fails += check_file(dir, "valid.pem", 0);
    /* error: unparseable input yields the -1 sentinel (caller decides). */
    fails += check_file(dir, "garbage.pem", -1);

    /* error: NULL / zero-length input is a clean -1, never a crash. */
    if (brix_tpc_proxy_pem_expired(NULL, 0, &test_log) != -1) {
        fprintf(stderr, "FAIL null/zero -> not -1\n");
        fails++;
    } else {
        fprintf(stderr, "ok null/zero -> -1\n");
    }

    return fails ? 1 : 0;
}
