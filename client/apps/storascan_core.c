/*
 * storascan_core.c — pure core for xrdstorascan (see storascan_core.h).
 *
 * No network, no allocation that outlives a call, no globals. Unit-tested by
 * storascan_unittest.c.
 */
#include "storascan_core.h"

#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ---- verify (A1) ---------------------------------------------------------- */

/* Advance past leading ASCII whitespace. */
static const char *
ckv_skip_ws(const char *s)
{
    while (*s != '\0' && isspace((unsigned char) *s)) {
        s++;
    }
    return s;
}

/* Length of s with trailing ASCII whitespace excluded. */
static size_t
ckv_trimmed_len(const char *s)
{
    size_t len = strlen(s);

    while (len > 0 && isspace((unsigned char) s[len - 1])) {
        len--;
    }
    return len;
}

storascan_cks_status
storascan_cks_compare(const char *computed_hex, const char *stored_hex)
{
    const char *want;
    const char *got;
    size_t      want_len;
    size_t      got_len;
    size_t      i;

    if (stored_hex == NULL) {
        return STORASCAN_CKS_MISSING;
    }
    want = ckv_skip_ws(stored_hex);
    want_len = ckv_trimmed_len(want);
    if (want_len == 0) {
        return STORASCAN_CKS_MISSING;
    }

    got = (computed_hex != NULL) ? ckv_skip_ws(computed_hex) : "";
    got_len = ckv_trimmed_len(got);

    if (got_len != want_len) {
        return STORASCAN_CKS_MISMATCH;
    }
    for (i = 0; i < want_len; i++) {
        if (tolower((unsigned char) got[i]) != tolower((unsigned char) want[i])) {
            return STORASCAN_CKS_MISMATCH;
        }
    }
    return STORASCAN_CKS_MATCH;
}

/* ---- bench (B1) ----------------------------------------------------------- */

double
storascan_percentile_ms(const double *sorted_ms, size_t n, double pct)
{
    double rank;
    size_t idx;

    if (n == 0 || sorted_ms == NULL) {
        return 0.0;
    }
    if (pct < 0.0) {
        pct = 0.0;
    }
    if (pct > 100.0) {
        pct = 100.0;
    }

    /* nearest-rank: rank = ceil(pct/100 * n), index = rank-1, clamped */
    rank = ceil((pct / 100.0) * (double) n);
    if (rank < 1.0) {
        idx = 0;
    } else {
        idx = (size_t) rank - 1;
        if (idx >= n) {
            idx = n - 1;
        }
    }
    return sorted_ms[idx];
}

static int
ckv_cmp_double(const void *a, const void *b)
{
    double da = *(const double *) a;
    double db = *(const double *) b;

    if (da < db) {
        return -1;
    }
    if (da > db) {
        return 1;
    }
    return 0;
}

void
storascan_bench_compute(const double *lat_ms, size_t n,
                        uint64_t bytes, double elapsed_s,
                        storascan_bench_result *out)
{
    double *sorted = NULL;

    out->ops = (uint64_t) n;
    out->bytes = bytes;
    out->elapsed_s = elapsed_s;

    if (elapsed_s > 0.0) {
        out->throughput_mibps = ((double) bytes / (double) (1u << 20)) / elapsed_s;
        out->iops = (double) n / elapsed_s;
    } else {
        out->throughput_mibps = 0.0;
        out->iops = 0.0;
    }

    out->p50_ms = out->p95_ms = out->p99_ms = 0.0;
    if (n == 0 || lat_ms == NULL) {
        return;
    }

    /* Sort a private copy so the caller's samples are left untouched. */
    sorted = (double *) malloc(n * sizeof(*sorted));
    if (sorted == NULL) {
        return;   /* percentiles stay 0 on OOM; totals above are still valid */
    }
    memcpy(sorted, lat_ms, n * sizeof(*sorted));
    qsort(sorted, n, sizeof(*sorted), ckv_cmp_double);

    out->p50_ms = storascan_percentile_ms(sorted, n, 50.0);
    out->p95_ms = storascan_percentile_ms(sorted, n, 95.0);
    out->p99_ms = storascan_percentile_ms(sorted, n, 99.0);

    free(sorted);
}
