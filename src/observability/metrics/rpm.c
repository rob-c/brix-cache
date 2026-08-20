#include "metrics_internal.h"

/*
 * WHAT: Prometheus export for the RPM/dnf pull-through mirror (phase-104
 *       D15.9).
 * WHY:  a package mirror is judged on two numbers: how much of the dnf
 *       traffic it absorbed without touching the WAN, and whether any
 *       metadata came back that did not hash to the checksum its own name
 *       carries. The first is the request family split by route class — the
 *       repomd/metadata/package split is exactly the split an operator sizing
 *       a mirror cares about — and the second is the verify counter, which
 *       should read zero forever and is an alert the day it does not.
 * HOW:  one two-label family (class x outcome, both fixed enums — INVARIANT
 *       #8) plus one scalar, through the shared writer helpers.
 */

/* Mirrors brix_rpm_class_str() (protocols/rpm/rpm_classify.c). */
static const char *brix_rpm_class_names[BRIX_RPM_REQ_COUNT] = {
    "repomd",
    "metadata",
    "package",
    "aux",
    "bad",
};

static const char *brix_rpm_outcome_names[BRIX_RPM_OUT_COUNT] = {
    "hit",
    "fill",
    "local",
    "refused",
    "error",
};

void
brix_export_rpm_metrics(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_brix_rpm_metrics_t *p = &shm->rpm;
    ngx_uint_t              c, k;

    mw_printf(mw,
        "# HELP brix_rpm_requests_total RPM repository mirror requests by "
        "object class and outcome\n"
        "# TYPE brix_rpm_requests_total counter\n");

    /* 5 x 5 = 25 series, every index a compile-time enum. Zero rows are
     * emitted too, so `rate()` on a fresh mirror reads 0 rather than "no
     * data" — the difference between a quiet mirror and a broken scrape. */
    for (c = 0; c < BRIX_RPM_REQ_COUNT; c++) {
        for (k = 0; k < BRIX_RPM_OUT_COUNT; k++) {
            mw_printf(mw,
                "brix_rpm_requests_total{class=\"%s\",outcome=\"%s\"} %lu\n",
                brix_rpm_class_names[c], brix_rpm_outcome_names[k],
                (unsigned long) p->requests_total[c][k]);
        }
    }

    mw_emit_scalar(mw, "brix_rpm_verify_fail_total",
        "repodata fills whose bytes did not hash to the checksum their own "
        "name carries (quarantined, never admitted)", &p->verify_fail_total);

    /* The warm-set counters answer one question — was the speculation worth
     * it? — and they answer it as a pair: warmed objects are round trips a
     * client did not wait for, failures are round trips nobody wanted. */
    mw_emit_scalar(mw, "brix_rpm_prefetch_total",
        "repodata objects (primary, filelists) warmed into the cache after a "
        "new repomd.xml named them, before any client asked",
        &p->prefetch_total);

    mw_emit_scalar(mw, "brix_rpm_prefetch_fail_total",
        "warm repodata fills the origin did not serve (the client pays the "
        "miss it would have paid anyway)", &p->prefetch_fail_total);
}
