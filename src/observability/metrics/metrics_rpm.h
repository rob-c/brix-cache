/*
 * metrics/metrics_rpm.h
 *
 * Per-process RPM/dnf mirror metrics (phase-104 D15.9): the fixed label
 * vocabulary for the pull-through repository mirror plus the aggregate struct
 * embedded in the per-server metrics block. Split out of metrics.h for the
 * same reason metrics_oci.h is — one observability domain, one header.
 *
 * INVARIANT #8 by construction: the two labels are enum indices into
 * compile-time name tables. Repository paths, package names and checksums
 * arrive FROM THE WIRE and are unbounded, so none of them is ever a label —
 * "which package is hot?" is an access-log question, not a scrape question.
 */

#ifndef NGX_BRIX_METRICS_RPM_H
#define NGX_BRIX_METRICS_RPM_H

#include <ngx_core.h>

#include "protocols/rpm/rpm_classify.h"   /* BRIX_RPM_REQ_COUNT — one route
                                             vocabulary, shared with the gate */

/* How the request was answered. `local` is the mirror's own answer with no
 * upstream round-trip (a 304 to a revalidating dnf); `refused` is a gate
 * rejection (a write-class method, a path the grammar will not name). */
typedef enum {
    BRIX_RPM_OUT_HIT = 0,
    BRIX_RPM_OUT_FILL,
    BRIX_RPM_OUT_LOCAL,
    BRIX_RPM_OUT_REFUSED,
    BRIX_RPM_OUT_ERROR,
    BRIX_RPM_OUT_COUNT
} brix_rpm_outcome_metric_e;

typedef struct {
    ngx_atomic_t requests_total[BRIX_RPM_REQ_COUNT][BRIX_RPM_OUT_COUNT];
    ngx_atomic_t verify_fail_total;   /* repodata that did not hash to the
                                         checksum its own name carries       */
    ngx_atomic_t prefetch_total;      /* metadata objects warmed before any
                                         client asked (D15.10)               */
    ngx_atomic_t prefetch_fail_total; /* warm fills the origin did not serve  */
} ngx_brix_rpm_metrics_t;

#endif /* NGX_BRIX_METRICS_RPM_H */
