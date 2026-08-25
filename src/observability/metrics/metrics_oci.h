/*
 * metrics/metrics_oci.h
 *
 * Per-process OCI distribution metrics (phase-104 D3.1): the fixed label
 * vocabularies for the mirror and registry surfaces plus the aggregate struct
 * embedded in the per-server metrics block. Split out of metrics.h so each
 * observability domain owns a focused header (the cluster is referenced only
 * by ngx_brix_metrics_t via the embedded `oci` member).
 *
 * INVARIANT #8 by construction: every label here is an enum index into a
 * compile-time name table. Repository names, tags and digests arrive FROM THE
 * WIRE and are unbounded, so none of them is ever a label value — the question
 * "which image is hot?" belongs to the access log, not to the scrape.
 */

#ifndef NGX_BRIX_METRICS_OCI_H
#define NGX_BRIX_METRICS_OCI_H

#include <ngx_core.h>

/* Which plane answered: the pull-through mirror or the local registry. */
typedef enum {
    BRIX_OCI_SURFACE_MIRROR = 0,
    BRIX_OCI_SURFACE_REGISTRY,
    BRIX_OCI_SURFACE_COUNT
} brix_oci_surface_metric_e;

/* Traffic class — the §0.7.1 endpoint matrix folded onto the seven routes the
 * classifier reports (brix_oci_class_str names these same tokens). */
typedef enum {
    BRIX_OCI_MCLASS_API = 0,
    BRIX_OCI_MCLASS_MANIFEST,
    BRIX_OCI_MCLASS_BLOB,
    BRIX_OCI_MCLASS_UPLOAD,
    BRIX_OCI_MCLASS_TAGS,
    BRIX_OCI_MCLASS_REFERRERS,
    BRIX_OCI_MCLASS_BAD,
    BRIX_OCI_MCLASS_COUNT
} brix_oci_mclass_metric_e;

/* How the request was answered. `local` is the mirror's own answer with no
 * upstream round-trip (GET /v2/, a 304); `refused` is a gate rejection (a push
 * at a read-only mirror, a grammar violation, a failed authz). */
typedef enum {
    BRIX_OCI_OUT_HIT = 0,
    BRIX_OCI_OUT_FILL,
    BRIX_OCI_OUT_LOCAL,
    BRIX_OCI_OUT_REFUSED,
    BRIX_OCI_OUT_ERROR,
    BRIX_OCI_OUT_COUNT
} brix_oci_outcome_metric_e;

/* Upstream token-dance dispositions. `cached` is an SHM-cache hit — the ratio
 * against `fetched` is what tells an operator whether the token zone is sized
 * for the pull rate. */
typedef enum {
    BRIX_OCI_TOKEN_CACHED = 0,
    BRIX_OCI_TOKEN_FETCHED,
    BRIX_OCI_TOKEN_FAILED,
    BRIX_OCI_TOKEN_COUNT
} brix_oci_token_metric_e;

/* Upstream failure buckets. Bucketed, not raw status codes: 401/403 separate
 * an expired token from a genuinely denied scope, 404 is an absent image, 429
 * is a rate-limited registry (the DockerHub pull-limit signal an operator
 * actually alerts on), and everything else folds into 5xx / other. */
typedef enum {
    BRIX_OCI_UPERR_401 = 0,
    BRIX_OCI_UPERR_403,
    BRIX_OCI_UPERR_404,
    BRIX_OCI_UPERR_429,
    BRIX_OCI_UPERR_5XX,
    BRIX_OCI_UPERR_OTHER,
    BRIX_OCI_UPERR_COUNT
} brix_oci_uperr_metric_e;

/* Delegated-pull (D16) proof dispositions. `cached` is an SHM proof-cache
 * hit; `granted` is a fresh upstream mint that verified; `denied` is the
 * upstream's refusal (surfaced downstream as the uniform 401); `error` is an
 * unreachable upstream (502 — the gate fails CLOSED, never open). */
typedef enum {
    BRIX_OCI_DELEG_CACHED = 0,
    BRIX_OCI_DELEG_GRANTED,
    BRIX_OCI_DELEG_DENIED,
    BRIX_OCI_DELEG_ERROR,
    BRIX_OCI_DELEG_COUNT
} brix_oci_deleg_metric_e;

typedef struct {
    ngx_atomic_t requests_total[BRIX_OCI_SURFACE_COUNT]
                               [BRIX_OCI_MCLASS_COUNT]
                               [BRIX_OCI_OUT_COUNT];
    ngx_atomic_t fill_bytes_total[BRIX_OCI_SURFACE_COUNT];
    ngx_atomic_t token_fetch_total[BRIX_OCI_TOKEN_COUNT];
    ngx_atomic_t verify_fail_total;      /* digest mismatches (quarantined)  */
    ngx_atomic_t upstream_errors_total[BRIX_OCI_UPERR_COUNT];
    ngx_atomic_t delegate_total[BRIX_OCI_DELEG_COUNT];
} ngx_brix_oci_metrics_t;

/* Map an upstream HTTP status onto its bucket (any status is accepted). */
brix_oci_uperr_metric_e brix_oci_uperr_bucket(ngx_uint_t status);

#endif /* NGX_BRIX_METRICS_OCI_H */
