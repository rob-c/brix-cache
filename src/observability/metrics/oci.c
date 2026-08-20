#include "metrics_internal.h"

/*
 * WHAT: Prometheus export for the OCI distribution plane (phase-104 D3.1).
 * WHY:  a registry mirror is judged on four numbers — how much of the pull
 *       traffic the cache absorbed, how many bytes still had to cross the WAN,
 *       whether the upstream token dance is working, and whether anything came
 *       back that did not hash to the digest it claimed. Everything here
 *       answers one of those.
 * HOW:  one three-label family (surface x class x outcome, all fixed enums —
 *       INVARIANT #8) written out row by row, plus four single-label/scalar
 *       families through the shared writer helpers. Image names, tags and
 *       digests never appear: they are unbounded wire data.
 */

static const char *brix_oci_surface_names[BRIX_OCI_SURFACE_COUNT] = {
    "mirror",
    "registry",
};

/* Mirrors brix_oci_class_str() (protocols/oci/oci_classify.c) — the two
 * upload routes share the "upload" token there and here. */
static const char *brix_oci_mclass_names[BRIX_OCI_MCLASS_COUNT] = {
    "api",
    "manifest",
    "blob",
    "upload",
    "tags",
    "referrers",
    "bad",
};

static const char *brix_oci_outcome_names[BRIX_OCI_OUT_COUNT] = {
    "hit",
    "fill",
    "local",
    "refused",
    "error",
};

static const char *brix_oci_token_names[BRIX_OCI_TOKEN_COUNT] = {
    "cached",
    "fetched",
    "failed",
};

static const char *brix_oci_uperr_names[BRIX_OCI_UPERR_COUNT] = {
    "401",
    "403",
    "404",
    "429",
    "5xx",
    "other",
};

brix_oci_uperr_metric_e
brix_oci_uperr_bucket(ngx_uint_t status)
{
    switch (status) {
    case 401: return BRIX_OCI_UPERR_401;
    case 403: return BRIX_OCI_UPERR_403;
    case 404: return BRIX_OCI_UPERR_404;
    case 429: return BRIX_OCI_UPERR_429;
    default:  break;
    }
    if (status >= 500 && status <= 599) {
        return BRIX_OCI_UPERR_5XX;
    }
    return BRIX_OCI_UPERR_OTHER;
}

/* The request family: 2 x 7 x 5 = 70 series, every index a compile-time enum.
 * Zero rows are emitted too — a family that appears only once traffic of that
 * shape arrives makes `rate()` on a fresh node return nothing rather than 0,
 * which reads as "no data" instead of "no pushes attempted". */
static void
oci_emit_requests(metrics_writer_t *mw, const ngx_brix_oci_metrics_t *o)
{
    ngx_uint_t s, c, k;

    mw_printf(mw,
        "# HELP brix_oci_requests_total OCI distribution requests by surface, "
        "traffic class and outcome\n"
        "# TYPE brix_oci_requests_total counter\n");

    for (s = 0; s < BRIX_OCI_SURFACE_COUNT; s++) {
        for (c = 0; c < BRIX_OCI_MCLASS_COUNT; c++) {
            for (k = 0; k < BRIX_OCI_OUT_COUNT; k++) {
                mw_printf(mw,
                    "brix_oci_requests_total"
                    "{surface=\"%s\",class=\"%s\",outcome=\"%s\"} %lu\n",
                    brix_oci_surface_names[s], brix_oci_mclass_names[c],
                    brix_oci_outcome_names[k],
                    (unsigned long) o->requests_total[s][c][k]);
            }
        }
    }
}

void
brix_export_oci_metrics(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_brix_oci_metrics_t *o = &shm->oci;

    oci_emit_requests(mw, o);

    mw_emit_labeled(mw, "brix_oci_fill_bytes_total",
        "bytes pulled from the upstream registry (WAN in)", "surface",
        brix_oci_surface_names, BRIX_OCI_SURFACE_COUNT, o->fill_bytes_total);

    mw_emit_labeled(mw, "brix_oci_token_fetch_total",
        "upstream Bearer-token acquisitions by disposition", "outcome",
        brix_oci_token_names, BRIX_OCI_TOKEN_COUNT, o->token_fetch_total);

    mw_emit_scalar(mw, "brix_oci_verify_fail_total",
        "fills whose bytes did not hash to the digest the request named "
        "(quarantined, never admitted)", &o->verify_fail_total);

    mw_emit_labeled(mw, "brix_oci_upstream_errors_total",
        "upstream registry error responses by status bucket", "status",
        brix_oci_uperr_names, BRIX_OCI_UPERR_COUNT, o->upstream_errors_total);
}
