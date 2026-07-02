#include "metrics_internal.h"

/*
 * WHAT: Prometheus export for the cvmfs:// protocol plane (phase-68).
 * WHY:  a CVMFS site cache is judged on exactly these numbers: request mix by
 *       traffic class, fill volume/failures, CAS verify rejections (the
 *       network-corruption evidence), origin failovers, and the LAN-out vs
 *       WAN-in byte split that yields the hit ratio.
 * HOW:  one labeled family (class is a fixed 4-value set — INVARIANT #8) plus
 *       scalar counters, all read lock-free from shm->cvmfs.
 */

static const char *xrootd_cvmfs_class_names[XROOTD_CVMFS_CLASS_COUNT] = {
    "cas",
    "manifest",
    "geo",
    "reject",
};

void
xrootd_export_cvmfs_metrics(metrics_writer_t *mw, ngx_xrootd_metrics_t *shm)
{
    ngx_xrootd_cvmfs_metrics_t *c = &shm->cvmfs;

    mw_emit_labeled(mw, "xrootd_cvmfs_requests_total",
        "CVMFS requests by traffic class", "class",
        xrootd_cvmfs_class_names, XROOTD_CVMFS_CLASS_COUNT,
        c->requests_total);

    mw_emit_scalar(mw, "xrootd_cvmfs_negative_hits_total",
        "404s absorbed by the per-worker negative cache",
        &c->negative_hits_total);
    mw_emit_scalar(mw, "xrootd_cvmfs_fills_total",
        "origin fills published to the cache", &c->fills_total);
    mw_emit_scalar(mw, "xrootd_cvmfs_fill_failures_total",
        "fills that failed definitively", &c->fill_failures_total);
    mw_emit_scalar(mw, "xrootd_cvmfs_verify_failures_total",
        "CAS verify mismatches (fill quarantined, never admitted)",
        &c->verify_failures_total);
    mw_emit_scalar(mw, "xrootd_cvmfs_origin_failovers_total",
        "read attempts that failed over to the next-ranked origin",
        &c->origin_failovers_total);
    mw_emit_scalar(mw, "xrootd_scvmfs_requests_total",
        "requests admitted by the scvmfs security preamble (EXPERIMENTAL)",
        &c->secure_requests_total);

    /* LAN out split by disposition + WAN in: the hit ratio and the
     * WAN-saved factor are one PromQL expression away. */
    mw_printf(mw,
        "# HELP xrootd_cvmfs_bytes_served_total bytes served to clients by cache disposition\n"
        "# TYPE xrootd_cvmfs_bytes_served_total counter\n"
        "xrootd_cvmfs_bytes_served_total{source=\"hit\"} %lu\n"
        "xrootd_cvmfs_bytes_served_total{source=\"fill\"} %lu\n",
        (unsigned long) c->bytes_served_hit_total,
        (unsigned long) c->bytes_served_fill_total);
    mw_emit_scalar(mw, "xrootd_cvmfs_origin_bytes_total",
        "bytes pulled from the Stratum-1 origins (WAN in)",
        &c->origin_bytes_total);
}
