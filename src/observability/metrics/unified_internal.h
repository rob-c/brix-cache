#ifndef NGX_BRIX_METRICS_UNIFIED_INTERNAL_H
#define NGX_BRIX_METRICS_UNIFIED_INTERNAL_H

/*
 * unified_internal.h — private cross-file contract for the unified metrics
 * implementation (unified.c + unified_record.c + unified_export_io.c +
 * unified_export.c).
 *
 * WHAT: Declares the handful of symbols that the unified metrics
 *       implementation shares ACROSS its four .c files but that are NOT part
 *       of the public unified.h API: the two label tables the exporter indexes
 *       directly (auth + tpc-direction names), the latency-bucket bound table,
 *       the lock-free counter reader (brix_metric_value), the root:// legacy
 *       auth fold (brix_unified_legacy_auth), and the three per-family io
 *       emitters the exporter orchestrator fans out to.
 * WHY:  unified.c was a single 1076-line file spanning four concerns
 *       (classification, record mutators, io export, non-io export). Splitting
 *       it per concern keeps every file small and focused (coding-standards §1)
 *       but leaves a small set of file-scope symbols that must cross the new
 *       file boundary; those — and only those — are promoted from `static` to
 *       external linkage and declared here so the link stays resolved.
 * HOW:  Each .c in the family includes this header. The DEFINING file drops the
 *       `static` on the symbol; every other file sees only this declaration.
 *       Requires metrics_internal.h (metrics_writer_t, ngx_brix_metrics_t) and
 *       unified.h (brix_proto_t, BRIX_* label counts) — pulled in below.
 */

#include "metrics_internal.h"

/* Label tables the exporter indexes directly (defined in unified.c). */
extern const char *brix_unified_auth_names[BRIX_METRIC_AUTH_COUNT];
extern const char *brix_unified_tpc_direction_names[
    BRIX_METRIC_TPC_DIRECTION_COUNT];

/* Finite latency-bucket upper bounds in usec (defined in unified.c); shared by
 * the record hot path (bucket selection) and the exporter (le="…" rendering). */
extern const ngx_msec_t brix_latency_bounds[BRIX_IO_LATENCY_BUCKETS - 1];

/* Lock-free read of an atomic counter (fetch-add of 0) as unsigned long long.
 * Defined in unified_export_io.c; used by every exporter file. */
unsigned long long brix_metric_value(ngx_atomic_t *counter);

/* Export-time fold of the legacy per-server stream auth counters into one
 * unified auth cell (non-zero for root:// only). Defined in
 * unified_export_io.c; called from the auth exporter in unified_export.c. */
unsigned long long brix_unified_legacy_auth(ngx_brix_metrics_t *shm,
    brix_proto_t proto, ngx_uint_t method, ngx_uint_t status);

/* Per-family io exporters (defined in unified_export_io.c); called from the
 * brix_export_unified_metrics orchestrator in unified_export.c. */
void unified_emit_io_bytes(metrics_writer_t *mw, ngx_brix_metrics_t *shm);
void unified_emit_io_ops(metrics_writer_t *mw, ngx_brix_metrics_t *shm);
void unified_emit_io_latency(metrics_writer_t *mw, ngx_brix_metrics_t *shm);

#endif /* NGX_BRIX_METRICS_UNIFIED_INTERNAL_H */
