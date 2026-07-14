#ifndef NGX_BRIX_METRICS_STREAM_INTERNAL_H
#define NGX_BRIX_METRICS_STREAM_INTERNAL_H

/*
 * stream_internal.h — private contract between the stream exporter's split
 * translation units (stream.c + stream_family.c).
 *
 * WHAT: declares the per-server-family emit helpers that live in
 *       stream_family.c but are driven from the top-level scrape sequence in
 *       stream.c (brix_export_prometheus_metrics). Each emits one or more
 *       Prometheus families as {port,auth}-labelled rows, one per in-use
 *       server slot, via the shared descriptor-table slot-scan emitter.
 * WHY:  stream.c was split for file-size hygiene; the exposition order stays
 *       frozen in the driver, so these helpers must be callable across the
 *       two files. Symbols used only within one file stay static there —
 *       only the driver-facing entry points are declared here.
 * HOW:  each helper takes the buffered writer `mw` and the read-only metrics
 *       SHM `shm`; counters are read lock-free (eventually consistent).
 */

#include "metrics_internal.h"

/* stream_family.c — per-server-slot ({port,auth}) Prometheus families, each
 * driven once from brix_export_prometheus_metrics() in exposition order. */
void  metrics_emit_config_generation(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm);
void  metrics_emit_connections(metrics_writer_t *mw, ngx_brix_metrics_t *shm);
void  metrics_emit_xfer_heap(metrics_writer_t *mw, ngx_brix_metrics_t *shm);
void  metrics_emit_bytes(metrics_writer_t *mw, ngx_brix_metrics_t *shm);
void  metrics_emit_wire_frames(metrics_writer_t *mw, ngx_brix_metrics_t *shm);
void  metrics_emit_fault_timeouts(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm);
void  metrics_emit_io_uring(metrics_writer_t *mw, ngx_brix_metrics_t *shm);
void  metrics_emit_path_depth(metrics_writer_t *mw, ngx_brix_metrics_t *shm);
void  metrics_emit_ssi(metrics_writer_t *mw, ngx_brix_metrics_t *shm);

#endif /* NGX_BRIX_METRICS_STREAM_INTERNAL_H */
