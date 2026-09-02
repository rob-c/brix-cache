/*
 * http_variables.h — the brix HTTP nginx-variable surface (phase 106 W1).
 *
 * WHAT: Declares brix_http_add_variables(), the single registration entry point
 *       for every `$brix_*` variable the HTTP planes expose, plus the shared
 *       cache-status vocabulary the planes report through it.
 *
 * WHY:  Variables are how an operator's existing nginx knowledge reaches brix
 *       state: log_format, map, if, add_header, split_clients and
 *       limit_req_zone all consume variables and none of them can be taught
 *       about brix any other way. Registration is owned by the COMMON http
 *       module (src/core/config/http_common.c preconfiguration) rather than by
 *       a protocol module, so one registration serves webdav/s3/cvmfs/oci/rpm
 *       — the same "bare name ⇒ common owner" thesis phases 101/105
 *       established for directives. Registering from a protocol module would
 *       also make the variable's existence depend on that module being loaded,
 *       which is a live hazard for dynamic (load_module) builds.
 *
 * HOW:  brix_http_add_variables() is called once from the common module's
 *       preconfiguration hook and registers the whole set. Per-variable
 *       get_handlers live next to the state they read; handlers that read
 *       protocol request-ctx state probe each brix module in turn exactly as
 *       $brix_protocol already does.
 */
#ifndef BRIX_CORE_HTTP_VARIABLES_H
#define BRIX_CORE_HTTP_VARIABLES_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* The cache-status vocabulary (brix_cache_status_e) and its name function
 * (brix_metric_cache_status_name) live in observability/metrics/unified.h —
 * the shared vocabulary home — since phase-110 W1: the SAME word must come out
 * of both planes' $brix_cache_status, the JSON access log and the Prometheus
 * label, so no HTTP header may own it. */
#include "observability/metrics/unified.h"

/* Register every $brix_* HTTP variable. Called from the common HTTP module's
 * preconfiguration. */
ngx_int_t brix_http_add_variables(ngx_conf_t *cf);

/*
 * Bind the request's I/O monitor onto a data-plane VFS ctx so the observer can
 * fold bytes/latency/page-CRC into it for $brix_bytes_served /
 * $brix_backend_time / $brix_checksum. Call from the HTTP data-plane ctx
 * builders (webdav_vfs_ctx_build_data, s3 GET/PUT ctx), which run on the EVENT
 * LOOP — never from an offloaded (thread) ctx build, as this may allocate on
 * r->pool. Idempotent and safe on NULL args. Forward-declared brix_vfs_ctx_s so
 * the header does not pull in the VFS surface.
 */
struct brix_vfs_ctx_s;
void brix_http_monitor_bind(ngx_http_request_t *r, struct brix_vfs_ctx_s *vctx);

/*
 * Record the client-facing served-byte count for $brix_bytes_served. Call from
 * the serve-metrics site with brix_http_serve_result_t.bytes_sent — the serve
 * is zero-copy (sendfile) and never reaches the per-op VFS observer, so this is
 * the authoritative byte source. No-op if the request bound no monitor or bytes
 * <= 0. Safe on the event loop (the serve path); never allocates.
 */
void brix_http_monitor_record_served(ngx_http_request_t *r, off_t bytes);

/*
 * Record the file checksum this plane REPORTED to the client for
 * $brix_checksum, as the canonical lowercase algorithm name and hex digits
 * (brix_integrity_info_t.alg_name / .hex — the same fields the WebDAV Digest
 * header and the root kXR_Qcksum reply are built from). Rendered "alg:hex".
 * No-op if the request bound no monitor. Event-loop only; never allocates.
 */
void brix_http_monitor_record_checksum(ngx_http_request_t *r, const char *alg,
    const char *hex);

#endif /* BRIX_CORE_HTTP_VARIABLES_H */
