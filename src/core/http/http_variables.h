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

/*
 * The cache-status vocabulary reported by $brix_cache_status.
 *
 * Deliberately nginx's own $upstream_cache_status spelling wherever the
 * semantics correspond, so an operator's existing dashboards and log parsers
 * work unchanged. BRIX_CACHE_STATUS_NEGHIT is the one brix extension: a
 * negative-cache hit has no nginx equivalent and must NOT be overloaded onto
 * BYPASS, which means something else entirely.
 */
typedef enum {
    BRIX_CACHE_STATUS_NONE = 0,   /* no cache decision was reached: "-"      */
    BRIX_CACHE_STATUS_HIT,        /* served from cache                       */
    BRIX_CACHE_STATUS_MISS,       /* went to origin and populated            */
    BRIX_CACHE_STATUS_BYPASS,     /* cache deliberately not consulted        */
    BRIX_CACHE_STATUS_NEGHIT      /* negative-cache hit (brix extension)     */
} brix_cache_status_e;

/* The wire spelling for a status; always a static string, never pool memory,
 * so a variable handler can hand it straight to nginx at log time. */
const char *brix_cache_status_name(brix_cache_status_e status);

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

#endif /* BRIX_CORE_HTTP_VARIABLES_H */
