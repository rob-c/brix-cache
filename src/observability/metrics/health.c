/*
 * health.c — content handler for the `brix_health on;` location (phase-47 W2).
 *
 * WHAT: ngx_http_brix_health_handler() serves GET/HEAD /healthz as a small
 *   JSON document so an external load balancer or a Kubernetes liveness/
 *   readiness probe has a cheap endpoint to poll.  Liveness is implicit: if
 *   this worker can accept the connection and run the handler it returns 200;
 *   the `time`/`time_epoch` fields (built per request from nginx's cached
 *   clock) prove the answer is freshly generated, not replayed by a cache.
 *   `?verbose` adds cheap, non-secret readiness signals (metrics SHM mapped,
 *   worker pid, nginx version) plus the service surface: every bound listen
 *   socket (addr/port/plane/open, with auth + connection counters for root://
 *   listeners) and every registered export (path + backend).
 *
 * WHY: The module already exposes /metrics (scrape) and the dashboard, but
 *   neither is a clean probe target — /metrics is a large text body and the
 *   dashboard needs auth.  A dedicated 200/JSON endpoint keeps probes light and
 *   lets an operator wire `livenessProbe: GET /healthz` directly.  It lives in
 *   the metrics module (not a new .so) and mirrors the read-only SRR/metrics
 *   handlers: method-gated, body discarded, no request input affects output.
 *
 * HOW: classify ?verbose → build the JSON in the request pool with ngx_snprintf
 *   (no jansson; the document is tiny and fixed-shape) → set status/headers →
 *   send_header → output the single memory buffer.  HEAD stops after the header.
 *   Reads only process globals (ngx_pid) and the metrics SHM zone pointer; it
 *   never touches the request body and never emits a secret.
 */

#include <ngx_stream.h>                    /* ngx_stream_init_connection      */

#include "metrics_internal.h"
#include "fs/backend/cache/sd_cache.h"     /* unwrap to the http source (T16) */
#include "fs/backend/http/sd_http.h"       /* per-origin health snapshot      */
#include "fs/vfs/vfs_backend_registry.h"
#include "core/http/http_headers.h"
#include "core/compat/alloc_guard.h"
#include "core/compat/time.h"              /* brix_format_iso8601             */
#include "core/ident.h"


/* True when the request's query string contains the bare `verbose` flag. */
static ngx_uint_t
health_verbose_requested(ngx_http_request_t *r)
{
    if (r->args.len == 0) {
        return 0;
    }
    return ngx_strnstr(r->args.data, "verbose", r->args.len) != NULL ? 1 : 0;
}


/* ---- Which nginx plane owns a listening socket ----
 *
 * WHAT: Returns "http", "stream", or "other" for a bound listening socket.
 *
 * WHY: The endpoint list reports every bound socket; the plane tag is what
 *   lets a prober match a row to the protocol tables (root:// listeners are
 *   stream, WebDAV/S3/CVMFS/metrics are http) without knowing port layout.
 *
 * HOW: 1. Compare ls->handler against the two public init-connection entry
 *         points nginx binds at listen time.
 *      2. Anything else (no third family is configured today) is "other".
 */
static const char *
health_listener_layer(const ngx_listening_t *ls)
{
    if (ls->handler == ngx_http_init_connection) {
        return "http";
    }
    if (ls->handler == ngx_stream_init_connection) {
        return "stream";
    }
    return "other";
}


/* ---- SHM metrics slot for a stream listen port ----
 *
 * WHAT: Returns the in-use per-server metrics slot whose listen port equals
 *   `port`, or NULL when no stream server block owns that port.
 *
 * WHY: The slot already carries a root:// listener's identity (auth flavour)
 *   and its liveness evidence (connection counters); joining by port lets the
 *   endpoint list surface both without any new bookkeeping on the data path.
 *
 * HOW: 1. Linear scan of the fixed slot array (BRIX_METRICS_MAX_SERVERS).
 *      2. First slot with in_use set and a matching port wins (listen ports
 *         are unique across server blocks by construction).
 */
static ngx_brix_srv_metrics_t *
health_stream_slot(ngx_brix_metrics_t *m, ngx_uint_t port)
{
    ngx_uint_t  slot;

    if (m == NULL) {
        return NULL;
    }
    for (slot = 0; slot < BRIX_METRICS_MAX_SERVERS; slot++) {
        if (m->servers[slot].in_use && m->servers[slot].port == port) {
            return &m->servers[slot];
        }
    }
    return NULL;
}


/* ---- Append the ,"endpoints":[...] array (verbose) ----
 *
 * WHAT: Appends one JSON row per bound listening socket — address text, port,
 *   owning plane, and whether the fd is open — plus proto/auth/connection
 *   counters for stream listeners that own a metrics slot.  Returns the new
 *   write cursor (never past `last`; ngx_snprintf is bounds-clamped).
 *
 * WHY: This is the "which endpoints are still alive" half of the document: an
 *   open fd reported by a worker that answered this request is being polled by
 *   a live event loop, and the monotonic connection counters let a prober
 *   distinguish a quiet-but-alive port from a dead one across two polls.
 *
 * HOW: 1. Walk ngx_cycle->listening, the ground truth of bound sockets.
 *      2. Emit addr/port/layer/open for every socket.
 *      3. For stream sockets, join the SHM slot by port and append the root://
 *         identity and counters.
 */
static u_char *
health_append_endpoints(u_char *p, u_char *last, ngx_brix_metrics_t *m)
{
    ngx_cycle_t      *cycle = (ngx_cycle_t *) ngx_cycle;
    ngx_listening_t  *ls = cycle->listening.elts;
    ngx_uint_t        i;
    int               first = 1;

    p = ngx_snprintf(p, (size_t) (last - p), ",\"endpoints\":[");

    for (i = 0; i < cycle->listening.nelts; i++) {
        ngx_uint_t                port;
        ngx_brix_srv_metrics_t  *slot;

        port = (ngx_uint_t) ngx_inet_get_port(ls[i].sockaddr);
        p = ngx_snprintf(p, (size_t) (last - p),
                "%s{\"addr\":\"%V\",\"port\":%ui,\"layer\":\"%s\","
                "\"open\":%s",
                first ? "" : ",", &ls[i].addr_text, port,
                health_listener_layer(&ls[i]),
                ls[i].fd != (ngx_socket_t) -1 ? "true" : "false");
        first = 0;

        slot = health_stream_slot(m, port);
        if (slot != NULL) {
            p = ngx_snprintf(p, (size_t) (last - p),
                    ",\"proto\":\"root\",\"auth\":\"%s\","
                    "\"connections_active\":%uL,"
                    "\"connections_total\":%uL",
                    slot->auth,
                    (uint64_t) slot->connections_active,
                    (uint64_t) slot->connections_total);
        }
        p = ngx_snprintf(p, (size_t) (last - p), "}");
    }
    return ngx_snprintf(p, (size_t) (last - p), "]");
}


/* ---- Append the ,"exports":[...] array (verbose) ----
 *
 * WHAT: Appends one row per registered export — its canonical root path and
 *   the configured storage backend.  Returns the new write cursor.
 *
 * WHY: The endpoint rows say which ports answer; the export rows say which
 *   namespace paths those ports serve — together they are the whole service
 *   surface.  Only config-time identity is emitted: no credentials, no origin
 *   hosts (those stay in cvmfs_origins) and no live probing.
 *
 * HOW: 1. Iterate the registry (config-time count, stable per process).
 *      2. Emit root_canon + backend for each entry export_info() fills.
 */
static u_char *
health_append_exports(u_char *p, u_char *last)
{
    ngx_uint_t  i, n_exports = brix_vfs_backend_export_count();
    int         first = 1;

    p = ngx_snprintf(p, (size_t) (last - p), ",\"exports\":[");
    for (i = 0; i < n_exports; i++) {
        brix_vfs_backend_info_t  info;

        if (brix_vfs_backend_export_info(i, &info) != NGX_OK) {
            continue;
        }
        p = ngx_snprintf(p, (size_t) (last - p),
                "%s{\"path\":\"%s\",\"backend\":\"%s\"}",
                first ? "" : ",", info.root_canon, info.backend);
        first = 0;
    }
    return ngx_snprintf(p, (size_t) (last - p), "]");
}


/* ---- Verbose buffer headroom for the endpoint/export arrays ----
 *
 * WHAT: Returns the extra bytes the verbose document needs on top of the
 *   fixed base capacity.
 *
 * WHY: The base document is fixed-shape, but listeners and exports scale with
 *   the deployment; sizing from the live counts keeps ngx_snprintf's clamped
 *   writes from truncating the JSON mid-array on a large fleet.
 *
 * HOW: 1. 256 bytes bounds a listener row (NGX_SOCKADDR_STRLEN plus the fixed
 *         keys and two 20-digit counters).
 *      2. Export rows are path-dominated: root strlen + fixed key overhead.
 */
static size_t
health_verbose_extra(void)
{
    ngx_cycle_t *cycle = (ngx_cycle_t *) ngx_cycle;
    ngx_uint_t   i, n_exports = brix_vfs_backend_export_count();
    size_t       extra;

    extra = 256 * cycle->listening.nelts;
    for (i = 0; i < n_exports; i++) {
        brix_vfs_backend_info_t  info;

        if (brix_vfs_backend_export_info(i, &info) == NGX_OK) {
            extra += ngx_strlen(info.root_canon) + 64;
        }
    }
    return extra;
}


/*
 * Render the health document into a pool buffer.  Non-verbose is a fixed
 * liveness line; verbose appends the readiness object.  Returns the buffer (and
 * its length via *len), or NULL on allocation failure.
 */
static u_char *
health_build_json(ngx_http_request_t *r, ngx_uint_t verbose, size_t *len)
{
    size_t                cap = 2048;
    u_char               *buf;
    u_char               *p;
    const char           *shm_state;
    char                  now_iso[32];
    ngx_brix_metrics_t *m;
    ngx_uint_t            generation = 0;
    uint64_t             config_hash = 0;

    if (verbose) {
        cap += health_verbose_extra();
    }
    BRIX_PNALLOC_OR_RETURN(buf, r->pool, cap, NULL);

    /* Built per request (not a compile-time constant), so two polls that
     * return different times prove the handler — not a cache — answered. */
    brix_format_iso8601(ngx_time(), now_iso, sizeof(now_iso));

    /* The metrics SHM zone is created at config time (metrics/config.c) and is
     * the module's shared state — "mapped" once a stream server block exists.
     * When mapped it also carries the config/reload fingerprint published by the
     * master in init_module (brix_config_version_publish). */
    m = (ngx_brix_shm_zone != NULL) ? ngx_brix_shm_zone->data : NULL;
    if (m != NULL) {
        generation  = (ngx_uint_t) m->config_generation;
        config_hash = m->config_hash;
    }

    if (!verbose) {
        /* config_generation/config_version are cheap and reload-relevant, so
         * they ride on the default (non-verbose) document: a probe can confirm a
         * reload took effect without opting into the heavier readiness block. */
        p = ngx_snprintf(buf, cap,
                         "{\"status\":\"ok\",\"service\":\"" BRIX_SERVER_NAME "\","
                         "\"version\":\"" BRIX_SERVER_VERSION "\","
                         "\"time\":\"%s\",\"time_epoch\":%T,"
                         "\"config_generation\":%ui,"
                         "\"config_version\":\"%016xL\"}\n",
                         now_iso, ngx_time(), generation, config_hash);
        *len = (size_t) (p - buf);
        return buf;
    }

    shm_state = (m != NULL) ? "mapped" : "unmapped";

    p = ngx_snprintf(buf, cap,
                     "{\"status\":\"ok\",\"service\":\"" BRIX_SERVER_NAME "\","
                     "\"version\":\"" BRIX_SERVER_VERSION "\","
                     "\"time\":\"%s\",\"time_epoch\":%T,"
                     "\"config_generation\":%ui,"
                     "\"config_version\":\"%016xL\","
                     "\"checks\":{"
                     "\"metrics_shm\":\"%s\","
                     "\"worker_pid\":%P,"
                     "\"nginx_version\":\"%s\""
                     "}",
                     now_iso, ngx_time(), generation, config_hash,
                     shm_state, ngx_pid, NGINX_VERSION);

    /* The service surface: every bound listen socket, then every export the
     * VFS registry knows.  Both read config-time/process state only. */
    p = health_append_endpoints(p, buf + cap, m);
    p = health_append_exports(p, buf + cap);

    /* phase-68: per-origin health of every http-backed export (the CVMFS
     * Stratum-1 sets). fail_score is the sd_http EWMA (0 = healthy). */
    {
        ngx_uint_t  i, n_exports = brix_vfs_backend_export_count();
        int         first = 1;

        p = ngx_snprintf(p, (size_t) (buf + cap - p), ",\"cvmfs_origins\":[");
        for (i = 0; i < n_exports; i++) {
            brix_vfs_backend_info_t  info;
            brix_sd_instance_t      *inst;
            char                       hosts[SD_HTTP_EP_MAX][256];
            int                        ports[SD_HTTP_EP_MAX];
            int                        scores[SD_HTTP_EP_MAX];
            int                        j, n;

            if (brix_vfs_backend_export_info(i, &info) != NGX_OK
                || ngx_strcmp(info.backend, "http") != 0)
            {
                continue;
            }
            inst = brix_vfs_backend_resolve(info.root_canon,
                                              r->connection->log);
            while (inst != NULL
                   && ngx_strcmp(inst->driver->name, "http") != 0)
            {
                inst = brix_sd_cache_source_instance(inst);
            }
            n = sd_http_health_snapshot(inst, hosts, ports, scores,
                                        SD_HTTP_EP_MAX);
            for (j = 0; j < n; j++) {
                p = ngx_snprintf(p, (size_t) (buf + cap - p),
                        "%s{\"host\":\"%s\",\"port\":%d,\"fail_score\":%d}",
                        first ? "" : ",", hosts[j], ports[j], scores[j]);
                first = 0;
            }
        }
        p = ngx_snprintf(p, (size_t) (buf + cap - p), "]}\n");
    }
    *len = (size_t) (p - buf);
    return buf;
}


ngx_int_t
ngx_http_brix_health_handler(ngx_http_request_t *r)
{
    ngx_http_brix_metrics_loc_conf_t *lcf;
    ngx_int_t                           rc;
    u_char                             *buf;
    size_t                              len;
    ngx_buf_t                          *b;
    ngx_chain_t                         out;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_metrics_module);
    if (!lcf->health) {
        return NGX_DECLINED;
    }

    /* AGPL-3.0 sec.13: offer remote users the source (X-Source header). */
    brix_http_source_offer(r);

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    buf = health_build_json(r, health_verbose_requested(r), &len);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) len;

    {
        ngx_str_t ct = ngx_string("application/json");
        r->headers_out.content_type         = ct;
        r->headers_out.content_type_len     = ct.len;
        r->headers_out.content_type_lowcase = NULL;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    BRIX_PCALLOC_OR_RETURN(b, r->pool, sizeof(*b), NGX_HTTP_INTERNAL_SERVER_ERROR);
    b->pos      = b->start = buf;
    b->last     = b->end   = buf + len;
    b->memory   = 1;
    b->last_buf = 1;

    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}
