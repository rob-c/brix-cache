/*
 * api_cvmfs.c - cvmfs:// site-cache section of the dashboard JSON API.
 *
 * WHAT: serialise the phase-68 cvmfs SHM metrics block (shm->cvmfs) as the
 *       "cvmfs" snapshot section and the /xrootd/api/v1/cvmfs endpoint:
 *       aggregate counters (request mix by class, LAN-out vs WAN-in bytes,
 *       fills/failures/verify/negative-hits/failovers) plus the bounded
 *       per-repository and per-upstream slot tables.
 * WHY:  a CVMFS site cache is judged on its hit ratio and its WAN-saved
 *       factor; the Prometheus exporter (metrics/cvmfs.c) has the numbers but
 *       the dashboard showed only a single bytes-out total. This file gives
 *       the dashboard UI the same view, one JSON fetch away.
 * HOW:  read lock-free from the metrics SHM zone exactly like
 *       dashboard_fill_cache; slot tables follow the exporter's rules -
 *       only READY slots, and a claim-race duplicate name is emitted once
 *       (lowest index wins). Repo fqrns and upstream hosts arrive from the
 *       wire/config, so the anonymous view redacts them (cluster-host
 *       pattern) while keeping the counters.
 */
#include "dashboard_api_internal.h"


static const char *cvmfs_json_class_names[BRIX_CVMFS_CLASS_COUNT] = {
    "cas",
    "manifest",
    "geo",
    "reject",
};


/* 1 iff an EARLIER READY repo slot carries the same name (claim-race
 * duplicate - mirror of the exporter's lowest-index convergence rule). */
static int
cvmfs_json_repo_is_dup(const ngx_brix_cvmfs_repo_metrics_t *repos,
    ngx_uint_t i)
{
    ngx_uint_t j;

    for (j = 0; j < i; j++) {
        if (repos[j].state == BRIX_CVMFS_REPO_READY
            && strcmp(repos[j].name, repos[i].name) == 0)
        {
            return 1;
        }
    }
    return 0;
}


/* 1 iff an EARLIER READY upstream slot carries the same name. */
static int
cvmfs_json_upstream_is_dup(const ngx_brix_cvmfs_upstream_metrics_t *ups,
    ngx_uint_t i)
{
    ngx_uint_t j;

    for (j = 0; j < i; j++) {
        if (ups[j].state == BRIX_CVMFS_REPO_READY
            && strcmp(ups[j].name, ups[i].name) == 0)
        {
            return 1;
        }
    }
    return 0;
}


/*
 * Build the {"cas":n,"manifest":n,"geo":n,"reject":n} request-mix object from
 * one per-class counter array. Returns NULL on OOM (json_object_set_new in
 * the caller absorbs a NULL child).
 */
static json_t *
cvmfs_json_requests(const ngx_atomic_t counts[BRIX_CVMFS_CLASS_COUNT])
{
    json_t     *obj = json_object();
    ngx_uint_t  cls;

    if (!obj) { return NULL; }
    for (cls = 0; cls < BRIX_CVMFS_CLASS_COUNT; cls++) {
        json_object_set_new(obj, cvmfs_json_class_names[cls],
            json_integer((json_int_t) counts[cls]));
    }
    return obj;
}


/*
 * Serialise one READY per-repository slot. The fqrn arrives from the wire,
 * so the anonymous view replaces it with "[redacted]" (counters stay).
 */
static json_t *
cvmfs_json_repo(const ngx_brix_cvmfs_repo_metrics_t *rm, ngx_uint_t redact)
{
    json_t *obj = json_object();

    if (!obj) { return NULL; }
    json_object_set_new(obj, "name",
        json_string(redact ? "[redacted]" : rm->name));
    json_object_set_new(obj, "requests", cvmfs_json_requests(rm->requests_total));
    json_object_set_new(obj, "files_accessed_total",
        json_integer((json_int_t) rm->files_accessed_total));
    json_object_set_new(obj, "cache_hits_total",
        json_integer((json_int_t) rm->cache_hits_total));
    json_object_set_new(obj, "cache_misses_total",
        json_integer((json_int_t) rm->cache_misses_total));
    json_object_set_new(obj, "fills_total",
        json_integer((json_int_t) rm->fills_total));
    json_object_set_new(obj, "fill_failures_total",
        json_integer((json_int_t) rm->fill_failures_total));
    json_object_set_new(obj, "verify_failures_total",
        json_integer((json_int_t) rm->verify_failures_total));
    json_object_set_new(obj, "negative_hits_total",
        json_integer((json_int_t) rm->negative_hits_total));
    json_object_set_new(obj, "bytes_served_hit_total",
        json_integer((json_int_t) rm->bytes_served_hit_total));
    json_object_set_new(obj, "bytes_served_fill_total",
        json_integer((json_int_t) rm->bytes_served_fill_total));
    json_object_set_new(obj, "origin_bytes_total",
        json_integer((json_int_t) rm->origin_bytes_total));
    return obj;
}


/*
 * Serialise one READY per-upstream (Stratum-1) slot. fill_duration_ms_sum /
 * fill_duration_count carry the histogram aggregate so the UI can show an
 * average fill time; the full le-bucket histogram stays Prometheus-only.
 */
static json_t *
cvmfs_json_upstream(const ngx_brix_cvmfs_upstream_metrics_t *u,
    ngx_uint_t redact)
{
    json_t *obj = json_object();

    if (!obj) { return NULL; }
    json_object_set_new(obj, "name",
        json_string(redact ? "[redacted]" : u->name));
    json_object_set_new(obj, "requests_total",
        json_integer((json_int_t) u->requests_total));
    json_object_set_new(obj, "fills_total",
        json_integer((json_int_t) u->fills_total));
    json_object_set_new(obj, "fill_failures_total",
        json_integer((json_int_t) u->fill_failures_total));
    json_object_set_new(obj, "failovers_total",
        json_integer((json_int_t) u->failovers_total));
    json_object_set_new(obj, "origin_bytes_total",
        json_integer((json_int_t) u->origin_bytes_total));
    json_object_set_new(obj, "fill_duration_ms_sum",
        json_integer((json_int_t) u->dur_sum_ms));
    json_object_set_new(obj, "fill_duration_count",
        json_integer((json_int_t) u->dur_count));
    return obj;
}


/*
 * dashboard_fill_cvmfs - adds the cvmfs aggregate counters plus the "repos"
 * and "upstreams" arrays directly to `target`.  Called with target=root for
 * v1/cvmfs (flat shape) and with target=sub-object for the snapshot (nested
 * under "cvmfs").  "enabled" is inferred from work done (any request seen),
 * matching the write_through inference in dashboard_fill_cache - the cvmfs
 * module's conf lives in another module and is not visible here.
 */
void
dashboard_fill_cvmfs(json_t *target, ngx_uint_t redact)
{
    ngx_brix_metrics_t       *met;
    ngx_brix_cvmfs_metrics_t *c;
    json_t                     *repos, *ups;
    ngx_uint_t                  i;
    uint64_t                    requests = 0;

    if (ngx_brix_shm_zone == NULL
        || ngx_brix_shm_zone->data == NULL
        || ngx_brix_shm_zone->data == (void *) 1)
    {
        json_object_set_new(target, "enabled",   json_false());
        json_object_set_new(target, "repos",     json_array());
        json_object_set_new(target, "upstreams", json_array());
        return;
    }

    met = ngx_brix_shm_zone->data;
    c   = &met->cvmfs;

    json_object_set_new(target, "requests", cvmfs_json_requests(c->requests_total));
    for (i = 0; i < BRIX_CVMFS_CLASS_COUNT; i++) {
        requests += (uint64_t) c->requests_total[i];
    }
    json_object_set_new(target, "enabled", requests ? json_true() : json_false());

    json_object_set_new(target, "negative_hits_total",
        json_integer((json_int_t) c->negative_hits_total));
    json_object_set_new(target, "fills_total",
        json_integer((json_int_t) c->fills_total));
    json_object_set_new(target, "fill_failures_total",
        json_integer((json_int_t) c->fill_failures_total));
    json_object_set_new(target, "verify_failures_total",
        json_integer((json_int_t) c->verify_failures_total));
    json_object_set_new(target, "origin_failovers_total",
        json_integer((json_int_t) c->origin_failovers_total));
    json_object_set_new(target, "secure_requests_total",
        json_integer((json_int_t) c->secure_requests_total));

    /* LAN out split by disposition + WAN in: hit ratio and WAN-saved factor
     * are one division away for the UI. */
    json_object_set_new(target, "bytes_served_hit_total",
        json_integer((json_int_t) c->bytes_served_hit_total));
    json_object_set_new(target, "bytes_served_fill_total",
        json_integer((json_int_t) c->bytes_served_fill_total));
    json_object_set_new(target, "origin_bytes_total",
        json_integer((json_int_t) c->origin_bytes_total));

    repos = json_array();
    if (repos) {
        for (i = 0; i < BRIX_CVMFS_REPO_SLOTS; i++) {
            const ngx_brix_cvmfs_repo_metrics_t *rm = &c->repos[i];

            if (rm->state != BRIX_CVMFS_REPO_READY
                || cvmfs_json_repo_is_dup(c->repos, i))
            {
                continue;
            }
            json_array_append_new(repos, cvmfs_json_repo(rm, redact));
        }
    }
    json_object_set_new(target, "repos", repos);

    ups = json_array();
    if (ups) {
        for (i = 0; i < BRIX_CVMFS_UPSTREAM_SLOTS; i++) {
            const ngx_brix_cvmfs_upstream_metrics_t *u = &c->upstreams[i];

            if (u->state != BRIX_CVMFS_REPO_READY
                || cvmfs_json_upstream_is_dup(c->upstreams, i))
            {
                continue;
            }
            json_array_append_new(ups, cvmfs_json_upstream(u, redact));
        }
    }
    json_object_set_new(target, "upstreams", ups);
}


/*
 * Top-level builder for GET /xrootd/api/v1/cvmfs - the flat single-section
 * document (schema envelope + anonymous flag + the cvmfs section fields).
 */
json_t *
dashboard_build_v1_cvmfs(int64_t now_ms,
    const ngx_http_brix_dashboard_loc_conf_t *conf, ngx_uint_t redact)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);

    if (!root) { return NULL; }
    json_object_set_new(root, "anonymous", redact ? json_true() : json_false());
    dashboard_fill_cvmfs(root, redact);
    return root;
}
