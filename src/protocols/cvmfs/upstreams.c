/* upstreams.c — bounded lazy per-upstream backend registry (proxy mode).
 *
 * WHAT: maps (host, port) → a synthetic VFS backend export built once per
 *       worker and reused; the entry's cache store lives under the
 *       "<host>_<port>" subtree so objects from different Stratum-1s can
 *       never alias in the store.
 * WHY:  proxy mode serves "whatever allowed upstream the client asked for";
 *       the tier machinery is driven entirely by the registry entry, so a
 *       per-upstream entry is the whole integration.
 * HOW:  per-worker fixed array (upstream_max <= CVMFS_UP_MAX), linear scan —
 *       a site talks to a handful of Stratum-1s. No eviction: exhaustion is
 *       a config error (allowlist bigger than upstream_max) surfaced loudly.
 *       Registration + resolve run on the event loop only.
 */
#include "cvmfs.h"
#include "fs/vfs/vfs_backend_registry.h"

#define CVMFS_UP_MAX 16

typedef struct {
    char                  host[128];
    in_port_t             port;
    char                  up_root[256];        /* synthetic registry key    */
    brix_sd_instance_t *inst;
} cvmfs_upstream_slot;

/* Per-worker registry (deliberately worker-local: the entry table it feeds
 * is per-process after fork, and a handful of upstreams per worker is the
 * whole population). */
static cvmfs_upstream_slot  cvmfs_ups[CVMFS_UP_MAX];
static ngx_uint_t           cvmfs_ups_n;

brix_sd_instance_t *
brix_cvmfs_upstream_get(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, const ngx_str_t *host,
    in_port_t port, const char **up_root_out, ngx_uint_t *status)
{
    ngx_uint_t            i, cap;
    cvmfs_upstream_slot  *s;
    char                  suffix[160];
    brix_sd_instance_t *inst;
    int                   n;

    for (i = 0; i < cvmfs_ups_n; i++) {
        s = &cvmfs_ups[i];
        if (s->port == port && ngx_strlen(s->host) == host->len
            && ngx_strncasecmp((u_char *) s->host, host->data, host->len) == 0)
        {
            *up_root_out = s->up_root;
            return s->inst;
        }
    }

    cap = ngx_min(lcf->cvmfs.upstream_max, CVMFS_UP_MAX);
    if (cvmfs_ups_n >= cap || host->len >= sizeof(cvmfs_ups[0].host)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "cvmfs: upstream registry full (%ui slots)\n"
            "  cause: more distinct Stratum-1 authorities than "
            "brix_cvmfs_upstream_max\n"
            "  fix:   raise brix_cvmfs_upstream_max or trim "
            "brix_cvmfs_upstream_allow", cap);
        *status = NGX_HTTP_SERVICE_UNAVAILABLE;
        return NULL;
    }

    s = &cvmfs_ups[cvmfs_ups_n];
    ngx_memcpy(s->host, host->data, host->len);
    s->host[host->len] = '\0';
    s->port = port;

    /* Synthetic registry key: ALWAYS per-upstream — each Stratum-1 is a
     * distinct fetch origin (a distinct backend instance). */
    n = snprintf(s->up_root, sizeof(s->up_root), "/#cvmfs-up/%s:%u",
                 s->host, (unsigned) port);
    if (n < 0 || (size_t) n >= sizeof(s->up_root)) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }

    /* Cache store subtree. Default (per-upstream): each origin caches under its
     * own "/host_port" subtree — safe isolation for an arbitrary proxy target.
     * shared_cache: ALL upstreams cache under the SAME subtree (empty suffix),
     * so an object filled via one Stratum-1 is a HIT for a request naming any
     * other. This is correct for CVMFS because the request key is the logical
     * "/cvmfs/<repo>/..." path (upstream-independent) and CAS objects are
     * content-addressed (byte-identical across replicas); manifests are the same
     * signed metadata. It collapses the client's cross-server failover storm
     * into one fill. verify-on-fill (brix_cache_verify cvmfs-cas) keeps a
     * mis-serving origin from poisoning the shared entry. */
    if (lcf->cvmfs.shared_cache) {
        suffix[0] = '\0';
    } else {
        (void) snprintf(suffix, sizeof(suffix), "/%s_%u", s->host,
                        (unsigned) port);
    }

    if (brix_vfs_backend_register_http_upstream(s->up_root,
            lcf->common.root_canon, s->host, (int) port, /* tls */ 0,
            suffix) != NGX_OK)
    {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }
    inst = brix_vfs_backend_resolve(s->up_root, r->connection->log);
    if (inst == NULL) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }
    s->inst = inst;
    cvmfs_ups_n++;
    *up_root_out = s->up_root;

    /* First time this worker sees this Stratum-1: record it so the origin
     * decisions that follow (which host served, any failover) can be tied
     * back to a concrete upstream. */
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "cvmfs: proxy-mode upstream registered %s:%ui (slot %ui/%ui, store %s)",
        s->host, (ngx_uint_t) port, cvmfs_ups_n, cap, s->up_root);
    return inst;
}
