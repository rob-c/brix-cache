/*
 * proxy_pool.h — Phase 23 dynamic WebDAV proxy backend pool (shared memory).
 *
 * Enabled per-location with `brix_webdav_proxy_dynamic on`.  Unlike the
 * Phase 21 config-pool backend array (immutable until reload, per-worker COW),
 * this pool lives in a shared-memory zone so the REST admin API can add,
 * remove, drain, and undrain backends at runtime across all workers.
 *
 * Selection is weighted round-robin skipping DRAINING/DEAD entries.  Each entry
 * carries an atomic in_flight counter (incremented when proxy.c starts an
 * upstream connection, decremented in finalize) so an operator can drain a
 * backend and poll until in_flight == 0 before removing it.
 */
#ifndef BRIX_WEBDAV_PROXY_POOL_H
#define BRIX_WEBDAV_PROXY_POOL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define BRIX_PROXY_POOL_SLOTS  32

typedef enum {
    BRIX_PROXY_BE_ACTIVE   = 0,
    BRIX_PROXY_BE_DRAINING,   /* no new selects; in-flight requests finish */
    BRIX_PROXY_BE_DEAD,       /* health-check failure; no new selects */
} brix_proxy_be_state_e;

typedef struct {
    ngx_uint_t               in_use;
    uint32_t                 id;            /* monotonic ID for the REST API */
    char                     host[256];     /* Host: header value */
    uint16_t                 port;
    ngx_uint_t               ssl;           /* 1 = https backend */
    ngx_uint_t               weight;        /* relative selection weight (>=1) */
    brix_proxy_be_state_e  state;
    ngx_msec_t               added_at;
    ngx_msec_t               drained_at;
    ngx_atomic_t             in_flight;     /* active upstream connections */
    struct sockaddr_storage  sockaddr;
    socklen_t                socklen;
    char                     url_base[512]; /* scheme://host[:port] */
} brix_proxy_be_entry_t;

typedef struct {
    ngx_shmtx_sh_t           lock;          /* must be first */
    uint32_t                 next_id;
    ngx_atomic_t             rr_index;
    ngx_uint_t               capacity;
    brix_proxy_be_entry_t  slots[];       /* capacity entries */
} brix_proxy_be_table_t;

/* Snapshot row for the dashboard/admin GET. */
typedef struct {
    uint32_t                 id;
    char                     host[256];
    uint16_t                 port;
    ngx_uint_t               ssl;
    ngx_uint_t               weight;
    brix_proxy_be_state_e  state;
    ngx_msec_t               added_at;
    uint32_t                 in_flight;
} brix_proxy_be_snapshot_t;

/* Configure / attach the SHM zone (call during webdav postconfiguration). */
ngx_int_t brix_proxy_pool_configure(ngx_conf_t *cf);

/*
 * Add a backend from a "scheme://host[:port]" URL.  Resolves the address using
 * the supplied (short-lived) pool, writes the entry into SHM, returns the new
 * id in *id_out.  Returns NGX_OK, NGX_ERROR (pool full / bad url / resolve
 * fail), or NGX_DECLINED (pool not configured).
 */
ngx_int_t brix_proxy_pool_add(const char *url, ngx_uint_t weight,
    ngx_pool_t *pool, ngx_log_t *log, uint32_t *id_out);

/* Remove / drain / undrain by id.  Return 1 on success, 0 if id not found. */
int brix_proxy_pool_remove(uint32_t id);
int brix_proxy_pool_drain(uint32_t id);
int brix_proxy_pool_undrain(uint32_t id);

/* Current in_flight count for id (or -1 if not found). */
long brix_proxy_pool_in_flight(uint32_t id);

/* A selected backend, copied out of SHM into request-owned memory. */
typedef struct {
    struct sockaddr_storage  sockaddr;
    socklen_t                socklen;
    uint16_t                 port;
    char                     host[256];
    char                     url_base[512];
    ngx_uint_t               ssl;
    uint32_t                 id;
} brix_proxy_be_pick_t;

/*
 * Select the next ACTIVE backend (weighted round-robin, skipping DRAINING/DEAD)
 * and copy it into *out (caller-allocated in the request pool); increments the
 * entry's in_flight.  Returns NGX_OK or NGX_DECLINED when none is available.
 */
ngx_int_t brix_proxy_pool_select(brix_proxy_be_pick_t *out);

/* Decrement in_flight for a backend previously returned by _select(). */
void brix_proxy_pool_dec_in_flight(uint32_t id);

/* Snapshot all entries for the admin/dashboard GET. */
ngx_uint_t brix_proxy_pool_snapshot(brix_proxy_be_snapshot_t *out,
    ngx_uint_t max);

#endif /* BRIX_WEBDAV_PROXY_POOL_H */
