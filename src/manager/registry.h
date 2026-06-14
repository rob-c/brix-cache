#ifndef XROOTD_SRV_REGISTRY_H
#define XROOTD_SRV_REGISTRY_H

/*
 * manager/registry.h — shared-memory server registry for cluster/redirector mode.
 *
 * Data servers that connect via the CMS management protocol call
 * xrootd_srv_register() on login and xrootd_srv_update_load() on each
 * heartbeat.  xrootd_srv_select() picks the best server for a given path
 * and is called from the kXR_locate and kXR_open handlers when
 * xrootd_manager_mode is on.
 *
 * The table lives in a dedicated ngx_shm_zone_t so all worker processes share
 * one consistent view.  Concurrent access is serialised by a single
 * ngx_shmtx_t spinlock embedded at the start of the shared region.
 *
 * Capacity: XROOTD_SRV_REGISTRY_SLOTS entries.  When the table is full new
 * registrations are silently dropped — existing servers continue to be used.
 * XROOTD_SRV_MAX_PATHS bounds the colon-delimited path list stored per entry.
 */

#include "../ngx_xrootd_module.h"

#define XROOTD_SRV_REGISTRY_SLOTS  128   /* default; overridden by xrootd_registry_slots */
#define XROOTD_SRV_MAX_PATHS      1024

typedef struct {
    char        host[256];                /* hostname or IP (NUL-terminated) */
    uint16_t    port;                     /* XRootD data port */
    char        paths[XROOTD_SRV_MAX_PATHS]; /* colon-delimited export paths */
    uint32_t    free_mb;                  /* last reported free megabytes */
    uint32_t    util_pct;                 /* last reported utilisation % */
    ngx_msec_t  last_seen;               /* ngx_current_msec at last update */
    ngx_uint_t  in_use;                  /* 1 = slot occupied */
    ngx_msec_t  blacklisted_until;       /* 0 = available; future ms = skip */
    uint32_t    error_count;             /* consecutive CMS disconnect count */

    /* Phase 22 — active health checks (off unless xrootd_health_check on). */
    ngx_msec_t  hc_next_check;           /* ngx_current_msec when next probe is due */
    ngx_msec_t  hc_last_ok;              /* ngx_current_msec of last passing probe */
    uint32_t    hc_fail_count;           /* consecutive probe failures */
    ngx_uint_t  hc_in_progress;          /* 1 = a worker has claimed this slot */
} xrootd_srv_entry_t;

typedef struct {
    ngx_shmtx_sh_t      lock;     /* must be first — required by ngx_shmtx_create */
    ngx_uint_t           capacity; /* number of valid entries in slots[] */
    xrootd_srv_entry_t   slots[];  /* C99 flexible array; capacity entries follow */
} xrootd_srv_table_t;

typedef struct {
    char        host[256];
    uint16_t    port;
    char        paths[XROOTD_SRV_MAX_PATHS];
    uint32_t    free_mb;
    uint32_t    util_pct;
    ngx_msec_t  last_seen;
    ngx_msec_t  blacklisted_until;
    uint32_t    error_count;
    ngx_msec_t  hc_last_ok;      /* Phase 22: last passing health probe */
    uint32_t    hc_fail_count;   /* Phase 22: consecutive probe failures */
} xrootd_srv_snapshot_entry_t;

extern ngx_shm_zone_t *xrootd_srv_shm_zone;

/*
 * nginx shm-zone init callback (set as shm_zone->init).  First boot (data==NULL):
 * casts shm.addr to the table, sets capacity, zero-fills slots[], creates the
 * spinlock.  Reattach (data!=NULL): adopts the existing table and recreates the
 * worker-local mutex handle against tbl->lock.  Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t xrootd_srv_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data);

/*
 * Reserve the registry shm zone during config parsing; call once, before
 * workers start.  slots sizes the table (sizeof(table) + slots*entry + a page);
 * stores the count globally and registers xrootd_srv_shm_init_zone as the init
 * callback.  Returns NGX_OK, or NGX_ERROR if ngx_shared_memory_add fails.
 */
ngx_int_t xrootd_srv_configure_registry(ngx_conf_t *cf, ngx_uint_t slots);

/* Called by the CMS server handler when a data server logs in. */
void xrootd_srv_register(const char *host, uint16_t port,
    const char *paths, uint32_t free_mb, uint32_t util_pct);

/* Called on each CMS heartbeat to refresh load metrics. */
void xrootd_srv_update_load(const char *host, uint16_t port,
    uint32_t free_mb, uint32_t util_pct);

/* Called when the CMS connection from a data server drops. */
void xrootd_srv_unregister(const char *host, uint16_t port);

/*
 * Blacklist a server for duration_ms milliseconds after a CMS disconnect.
 * xrootd_srv_select() skips blacklisted entries.  xrootd_srv_register()
 * clears the blacklist when the server successfully reconnects.
 */
void xrootd_srv_blacklist(const char *host, uint16_t port,
    ngx_msec_t duration_ms);

/* Phase 23 — clear a drain/blacklist (admin "undrain"); 1 if found. */
int xrootd_srv_undrain(const char *host, uint16_t port);

/*
 * Phase 22 — active health checks.
 *
 * xrootd_srv_hc_claim(): under the registry spinlock, find the first in-use
 *   slot whose hc_next_check is due and that no other worker is probing.  On
 *   success sets hc_in_progress=1, advances hc_next_check by interval_ms,
 *   copies host/port to the out params, and returns 1.  Returns 0 if nothing
 *   is due — guaranteeing exactly one worker probes each server per interval.
 *
 * xrootd_srv_hc_pass(): probe succeeded — clears hc_fail_count, sets
 *   hc_last_ok, clears hc_in_progress, and clears a blacklist only if it was
 *   set by health checking (hc_fail_count was > 0), never a CMS-disconnect one.
 *
 * xrootd_srv_hc_fail(): probe failed — increments hc_fail_count, clears
 *   hc_in_progress, and blacklists the server for blacklist_ms once
 *   hc_fail_count reaches threshold.  Returns 1 if it newly blacklisted.
 */
int  xrootd_srv_hc_claim(char *host_out, size_t host_size,
    uint16_t *port_out, ngx_msec_t interval_ms);
void xrootd_srv_hc_pass(const char *host, uint16_t port);
int  xrootd_srv_hc_fail(const char *host, uint16_t port,
    uint32_t threshold, ngx_msec_t blacklist_ms);

/* Remove a single path token from a slot's colon-delimited path list.
 * Used by cache eviction to deregister a specific file without removing
 * the whole entry.  Thread-safe (spinlock). */
void xrootd_srv_unregister_path(const char *host, uint16_t port,
    const char *path);

/*
 * Select the best server for path.  For reads (for_write=0) picks the server
 * with the lowest util_pct; for writes picks the server with the most free_mb.
 * Path prefix matching is longest-match over each colon-delimited token in the
 * entry's paths field.
 *
 * Returns 1 and fills host_out/port_out on success.  Returns 0 if no server
 * exports a prefix that covers path.
 */
int xrootd_srv_select(const char *path, int for_write,
    char *host_out, size_t host_size, uint16_t *port_out);

/*
 * Count occupied, non-blacklisted servers exporting a prefix covering path —
 * how many distinct data servers a client could be redirected to.
 */
int xrootd_srv_count_matching(const char *path);

/*
 * tried/triedrc retry protocol: extracts the opaque CGI from the raw request
 * payload and returns 1 when its tried= list already covers every server
 * matching clean_path, meaning the manager must answer kXR_NotFound instead of
 * redirecting again (prevents the client redirect-limit loop on a path no
 * server holds).  payload may be NULL.
 */
int xrootd_manager_tried_exhausted(const u_char *payload, size_t payload_len,
    const char *clean_path);

/*
 * Build a kXR_locate response body listing all non-blacklisted servers that
 * export a prefix covering path.  Format is space-separated "S<r|w>host:port"
 * entries, NUL-terminated, as required by the XRootD locate wire format.
 *
 * Returns the number of bytes written (not counting the terminating NUL), or
 * 0 if no servers match or the buffer is too small to hold even one entry.
 */
int xrootd_srv_locate_all(const char *path, int for_write,
    char *buf, size_t bufsz);

/*
 * Aggregate space metrics across all occupied registry slots.
 * *total_free_mb  receives the sum of free_mb across all registered servers.
 * *avg_util_pct   receives the arithmetic mean util_pct (0 if no servers).
 * Used by the CMS client when manager_mode is on so the node reports
 * aggregate child capacity upward rather than its own (possibly zero) disk.
 */
void xrootd_srv_aggregate_space(uint32_t *total_free_mb,
    uint32_t *avg_util_pct);

/*
 * Take a point-in-time copy of up to max_entries occupied slots into the
 * caller-owned out[] array (caller allocates; entries are copied by value, no
 * aliasing of shm).  Holds the spinlock for the copy.  The now argument is
 * currently ignored.  Returns the number of entries written.
 */
ngx_uint_t xrootd_srv_snapshot(xrootd_srv_snapshot_entry_t *out,
    ngx_uint_t max_entries, ngx_msec_t now);

#endif /* XROOTD_SRV_REGISTRY_H */
