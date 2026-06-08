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
} xrootd_srv_snapshot_entry_t;

extern ngx_shm_zone_t *xrootd_srv_shm_zone;

ngx_int_t xrootd_srv_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data);
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

ngx_uint_t xrootd_srv_snapshot(xrootd_srv_snapshot_entry_t *out,
    ngx_uint_t max_entries, ngx_msec_t now);

#endif /* XROOTD_SRV_REGISTRY_H */
