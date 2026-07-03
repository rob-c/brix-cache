#ifndef BRIX_REDIR_CACHE_H
#define BRIX_REDIR_CACHE_H

/*
 * manager/redir_cache.h — short-lived redirect-collapse cache.
 *
 * When brix_collapse_redir is on, successful path→DS redirect results are
 * stored here so repeat requests for the same path skip the CMS round-trip.
 * The cache lives in a shared-memory zone so all worker processes share one
 * consistent view.  Entries expire after brix_collapse_redir_ttl ms.
 *
 * API:
 *   brix_redir_cache_configure() — call once from postconfiguration.
 *   brix_redir_cache_lookup()    — returns 1 and fills host/port on hit.
 *   brix_redir_cache_insert()    — stores a resolved redirect with TTL.
 */

#include "core/ngx_brix_module.h"

#define BRIX_REDIR_CACHE_SLOTS  512

/* slots: runtime ring-buffer capacity (brix_redir_cache_slots);
 * 0 selects the compile-time default BRIX_REDIR_CACHE_SLOTS. */
ngx_int_t brix_redir_cache_configure(ngx_conf_t *cf, ngx_uint_t slots);

/*
 * Look up path in the cache.  Returns 1 and writes NUL-terminated host and
 * port to the output buffers if a live entry is found; 0 on miss or expiry.
 */
int brix_redir_cache_lookup(const char *path,
    char *host_out, size_t host_size, uint16_t *port_out);

/*
 * Insert or refresh a path→(host,port) mapping with the given TTL in ms.
 * If the cache is full the oldest-by-expiry slot is evicted.
 */
void brix_redir_cache_insert(const char *path,
    const char *host, uint16_t port, ngx_msec_t ttl_ms);

#endif /* BRIX_REDIR_CACHE_H */
