#ifndef XROOTD_REDIR_CACHE_H
#define XROOTD_REDIR_CACHE_H

/*
 * manager/redir_cache.h — short-lived redirect-collapse cache.
 *
 * When xrootd_collapse_redir is on, successful path→DS redirect results are
 * stored here so repeat requests for the same path skip the CMS round-trip.
 * The cache lives in a shared-memory zone so all worker processes share one
 * consistent view.  Entries expire after xrootd_collapse_redir_ttl ms.
 *
 * API:
 *   xrootd_redir_cache_configure() — call once from postconfiguration.
 *   xrootd_redir_cache_lookup()    — returns 1 and fills host/port on hit.
 *   xrootd_redir_cache_insert()    — stores a resolved redirect with TTL.
 */

#include "../ngx_xrootd_module.h"

#define XROOTD_REDIR_CACHE_SLOTS  512

ngx_int_t xrootd_redir_cache_configure(ngx_conf_t *cf);

/*
 * Look up path in the cache.  Returns 1 and writes NUL-terminated host and
 * port to the output buffers if a live entry is found; 0 on miss or expiry.
 */
int xrootd_redir_cache_lookup(const char *path,
    char *host_out, size_t host_size, uint16_t *port_out);

/*
 * Insert or refresh a path→(host,port) mapping with the given TTL in ms.
 * If the cache is full the oldest-by-expiry slot is evicted.
 */
void xrootd_redir_cache_insert(const char *path,
    const char *host, uint16_t port, ngx_msec_t ttl_ms);

#endif /* XROOTD_REDIR_CACHE_H */
