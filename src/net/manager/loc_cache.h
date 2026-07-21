#ifndef BRIX_MANAGER_LOC_CACHE_H
#define BRIX_MANAGER_LOC_CACHE_H

#include <ngx_core.h>
#include <ngx_shmtx.h>

/*
 * loc_cache.h — dynamic file-location cache (Phase-89 W3, phase-61 App C.1).
 *
 * WHAT: A shared-memory map path → (host, port) recording which data node
 *       last asserted kYR_have for a file.  Filled by the CMS manager side
 *       when a node answers a kYR_state probe (server_recv_frame.c); consulted
 *       by kXR_locate (locate.c) before falling back to the state fan-out.
 *
 * WHY:  Static registration is prefix-granular — every node exporting "/"
 *       matches every path, so prefix selection cannot know which node HOLDS
 *       a given file.  Stock cmsd answers this with an on-demand kYR_state
 *       query cached per path; this table is that cache.  It is SHM so a HAVE
 *       ingested on the worker owning the node connection is visible to the
 *       worker serving the client.
 *
 * HOW:  Open-addressing table (linear probe over a power-of-two slot count),
 *       fnv1a path hash, TTL-lazy eviction: expired slots are treated as free
 *       by both lookup and insert — no sweeper.  The table lives in its own
 *       zone allocated via brix_shm_table_alloc (INVARIANT #10: slab header
 *       preserved, mutex bound to the slab pool's recoverable lock word —
 *       never a bare ngx_shmtx_create).
 */

#define BRIX_LOC_CACHE_SLOTS    256    /* power of two (probe mask) */
#define BRIX_LOC_CACHE_PATH_MAX 1024
#define BRIX_LOC_CACHE_TTL_MS   30000  /* v1 fixed TTL: matches the
                                          collapse-redir cache default */

typedef struct {
    uint32_t    path_hash;                        /* fnv1a of path        */
    char        path[BRIX_LOC_CACHE_PATH_MAX];    /* NUL-terminated       */
    char        host[256];                        /* serving node (IP)    */
    uint16_t    port;                             /* node XRootD data port */
    ngx_msec_t  expires;                          /* insert + TTL          */
    ngx_uint_t  in_use;                           /* 1 = occupied          */
} brix_loc_entry_t;

typedef struct {
    ngx_shmtx_sh_t    lock;    /* layout parity with sibling tables; the
                                  runtime mutex binds to the slab pool word */
    brix_loc_entry_t  slots[BRIX_LOC_CACHE_SLOTS];
} brix_loc_table_t;

/* Create/attach the "brix_loc_cache" zone during postconfiguration.  Cheap
 * and unconditional (like the pending table): the zone exists even when
 * brix_cms_locate_window is 0 everywhere — lookups just never happen. */
ngx_int_t brix_loc_cache_configure(ngx_conf_t *cf);

/* Copy the cached (host, port) for path into the caller's buffers.  Returns
 * 1 on a fresh hit, 0 on miss/expired/zone-absent. */
int brix_loc_cache_lookup(const char *path, char *host, size_t host_sz,
    uint16_t *port);

/* Record "host:port holds path" for BRIX_LOC_CACHE_TTL_MS.  Last writer wins
 * (a fresher HAVE simply refreshes/replaces the entry).  When every probed
 * slot is live, the entry at the path's home slot is overwritten — bounded
 * eviction rather than an unbounded probe.  Safe no-op if the zone is absent. */
void brix_loc_cache_insert(const char *path, const char *host, uint16_t port);

#endif /* BRIX_MANAGER_LOC_CACHE_H */
