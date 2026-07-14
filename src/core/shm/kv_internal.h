/*
 * kv_internal.h — private on-slab layout types shared between the two halves of
 * the SHM key/value store after the phase-79 file-size split.
 *
 * WHAT: Defines the two private structs that describe the slab-backed table
 *       layout — the per-zone header (lock + counters + geometry) and a single
 *       hash entry — used by both kv.c (data-plane ops: get/set/delete/stats)
 *       and kv_config.c (configuration + registry + zone init).
 * WHY:  kv.c (577 lines) exceeded the 500-line cap. The data plane and the
 *       configuration/registry plane are cohesive but independent — the only
 *       thing they share is this private table layout, so it is factored here
 *       rather than duplicated. These types are deliberately NOT in the public
 *       kv.h: consumers see only the opaque brix_kv_t handle, never the layout.
 * HOW:  Both translation units include this header. The header carries only the
 *       two struct typedefs; there are no cross-file function calls between the
 *       two halves, so no function crosses the boundary. Requires ngx core
 *       types (ngx_shmtx_sh_t, ngx_msec_t, fixed-width ints) before inclusion.
 *
 * Slab block layout (allocated FROM the zone's slab pool via
 * brix_shm_table_alloc and published through shm_zone->data — it does NOT
 * overlay shm.addr, which holds nginx's ngx_slab_pool_t header):
 *
 *   +----------------------+  table base (shm_zone->data)
 *   | brix_kv_header_t     |  (lock must be first — ngx_shmtx_create target)
 *   +----------------------+  offset sizeof(header)
 *   | entry[0]             |  stride = sizeof(entry) + key_max + val_max
 *   | entry[1]             |
 *   |  ...                 |
 *   | entry[capacity-1]    |
 *   +----------------------+
 *
 * capacity is the largest power of two that fits the configured zone size, so
 * (hash & (capacity-1)) selects the home bucket without a modulo.
 */
#ifndef BRIX_SHM_KV_INTERNAL_H
#define BRIX_SHM_KV_INTERNAL_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct {
    ngx_shmtx_sh_t  lock;        /* spinlock — MUST be first */
    uint64_t        count;       /* live entries */
    uint64_t        hits;        /* cache hits */
    uint64_t        misses;      /* cache misses */
    uint64_t        evictions;   /* TTL-expiry evictions */
    uint32_t        capacity;    /* number of buckets (power of two) */
    uint32_t        key_max;     /* max key bytes per entry */
    uint32_t        val_max;     /* max value bytes per entry */
    uint32_t        pad;
} brix_kv_header_t;

typedef struct {
    uint64_t     hash;       /* FNV-1a 64-bit hash of the key */
    uint32_t     key_len;    /* 0 = slot free */
    uint32_t     val_len;
    ngx_msec_t   expires;    /* ngx_current_msec at expiry; 0 = never */
    /* u_char key[key_max]; u_char val[val_max]; follow immediately */
} brix_kv_entry_t;

#endif /* BRIX_SHM_KV_INTERNAL_H */
