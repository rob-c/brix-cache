/*
 * registry_internal.h - private split contract for registry.c and its Phase-38 siblings.
 * Not a public API: include only from src/manager/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_REGISTRY_INTERNAL_H
#define BRIX_REGISTRY_INTERNAL_H

#include "registry.h"
#include "core/compat/net_target.h"   
#include "core/compat/host_format.h"  
#include "core/compat/shm_slots.h"    
#include <ngx_shmtx.h>
#include <string.h>

/*
 * Module state container - encapsulates all registry policy globals.
 * Access via brix_srv_state() accessor (thread-safe, zero overhead).
 */
typedef struct {
    ngx_uint_t         registry_nslots;     /* Table capacity */
    ngx_msec_t         stale_after_ms;      /* Staleness threshold */
    ngx_uint_t         load_weight;         /* Legacy weight 0-100 */
    ngx_uint_t         affinity;            /* Path-sticky routing */
    ngx_uint_t         delay_servers;       /* SUPCount floor */
    brix_srv_sched_t   sched;               /* Component weights */
    brix_srv_space_t   space;               /* Write-eligibility policy */
} brix_srv_state_t;

/* Accessor - returns pointer to module state (config-time set, read-only after fork) */
const brix_srv_state_t *brix_srv_state(void);

/* Config-time mutation stays with the private state owner. */
void brix_srv_set_registry_slots(ngx_uint_t slots);


/* registry.c */
brix_srv_table_t * srv_table(void);
/* §2.4: re-latch one entry's write-block from its current free_mb; caller
 * MUST hold brix_srv_mutex.  Shared by the three space-update points. */
void srv_space_reeval_locked(brix_srv_entry_t *e);
/* Locate the in-use entry for host:port; caller MUST hold brix_srv_mutex.
 * NULL when unknown (or the zone is absent). */
brix_srv_entry_t * srv_find_locked(const char *host, uint16_t port);
/* Set the global srv_state.space (cluster space accounting). */
void brix_srv_set_space(const brix_srv_space_t *space);
/* Set the global srv_state.sched (scheduler policy). */
void brix_srv_set_sched(const brix_srv_sched_t *sched);

/* registry_select.c */
int srv_path_matches(const char *paths, const char *path);
int srv_select_core(const char *path, int for_write, int allow_blacklisted, char *host_out, size_t host_size, uint16_t *port_out);

/* registry_select_sched.c — §2.3 metric policy (legacy load-weight blend or
 * the cms.sched component blend) + the maxload ceiling test. */
uint32_t srv_sel_metric(const brix_srv_entry_t *e, int for_write);
int      srv_sel_over_maxload(const brix_srv_entry_t *e);

#endif /* BRIX_REGISTRY_INTERNAL_H */
