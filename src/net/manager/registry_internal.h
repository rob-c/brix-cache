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
extern ngx_shmtx_t   brix_srv_mutex;
extern ngx_uint_t    brix_srv_registry_nslots;
extern ngx_msec_t    brix_srv_stale_after_ms;
extern ngx_uint_t    brix_srv_load_weight;   /* Phase 89 W4: 0-100, 0 = off */
extern ngx_uint_t    brix_srv_affinity;      /* Phase 89 W5: path-sticky, 0 = off */


/* registry.c */
brix_srv_table_t * srv_table(void);

/* registry_select.c */
int srv_path_matches(const char *paths, const char *path);
int srv_select_core(const char *path, int for_write, int allow_blacklisted, char *host_out, size_t host_size, uint16_t *port_out);

#endif /* BRIX_REGISTRY_INTERNAL_H */
