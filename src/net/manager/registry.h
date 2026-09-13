#ifndef __BRIX_MANAGER_REGISTRY_H__
#define __BRIX_MANAGER_REGISTRY_H__

/*
 * registry.h - Server registry API (encapsulated SHM access)
 *
 * WHAT: Public API for server registry shared memory operations.
 *       Provides accessor functions to encapsulate SHM zone access.
 *
 * WHY: Encapsulation prevents accidental modification of SHM zone pointers
 *      and enables future changes to the underlying storage mechanism.
 */

#include <ngx_core.h>

/* Forward declarations */
typedef struct brix_srv_table_s brix_srv_table_t;
typedef struct brix_srv_entry_s brix_srv_entry_t;

/*
 * brix_srv_get_shm_zone — accessor for server registry SHM zone.
 *
 * WHAT: Returns pointer to server registry shared memory zone.
 * WHY:  Encapsulation — callers use accessor rather than direct global access.
 * HOW:  Returns NULL if not initialized, otherwise zone pointer.
 *       Thread safety: read-only after initialization.
 */
ngx_shm_zone_t *brix_srv_get_shm_zone(void);

/*
 * brix_srv_get_mutex — accessor for server registry mutex.
 *
 * WHAT: Returns pointer to server registry spinlock.
 * WHY:  Encapsulation — centralized mutex access for proper locking.
 * HOW:  Returns pointer to static mutex (initialized during startup).
 */
ngx_shmtx_t *brix_srv_get_mutex(void);

/* Existing API */
void brix_srv_set_stale_after(ngx_msec_t ms);
brix_srv_table_t *srv_table(void);
ngx_int_t brix_srv_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data);

#endif /* __BRIX_MANAGER_REGISTRY_H__ */
