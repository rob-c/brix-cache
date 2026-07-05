#ifndef BRIX_FS_BACKEND_CACHE_SD_CACHE_INTERNAL_H
#define BRIX_FS_BACKEND_CACHE_SD_CACHE_INTERNAL_H

/*
 * sd_cache_internal.h — shared internal state for the read-through cache driver.
 *
 * The per-export instance state (inst->state) is split into this header so it is
 * visible to both the vtable adapters (sd_cache.c) and the admission/policy +
 * metrics helpers (sd_cache_policy.c) without either file re-declaring it.  This
 * is a driver-private header: it is not part of the sd_cache public surface
 * (sd_cache.h).
 */

#include "fs/backend/sd.h"       /* brix_sd_instance_t */
#include "fs/cache/cstore.h"     /* brix_cstore_t */
#include "fs/tier/tier.h"        /* brix_cache_policy_t */

/* Per-export instance state (inst->state). */
typedef struct {
    brix_sd_instance_t  *source;         /* the tier below (stage | backend)    */
    brix_cstore_t        cstore;
    brix_cache_policy_t  policy;
    ngx_log_t             *log;
} sd_cache_inst_state;

#define SD_CACHE_ST(inst)   ((sd_cache_inst_state *) (inst)->state)
#define SD_CACHE_SRC(inst)  (SD_CACHE_ST(inst)->source)

#endif /* BRIX_FS_BACKEND_CACHE_SD_CACHE_INTERNAL_H */
