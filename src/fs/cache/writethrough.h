#ifndef BRIX_CACHE_WRITETHROUGH_H
#define BRIX_CACHE_WRITETHROUGH_H

#include "fs/vfs/vfs.h"
#include "writethrough_decision.h"

brix_wt_decision_t brix_cache_should_writethrough(
    const brix_vfs_ctx_t *ctx, off_t offset, size_t length);

#endif /* BRIX_CACHE_WRITETHROUGH_H */
