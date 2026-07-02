#ifndef XROOTD_CACHE_WRITETHROUGH_H
#define XROOTD_CACHE_WRITETHROUGH_H

#include "fs/vfs/vfs.h"
#include "writethrough_decision.h"

xrootd_wt_decision_t xrootd_cache_should_writethrough(
    const xrootd_vfs_ctx_t *ctx, off_t offset, size_t length);

#endif /* XROOTD_CACHE_WRITETHROUGH_H */
