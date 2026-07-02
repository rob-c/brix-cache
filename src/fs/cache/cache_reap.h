#ifndef XROOTD_CACHE_REAP_H
#define XROOTD_CACHE_REAP_H

#include "cache_internal.h"

/*
 * cache_reap.h — the stale-dirty reaper for the unified cache-state engine.
 *
 * WHAT: xrootd_cache_reap_dirty() scans a server's cache/state tree and removes,
 *       unconditionally, any cached file whose unified record (.cinfo) has been
 *       DIRTY for longer than conf->cache_dirty_max_age — the cached/staging data
 *       file plus its .cinfo/.meta sidecars — and returns the count reaped.
 *
 * WHY:  The eviction guard protects a dirty file from LRU reclamation so an
 *       un-flushed write-back is never lost. Without an upper bound that makes an
 *       ABANDONED write-back (origin permanently gone, client vanished) protected
 *       forever and able to leak disk indefinitely. The reaper bounds it: past the
 *       max age the writes are presumed lost and the file is removed (with a WARN
 *       so the discard is auditable).
 *
 * HOW:  A recursive same-device scan of the state root; for each regular data
 *       file it queries the dirty extent + dirty_since; if dirty and aged it
 *       unlinks the file and its sidecars. No-op when cache_dirty_max_age == 0 or
 *       no state root resolves. Runs on a per-worker maintenance timer
 *       (src/config/process.c), independent of occupancy.
 */
ngx_uint_t xrootd_cache_reap_dirty(const ngx_stream_xrootd_srv_conf_t *conf,
    ngx_log_t *log);

#endif /* XROOTD_CACHE_REAP_H */
