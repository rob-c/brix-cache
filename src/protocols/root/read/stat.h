#ifndef BRIX_READ_STAT_H
#define BRIX_READ_STAT_H

#include "fs/vfs/vfs.h"   /* brix_vfs_stat_t for the projection helper */
#include <sys/stat.h>    /* struct stat for brix_vfs_to_struct_stat */

/* ---- Module: Stat Operations ----
 *
 * WHAT: Function declarations for XRootD stat opcodes — kXR_stat queries file metadata (inode, size, flags,
 *       mtime) via path-based stat(2) or handle-based fstat(2). brix_cache_path_flag() provides cache-hit
 *       detection returning kXR_cachersp flag when a path exists under the local cache_root.
 *
 * WHY: Stat is one of the most frequently called opcodes — clients query metadata before opening files,
 *      during directory listing iterations, and for cache-hit validation. Handle-based stat provides fast
 *      metadata access without re-resolving paths. Cache flag detection helps clients distinguish between
 *      local cached content vs origin content for prefetch optimization.
 *
 * Parameters:
 *   ctx  - stream session context (payload, hdr_buf, cur_dlen, files[])
 *   c    - nginx connection (log, ssl state)
 *   conf - server config (root, cache, vo_rules)
 */
ngx_int_t brix_handle_stat(brix_ctx_t *ctx, ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf);

/* ---- Function: brix_cache_path_flag() ----
 *
 * WHAT: Checks whether a requested path exists in the local cache (conf->cache_root). Returns kXR_cachersp
 *       flag if found, 0 otherwise. Tells clients the file is served from cache rather than origin.
 *
 * WHY: Clients can optimize read patterns when they know content is cached locally — skip origin fetches for
 *      repeated access patterns, reducing latency across session boundaries. Particularly valuable for large
 *      files accessed by multiple clients.
 *
 * HOW: Three-step validation → cache enabled check (skip if disabled or cache_root empty) → build cache_path =
 *      conf->cache_root + reqpath via snprintf → stat(2) on cache path → return kXR_cachersp if regular file
 *      exists, 0 otherwise. Uses PATH_MAX buffer to prevent overflow.
 *
 * Parameters:
 *   conf   - server config (cache flag, cache_root ngx_str_t)
 *   reqpath - client's clean path string
 */
int brix_cache_path_flag(const ngx_stream_brix_srv_conf_t *conf,
    const char *reqpath);

/* Project a VFS stat result into the struct stat fields the kXR_stat/statx
 * response builders read (unique id, size, perm flags, mtime, blocks). Shared by
 * the stat and statx handlers' VFS-probe fallbacks. */
void brix_vfs_to_struct_stat(const brix_vfs_stat_t *v, struct stat *st);

#endif /* BRIX_READ_STAT_H */
