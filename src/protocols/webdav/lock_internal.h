/*
 * lock_internal.h — cross-file helpers shared by the WebDAV lock translation
 * units (lock.c / lock_check.c / lock_discovery.c).
 *
 * Only symbols DEFINED in one of those files and REFERENCED from another live
 * here; single-file helpers stay static.  The public lock API is declared in
 * webdav_lock.h (check/sweep/discovery) and webdav_methods.h (LOCK/UNLOCK
 * entry points) — do not duplicate those here.
 */
#ifndef BRIX_WEBDAV_LOCK_INTERNAL_H
#define BRIX_WEBDAV_LOCK_INTERNAL_H

#include "webdav.h"
#include "fs/vfs/vfs.h"

/*
 * webdav_lock_vfs_ctx — build a confined VFS ctx for a lock-DB namespace op on
 * `path` (defined in lock.c).  Identity comes from the request ctx so the op
 * runs as the mapped user under impersonation.
 */
void
webdav_lock_vfs_ctx(ngx_http_request_t *r, const char *path,
    brix_vfs_ctx_t *vctx);

/*
 * webdav_lock_reap_null — release a lock-null placeholder (defined in lock.c).
 * If `e` recorded a lock-null lock and the resource is still an empty regular
 * file, unlink it so the reserved name disappears with the lock.  Best-effort.
 */
void
webdav_lock_reap_null(ngx_http_request_t *r, const char *path,
    const webdav_lock_xattr_t *e);

#endif /* BRIX_WEBDAV_LOCK_INTERNAL_H */
