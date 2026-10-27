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
 * webdav_lock_authorize_target — exact mutation authority for LOCK/UNLOCK.
 *
 * WHAT: Re-evaluates the request URI's logical and resolved target through
 *       every active bearer, native authdb/VO, and XrdAcc policy. Returns
 *       NGX_OK on allow or a fail-closed HTTP status on denial/malformed input.
 * WHY:  Lock metadata changes resource state and LOCK may materialise a
 *       lock-null object; neither operation may rely on read authority or the
 *       configurable observe-only VFS backstop.
 * HOW:  Decode the request path through the shared logical-path seam, pair it
 *       with the already confined resolved path, and require UPDATE authority.
 */
ngx_int_t
webdav_lock_authorize_target(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *resolved_path,
    const char *operation);

/*
 * webdav_lock_reap_null — release a lock-null placeholder (defined in lock.c).
 * If `e` recorded a lock-null lock and the resource is still an empty regular
 * file, unlink it so the reserved name disappears with the lock.  Best-effort.
 */
void
webdav_lock_reap_null(ngx_http_request_t *r, const char *path,
    const webdav_lock_xattr_t *e);

/*
 * webdav_lock_expired_cleanup — opportunistic removal of an EXPIRED lock's
 * stored state (defined in lock.c).
 *
 * WHAT: On a WRITABLE export, drop the stale lock xattr and — when `reap_null`
 *       is set — the lock-null placeholder it reserved. On a read-only export,
 *       do nothing at all.
 * WHY:  Phase-105 Appendix H.2. Discovering an expired lock happens on read
 *       paths (LOCK refresh, the If-header lock check, UNLOCK of a lock that
 *       already lapsed), and a read-only endpoint must not mutate the export as
 *       a side effect of reading it. The VFS would refuse the removexattr with
 *       EROFS anyway; declining to attempt it keeps every ordinary request off
 *       the mutation-denied counter, so that counter keeps meaning "something
 *       tried to write to a read-only export".
 * HOW:  Callers keep treating the expired lock as ABSENT regardless — request
 *       semantics never depend on whether the cleanup ran. Pass reap_null = 0
 *       on a path that is about to be re-locked (see webdav_lock_reap_null).
 */
void
webdav_lock_expired_cleanup(ngx_http_request_t *r, const char *path,
    const webdav_lock_xattr_t *e, int reap_null);

#endif /* BRIX_WEBDAV_LOCK_INTERNAL_H */
