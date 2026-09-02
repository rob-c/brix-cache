/*
 * prop_xattr.c — xattr-based lock persistence for WebDAV.
 *
 * A WebDAV lock is encoded as a single xattr on the locked resource:
 *   token=<tok>|owner=<owner>|expires=<msec>|scope=<exclusive|shared>|depth=<infinity|0>
 *
 * XATTR_CREATE semantics make lock creation atomic across workers: if two
 * workers race on the same unlocked path, exactly one setxattr(XATTR_CREATE)
 * succeeds and the other gets EEXIST → NGX_DECLINED → 423 Locked.
 */
#include "webdav.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"

#include <sys/xattr.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

/*
 * Phase 40: lock xattrs must be written/read/removed AS THE MAPPED USER under
 * impersonation, else the worker (svc) cannot setxattr on the user-owned lock
 * file (EACCES) and LOCK/UNLOCK break.  These helpers take the request so they
 * can resolve the export root and route through the VFS xattr surface, which
 * delegates to brix_*xattr_confined_canon (the broker when map mode is active,
 * the raw path-based syscall otherwise) while adding the OP_XATTR metric +
 * access-log line — confinement and errno behaviour are unchanged.
 */

/*
 * Build a transient VFS ctx for a confined xattr op on `path`.  The xattr
 * family is not allow_write-gated, so the allow_write flag threaded through
 * does not affect set/remove behaviour.  The _ns (namespace) credential build
 * is deliberate: minting is reserved for data-plane GET/PUT/COPY sites, so a
 * lock xattr op that needs a credential the user doesn't already have falls
 * back per the configured storage_credential_fallback policy, same as every
 * other namespace-only VFS ctx in this codebase (see mv.c's probe ctxs).
 */
static void
webdav_lock_vfs_ctx_init(ngx_http_request_t *r, const char *path,
    brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    webdav_vfs_ctx_build_ns(r, conf, path, vctx);
    /* Phase-3 T1: route through the export's selected storage backend (NULL =
     * default POSIX) so a remote-backed export's cred gate (brix_vfs_ns_cred,
     * keyed on the leaf driver's stat_cred/setxattr_cred capability) actually
     * engages for lock-state xattr ops — mirrors every other namespace ctx in
     * this codebase (put.c, mv.c). Without this, vctx->sd stays NULL and the
     * gate is structurally unreachable (brix_vfs_ctx_driver(ctx) == NULL), so
     * a deny-mode no-cred user would silently touch the lock xattr via the
     * bare local-fs path. On a LOCAL (POSIX, non-instance) export this is a
     * no-op (brix_webdav_backend_instance returns NULL), so behaviour there is
     * unchanged. */
    vctx->sd = brix_webdav_backend_instance(conf, r->connection->log);
}

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

/* The record format (encode/decode + the schema-v2 migration guard) moved to
 * core/compat/lock_record.c in phase-107 C7 — the VFS lock gate reads the same
 * records. This file keeps the xattr I/O around it: who reads/writes the
 * record, under which credential, with which confinement. */

ngx_int_t
webdav_lock_xattr_write(ngx_http_request_t *r, const char *path,
    const webdav_lock_xattr_t *e, int flags)
{
    ngx_log_t        *log = r->connection->log;
    brix_vfs_ctx_t  vctx;
    char              buf[WEBDAV_LOCK_XATTR_MAXLEN];

    if (brix_lock_record_encode(e, buf, sizeof(buf)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_webdav: lock xattr encode failed for \"%s\"", path);
        return NGX_ERROR;
    }

    webdav_lock_vfs_ctx_init(r, path, &vctx);

    if (brix_vfs_setxattr(&vctx, WEBDAV_LOCK_XATTR_KEY, buf, strlen(buf),
                            flags) != NGX_OK)
    {
        if (errno == EEXIST) {
            return NGX_DECLINED;   /* XATTR_CREATE race — another worker won */
        }
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "brix_webdav: setxattr lock on \"%s\" failed", path);
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
webdav_lock_xattr_read(ngx_http_request_t *r, const char *path,
    webdav_lock_xattr_t *e)
{
    ngx_log_t        *log = r->connection->log;
    brix_vfs_ctx_t  vctx;
    char              buf[WEBDAV_LOCK_XATTR_MAXLEN];
    ssize_t           n;

    webdav_lock_vfs_ctx_init(r, path, &vctx);

    n = brix_vfs_getxattr(&vctx, WEBDAV_LOCK_XATTR_KEY, buf, sizeof(buf) - 1);
    if (n < 0) {
        /* No lock present, OR a backend that cannot store xattrs at all (object /
         * remote root:// stores) — either way the resource carries no WebDAV lock,
         * so a write may proceed. EACCES/EPERM here (added by the phase-2 backend
         * credential bind above) means the per-user backend credential gate
         * denied THIS lock-state probe — it does NOT mean "proceed unlocked and
         * unchecked": the actual write/delete/move this check gates re-runs the
         * SAME gate on its own data-plane VFS ctx and is independently refused
         * with a clean 403 if the user has no credential, so declining here
         * (treating the lock as unknown/absent) cannot bypass the deny — it can
         * only, in the worst case, miss an existing lock for a caller who is
         * about to be denied by the write path anyway. */
        if (errno == ENODATA || errno == ENOATTR || errno == ENOENT
            || errno == ENOTSUP || errno == EOPNOTSUPP || errno == ENOSYS
            || errno == EACCES || errno == EPERM)
        {
            return NGX_DECLINED;
        }
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "brix_webdav: getxattr lock on \"%s\" failed", path);
        return NGX_ERROR;
    }

    return brix_lock_record_decode(buf, (size_t) n, e);
}

ngx_int_t
webdav_lock_xattr_delete(ngx_http_request_t *r, const char *path)
{
    ngx_log_t        *log = r->connection->log;
    brix_vfs_ctx_t  vctx;

    webdav_lock_vfs_ctx_init(r, path, &vctx);

    if (brix_vfs_removexattr(&vctx, WEBDAV_LOCK_XATTR_KEY) != NGX_OK) {
        if (errno == ENODATA || errno == ENOATTR || errno == ENOENT
            || errno == ENOTSUP || errno == EOPNOTSUPP || errno == ENOSYS)
        {
            return NGX_OK;   /* idempotent (incl. backends without xattr) */
        }
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "brix_webdav: removexattr lock on \"%s\" failed", path);
        return NGX_ERROR;
    }

    return NGX_OK;
}
