/*
 * prop_xattr.c — xattr-based lock persistence for WebDAV.
 *
 * A WebDAV lock is encoded as a single xattr on the locked resource:
 *   token=<tok>|owner=<owner>|expires=<msec>|scope=<exclusive|shared>|depth=<infinity|0>
 *
 * Local storage uses a serialized, inode-bound VFS lock-store transaction.
 * Driver/broker-owned storage retains native conditional xattr dispatch.
 */
#include "core/compat/log_event.h"
#include "webdav.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"

#include "platform/platform_api.h"
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
 * Build a transient VFS ctx for a confined xattr op on `path`.  Lock-record
 * mutations retain the export's typed mutation policy; reads need no mutation
 * authority.  The _ns (namespace) credential build
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
    const webdav_lock_xattr_t *e, int flags, const webdav_lock_xattr_t *expected)
{
    ngx_log_t        *log = r->connection->log;
    brix_vfs_ctx_t  vctx;
    char              buf[WEBDAV_LOCK_XATTR_MAXLEN];
    ngx_int_t         result;

    if (brix_lock_record_encode(e, buf, sizeof(buf)) != NGX_OK) {
        BRIX_LOG(NGX_LOG_ERR, log, 0,
                      "brix_webdav: lock xattr encode failed for \"%s\"", path);
        return NGX_ERROR;
    }

    webdav_lock_vfs_ctx_init(r, path, &vctx);

    result = brix_vfs_lock_store_update(&vctx, expected, e);
    if (result == NGX_DECLINED && errno == ENOTSUP) {
        result = brix_vfs_setxattr(&vctx, WEBDAV_LOCK_XATTR_KEY,
                                   buf, strlen(buf), flags);
    }
    if (result != NGX_OK)
    {
        if (errno == EEXIST || errno == EBUSY || errno == EWOULDBLOCK) {
            return NGX_DECLINED;   /* XATTR_CREATE race — another worker won */
        }
        BRIX_LOG(NGX_LOG_ERR, log, errno,
                      "brix_webdav: setxattr lock on \"%s\" failed", path);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
webdav_lock_xattr_read_impl(ngx_http_request_t *r, const char *path,
    webdav_lock_xattr_t *e, int for_mutation)
{
    ngx_log_t        *log = r->connection->log;
    brix_vfs_ctx_t  vctx;
    char              buf[WEBDAV_LOCK_XATTR_MAXLEN];
    ssize_t           n;

    webdav_lock_vfs_ctx_init(r, path, &vctx);

    n = for_mutation
        ? brix_vfs_getxattr_for_mutation(&vctx, WEBDAV_LOCK_XATTR_KEY,
                                         buf, sizeof(buf) - 1)
        : brix_vfs_getxattr(&vctx, WEBDAV_LOCK_XATTR_KEY,
                            buf, sizeof(buf) - 1);
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
        BRIX_LOG(NGX_LOG_ERR, log, errno,
                      "brix_webdav: getxattr lock on \"%s\" failed", path);
        return NGX_ERROR;
    }

    return brix_lock_record_decode(buf, (size_t) n, e);
}

ngx_int_t
webdav_lock_xattr_read(ngx_http_request_t *r, const char *path,
    webdav_lock_xattr_t *e)
{
    return webdav_lock_xattr_read_impl(r, path, e, 0);
}

ngx_int_t
webdav_lock_xattr_read_mutation(ngx_http_request_t *r, const char *path,
    webdav_lock_xattr_t *e)
{
    return webdav_lock_xattr_read_impl(r, path, e, 1);
}

ngx_int_t
webdav_lock_xattr_delete(ngx_http_request_t *r, const char *path,
    const webdav_lock_xattr_t *expected)
{
    ngx_log_t        *log = r->connection->log;
    brix_vfs_ctx_t  vctx;
    ngx_int_t       result;

    webdav_lock_vfs_ctx_init(r, path, &vctx);

    result = brix_vfs_lock_store_update(&vctx, expected, NULL);
    if (result == NGX_DECLINED && errno == ENOTSUP) {
        result = brix_vfs_removexattr(&vctx, WEBDAV_LOCK_XATTR_KEY);
    }
    if (result != NGX_OK) {
        if (errno == ENODATA || errno == ENOATTR || errno == ENOENT
            || errno == ENOTSUP || errno == EOPNOTSUPP || errno == ENOSYS)
        {
            return NGX_OK;   /* idempotent (incl. backends without xattr) */
        }
        BRIX_LOG(NGX_LOG_WARN, log, errno,
                      "brix_webdav: removexattr lock on \"%s\" failed", path);
        return NGX_ERROR;
    }

    return NGX_OK;
}
