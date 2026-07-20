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
 * Build a transient VFS ctx for a confined xattr op on `path` (mirrors the
 * canonical construction in get.c).  The xattr family is not allow_write-gated,
 * so the allow_write flag passed here does not affect set/remove behaviour.
 */
static void
webdav_lock_vfs_ctx_init(ngx_http_request_t *r, const char *path,
    brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    int is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(vctx, r->pool, r->connection->log,
        BRIX_PROTO_WEBDAV, conf->common.root_canon,
        conf->cache_root_canon, conf->common.allow_write, is_tls,
        (wctx != NULL) ? wctx->identity : NULL, path);
    /* Bind the export's per-user backend credential policy so lock-state
     * xattr ops on a remote-backed export present the REQUESTING USER's
     * credential (wctx->identity, already threaded above), not the shared
     * service credential. Minting is not bound here (mint is reserved for
     * data-plane GET/PUT sites): a lock xattr op that needs a credential the
     * user doesn't already have falls back per the configured
     * storage_credential_fallback policy, same as every other namespace-only
     * VFS ctx in this codebase (see mv.c's probe ctxs). */
    brix_vfs_ctx_bind_backend_cred(vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    webdav_vfs_bind_deleg(r, conf, vctx);
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

ngx_int_t
webdav_lock_xattr_encode(const webdav_lock_xattr_t *e, char *out, size_t outsz)
{
    int n;

    /*
     * Schema v2: `expires` is absolute Unix WALL-CLOCK seconds (not the legacy
     * v1 monotonic-msec value, which was meaningless after a reboot). The leading
     * `v=2` lets the decoder reject/expire any pre-upgrade v1 record. `null=1`
     * marks a lock-null placeholder (RFC 4918 §9.10.1).
     */
    n = snprintf(out, outsz,
                 "v=2|token=%s|owner=%s|expires=%lld|scope=%s|depth=%s|null=%d",
                 e->token, e->owner,
                 (long long) e->expires,
                 e->exclusive ? "exclusive" : "shared",
                 e->depth_infinity ? "infinity" : "0",
                 e->is_null ? 1 : 0);
    return (n > 0 && (size_t) n < outsz) ? NGX_OK : NGX_ERROR;
}

/* ---- Apply one decoded `key`/`val` field pair to the lock record ----
 *
 * WHAT: Dispatches a single `key=val` pair (already split, NUL-terminated) from
 * a lock xattr into the matching field of `*e`, and captures the schema version
 * into `*version` for the `v` key. Unknown keys are ignored (forward-compat).
 *
 * WHY: The per-key branch ladder is the sole source of decode complexity; hoisting
 * it out of webdav_lock_xattr_decode keeps that parser a small loop and makes the
 * field-mapping table reviewable on its own. Field semantics (schema v2 encoding,
 * scope/depth string forms, null placeholder) are preserved byte-for-byte.
 *
 * HOW:
 *   1. Compare `key` against each known field name in turn.
 *   2. On match, parse `val` into the field with the same primitive the inline
 *      ladder used (strtol/strtoll for numerics, ngx_cpystrn for bounded strings,
 *      exact-string equality for the enum-like scope/depth/null fields).
 *   3. Return with no effect when `key` matches nothing.
 */
static void
webdav_lock_xattr_apply_field(const char *key, char *val,
    webdav_lock_xattr_t *e, int *version)
{
    if (strcmp(key, "v") == 0) {
        *version = (int) strtol(val, NULL, 10);
    } else if (strcmp(key, "token") == 0) {
        ngx_cpystrn((u_char *) e->token, (u_char *) val, sizeof(e->token));
    } else if (strcmp(key, "owner") == 0) {
        ngx_cpystrn((u_char *) e->owner, (u_char *) val, sizeof(e->owner));
    } else if (strcmp(key, "expires") == 0) {
        e->expires = (int64_t) strtoll(val, NULL, 10);
    } else if (strcmp(key, "scope") == 0) {
        e->exclusive = (strcmp(val, "exclusive") == 0) ? 1 : 0;
    } else if (strcmp(key, "depth") == 0) {
        e->depth_infinity = (strcmp(val, "infinity") == 0) ? 1 : 0;
    } else if (strcmp(key, "null") == 0) {
        e->is_null = (strcmp(val, "1") == 0) ? 1 : 0;
    }
}

ngx_int_t
webdav_lock_xattr_decode(const char *raw, size_t rawlen, webdav_lock_xattr_t *e)
{
    char   buf[WEBDAV_LOCK_XATTR_MAXLEN];
    char  *p, *end, *val, *next;
    int    version = 0;

    if (rawlen == 0 || rawlen >= sizeof(buf)) {
        return NGX_DECLINED;
    }

    ngx_memcpy(buf, raw, rawlen);
    buf[rawlen] = '\0';
    ngx_memzero(e, sizeof(*e));

    p   = buf;
    end = buf + rawlen;

    while (p < end) {
        next = strchr(p, '|');
        if (next != NULL) {
            *next = '\0';
        }

        val = strchr(p, '=');
        if (val != NULL) {
            *val++ = '\0';
            webdav_lock_xattr_apply_field(p, val, e, &version);
        }

        p = next ? next + 1 : end;
    }

    if (e->token[0] == '\0') {
        return NGX_DECLINED;
    }

    /*
     * Migration guard: a legacy v1 record (no `v=2`) carries a MONOTONIC `expires`
     * that is meaningless in this process (especially after a reboot). Force it to
     * 0 (already-expired) so every caller's existing expired-lock cleanup path
     * deletes it and proceeds — a downgrade therefore releases stale locks rather
     * than honouring a bogus deadline. Returning NGX_OK (not NGX_DECLINED) is
     * deliberate: NGX_DECLINED would leave the physical xattr in place and a fresh
     * XATTR_CREATE LOCK would then wrongly hit EEXIST -> 423.
     */
    if (version != 2) {
        e->expires = 0;
    }

    return NGX_OK;
}

ngx_int_t
webdav_lock_xattr_write(ngx_http_request_t *r, const char *path,
    const webdav_lock_xattr_t *e, int flags)
{
    ngx_log_t        *log = r->connection->log;
    brix_vfs_ctx_t  vctx;
    char              buf[WEBDAV_LOCK_XATTR_MAXLEN];

    if (webdav_lock_xattr_encode(e, buf, sizeof(buf)) != NGX_OK) {
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

    return webdav_lock_xattr_decode(buf, (size_t) n, e);
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
