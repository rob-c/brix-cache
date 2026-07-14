/*
 * lock_check.c — WebDAV lock-conflict checking (RFC 4918 §9.10 locking).
 *
 * Split from lock.c (mechanical, zero behaviour change): the ancestor walk
 * (webdav_check_locks) and the recursive descendant scan
 * (webdav_check_locks_tree) that DELETE/COPY/MOVE consult before mutating a
 * resource or collection.  Lock state is stored as a single xattr on each
 * resource (see prop_xattr.c); this file only reads/expires those records.
 *
 * The confined-ctx helper (webdav_lock_vfs_ctx) and the lock-null reaper
 * (webdav_lock_reap_null) are defined in lock.c and shared via lock_internal.h.
 */
#include "webdav.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"   /* lock-DB namespace ops via the VFS seam */
#include "auth/impersonate/lifecycle.h"
#include "protocols/webdav/locks/request.h"
#include "core/http/http_xml.h"
#include "core/compat/fs_walk.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>

#include "lock_internal.h"

/* RFC 4918 §11.1: 423 Locked */
#ifndef NGX_HTTP_LOCKED
#define NGX_HTTP_LOCKED 423
#endif

/*
 * webdav_check_lock_at — evaluate the lock (if any) recorded on one ancestor
 * path `check` while checking whether the target path is blocked.
 *
 * WHAT: Reads the lock xattr on `check`; if active and it covers the target and
 *       the client does not own it, reports the operation as blocked.  Expired
 *       locks are cleaned up lazily (delete + lock-null reap) exactly as before.
 * WHY:  Isolating the per-level lock decision keeps the ascent loop in
 *       webdav_check_locks a simple, low-complexity path-walk.
 * HOW:  The ancestor `check`/`check_len` and the immutable target `path`/
 *       `path_len` travel together in a single walk struct.  Returns NGX_OK
 *       (not blocked here), NGX_HTTP_LOCKED (an owning-mismatch lock covers the
 *       target), or NGX_HTTP_INTERNAL_SERVER_ERROR (xattr read failure).
 *       Coverage rule is unchanged: exact match, or a depth-infinity ancestor
 *       on a path boundary.
 */
/* One level of the ancestor walk: the (mutable) ancestor path being examined
 * plus the (immutable) target path the whole walk is checking. */
typedef struct {
    const char *check;
    size_t      check_len;
    const char *path;
    size_t      path_len;
} webdav_lock_walk_t;

static ngx_int_t
webdav_check_lock_at(ngx_http_request_t *r, const webdav_lock_walk_t *w)
{
    webdav_lock_xattr_t e;
    ngx_int_t           rc;
    int                 covers;

    rc = webdav_lock_xattr_read(r, w->check, &e);
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (rc != NGX_OK) {
        return NGX_OK;
    }

    if (e.expires <= (int64_t) ngx_time()) {
        (void) webdav_lock_xattr_delete(r, w->check);
        webdav_lock_reap_null(r, w->check, &e);
        return NGX_OK;
    }

    /* Lock covers path if: exact match or depth-infinity ancestor. */
    covers = (w->check_len == w->path_len)
             || (e.depth_infinity
                 && w->check_len < w->path_len
                 && (w->check[w->check_len - 1] == '/'
                     || w->path[w->check_len] == '/'));
    if (covers && !webdav_lock_if_header_matches(r, e.token)) {
        return NGX_HTTP_LOCKED;
    }
    return NGX_OK;
}

/*
 * webdav_lock_path_ascend — strip the last component from `check` in place.
 *
 * WHAT: Removes trailing slashes then the final path component of `check`.
 * WHY:  Advances the ancestor walk one level toward the export root.
 * HOW:  Returns 1 when a shorter parent path remains in `check`, 0 when the
 *       path can no longer be shortened (no interior slash) so the caller stops.
 */
static int
webdav_lock_path_ascend(char *check, size_t check_len)
{
    char *slash = check + check_len - 1;

    while (slash > check && *slash == '/') {
        slash--;
    }
    while (slash > check && *slash != '/') {
        slash--;
    }
    if (*slash != '/') {
        return 0;
    }
    *slash = '\0';
    return 1;
}

/*
 * webdav_check_locks — walk from path up to export root, checking for active
 * xattr locks at each level.  O(path_depth) xattr reads.
 *
 * Returns NGX_HTTP_LOCKED if an active, client-unowned lock blocks this
 * operation; NGX_OK otherwise.
 */
ngx_int_t
webdav_check_locks(ngx_http_request_t *r, const char *path, int need_write)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char               check[PATH_MAX];
    size_t             root_len;
    webdav_lock_walk_t w;
    ngx_int_t          blocked;

    (void) need_write;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    root_len = strlen(conf->common.root_canon);

    ngx_cpystrn((u_char *) check, (u_char *) path, sizeof(check));

    w.check = check;
    w.path = path;
    w.path_len = strlen(path);

    for (;;) {
        w.check_len = strlen(check);

        blocked = webdav_check_lock_at(r, &w);
        if (blocked != NGX_OK) {
            return blocked;
        }

        /* Stop at or above export root. */
        if (w.check_len <= root_len) {
            break;
        }

        if (!webdav_lock_path_ascend(check, w.check_len)) {
            break;
        }

        if (strlen(check) < root_len) {
            break;
        }
    }

    return NGX_OK;
}

/*
 * check_locks_descendants — scan direct and recursive children of a directory
 * for unexpired xattr locks not covered by the client's If header.
 * Does NOT walk upward; the caller is responsible for checking ancestors.
 */
static ngx_int_t
check_locks_descendants(ngx_http_request_t *r, const char *dir)
{
    brix_vfs_ctx_t    vctx;
    brix_vfs_dir_t   *dp;
    char                child[PATH_MAX];
    size_t              dir_len;
    webdav_lock_xattr_t e;
    ngx_int_t           rc;

    /* Confined NON-metered opendir (recursive lock scan; a planted in-export
     * symlink cannot redirect it out of the export root). */
    webdav_lock_vfs_ctx(r, dir, &vctx);
    dp = brix_vfs_opendir_quiet(&vctx, NULL);
    if (dp == NULL) {
        return NGX_OK;
    }

    dir_len = strlen(dir);
    rc = NGX_OK;

    for ( ;; ) {
        ngx_str_t                 name;
        brix_vfs_dirent_kind_t  dkind;
        const char               *dname;
        int                       is_dir;
        ngx_int_t                 xrc;

        /* "."/".." filtered by readdir_kind; kind from d_type. */
        if (brix_vfs_readdir_kind(dp, &name, &dkind) != NGX_OK) {
            break;   /* NGX_DONE (end) or error → stop */
        }
        dname = (const char *) name.data;

        if (dir_len + 1 + name.len + 1 > sizeof(child)) {
            continue;   /* path too long — skip */
        }
        snprintf(child, sizeof(child), "%s/%s", dir, dname);

        /* Check lock xattr directly on this child. */
        xrc = webdav_lock_xattr_read(r, child, &e);
        if (xrc == NGX_ERROR) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (xrc == NGX_OK) {
            if (e.expires > (int64_t) ngx_time()) {
                if (!webdav_lock_if_header_matches(r, e.token)) {
                    rc = NGX_HTTP_LOCKED;
                    break;
                }
            } else {
                (void) webdav_lock_xattr_delete(r, child);
                webdav_lock_reap_null(r, child, &e);
            }
        }
        /* xrc == NGX_DECLINED: no lock xattr on this child — OK */

        /* Recurse into subdirectories. d_type gives the answer directly; on a
         * DT_UNKNOWN filesystem fall back to a confined no-follow probe so a
         * trailing symlink is never followed into recursion. */
        is_dir = (dkind == BRIX_VFS_DT_DIR);
        if (dkind == BRIX_VFS_DT_UNKNOWN) {
            brix_vfs_ctx_t  cctx;
            brix_vfs_stat_t cvst;

            webdav_lock_vfs_ctx(r, child, &cctx);
            is_dir = (brix_vfs_probe(&cctx, 1 /* no-follow */, &cvst) == NGX_OK
                      && cvst.is_directory);
        }
        if (is_dir) {
            rc = check_locks_descendants(r, child);
            if (rc != NGX_OK) {
                break;
            }
        }
    }

    brix_vfs_closedir(dp, r->connection->log);
    return rc;
}

/*
 * webdav_check_locks_tree — check locks on a path and all its descendants.
 * Use this instead of webdav_check_locks() for DELETE/COPY/MOVE on
 * collections, where a lock on any child must block the operation.
 */
ngx_int_t
webdav_check_locks_tree(ngx_http_request_t *r, const char *path)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;
    ngx_int_t         rc;

    rc = webdav_check_locks(r, path, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Only recurse for a directory (confined no-follow probe). */
    webdav_lock_vfs_ctx(r, path, &vctx);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) == NGX_OK
        && vst.is_directory)
    {
        rc = check_locks_descendants(r, path);
    }

    return rc;
}
