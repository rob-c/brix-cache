/*
 * lock.c — WebDAV LOCK and UNLOCK handler (RFC 4918 §9.10, §9.11).
 *
 * Lock state is stored as a single xattr on the locked resource
 * (see prop_xattr.c).  No shared memory or mutex is needed:
 * XATTR_CREATE provides kernel-serialized atomic lock creation;
 * expiry cleanup is lazy (on next access to that path).
 *
 * Lock check walks from the target path up to the export root,
 * O(path_depth) xattr reads rather than O(1024) SHM slot scans.
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

/* RFC 4918 §11.1: 423 Locked */
#ifndef NGX_HTTP_LOCKED
#define NGX_HTTP_LOCKED 423
#endif

/*
 * Generate Version 4 UUID for WebDAV lock token (`opaquelocktoken:` prefix).
 * OpenSSL RAND_bytes provides collision-resistant identifiers.
 */
static void
webdav_generate_uuid(char *buf, size_t bufsz)
{
    u_char bytes[16];
    (void) RAND_bytes(bytes, 16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;   /* Version 4 */
    bytes[8] = (bytes[8] & 0x3f) | 0x80;   /* Variant */

    snprintf(buf, bufsz,
             "opaquelocktoken:%02x%02x%02x%02x-%02x%02x-%02x%02x"
             "-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

/*
 * Startup lock sweep — remove every persisted lock xattr under the export
 * root.  Locks are stored as the WEBDAV_LOCK_XATTR_KEY xattr on each resource
 * (prop_xattr.c), so they normally survive an nginx restart.  When
 * brix_webdav_lock_startup_sweep is on, this walk restores ephemeral
 * RFC 4918 §10.1 semantics by clearing them once at startup.
 *
 * removexattr is idempotent: a node with no lock returns ENODATA/ENOATTR,
 * which is not counted and not an error.  The walk continues past per-node
 * failures so one unreadable subtree cannot abort the sweep.
 */
/* Sweep state threaded to the walk callback so each node can build a transient,
 * confined VFS ctx for its lock-xattr removal (the sweep runs at config-merge
 * time, so it carries its own pool/log/root_canon rather than a request ctx). */
typedef struct {
    ngx_uint_t  removed;
    ngx_pool_t *pool;
    ngx_log_t  *log;
    const char *root_canon;
} webdav_lock_sweep_ctx_t;

/* Remove the lock xattr on one absolute path through the VFS seam. removexattr
 * via the VFS is idempotent for our purposes: ENODATA/ENOATTR (no lock) returns
 * NGX_ERROR but is simply not counted, so a node without a lock is a no-op. */
static void
webdav_lock_sweep_remove(webdav_lock_sweep_ctx_t *sw, const char *path)
{
    brix_vfs_ctx_t vctx;

    brix_vfs_ctx_init(&vctx, sw->pool, sw->log, BRIX_PROTO_WEBDAV,
        sw->root_canon, NULL, 1 /* allow_write */, 0 /* is_tls */, NULL, path);

    if (brix_vfs_removexattr(&vctx, WEBDAV_LOCK_XATTR_KEY) == NGX_OK) {
        sw->removed++;
    }
}

static ngx_int_t
webdav_lock_sweep_cb(const brix_fs_walk_entry_t *entry, void *data)
{
    webdav_lock_sweep_remove(data, entry->path);
    return NGX_OK;   /* continue regardless of per-node result */
}

ngx_uint_t
webdav_lock_startup_sweep(ngx_pool_t *pool, ngx_log_t *log,
    const char *root_canon)
{
    brix_fs_walk_options_t opts;
    webdav_lock_sweep_ctx_t  sw;

    if (root_canon == NULL || root_canon[0] == '\0') {
        return 0;
    }

    ngx_memzero(&sw, sizeof(sw));
    sw.pool = pool;
    sw.log = log;
    sw.root_canon = root_canon;

    /* The tree walk visits children only; clear a lock on the root itself. */
    webdav_lock_sweep_remove(&sw, root_canon);

    ngx_memzero(&opts, sizeof(opts));
    opts.include_files = 1;   /* locks may sit on files ... */
    opts.include_dirs  = 1;   /* ... and on collections (Depth: infinity) */

    (void) brix_fs_walk(log, root_canon, &opts, webdav_lock_sweep_cb, &sw);
    return sw.removed;
}

/*
 * Build and send the RFC 4918 §9.10 LOCK response body (activelock XML)
 * plus Lock-Token response header.
 */
static void
webdav_lock_xml_response(ngx_http_request_t *r, webdav_lock_xattr_t *e)
{
    ngx_chain_t     *head = NULL, *tail = NULL;
    char             timeout_buf[32];
    char            *safe_owner;
    int64_t          now = (int64_t) ngx_time();
    ngx_uint_t       remaining;
    off_t            total_len = 0;
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;

    /* expires is absolute wall-clock seconds → remaining is a plain subtraction. */
    remaining = (e->expires > now) ? (ngx_uint_t) (e->expires - now) : 0;
    ngx_sprintf((u_char *) timeout_buf, "Second-%ui", remaining);

    safe_owner = webdav_escape_xml_text(r->pool, e->owner);
    if (safe_owner == NULL) {
        safe_owner = "anonymous";
    }

    brix_http_chain_appendf(r->pool, &head, &tail,
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<D:prop xmlns:D=\"DAV:\">"
        "<D:lockdiscovery>"
        "<D:activelock>"
        "<D:locktype><D:write/></D:locktype>"
        "<D:lockscope>%s</D:lockscope>"
        "<D:depth>%s</D:depth>"
        "<D:owner>%s</D:owner>"
        "<D:timeout>%s</D:timeout>"
        "<D:locktoken><D:href>%s</D:href></D:locktoken>"
        "</D:activelock>"
        "</D:lockdiscovery>"
        "</D:prop>",
        e->exclusive ? "<D:exclusive/>" : "<D:shared/>",
        e->depth_infinity ? "infinity" : "0",
        safe_owner, timeout_buf, e->token);

    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    for (lc = head; lc != NULL; lc = lc->next) {
        total_len += lc->buf->last - lc->buf->pos;
    }

    r->headers_out.content_length_n = total_len;

    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key, "Content-Type");
        ngx_str_set(&h->value, "application/xml; charset=\"utf-8\"");
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key, "Lock-Token");
        h->value.len = strlen(e->token) + 2;
        h->value.data = ngx_pnalloc(r->pool, h->value.len);
        if (h->value.data != NULL) {
            ngx_sprintf(h->value.data, "<%s>", e->token);
        }
    }

    ngx_http_send_header(r);
    ngx_http_output_filter(r, head);
}

/*
 * webdav_lock_reap_null — release a lock-null placeholder.
 *
 * WHAT: If `e` recorded a lock-null lock (the LOCK created a zero-byte resource
 *       to reserve a name, RFC 4918 §9.10.1) AND the resource is still an empty
 *       regular file, unlink it so the reserved name disappears with the lock.
 * WHY:  Without this, UNLOCK (or expiry) of a never-PUT lock-null resource would
 *       leave an orphaned 0-byte file behind. A resource the client PUT data into
 *       is non-empty and is never reaped, so the is_null flag becomes inert once
 *       real content exists — no need to clear it on PUT.
 * HOW:  Confined no-follow lstat; only a regular, zero-length file is unlinked,
 *       via the confined unlink. Best-effort — failures are ignored. MUST NOT be
 *       called on a path that is about to be re-locked (it would remove the file
 *       out from under a follow-up XATTR_CREATE).
 */
/* Build a confined VFS ctx for a lock-DB namespace op on `path` (mirrors the
 * canonical webdav construction). Identity comes from the request ctx so the op
 * runs as the mapped user under impersonation. */
static void
webdav_lock_vfs_ctx(ngx_http_request_t *r, const char *path,
    brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t  *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    int is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        conf->common.root_canon, conf->cache_root_canon, conf->common.allow_write,
        is_tls, (rx != NULL) ? rx->identity : NULL, path);
}

static void
webdav_lock_reap_null(ngx_http_request_t *r, const char *path,
                      const webdav_lock_xattr_t *e)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;

    if (!e->is_null) {
        return;
    }

    /* Confined no-follow probe; only a regular, zero-length file is unlinked,
     * through the VFS. Best-effort — failures are ignored. */
    webdav_lock_vfs_ctx(r, path, &vctx);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) == NGX_OK
        && vst.is_regular && vst.size == 0)
    {
        (void) brix_vfs_unlink(&vctx);
    }
}

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

static void webdav_handle_lock_inner(ngx_http_request_t *r);

/*
 * LOCK body-ready callback.  Phase 40: the lockinfo body is read asynchronously,
 * so the dispatch wrapper already cleared the impersonation principal.
 * Re-establish it (mirrors PUT/PROPFIND/PROPPATCH) so the lock xattr AND any
 * zero-byte resource creation happen AS THE MAPPED USER via the broker; without
 * it the worker (svc) cannot setxattr the user-owned lock target (EACCES) and
 * LOCK fails 500.  No-op unless map mode is active.
 */
void
webdav_handle_lock(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    webdav_handle_lock_inner(r);
    brix_imp_request_end();
}

/*
 * webdav_lock_create_null — RFC 4918 §9.10.1 lock-null placeholder creation.
 *
 * WHAT: If `path` does not exist, atomically create a zero-byte resource to
 *       host the lock, and report via *created_null whether we made it.
 * WHY:  A LOCK on a non-existent resource MUST reserve the name; the placeholder
 *       is reaped on UNLOCK/expiry if never converted by a PUT/MKCOL.
 * HOW:  Confined no-follow probe; on ENOENT do an O_CREATE|O_EXCL open. A race
 *       loser (EEXIST) is not an error and leaves created_null clear. Returns
 *       NGX_OK on success (whether or not a file was created) or
 *       NGX_HTTP_INTERNAL_SERVER_ERROR when the create fails for another reason.
 */
static ngx_int_t
webdav_lock_create_null(ngx_http_request_t *r, const char *path,
    int *created_null)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;
    brix_vfs_file_t *fh;
    int              verr = 0;

    *created_null = 0;

    webdav_lock_vfs_ctx(r, path, &vctx);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) != NGX_DECLINED
        || errno != ENOENT)
    {
        return NGX_OK;
    }

    fh = brix_vfs_open(&vctx,
        BRIX_VFS_O_WRITE | BRIX_VFS_O_CREATE | BRIX_VFS_O_EXCL, &verr);
    if (fh == NULL) {
        return (verr == EEXIST) ? NGX_OK : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    brix_vfs_close(fh, r->connection->log);
    /* We created the resource solely to host this lock: it is a lock-null
     * placeholder, reaped on UNLOCK/expiry if still empty. */
    *created_null = 1;
    return NGX_OK;
}

/* Parsed inputs for a fresh lock, threaded from the handler into
 * webdav_lock_create so its signature stays small. */
typedef struct {
    const char *owner;
    int         exclusive;
    int         depth_infinity;
    int         created_null;   /* lock-null placeholder was created */
} webdav_lock_new_t;

/*
 * webdav_lock_owner_set — choose the <D:owner> value for a fresh lock.
 *
 * WHAT: Copies, in priority order, the request-supplied owner, else the
 *       authenticated DN, else the literal "anonymous", into e->owner.
 * WHY:  Keeps owner-selection out of the create path so its intent is explicit
 *       and unchanged. HOW: bounded ngx_cpystrn into the fixed owner buffer.
 */
static void
webdav_lock_owner_set(webdav_lock_xattr_t *e, const char *owner,
    const ngx_http_brix_webdav_req_ctx_t *ctx)
{
    if (owner[0] != '\0') {
        ngx_cpystrn((u_char *) e->owner, (u_char *) owner, sizeof(e->owner));
    } else if (ctx != NULL && ctx->dn[0] != '\0') {
        ngx_cpystrn((u_char *) e->owner, (u_char *) ctx->dn, sizeof(e->owner));
    } else {
        ngx_cpystrn((u_char *) e->owner, (u_char *) "anonymous",
                    sizeof(e->owner));
    }
}

/*
 * webdav_lock_write_status — map an XATTR_CREATE lock-write result to a status.
 *
 * WHAT: Translates the write rc/errno into the wire status for the new-lock
 *       path: NGX_HTTP_LOCKED on a lost race (NGX_DECLINED), 403 vs 500 on
 *       failure, or NGX_OK on success.
 * WHY:  The two-EACCES-source disambiguation is subtle and load-bearing; giving
 *       it its own function keeps the create path readable while preserving the
 *       exact policy-vs-syscall distinction documented below.
 * HOW:  See the inline rationale — a remote-backed export's credential gate
 *       (drv != NULL) yields 403; a plain local-syscall EACCES stays 500.
 */
static ngx_int_t
webdav_lock_write_status(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_int_t rc)
{
    if (rc == NGX_DECLINED) {
        /* Another worker created the lock between our read and write. */
        return NGX_HTTP_LOCKED;
    }
    if (rc == NGX_OK) {
        return NGX_OK;
    }

    /* Two DIFFERENT EACCES sources land here, and they must map to
     * different statuses (phase-3 T1):
     *   (a) the per-user backend credential gate (brix_vfs_ns_cred,
     *       src/fs/vfs/vfs_xattr.c) denying a no-cred user in deny
     *       mode on a REMOTE-BACKED export — the gate runs and fails
     *       BEFORE brix_vfs_setxattr ever reaches a syscall, and only
     *       engages when the lock ctx's vctx->sd is a non-NULL backend
     *       instance (webdav_lock_vfs_ctx_init in prop_xattr.c binds
     *       it via brix_webdav_backend_instance). This is a policy
     *       refusal -> 403.
     *   (b) the impersonation broker's setxattr on a user-owned file
     *       failing EACCES on a LOCAL POSIX export (vctx->sd stays
     *       NULL there, so the gate path above is never taken and
     *       this EACCES can only come from the raw syscall) -- the
     *       service worker genuinely could not perform the op. This
     *       is intentionally left 500 (documented at
     *       webdav_handle_lock's WHAT/WHY/HOW comment above).
     * The two cases are structurally distinguishable at this callsite
     * because vfs_xattr.c sets errno = EACCES from the gate check
     * (source a) using a DIFFERENT code path (drv != NULL) than the
     * plain-syscall EACCES (source b, drv == NULL) -- but distinguishing
     * *here* would require re-deriving whether the export is remote-
     * backed, duplicating prop_xattr.c's internal ctx-driver logic.
     * brix_webdav_backend_instance(conf, log) is idempotent and cheap
     * (a config-scoped cached instance, not a fresh connection), so
     * calling it again here to re-derive "remote-backed?" is safe and
     * avoids threading a new out-parameter through webdav_lock_xattr_write. */
    if ((errno == EACCES || errno == EPERM)
        && brix_webdav_backend_instance(conf, r->connection->log) != NULL)
    {
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * webdav_lock_refresh — refresh an existing active lock (RFC 4918 §9.10).
 *
 * WHAT: If the client owns the lock, extend its timeout and rewrite the xattr;
 *       otherwise report 423 Locked.
 * WHY:  Splits the "existing lock" branch out of the handler so both branches
 *       read as a single decision each. HOW: token match via the If header,
 *       XATTR_REPLACE rewrite; sets 200 OK on success. Returns NGX_OK when the
 *       caller should proceed to emit the XML body, else a finalized status.
 */
static ngx_int_t
webdav_lock_refresh(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    webdav_lock_xattr_t *e)
{
    if (!webdav_lock_if_header_matches(r, e->token)) {
        return NGX_HTTP_LOCKED;
    }
    e->expires = webdav_lock_parse_timeout(r, conf);
    if (webdav_lock_xattr_write(r, path, e, XATTR_REPLACE) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.status = NGX_HTTP_OK;
    return NGX_OK;
}

/*
 * webdav_lock_create — create a new lock atomically (RFC 4918 §9.10).
 *
 * WHAT: Builds a fresh lock record (new token, owner, scope, depth, timeout,
 *       lock-null flag) and writes it with XATTR_CREATE.
 * WHY:  Splits the "no existing lock" branch out of the handler. HOW: delegates
 *       owner selection and write-result mapping to helpers; sets 201 Created on
 *       success. Returns NGX_OK when the caller should emit the XML body, else a
 *       finalized status.
 */
static ngx_int_t
webdav_lock_create(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    const webdav_lock_new_t *nl, webdav_lock_xattr_t *e)
{
    ngx_http_brix_webdav_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    ngx_int_t rc;

    ngx_memzero(e, sizeof(*e));
    webdav_generate_uuid(e->token, sizeof(e->token));
    webdav_lock_owner_set(e, nl->owner, ctx);

    e->exclusive      = nl->exclusive;
    e->depth_infinity = nl->depth_infinity;
    e->is_null        = nl->created_null;
    e->expires        = webdav_lock_parse_timeout(r, conf);

    rc = webdav_lock_xattr_write(r, path, e, XATTR_CREATE);
    rc = webdav_lock_write_status(r, conf, rc);
    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.status = NGX_HTTP_CREATED;
    return NGX_OK;
}

static void
webdav_handle_lock_inner(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    webdav_lock_xattr_t                e;
    webdav_lock_new_t                  nl;
    char                               owner[256];

    ngx_memzero(&nl, sizeof(nl));
    nl.depth_infinity = 1;
    nl.exclusive = 1;
    nl.owner = owner;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon,
                                              path, sizeof(path));
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    rc = webdav_lock_parse_depth(r, &nl.depth_infinity);
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    webdav_lock_parse_body(r, owner, sizeof(owner), &nl.exclusive);

    /* RFC 4918 §9.10.1: LOCK on non-existent resource MUST create zero-byte resource. */
    rc = webdav_lock_create_null(r, path, &nl.created_null);
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    rc = webdav_lock_xattr_read(r, path, &e);
    if (rc == NGX_ERROR) {
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Treat expired lock as absent. */
    if (rc == NGX_OK && e.expires <= (int64_t) ngx_time()) {
        (void) webdav_lock_xattr_delete(r, path);
        rc = NGX_DECLINED;
    }

    if (rc == NGX_OK) {
        /* Existing active lock: refresh if token matches, else 423. */
        rc = webdav_lock_refresh(r, conf, path, &e);
    } else {
        /* No lock: create atomically with XATTR_CREATE. */
        rc = webdav_lock_create(r, conf, path, &nl, &e);
    }

    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    webdav_lock_xml_response(r, &e);
}

ngx_int_t
webdav_handle_unlock(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    ngx_table_elt_t                   *h;
    webdav_lock_xattr_t                e;
    const u_char                      *lock_val;
    size_t                             lock_len, token_len;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    h = webdav_tpc_find_header(r, "Lock-Token", sizeof("Lock-Token") - 1);
    if (h == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon,
                                              path, sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_lock_xattr_read(r, path, &e);
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (rc == NGX_DECLINED || e.expires <= (int64_t) ngx_time()) {
        /* No active lock on this path. */
        if (rc == NGX_OK) {
            (void) webdav_lock_xattr_delete(r, path);
            webdav_lock_reap_null(r, path, &e);
        }
        return NGX_HTTP_CONFLICT;
    }

    /* Strip angle brackets from Lock-Token header: <opaquelocktoken:...> → token */
    lock_val = h->value.data;
    lock_len = (size_t) h->value.len;
    if (lock_len > 0 && lock_val[0] == '<') {
        lock_val++;
        lock_len--;
        if (lock_len > 0 && lock_val[lock_len - 1] == '>') {
            lock_len--;
        }
    }

    token_len = strlen(e.token);
    if (lock_len != token_len
        || CRYPTO_memcmp(lock_val, (u_char *) e.token, token_len) != 0)
    {
        return NGX_HTTP_CONFLICT;   /* token mismatch — not our lock */
    }

    /*
     * Remove the lock xattr and HONOUR the result.  Under impersonation the
     * removexattr runs (via the broker) as the requester's mapped user, so a
     * NON-OWNER who presents a valid (e.g. stolen/leaked) lock token cannot
     * actually clear the lock on another user's file — the broker returns EACCES.
     * Returning 204 unconditionally would falsely report success for that denied
     * removal; surface it as 403 instead so the lock state and the response agree.
     * (ENODATA/ENOENT collapse to NGX_OK inside the helper — idempotent unlock.)
     */
    if (webdav_lock_xattr_delete(r, path) != NGX_OK) {
        return NGX_HTTP_FORBIDDEN;
    }

    /* RFC 4918 §9.10.1: a lock-null resource that was never converted by a PUT/
     * MKCOL disappears when its lock is removed.  Reap the empty placeholder. */
    webdav_lock_reap_null(r, path, &e);

    return webdav_send_no_body(r, NGX_HTTP_NO_CONTENT);
}

/*
 * webdav_lock_append_supported — emit static <D:supportedlock> XML.
 * Unchanged from SHM implementation.
 */
ngx_int_t
webdav_lock_append_supported(ngx_http_request_t *r,
                             ngx_chain_t **head, ngx_chain_t **tail)
{
    if (brix_http_chain_appendf(r->pool, head, tail,
            "<D:supportedlock>"
            "<D:lockentry>"
            "<D:lockscope><D:exclusive/></D:lockscope>"
            "<D:locktype><D:write/></D:locktype>"
            "</D:lockentry>"
            "<D:lockentry>"
            "<D:lockscope><D:shared/></D:lockscope>"
            "<D:locktype><D:write/></D:locktype>"
            "</D:lockentry>"
            "</D:supportedlock>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * webdav_lock_append_discovery — emit <D:lockdiscovery> XML for PROPFIND.
 * Reads the xattr on path; emits an empty element if no active lock.
 */
ngx_int_t
webdav_lock_append_discovery(ngx_http_request_t *r, const char *path,
                             ngx_chain_t **head, ngx_chain_t **tail)
{
    webdav_lock_xattr_t  e;
    ngx_int_t            rc;
    int64_t              now;
    ngx_uint_t           remaining;
    char                *safe_owner;

    if (brix_http_chain_appendf(r->pool, head, tail,
                                  "<D:lockdiscovery>") == NULL)
    {
        return NGX_ERROR;
    }

    rc = webdav_lock_xattr_read(r, path, &e);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    now = (int64_t) ngx_time();

    if (rc == NGX_OK && e.expires > now) {
        remaining  = (ngx_uint_t) (e.expires - now);
        safe_owner = webdav_escape_xml_text(r->pool,
            (e.owner[0] != '\0') ? e.owner : "anonymous");
        if (safe_owner == NULL) {
            safe_owner = "anonymous";
        }

        if (brix_http_chain_appendf(r->pool, head, tail,
                "<D:activelock>"
                "<D:locktype><D:write/></D:locktype>"
                "<D:lockscope>%s</D:lockscope>"
                "<D:depth>%s</D:depth>"
                "<D:owner>%s</D:owner>"
                "<D:timeout>Second-%lu</D:timeout>"
                "<D:locktoken>"
                "<D:href>%s</D:href>"
                "</D:locktoken>"
                "</D:activelock>",
                e.exclusive ? "<D:exclusive/>" : "<D:shared/>",
                e.depth_infinity ? "infinity" : "0",
                safe_owner, (unsigned long) remaining, e.token) == NULL)
        {
            return NGX_ERROR;
        }
    } else if (rc == NGX_OK) {
        /* Expired lock — clean up lazily (and reap a lock-null placeholder). */
        (void) webdav_lock_xattr_delete(r, path);
        webdav_lock_reap_null(r, path, &e);
    }

    if (brix_http_chain_appendf(r->pool, head, tail,
                                  "</D:lockdiscovery>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
