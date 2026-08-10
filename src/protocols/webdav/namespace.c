/*
 * namespace.c - WebDAV DELETE and MKCOL namespace operations.
 */

#include "webdav.h"
#include "core/compat/fs_walk.h"
#include "fs/vfs/vfs.h"
#include "net/cms/cns.h"        /* BRIX_CNS_ADD/DEL/MKDIR/RMDIR             */
#include "net/cms/cns_emit.h"   /* brix_cns_emit_at, brix_cns_emit_active   */
#include "protocols/shared/backend_async_http.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Build a transient VFS ctx for a confined namespace op on `path` (mirrors the
 * canonical construction in get.c).  Used by DELETE so the unlink/rmdir is
 * metered as OP_DELETE while keeping identical confinement and write-gating.
 */
static void
webdav_ns_vfs_ctx_init(ngx_http_request_t *r, const char *path,
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
        conf->common.cache_root_canon, conf->common.allow_write, is_tls,
        (wctx != NULL) ? wctx->identity : NULL, path);
    /* Wire per-user backend credential gate (Phase 2 Task 1) so that
     * DELETE/MKCOL namespace ops on a remote backend use the per-user
     * credential and deny mode rejects before opening any origin session. */
    brix_vfs_ctx_bind_backend_cred(vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    webdav_vfs_bind_deleg(r, conf, vctx);
}

/*
 * ---------------------------------------------------------------------------
 * CNS reporting (phase-97 §5)
 *
 * WHY: `brix_cns_emit` binds to a stream{} server conf, so until now only
 *      root:// mutations reached the manager's inventory. A federation that
 *      also accepts WebDAV writes had a manager that never learned about them —
 *      every such path fell through to a locate forever. These three wrappers
 *      put the http{} plane on the same seam.
 * HOW: gate on a live manager link FIRST (so a non-federated node pays nothing),
 *      then observe through the plane's own confined VFS ctx — never a raw
 *      stat(), which would both breach INVARIANT 12 and read the wrong thing on
 *      a non-POSIX backend — and report the observed metadata.
 *
 * Best-effort throughout: a mutation that cannot be reported still succeeded,
 * and the manager falls through to locate for anything it does not hold.
 * ---------------------------------------------------------------------------
 */

/*
 * One completed create/overwrite: report the object as it now stands.
 * `path` is the resolved (root_canon-prefixed) on-disk path.
 */
void
webdav_cns_note_written(ngx_http_request_t *r, const char *path)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    brix_vfs_ctx_t                    vctx;
    brix_vfs_stat_t                   st;

    if (path == NULL || !brix_cns_emit_active()) {
        return;
    }

    webdav_ns_vfs_ctx_init(r, path, &vctx);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &st) != NGX_OK) {
        return;              /* unobservable → report nothing over a guess */
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    brix_cns_emit_at(conf->common.root_canon,
                     st.is_directory ? BRIX_CNS_MKDIR : BRIX_CNS_ADD,
                     path, (uint64_t) st.size, (uint64_t) st.mtime);
}

/*
 * One completed removal. No probe: the object is gone, and apply ignores
 * size/mtime for DEL/RMDIR — so the caller's own dir-ness is the only input.
 */
void
webdav_cns_note_removed(ngx_http_request_t *r, const char *path, int is_dir)
{
    ngx_http_brix_webdav_loc_conf_t *conf;

    if (path == NULL || !brix_cns_emit_active()) {
        return;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    brix_cns_emit_at(conf->common.root_canon,
                     is_dir ? BRIX_CNS_RMDIR : BRIX_CNS_DEL, path, 0, 0);
}

/*
 * One completed rename. Emits a single subtree-aware MV for the same reason the
 * root plane does: a DEL+ADD pair would strand every recorded child of a moved
 * collection at a path the cluster no longer serves. Degrades to a DEL of the
 * source when the destination cannot be observed — an absent entry falls
 * through to locate, an invented size is served as truth.
 */
void
webdav_cns_note_moved(ngx_http_request_t *r, const char *src, const char *dst)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    brix_vfs_ctx_t                    vctx;
    brix_vfs_stat_t                   st;

    if (src == NULL || dst == NULL || !brix_cns_emit_active()) {
        return;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    webdav_ns_vfs_ctx_init(r, dst, &vctx);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &st) != NGX_OK) {
        brix_cns_emit_at(conf->common.root_canon, BRIX_CNS_DEL, src, 0, 0);
        return;
    }

    brix_cns_emit_rename_at(conf->common.root_canon, src, dst,
                            (uint64_t) st.size, (uint64_t) st.mtime,
                            st.is_directory);
}

/*
 * webdav_delete_path_recursive — recursively delete a directory and all its members.
 *
 * Uses opendir/readdir to traverse the tree.  Files are unlinked; directories
 * are emptied recursively and then rmdir'd.  Root confinement is enforced
 * via brix_unlink_confined_canon.
 *
 * Returns: NGX_OK on success, NGX_ERROR on any failure.
 */
ngx_int_t
webdav_delete_path_recursive(ngx_log_t *log, const char *root_canon,
                             const char *path)
{
    return brix_fs_remove_tree_confined(log, root_canon, path);
}

/*
 * Map a completed DELETE's result (op_errno 0 = removed) to the WebDAV response.
 * Shared by the synchronous handler and the async-queue wake so both render the
 * same status: 0 -> 204; ENOTEMPTY -> 409; ENOENT -> 404; EACCES -> 403 (deny-mode
 * per-user backend credential rejection); else 500. Success sends the body here;
 * error branches return the status code for the caller to finalise.
 */
static ngx_int_t
webdav_delete_respond(ngx_http_request_t *r, int op_errno)
{
    if (op_errno == 0) {
        return webdav_send_no_body(r, NGX_HTTP_NO_CONTENT);
    }
    if (op_errno == ENOTEMPTY) {
        return NGX_HTTP_CONFLICT;
    }
    if (op_errno == ENOENT) {
        return NGX_HTTP_NOT_FOUND;
    }
    if (op_errno == EACCES) {
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * What a deferred DELETE has to remember in order to report itself.
 *
 * The queue runs the unlink/rmdir long after the handler returned, so the wake
 * is the only place a CNS event can come from — and by then the handler's stack
 * (with the resolved path and the lstat that decided dir-ness) is gone. Both
 * are carried here, in the request pool, for the wake to read back.
 */
typedef struct {
    const char *path;
    int         is_dir;
} webdav_delete_async_ctx_t;

/*
 * Async-queue wake for a deferred DELETE: render the response for the batch's
 * unlink/rmdir result and finalise the request. Runs on the event loop after the
 * flush; ctx carries what the CNS event needs (NULL when CNS is not reporting).
 */
static void
webdav_delete_async_render(ngx_http_request_t *r, void *ctx, int op_errno)
{
    webdav_delete_async_ctx_t *dctx = ctx;

    /* op_errno 0 is "the queue removed it"; anything else left the namespace
     * untouched and must not evict the manager's entry. */
    if (op_errno == 0 && dctx != NULL) {
        webdav_cns_note_removed(r, dctx->path, dctx->is_dir);
    }

    webdav_metrics_finalize_request(r, webdav_delete_respond(r, op_errno));
}

/*
 * Package the resolved path + dir-ness for the wake above. Returns NULL when
 * there is nothing to report to (no manager link) or the pool is exhausted —
 * both leave the DELETE itself untouched, which is the best-effort contract.
 */
static webdav_delete_async_ctx_t *
webdav_delete_async_ctx(ngx_http_request_t *r, const char *path, int is_dir)
{
    webdav_delete_async_ctx_t *dctx;
    size_t                     len;
    char                      *copy;

    if (!brix_cns_emit_active()) {
        return NULL;
    }

    len = ngx_strlen(path);

    dctx = ngx_palloc(r->pool, sizeof(*dctx));
    copy = ngx_pnalloc(r->pool, len + 1);
    if (dctx == NULL || copy == NULL) {
        return NULL;
    }

    ngx_memcpy(copy, path, len + 1);
    dctx->path = copy;
    dctx->is_dir = is_dir;

    return dctx;
}

/*
 * webdav_handle_delete — handle HTTP DELETE: remove a file or directory.
 *
 * RFC 4918 §9.6.1: DELETE on a collection MUST recursively delete all its
 * members and all their properties.
 *
 * The fd-cache entry for the path is evicted before the delete to prevent
 * use-after-free on cached file descriptors.
 */
ngx_int_t
webdav_handle_delete(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    char                              path[WEBDAV_MAX_PATH];
    struct stat                       sb;
    ngx_int_t                         rc;
    brix_vfs_ctx_t                  vctx;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_check_locks_tree(r, path);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Async backend: enqueue the unlink/rmdir and park the request until the
     * batch flushes. DELETE is already allow_write-gated at the access phase, so
     * the write gate has passed before we reach the queue. The queue drives the
     * same confined-VFS primitive as the sync path, keyed by the absolute
     * resolved `path`; a directory maps to RMDIR (non-recursive => require-empty,
     * the Standard WebDAV module policy), a file/symlink to UNLINK. NGX_DECLINED
     * (async off / enqueue failure) falls through to the inline op. */
    if (conf->common.backend_async) {
        brix_baq_op_t op = S_ISDIR(sb.st_mode) ? BRIX_BAQ_RMDIR
                                               : BRIX_BAQ_UNLINK;
        if (brix_baq_http_try(r, &conf->common, op, conf->common.root_canon,
                              path, NULL, 0, webdav_delete_async_render,
                              webdav_delete_async_ctx(r, path,
                                                      S_ISDIR(sb.st_mode)))
            == NGX_DONE)
        {
            return NGX_DONE;
        }
    }

    /* Route the delete through the metered VFS surface. webdav_resolve_stat
     * lstat'd the target (vfs_stat does not follow symlinks), so S_ISDIR here
     * agrees with brix_ns_delete's own lstat dispatch: a directory goes to
     * rmdir (non-recursive => require-empty, the Standard WebDAV module policy);
     * a file or symlink goes to unlink. DELETE is already allow_write-gated at
     * the access phase, so the VFS write-gate never fires here. */
    webdav_ns_vfs_ctx_init(r, path, &vctx);

    if (S_ISDIR(sb.st_mode)) {
        rc = brix_vfs_rmdir(&vctx, 0);
    } else {
        rc = brix_vfs_unlink(&vctx);
    }

    /* Report only a removal that actually happened: a failed DELETE must not be
     * able to evict a live entry from the manager's inventory. */
    if (rc == NGX_OK) {
        webdav_cns_note_removed(r, path, S_ISDIR(sb.st_mode));
    }

    return webdav_delete_respond(r, (rc == NGX_OK) ? 0 : errno);
}

ngx_int_t
webdav_handle_mkcol(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    brix_vfs_ctx_t                   vctx;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon, path,
                                             sizeof(path));
    if (rc == (ngx_int_t) NGX_HTTP_NOT_FOUND) {
        return NGX_HTTP_CONFLICT;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_check_locks(r, path, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Route MKCOL through the metered VFS surface (non-recursive: a missing
     * parent component is a 409, matching the prior BRIX_NS_NOT_FOUND mapping).
     * MKCOL is allow_write-gated at the access phase, so the VFS write-gate never
     * fires here. errno after a failed vfs_mkdir mirrors brix_ns_mkdir:
     * EEXIST (target present) -> 405, ENOENT (parent missing) -> 409. */
    webdav_ns_vfs_ctx_init(r, path, &vctx);

    if (brix_vfs_mkdir(&vctx, 0755, 0 /* no parents */) == NGX_OK) {
        webdav_cns_note_written(r, path);
        return webdav_send_no_body(r, NGX_HTTP_CREATED);
    }

    if (errno == EEXIST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (errno == ENOENT) {
        return NGX_HTTP_CONFLICT;
    }

    if (errno == EACCES) {
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
