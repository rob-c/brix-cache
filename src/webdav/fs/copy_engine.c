/*
 * WHAT: WebDAV local COPY helpers (not HTTP-TPC remote transfers).
 *       webdav_copy_file / webdav_copy_dir_recursive copy a confined file or
 *       directory tree on the local export, preserving metadata.
 *
 * WHY:  WebDAV COPY/MOVE on local destinations needs a confined, metadata-
 *       preserving copy. The confined byte copy (copy_file_range + fallback), the
 *       confined open/opendir/mkdir, fattr preservation, and the recursion now
 *       live in the VFS (xrootd_vfs_copyfile / xrootd_vfs_copytree,
 *       src/fs/vfs_walk.c) so this protocol layer never reaches a confined helper
 *       directly — and the same engine is reusable by any future copy consumer.
 *
 * HOW:  Both functions are thin wrappers that delegate to the VFS copy primitives
 *       with preserve_xattrs=1 (the generic user.* fattrs) plus a metadata
 *       callback (webdav_copy_meta_cb) that carries the WebDAV-specific dead-
 *       property xattrs — the one bit the protocol-agnostic VFS must not know.
 */

#include "copy_engine.h"
#include "../../fs/vfs.h"   /* xrootd_vfs_copyfile / xrootd_vfs_copytree */

/*
 * webdav_copy_meta_cb — per-entry metadata callback for the VFS copy primitives.
 * The generic user.* fattrs are preserved by the VFS itself (preserve_xattrs=1);
 * this carries the WebDAV-specific dead-property xattrs that the VFS layer must
 * not know about. cookie is the request log.
 */
static ngx_int_t
webdav_copy_meta_cb(void *cookie, const char *src, const char *dst, int is_dir)
{
    (void) is_dir;
    webdav_dead_props_copy((ngx_log_t *) cookie, src, dst);
    return NGX_OK;
}

/*
 * WebDAV local COPY now delegates the confined copy + traversal to the VFS
 * (xrootd_vfs_copyfile / xrootd_vfs_copytree, src/fs/vfs_walk.c) — which owns the
 * copy_file_range/fallback, the confined open/opendir/mkdir, fattr preservation,
 * and the recursion. These thin wrappers add only the WebDAV dead-property copy
 * via the metadata callback, keeping the protocol-specific bit out of the VFS.
 */
ngx_int_t
webdav_copy_file(ngx_log_t *log, const char *root_canon,
    const char *src, const char *dst)
{
    return xrootd_vfs_copyfile(log, root_canon, src, dst,
                               1 /* preserve xattrs */, webdav_copy_meta_cb, log);
}

ngx_int_t
webdav_copy_dir_recursive(ngx_log_t *log, const char *root_canon,
    const char *src, const char *dst)
{
    return xrootd_vfs_copytree(log, root_canon, src, dst,
                               1 /* preserve xattrs */, webdav_copy_meta_cb, log);
}
