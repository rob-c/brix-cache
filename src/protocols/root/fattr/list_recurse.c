#include "ngx_brix_fattr.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "core/compat/safe_size.h"

/* kXR_fa_recurse is a local extension which returns
 * "<relative-path>:<attribute-name>\0" entries for a directory tree. */
#define FATTR_RECURSE_XLIST_BUF  BRIX_ROOT_FATTR_XLIST_BUF
#define FATTR_RECURSE_RESP_CAP   BRIX_ROOT_FATTR_RESP_CAP
#define FATTR_RECURSE_MAX_DEPTH  16

typedef struct {
    u_char               *buf;
    size_t                cap;
    size_t                len;
    size_t                root_len;
    const brix_vfs_ctx_t  *vfs_scope;
    ngx_log_t             *log;
    ngx_pool_t            *pool;
} fattr_recurse_ctx_t;

/*
 * WHAT: Derives a confined VFS context for one node in a recursive walk.
 *
 * WHY: Every metadata operation must retain the parent request's identity,
 *       credential and export confinement rather than use service credentials.
 *
 * HOW: Rebinds only the path while inheriting the existing VFS scope. */
static void
fattr_recurse_init_node_ctx(fattr_recurse_ctx_t *rctx, brix_vfs_ctx_t *vctx,
    const char *node_path)
{
    (void) brix_vfs_ctx_derive_path(vctx, rctx->vfs_scope, node_path);
}

/*
 * WHAT: Appends managed names from one bounded NUL-separated xattr list.
 *       Returns NGX_OK, or NGX_ERROR for malformed or over-cap input.
 *
 * WHY: Backend lengths and terminators are untrusted; accepting a partial list
 *       can hide attributes and an unbounded strlen can read past the buffer.
 *
 * HOW: Finds every terminator with memchr, decodes the managed name, computes
 *      the complete entry with checked additions, then appends it atomically. */
static ngx_int_t
fattr_recurse_emit_names(fattr_recurse_ctx_t *rctx, brix_vfs_ctx_t *vctx,
    const char *fpath, const char *relpath, const char *xlist, size_t list_sz)
{
    const char *cursor = xlist;
    const char *end = xlist + list_sz;
    size_t      relpath_len = strlen(relpath);

    while (cursor < end) {
        const char          *nul;
        brix_fattr_stored_t  stored;
        int                  decoded;

        nul = memchr(cursor, '\0', (size_t) (end - cursor));
        if (nul == NULL) {
            errno = EIO;
            return NGX_ERROR;
        }
        decoded = fattr_storage_decode_list(rctx->pool, vctx, fpath, -1,
                                             cursor, &stored);
        if (decoded < 0) return NGX_ERROR;
        if (decoded == 1) {
            size_t entry_len;

            if (brix_size_add(relpath_len, 1U, &entry_len) != NGX_OK
                || brix_size_add(entry_len, stored.nlen, &entry_len) != NGX_OK
                || brix_size_add(entry_len, 1U, &entry_len) != NGX_OK
                || rctx->len > rctx->cap
                || entry_len > rctx->cap - rctx->len)
            {
                errno = ERANGE;
                return NGX_ERROR;
            }
            ngx_memcpy(rctx->buf + rctx->len, relpath, relpath_len);
            rctx->len += relpath_len;
            rctx->buf[rctx->len++] = ':';
            ngx_memcpy(rctx->buf + rctx->len, stored.name, stored.nlen);
            rctx->len += stored.nlen;
            rctx->buf[rctx->len++] = '\0';
        }
        cursor = nul + 1;
    }
    return NGX_OK;
}

/*
 * WHAT: Adds managed names from one regular file to the recursive response.
 *       Returns NGX_ERROR if a backend violates the bounded-list contract.
 *
 * WHY: A positive backend byte count must never be trusted past the supplied
 *       stack buffer, even when every built-in backend obeys the VFS contract.
 *
 * HOW: Derives the file context, performs one bounded list read, validates the
 *      returned count, and delegates parsing to fattr_recurse_emit_names. */
static ngx_int_t
fattr_recurse_file(fattr_recurse_ctx_t *rctx, const char *fpath,
    const brix_vfs_stat_t *vst)
{
    char            xlist[FATTR_RECURSE_XLIST_BUF];
    ssize_t         list_sz;
    const char     *relpath;
    brix_vfs_ctx_t  fvctx;

    if (!vst->is_regular) return NGX_OK;
    relpath = fpath + rctx->root_len;
    if (*relpath == '/') relpath++;

    fattr_recurse_init_node_ctx(rctx, &fvctx, fpath);
    list_sz = brix_vfs_listxattr(&fvctx, xlist, sizeof(xlist));
    if (list_sz <= 0) return NGX_OK;
    if ((size_t) list_sz > sizeof(xlist)) {
        errno = EIO;
        return NGX_ERROR;
    }
    return fattr_recurse_emit_names(rctx, &fvctx, fpath, relpath, xlist,
                                     (size_t) list_sz);
}

/*
 * WHAT: Walks a confined directory tree and accumulates managed attributes.
 *       Returns NGX_ERROR without sending a partial response on any hard limit.
 *
 * WHY: Symlinks, oversized paths and deep trees must not escape confinement or
 *       produce a deceptively incomplete security-relevant enumeration.
 *
 * HOW: Uses VFS no-follow metadata, descends real directories to a fixed depth,
 *      and closes the directory before propagating every child failure. */
static ngx_int_t
fattr_recurse_dir(fattr_recurse_ctx_t *rctx, const char *dir_path, int depth)
{
    brix_vfs_ctx_t   dvctx;
    brix_vfs_dir_t  *dir;
    ngx_str_t        name;
    brix_vfs_stat_t  vst;
    char             fpath[BRIX_PATH_MAX];
    int              path_len;

    if (depth > FATTR_RECURSE_MAX_DEPTH) {
        errno = ELOOP;
        return NGX_ERROR;
    }
    fattr_recurse_init_node_ctx(rctx, &dvctx, dir_path);
    dir = brix_vfs_opendir_quiet(&dvctx, NULL);
    if (dir == NULL) return NGX_OK;

    while (brix_vfs_readdir(dir, &name, &vst) == NGX_OK) {
        ngx_int_t child_rc;

        if (name.len == 0 || name.data[0] == '.') continue;
        path_len = snprintf(fpath, sizeof(fpath), "%s/%s", dir_path,
                            (char *) name.data);
        if (path_len < 0 || path_len >= (int) sizeof(fpath)) {
            errno = ENAMETOOLONG;
            brix_vfs_closedir(dir, rctx->log);
            return NGX_ERROR;
        }
        child_rc = vst.is_directory
                   ? fattr_recurse_dir(rctx, fpath, depth + 1)
                   : fattr_recurse_file(rctx, fpath, &vst);
        if (child_rc != NGX_OK) {
            brix_vfs_closedir(dir, rctx->log);
            return NGX_ERROR;
        }
    }
    brix_vfs_closedir(dir, rctx->log);
    return NGX_OK;
}

/*
 * WHAT: Builds and sends one recursive fattr response under a fixed cap.
 *       Returns the nginx send result, mapping size failures to ArgTooLong.
 *
 * WHY: Recursive enumeration must be atomic: truncating at the cap would make
 *       a successful response indistinguishable from a complete inventory.
 *
 * HOW: Allocates the capped accumulator, walks the tree, maps any failure, and
 *      sends the complete list only after the walk succeeds. */
static ngx_int_t
fattr_list_recurse(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_vfs_ctx_t *vctx, const char *path)
{
    fattr_recurse_ctx_t  rctx;
    u_char              *buf;

    buf = ngx_palloc(c->pool, FATTR_RECURSE_RESP_CAP);
    if (buf == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        return brix_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }
    rctx.buf = buf;
    rctx.cap = FATTR_RECURSE_RESP_CAP;
    rctx.len = 0;
    rctx.root_len = strlen(path);
    rctx.vfs_scope = vctx;
    rctx.log = vctx->log;
    rctx.pool = c->pool;

    if (fattr_recurse_dir(&rctx, path, 0) != NGX_OK) {
        int walk_errno = errno;

        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        if (walk_errno == ERANGE || walk_errno == E2BIG
            || walk_errno == ENAMETOOLONG)
        {
            return brix_send_error(ctx, c, kXR_ArgTooLong,
                                   "recursive fattr list too large");
        }
        return brix_send_error(ctx, c, kXR_FSError,
                               "recursive fattr list failed");
    }
    BRIX_OP_OK(ctx, BRIX_OP_FATTR);
    if (rctx.len == 0) return brix_send_ok(ctx, c, NULL, 0);
    return brix_send_ok(ctx, c, rctx.buf, (uint32_t) rctx.len);
}

/*
 * WHAT: Dispatches directory requests carrying kXR_fa_recurse.
 *       Returns one when handled and writes the send result to *out.
 *
 * WHY: Keeps the standard flat-list path independent from the local recursive
 *       extension while sharing the already-authorized VFS request context.
 *
 * HOW: Probes the target through VFS and invokes the recursive builder only for
 *      directories; all other requests return zero for normal processing. */
int
fattr_list_try_recurse(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_vfs_ctx_t *vctx, const char *path, int options, ngx_int_t *out)
{
    brix_vfs_stat_t rvst;

    if ((options & kXR_fa_recurse) && path != NULL
        && brix_vfs_probe(vctx, 0, &rvst) == NGX_OK && rvst.is_directory)
    {
        *out = fattr_list_recurse(ctx, c, vctx, path);
        return 1;
    }
    return 0;
}
