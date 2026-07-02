#include "ngx_xrootd_fattr.h"
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "compat/alloc_guard.h"

/* kXR_fa_recurse support */
/*
 * kXR_fa_recurse is a local extension: when fattrList targets a directory the
 * server walks the subtree and emits one "<relpath>:<U.name>\0" entry per
 * managed xattr found on each regular file (NOT the standard XRootD behaviour).
 *
 * FATTR_RECURSE_XLIST_BUF — per-file listxattr() scratch; names longer than
 *   this whole buffer are silently skipped (return value <= 0 below).
 * FATTR_RECURSE_RESP_CAP  — hard ceiling on the assembled response; entries
 *   past the cap are dropped (see the rctx->len bound check), bounding both
 *   memory and wire frame size for huge trees.
 * FATTR_RECURSE_MAX_DEPTH — recursion guard against deep/symlink-loop trees.
 */
#define FATTR_RECURSE_XLIST_BUF  8192
#define FATTR_RECURSE_RESP_CAP   (256 * 1024)
#define FATTR_RECURSE_MAX_DEPTH  16

typedef struct {
    u_char     *buf;
    size_t      cap;
    size_t      len;
    size_t      root_len;   /* length of root path; relpath = fullpath + root_len */
    /* Carried so each visited node can build a transient VFS ctx (every opendir /
     * lstat / listxattr in the walk routes through the confined VFS seam). */
    ngx_pool_t *pool;
    ngx_log_t  *log;
    const char *root_canon;
} fattr_recurse_ctx_t;

/*
 *
 * WHAT: Depth-first walk of dir_path. For every regular file it reads the file's
 *       xattr name list, keeps only the "user.U.*" managed keys, and appends an
 *       entry "<relpath>:<U.name>\0" (relpath = path relative to the recurse root)
 *       into rctx->buf, never exceeding rctx->cap.
 *
 * WHY: Lets a single fattrList on a directory enumerate all managed attributes in
 *       a subtree (a local convenience extension). lstat (not stat) is used so we
 *       descend real directories only and never follow symlinks into other trees;
 *       dotfiles are skipped to avoid . / .. recursion and hidden control files.
 *
 * HOW: Returns early past FATTR_RECURSE_MAX_DEPTH. Opens the dir via the VFS
 *       (xrootd_vfs_opendir_quiet) and iterates with xrootd_vfs_readdir, whose
 *       per-child lstat (nofollow) is the same "do not follow symlinks out of the
 *       subtree" guarantee — recurse into dirs, ignore non-regular files. relpath
 *       is computed by offsetting past root_len (and a leading '/'). Each file's
 *       xattr names come from xrootd_vfs_listxattr into a stack buffer that is
 *       NUL-separated; the inner loop strides name-by-name. Entries that would
 *       overflow rctx->cap are dropped (no error — best-effort enumeration).
 *       No return value: results accumulate in rctx. */
static void
fattr_recurse_dir(fattr_recurse_ctx_t *rctx, const char *dir_path, int depth)
{
    xrootd_vfs_ctx_t   dvctx;
    xrootd_vfs_dir_t  *dir;
    ngx_str_t          name;
    xrootd_vfs_stat_t  vst;
    char               fpath[XROOTD_PATH_MAX];
    char               xlist[FATTR_RECURSE_XLIST_BUF];
    ssize_t            list_sz;
    char              *lp, *lend;
    size_t             full_nlen;
    const char        *relpath;
    int                plen;
    ngx_int_t          rc;

    if (depth > FATTR_RECURSE_MAX_DEPTH) {
        return;
    }

    /* Confined, non-metered open of this subtree directory (the enclosing
     * fattrList op accounts for the whole walk). */
    xrootd_vfs_ctx_init(&dvctx, rctx->pool, rctx->log, XROOTD_PROTO_STREAM,
        rctx->root_canon, NULL, 0 /* allow_write */, 0 /* is_tls */, NULL,
        dir_path);
    dir = xrootd_vfs_opendir_quiet(&dvctx, NULL);
    if (dir == NULL) {
        return;
    }

    /* readdir with a stat_out performs a per-child lstat (nofollow) — "." and
     * ".." are already filtered by the VFS. */
    while ((rc = xrootd_vfs_readdir(dir, &name, &vst)) == NGX_OK) {
        /* Skip any dotfile — avoids hidden control files (and self/parent). */
        if (name.len == 0 || name.data[0] == '.') {
            continue;
        }

        /* Build the absolute child path; drop entries that would truncate. */
        plen = snprintf(fpath, sizeof(fpath), "%s/%s", dir_path,
                        (char *) name.data);
        if (plen < 0 || plen >= (int) sizeof(fpath)) {
            continue;
        }

        if (vst.is_directory) {
            fattr_recurse_dir(rctx, fpath, depth + 1);
            continue;
        }

        /* Only regular files carry managed xattrs we report. */
        if (!vst.is_regular) {
            continue;
        }

        /* relpath = path relative to the recurse root (strip root + leading '/'). */
        relpath = fpath + rctx->root_len;
        if (*relpath == '/') {
            relpath++;
        }

        /* listxattr (via the VFS) fills xlist with NUL-separated names; <=0 means
         * none/error. A transient per-file ctx re-verifies confinement. */
        {
            xrootd_vfs_ctx_t fvctx;

            xrootd_vfs_ctx_init(&fvctx, rctx->pool, rctx->log,
                XROOTD_PROTO_STREAM, rctx->root_canon, NULL, 0, 0, NULL, fpath);
            list_sz = xrootd_vfs_listxattr(&fvctx, xlist, sizeof(xlist));
        }
        if (list_sz <= 0) {
            continue;
        }

        /* Stride name-by-name through the NUL-separated list (lp..lend). */
        lp   = xlist;
        lend = xlist + list_sz;
        while (lp < lend) {
            full_nlen = strlen(lp);
            /* Keep only our managed "user.U.*" keys (and require a non-empty
             * suffix after the prefix). */
            if (strncmp(lp, XROOTD_FATTR_XKEY_PFX, XROOTD_FATTR_XKEY_PFX_LEN) == 0
                && full_nlen > XROOTD_FATTR_XKEY_PFX_LEN)
            {
                /* Strip the full internal "user.U." prefix (7 bytes) so the
                 * client sees the bare name it set — the reference uses 'U' only
                 * as an internal SFS namespace and returns verbatim names in the
                 * List response (XeqFALsd). Returning "U.name" both diverged from
                 * stock AND broke list→get round-trips (a re-get of "U.name"
                 * would resolve to "user.U.U.name"). */
                const char *resp_name   = lp + XROOTD_FATTR_XKEY_PFX_LEN;
                size_t      resp_nlen   = full_nlen - XROOTD_FATTR_XKEY_PFX_LEN;
                size_t      relpath_len = strlen(relpath);
                /* entry = "relpath:name\0" — +1 for ':' separator, +1 for NUL */
                size_t      entry_len   = relpath_len + 1 + resp_nlen + 1;

                /* Append only if it fits; over-cap entries are silently dropped. */
                if (rctx->len + entry_len <= rctx->cap) {
                    ngx_memcpy(rctx->buf + rctx->len, relpath, relpath_len);
                    rctx->len += relpath_len;
                    rctx->buf[rctx->len++] = ':';
                    ngx_memcpy(rctx->buf + rctx->len, resp_name, resp_nlen);
                    rctx->len += resp_nlen;
                    rctx->buf[rctx->len++] = '\0';
                }
            }
            /* Advance past this name and its NUL terminator. */
            lp += full_nlen + 1;
        }
    }

    xrootd_vfs_closedir(dir, rctx->log);
}

/*
 *
 * WHAT: Allocates the response accumulator, seeds the walk context (root_len so
 *       child paths are reported relative to this directory), drives
 *       fattr_recurse_dir() over the tree, and sends the assembled
 *       "<relpath>:<U.name>\0" list as a kXR_fattr OK response.
 *
 * WHY: Entry point for the kXR_fa_recurse extension; isolates the one-shot buffer
 *       allocation and response framing from the recursive walker.
 *
 * HOW: Buffer comes from the connection pool (freed with the request). An empty
 *       result still returns OK with a NULL/0 body (valid empty list, not error). */
static ngx_int_t
fattr_list_recurse(xrootd_ctx_t *ctx, ngx_connection_t *c,
    xrootd_vfs_ctx_t *vctx, const char *path)
{
    fattr_recurse_ctx_t rctx;
    u_char             *buf;

    XROOTD_PALLOC_OR_RETURN(buf, c->pool, FATTR_RECURSE_RESP_CAP, xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory"));

    rctx.buf        = buf;
    rctx.cap        = FATTR_RECURSE_RESP_CAP;
    rctx.len        = 0;
    rctx.root_len   = strlen(path);  /* relpath = fullpath + root_len in the walk */
    rctx.pool       = vctx->pool;
    rctx.log        = vctx->log;
    rctx.root_canon = vctx->root_canon;

    fattr_recurse_dir(&rctx, path, 0);

    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    if (rctx.len == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    return xrootd_send_ok(ctx, c, rctx.buf, (uint32_t) rctx.len);
}

/*
 *
 * WHAT: Handles kXR_fattrList by calling listxattr(path, NULL, 0) for path-based
 *       operations or flistxattr(fd, NULL, 0) for open-file-handle operations to
 *       query the size of all attribute names stored on the filesystem, then reads
 *       the full NUL-separated name string into a buffer. Filters entries to only
 *       those prefixed with XROOTD_FATTR_XKEY_PFX (the user namespace prefix used by
 *       nginx-xrootd), stripping the 5-byte prefix from returned names so clients see
 *       bare attribute keys. When kXR_fa_aData flag is set, also reads each filtered
 *       attribute's value via getxattr/fgetxattr and appends it to the response.
 *
 * WHY: XRootD fattrList returns all user-space extended attributes on a file;
 *       nginx-xrootd uses only the user namespace prefixed with "user." so filtering
 *       ensures only managed attributes are visible. The two-phase list (query size
 *       then read) prevents over-allocation. ENOTSUP/EOPNOTSUPP handled gracefully —
 *       filesystems without xattr support return empty response rather than error.
 *       Thread safety: operates only on provided ctx, c, pool and local stack variables. */
ngx_int_t fattr_list(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    xrootd_vfs_ctx_t *vctx, const char *path, int fd,
                    int options) {
    ngx_pool_t *pool = c->pool;
    int aData = (options & kXR_fa_aData);

    /* Directory + recurse flag → take the subtree-walk path instead. */
    if ((options & kXR_fa_recurse) && path != NULL) {
        xrootd_vfs_stat_t rvst;
        if (xrootd_vfs_probe(vctx, 0 /* follow */, &rvst) == NGX_OK
            && rvst.is_directory) {
            return fattr_list_recurse(ctx, c, vctx, path);
        }
    }
    /* Phase 1: probe (size, NULL) to learn how big the name list is. */
    ssize_t list_sz = path ? xrootd_vfs_listxattr(vctx, NULL, 0)
                           : xrootd_vfs_flistxattr(vctx, fd, NULL, 0);
    if (list_sz < 0) {
        /* Filesystem with no xattr support → empty list, not an error. */
        if (errno == ENOTSUP || errno == EOPNOTSUPP) {
            XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
            return xrootd_send_ok(ctx, c, NULL, 0);
        }
        XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
        return xrootd_send_error(ctx, c, kXR_FSError, "listxattr failed");
    }
    if (list_sz == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    /* +4096 slack absorbs names added between phase 1 and phase 2 (TOCTOU). */
    char *raw = ngx_palloc(pool, list_sz + 4096);
    if (raw == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }
    /* Phase 2: read the actual NUL-separated name list into raw. */
    ssize_t actual = path ? xrootd_vfs_listxattr(vctx, raw, list_sz + 4096)
                          : xrootd_vfs_flistxattr(vctx, fd, raw, list_sz + 4096);
    if (actual < 0) {
        return xrootd_send_error(ctx, c, kXR_FSError, "listxattr failed");
    }
    if (actual == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    /*
     * Worst-case response size: every raw name kept, plus for aData each of up
     * to kXR_faMaxVars attributes contributes a 4-byte length prefix + a value
     * up to 4096 bytes; +64 header slop. Over-provisioned so the build loop need
     * not realloc — the break below still guards against exceeding it.
     */
    size_t resp_cap = (size_t) actual + kXR_faMaxVars * (4 + 4096) + 64;
    u_char *resp = ngx_palloc(pool, resp_cap);
    if (resp == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }
    /* wp = write cursor into resp; lp/lend stride the raw name list. */
    u_char *wp   = resp;
    char   *lp   = raw;
    char   *lend = raw + actual;
    while (lp < lend) {
        size_t full_nlen = strlen(lp);
        /* Emit only managed "user.U.*" keys with a non-empty suffix. */
        if (strncmp(lp, XROOTD_FATTR_XKEY_PFX, XROOTD_FATTR_XKEY_PFX_LEN) == 0
            && full_nlen > XROOTD_FATTR_XKEY_PFX_LEN) {
            /* Strip the full internal "user.U." prefix (7 bytes) so the client
             * sees the bare name it set — matching the reference XeqFALsd, which
             * returns verbatim names (the 'U' namespace is internal only). */
            const char *resp_name = lp + XROOTD_FATTR_XKEY_PFX_LEN;
            size_t      resp_nlen = full_nlen - XROOTD_FATTR_XKEY_PFX_LEN;
            /* name + NUL, plus (if aData) the 4-byte len prefix + value buffer. */
            size_t space_needed = resp_nlen + 1
                                  + (aData ? 4 + 4096 : 0);
            /* Stop before overrunning resp_cap (rest of the list is dropped). */
            if ((size_t)(wp - resp) + space_needed > resp_cap) break;
            ngx_memcpy(wp, resp_name, resp_nlen);
            wp += resp_nlen;
            *wp++ = '\0';
            if (aData) {
                /* Append [uint32 big-endian vlen][value bytes] for this attr.
                 * Note getxattr uses the full "user.U.name" key (lp), while the
                 * emitted name above was the stripped form. */
                char    val[4096];
                ssize_t vlen = path
                    ? xrootd_vfs_getxattr(vctx, lp, val, sizeof(val))
                    : xrootd_vfs_fgetxattr(vctx, fd, lp, val, sizeof(val));
                if (vlen < 0) vlen = 0;   /* unreadable value → zero-length */
                uint32_t vlen_be = htonl((uint32_t) vlen);
                ngx_memcpy(wp, &vlen_be, 4);
                wp += 4;
                if (vlen > 0) {
                    ngx_memcpy(wp, val, vlen);
                    wp += vlen;
                }
            }
        }
        /* Advance past this name and its NUL terminator. */
        lp += full_nlen + 1;
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    size_t resp_len = (size_t)(wp - resp);
    if (resp_len == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    return xrootd_send_ok(ctx, c, resp, (uint32_t) resp_len);
}
