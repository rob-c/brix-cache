#include "ngx_brix_fattr.h"
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "core/compat/alloc_guard.h"

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
    ngx_pool_t         *pool;
    ngx_log_t          *log;
    const char          *root_canon;
    /* Per-user backend credential (Phase 2 Task 6 review-finding fix): the
     * requesting session's identity, plus the export's credential dir/fallback
     * policy — carried so every transient per-node ctx below binds the SAME
     * credential gate as the enclosing fattrList op, instead of riding the
     * shared service credential for the whole recursive walk. */
    brix_identity_t   *identity;
    const ngx_str_t     *storage_cred_dir;
    ngx_uint_t           storage_cred_fallback;
    /* Phase-70 §5.4: the enclosing op's resolved delegation mode + captured raw
     * bearer, snapshotted from the parent vctx so every transient per-node ctx
     * below re-binds the SAME backend PASSTHROUGH credential as the top-level
     * fattrList op (not just the dir-based SELECT). deleg_bearer borrows session
     * memory (outlives the walk); deleg_mode is BRIX_CRED_SELECT when off. */
    enum brix_cred_mode  deleg_mode;
    ngx_str_t            deleg_bearer;
} fattr_recurse_ctx_t;

/* Re-bind the enclosing op's captured PASSTHROUGH credential onto a transient
 * per-node ctx during the recursive walk (phase-70 §5.4). A no-op when the op is
 * on the SELECT path or captured no bearer. */
static void
fattr_recurse_bind_deleg(fattr_recurse_ctx_t *rctx, brix_vfs_ctx_t *vctx)
{
    (void) brix_vfs_deleg_bind(rctx->pool, vctx, rctx->deleg_mode,
        &rctx->deleg_bearer, NULL);
}

/*
 *
 * WHAT: Initialises a transient per-node VFS ctx (vctx) for node_path, binding the
 *       enclosing op's confinement root, backend credential, and PASSTHROUGH
 *       delegation exactly as the top-level fattrList op did.
 *
 * WHY: Every opendir/listxattr in the recursive walk must route through the
 *       confined VFS seam under the SAME identity + credential gate as the parent
 *       op (not the shared service credential). Both the directory-open and the
 *       per-file-listxattr call sites need identical binding, so it lives here once.
 *
 * HOW: Non-metered, read-only (allow_write=0), cleartext (is_tls=0) init followed
 *       by the backend-cred bind and the deleg re-bind. No return value. */
static void
fattr_recurse_init_node_ctx(fattr_recurse_ctx_t *rctx, brix_vfs_ctx_t *vctx,
    const char *node_path)
{
    brix_vfs_ctx_init(vctx, rctx->pool, rctx->log, BRIX_PROTO_ROOT,
        rctx->root_canon, NULL, 0 /* allow_write */, 0 /* is_tls */,
        rctx->identity, node_path);
    brix_vfs_ctx_bind_backend_cred(vctx, rctx->storage_cred_dir,
        rctx->storage_cred_fallback);
    fattr_recurse_bind_deleg(rctx, vctx);
}

/*
 *
 * WHAT: Strides a NUL-separated xattr name list (xlist..xlist+list_sz), keeps the
 *       managed "user.U.*" keys, and appends one "<relpath>:<name>\0" entry per key
 *       into rctx->buf (bounded by rctx->cap).
 *
 * WHY: Factors the deepest nesting of the recursive walk (inner name loop + prefix
 *       filter + bounded append) out of fattr_recurse_dir. Behaviour is unchanged:
 *       over-cap entries are silently dropped (best-effort enumeration).
 *
 * HOW: For each name, filter on BRIX_FATTR_XKEY_PFX with a non-empty suffix, strip
 *       the full 7-byte internal prefix so the client sees the bare name it set,
 *       and append only if the whole entry fits. No return value. */
static void
fattr_recurse_emit_names(fattr_recurse_ctx_t *rctx, const char *relpath,
    const char *xlist, ssize_t list_sz)
{
    const char *lp   = xlist;
    const char *lend = xlist + list_sz;

    /* Stride name-by-name through the NUL-separated list (lp..lend). */
    while (lp < lend) {
        size_t full_nlen = strlen(lp);
        /* Keep only our managed "user.U.*" keys (and require a non-empty
         * suffix after the prefix). */
        if (strncmp(lp, BRIX_FATTR_XKEY_PFX, BRIX_FATTR_XKEY_PFX_LEN) == 0
            && full_nlen > BRIX_FATTR_XKEY_PFX_LEN)
        {
            /* Strip the full internal "user.U." prefix (7 bytes) so the
             * client sees the bare name it set — the reference uses 'U' only
             * as an internal SFS namespace and returns verbatim names in the
             * List response (XeqFALsd). Returning "U.name" both diverged from
             * stock AND broke list->get round-trips (a re-get of "U.name"
             * would resolve to "user.U.U.name"). */
            const char *resp_name   = lp + BRIX_FATTR_XKEY_PFX_LEN;
            size_t      resp_nlen   = full_nlen - BRIX_FATTR_XKEY_PFX_LEN;
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

/*
 *
 * WHAT: Processes a single non-directory child (fpath) discovered during the walk:
 *       for a regular file it reads the managed xattr names and emits the matching
 *       "<relpath>:<name>\0" entries into rctx.
 *
 * WHY: Isolates the per-file half of fattr_recurse_dir's loop body (regular-file
 *       gate, relpath computation, transient listxattr, name emission) so the
 *       walker stays a thin dir/file dispatcher.
 *
 * HOW: Non-regular files are ignored. relpath is fpath offset past root_len (and a
 *       leading '/'). A transient per-file ctx re-verifies confinement; listxattr
 *       fills a stack buffer whose NUL-separated names are strided by
 *       fattr_recurse_emit_names. No return value. */
static void
fattr_recurse_file(fattr_recurse_ctx_t *rctx, const char *fpath,
    const brix_vfs_stat_t *vst)
{
    char           xlist[FATTR_RECURSE_XLIST_BUF];
    ssize_t        list_sz;
    const char    *relpath;
    brix_vfs_ctx_t fvctx;

    /* Only regular files carry managed xattrs we report. */
    if (!vst->is_regular) {
        return;
    }

    /* relpath = path relative to the recurse root (strip root + leading '/'). */
    relpath = fpath + rctx->root_len;
    if (*relpath == '/') {
        relpath++;
    }

    /* listxattr (via the VFS) fills xlist with NUL-separated names; <=0 means
     * none/error. A transient per-file ctx re-verifies confinement. */
    fattr_recurse_init_node_ctx(rctx, &fvctx, fpath);
    list_sz = brix_vfs_listxattr(&fvctx, xlist, sizeof(xlist));
    if (list_sz <= 0) {
        return;
    }

    fattr_recurse_emit_names(rctx, relpath, xlist, list_sz);
}

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
 *       (brix_vfs_opendir_quiet) and iterates with brix_vfs_readdir, whose
 *       per-child lstat (nofollow) is the same "do not follow symlinks out of the
 *       subtree" guarantee — recurse into dirs, delegate files to
 *       fattr_recurse_file. No return value: results accumulate in rctx. */
static void
fattr_recurse_dir(fattr_recurse_ctx_t *rctx, const char *dir_path, int depth)
{
    brix_vfs_ctx_t   dvctx;
    brix_vfs_dir_t  *dir;
    ngx_str_t          name;
    brix_vfs_stat_t  vst;
    char               fpath[BRIX_PATH_MAX];
    int                plen;

    if (depth > FATTR_RECURSE_MAX_DEPTH) {
        return;
    }

    /* Confined, non-metered open of this subtree directory (the enclosing
     * fattrList op accounts for the whole walk). */
    fattr_recurse_init_node_ctx(rctx, &dvctx, dir_path);
    dir = brix_vfs_opendir_quiet(&dvctx, NULL);
    if (dir == NULL) {
        return;
    }

    /* readdir with a stat_out performs a per-child lstat (nofollow) — "." and
     * ".." are already filtered by the VFS. */
    while (brix_vfs_readdir(dir, &name, &vst) == NGX_OK) {
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

        fattr_recurse_file(rctx, fpath, &vst);
    }

    brix_vfs_closedir(dir, rctx->log);
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
fattr_list_recurse(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_vfs_ctx_t *vctx, const char *path)
{
    fattr_recurse_ctx_t rctx;
    u_char             *buf;

    BRIX_PALLOC_OR_RETURN(buf, c->pool, FATTR_RECURSE_RESP_CAP, brix_send_error(ctx, c, kXR_NoMemory, "out of memory"));

    rctx.buf        = buf;
    rctx.cap        = FATTR_RECURSE_RESP_CAP;
    rctx.len        = 0;
    rctx.root_len   = strlen(path);  /* relpath = fullpath + root_len in the walk */
    rctx.pool                  = vctx->pool;
    rctx.log                   = vctx->log;
    rctx.root_canon            = vctx->root_canon;
    rctx.identity              = vctx->identity;
    rctx.storage_cred_dir      = NULL;
    rctx.storage_cred_fallback = 0;
    if (vctx->storage_cred_dir != NULL && vctx->storage_cred_dir[0] != '\0') {
        ngx_str_t *cred_dir_str;

        BRIX_PALLOC_OR_RETURN(cred_dir_str, c->pool, sizeof(ngx_str_t),
            brix_send_error(ctx, c, kXR_NoMemory, "out of memory"));
        cred_dir_str->data = (u_char *) vctx->storage_cred_dir;
        cred_dir_str->len  = ngx_strlen(vctx->storage_cred_dir);
        rctx.storage_cred_dir      = cred_dir_str;
        rctx.storage_cred_fallback = vctx->storage_cred_deny;
    }
    /* Snapshot the op's captured PASSTHROUGH credential (mode + raw bearer) so
     * every per-node ctx in the walk re-binds it, not just the SELECT dir. */
    brix_vfs_deleg_snapshot(vctx, &rctx.deleg_mode, &rctx.deleg_bearer);

    fattr_recurse_dir(&rctx, path, 0);

    BRIX_OP_OK(ctx, BRIX_OP_FATTR);
    if (rctx.len == 0) {
        return brix_send_ok(ctx, c, NULL, 0);
    }
    return brix_send_ok(ctx, c, rctx.buf, (uint32_t) rctx.len);
}

/* Outcome of the two-phase name-list read (fattr_list_read_names). When
 * `done` is set the caller must return `rc` verbatim (a terminal send already
 * happened, whether OK-empty or an error); otherwise (raw, actual) hold the
 * NUL-separated name list to build the response from. */
typedef struct {
    int       done;      /* terminal response already sent → return rc */
    ngx_int_t rc;        /* value to return when done                  */
    char     *raw;       /* name-list buffer (valid when !done)        */
    ssize_t   actual;    /* bytes in raw (valid when !done)            */
} fattr_list_read_t;

/*
 *
 * WHAT: If this fattrList targets a directory with kXR_fa_recurse set, dispatches
 *       to the subtree-walk path and reports that it handled the request.
 *
 * WHY: Isolates the recurse-vs-flat decision from fattr_list. lets the main handler
 *       stay a straight-line two-phase reader.
 *
 * HOW: Returns 1 and stores the walk's result in *out when the recurse path is
 *       taken; returns 0 (leaving *out untouched) so the caller proceeds with the
 *       flat listxattr path. */
static int
fattr_list_try_recurse(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_vfs_ctx_t *vctx, const char *path, int options, ngx_int_t *out)
{
    brix_vfs_stat_t rvst;

    /* Directory + recurse flag → take the subtree-walk path instead. */
    if ((options & kXR_fa_recurse) && path != NULL
        && brix_vfs_probe(vctx, 0 /* follow */, &rvst) == NGX_OK
        && rvst.is_directory)
    {
        *out = fattr_list_recurse(ctx, c, vctx, path);
        return 1;
    }
    return 0;
}

/*
 *
 * WHAT: Two-phase read of the full NUL-separated xattr name list: probe the size,
 *       allocate, then read the names into a buffer.
 *
 * WHY: Factors the size-probe + allocation + read (and their several terminal
 *       responses: no-xattr-support, empty list, alloc failure, read error) out of
 *       fattr_list, so the handler body is just "read then build".
 *
 * HOW: Returns a fattr_list_read_t. When `done` is set the caller returns `rc`
 *       (a terminal send already happened — OK-empty or error); otherwise (raw,
 *       actual) hold the name list. A +4096 slack absorbs names added between the
 *       two phases (TOCTOU). Behaviour and error codes are identical to the inline
 *       original. */
static fattr_list_read_t
fattr_list_read_names(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_vfs_ctx_t *vctx, const char *path, int fd)
{
    fattr_list_read_t out = { 0 };
    char             *raw;
    ssize_t           list_sz;
    ssize_t           actual;

    /* Phase 1: probe (size, NULL) to learn how big the name list is. */
    list_sz = path ? brix_vfs_listxattr(vctx, NULL, 0)
                   : brix_vfs_flistxattr(vctx, fd, NULL, 0);
    if (list_sz < 0) {
        out.done = 1;
        /* Filesystem with no xattr support → empty list, not an error. */
        if (errno == ENOTSUP || errno == EOPNOTSUPP) {
            BRIX_OP_OK(ctx, BRIX_OP_FATTR);
            out.rc = brix_send_ok(ctx, c, NULL, 0);
            return out;
        }
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        out.rc = brix_send_error(ctx, c, kXR_FSError, "listxattr failed");
        return out;
    }
    if (list_sz == 0) {
        out.done = 1;
        BRIX_OP_OK(ctx, BRIX_OP_FATTR);
        out.rc = brix_send_ok(ctx, c, NULL, 0);
        return out;
    }

    /* +4096 slack absorbs names added between phase 1 and phase 2 (TOCTOU). */
    raw = ngx_palloc(c->pool, list_sz + 4096);
    if (raw == NULL) {
        out.done = 1;
        out.rc = brix_send_error(ctx, c, kXR_NoMemory, "out of memory");
        return out;
    }

    /* Phase 2: read the actual NUL-separated name list into raw. */
    actual = path ? brix_vfs_listxattr(vctx, raw, list_sz + 4096)
                  : brix_vfs_flistxattr(vctx, fd, raw, list_sz + 4096);
    if (actual < 0) {
        out.done = 1;
        out.rc = brix_send_error(ctx, c, kXR_FSError, "listxattr failed");
        return out;
    }
    if (actual == 0) {
        out.done = 1;
        BRIX_OP_OK(ctx, BRIX_OP_FATTR);
        out.rc = brix_send_ok(ctx, c, NULL, 0);
        return out;
    }

    out.raw    = raw;
    out.actual = actual;
    return out;
}

/*
 *
 * WHAT: Appends one attribute's value block to *wp: [uint32 big-endian vlen][value
 *       bytes], reading the value via getxattr/fgetxattr on the full "user.U.name"
 *       key (`full_key`).
 *
 * WHY: Factors the kXR_fa_aData value-append out of the build loop. Note getxattr
 *       uses the full internal key while the emitted name is the stripped form.
 *
 * HOW: Unreadable values (vlen < 0) are emitted as zero-length. Advances *wp past
 *       the 4-byte length prefix and the value bytes. No return value. */
static void
fattr_list_append_value(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *full_key, u_char **wp)
{
    char     val[4096];
    ssize_t  vlen = path
        ? brix_vfs_getxattr(vctx, full_key, val, sizeof(val))
        : brix_vfs_fgetxattr(vctx, fd, full_key, val, sizeof(val));
    uint32_t vlen_be;

    if (vlen < 0) vlen = 0;   /* unreadable value → zero-length */
    vlen_be = htonl((uint32_t) vlen);
    ngx_memcpy(*wp, &vlen_be, 4);
    *wp += 4;
    if (vlen > 0) {
        ngx_memcpy(*wp, val, vlen);
        *wp += vlen;
    }
}

/*
 *
 * WHAT: Builds the fattrList response body into `resp` (capacity resp_cap) by
 *       striding the raw NUL-separated name list, keeping managed "user.U.*" keys,
 *       and (when aData) appending each attribute's value. Returns the byte length.
 *
 * WHY: Factors the response-assembly loop out of fattr_list so the handler is a
 *       thin read→build→send sequence.
 *
 * HOW: Each kept name has its full 7-byte internal prefix stripped so the client
 *       sees the bare name it set (matching the reference XeqFALsd). Entries that
 *       would overrun resp_cap stop the loop (rest of the list is dropped) — the
 *       cap is over-provisioned for kXR_faMaxVars aData values so this is only a
 *       guard. */
static size_t
fattr_list_build(brix_vfs_ctx_t *vctx, const char *path, int fd, int aData,
    const char *raw, ssize_t actual, u_char *resp, size_t resp_cap)
{
    /* wp = write cursor into resp; lp/lend stride the raw name list. */
    u_char     *wp   = resp;
    const char *lp   = raw;
    const char *lend = raw + actual;

    while (lp < lend) {
        size_t full_nlen = strlen(lp);
        /* Emit only managed "user.U.*" keys with a non-empty suffix. */
        if (strncmp(lp, BRIX_FATTR_XKEY_PFX, BRIX_FATTR_XKEY_PFX_LEN) == 0
            && full_nlen > BRIX_FATTR_XKEY_PFX_LEN) {
            /* Strip the full internal "user.U." prefix (7 bytes) so the client
             * sees the bare name it set — matching the reference XeqFALsd, which
             * returns verbatim names (the 'U' namespace is internal only). */
            const char *resp_name = lp + BRIX_FATTR_XKEY_PFX_LEN;
            size_t      resp_nlen = full_nlen - BRIX_FATTR_XKEY_PFX_LEN;
            /* name + NUL, plus (if aData) the 4-byte len prefix + value buffer. */
            size_t space_needed = resp_nlen + 1
                                  + (aData ? 4 + 4096 : 0);
            /* Stop before overrunning resp_cap (rest of the list is dropped). */
            if ((size_t)(wp - resp) + space_needed > resp_cap) break;
            ngx_memcpy(wp, resp_name, resp_nlen);
            wp += resp_nlen;
            *wp++ = '\0';
            if (aData) {
                fattr_list_append_value(vctx, path, fd, lp, &wp);
            }
        }
        /* Advance past this name and its NUL terminator. */
        lp += full_nlen + 1;
    }

    return (size_t)(wp - resp);
}

/*
 *
 * WHAT: Handles kXR_fattrList by calling listxattr(path, NULL, 0) for path-based
 *       operations or flistxattr(fd, NULL, 0) for open-file-handle operations to
 *       query the size of all attribute names stored on the filesystem, then reads
 *       the full NUL-separated name string into a buffer. Filters entries to only
 *       those prefixed with BRIX_FATTR_XKEY_PFX (the user namespace prefix used by
 *       nginx-xrootd), stripping the 5-byte prefix from returned names so clients see
 *       bare attribute keys. When kXR_fa_aData flag is set, also reads each filtered
 *       attribute's value via getxattr/fgetxattr and appends it to the response.
 *
 * WHY: XRootD fattrList returns all user-space extended attributes on a file;
 *       nginx-xrootd uses only the user namespace prefixed with "user." so filtering
 *       ensures only managed attributes are visible. The two-phase list (query size
 *       then read) prevents over-allocation. ENOTSUP/EOPNOTSUPP handled gracefully —
 *       filesystems without xattr support return empty response rather than error.
 *       Thread safety: operates only on provided ctx, c, pool and local stack variables.
 *
 * HOW: Recurse dispatch → two-phase read (fattr_list_read_names) → build
 *       (fattr_list_build) → send. Each stage is a small helper; this body is the
 *       straight-line composition. */
ngx_int_t fattr_list(brix_ctx_t *ctx, ngx_connection_t *c,
                    brix_vfs_ctx_t *vctx, const char *path, int fd,
                    int options) {
    int                aData = (options & kXR_fa_aData);
    ngx_int_t          recurse_rc = NGX_OK;
    fattr_list_read_t  rd;
    size_t             resp_cap;
    size_t             resp_len;
    u_char            *resp;

    /* Directory + recurse flag → take the subtree-walk path instead. */
    if (fattr_list_try_recurse(ctx, c, vctx, path, options, &recurse_rc)) {
        return recurse_rc;
    }

    rd = fattr_list_read_names(ctx, c, vctx, path, fd);
    if (rd.done) {
        return rd.rc;
    }

    /*
     * Worst-case response size: every raw name kept, plus for aData each of up
     * to kXR_faMaxVars attributes contributes a 4-byte length prefix + a value
     * up to 4096 bytes; +64 header slop. Over-provisioned so the build loop need
     * not realloc — the break inside still guards against exceeding it.
     */
    resp_cap = (size_t) rd.actual + kXR_faMaxVars * (4 + 4096) + 64;
    resp = ngx_palloc(c->pool, resp_cap);
    if (resp == NULL) {
        return brix_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    resp_len = fattr_list_build(vctx, path, fd, aData, rd.raw, rd.actual,
        resp, resp_cap);

    BRIX_OP_OK(ctx, BRIX_OP_FATTR);
    if (resp_len == 0) {
        return brix_send_ok(ctx, c, NULL, 0);
    }
    return brix_send_ok(ctx, c, resp, (uint32_t) resp_len);
}
