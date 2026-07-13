/*
 * vfs_dir.c — VFS directory enumeration (opendir/readdir/closedir).
 *
 * WHAT: Implements brix_vfs_opendir(), brix_vfs_readdir(), and
 *       brix_vfs_closedir() over the opaque brix_vfs_dir_t handle. readdir
 *       yields one entry per call as a pooled, NUL-terminated ngx_str_t, with an
 *       optional lstat of the child filled into an brix_vfs_stat_t.
 *
 * WHY:  Directory listing (XRootD kXR_dirlist, WebDAV PROPFIND, S3 LIST) needs
 *       confinement, the "." / ".." filter, and a NGX_DONE end-of-stream signal
 *       to be handled once, the same way, for every protocol — rather than each
 *       front end driving opendir/readdir itself.
 *
 * HOW:  opendir re-verifies confinement, pcalloc's the handle on ctx->pool,
 *       dups the resolved path, and opens the C-library DIR*; the open itself is
 *       observed as BRIX_METRIC_OP_DIRLIST. readdir loops skipping "."/".."
 *       (and entries are distinguished from a real error via errno-cleared
 *       readdir, returning NGX_DONE when the stream ends), copies the name into
 *       the pool, and optionally builds "<dir>/<name>" for an lstat. closedir
 *       calls closedir(3) and nulls the handle so it is idempotent.
 */
#include "vfs_internal.h"
#include "core/compat/log_diag.h"

/* vfs_opendir_fail — shared error tail for the opendir body.
 *
 * WHAT: Reports a failed opendir: copies `err` into *err_out (when the caller
 *       asked for it), meters the failure as OP_DIRLIST when `observe` is set,
 *       and returns NULL for the caller to relay.
 * WHY:  Every early-out of the opendir body ends the same way; folding the
 *       report into one helper keeps the body's control flow flat.
 * HOW:  Pure reporting — errno is deliberately NOT touched here so each call
 *       site preserves exactly the errno state the pre-refactor code left; the
 *       observed path is the ctx's resolved path (what every caller reports). */
static brix_vfs_dir_t *
vfs_opendir_fail(brix_vfs_ctx_t *ctx, int err, int observe, uint64_t start,
    int *err_out)
{
    if (err_out != NULL) {
        *err_out = err;
    }
    if (observe) {
        brix_vfs_observe_ctx_op(ctx, brix_vfs_ctx_path(ctx),
                                  BRIX_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_ERROR, err, start);
    }
    return NULL;
}

/* vfs_dir_route — the SECURITY SEAM: export confinement + plane selection.
 *
 * WHAT: Verifies the resolved ctx path is confined to the export root, then
 *       selects the enumeration plane: a non-POSIX driver iterator (*drv_out
 *       set) or the confined POSIX/broker opendir (*drv_out NULL).
 * WHY:  Confinement MUST be re-verified before any directory is opened, and
 *       the driver-vs-broker decision must live in exactly one place so no
 *       future path can enumerate an unconfined directory.
 * HOW:  brix_vfs_require_confined() gates everything; on failure *err carries
 *       its errno for the caller's report (errno itself is left untouched). */
static ngx_int_t
vfs_dir_route(brix_vfs_ctx_t *ctx, const brix_sd_driver_t **drv_out, int *err)
{
    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        *err = errno;
        return NGX_ERROR;
    }
    *drv_out = brix_vfs_ctx_driver(ctx);
    return NGX_OK;
}

/* vfs_dir_open_driver — open a non-POSIX backend's directory iterator.
 *
 * WHAT: Resolves the export-relative logical path, loads the per-user backend
 *       credential when the export is credential-scoped, and opens the leaf
 *       driver's directory iterator into dh->sd_dir, filling the handle's
 *       driver-plane fields.
 * WHY:  Object/remote backends have no DIR*; enumeration goes through the
 *       driver's opendir/readdir verbs instead of the confined POSIX path.
 * HOW:  Returns NGX_OK, or NGX_ERROR with *err set to the errno to report
 *       (errno itself only set where the pre-refactor code set it: the
 *       credential-load failure). Dispatches on the leaf instance so
 *       brix_sd_opendir_maybe_cred finds the leaf driver's opendir_cred slot
 *       (decorators have only plain relays). */
static ngx_int_t
vfs_dir_open_driver(brix_vfs_ctx_t *ctx, brix_vfs_dir_t *dh,
    const brix_sd_driver_t *drv, const char *path, int *err_out)
{
    const char       *logical = brix_vfs_export_relative(ctx, path);
    brix_sd_ucred_t   store;
    brix_sd_cred_t    cred;
    int               use_cred = 0, cred_err = 0;
    int               err = 0;

    /* Zero before the gate: it fills only the active credential kind; an
     * unzeroed cred hands a garbage inactive pointer to the driver's cred
     * slot (bearer PASSTHROUGH would leave x509_proxy dangling). */
    ngx_memzero(&cred, sizeof(cred));

    if (brix_vfs_cred_gate_active(ctx)) {
        if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
            != NGX_OK)
        {
            *err_out = cred_err ? cred_err : EACCES;
            errno = *err_out;
            return NGX_ERROR;
        }
    }

    if (drv->opendir == NULL) {
        errno = ENOTSUP;
    }
    dh->sd_dir = (drv->opendir != NULL)
        ? brix_sd_opendir_maybe_cred(brix_vfs_ns_leaf(ctx->sd),
              logical, &err, use_cred ? &cred : NULL)
        : NULL;
    if (dh->sd_dir == NULL) {
        *err_out = (err != 0) ? err : errno;
        return NGX_ERROR;
    }

    dh->sd  = ctx->sd;
    dh->drv = drv;
    dh->sd_logical = brix_vfs_copy_path(ctx->pool, logical);
    dh->pool = ctx->pool;
    dh->log = ctx->log;
    return NGX_OK;
}

/* vfs_dir_open_confined — the confined POSIX/broker opendir (do NOT weaken).
 *
 * WHAT: Opens dh->dir under export-root confinement and fills the handle's
 *       POSIX-plane fields.
 * WHY:  brix_opendir_confined_canon is the openat2 RESOLVE_IN_ROOT path from
 *       the symlink-escape fix — an outward symlink inside an export must stay
 *       invisible — and under impersonation it opens AS THE MAPPED USER
 *       (broker fdopendir) so a 0700 user-owned / 0770 group-restricted dir
 *       the unprivileged worker cannot itself open is enumerable by its
 *       legitimate owner/group-member; off impersonation it is a bare
 *       opendir().
 * HOW:  Returns NGX_OK, or NGX_ERROR with errno left exactly as the confined
 *       open set it. */
static ngx_int_t
vfs_dir_open_confined(brix_vfs_ctx_t *ctx, brix_vfs_dir_t *dh,
    const char *path)
{
    dh->dir = brix_opendir_confined_canon(ctx->log, ctx->root_canon, path);
    if (dh->dir == NULL) {
        return NGX_ERROR;
    }

    dh->pool = ctx->pool;
    dh->log = ctx->log;
    dh->root_canon = ctx->root_canon;
    return NGX_OK;
}

/* Shared opendir body. When `observe` is set the open is metered as OP_DIRLIST;
 * the quiet variant (observe=0) skips the metric/access-log entirely — for bulk
 * recursive walks (S3 ListObjects, WebDAV SEARCH) whose enclosing protocol op
 * already accounts for the traversal and would otherwise emit one phantom
 * OP_DIRLIST per visited subdirectory. */
static brix_vfs_dir_t *
brix_vfs_opendir_impl(brix_vfs_ctx_t *ctx, int *err_out, int observe)
{
    brix_vfs_dir_t           *dh;
    const char               *path;
    const brix_sd_driver_t   *drv = NULL;
    uint64_t                  start;
    int                       err = 0;

    start = brix_vfs_now_ns();

    if (err_out != NULL) {
        *err_out = 0;
    }

    if (vfs_dir_route(ctx, &drv, &err) != NGX_OK) {
        return vfs_opendir_fail(ctx, err, observe, start, err_out);
    }

    path = brix_vfs_ctx_path(ctx);
    dh = ngx_pcalloc(ctx->pool, sizeof(*dh));
    if (dh == NULL) {
        errno = ENOMEM;
        return vfs_opendir_fail(ctx, ENOMEM, observe, start, err_out);
    }

    dh->path = brix_vfs_copy_path(ctx->pool, path);
    if (dh->path == NULL) {
        return vfs_opendir_fail(ctx, errno, observe, start, err_out);
    }

    if (drv != NULL) {
        /* Non-POSIX backend: enumerate through the driver's iterator. */
        if (vfs_dir_open_driver(ctx, dh, drv, path, &err) != NGX_OK) {
            return vfs_opendir_fail(ctx, err, observe, start, err_out);
        }
    } else if (vfs_dir_open_confined(ctx, dh, path) != NGX_OK) {
        return vfs_opendir_fail(ctx, errno, observe, start, err_out);
    }

    if (observe) {
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_OK, 0, start);
    }
    return dh;
}

/* Open the resolved ctx directory under confinement. Returns a pooled handle or
 * NULL with the errno in *err_out; the open is metered as OP_DIRLIST. */
brix_vfs_dir_t *
brix_vfs_opendir(brix_vfs_ctx_t *ctx, int *err_out)
{
    return brix_vfs_opendir_impl(ctx, err_out, 1 /* observe */);
}

/* Non-metered confined opendir for bulk recursive walks (no OP_DIRLIST emitted —
 * the enclosing protocol op accounts for the whole traversal). Otherwise
 * identical to brix_vfs_opendir. */
brix_vfs_dir_t *
brix_vfs_opendir_quiet(brix_vfs_ctx_t *ctx, int *err_out)
{
    return brix_vfs_opendir_impl(ctx, err_out, 0 /* quiet */);
}

/* The open directory's fd (for a dirfd-relative entry openat that must remain in
 * the same impersonation-confined directory). NGX_INVALID_FILE if unavailable. */
ngx_fd_t
brix_vfs_dir_fd(const brix_vfs_dir_t *dh)
{
    return (dh != NULL && dh->dir != NULL) ? dirfd(dh->dir) : NGX_INVALID_FILE;
}

/* vfs_readdir_fill_entry — copy an entry name into the pooled name_out.
 *
 * WHAT: Fills *name_out with a pooled, NUL-terminated copy of `name`.
 * WHY:  Both readdir variants, on both planes, end by handing the caller a
 *       pool-owned copy of the entry name; one helper kills the copy-paste.
 * HOW:  ngx_pnalloc(len+1) + memcpy + explicit NUL; NGX_ERROR with
 *       errno=ENOMEM on allocation failure. */
static ngx_int_t
vfs_readdir_fill_entry(ngx_pool_t *pool, const char *name,
    ngx_str_t *name_out)
{
    name_out->len = ngx_strlen(name);
    name_out->data = ngx_pnalloc(pool, name_out->len + 1);
    if (name_out->data == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    ngx_memcpy(name_out->data, name, name_out->len);
    name_out->data[name_out->len] = '\0';
    return NGX_OK;
}

/* vfs_readdir_next_posix — next POSIX dirent, "." / ".." filtered out.
 *
 * WHAT: Yields the next non-dot entry of dh->dir into *de_out.
 * WHY:  Both readdir variants share the errno-cleared readdir(3) idiom that
 *       distinguishes end-of-stream from a real error, and the dot filter.
 * HOW:  errno=0 before each readdir(3): NULL with errno still 0 is NGX_DONE,
 *       NULL with errno set is NGX_ERROR; "." and ".." are skipped in-loop. */
static ngx_int_t
vfs_readdir_next_posix(brix_vfs_dir_t *dh, struct dirent **de_out)
{
    struct dirent *de;

    for ( ;; ) {
        errno = 0;
        de = readdir(dh->dir);
        if (de == NULL) {
            return errno == 0 ? NGX_DONE : NGX_ERROR;
        }

        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;
        }

        *de_out = de;
        return NGX_OK;
    }
}

/* vfs_readdir_stat_child — confined lstat of one POSIX entry.
 *
 * WHAT: Joins "<dir>/<name>", lstats it under export confinement, and fills
 *       *stat_out on success.
 * WHY:  Per-entry stat must SKIP a bad entry rather than truncate the listing;
 *       returning NGX_ERROR here lets the scan loop drop the entry and go on.
 * HOW:  snprintf join (unrepresentable path → NGX_ERROR), then
 *       brix_lstat_confined_canon AS THE MAPPED USER (broker-routed) so
 *       enumerating a group-restricted dir does not EACCES per child as the
 *       worker. lstat (not stat) keeps outward symlinks unfollowed. */
static ngx_int_t
vfs_readdir_stat_child(brix_vfs_dir_t *dh, const char *name,
    brix_vfs_stat_t *stat_out)
{
    char         child[PATH_MAX];
    struct stat  st;
    int          n;

    n = snprintf(child, sizeof(child), "%s/%s", dh->path, name);
    if (n < 0 || (size_t) n >= sizeof(child)) {
        return NGX_ERROR;
    }
    if (brix_lstat_confined_canon(dh->log, dh->root_canon, child,
                                    &st, 1) != 0) {
        return NGX_ERROR;
    }
    brix_vfs_fill_stat(&st, stat_out);
    return NGX_OK;
}

/* vfs_sd_stat_child — stat one driver-plane entry through the driver.
 *
 * WHAT: Joins the handle's logical directory with `name` and stats the child
 *       via dh->drv->stat into *sd_st.
 * WHY:  Both readdir variants build the same "<logical>/<name>" join (with
 *       the "/"-root special case) before the driver stat.
 * HOW:  Fixed PATH_MAX join via ngx_snprintf, then the driver's stat verb;
 *       the caller must have checked dh->drv->stat != NULL. */
static ngx_int_t
vfs_sd_stat_child(brix_vfs_dir_t *dh, const char *name, brix_sd_stat_t *sd_st)
{
    char child[PATH_MAX];

    ngx_snprintf((u_char *) child, sizeof(child), "%s/%s%Z",
                 (dh->sd_logical[0] == '/' && dh->sd_logical[1] == '\0')
                     ? "" : dh->sd_logical, name);
    return dh->drv->stat(dh->sd, child, sd_st);
}

/* vfs_readdir_sd — driver-plane body of brix_vfs_readdir.
 *
 * WHAT: Pulls the next entry from the driver iterator, stats the child
 *       through the same driver when the caller wants stats, and fills the
 *       pooled name.
 * WHY:  Keeps the driver iterator's skip-on-vanished-child scan out of the
 *       public entry point.
 * HOW:  Loops (instead of the former tail-recursion) so a child that vanished
 *       mid-scan is skipped; only NGX_DONE/NGX_ERROR from the iterator stop
 *       the caller's loop. */
static ngx_int_t
vfs_readdir_sd(brix_vfs_dir_t *dh, ngx_str_t *name_out,
    brix_vfs_stat_t *stat_out)
{
    brix_sd_dirent_t  de_sd;
    brix_sd_stat_t    sd_st;
    ngx_int_t         rc;

    for ( ;; ) {
        rc = dh->drv->readdir(dh->sd_dir, &de_sd);
        if (rc != NGX_OK) {
            return rc;                                 /* NGX_DONE / NGX_ERROR */
        }
        if (stat_out == NULL || dh->drv->stat == NULL) {
            break;
        }
        if (vfs_sd_stat_child(dh, de_sd.name, &sd_st) == NGX_OK) {
            brix_vfs_sd_stat_fill(&sd_st, stat_out);
            break;
        }
        /* Child vanished mid-scan: skip it and keep enumerating. */
    }

    return vfs_readdir_fill_entry(dh->pool, de_sd.name, name_out);
}

/* Return the next entry: name as a pooled NUL-terminated ngx_str_t, plus an
 * optional lstat of the child. Skips "." and ".."; returns NGX_DONE at
 * end-of-stream and NGX_ERROR (errno set) on failure. */
ngx_int_t
brix_vfs_readdir(brix_vfs_dir_t *dh, ngx_str_t *name_out,
    brix_vfs_stat_t *stat_out)
{
    struct dirent *de;
    ngx_int_t      rc;

    if (dh == NULL || name_out == NULL
        || (dh->dir == NULL && dh->sd_dir == NULL))
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    /* Non-POSIX backend: enumerate through the driver iterator. */
    if (dh->sd_dir != NULL) {
        return vfs_readdir_sd(dh, name_out, stat_out);
    }

    /* Per-entry stat is folded into the scan so a single bad entry SKIPS
     * rather than truncating the listing: a child that races an unlink
     * (ENOENT), or whose joined path is unrepresentable, is dropped and the
     * scan continues. (Only NGX_DONE/NGX_ERROR — true end/stream error —
     * stop the caller's loop.) */
    for ( ;; ) {
        rc = vfs_readdir_next_posix(dh, &de);
        if (rc != NGX_OK) {
            return rc;
        }
        if (stat_out == NULL
            || vfs_readdir_stat_child(dh, de->d_name, stat_out) == NGX_OK)
        {
            break;
        }
    }

    return vfs_readdir_fill_entry(dh->pool, de->d_name, name_out);
}

/* Yield the next entry's name plus its KIND from the readdir d_type, with no
 * per-entry stat — for callers that classify dir-vs-file on the fast path and
 * only stat (via brix_vfs_probe) on a DT_UNKNOWN filesystem. Skips "."/"..";
 * NGX_DONE at end-of-stream, NGX_ERROR (errno set) on failure. */
/* vfs_sd_entry_kind — classify one driver-plane entry as dir/file.
 *
 * WHAT: Returns the entry's kind from a driver stat of the joined child.
 * WHY:  Driver dirents carry no d_type; kind comes from the driver's stat
 *       verb, and a driver without one (or a failed stat) yields UNKNOWN so
 *       the caller falls back to brix_vfs_probe.
 * HOW:  Guards dh->drv->stat, joins via vfs_sd_stat_child, and maps
 *       is_dir → DT_DIR / DT_REG. */
static brix_vfs_dirent_kind_t
vfs_sd_entry_kind(brix_vfs_dir_t *dh, const char *name)
{
    brix_sd_stat_t sd_st;

    if (dh->drv->stat == NULL
        || vfs_sd_stat_child(dh, name, &sd_st) != NGX_OK)
    {
        return BRIX_VFS_DT_UNKNOWN;
    }
    return sd_st.is_dir ? BRIX_VFS_DT_DIR : BRIX_VFS_DT_REG;
}

/* vfs_posix_dtype_kind — map a readdir d_type onto the VFS entry kind.
 *
 * WHAT: DT_DIR/DT_REG/DT_UNKNOWN map onto their VFS kinds; anything else
 *       (symlink, fifo, socket, ...) is DT_OTHER.
 * WHY:  Callers classify dir-vs-file on the fast path and only stat on a
 *       DT_UNKNOWN filesystem; the mapping is a pure table.
 * HOW:  A single switch — no side effects. */
static brix_vfs_dirent_kind_t
vfs_posix_dtype_kind(unsigned char d_type)
{
    switch (d_type) {
    case DT_DIR:     return BRIX_VFS_DT_DIR;
    case DT_REG:     return BRIX_VFS_DT_REG;
    case DT_UNKNOWN: return BRIX_VFS_DT_UNKNOWN;
    default:         return BRIX_VFS_DT_OTHER;
    }
}

ngx_int_t
brix_vfs_readdir_kind(brix_vfs_dir_t *dh, ngx_str_t *name_out,
    brix_vfs_dirent_kind_t *kind_out)
{
    struct dirent *de;
    ngx_int_t      rc;

    if (dh == NULL || name_out == NULL
        || (dh->dir == NULL && dh->sd_dir == NULL))
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (dh->sd_dir != NULL) {
        brix_sd_dirent_t de_sd;

        rc = dh->drv->readdir(dh->sd_dir, &de_sd);
        if (rc != NGX_OK) {
            return rc;
        }
        if (kind_out != NULL) {
            *kind_out = vfs_sd_entry_kind(dh, de_sd.name);
        }
        return vfs_readdir_fill_entry(dh->pool, de_sd.name, name_out);
    }

    rc = vfs_readdir_next_posix(dh, &de);
    if (rc != NGX_OK) {
        return rc;
    }

    if (kind_out != NULL) {
        *kind_out = vfs_posix_dtype_kind(de->d_type);
    }

    return vfs_readdir_fill_entry(dh->pool, de->d_name, name_out);
}

/* Close the directory stream and null the handle (idempotent). Logs and returns
 * NGX_ERROR if closedir(3) fails. */
ngx_int_t
brix_vfs_closedir(brix_vfs_dir_t *dh, ngx_log_t *log)
{
    if (dh == NULL || (dh->dir == NULL && dh->sd_dir == NULL)) {
        return NGX_OK;
    }

    if (dh->sd_dir != NULL) {
        ngx_int_t rc = (dh->drv->closedir != NULL)
            ? dh->drv->closedir(dh->sd_dir) : NGX_OK;

        dh->sd_dir = NULL;
        return rc;
    }

    if (closedir(dh->dir) != 0) {
        BRIX_DIAG_ERR(log != NULL ? log : dh->log, errno,
            "xrootd[disk]: closedir failed for \"%s\"",
            "the underlying directory stream returned an error on close — "
            "usually an I/O error on the backing storage",
            "check dmesg and the filesystem health for that path; the OS "
            "reason is appended below",
            dh->path != NULL ? dh->path : "-");
        dh->dir = NULL;
        return NGX_ERROR;
    }

    dh->dir = NULL;
    return NGX_OK;
}

/* brix_vfs_enumerate_catalog — driver-agnostic backend-catalog enumeration
 * (inventory/drift). Dispatches to the bound driver's optional `enumerate` verb;
 * a backend with no native object catalog (POSIX — the namespace IS the catalog)
 * leaves the verb NULL, and this reports ENOTSUP via NGX_DECLINED so the engine
 * falls back to a namespace walk. See vfs.h. */
ngx_int_t
brix_vfs_enumerate_catalog(brix_sd_instance_t *sd, int want_stat,
    brix_sd_catalog_cb cb, void *ctx)
{
    if (sd == NULL || sd->driver == NULL || sd->driver->enumerate == NULL) {
        errno = ENOTSUP;
        return NGX_DECLINED;
    }
    return sd->driver->enumerate(sd, want_stat, cb, ctx);
}
