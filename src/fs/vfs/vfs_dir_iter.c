/*
 * vfs_dir_iter.c — VFS directory iteration (the readdir family).
 *
 * WHAT: Implements brix_vfs_readdir() (pooled-copy name), the zero-copy
 *       brix_vfs_readdir_borrow() (name borrowed from the handle, valid only
 *       until the next readdir/closedir on it), and brix_vfs_readdir_kind()
 *       (d_type classification, no per-entry stat) over the brix_vfs_dir_t
 *       handle that vfs_dir.c opens and closes.
 *
 * WHY:  Every protocol listing (kXR_dirlist, WebDAV PROPFIND, S3 LIST) shares
 *       the "." / ".." filter, the errno-cleared end-of-stream signal, the
 *       skip-on-vanished-child scan, and the driver-plane fallback; and the
 *       hot single-pass consumer (kXR_dirlist streams each name into the wire
 *       chunk within the same iteration) must not pay a pooled copy per entry
 *       — brix_vfs_readdir was ngx_pnalloc+memcpy'ing every name into the
 *       CONNECTION pool, which both burned CPU and grew the pool per request.
 *
 * HOW:  One borrowed-name core (vfs_readdir_next) yields the entry name in
 *       place — the POSIX dirent's own d_name, or the handle's de_scratch for
 *       a driver iterator — plus the optional folded child lstat; the classic
 *       entry point wraps it with the pooled copy, the borrow entry point
 *       hands the core's pointer straight through.
 */
#include "vfs_internal.h"
#include "auth/impersonate/impersonate.h"

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
 * HOW:  Off impersonation, a dirfd-relative fstatat of the bare entry name —
 *       O(1) per child, no join, no re-walk: dh->dir was opened through the
 *       RESOLVE_IN_ROOT-confined opendir, and readdir names contain no '/',
 *       so the child cannot escape the already-confined directory. Under
 *       impersonation, the snprintf join + brix_lstat_confined_canon AS THE
 *       MAPPED USER (broker-routed) is mandatory — mapped-user DAC — and is
 *       kept unchanged. lstat/AT_SYMLINK_NOFOLLOW keeps outward symlinks
 *       unfollowed on both paths. The caller skips a failed entry; only the
 *       benign unlink race (ENOENT) is silent — EIO/EACCES etc. are logged so
 *       a shrinking listing is diagnosable. */
static ngx_int_t
vfs_readdir_stat_child(brix_vfs_dir_t *dh, const char *name,
    brix_vfs_stat_t *stat_out)
{
    char         child[PATH_MAX];
    struct stat  st;
    int          n, rc;

    if (!brix_imp_client_active()) {
        int dfd = dirfd(dh->dir);

        if (dfd < 0) {
            /* Only reachable with a torn-down handle; fstatat would answer
             * EBADF and the entry would vanish with a misleading errno. */
            ngx_log_error(NGX_LOG_ERR, dh->log, errno,
                          "xrootd[disk]: dirlist of \"%s\" has no directory "
                          "descriptor; entry \"%s\" omitted from the listing",
                          dh->path, name);
            return NGX_ERROR;
        }
        rc = fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW);
        if (rc != 0) {
            if (errno != ENOENT) {
                ngx_log_error(NGX_LOG_ERR, dh->log, errno,
                              "xrootd[disk]: dirlist stat of entry \"%s\" "
                              "under \"%s\" failed; entry omitted from the "
                              "listing", name, dh->path);
            }
            return NGX_ERROR;
        }
        brix_vfs_fill_stat(&st, stat_out);
        return NGX_OK;
    }

    n = snprintf(child, sizeof(child), "%s/%s", dh->path, name);
    if (n < 0 || (size_t) n >= sizeof(child)) {
        errno = ENAMETOOLONG;
        ngx_log_error(NGX_LOG_ERR, dh->log, errno,
                      "xrootd[disk]: dirlist entry \"%s\" under \"%s\" joins "
                      "to an unrepresentable path; entry omitted",
                      name, dh->path);
        return NGX_ERROR;
    }
    if (brix_lstat_confined_canon(dh->log, dh->root_canon, child,
                                    &st, 1) != 0) {
        if (errno != ENOENT) {
            ngx_log_error(NGX_LOG_ERR, dh->log, errno,
                          "xrootd[disk]: dirlist stat of \"%s\" failed; "
                          "entry omitted from the listing", child);
        }
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

/* vfs_readdir_sd — driver-plane body of the readdir core.
 *
 * WHAT: Pulls the next entry from the driver iterator into the HANDLE's
 *       dirent scratch, stats the child through the same driver when the
 *       caller wants stats, and yields the scratch name borrowed.
 * WHY:  Keeps the driver iterator's skip-on-vanished-child scan out of the
 *       core; the scratch lives on the handle (not the stack) so the borrow
 *       contract — name valid until the next readdir/closedir — holds on the
 *       driver plane exactly as it does for a POSIX dirent.
 * HOW:  Loops (instead of the former tail-recursion) so a child that vanished
 *       mid-scan is skipped; only NGX_DONE/NGX_ERROR from the iterator stop
 *       the caller's loop. */
static ngx_int_t
vfs_readdir_sd(brix_vfs_dir_t *dh, const char **name_out,
    brix_vfs_stat_t *stat_out)
{
    brix_sd_dirent_t  *de_sd = &dh->de_scratch;
    brix_sd_stat_t     sd_st;
    ngx_int_t          rc;

    for ( ;; ) {
        /* Zeroed so a driver that fills only the name yields d_type ==
         * DT_UNKNOWN (= 0), never scratch garbage from the previous entry. */
        ngx_memzero(de_sd, sizeof(*de_sd));
        rc = dh->drv->readdir(dh->sd_dir, de_sd);
        if (rc != NGX_OK) {
            return rc;                                 /* NGX_DONE / NGX_ERROR */
        }
        if (stat_out == NULL || dh->drv->stat == NULL) {
            break;
        }
        if (vfs_sd_stat_child(dh, de_sd->name, &sd_st) == NGX_OK) {
            brix_vfs_sd_stat_fill(&sd_st, stat_out);
            break;
        }
        /* Child vanished mid-scan (ENOENT): skip it and keep enumerating.
         * Any other driver stat failure is surfaced before the skip. */
        if (errno != ENOENT) {
            ngx_log_error(NGX_LOG_ERR, dh->log, errno,
                          "xrootd[disk]: dirlist driver stat of entry \"%s\" "
                          "under \"%s\" failed; entry omitted from the "
                          "listing", de_sd->name, dh->sd_logical);
        }
    }

    *name_out = de_sd->name;
    return NGX_OK;
}

/* vfs_readdir_next — the borrowed-name core both public variants share.
 *
 * WHAT: Yields the next visible entry's name IN PLACE (no copy) plus the
 *       optional folded child lstat.
 * WHY:  The pooled-copy and zero-copy entry points differ ONLY in how the
 *       name leaves the function; everything else — handle guard, plane
 *       dispatch, dot filter, skip-on-bad-entry stat fold — is this core.
 * HOW:  POSIX: the dirent's own d_name (valid until the next readdir(3) on
 *       dh->dir). Driver plane: the handle's de_scratch (valid until the next
 *       core call). Per-entry stat is folded into the scan so a single bad
 *       entry SKIPS rather than truncating the listing: a child that races an
 *       unlink (ENOENT), or whose joined path is unrepresentable, is dropped
 *       and the scan continues; only NGX_DONE/NGX_ERROR stop the caller. */
static ngx_int_t
vfs_readdir_next(brix_vfs_dir_t *dh, const char **name_out,
    brix_vfs_stat_t *stat_out)
{
    struct dirent *de;
    ngx_int_t      rc;

    if (dh == NULL || (dh->dir == NULL && dh->sd_dir == NULL)) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (dh->sd_dir != NULL) {
        return vfs_readdir_sd(dh, name_out, stat_out);
    }

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

    *name_out = de->d_name;
    return NGX_OK;
}

/* Return the next entry: name as a pooled NUL-terminated ngx_str_t, plus an
 * optional lstat of the child. Skips "." and ".."; returns NGX_DONE at
 * end-of-stream and NGX_ERROR (errno set) on failure. */
ngx_int_t
brix_vfs_readdir(brix_vfs_dir_t *dh, ngx_str_t *name_out,
    brix_vfs_stat_t *stat_out)
{
    const char *name;
    ngx_int_t   rc;

    if (name_out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    rc = vfs_readdir_next(dh, &name, stat_out);
    if (rc != NGX_OK) {
        return rc;
    }
    return vfs_readdir_fill_entry(dh->pool, name, name_out);
}

/* Zero-copy sibling of brix_vfs_readdir: name_out->data BORROWS the handle's
 * current entry name (the POSIX dirent / the driver scratch) — valid ONLY
 * until the next readdir or closedir on this handle, so it is for single-pass
 * consumers that finish with the name inside the same iteration. */
ngx_int_t
brix_vfs_readdir_borrow(brix_vfs_dir_t *dh, ngx_str_t *name_out,
    brix_vfs_stat_t *stat_out)
{
    const char *name;
    ngx_int_t   rc;

    if (name_out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    rc = vfs_readdir_next(dh, &name, stat_out);
    if (rc != NGX_OK) {
        return rc;
    }
    name_out->data = (u_char *) name;
    name_out->len = ngx_strlen(name);
    return NGX_OK;
}

/* Yield the next entry's name plus its KIND from the readdir d_type, with no
 * per-entry stat — for callers that classify dir-vs-file on the fast path and
 * only stat (via brix_vfs_probe) on a DT_UNKNOWN filesystem. Skips "."/"..";
 * NGX_DONE at end-of-stream, NGX_ERROR (errno set) on failure. */
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

/* vfs_sd_entry_kind — classify one driver-plane entry as dir/file.
 *
 * WHAT: Returns the entry's kind, preferring the dirent's own d_type and
 *       falling back to a driver stat of the joined child.
 * WHY:  A backend that classifies during enumeration (POSIX readdir) makes
 *       the per-entry stat redundant; one that cannot leaves d_type ==
 *       DT_UNKNOWN (never guessed) and the stat verb decides. Kind is
 *       display/routing metadata only — NEVER an authorization input.
 * HOW:  Non-UNKNOWN d_type maps through the same pure table as the POSIX
 *       plane; on UNKNOWN, guard dh->drv->stat, join via vfs_sd_stat_child,
 *       and map is_dir → DT_DIR / DT_REG. */
static brix_vfs_dirent_kind_t
vfs_sd_entry_kind(brix_vfs_dir_t *dh, const brix_sd_dirent_t *de)
{
    brix_sd_stat_t sd_st;

    if (de->d_type != DT_UNKNOWN) {
        return vfs_posix_dtype_kind(de->d_type);
    }

    if (dh->drv->stat == NULL
        || vfs_sd_stat_child(dh, de->name, &sd_st) != NGX_OK)
    {
        return BRIX_VFS_DT_UNKNOWN;
    }
    return sd_st.is_dir ? BRIX_VFS_DT_DIR : BRIX_VFS_DT_REG;
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

        /* Zeroed: a name-only driver yields d_type == DT_UNKNOWN, not junk. */
        ngx_memzero(&de_sd, sizeof(de_sd));
        rc = dh->drv->readdir(dh->sd_dir, &de_sd);
        if (rc != NGX_OK) {
            return rc;
        }
        if (kind_out != NULL) {
            *kind_out = vfs_sd_entry_kind(dh, &de_sd);
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
