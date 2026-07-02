/*
 * cstore.c - the cache's one storage adapter (section 6.1). See header.
 *
 * The fill and serve calls are thin forwards onto the cache-store driver's
 * staged-write / open / pread slots; evict/scan/freespace walk the store's
 * namespace; cinfo_load/store keep the per-object record. SP1 implements LOCAL
 * mode (a posix cache store with
 * byte-identical ".cinfo" sidecars and a per-worker write-through L1); XATTR and
 * SIDECAR modes land in SP2 and return ENOSYS here until then.
 */
#include "cstore.h"
#include "cinfo_xattr.h"     /* cinfo as a store xattr (XATTR mode)            */
#include "cinfo_sidecar.h"   /* cinfo as a co-located object (SIDECAR mode)    */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

/* ---- LOCAL-mode path helper ----------------------------------------------- */

/* Join the store's local root with an export-relative `key` into out[cap] (the
 * on-disk path of the cached object). Returns 0, or -1 when it would overflow. */
static int
cstore_local_path(const xrootd_cstore_t *cs, const char *key, char *out,
    size_t cap)
{
    size_t rlen = strlen(cs->local_root);
    int    n;

    while (rlen > 1 && cs->local_root[rlen - 1] == '/') {
        rlen--;
    }
    n = snprintf(out, cap, "%.*s%s%s", (int) rlen, cs->local_root,
                 (key[0] == '/') ? "" : "/", key);
    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* ---- lifecycle ------------------------------------------------------------ */

ngx_int_t
xrootd_cstore_init(xrootd_cstore_t *cs, xrootd_sd_instance_t *store,
    const char *local_root, int meta_mode, size_t l1_entries, int batch_cinfo,
    ngx_log_t *log)
{
    if (cs == NULL || store == NULL || store->driver == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    memset(cs, 0, sizeof(*cs));
    cs->store       = store;
    cs->batch_cinfo = batch_cinfo;
    cs->log         = log;

    if (local_root != NULL && local_root[0] != '\0') {
        snprintf(cs->local_root, sizeof(cs->local_root), "%s", local_root);
    }

    /* AUTO resolves from the store: a known local dir -> LOCAL; a store that can
     * carry xattrs -> XATTR; else SIDECAR (section 6.3). */
    if (meta_mode == XROOTD_CMETA_AUTO) {
        if (cs->local_root[0] != '\0') {
            meta_mode = XROOTD_CMETA_LOCAL;
        } else if (xrootd_sd_caps(store) & XROOTD_SD_CAP_XATTR) {
            meta_mode = XROOTD_CMETA_XATTR;
        } else {
            meta_mode = XROOTD_CMETA_SIDECAR;
        }
    }
    cs->meta_mode = meta_mode;

    cs->l1 = xrootd_cinfo_l1_create(l1_entries, log);
    if (cs->l1 == NULL) {
        return NGX_ERROR;       /* errno set by create */
    }

    if (meta_mode == XROOTD_CMETA_SIDECAR && cs->store->driver->staged_open == NULL
        && log != NULL)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd cstore: SIDECAR cinfo mode needs a writable store (staged_open) "
            "to persist hit state; this store has none");
    }
    return NGX_OK;
}

void
xrootd_cstore_cleanup(xrootd_cstore_t *cs)
{
    if (cs == NULL) {
        return;
    }
    xrootd_cinfo_l1_destroy(cs->l1);
    cs->l1 = NULL;
}

/* ---- fill spine ----------------------------------------------------------- */

/* Create the key's parent directories on the store (mkdir -p), so a staged write
 * for a nested key (e.g. "/sub/file") does not fail on a missing parent. Each
 * level is created through the store driver; an already-present level is ignored. */
static void
cstore_make_parents(xrootd_cstore_t *cs, const char *key)
{
    char   path[PATH_MAX];
    size_t i;
    size_t n = strlen(key);

    if (cs->store->driver->mkdir == NULL || n == 0 || n >= sizeof(path)) {
        return;
    }
    memcpy(path, key, n + 1);
    for (i = 1; i < n; i++) {                   /* skip the leading '/' */
        if (path[i] == '/') {
            path[i] = '\0';
            (void) cs->store->driver->mkdir(cs->store, path, 0755);  /* EEXIST ok */
            path[i] = '/';
        }
    }
}

xrootd_sd_staged_t *
xrootd_cstore_fill_open(xrootd_cstore_t *cs, const char *key, mode_t mode)
{
    xrootd_sd_staged_t *st;
    int                 err = 0;

    if (cs == NULL || cs->store == NULL || cs->store->driver->staged_open == NULL) {
        errno = ENOSYS;
        return NULL;
    }
    cstore_make_parents(cs, key);
    st = cs->store->driver->staged_open(cs->store, key, mode, &err);
    if (st == NULL && err != 0) {
        errno = err;
    }
    return st;
}

ssize_t
xrootd_cstore_fill_write(xrootd_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    if (st == NULL || st->inst == NULL || st->inst->driver->staged_write == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return st->inst->driver->staged_write(st, buf, len, off);
}

ngx_int_t
xrootd_cstore_fill_commit(xrootd_sd_staged_t *st)
{
    if (st == NULL || st->inst == NULL || st->inst->driver->staged_commit == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    return st->inst->driver->staged_commit(st, 0);
}

void
xrootd_cstore_fill_abort(xrootd_sd_staged_t *st)
{
    if (st != NULL && st->inst != NULL
        && st->inst->driver->staged_abort != NULL)
    {
        st->inst->driver->staged_abort(st);
    }
}

/* ---- serve ---------------------------------------------------------------- */

xrootd_sd_obj_t *
xrootd_cstore_serve_open(xrootd_cstore_t *cs, const char *key, int *err)
{
    if (cs == NULL || cs->store == NULL || cs->store->driver->open == NULL) {
        if (err != NULL) {
            *err = ENOSYS;
        }
        return NULL;
    }
    return cs->store->driver->open(cs->store, key, XROOTD_SD_O_READ, 0, err);
}

ssize_t
xrootd_cstore_serve_pread(int cache_fd, const uint8_t *bitmap, uint64_t nblocks,
    uint32_t block_size, off_t size, void *buf, size_t len, off_t off,
    xrootd_cstore_fill_block_fn fill, void *ctx)
{
    xrootd_sd_obj_t o;
    uint64_t        first, last, blk;

    if (block_size == 0) {
        errno = EINVAL;
        return -1;
    }
    if (off >= size) {
        return 0;
    }
    if (off + (off_t) len > size) {
        len = (size_t) (size - off);
    }
    if (len == 0) {
        return 0;
    }

    /* Range-fill: any block the read touches that the present bitmap does not
     * cover is filled through the decorator's callback (source -> cache store). */
    first = (uint64_t) off / block_size;
    last  = (uint64_t) (off + (off_t) len - 1) / block_size;
    for (blk = first; blk <= last; blk++) {
        int present = (bitmap != NULL && blk < nblocks
                       && xrootd_cache_cinfo_block_present(bitmap, blk));
        if (!present && fill != NULL && fill(ctx, blk) != 0) {
            return -1;
        }
    }

    /* Serve from the cache object through the POSIX store driver (raw byte I/O
     * stays in the backend, not here). */
    xrootd_sd_posix_wrap(&o, cache_fd);
    return o.driver->pread(&o, buf, len, off);
}

int
xrootd_cstore_partial_open(xrootd_cstore_t *cs, const char *key, mode_t mode,
    off_t size, char *path_out, size_t path_cap)
{
    char        path[PATH_MAX];
    struct stat sb;
    int         fd;

    if (cs == NULL || cs->meta_mode != XROOTD_CMETA_LOCAL) {
        errno = ENOTSUP;            /* partial caching needs a local RW object */
        return -1;
    }
    if (cstore_local_path(cs, key, path, sizeof(path)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    cstore_make_parents(cs, key);
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, mode ? mode : 0644);
    if (fd < 0) {
        return -1;
    }
    /* Size the (sparse) object so per-block pwrites land at their file offsets. */
    if (fstat(fd, &sb) == 0 && sb.st_size < size && ftruncate(fd, size) != 0) {
        int e = errno;

        (void) close(fd);
        errno = e;
        return -1;
    }
    if (path_out != NULL && path_cap > 0) {
        snprintf(path_out, path_cap, "%s", path);
    }
    return fd;
}

/* ---- evict ---------------------------------------------------------------- */

ngx_int_t
xrootd_cstore_evict(xrootd_cstore_t *cs, const char *key)
{
    if (cs == NULL || cs->store == NULL || key == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    xrootd_cinfo_l1_drop(cs->l1, key);

    /* Drop the cinfo record. LOCAL: the byte-identical ".cinfo" sidecar next to
     * the cache object (the cache tree is the read-cache's own raw domain). */
    if (cs->meta_mode == XROOTD_CMETA_LOCAL) {
        char path[PATH_MAX];
        char cipath[PATH_MAX];

        if (cstore_local_path(cs, key, path, sizeof(path)) == 0
            && xrootd_cache_cinfo_path(cipath, sizeof(cipath), path) == 0)
        {
            (void) unlink(cipath);   /* cache-store sidecar; ENOENT is fine */
        }
    } else if (cs->meta_mode == XROOTD_CMETA_XATTR) {
        (void) xrootd_cinfo_xattr_remove(cs->store, key);
    } else if (cs->meta_mode == XROOTD_CMETA_SIDECAR) {
        (void) xrootd_cinfo_sidecar_remove(cs->store, key);  /* <key>.xrdcinfo obj */
    }

    if (cs->store->driver->unlink != NULL) {
        (void) cs->store->driver->unlink(cs->store, key, 0);  /* idempotent */
    }
    return NGX_OK;
}

/* ---- cinfo ---------------------------------------------------------------- */

ngx_int_t
xrootd_cstore_cinfo_load(xrootd_cstore_t *cs, const char *key,
    xrootd_cache_cinfo_t *ci)
{
    char       path[PATH_MAX];
    uint8_t   *bitmap = NULL;
    size_t     bitmap_len = 0;
    ngx_int_t  rc;

    if (cs == NULL || key == NULL || ci == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (xrootd_cinfo_l1_get(cs->l1, key, ci) == NGX_OK) {
        return NGX_OK;                          /* warm: no store round-trip */
    }
    if (cs->meta_mode == XROOTD_CMETA_XATTR) {
        rc = xrootd_cinfo_xattr_load(cs->store, key, ci);   /* user.xrd.cinfo */
        if (rc == NGX_OK) {
            xrootd_cinfo_l1_put(cs->l1, key, ci);
        }
        return rc;
    }
    if (cs->meta_mode == XROOTD_CMETA_SIDECAR) {
        rc = xrootd_cinfo_sidecar_load(cs->store, key, ci); /* <key>.xrdcinfo obj */
        if (rc == NGX_OK) {
            xrootd_cinfo_l1_put(cs->l1, key, ci);
        }
        return rc;
    }
    if (cs->meta_mode != XROOTD_CMETA_LOCAL) {
        errno = ENOSYS;                         /* unknown mode */
        return NGX_ERROR;
    }
    if (cstore_local_path(cs, key, path, sizeof(path)) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    rc = xrootd_cache_cinfo_load(path, ci, &bitmap, &bitmap_len);
    free(bitmap);                               /* L1 caches only the header */
    if (rc == NGX_OK) {
        xrootd_cinfo_l1_put(cs->l1, key, ci);
    }
    return rc;                                  /* NGX_OK | NGX_DECLINED | NGX_ERROR */
}

ngx_int_t
xrootd_cstore_cinfo_store(xrootd_cstore_t *cs, const char *key,
    const xrootd_cache_cinfo_t *ci)
{
    char                  path[PATH_MAX];
    xrootd_cache_cinfo_t  old;
    uint8_t              *bitmap = NULL;
    size_t                existing_len = 0;
    size_t                need_len;
    ngx_int_t             rc;

    if (cs == NULL || key == NULL || ci == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (cs->meta_mode == XROOTD_CMETA_XATTR) {
        ngx_int_t xrc = xrootd_cinfo_xattr_store(cs->store, key, ci);
        if (xrc == NGX_OK) {
            xrootd_cinfo_l1_put(cs->l1, key, ci);    /* write-through (§6.4) */
        }
        return xrc;
    }
    if (cs->meta_mode == XROOTD_CMETA_SIDECAR) {
        ngx_int_t src = xrootd_cinfo_sidecar_store(cs->store, key, ci);
        if (src == NGX_OK) {
            xrootd_cinfo_l1_put(cs->l1, key, ci);    /* write-through (§6.4) */
        }
        return src;
    }
    if (cs->meta_mode != XROOTD_CMETA_LOCAL) {
        errno = ENOSYS;                         /* unknown mode */
        return NGX_ERROR;
    }
    if (cstore_local_path(cs, key, path, sizeof(path)) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    /* Preserve an existing present-bitmap when its size still matches; otherwise
     * synthesize one from the COMPLETE flag (whole-file caching, SP1 - a partial
     * bitmap merge is section 6.5 / SP2). */
    need_len = xrootd_cache_cinfo_bitmap_len(ci->nblocks);
    if (xrootd_cache_cinfo_load(path, &old, &bitmap, &existing_len) != NGX_OK
        || existing_len != need_len)
    {
        free(bitmap);
        bitmap = NULL;
        if (need_len > 0) {
            bitmap = malloc(need_len);
            if (bitmap == NULL) {
                errno = ENOMEM;
                return NGX_ERROR;
            }
            memset(bitmap,
                   (ci->flags & XROOTD_CINFO_F_COMPLETE) ? 0xFF : 0x00,
                   need_len);
        }
    }

    rc = xrootd_cache_cinfo_store(path, ci, bitmap, need_len);
    free(bitmap);
    if (rc == NGX_OK) {
        xrootd_cinfo_l1_put(cs->l1, key, ci);
    }
    return rc;
}

/* ---- scan ----------------------------------------------------------------- */

/* True when `name` is a cstore metadata sidecar rather than a cached object. */
static int
cstore_is_sidecar(const char *name)
{
    size_t n = strlen(name);

    return (n >= 6 && strcmp(name + n - 6, ".cinfo") == 0)
        || (n >= 5 && strcmp(name + n - 5, ".meta") == 0)
        || (n >= 9 && strcmp(name + n - 9, ".xrdcinfo") == 0);
}

/* Recursively visit cached objects beneath `dirkey` on the store. */
static ngx_int_t
cstore_scan_dir(xrootd_cstore_t *cs, const char *dirkey,
    xrootd_cstore_visit_fn visit, void *ctx)
{
    xrootd_sd_dir_t    *d;
    xrootd_sd_dirent_t  de;
    ngx_int_t           rc = NGX_OK;
    int                 err = 0;
    size_t              dklen = strlen(dirkey);

    d = cs->store->driver->opendir(cs->store, dirkey, &err);
    if (d == NULL) {
        return (err == ENOENT) ? NGX_OK : NGX_ERROR;
    }

    while (cs->store->driver->readdir(d, &de) == NGX_OK) {
        char             childkey[PATH_MAX];
        xrootd_sd_stat_t stx;
        int              n;

        if (de.name[0] == '\0' || strcmp(de.name, ".") == 0
            || strcmp(de.name, "..") == 0 || cstore_is_sidecar(de.name))
        {
            continue;
        }
        n = snprintf(childkey, sizeof(childkey), "%s%s%s", dirkey,
                     (dklen > 0 && dirkey[dklen - 1] == '/') ? "" : "/",
                     de.name);
        if (n <= 0 || (size_t) n >= sizeof(childkey)) {
            continue;
        }
        if (cs->store->driver->stat == NULL
            || cs->store->driver->stat(cs->store, childkey, &stx) != NGX_OK)
        {
            continue;
        }
        if (stx.is_dir) {
            rc = cstore_scan_dir(cs, childkey, visit, ctx);
        } else if (stx.is_reg) {
            xrootd_cache_cinfo_t ci;
            int loaded = (xrootd_cstore_cinfo_load(cs, childkey, &ci) == NGX_OK);

            /* Visit every regular object — with its cinfo when present, NULL when
             * not (orphan/partial) — and always the store stat, so an eviction
             * policy sees the same set a raw driver scan would and can sort by the
             * object's own size/mtime. */
            rc = visit(childkey, loaded ? &ci : NULL, &stx, ctx);
        }
        if (rc != NGX_OK) {
            break;                              /* visitor / subdir stopped early */
        }
    }

    cs->store->driver->closedir(d);
    return rc;
}

ngx_int_t
xrootd_cstore_scan(xrootd_cstore_t *cs, xrootd_cstore_visit_fn visit, void *ctx)
{
    if (cs == NULL || cs->store == NULL || visit == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (cs->store->driver->opendir == NULL || cs->store->driver->readdir == NULL
        || cs->store->driver->closedir == NULL)
    {
        errno = ENOSYS;                         /* store lacks DIRS - needs dev */
        return NGX_DECLINED;
    }
    return cstore_scan_dir(cs, "/", visit, ctx);
}

/* ---- introspection --------------------------------------------------------- */

const char *
xrootd_cstore_local_root(const xrootd_cstore_t *cs)
{
    if (cs == NULL || cs->meta_mode != XROOTD_CMETA_LOCAL
        || cs->local_root[0] == '\0')
    {
        return NULL;                            /* non-local store: no dir to reap */
    }
    return cs->local_root;
}

/* ---- freespace ------------------------------------------------------------ */

ngx_int_t
xrootd_cstore_freespace(xrootd_cstore_t *cs, uint64_t *total, uint64_t *avail)
{
    struct statvfs vfs;

    if (cs == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (cs->meta_mode != XROOTD_CMETA_LOCAL || cs->local_root[0] == '\0') {
        return NGX_DECLINED;                    /* non-local store: statf slot, SP2 */
    }
    if (statvfs(cs->local_root, &vfs) != 0) {
        return NGX_ERROR;
    }
    if (total != NULL) {
        *total = (uint64_t) vfs.f_blocks * (uint64_t) vfs.f_frsize;
    }
    if (avail != NULL) {
        *avail = (uint64_t) vfs.f_bavail * (uint64_t) vfs.f_frsize;
    }
    return NGX_OK;
}
