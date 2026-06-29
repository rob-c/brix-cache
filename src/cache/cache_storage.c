/*
 * cache_storage.c — per-role SD storage instances for the cache. See the header.
 */

#include "cache_storage.h"
#include "../fs/vfs_backend_registry.h"   /* xrootd_vfs_backend_resolve */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* xrootd_cache_key_from lives in cache_key.c (pure, libc-only) so it links into
 * the standalone unit test without dragging the nginx-dependent code here. */

int
xrootd_cache_key(const ngx_stream_xrootd_srv_conf_t *conf, const char *resolved,
                 char *dst, size_t dstsz)
{
    if (conf->cache_root.len == 0) {
        return -1;
    }
    return xrootd_cache_key_from((const char *) conf->cache_root.data,
                                 conf->common.root_canon, resolved, dst, dstsz);
}

/* The export-relative key (leading '/') under cache_root for an absolute
 * cache_path, or NULL when cache_path is not under cache_root. */
const char *
xrootd_cache_key_under_root(const ngx_stream_xrootd_srv_conf_t *conf,
    const char *cache_path)
{
    const char *key;

    if (conf->cache_root.len == 0 || cache_path == NULL
        || ngx_strncmp((u_char *) cache_path, conf->cache_root.data,
                       conf->cache_root.len) != 0)
    {
        return NULL;
    }
    key = cache_path + conf->cache_root.len;
    return (key[0] == '/') ? key : NULL;
}

/* Driver-aware readiness: a configured cache STORAGE backend keeps its bytes in
 * the driver namespace (no POSIX file at cache_path), so probe via a driver stat
 * of the export-relative key; a POSIX cache keeps the proven file_ready() stat. */
int
xrootd_cache_ready(const ngx_stream_xrootd_srv_conf_t *conf,
    const char *cache_path)
{
    xrootd_sd_instance_t *inst = conf->cache_storage_inst;
    const char           *key;
    xrootd_sd_stat_t      sst;

    if (conf->cache_storage_backend.len == 0 || inst == NULL) {
        return xrootd_cache_file_ready(cache_path);   /* POSIX cache */
    }
    key = xrootd_cache_key_under_root(conf, cache_path);
    if (key == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (inst->driver->stat(inst, key, &sst) != NGX_OK) {
        return (errno == ENOENT || errno == ENOTDIR) ? 0 : -1;
    }
    if (!sst.is_reg) {
        errno = EINVAL;
        return -1;
    }
    return 1;
}

/* ---- per-worker cache_root → instance table ----------------------------
 * The VFS cache-open hook (open.c) receives a VFS ctx carrying cache_root_canon
 * but not the server conf, so it cannot read conf->cache_storage_inst directly.
 * This small process-local table (populated by xrootd_cache_storage_init) maps a
 * cache root to its read + state instances for that lookup. */
#define XROOTD_CACHE_STORAGE_MAX 64
typedef struct {
    char                  root[PATH_MAX];
    char                  state_root[PATH_MAX];   /* POSIX sidecar tree */
    xrootd_sd_instance_t *read_inst;
    xrootd_sd_instance_t *state_inst;
} cs_root_entry_t;
static cs_root_entry_t cs_root_table[XROOTD_CACHE_STORAGE_MAX];
static ngx_uint_t      cs_root_count;
static cs_root_entry_t *cs_root_find(const char *root);

static void
cs_root_register(const char *root, const char *state_root,
    xrootd_sd_instance_t *read_inst, xrootd_sd_instance_t *state_inst)
{
    cs_root_entry_t *e = NULL;
    ngx_uint_t       i;

    if (root == NULL || root[0] == '\0') {
        return;
    }
    for (i = 0; i < cs_root_count; i++) {
        if (strcmp(cs_root_table[i].root, root) == 0) {
            e = &cs_root_table[i];                      /* refresh on reload */
            break;
        }
    }
    if (e == NULL) {
        if (cs_root_count >= XROOTD_CACHE_STORAGE_MAX) {
            return;
        }
        e = &cs_root_table[cs_root_count++];
        snprintf(e->root, sizeof(e->root), "%s", root);
    }
    snprintf(e->state_root, sizeof(e->state_root), "%s",
             (state_root && state_root[0]) ? state_root : root);
    e->read_inst = read_inst;
    e->state_inst = state_inst;
}

/* The state (sidecar) root for a cache root — the cache_state_root if distinct,
 * else the cache root (co-located). NULL if the cache root is unknown. */
const char *
xrootd_cache_state_root_by_root(const char *cache_root_canon)
{
    cs_root_entry_t *e = cs_root_find(cache_root_canon);
    return e ? e->state_root : NULL;
}

/* Map a cache_path (cache_root + key) to its sidecar base path (state_root + key).
 * For a co-located cache (state_root == cache_root) this returns cache_path
 * unchanged. 0 / -1 (not under cache_root, or overflow). */
int
xrootd_cache_sidecar_path(const char *cache_root, const char *state_root,
    const char *cache_path, char *dst, size_t dstsz)
{
    size_t crlen = strlen(cache_root);

    if (strncmp(cache_path, cache_root, crlen) != 0) {
        return -1;
    }
    if ((size_t) snprintf(dst, dstsz, "%s%s", state_root, cache_path + crlen)
        >= dstsz)
    {
        return -1;
    }
    return 0;
}

static cs_root_entry_t *
cs_root_find(const char *root)
{
    ngx_uint_t i;

    if (root == NULL) {
        return NULL;
    }
    for (i = 0; i < cs_root_count; i++) {
        if (strcmp(cs_root_table[i].root, root) == 0) {
            return &cs_root_table[i];
        }
    }
    return NULL;
}

/* Lazily register a POSIX co-located instance for a cache root that was not set up
 * by xrootd_cache_storage_init — namely an HTTP-module cache (xrootd_webdav_cache_root),
 * whose server conf the stream-only worker-init loop never visits. A driver-backed
 * cache is always pre-registered at config time, so this fallback only ever builds
 * the default POSIX driver (state co-located), matching the cache's POSIX default.
 * Event-loop only (single-threaded per worker); the borrowed O_PATH fd lives for the
 * worker's lifetime. NULL if the root cannot be opened. */
static xrootd_sd_instance_t *
cs_root_lazy_posix(const char *root)
{
    int                   fd;
    xrootd_sd_instance_t *inst;

    if (root == NULL || root[0] == '\0' || ngx_cycle == NULL) {
        return NULL;
    }
    fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return NULL;
    }
    inst = xrootd_sd_posix_borrow_instance(ngx_cycle->pool, ngx_cycle->log, fd,
                                           root);
    if (inst == NULL) {
        close(fd);
        return NULL;
    }
    cs_root_register(root, root, inst, inst);   /* POSIX, state co-located */
    return inst;
}

xrootd_sd_instance_t *
xrootd_cache_storage_by_root(const char *cache_root_canon)
{
    cs_root_entry_t *e = cs_root_find(cache_root_canon);
    return e ? e->read_inst : cs_root_lazy_posix(cache_root_canon);
}

xrootd_sd_instance_t *
xrootd_cache_state_by_root(const char *cache_root_canon)
{
    cs_root_entry_t *e = cs_root_find(cache_root_canon);
    return e ? e->state_inst : NULL;
}

/* ---- instance resolution (conf-based) ---------------------------------- */

xrootd_sd_instance_t *
xrootd_cache_storage(const ngx_stream_xrootd_srv_conf_t *conf)
{
    return conf->cache_storage_inst;
}

xrootd_sd_instance_t *
xrootd_cache_state_storage(const ngx_stream_xrootd_srv_conf_t *conf)
{
    return conf->cache_state_inst;
}

xrootd_sd_instance_t *
xrootd_cache_wt_stage(const ngx_stream_xrootd_srv_conf_t *conf)
{
    return conf->cache_wt_stage_inst;
}

/* ---- per-worker init / cleanup ----------------------------------------- */

/* Open an O_PATH rootfd on `root` (a configured cache dir). -1 if `root` empty. */
static int
cache_open_rootfd(const ngx_str_t *root, ngx_log_t *log)
{
    int fd;

    if (root == NULL || root->len == 0) {
        return -1;
    }
    fd = open((const char *) root->data, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_EMERG, log, errno,
                      "xrootd: cannot open cache dir \"%V\" for VFS storage",
                      root);
    }
    return fd;
}

/* Build a role's SD instance: the configured backend (via the registry) when
 * `backend` is named, else the POSIX driver borrowing `rootfd`. NULL if neither
 * a backend nor a usable rootfd is available. */
static xrootd_sd_instance_t *
cache_build_instance(ngx_pool_t *pool, ngx_log_t *log, const ngx_str_t *root,
    const ngx_str_t *backend, int rootfd)
{
    if (backend != NULL && backend->len > 0) {
        /* Registered at config time (Tasks 6/7) keyed on the role's root. */
        return xrootd_vfs_backend_resolve((const char *) root->data, log);
    }
    if (rootfd < 0) {
        return NULL;
    }
    return xrootd_sd_posix_borrow_instance(pool, log, rootfd,
                                           (const char *) root->data);
}

ngx_int_t
xrootd_cache_storage_init(ngx_stream_xrootd_srv_conf_t *conf, ngx_cycle_t *cycle)
{
    ngx_pool_t *pool = cycle->pool;
    ngx_log_t  *log = cycle->log;
    const ngx_str_t *state_root;

    conf->cache_rootfd = -1;
    conf->cache_state_rootfd = -1;
    conf->cache_wt_stage_rootfd = -1;
    conf->cache_storage_inst = NULL;
    conf->cache_state_inst = NULL;
    conf->cache_wt_stage_inst = NULL;

    if (conf->cache_root.len == 0) {
        return NGX_OK;                   /* no cache configured */
    }

    /* Read cache (cache_root). */
    conf->cache_rootfd = cache_open_rootfd(&conf->cache_root, log);
    conf->cache_storage_inst = cache_build_instance(pool, log, &conf->cache_root,
        &conf->cache_storage_backend, conf->cache_rootfd);

    /* Sidecar/state tree — always POSIX (cache_state_root, else cache_root). */
    state_root = conf->cache_state_root.len ? &conf->cache_state_root
                                            : &conf->cache_root;
    conf->cache_state_rootfd = (conf->cache_state_root.len)
        ? cache_open_rootfd(&conf->cache_state_root, log)
        : conf->cache_rootfd;            /* reuse cache_root's fd when same dir */
    {
        ngx_str_t no_backend = ngx_null_string;
        conf->cache_state_inst = cache_build_instance(pool, log, state_root,
            &no_backend, conf->cache_state_rootfd);
    }

    /* Write-back staging cache (optional). */
    if (conf->cache_wt_stage_root.len > 0) {
        conf->cache_wt_stage_rootfd =
            cache_open_rootfd(&conf->cache_wt_stage_root, log);
        conf->cache_wt_stage_inst = cache_build_instance(pool, log,
            &conf->cache_wt_stage_root, &conf->cache_wt_stage_backend,
            conf->cache_wt_stage_rootfd);
    }

    /* Publish the read + state instances for the conf-less VFS cache-open hook. */
    cs_root_register((const char *) conf->cache_root.data,
                     (const char *) state_root->data,
                     conf->cache_storage_inst, conf->cache_state_inst);

    return NGX_OK;
}

void
xrootd_cache_storage_cleanup(ngx_stream_xrootd_srv_conf_t *conf)
{
    if (conf->cache_rootfd >= 0) {
        close(conf->cache_rootfd);
    }
    /* cache_state_rootfd may alias cache_rootfd (same dir) — only close a distinct fd. */
    if (conf->cache_state_rootfd >= 0
        && conf->cache_state_rootfd != conf->cache_rootfd)
    {
        close(conf->cache_state_rootfd);
    }
    if (conf->cache_wt_stage_rootfd >= 0) {
        close(conf->cache_wt_stage_rootfd);
    }
    conf->cache_rootfd = -1;
    conf->cache_state_rootfd = -1;
    conf->cache_wt_stage_rootfd = -1;
    conf->cache_storage_inst = NULL;
    conf->cache_state_inst = NULL;
    conf->cache_wt_stage_inst = NULL;
}
