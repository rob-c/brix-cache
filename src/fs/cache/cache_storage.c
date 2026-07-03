/*
 * cache_storage.c — per-role SD storage instances for the cache. See the header.
 */

#include "cache_storage.h"
#include "cache_internal.h"               /* brix_cache_build_origin (shared read-origin map) */
#include "cstore.h"                       /* policy-layer cstore adapter */
#include "fs/vfs/vfs_backend_registry.h"   /* brix_vfs_backend_resolve */
#include "fs/backend/xroot/sd_xroot.h" /* brix_sd_xroot_create_origin (§6.5) */
#include "fs/backend/cache/sd_cache.h" /* brix_sd_cache_create (slice decorator) */
#include "fs/backend/stage/sd_stage.h" /* brix_sd_stage_create (write-through) */
#include "fs/tier/tier.h"              /* brix_cache_policy_t */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* brix_cache_key_from lives in cache_key.c (pure, libc-only) so it links into
 * the standalone unit test without dragging the nginx-dependent code here. */

int
brix_cache_key(const ngx_stream_brix_srv_conf_t *conf, const char *resolved,
                 char *dst, size_t dstsz)
{
    if (conf->cache_root.len == 0) {
        return -1;
    }
    return brix_cache_key_from((const char *) conf->cache_root.data,
                                 conf->common.root_canon, resolved, dst, dstsz);
}

/* The export-relative key (leading '/') under cache_root for an absolute
 * cache_path, or NULL when cache_path is not under cache_root. */
const char *
brix_cache_key_under_root(const ngx_stream_brix_srv_conf_t *conf,
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

/* Cache readiness for an `brix_cache on` POSIX cache: is the cached file
 * fully present? (§14: the driver-backed cache_storage_backend variant is
 * retired — a driver cache store is the tier grammar's composed sd_cache.) */
int
brix_cache_ready(const ngx_stream_brix_srv_conf_t *conf,
    const char *cache_path)
{
    (void) conf;
    return brix_cache_file_ready(cache_path);
}

/* ---- per-worker cache_root → instance table ----------------------------
 * The VFS cache-open hook (open.c) receives a VFS ctx carrying cache_root_canon
 * but not the server conf, so it cannot read conf->cache_storage_inst directly.
 * This small process-local table (populated by brix_cache_storage_init) maps a
 * cache root to its read + state instances for that lookup. */
#define BRIX_CACHE_STORAGE_MAX 64
typedef struct {
    char                  root[PATH_MAX];
    char                  state_root[PATH_MAX];   /* POSIX sidecar tree */
    brix_sd_instance_t *read_inst;
    brix_sd_instance_t *state_inst;
} cs_root_entry_t;
static cs_root_entry_t cs_root_table[BRIX_CACHE_STORAGE_MAX];
static ngx_uint_t      cs_root_count;
static cs_root_entry_t *cs_root_find(const char *root);

static void
cs_root_register(const char *root, const char *state_root,
    brix_sd_instance_t *read_inst, brix_sd_instance_t *state_inst)
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
        if (cs_root_count >= BRIX_CACHE_STORAGE_MAX) {
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
brix_cache_state_root_by_root(const char *cache_root_canon)
{
    cs_root_entry_t *e = cs_root_find(cache_root_canon);
    return e ? e->state_root : NULL;
}

/* Map a cache_path (cache_root + key) to its sidecar base path (state_root + key).
 * For a co-located cache (state_root == cache_root) this returns cache_path
 * unchanged. 0 / -1 (not under cache_root, or overflow). */
int
brix_cache_sidecar_path(const char *cache_root, const char *state_root,
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
 * by brix_cache_storage_init — namely an HTTP-module cache (brix_webdav_cache_root),
 * whose server conf the stream-only worker-init loop never visits. A driver-backed
 * cache is always pre-registered at config time, so this fallback only ever builds
 * the default POSIX driver (state co-located), matching the cache's POSIX default.
 * Event-loop only (single-threaded per worker); the borrowed O_PATH fd lives for the
 * worker's lifetime. NULL if the root cannot be opened. */
static brix_sd_instance_t *
cs_root_lazy_posix(const char *root)
{
    int                   fd;
    brix_sd_instance_t *inst;

    if (root == NULL || root[0] == '\0' || ngx_cycle == NULL) {
        return NULL;
    }
    fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return NULL;
    }
    inst = brix_sd_posix_borrow_instance(ngx_cycle->pool, ngx_cycle->log, fd,
                                           root);
    if (inst == NULL) {
        close(fd);
        return NULL;
    }
    cs_root_register(root, root, inst, inst);   /* POSIX, state co-located */
    return inst;
}

brix_sd_instance_t *
brix_cache_storage_by_root(const char *cache_root_canon)
{
    cs_root_entry_t *e = cs_root_find(cache_root_canon);
    return e ? e->read_inst : cs_root_lazy_posix(cache_root_canon);
}

brix_sd_instance_t *
brix_cache_state_by_root(const char *cache_root_canon)
{
    cs_root_entry_t *e = cs_root_find(cache_root_canon);
    return e ? e->state_inst : NULL;
}

/* ---- instance resolution (conf-based) ---------------------------------- */

/* §14a: the read-cache STORE + cstore the eviction/reaper enumerate through. A
 * legacy cache_root cache is cache_storage_inst; a composable tier cache
 * (cache_store) is the registry's composed sd_cache — its own store + cstore hold
 * the objects the read path fills, so the reaper must evict through THOSE (not the
 * legacy cache_storage_inst, which a pure-tier cache never builds). */
brix_sd_instance_t *
brix_cache_storage(const ngx_stream_brix_srv_conf_t *conf)
{
    if (conf->common.cache_store.len > 0) {
        brix_sd_instance_t *c =
            brix_vfs_backend_resolve(conf->common.root_canon, ngx_cycle->log);
        if (c != NULL && brix_sd_cache_instance_is(c)) {
            return brix_sd_cache_store_instance(c);
        }
    }
    return conf->cache_storage_inst;
}

brix_cstore_t *
brix_cache_storage_cstore(const ngx_stream_brix_srv_conf_t *conf)
{
    if (conf->common.cache_store.len > 0) {
        brix_sd_instance_t *c =
            brix_vfs_backend_resolve(conf->common.root_canon, ngx_cycle->log);
        if (c != NULL && brix_sd_cache_instance_is(c)) {
            return (brix_cstore_t *) brix_sd_cache_cstore(c);
        }
    }
    return (brix_cstore_t *) conf->cache_storage_cstore;
}

brix_sd_instance_t *
brix_cache_source_inst(const ngx_stream_brix_srv_conf_t *conf)
{
    return (brix_sd_instance_t *) conf->cache_source_inst;
}

brix_sd_instance_t *
brix_cache_wt_stage_sd_inst(const ngx_stream_brix_srv_conf_t *conf)
{
    return (brix_sd_instance_t *) conf->cache_wt_stage_sd_inst;
}

brix_sd_instance_t *
brix_cache_state_storage(const ngx_stream_brix_srv_conf_t *conf)
{
    return conf->cache_state_inst;
}

brix_sd_instance_t *
brix_cache_wt_stage(const ngx_stream_brix_srv_conf_t *conf)
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
                      "brix: cannot open cache dir \"%V\" for VFS storage",
                      root);
    }
    return fd;
}

/* Build a role's SD instance: the configured backend (via the registry) when
 * `backend` is named, else the POSIX driver borrowing `rootfd`. NULL if neither
 * a backend nor a usable rootfd is available. */
static brix_sd_instance_t *
cache_build_instance(ngx_pool_t *pool, ngx_log_t *log, const ngx_str_t *root,
    const ngx_str_t *backend, int rootfd)
{
    if (backend != NULL && backend->len > 0) {
        /* Registered at config time (Tasks 6/7) keyed on the role's root. */
        return brix_vfs_backend_resolve((const char *) root->data, log);
    }
    if (rootfd < 0) {
        return NULL;
    }
    return brix_sd_posix_borrow_instance(pool, log, rootfd,
                                           (const char *) root->data);
}


/* Compose the write-through sd_stage(source=wt_origin, store=export backend) — the
 * ONE write mechanism (Option A). Independent of cache_root: a pure write-through
 * export has no read cache. The store is the export's registered backend when there
 * is one, else a posix instance on the export root (where a posix write lands). NULL
 * when write-through is off or no origin/store is available. */
static void
cache_build_wt_stage(ngx_pool_t *pool, ngx_log_t *log,
                     ngx_stream_brix_srv_conf_t *conf)
{
    brix_sd_instance_t *store;
    brix_sd_instance_t *origin;

    if (!conf->wt_enable
        || (conf->wt_origin_host.len == 0 && conf->cache_origin_host.len == 0))
    {
        return;
    }

    store  = brix_vfs_backend_resolve(conf->common.root_canon, log);
    origin = brix_cache_build_wt_origin(conf, log);

    if (store == NULL) {
        conf->cache_wt_store_rootfd =
            open((const char *) conf->common.root_canon,
                 O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (conf->cache_wt_store_rootfd >= 0) {
            store = brix_sd_posix_borrow_instance(pool, log,
                        conf->cache_wt_store_rootfd,
                        (const char *) conf->common.root_canon);
        }
    }

    if (store != NULL && origin != NULL) {
        brix_stage_policy_t pol;

        ngx_memzero(&pol, sizeof(pol));
        pol.flush_mode = (conf->wt_mode == BRIX_WT_MODE_ASYNC)
                         ? BRIX_WT_MODE_ASYNC : BRIX_WT_MODE_SYNC;
        conf->cache_wt_stage_sd_inst = brix_sd_stage_create(origin, store, &pol,
            (const char *) conf->common.root_canon, log);
    }
    if (conf->cache_wt_stage_sd_inst == NULL && origin != NULL) {
        brix_sd_xroot_destroy(origin);
    }
}


ngx_int_t
brix_cache_storage_init(ngx_stream_brix_srv_conf_t *conf, ngx_cycle_t *cycle)
{
    ngx_pool_t *pool = cycle->pool;
    ngx_log_t  *log = cycle->log;
    const ngx_str_t *state_root;

    conf->cache_rootfd = -1;
    conf->cache_state_rootfd = -1;
    conf->cache_wt_stage_rootfd = -1;
    conf->cache_storage_inst = NULL;
    conf->cache_storage_cstore = NULL;
    conf->cache_source_inst = NULL;
    conf->cache_wt_stage_sd_inst = NULL;
    conf->cache_wt_store_rootfd = -1;
    conf->cache_state_inst = NULL;
    conf->cache_wt_stage_inst = NULL;

    /* Write-through composes independently of a read cache (a pure write-through
     * export has no cache_root), so build it BEFORE the no-cache early return. */
    cache_build_wt_stage(pool, log, conf);

    if (conf->cache_root.len == 0) {
        return NGX_OK;                   /* no read cache configured */
    }

    /* Read cache (cache_root). */
    conf->cache_rootfd = cache_open_rootfd(&conf->cache_root, log);
    {
        /* §14: cache_storage_backend is retired — an `brix_cache on` read cache
         * is always the POSIX driver on cache_root (driver stores = cache_store). */
        ngx_str_t no_backend = ngx_null_string;
        conf->cache_storage_inst = cache_build_instance(pool, log,
            &conf->cache_root, &no_backend, conf->cache_rootfd);
    }

    /* Policy-layer cstore over the bare read-cache store: eviction / reaper /
     * free-space drive the store through this adapter (phase-64 P3/G5), never the
     * bare driver. AUTO resolves to LOCAL for the co-located posix cache_root
     * (byte-identical sidecars); batch_cinfo=0 keeps the old per-op behaviour. */
    if (conf->cache_storage_inst != NULL) {
        brix_cstore_t *cs = ngx_pcalloc(pool, sizeof(*cs));
        size_t           l1 = (conf->common.cache_index_cache > 0)
                              ? (size_t) conf->common.cache_index_cache : 0;

        if (cs == NULL) {
            return NGX_ERROR;
        }
        if (brix_cstore_init(cs, conf->cache_storage_inst,
                               (const char *) conf->cache_root.data,
                               BRIX_CMETA_AUTO, l1, 0, log) != NGX_OK) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                "brix: cache policy cstore init failed for \"%V\"",
                &conf->cache_root);
            return NGX_ERROR;
        }
        conf->cache_storage_cstore = cs;
    }

    /* §14 (phase-64): the legacy cache_slice_inst decorator (built over the
     * retired cache_origin config) is DELETED — slice/partial caching is the
     * tier grammar's composed sd_cache (brix_cache_store +
     * brix_cache_slice_size), resolved via brix_vfs_backend_resolve. */

    /* §14: no legacy cache_origin — an `brix_cache on` cache fills from the
     * export's REGISTERED storage backend (the C-1 spine resolves it per fill). */
    conf->cache_source_inst = NULL;

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
brix_cache_storage_cleanup(ngx_stream_brix_srv_conf_t *conf)
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
    if (conf->cache_storage_cstore != NULL) {
        brix_cstore_cleanup((brix_cstore_t *) conf->cache_storage_cstore);
        conf->cache_storage_cstore = NULL;
    }
    if (conf->cache_wt_stage_sd_inst != NULL) {
        /* Free the decorator then the origin SOURCE we own (the store is the export
         * backend, freed on its own path — the decorator borrows it). */
        brix_sd_instance_t *dec = conf->cache_wt_stage_sd_inst;
        brix_sd_instance_t *origin = brix_sd_stage_source_instance(dec);

        brix_sd_stage_destroy(dec);
        if (origin != NULL) {
            brix_sd_xroot_destroy(origin);
        }
        conf->cache_wt_stage_sd_inst = NULL;
    }
    if (conf->cache_wt_store_rootfd >= 0) {
        close(conf->cache_wt_store_rootfd);
        conf->cache_wt_store_rootfd = -1;
    }
    conf->cache_rootfd = -1;
    conf->cache_state_rootfd = -1;
    conf->cache_wt_stage_rootfd = -1;
    conf->cache_storage_inst = NULL;
    conf->cache_state_inst = NULL;
    conf->cache_wt_stage_inst = NULL;
}
