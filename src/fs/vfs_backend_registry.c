/*
 * vfs_backend_registry.c — per-export storage-backend resolution (see the header).
 */
#include "vfs_backend_registry.h"
#include "backend/xroot/sd_xroot.h"   /* remote root:// backend (xrootd_sd_xroot_create) */

#include <string.h>

/* One registered export. `inst` is per-worker (copy-on-write after fork): the
 * master leaves it NULL at config time; each worker fills its own on first use. */
typedef struct {
    char                  root_canon[PATH_MAX];
    char                  backend[16];   /* "pblock" | "xroot" */
    int64_t               block_size;
    void                 *srv_conf;       /* xroot: the srv conf the origin reads */
    xrootd_sd_instance_t *inst;          /* lazily built per worker, or NULL */
} xrootd_vfs_backend_entry_t;

/* Exports are few (one per location/server block); a small fixed table avoids any
 * allocation and is scanned linearly. */
#define XROOTD_VFS_BACKEND_MAX 64
static xrootd_vfs_backend_entry_t  xrootd_vfs_backends[XROOTD_VFS_BACKEND_MAX];
static ngx_uint_t                  xrootd_vfs_backend_count;

void
xrootd_vfs_backend_config(const char *root_canon, const ngx_str_t *name,
    size_t block_size)
{
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0' || name == NULL
        || name->len == 0)
    {
        return;
    }
    /* Only "pblock" is a registered non-POSIX backend today. */
    if (name->len != sizeof("pblock") - 1
        || ngx_strncmp(name->data, "pblock", sizeof("pblock") - 1) != 0)
    {
        return;
    }

    /* Dedup on root_canon so a config reload updates rather than appends. */
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            xrootd_vfs_backends[i].block_size = (int64_t) block_size;
            xrootd_vfs_backends[i].inst = NULL;   /* rebuilt on next resolve */
            return;
        }
    }
    if (xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX) {
        return;
    }

    {
        xrootd_vfs_backend_entry_t *e =
            &xrootd_vfs_backends[xrootd_vfs_backend_count++];

        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                    sizeof(e->root_canon));
        ngx_memcpy(e->backend, "pblock", sizeof("pblock"));
        e->block_size = (int64_t) block_size;
    }
}

void
xrootd_vfs_backend_config_xroot(const char *root_canon, void *srv_conf)
{
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0' || srv_conf == NULL) {
        return;
    }

    /* Dedup on root_canon so a config reload updates rather than appends. */
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            ngx_memcpy(xrootd_vfs_backends[i].backend, "xroot",
                       sizeof("xroot"));
            xrootd_vfs_backends[i].srv_conf = srv_conf;
            xrootd_vfs_backends[i].inst     = NULL;   /* rebuilt on next resolve */
            return;
        }
    }
    if (xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX) {
        return;
    }
    {
        xrootd_vfs_backend_entry_t *e =
            &xrootd_vfs_backends[xrootd_vfs_backend_count++];

        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                    sizeof(e->root_canon));
        ngx_memcpy(e->backend, "xroot", sizeof("xroot"));
        e->srv_conf = srv_conf;
    }
}

/* Lazily build (per worker) and cache the entry's storage-driver instance. The
 * master leaves entry->inst NULL at config time; each worker fills its own on
 * first use (a SQLite connection must never be shared across fork). */
static xrootd_sd_instance_t *
xrootd_vfs_backend_entry_build(xrootd_vfs_backend_entry_t *e, ngx_log_t *log)
{
    if (e->inst != NULL) {
        return e->inst;                /* already built in this worker */
    }

    /* Remote root:// backend: wrap the in-process origin wire client (read +
     * Phase-1 write data path). The instance is malloc-owned (no pool), worker-
     * safe; it reads cache_origin_host/port/tls from the bound srv conf. */
    if (ngx_strcmp(e->backend, "xroot") == 0) {
        e->inst = xrootd_sd_xroot_create(e->srv_conf, log);
        if (e->inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: remote root:// backend init failed for export \"%s\"",
                e->root_canon);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: remote root:// storage backend ready at \"%s\"",
                e->root_canon);
        }
        return e->inst;
    }
#if XROOTD_HAVE_SQLITE
    {
        xrootd_sd_pblock_conf_t conf;
        int                     sderr = 0;

        ngx_memzero(&conf, sizeof(conf));
        conf.root            = e->root_canon;
        conf.busy_timeout_ms = 5000;
        conf.block_size      = e->block_size;

        e->inst = xrootd_sd_instance_create(ngx_cycle->pool, log, "pblock",
                                            &conf, &sderr);
        if (e->inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, sderr,
                "xrootd: pblock backend init failed for export \"%s\"",
                e->root_canon);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: pblock storage backend ready at \"%s\" "
                "(block_size=%uz)", e->root_canon, (size_t) e->block_size);
        }
        return e->inst;
    }
#else
    (void) log;
    return NULL;
#endif
}

xrootd_sd_instance_t *
xrootd_vfs_backend_resolve(const char *root_canon, ngx_log_t *log)
{
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0'
        || xrootd_vfs_backend_count == 0)
    {
        return NULL;
    }

    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        xrootd_vfs_backend_entry_t *e = &xrootd_vfs_backends[i];

        if (ngx_strcmp(e->root_canon, root_canon) != 0) {
            continue;
        }
        return xrootd_vfs_backend_entry_build(e, log);
    }
    return NULL;
}

xrootd_sd_instance_t *
xrootd_vfs_backend_resolve_for_path(const char *abs_path, const char **root_out,
    ngx_log_t *log)
{
    xrootd_vfs_backend_entry_t *best = NULL;
    size_t                      best_len = 0;
    ngx_uint_t                  i;

    if (abs_path == NULL || abs_path[0] == '\0'
        || xrootd_vfs_backend_count == 0)
    {
        return NULL;
    }

    /* Longest registered export root that is a prefix of abs_path: a match is the
     * root itself or root + "/..." (so "/exp" never matches "/export/x"). */
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        xrootd_vfs_backend_entry_t *e = &xrootd_vfs_backends[i];
        size_t                      rl = ngx_strlen(e->root_canon);

        if (ngx_strncmp(abs_path, e->root_canon, rl) != 0) {
            continue;
        }
        if (abs_path[rl] != '/' && abs_path[rl] != '\0') {
            continue;                  /* shares a prefix but a different name */
        }
        if (rl > best_len) {
            best_len = rl;
            best     = e;
        }
    }
    if (best == NULL) {
        return NULL;
    }
    if (root_out != NULL) {
        *root_out = best->root_canon;
    }
    return xrootd_vfs_backend_entry_build(best, log);
}
