/*
 * root_prepare.c — shared export-root validation and canonicalization.
 *
 * All three protocol surfaces (native root://, WebDAV, S3) need the same
 * startup check on their configured export root: verify it exists, is a
 * readable directory with the right permissions, and resolve it through
 * realpath(3) to eliminate symlinks from the confinement boundary.
 *
 * This helper centralises that logic so the behaviour is identical across
 * all surfaces.  It must be called during merge_loc_conf / postconfiguration
 * so that nginx -t catches misconfigured roots before traffic is accepted.
 */

#include "config.h"
#include "root_prepare.h"
#include "export_guard.h"   /* brix_assert_dir_outside_export (hard guard) */
#include "core/compat/tmp_path.h"        /* brix_tmp_reap_register */
#include "fs/vfs/vfs_backend_registry.h"  /* brix_vfs_backend_set_spill */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

char *
brix_prepare_export_root(ngx_conf_t *cf,
    const ngx_str_t *root, const brix_export_root_opts_t *opts,
    char *root_canon)
{
    char       root_buf[PATH_MAX];
    int        access_mode;
    ngx_str_t  root_str;

    /* Empty root — either silently skip or hard fail depending on opts. */
    if (root == NULL || root->len == 0) {
        if (opts->required) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s is required but not set",
                               opts->directive_name);
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }

    /* Guard against paths that would overflow the canonical buffer. */
    if (root->len >= opts->canon_size || root->len >= sizeof(root_buf)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%s path is too long", opts->directive_name);
        return NGX_CONF_ERROR;
    }

    /* Build a NUL-terminated copy for stat/access/realpath. */
    ngx_memcpy(root_buf, root->data, root->len);
    root_buf[root->len] = '\0';

    /* Validate existence, kind (directory), and access permissions. */
    root_str.data = (u_char *) root_buf;
    root_str.len  = root->len;
    access_mode   = opts->allow_write ? (R_OK | W_OK | X_OK) : (R_OK | X_OK);

    if (brix_validate_path(cf, opts->directive_name, &root_str,
                             BRIX_PATH_DIRECTORY, access_mode) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* Resolve symlinks and normalise the path for the confinement boundary. */
    if (realpath(root_buf, root_canon) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
                           "%s: cannot resolve canonical path for \"%s\"",
                           opts->directive_name, root_buf);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

char *
brix_prepare_cache_root(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *common)
{
    static const char       prefix[] = "posix:";
    brix_export_root_opts_t cache_opts;
    u_char                 *store;
    size_t                  root_len;

    if (common->cache_root.len == 0) {
        return NGX_CONF_OK;
    }
    if (common->cache_store.len > 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_root is shorthand for a POSIX brix_cache_store; "
            "configure only one of them");
        return NGX_CONF_ERROR;
    }
    cache_opts.directive_name = "brix_cache_root";
    cache_opts.allow_write    = 1;
    cache_opts.required       = 0;
    cache_opts.canon_size     = sizeof(common->cache_root_canon);
    if (brix_prepare_export_root(cf, &common->cache_root, &cache_opts,
                                   common->cache_root_canon) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* HARD config guard: the read-through cache root must live OUTSIDE the
     * export, or cache sidecars would be exposed in the client namespace. */
    if (brix_assert_dir_outside_export(cf, "brix_cache_root",
            common->root_canon, common->cache_root_canon) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* W9: cache_root is syntax sugar, not a second runtime cache engine.
     * Canonicalize and confinement-check the directory under its public name,
     * then lower it to the composable tier grammar before registration. Clear
     * both legacy fields so VFS opens cannot consult the old by-root cache and
     * the sd_cache decorator for the same request. */
    root_len = ngx_strlen(common->cache_root_canon);
    store = ngx_pnalloc(cf->pool, sizeof(prefix) - 1 + root_len + 1);
    if (store == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(store, prefix, sizeof(prefix) - 1);
    ngx_memcpy(store + sizeof(prefix) - 1, common->cache_root_canon,
               root_len + 1);
    common->cache_store.data = store;
    common->cache_store.len = sizeof(prefix) - 1 + root_len;
    common->cache_root.data = NULL;
    common->cache_root.len = 0;
    common->cache_root_canon[0] = '\0';
    return NGX_CONF_OK;
}

/* Validate an explicit brix_vfs_spill_path and canonicalise it into
 * spill_canon (size PATH_MAX). Split from brix_prepare_spill_scratch to keep
 * its decision count in budget. */
static char *
brix_prepare_spill_path(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *common,
    char *spill_canon)
{
    brix_export_root_opts_t  opts;

    /* realpath() would silently resolve a relative path against the
     * master's cwd — refuse it up front so the boundary is explicit. */
    if (common->vfs_spill_path.data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_vfs_spill_path must be absolute (got \"%V\")",
            &common->vfs_spill_path);
        return NGX_CONF_ERROR;
    }
    opts.directive_name = "brix_vfs_spill_path";
    opts.allow_write    = 1;
    opts.required       = 0;
    opts.canon_size     = PATH_MAX;
    if (brix_prepare_export_root(cf, &common->vfs_spill_path, &opts,
                                 spill_canon) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    /* HARD config guard: scratch inside the export would make service
     * storage reachable as export storage (and expose spill temps in the
     * client namespace). */
    if (brix_assert_dir_outside_export(cf, "brix_vfs_spill_path",
            common->root_canon, spill_canon) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

char *
brix_prepare_spill_scratch(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *common,
    const char *stage_dir_canon)
{
    char                     spill_canon[PATH_MAX];
    const char              *scratch = NULL;
    size_t                   max;

    max = (common->vfs_spill_max == (size_t) NGX_CONF_UNSET_SIZE)
        ? 0 : common->vfs_spill_max;
    if (max != 0 && max < 1024 * 1024) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_vfs_spill_max must be 0 or at least 1m (got %uz)", max);
        return NGX_CONF_ERROR;
    }

    if (common->vfs_spill_path.len > 0) {
        if (brix_prepare_spill_path(cf, common, spill_canon) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
        scratch = spill_canon;
    } else if (stage_dir_canon != NULL && stage_dir_canon[0] != '\0') {
        /* Default per the C1 contract: the export's staged temp directory —
         * already canonical and already guarded outside the export by its own
         * brix_stage_dir preparation. */
        scratch = stage_dir_canon;
    }

    /* Phase-107 C3 rides the same per-export preparation: register a merged
     * `brix_durable_publish off` so the publish barrier is skipped for this
     * export. Registered only when OFF — an absent registry entry is durable
     * (fails safe), and the table stays free of entries for every
     * default-configured export. */
    if (common->durable_publish == 0 && common->root_canon[0] != '\0') {
        brix_vfs_backend_set_durable(common->root_canon, 0);
    }

    /* Phase-107 C7 rides the same preparation: register a merged
     * `brix_lock_enforcement advisory|off` so the VFS lock gate relaxes for
     * this export. Registered only when non-strict — an absent registry entry
     * is STRICT (fails toward enforcement), and the table stays free of
     * entries for every default-configured export. */
    if (common->lock_enforcement != 0 && common->root_canon[0] != '\0') {
        brix_vfs_backend_set_lock_enforcement(common->root_canon,
                                              common->lock_enforcement);
    }

    if (scratch == NULL || common->root_canon[0] == '\0') {
        /* No scratch (reordered uploads refuse ENOSPC) or no export anchored
         * here to key the registry entry on — directives were still validated. */
        return NGX_CONF_OK;
    }
    brix_vfs_backend_set_spill(common->root_canon, scratch, (off_t) max);
    /* Owned-temp reclaim: a crashed worker's spill is recognised by its
     * .xrd-tmp.<pid>. name when the reaper walks this registered root. */
    brix_tmp_reap_register(scratch);
    return NGX_CONF_OK;
}
