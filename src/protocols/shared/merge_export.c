/*
 * merge_export.c — see merge_export.h for the WHAT/WHY/HOW.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "merge_export.h"

#include "core/config/http_rootfd.h"
#include "core/config/root_prepare.h"
#include "fs/vfs/vfs_backend_registry.h"


char *
brix_http_merge_export_anchor(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common, const char *directive_name,
    ngx_flag_t allow_write)
{
    brix_export_root_opts_t  root_opts;

    if (common->root.len == 0) {
        ngx_str_set(&common->root, "/");
    }

    root_opts.directive_name = directive_name;
    root_opts.allow_write    = allow_write;
    root_opts.required       = 1;
    root_opts.canon_size     = sizeof(common->root_canon);

    if (brix_prepare_export_root(cf, &common->root, &root_opts,
                                 common->root_canon) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (brix_http_open_rootfd(cf, common) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (brix_vfs_backend_config_str(cf, common->root_canon,
                                    &common->storage_backend,
                                    common->pblock_block_size, BRIX_AF_AUTO)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* phase-107 C1: writer reorder-spill scratch (these surfaces have no
     * brix_stage_dir, so only an explicit brix_vfs_spill_path provisions one). */
    if (brix_prepare_spill_scratch(cf, common, NULL) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
