/*
 * merge_export.c — see merge_export.h for the WHAT/WHY/HOW.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "merge_export.h"

#include "core/config/credential_block.h"
#include "core/config/http_rootfd.h"
#include "core/config/root_prepare.h"
#include "fs/vfs/vfs_backend_registry.h"


char *
brix_http_register_storage_backend(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common)
{
    if (brix_vfs_backend_config_str(cf, common->root_canon,
                                    &common->storage_backend,
                                    common->pblock_block_size, BRIX_AF_AUTO)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    if (brix_vfs_backend_store_params(cf, common->root_canon,
                                      &common->storage_backend,
                                      common->storage_backend_args) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    brix_vfs_backend_set_dns(common->root_canon, common->dns.policy);
    if (brix_vfs_backend_config_n2n(cf, common->root_canon,
                                    &common->n2n_scheme, &common->n2n_pool,
                                    &common->n2n_prefix) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


char *
brix_http_attach_storage_credential(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common)
{
    char                     cred_z[256];
    char                     bearer[4096];
    const brix_credential_t *cred;
    brix_vfs_backend_cred_t  bcred;

    if (common->storage_credential.len == 0) {
        return NGX_CONF_OK;
    }
    ngx_cpystrn((u_char *) cred_z, common->storage_credential.data,
                ngx_min(common->storage_credential.len + 1, sizeof(cred_z)));
    cred = brix_credential_lookup(cred_z);
    if (cred == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_credential: no brix_credential \"%V\"",
            &common->storage_credential);
        return NGX_CONF_ERROR;
    }
    if (brix_credential_to_backend_cred(cred, bearer, sizeof(bearer),
                                          &bcred, cf->log) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    brix_vfs_backend_set_credential(common->root_canon, &bcred);

    return NGX_CONF_OK;
}


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

    if (brix_http_register_storage_backend(cf, common) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    /* phase-107 C1: writer reorder-spill scratch (these surfaces have no
     * brix_stage_dir, so only an explicit brix_vfs_spill_path provisions one). */
    if (brix_prepare_spill_scratch(cf, common, NULL) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
