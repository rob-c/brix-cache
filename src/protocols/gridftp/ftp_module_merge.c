#include "ftp_gateway.h"
#include "ftp_module_internal.h"           /* brix_ftp_build_gsi (ftp_module_gsi.c) */
#include "core/config/stream_common.h"     /* phase-101 W3: adopt the bare storage names */
#include <stdlib.h>                        /* realpath */
#include <limits.h>                        /* PATH_MAX */

#include "fs/vfs/vfs_backend_registry.h"   /* per-export storage-backend register */
#include "core/config/credential_block.h"  /* s3:// backend SigV4 credential      */
#include "fs/path/path.h"                  /* brix_finalize_vo_rules, brix_vo_rule_t */

/*
 * ftp_module_merge.c — the GridFTP gateway's parent→child config merge.
 *
 * Split out of ftp_module.c (600-line cap, coding-standards §1): the module
 * descriptor, per-block config and directive setters stay there; everything the
 * merge needs — the backend-credential bind, the VO-rule deep merge, the storage
 * registry entry and the GSI context — lives here. One entry point,
 * brix_ftp_merge_conf, referenced by the module ctx.
 */


/* brix_ftp_install_backend_credential — bind the named brix_credential block's
 * upstream identity (SigV4 keys for an s3:// backend) to this export's registry
 * entry, so per-request ctx resolution builds a signed backend instance. Mirrors
 * the root/webdav wiring via the ONE shared credential→backend_cred mapper
 * (P80.1). A no-op when no credential is named; a hard error on an unknown name
 * or an unreadable token_file (a misconfigured upstream must fail the config, not
 * serve unauthenticated). */
static char *
brix_ftp_install_backend_credential(ngx_conf_t *cf,
    ngx_stream_brix_ftp_srv_conf_t *conf)
{
    char                     name[256];
    char                     bearer[4096];
    const brix_credential_t *cred;
    brix_vfs_backend_cred_t  bcred;

    if (conf->common.storage_credential.len == 0) {
        return NGX_CONF_OK;
    }
    ngx_cpystrn((u_char *) name, conf->common.storage_credential.data,
                ngx_min(conf->common.storage_credential.len + 1, sizeof(name)));
    cred = brix_credential_lookup(name);
    if (cred == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_credential \"%s\" names no brix_credential "
            "block", name);
        return NGX_CONF_ERROR;
    }
    if (brix_credential_to_backend_cred(cred, bearer, sizeof(bearer),
                                        &bcred, cf->log) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp: cannot derive credential \"%s\" for export \"%s\"",
            name, conf->common.root_canon);
        return NGX_CONF_ERROR;
    }
    brix_vfs_backend_set_credential(conf->common.root_canon, &bcred);

    /* An explicit `mode` on the block overrides the gateway's default per-request
     * delegation mode (e.g. `mode select` pins the service credential and never
     * forwards the client's proxy). */
    if (cred->mode != NGX_CONF_UNSET) {
        conf->deleg_mode = (enum brix_cred_mode) cred->mode;
    }
    return NGX_CONF_OK;
}


/* Merge parent+child VO rules into a fresh per-block array (child entries
 * shadow parent — the same deep-merge the core module uses, so a shared parent
 * array is never finalized twice against differing roots), then
 * realpath()-canonicalise every rule's .path into .resolved against this
 * export's root so the request-time gate matches confined resolve output. */
static char *
brix_ftp_finalize_vo_rules(ngx_conf_t *cf,
    ngx_stream_brix_ftp_srv_conf_t *conf)
{
    ngx_str_t    root;

    if (conf->common.vo_rules == NULL || conf->common.vo_rules->nelts == 0
        || conf->common.root_canon[0] == '\0')
    {
        return NGX_CONF_OK;
    }
    root.data = (u_char *) conf->common.root_canon;
    root.len  = ngx_strlen(conf->common.root_canon);
    if (brix_finalize_vo_rules(cf->log, &root, conf->common.vo_rules) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_require_vo: cannot finalize VO rules for "
            "export \"%s\"", conf->common.root_canon);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


/* Register this export's storage backend so every per-request ftp_vfs_ctx()
 * (which calls brix_vfs_ctx_init → brix_vfs_backend_resolve on root_canon)
 * routes through the selected driver — "pblock" today, POSIX when unset.
 * The gateway itself only ever touches storage through brix_vfs_*, so no
 * data-path change is needed once the choice is on the registry. */
static char *
brix_ftp_merge_storage(ngx_conf_t *cf, ngx_stream_brix_ftp_srv_conf_t *conf)
{
    if (!conf->enable || conf->common.root_canon[0] == '\0') {
        return NGX_CONF_OK;
    }
    if (brix_vfs_backend_config_str(cf, conf->common.root_canon,
            &conf->common.storage_backend, 0, BRIX_AF_AUTO) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    /* Default: forward the client's delegated proxy (PASSTHROUGH). A named
     * brix_credential block's `mode` may override this inside install below;
     * the request-time bind (ftp_ev_path.c) additionally no-ops on backends
     * that do not consume a proxy, so posix/pblock exports are unaffected. */
    conf->deleg_mode = BRIX_CRED_PASSTHROUGH;
    return brix_ftp_install_backend_credential(cf, conf);
}


/* Inherit the parent's already-built GSI context when the child built none;
 * otherwise build this block's own from its certificate/CA directives. */
static char *
brix_ftp_merge_tls(ngx_conf_t *cf, ngx_stream_brix_ftp_srv_conf_t *prev,
    ngx_stream_brix_ftp_srv_conf_t *conf)
{
    if (conf->tls_ctx != NULL) {
        return NGX_CONF_OK;
    }
    if (prev->tls_ctx != NULL) {
        conf->tls_ctx  = prev->tls_ctx;      /* inherit built ctx */
        conf->ca_store = prev->ca_store;
        return NGX_CONF_OK;
    }
    if (conf->enable && conf->gsi) {
        return brix_ftp_build_gsi(cf, conf);
    }
    return NGX_CONF_OK;
}


static char *
ftp_resolve_root(ngx_conf_t *cf, ngx_stream_brix_ftp_srv_conf_t *conf)
{
    ngx_str_t  dir;
    char       raw[PATH_MAX];

    if (conf->common.root.len == 0) {
        return NGX_CONF_OK;
    }
    dir = conf->common.root;
    if (ngx_conf_full_name(cf->cycle, &dir, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    if (dir.len >= sizeof(raw)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_export path too long: %V", &dir);
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(raw, dir.data, dir.len);
    raw[dir.len] = '\0';
    if (realpath(raw, conf->common.root_canon) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix_export \"%s\" cannot be resolved (does it exist?)", raw);
        return NGX_CONF_ERROR;
    }
    conf->common.root = dir;
    return NGX_CONF_OK;
}

/* brix_ftp_merge_conf — parent→child merge: disabled and read-only by default;
 * inherit the export root when the child omitted its own. */
char *
brix_ftp_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_brix_ftp_srv_conf_t *prev = parent;
    ngx_stream_brix_ftp_srv_conf_t *conf = child;
    char                           *rv;

    brix_stream_common_adopt(cf, &conf->common);
    if (ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    if (brix_shared_clone_vo_rules(cf, &conf->common) != NGX_OK
        || ftp_resolve_root(cf, conf) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->enable,      prev->enable,      0);
    ngx_conf_merge_value(conf->gsi,         prev->gsi,         0);
    ngx_conf_merge_value(conf->pasv_port_lo, prev->pasv_port_lo, 0);
    ngx_conf_merge_value(conf->pasv_port_hi, prev->pasv_port_hi, 0);
    ngx_conf_merge_value(conf->require_allo_size, prev->require_allo_size, 0);
    rv = brix_ftp_finalize_vo_rules(cf, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (conf->enable && conf->common.root_canon[0] == '\0') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp is on but brix_export is unset or "
            "unresolvable");
        return NGX_CONF_ERROR;
    }

    rv = brix_ftp_merge_storage(cf, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }
    return brix_ftp_merge_tls(cf, prev, conf);
}
