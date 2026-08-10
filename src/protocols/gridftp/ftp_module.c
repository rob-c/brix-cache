#include "ftp_gateway.h"
#include "ftp_module_internal.h"           /* brix_ftp_build_gsi (ftp_module_gsi.c) */

#include "fs/vfs/vfs_backend_registry.h"   /* per-export storage-backend register */
#include "core/config/credential_block.h"  /* s3:// backend SigV4 credential      */
#include "fs/path/path.h"                  /* brix_normalize_policy_path,
                                            * brix_finalize_vo_rules, brix_vo_rule_t */
#include "core/config/config.h"            /* brix_copy_conf_string               */

#include <stdlib.h>   /* realpath */

/*
 * ftp_module.c — GridFTP gateway module descriptor, per-block config, and the
 * directive setters that (a) install the stream handler when enabled and
 * (b) canonicalise the exported tree root for path confinement.
 */


/* brix_ftp_create_conf — allocate the srv_conf with UNSET sentinels so merge can
 * distinguish "not configured" from "explicitly off". */
static void *
brix_ftp_create_conf(ngx_conf_t *cf)
{
    ngx_stream_brix_ftp_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable       = NGX_CONF_UNSET;
    conf->allow_write  = NGX_CONF_UNSET;
    conf->verify_write = NGX_CONF_UNSET;
    conf->gsi          = NGX_CONF_UNSET;
    conf->pasv_port_lo = NGX_CONF_UNSET;
    conf->pasv_port_hi = NGX_CONF_UNSET;
    conf->require_allo_size = NGX_CONF_UNSET;
    /* export / root_canon / cert paths zero-initialised by pcalloc. */

    return conf;
}


/* brix_ftp_install_handler — install the non-blocking ev/ STREAM engine as the
 * stream content handler for a server block that enabled brix_gridftp. */
static void
brix_ftp_install_handler(ngx_conf_t *cf, ngx_stream_brix_ftp_srv_conf_t *conf)
{
    ngx_stream_core_srv_conf_t *cscf;

    (void) conf;

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = brix_ftp_ev_handler;
}


/* brix_ftp_set_enable — parse the brix_gridftp flag and, when on, install the
 * stream connection handler so the module only intercepts connections in server
 * blocks that enabled it. */
static char *
brix_ftp_set_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_stream_brix_ftp_srv_conf_t *conf = conf_ptr;
    char                           *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf_ptr);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (!conf->enable) {
        return NGX_CONF_OK;
    }

    brix_ftp_install_handler(cf, conf);

    return NGX_CONF_OK;
}


/* brix_ftp_set_export removed (phase-101 W3): brix_gridftp_export -> bare
 * brix_export, owned by ngx_stream_brix_common_module.  The realpath-into-
 * root_canon + "export must exist" check this setter performed at parse time is
 * now done on the adopted export in brix_ftp_merge_conf (ftp_module_merge.c). */


/* brix_ftp_set_pasv_range — parse `brix_gridftp_pasv_port_range <lo> <hi>` into
 * the inclusive passive-data-port window.  Both must be valid TCP ports and
 * lo <= hi; a well-formed but empty/inverted range is a config error rather than
 * a silent fall-back to ephemeral, so a firewalled deployment cannot boot with a
 * range that would still hand out un-openable ports. */
static char *
brix_ftp_set_pasv_range(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_stream_brix_ftp_srv_conf_t *conf = conf_ptr;
    ngx_str_t                      *value = cf->args->elts;
    ngx_int_t                       lo, hi;

    (void) cmd;

    if (conf->pasv_port_lo != NGX_CONF_UNSET) {
        return "is duplicate";
    }
    lo = ngx_atoi(value[1].data, value[1].len);
    hi = ngx_atoi(value[2].data, value[2].len);
    if (lo == NGX_ERROR || hi == NGX_ERROR
        || lo < 1 || lo > 65535 || hi < 1 || hi > 65535)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_pasv_port_range: each bound must be a TCP port "
            "1..65535 (got \"%V\" \"%V\")", &value[1], &value[2]);
        return NGX_CONF_ERROR;
    }
    if (lo > hi) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_pasv_port_range: low bound %i exceeds high bound %i",
            lo, hi);
        return NGX_CONF_ERROR;
    }
    conf->pasv_port_lo = lo;
    conf->pasv_port_hi = hi;
    return NGX_CONF_OK;
}


/* brix_ftp_set_require_vo removed (phase-101 W3 stage 3b): brix_gridftp_require_vo
 * -> bare brix_require_vo, owned by ngx_stream_brix_common_module.  gridftp now
 * deep-copies the parsed rules into conf->vo_rules in brix_ftp_merge_conf and
 * finalizes them against root_canon there, as before. */


static ngx_command_t  brix_ftp_commands[] = {

    { ngx_string("brix_gridftp"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      brix_ftp_set_enable,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, enable),
      NULL },

    /* brix_gridftp_export / _allow_write / _storage_backend /
     * _storage_credential / _verify_write -> the bare storage names
     * (brix_export, brix_allow_write, brix_storage_backend,
     * brix_storage_credential, brix_verify_write) owned by
     * ngx_stream_brix_common_module (phase-101 W3 variant A).  gridftp adopts
     * this server's values into its flat fields in brix_ftp_merge_conf
     * (ftp_module_merge.c), which also realpath()s the adopted export into
     * root_canon — the check the brix_gridftp_export setter used to do at parse.
     * The flat fields (ftp_gateway.h) and every reader are unchanged. */

    /* Pin PASV/EPSV data ports to a firewall-opened inclusive range so the
     * gateway is reachable from behind a NAT/firewall on a locked-down network.
     * Unset = ephemeral (kernel-chosen), which cannot be firewalled. */
    { ngx_string("brix_gridftp_pasv_port_range"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
      brix_ftp_set_pasv_range,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Hold a stream-mode STOR preceded by ALLO <size> to exactly that many bytes,
     * so a truncated upload (a hostile middlebox dropping the data connection —
     * otherwise indistinguishable from a clean EOF) fails 550 instead of
     * committing a short object as complete. Default off (ALLO is RFC-advisory). */
    { ngx_string("brix_gridftp_require_allo_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, require_allo_size),
      NULL },

    { ngx_string("brix_gridftp_gsi"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, gsi),
      NULL },

    /* brix_gridftp_certificate / _certificate_key / _trusted_ca / _vomsdir /
     * _voms_cert_dir -> the bare x509 GSI-trust names (brix_certificate,
     * brix_certificate_key, brix_trusted_ca, brix_vomsdir, brix_voms_cert_dir)
     * owned by ngx_stream_brix_common_module (phase-101 W3 stage 3).  gridftp
     * adopts this server's values into its flat fields in brix_ftp_merge_conf
     * before brix_ftp_build_gsi; the flat fields (ftp_gateway.h) and every GSI
     * reader are unchanged. */

    /* brix_gridftp_require_vo -> bare brix_require_vo owned by
     * ngx_stream_brix_common_module (phase-101 W3 stage 3b).  gridftp deep-copies
     * this server's VO-ACL rules into conf->vo_rules in brix_ftp_merge_conf, then
     * brix_ftp_merge_vo_rules finalizes them against root_canon — unchanged. */

    ngx_null_command
};


/* brix_ftp_init_process — per-worker credential replay for every enabled GridFTP
 * export. brix_vfs_backend_set_credential runs at config parse in the master; the
 * VFS backend registry is rebuilt per worker, so without this replay a forked
 * worker holds the s3:// backend with an EMPTY credential and the first upstream
 * PUT/GET fails "no credential set". Mirrors the core stream module's
 * brix_init_server_backend_credential (process_server_init.c) for the gridftp
 * module's own srv conf. A missing credential/backend is a legitimate no-op; a
 * name that resolves to no block, or a credential that cannot be mapped, is
 * logged (WARN) and the worker still comes up — the failure surfaces on first use,
 * exactly as the config-time path already guaranteed the name exists. */
static ngx_int_t
brix_ftp_init_process(ngx_cycle_t *cycle)
{
    ngx_stream_core_main_conf_t    *cmcf;
    ngx_stream_core_srv_conf_t    **cscfp;
    ngx_stream_brix_ftp_srv_conf_t *conf;
    ngx_uint_t                      i;

    cmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_core_module);
    if (cmcf == NULL) {
        return NGX_OK;
    }
    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        char                     name[256];
        char                     bearer[4096];
        const brix_credential_t *cred;
        brix_vfs_backend_cred_t  bcred;

        conf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_brix_ftp_module);
        if (conf == NULL || !conf->enable
            || conf->storage_credential.len == 0
            || conf->root_canon[0] == '\0')
        {
            continue;
        }

        ngx_cpystrn((u_char *) name, conf->storage_credential.data,
                    ngx_min(conf->storage_credential.len + 1, sizeof(name)));
        cred = brix_credential_lookup(name);
        if (cred == NULL) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                "brix_gridftp: worker credential replay: no brix_credential "
                "\"%s\" for export \"%s\" — upstream auth WILL fail",
                name, conf->root_canon);
            continue;
        }
        if (brix_credential_to_backend_cred(cred, bearer, sizeof(bearer),
                                            &bcred, cycle->log) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                "brix_gridftp: worker credential replay: cannot derive "
                "credential \"%s\" for export \"%s\" — upstream auth WILL fail",
                name, conf->root_canon);
            continue;
        }
        brix_vfs_backend_set_credential(conf->root_canon, &bcred);
    }

    return NGX_OK;
}


static ngx_stream_module_t  brix_ftp_module_ctx = {
    NULL,                     /* preconfiguration  */
    NULL,                     /* postconfiguration */
    NULL,                     /* create main conf  */
    NULL,                     /* init main conf    */
    brix_ftp_create_conf,     /* create srv conf   */
    brix_ftp_merge_conf,      /* merge srv conf    */
};

ngx_module_t  ngx_stream_brix_ftp_module = {
    NGX_MODULE_V1,
    &brix_ftp_module_ctx,
    brix_ftp_commands,
    NGX_STREAM_MODULE,
    NULL,                     /* init master   */
    NULL,                     /* init module   */
    brix_ftp_init_process,    /* init process  */
    NULL,                     /* init thread   */
    NULL,                     /* exit thread   */
    NULL,                     /* exit process  */
    NULL,                     /* exit master   */
    NGX_MODULE_V1_PADDING
};
