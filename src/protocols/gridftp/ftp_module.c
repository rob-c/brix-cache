#include "ftp_gateway.h"
#include "ftp_module_internal.h"           /* brix_ftp_build_gsi (ftp_module_gsi.c) */

#include "fs/vfs/vfs_backend_registry.h"   /* per-export storage-backend register */
#include "core/config/credential_block.h"  /* s3:// backend SigV4 credential      */

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

    if (conf->storage_credential.len == 0) {
        return NGX_CONF_OK;
    }
    ngx_cpystrn((u_char *) name, conf->storage_credential.data,
                ngx_min(conf->storage_credential.len + 1, sizeof(name)));
    cred = brix_credential_lookup(name);
    if (cred == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_storage_credential \"%s\" names no brix_credential "
            "block", name);
        return NGX_CONF_ERROR;
    }
    if (brix_credential_to_backend_cred(cred, bearer, sizeof(bearer),
                                        &bcred, cf->log) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp: cannot derive credential \"%s\" for export \"%s\"",
            name, conf->root_canon);
        return NGX_CONF_ERROR;
    }
    brix_vfs_backend_set_credential(conf->root_canon, &bcred);

    /* An explicit `mode` on the block overrides the gateway's default per-request
     * delegation mode (e.g. `mode select` pins the service credential and never
     * forwards the client's proxy). */
    if (cred->mode != NGX_CONF_UNSET) {
        conf->deleg_mode = (enum brix_cred_mode) cred->mode;
    }
    return NGX_CONF_OK;
}


/* brix_ftp_merge_conf — parent→child merge: disabled and read-only by default;
 * inherit the export root when the child omitted its own. */
static char *
brix_ftp_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_brix_ftp_srv_conf_t *prev = parent;
    ngx_stream_brix_ftp_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable,      prev->enable,      0);
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_value(conf->verify_write, prev->verify_write, 0);
    ngx_conf_merge_value(conf->gsi,         prev->gsi,         0);
    ngx_conf_merge_value(conf->pasv_port_lo, prev->pasv_port_lo, 0);
    ngx_conf_merge_value(conf->pasv_port_hi, prev->pasv_port_hi, 0);
    ngx_conf_merge_value(conf->require_allo_size, prev->require_allo_size, 0);
    ngx_conf_merge_str_value(conf->export,  prev->export,      "");
    ngx_conf_merge_str_value(conf->storage_backend, prev->storage_backend, "");
    ngx_conf_merge_str_value(conf->storage_credential,
                             prev->storage_credential, "");
    ngx_conf_merge_str_value(conf->certificate,     prev->certificate,     "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_str_value(conf->trusted_ca,      prev->trusted_ca,      "");

    if (conf->root_canon[0] == '\0' && prev->root_canon[0] != '\0') {
        ngx_memcpy(conf->root_canon, prev->root_canon,
                   sizeof(conf->root_canon));
    }

    if (conf->enable && conf->root_canon[0] == '\0') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp is on but brix_gridftp_export is unset or "
            "unresolvable");
        return NGX_CONF_ERROR;
    }

    /* Register this export's storage backend so every per-request ftp_vfs_ctx()
     * (which calls brix_vfs_ctx_init → brix_vfs_backend_resolve on root_canon)
     * routes through the selected driver — "pblock" today, POSIX when unset.
     * The gateway itself only ever touches storage through brix_vfs_*, so no
     * data-path change is needed once the choice is on the registry. */
    if (conf->enable && conf->root_canon[0] != '\0') {
        char *rv;
        if (brix_vfs_backend_config_str(cf, conf->root_canon,
                &conf->storage_backend, 0, BRIX_AF_AUTO) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
        /* Default: forward the client's delegated proxy (PASSTHROUGH). A named
         * brix_credential block's `mode` may override this inside install below;
         * the request-time bind (ftp_ev_path.c) additionally no-ops on backends
         * that do not consume a proxy, so posix/pblock exports are unaffected. */
        conf->deleg_mode = BRIX_CRED_PASSTHROUGH;
        rv = brix_ftp_install_backend_credential(cf, conf);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    if (conf->tls_ctx == NULL && prev->tls_ctx != NULL) {
        conf->tls_ctx  = prev->tls_ctx;      /* inherit built ctx */
        conf->ca_store = prev->ca_store;
    } else if (conf->enable && conf->gsi && conf->tls_ctx == NULL) {
        char *rv = brix_ftp_build_gsi(cf, conf);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    return NGX_CONF_OK;
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


/* brix_ftp_set_export — store the raw export string and realpath(3) it into
 * root_canon at config time so every per-request brix_http_resolve_path() has a
 * canonical confinement root.  A not-yet-existing tree fails the config (unlike
 * a cache dir, an export must exist to serve). */
static char *
brix_ftp_set_export(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_stream_brix_ftp_srv_conf_t *conf = conf_ptr;
    ngx_str_t                      *value = cf->args->elts;
    ngx_str_t                       dir   = value[1];
    char                            raw[PATH_MAX];

    (void) cmd;

    if (conf->export.len != 0) {
        return "is duplicate";
    }
    if (ngx_conf_full_name(cf->cycle, &dir, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    if (dir.len >= sizeof(raw)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_export path too long: %V", &dir);
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(raw, dir.data, dir.len);
    raw[dir.len] = '\0';

    if (realpath(raw, conf->root_canon) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix_gridftp_export \"%s\" cannot be resolved (does it exist?)",
            raw);
        return NGX_CONF_ERROR;
    }

    conf->export = dir;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: GridFTP gateway export=%s (canon)", conf->root_canon);

    return NGX_CONF_OK;
}


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


static ngx_command_t  brix_ftp_commands[] = {

    { ngx_string("brix_gridftp"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      brix_ftp_set_enable,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, enable),
      NULL },

    { ngx_string("brix_gridftp_export"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_ftp_set_export,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_gridftp_allow_write"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, allow_write),
      NULL },

    /* Selects the storage backend for the export: "posix" (default) or
     * "pblock" (block store rooted at brix_gridftp_export; needs the sqlite
     * build). The gateway serves it transparently through brix_vfs_*. */
    { ngx_string("brix_gridftp_storage_backend"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, storage_backend),
      NULL },

    /* Names the brix_credential block that carries the upstream identity for an
     * s3:// storage backend (SigV4 access/secret/region). Ignored for the POSIX
     * default export and pblock, which need no upstream credential. */
    { ngx_string("brix_gridftp_storage_credential"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, storage_credential),
      NULL },

    /* After each STOR, re-read the object through the storage driver and
     * CRC-check it against the bytes that were written; a mismatch fails the
     * transfer and unlinks the object. Off by default (doubles read I/O per
     * upload). This is a STORAGE-persistence check — it proves the driver
     * persisted exactly the bytes it received (catching an object backend that
     * routes a write short/empty), NOT a wire-integrity check: the CRC is seeded
     * from the received bytes, so a byte the network corrupted in flight is
     * accumulated, written, read back, and matches. Wire integrity is the
     * client's CKSM after transfer (compared against its local digest). */
    { ngx_string("brix_gridftp_verify_write"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, verify_write),
      NULL },

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

    { ngx_string("brix_gridftp_certificate"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, certificate),
      NULL },

    { ngx_string("brix_gridftp_certificate_key"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, certificate_key),
      NULL },

    { ngx_string("brix_gridftp_trusted_ca"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_ftp_srv_conf_t, trusted_ca),
      NULL },

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
