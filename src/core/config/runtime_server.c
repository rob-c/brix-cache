/*
 * runtime_server.c — per-server-block runtime preparation at postconfiguration.
 */

#include "config.h"
#include "root_prepare.h"
#include "credential_block.h"             /* §14 brix_credential lookup/bearer */
#include "core/compat/staged_file.h"
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "fs/vfs/vfs_backend_registry.h"   /* per-export backend registration */
#include "fs/path/path.h"                 /* brix_mkdir_recursive (pblock:// init) */
#include "fs/tier/tier.h"              /* phase-64 tier parse + cache/stage register */
#include "fs/cache/cache_internal.h"   /* brix_cache_state_root (effective sidecar tree) */
#include "core/config/export_guard.h"  /* brix_assert_dir_outside_export (hard guard) */

/* Directive setter for a tier store-URL directive: arg[1] = the store URL (into the
 * ngx_str_t at cmd->offset); args[2..] = trailing credential=/block_size= params
 * (into the ngx_array_t* at the field offset carried in cmd->post). See header. */
char *
brix_conf_set_store_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char         *p = conf;
    ngx_str_t    *url  = (ngx_str_t *) (p + cmd->offset);
    ngx_array_t **args = (ngx_array_t **) (p + (uintptr_t) cmd->post);
    ngx_str_t    *value = cf->args->elts;
    ngx_uint_t    i;

    if (url->data != NULL) {
        return "is duplicate";
    }
    *url = value[1];                            /* the store URL token */

    if (cf->args->nelts > 2) {
        *args = ngx_array_create(cf->pool, cf->args->nelts - 2, sizeof(ngx_str_t));
        if (*args == NULL) {
            return NGX_CONF_ERROR;
        }
        for (i = 2; i < cf->args->nelts; i++) {
            ngx_str_t *a = ngx_array_push(*args);

            if (a == NULL) {
                return NGX_CONF_ERROR;
            }
            *a = value[i];                      /* "credential=..." / "block_size=..." */
        }
    }
    return NGX_CONF_OK;
}

/* A LOCAL storage backend NAMES THE EXPORT TREE — the fully composable replacement
 * for brix_root. Rewrites common->root from the backend URL and anchors root_canon
 * there. No-op for a remote/non-local backend (root://, tape://, http://, a cache
 * origin, or none). Shared by all three protocol finalisers; called BEFORE the
 * export-root prep. Two forms:
 *   posix:<path>      → root = <path>; CLEAR the backend (default POSIX driver).
 *   pblock://<path>   → root = /<path> (one leading '/' guaranteed: "pblock://x"→
 *                       "/x", "pblock:///abs"→"//abs"→/abs); KEEP the "pblock"
 *                       driver; create the block-store directory on init if needed. */
void
brix_storage_backend_posix_root(ngx_http_brix_shared_conf_t *common)
{
    ngx_str_t *sb = &common->storage_backend;

    if (sb->len > sizeof("posix:") - 1
        && ngx_strncmp(sb->data, "posix:", sizeof("posix:") - 1) == 0)
    {
        u_char *p    = sb->data + (sizeof("posix:") - 1);
        size_t  plen = sb->len  - (sizeof("posix:") - 1);

        /* Accept both posix:<path> and posix://<path>: collapse leading "//" runs to
         * one '/' so the root is a single canonical path (a stray double slash
         * propagates into common->root and breaks raw prefix-strip path uses).
         * "posix://abs" with an absolute path yields "///abs" → "/abs". */
        while (plen >= 2 && p[0] == '/' && p[1] == '/') {
            p++;
            plen--;
        }
        common->root.data = p;
        common->root.len  = plen;
        sb->len           = 0;                       /* default POSIX driver */
        return;
    }

    if (sb->len > sizeof("pblock://") - 1
        && ngx_strncmp(sb->data, "pblock://", sizeof("pblock://") - 1) == 0)
    {
        size_t base = sizeof("pblock://") - 1;       /* past "pblock://" */

        /* Yield EXACTLY one leading '/': "pblock:///abs" already has it (offset
         * `base`); "pblock://rel" gains it by keeping the prior '/' (offset base-1).
         * A double slash would break the write-through's prefix-strip path derivation. */
        if (sb->data[base] == '/') {
            common->root.data = sb->data + base;
            common->root.len  = sb->len  - base;
        } else {
            common->root.data = sb->data + base - 1;
            common->root.len  = sb->len  - base + 1;
        }
        sb->len = sizeof("pblock") - 1;              /* the bare "pblock" driver */
        (void) brix_mkdir_recursive((const char *) common->root.data, 0755);
    }
}

/* 1 iff the storage backend is REMOTE (the export's bytes live off-box: a root://
 * origin, http(s)://, s3://, tape://, ceph). For such an export the LOCAL root_canon
 * is only a namespace anchor — never written — so its export-root prep must not
 * demand W_OK (a pure remote-backed node defaults root_canon to "/", which is not
 * writable). Local backends (posix/pblock, or none) return 0 and keep the W_OK
 * check. Called after brix_storage_backend_posix_root (posix:/pblock:// already
 * rewritten away). */
int
brix_storage_backend_is_remote(const ngx_http_brix_shared_conf_t *common)
{
    static const char *const schemes[] = {
        "root://", "roots://", "http://", "https://", "s3://",
        "tape://", "frm://", "rados://", "ceph:", "cephfsro:", NULL
    };
    const ngx_str_t *sb = &common->storage_backend;
    int               i;

    for (i = 0; schemes[i] != NULL; i++) {
        size_t n = ngx_strlen(schemes[i]);

        if (sb->len >= n && ngx_strncmp(sb->data, schemes[i], n) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Parse the cache_store URL and record its tier cfg + read-through policy on the
 * backend registry. Split out of brix_tier_register_stores so each function's
 * branching stays within the readability gate. Operator errors are [emerg]. */
static ngx_int_t
brix_tier_register_cache_store(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common)
{
    char                err[256];
    brix_tier_cfg_t     cfg;
    brix_cache_policy_t pol;
    brix_tier_parse_t   tp = { cf, &cfg, err, sizeof(err) };

    if (brix_tier_parse_store(&tp, &common->cache_store,
            common->cache_store_args, BRIX_TIER_CACHE) != NGX_OK)
    {
        return NGX_ERROR;                      /* [emerg] already logged */
    }
    ngx_memzero(&pol, sizeof(pol));
    pol.enabled       = 1;
    pol.max_file_size = common->cache_max_object;
    pol.evict_at      = common->cache_evict_at;
    pol.evict_to      = common->cache_evict_to;
    pol.meta_mode     = (int) common->cache_meta_mode;
    pol.batch_cinfo   = (common->cache_batch_cinfo == 2)
                      ? -1 : (int) common->cache_batch_cinfo;
    pol.l1_entries    = common->cache_index_cache;
    pol.slice_size    = common->cache_slice_size;
    /* phase-68: digest verification on fill (cvmfs-cas today). The verify
     * runs on the staged temp BEFORE commit, which needs the store's
     * staged_path — a local posix store; reject other stores loudly. */
    pol.verify = (common->cache_verify_mode == NGX_CONF_UNSET_UINT)
               ? BRIX_CACHE_VERIFY_OFF
               : (brix_cache_verify_mode_e) common->cache_verify_mode;
    if (pol.verify == BRIX_CACHE_VERIFY_CVMFS_CAS
        && ngx_strcmp(cfg.driver, "posix") != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_verify cvmfs-cas requires a local posix "
            "cache store (got \"%s\")", cfg.driver);
        return NGX_ERROR;
    }
    pol.cvmfs_manifest_ttl = common->cache_manifest_ttl;
    if (common->cache_quarantine_dir.len > 0) {
        ngx_cpystrn((u_char *) pol.quarantine_dir,
                    common->cache_quarantine_dir.data,
                    ngx_min(common->cache_quarantine_dir.len + 1,
                            sizeof(pol.quarantine_dir)));
    }
    brix_vfs_backend_config_cache_store(common->root_canon, &cfg, &pol);
    return NGX_OK;
}

/* Register the export's phase-64 composable cache/stage tiers (additive over the
 * storage backend). Parses the cache_store / stage_store URLs (operator errors are
 * [emerg], failing nginx -t) and records the tier cfg + policy on the backend
 * registry, which composes the sd_cache / sd_stage decorators per worker. Shared by
 * all three protocol finalisers (§4.4) - it reads only the common preamble. */
ngx_int_t
brix_tier_register_stores(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *common)
{
    char                           err[256];

    /* G8 (P4/§9.4): a nearline (tape) backend is unservable without a cache tier
     * as the recall target - reject at config time. "frm://" is the tape:// alias. */
    {
        const ngx_str_t *sb = &common->storage_backend;
        int is_nearline =
            (sb->len > sizeof("tape://") - 1
             && ngx_strncmp(sb->data, "tape://", sizeof("tape://") - 1) == 0)
            || (sb->len > sizeof("frm://") - 1
                && ngx_strncmp(sb->data, "frm://", sizeof("frm://") - 1) == 0);

        if (is_nearline && common->cache_store.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: a \"tape://\"/\"frm://\" backend is nearline and requires "
                "brix_cache_store (the recall target); add a cache tier");
            return NGX_ERROR;
        }
    }

    if (common->cache_store.len > 0
        && brix_tier_register_cache_store(cf, common) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (common->stage_enable == 1) {
        brix_tier_cfg_t     cfg;
        brix_stage_policy_t spol;
        brix_tier_parse_t   tp = { cf, &cfg, err, sizeof(err) };

        if (common->stage_store.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_stage on requires brix_stage_store");
            return NGX_ERROR;
        }
        if (brix_tier_parse_store(&tp, &common->stage_store,
                common->stage_store_args, BRIX_TIER_STAGE) != NGX_OK)
        {
            return NGX_ERROR;
        }
        ngx_memzero(&spol, sizeof(spol));
        spol.enabled    = 1;
        spol.flush_mode = common->stage_flush_async ? BRIX_WT_MODE_ASYNC
                                                     : BRIX_WT_MODE_SYNC;
        brix_vfs_backend_config_stage_store(common->root_canon, &cfg, &spol);
    }

    return NGX_OK;
}

static int
brix_server_has_runtime_export(const ngx_stream_brix_srv_conf_t *xcf)
{
    return !xcf->manager_mode && !xcf->caps.supervisor
           && xcf->manager_map == NULL && !xcf->proxy.enable;
}

static int
brix_server_storage_backend_is_remote(const ngx_str_t *sb)
{
    return (sb->len > sizeof("root://") - 1
            && ngx_strncmp(sb->data, "root://", sizeof("root://") - 1) == 0)
           || (sb->len > sizeof("roots://") - 1
               && ngx_strncmp(sb->data, "roots://", sizeof("roots://") - 1) == 0)
           || (sb->len > sizeof("http://") - 1
               && ngx_strncmp(sb->data, "http://", sizeof("http://") - 1) == 0)
           || (sb->len > sizeof("https://") - 1
               && ngx_strncmp(sb->data, "https://", sizeof("https://") - 1) == 0);
}

static const char *
brix_server_cred_str_or_null(const ngx_str_t *s)
{
    return (s->len > 0) ? (const char *) s->data : NULL;
}

static void
brix_server_fill_x509_credential(const brix_credential_t *cred,
    brix_vfs_backend_cred_t *bcred)
{
    if (cred->x509_proxy.len > 0) {
        bcred->x509_proxy = (const char *) cred->x509_proxy.data;
        return;
    }
    if (cred->x509_cert.len > 0) {
        bcred->x509_proxy = (const char *) cred->x509_cert.data;
    }
    if (cred->x509_key.len > 0) {
        bcred->x509_key = (const char *) cred->x509_key.data;
    }
}

static ngx_int_t
brix_server_set_storage_credential(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    char                     cred_z[256];
    char                     bearer[4096];
    const brix_credential_t *cred;
    brix_vfs_backend_cred_t  bcred;

    if (xcf->common.storage_credential.len == 0) {
        return NGX_OK;
    }
    ngx_cpystrn((u_char *) cred_z, xcf->common.storage_credential.data,
                ngx_min(xcf->common.storage_credential.len + 1,
                        sizeof(cred_z)));
    cred = brix_credential_lookup(cred_z);
    if (cred == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_credential: no brix_credential \"%V\"",
            &xcf->common.storage_credential);
        return NGX_ERROR;
    }
    if (brix_credential_bearer(cred, bearer, sizeof(bearer), cf->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&bcred, sizeof(bcred));
    bcred.bearer = (bearer[0] != '\0') ? bearer : NULL;
    brix_server_fill_x509_credential(cred, &bcred);
    bcred.ca_dir = brix_server_cred_str_or_null(&cred->ca_dir);
    bcred.s3_access_key = brix_server_cred_str_or_null(&cred->s3_access_key);
    bcred.s3_secret_key = brix_server_cred_str_or_null(&cred->s3_secret_key);
    bcred.s3_region = brix_server_cred_str_or_null(&cred->s3_region);
    bcred.sss_keytab = brix_server_cred_str_or_null(&cred->sss_keytab);
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: backend credential \"%V\" for \"%s\": gsi=%s key=%s bearer=%s",
        &xcf->common.storage_credential, xcf->common.root_canon,
        bcred.x509_proxy ? bcred.x509_proxy : "(none)",
        bcred.x509_key ? bcred.x509_key : "(in-proxy/none)",
        bcred.bearer ? "set" : "(none)");
    brix_vfs_backend_set_credential(xcf->common.root_canon, &bcred);
    return NGX_OK;
}

static ngx_int_t
brix_server_set_wt_credential(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    char                     cred_z[256];
    char                     bearer[4096];
    const brix_credential_t *cred;

    if (xcf->wt.credential.len == 0) {
        return NGX_OK;
    }
    ngx_cpystrn((u_char *) cred_z, xcf->wt.credential.data,
                ngx_min(xcf->wt.credential.len + 1, sizeof(cred_z)));
    cred = brix_credential_lookup(cred_z);
    if (cred == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_wt_credential: no brix_credential \"%V\"",
            &xcf->wt.credential);
        return NGX_ERROR;
    }
    if (brix_credential_bearer(cred, bearer, sizeof(bearer), cf->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (bearer[0] != '\0') {
        size_t  bl = ngx_strlen(bearer);
        u_char *bp = ngx_pnalloc(cf->pool, bl + 1);

        if (bp == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(bp, bearer, bl + 1);
        xcf->cache_origin_bearer.data = bp;
        xcf->cache_origin_bearer.len  = bl;
    }
    if (cred->x509_proxy.len > 0) {
        xcf->cache_origin_x509_proxy = cred->x509_proxy;
    } else if (cred->x509_cert.len > 0) {
        xcf->cache_origin_x509_proxy = cred->x509_cert;
        xcf->cache_origin_x509_key   = cred->x509_key;
    }
    if (cred->ca_dir.len > 0) {
        xcf->cache_origin_ca_dir = cred->ca_dir;
    }
    return NGX_OK;
}

static ngx_int_t
brix_server_setup_export(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    brix_export_root_opts_t root_opts;

    if (!brix_server_has_runtime_export(xcf)) {
        return NGX_OK;
    }
    brix_storage_backend_posix_root(&xcf->common);
    root_opts.directive_name = "brix_export";
    root_opts.allow_write    = xcf->common.allow_write
                             && !brix_storage_backend_is_remote(&xcf->common);
    root_opts.required       = 1;
    root_opts.canon_size     = sizeof(xcf->common.root_canon);
    if (brix_prepare_export_root(cf, &xcf->common.root, &root_opts,
                                   xcf->common.root_canon) != NGX_CONF_OK)
    {
        return NGX_ERROR;
    }
    brix_tmp_reap_register(xcf->common.root_canon);
    if (brix_vfs_backend_config_str(cf, xcf->common.root_canon,
            &xcf->common.storage_backend, xcf->common.pblock_block_size,
            (int) xcf->cache_origin_family) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (brix_server_set_storage_credential(cf, xcf) != NGX_OK
        || brix_server_set_wt_credential(cf, xcf) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (xcf->upload_stage_dir.len > 0) {
        brix_export_root_opts_t stage_opts;
        stage_opts.directive_name = "brix_stage_dir";
        stage_opts.allow_write    = 1;
        stage_opts.required       = 0;
        stage_opts.canon_size     = sizeof(xcf->upload_stage_dir_canon);
        if (brix_prepare_export_root(cf, &xcf->upload_stage_dir,
                &stage_opts, xcf->upload_stage_dir_canon) != NGX_CONF_OK)
        {
            return NGX_ERROR;
        }
        brix_stage_dir_register(xcf->upload_stage_dir_canon);
    }
    if (brix_tier_register_stores(cf, &xcf->common) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_assert_dir_outside_export(cf, "cache state/sidecar tree",
            xcf->common.root_canon, brix_cache_state_root(xcf)) != NGX_OK
        || brix_assert_dir_outside_export(cf, "brix_stage_dir",
            xcf->common.root_canon, xcf->upload_stage_dir_canon) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
brix_server_validate_cache_stage_backend(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->cache_wt_stage_backend.len == 0) {
        return NGX_OK;
    }
    if (xcf->cache_wt_stage_root.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_wt_stage_backend requires brix_cache_wt_stage_root");
        return NGX_ERROR;
    }
    if (xcf->cache_state_root.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_wt_stage_backend requires a POSIX "
            "brix_cache_state_root for its sidecars");
        return NGX_ERROR;
    }
    brix_vfs_backend_config((const char *) xcf->cache_wt_stage_root.data,
                              &xcf->cache_wt_stage_backend,
                              xcf->cache_wt_stage_block_size);
    return NGX_OK;
}

static ngx_int_t
brix_server_validate_cache_watermarks(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->cache_eviction_threshold == 0
        || xcf->cache_eviction_threshold >= 1000000)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_eviction_threshold must be greater than 0 "
            "and less than 1.0");
        return NGX_ERROR;
    }
    if (xcf->reaper.high_watermark == 0
        || xcf->reaper.high_watermark >= 1000000
        || xcf->reaper.low_watermark == 0
        || xcf->reaper.low_watermark >= xcf->reaper.high_watermark)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_low_watermark must be greater than 0 and less "
            "than brix_cache_high_watermark (which must be < 1.0)");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
brix_server_validate_cache(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    if (!xcf->cache) {
        return NGX_OK;
    }
    if (xcf->common.allow_write && !xcf->wt.enable) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache is read-only and requires "
            "brix_allow_write off (or enable brix_write_through)");
        return NGX_ERROR;
    }
    if (brix_server_validate_cache_stage_backend(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (xcf->cache_root.len == 0
        || !brix_server_storage_backend_is_remote(&xcf->common.storage_backend))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache on requires brix_cache_export and a remote "
            "brix_storage_backend (root://host:port); the retired "
            "brix_cache_origin model is the tier grammar now "
            "(brix_storage_backend + brix_cache_store)");
        return NGX_ERROR;
    }
    if (brix_validate_path(cf, "brix_cache_export", &xcf->cache_root,
                             BRIX_PATH_DIRECTORY, R_OK | W_OK | X_OK)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (xcf->cache_lock_timeout <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_lock_timeout must be greater than zero");
        return NGX_ERROR;
    }
    if (brix_server_validate_cache_watermarks(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: cache enabled root=%V origin=%V tls=%s "
        "lock_timeout=%ds eviction_threshold=0.%06ui",
        &xcf->cache_root, &xcf->cache_origin,
        xcf->cache_origin_tls ? "on" : "off",
        (int) xcf->cache_lock_timeout,
        xcf->cache_eviction_threshold);
    return NGX_OK;
}

static ngx_int_t
brix_server_validate_wt_stage(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->cache_wt_stage_high_watermark == 0) {
        return NGX_OK;
    }
    if (xcf->cache_wt_stage_root.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_wt_stage_high_watermark requires brix_cache_wt_stage_root");
        return NGX_ERROR;
    }
    if (xcf->cache_wt_stage_high_watermark >= 1000000
        || xcf->cache_wt_stage_low_watermark == 0
        || xcf->cache_wt_stage_low_watermark
               >= xcf->cache_wt_stage_high_watermark)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_wt_stage_low_watermark must be greater than 0 and "
            "less than brix_wt_stage_high_watermark (which must be < 1.0)");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
brix_server_setup_logging(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->access_log.len > 0
        && ngx_strcmp(xcf->access_log.data, (u_char *) "off") != 0)
    {
        xcf->access_log_file = ngx_conf_open_file(cf->cycle, &xcf->access_log);
        if (xcf->access_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: cannot register access log \"%V\"", &xcf->access_log);
            return NGX_ERROR;
        }
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix: access log \"%V\" registered", &xcf->access_log);
    }
    if (xcf->proxy.enable && xcf->proxy.audit_log.len > 0
        && ngx_strcmp(xcf->proxy.audit_log.data, (u_char *) "off") != 0)
    {
        xcf->proxy.audit_log_file = ngx_conf_open_file(cf->cycle,
                                                       &xcf->proxy.audit_log);
        if (xcf->proxy.audit_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: cannot register proxy audit log \"%V\"",
                &xcf->proxy.audit_log);
            return NGX_ERROR;
        }
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix: proxy audit log \"%V\" registered", &xcf->proxy.audit_log);
    }
    return NGX_OK;
}

static ngx_int_t
brix_server_setup_tls(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
#if (NGX_SSL)
    if (xcf->proxy.enable && xcf->proxy.upstream_tls) {
        xcf->proxy.tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (xcf->proxy.tls_ctx == NULL) {
            return NGX_ERROR;
        }
        xcf->proxy.tls_ctx->log = cf->log;
        if (ngx_ssl_create(xcf->proxy.tls_ctx,
                           NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3,
                           NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
        if (xcf->proxy.upstream_tls_ca.len > 0) {
            if (ngx_ssl_trusted_certificate(cf, xcf->proxy.tls_ctx,
                                             &xcf->proxy.upstream_tls_ca,
                                             5) != NGX_OK)
            {
                return NGX_ERROR;
            }
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "brix: proxy upstream TLS CA loaded from \"%V\"",
                &xcf->proxy.upstream_tls_ca);
        }
    }
    if (xcf->upstream_tls) {
        xcf->upstream_tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (xcf->upstream_tls_ctx == NULL) {
            return NGX_ERROR;
        }
        xcf->upstream_tls_ctx->log = cf->log;
        if (ngx_ssl_create(xcf->upstream_tls_ctx,
                           NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3,
                           NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
        if (xcf->upstream_tls_ca.len > 0) {
            if (ngx_ssl_trusted_certificate(cf, xcf->upstream_tls_ctx,
                                             &xcf->upstream_tls_ca,
                                             5) != NGX_OK)
            {
                return NGX_ERROR;
            }
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "brix: upstream redirector TLS CA loaded from \"%V\"",
                &xcf->upstream_tls_ca);
        }
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix: upstream redirector TLS enabled (kXR_gotoTLS support)");
    }
#else
    (void) cf;
    (void) xcf;
#endif
    return NGX_OK;
}

/* Prepare one server block at postconfiguration: validate the configured root
 * is an existing, accessible directory (access mode matching the write policy)
 * and check the cache configuration, before the block accepts connections.
 * Returns NGX_OK, or NGX_ERROR (emerg-logged) on any invalid resource. */
ngx_int_t
brix_config_prepare_server(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    /* Hard read-only switch: force allow_write off before any allow_write-dependent
     * setup, so every write gate rejects (root:// require_write, write-open, ...). */
    brix_shared_apply_read_only(&xcf->common, cf->log);

    /* Phase-4b: a GSI tap proxy must capture the client's delegated proxy to
     * present it upstream — auto-enable delegation receipt if the admin didn't. */
    if (xcf->proxy.enable && xcf->proxy.auth == BRIX_PROXY_AUTH_GSI
        && !xcf->tpc_delegate)
    {
        xcf->tpc_delegate = 1;
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix_tap_proxy_auth gsi: enabling GSI proxy delegation capture");
    }

    if (brix_server_setup_export(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_server_validate_cache(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_server_validate_wt_stage(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_server_setup_logging(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_server_setup_tls(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
