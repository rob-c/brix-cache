/*
 * runtime_server.c — per-server-block runtime preparation at postconfiguration.
 */

#include "config.h"
#include "root_prepare.h"
#include "credential_block.h"             /* §14 xrootd_credential lookup/bearer */
#include "core/compat/staged_file.h"
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "fs/vfs_backend_registry.h"   /* per-export backend registration */
#include "fs/path/path.h"                 /* xrootd_mkdir_recursive (pblock:// init) */
#include "fs/tier/tier.h"              /* phase-64 tier parse + cache/stage register */

/* Directive setter for a tier store-URL directive: arg[1] = the store URL (into the
 * ngx_str_t at cmd->offset); args[2..] = trailing credential=/block_size= params
 * (into the ngx_array_t* at the field offset carried in cmd->post). See header. */
char *
xrootd_conf_set_store_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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
 * for xrootd_root. Rewrites common->root from the backend URL and anchors root_canon
 * there. No-op for a remote/non-local backend (root://, tape://, http://, a cache
 * origin, or none). Shared by all three protocol finalisers; called BEFORE the
 * export-root prep. Two forms:
 *   posix:<path>      → root = <path>; CLEAR the backend (default POSIX driver).
 *   pblock://<path>   → root = /<path> (one leading '/' guaranteed: "pblock://x"→
 *                       "/x", "pblock:///abs"→"//abs"→/abs); KEEP the "pblock"
 *                       driver; create the block-store directory on init if needed. */
void
xrootd_storage_backend_posix_root(ngx_http_xrootd_shared_conf_t *common)
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
        (void) xrootd_mkdir_recursive((const char *) common->root.data, 0755);
    }
}

/* 1 iff the storage backend is REMOTE (the export's bytes live off-box: a root://
 * origin, http(s)://, s3://, tape://, ceph). For such an export the LOCAL root_canon
 * is only a namespace anchor — never written — so its export-root prep must not
 * demand W_OK (a pure remote-backed node defaults root_canon to "/", which is not
 * writable). Local backends (posix/pblock, or none) return 0 and keep the W_OK
 * check. Called after xrootd_storage_backend_posix_root (posix:/pblock:// already
 * rewritten away). */
int
xrootd_storage_backend_is_remote(const ngx_http_xrootd_shared_conf_t *common)
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

/* Register the export's phase-64 composable cache/stage tiers (additive over the
 * storage backend). Parses the cache_store / stage_store URLs (operator errors are
 * [emerg], failing nginx -t) and records the tier cfg + policy on the backend
 * registry, which composes the sd_cache / sd_stage decorators per worker. Shared by
 * all three protocol finalisers (§4.4) - it reads only the common preamble. */
ngx_int_t
xrootd_tier_register_stores(ngx_conf_t *cf, ngx_http_xrootd_shared_conf_t *common)
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
                "xrootd: a \"tape://\"/\"frm://\" backend is nearline and requires "
                "xrootd_cache_store (the recall target); add a cache tier");
            return NGX_ERROR;
        }
    }

    if (common->cache_store.len > 0) {
        xrootd_tier_cfg_t     cfg;
        xrootd_cache_policy_t pol;

        if (xrootd_tier_parse_store(cf, &common->cache_store,
                common->cache_store_args, XROOTD_TIER_CACHE, &cfg, err,
                sizeof(err)) != NGX_OK)
        {
            return NGX_ERROR;                  /* [emerg] already logged */
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
        xrootd_vfs_backend_config_cache_store(common->root_canon, &cfg, &pol);
    }

    if (common->stage_enable == 1) {
        xrootd_tier_cfg_t     cfg;
        xrootd_stage_policy_t spol;

        if (common->stage_store.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_stage on requires xrootd_stage_store");
            return NGX_ERROR;
        }
        if (xrootd_tier_parse_store(cf, &common->stage_store,
                common->stage_store_args, XROOTD_TIER_STAGE, &cfg, err,
                sizeof(err)) != NGX_OK)
        {
            return NGX_ERROR;
        }
        ngx_memzero(&spol, sizeof(spol));
        spol.enabled    = 1;
        spol.flush_mode = common->stage_flush_async ? XROOTD_WT_MODE_ASYNC
                                                     : XROOTD_WT_MODE_SYNC;
        xrootd_vfs_backend_config_stage_store(common->root_canon, &cfg, &spol);
    }

    return NGX_OK;
}

/* Prepare one server block at postconfiguration: validate the configured root
 * is an existing, accessible directory (access mode matching the write policy)
 * and check the cache configuration, before the block accepts connections.
 * Returns NGX_OK, or NGX_ERROR (emerg-logged) on any invalid resource. */
ngx_int_t
xrootd_config_prepare_server(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf)
{
    /* Hard read-only switch: force allow_write off before any allow_write-dependent
     * setup, so every write gate rejects (root:// require_write, write-open, ...). */
    xrootd_shared_apply_read_only(&xcf->common, cf->log);

    /* Phase-4b: a GSI tap proxy must capture the client's delegated proxy to
     * present it upstream — auto-enable delegation receipt if the admin didn't. */
    if (xcf->proxy_enable && xcf->proxy_auth == XROOTD_PROXY_AUTH_GSI
        && !xcf->tpc_delegate)
    {
        xcf->tpc_delegate = 1;
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd_tap_proxy_auth gsi: enabling GSI proxy delegation capture");
    }

    if (!xcf->manager_mode && !xcf->supervisor
        && xcf->manager_map == NULL && !xcf->proxy_enable) {
        xrootd_export_root_opts_t root_opts;

        /* A "posix:<path>" storage backend NAMES THE LOCAL EXPORT TREE — the fully
         * composable replacement for xrootd_root. Anchor the export root at <path>
         * and clear the backend so the default POSIX driver serves it directly. */
        xrootd_storage_backend_posix_root(&xcf->common);

        root_opts.directive_name = "xrootd_root";
        root_opts.allow_write    = xcf->common.allow_write
                                 && !xrootd_storage_backend_is_remote(&xcf->common);
        /* A pure cache node needs no local export tree: xrootd_cache_store is the
         * physical FSAL and xrootd_cache_root the advertised root. xrootd_root then
         * defaults to "/" (server_conf.c) — the cache serves the "/" namespace,
         * filling from the backend into the store. */
        root_opts.required       = 1;
        root_opts.canon_size     = sizeof(xcf->common.root_canon);
        if (xrootd_prepare_export_root(cf, &xcf->common.root, &root_opts,
                                       xcf->common.root_canon) != NGX_CONF_OK)
        {
            return NGX_ERROR;
        }
        /* SP4: reap interrupted NON-staged direct-write temps under a real export
         * tree (xrootd_tmp_reap_register itself refuses "/" — a pure cache node,
         * whose root_canon is "/", keeps its in-flight temps in the store tier). */
        xrootd_tmp_reap_register(xcf->common.root_canon);

        /* Register the export's selected storage backend for VFS resolution at
         * request time. A "root://host:port" value makes the export's PRIMARY
         * storage a REMOTE XRootD server (read + write-through via sd_xroot); a
         * driver name (e.g. "pblock") selects a local backend; default POSIX is a
         * no-op. */
        if (xrootd_vfs_backend_config_str(cf, xcf->common.root_canon,
                &xcf->common.storage_backend, xcf->common.pblock_block_size,
                (int) xcf->cache_origin_family)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        /* §14: attach the named xrootd_credential's bearer token to the source
         * backend (today consumed by sd_http as Authorization: Bearer). Resolved at
         * config time so a missing credential fails loudly; an empty token_file is
         * an error too. No xrootd_storage_credential ⇒ anonymous. */
        if (xcf->common.storage_credential.len > 0) {
            char                       cred_z[256];
            char                       bearer[4096];
            const xrootd_credential_t *cred;

            ngx_cpystrn((u_char *) cred_z, xcf->common.storage_credential.data,
                        ngx_min(xcf->common.storage_credential.len + 1,
                                sizeof(cred_z)));
            cred = xrootd_credential_lookup(cred_z);
            if (cred == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_storage_credential: no xrootd_credential \"%V\"",
                    &xcf->common.storage_credential);
                return NGX_ERROR;
            }
            if (xrootd_credential_bearer(cred, bearer, sizeof(bearer), cf->log)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            {
                xrootd_vfs_backend_cred_t bcred;

                ngx_memzero(&bcred, sizeof(bcred));
                bcred.bearer = (bearer[0] != '\0') ? bearer : NULL;
                bcred.x509_proxy = (cred->x509_proxy.len > 0)
                    ? (const char *) cred->x509_proxy.data : NULL;
                bcred.ca_dir = (cred->ca_dir.len > 0)
                    ? (const char *) cred->ca_dir.data : NULL;
                bcred.s3_access_key = (cred->s3_access_key.len > 0)
                    ? (const char *) cred->s3_access_key.data : NULL;
                bcred.s3_secret_key = (cred->s3_secret_key.len > 0)
                    ? (const char *) cred->s3_secret_key.data : NULL;
                bcred.s3_region = (cred->s3_region.len > 0)
                    ? (const char *) cred->s3_region.data : NULL;
                bcred.sss_keytab = (cred->sss_keytab.len > 0)
                    ? (const char *) cred->sss_keytab.data : NULL;
                xrootd_vfs_backend_set_credential(xcf->common.root_canon, &bcred);
            }
        }

        /* §14 + C-3/C-5: the write-back flush authenticates to its wt_origin with a
         * credential too (ztn bearer). Resolve into cache_origin_bearer, which the
         * C-5 driver write-back already threads into its sd_xroot dest. */
        if (xcf->wt_credential.len > 0) {
            char                       cred_z[256];
            char                       bearer[4096];
            const xrootd_credential_t *cred;

            ngx_cpystrn((u_char *) cred_z, xcf->wt_credential.data,
                        ngx_min(xcf->wt_credential.len + 1, sizeof(cred_z)));
            cred = xrootd_credential_lookup(cred_z);
            if (cred == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_wt_credential: no xrootd_credential \"%V\"",
                    &xcf->wt_credential);
                return NGX_ERROR;
            }
            if (xrootd_credential_bearer(cred, bearer, sizeof(bearer), cf->log)
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
            /* GSI write-back: the proxy + verify-CA the C-5 dest presents/uses. */
            if (cred->x509_proxy.len > 0) {
                xcf->cache_origin_x509_proxy = cred->x509_proxy;
            }
            if (cred->ca_dir.len > 0) {
                xcf->cache_origin_ca_dir = cred->ca_dir;
            }
        }

        /* Optional fast-cache upload staging device.  Canonicalize once here; an
         * unset/empty value leaves upload_stage_dir_canon empty (stage adjacent
         * to the destination).  A configured-but-bad path fails config loudly. */
        if (xcf->upload_stage_dir.len > 0) {
            xrootd_export_root_opts_t stage_opts;
            stage_opts.directive_name = "xrootd_stage_dir";
            stage_opts.allow_write    = 1;
            stage_opts.required       = 0;
            stage_opts.canon_size     = sizeof(xcf->upload_stage_dir_canon);
            if (xrootd_prepare_export_root(cf, &xcf->upload_stage_dir,
                    &stage_opts, xcf->upload_stage_dir_canon) != NGX_CONF_OK)
            {
                return NGX_ERROR;
            }
            /* Track for the stage-out reaper (finishes interrupted cache->storage
             * commits across restarts). */
            xrootd_stage_dir_register(xcf->upload_stage_dir_canon);
        }

        /* Phase-64: register the composable cache/stage tiers (sd_cache / sd_stage
         * decorators composed over the backend, per worker). */
        if (xrootd_tier_register_stores(cf, &xcf->common) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (xcf->cache) {
        /* The read-through cache is read-only UNLESS write-through is enabled,
         * in which case write handles are accepted and mirrored to the origin
         * at kXR_sync/kXR_close (see src/cache/writethrough_flush.c). */
        if (xcf->common.allow_write && !xcf->wt_enable) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache is read-only and requires "
                "xrootd_allow_write off (or enable xrootd_write_through)");
            return NGX_ERROR;
        }

        /* §14: xrootd_cache_storage_backend is retired — a driver-backed cache
         * is the tier grammar's xrootd_cache_store. */

        /* Write-back staging cache backend (its own root). Same sidecar rule. */
        if (xcf->cache_wt_stage_backend.len > 0) {
            if (xcf->cache_wt_stage_root.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_cache_wt_stage_backend requires "
                    "xrootd_cache_wt_stage_root");
                return NGX_ERROR;
            }
            if (xcf->cache_state_root.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_cache_wt_stage_backend requires a POSIX "
                    "xrootd_cache_state_root for its sidecars");
                return NGX_ERROR;
            }
            xrootd_vfs_backend_config((const char *) xcf->cache_wt_stage_root.data,
                                      &xcf->cache_wt_stage_backend,
                                      xcf->cache_wt_stage_block_size);
        }

        {
            /* C-1 (phase-63): the cache source may be a remote xrootd_storage_backend
             * (root://...) instead of a separate xrootd_cache_origin — the cache then
             * fills from the registered backend (open_or_fill resolves it). */
            ngx_str_t *sb = &xcf->common.storage_backend;
            int remote_source =
                (sb->len > sizeof("root://") - 1
                 && ngx_strncmp(sb->data, "root://", sizeof("root://") - 1) == 0)
                || (sb->len > sizeof("roots://") - 1
                    && ngx_strncmp(sb->data, "roots://",
                                   sizeof("roots://") - 1) == 0)
                || (sb->len > sizeof("http://") - 1
                    && ngx_strncmp(sb->data, "http://",
                                   sizeof("http://") - 1) == 0)
                || (sb->len > sizeof("https://") - 1
                    && ngx_strncmp(sb->data, "https://",
                                   sizeof("https://") - 1) == 0);

            /* §14: the legacy xrootd_cache_origin is retired — an `xrootd_cache
             * on` cache fills from the export's REMOTE storage backend. */
            if (xcf->cache_root.len == 0 || !remote_source) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_cache on requires xrootd_cache_root and a remote "
                    "xrootd_storage_backend (root://host:port); the retired "
                    "xrootd_cache_origin model is the tier grammar now "
                    "(xrootd_storage_backend + xrootd_cache_store)");
                return NGX_ERROR;
            }
        }

        if (xrootd_validate_path(cf, "xrootd_cache_root",
                                 &xcf->cache_root,
                                 XROOTD_PATH_DIRECTORY,
                                 R_OK | W_OK | X_OK)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (xcf->cache_lock_timeout <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache_lock_timeout must be greater than zero");
            return NGX_ERROR;
        }

        if (xcf->cache_eviction_threshold == 0
            || xcf->cache_eviction_threshold >= 1000000)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache_eviction_threshold must be greater than 0 "
                "and less than 1.0");
            return NGX_ERROR;
        }

        /* Watermark reaper ordering: 0 < low < high < 1.0. Defaults already
         * satisfy this; an explicit pair that inverts it is a config error. */
        if (xcf->cache_high_watermark == 0
            || xcf->cache_high_watermark >= 1000000
            || xcf->cache_low_watermark == 0
            || xcf->cache_low_watermark >= xcf->cache_high_watermark)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache_low_watermark must be greater than 0 and less "
                "than xrootd_cache_high_watermark (which must be < 1.0)");
            return NGX_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: cache enabled root=%V origin=%V tls=%s "
            "lock_timeout=%ds eviction_threshold=0.%06ui",
            &xcf->cache_root, &xcf->cache_origin,
            xcf->cache_origin_tls ? "on" : "off",
            (int) xcf->cache_lock_timeout,
            xcf->cache_eviction_threshold);
    }

    /* Write-back-staging backpressure validation. Independent of the read cache —
     * write-through staging exists whenever xrootd_write_through is on, so this
     * runs at the server level. When a HIGH watermark is set it needs a staging
     * root to measure, and the pair must satisfy 0 < low < high < 1.0. */
    if (xcf->cache_wt_stage_high_watermark > 0) {
        if (xcf->cache_wt_stage_root.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_wt_stage_high_watermark requires "
                "xrootd_cache_wt_stage_root");
            return NGX_ERROR;
        }
        if (xcf->cache_wt_stage_high_watermark >= 1000000
            || xcf->cache_wt_stage_low_watermark == 0
            || xcf->cache_wt_stage_low_watermark
                   >= xcf->cache_wt_stage_high_watermark)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_wt_stage_low_watermark must be greater than 0 and "
                "less than xrootd_wt_stage_high_watermark (which must be < 1.0)");
            return NGX_ERROR;
        }
    }

    /*
     * Access log handling mirrors nginx conventions: empty means disabled by
     * default, the literal string "off" suppresses logging explicitly, and
     * any other value is treated as the path to append to.
     */
    if (xcf->access_log.len > 0
        && ngx_strcmp(xcf->access_log.data, (u_char *) "off") != 0)
    {
        /*
         * Register the log with nginx (cycle->open_files) rather than opening a
         * raw fd here.  The master opens it during ngx_init_cycle, reopens it on
         * USR1 (dup2 onto the same fd number), and closes it cleanly when the
         * cycle is torn down — so log rotation and `nginx -s reload` no longer
         * leak fds or keep writing to a rotated inode.  Each worker captures
         * file->fd into access_log_fd in init_process (the fd is not yet open at
         * this config-time point).
         */
        xcf->access_log_file = ngx_conf_open_file(cf->cycle, &xcf->access_log);
        if (xcf->access_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd: cannot register access log \"%V\"",
                &xcf->access_log);
            return NGX_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: access log \"%V\" registered",
            &xcf->access_log);
    }

    if (xcf->proxy_enable
        && xcf->proxy_audit_log.len > 0
        && ngx_strcmp(xcf->proxy_audit_log.data, (u_char *) "off") != 0)
    {
        /* nginx-managed handle; see the access-log note above. */
        xcf->proxy_audit_log_file = ngx_conf_open_file(cf->cycle,
                                                       &xcf->proxy_audit_log);
        if (xcf->proxy_audit_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd: cannot register proxy audit log \"%V\"",
                &xcf->proxy_audit_log);
            return NGX_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: proxy audit log \"%V\" registered",
            &xcf->proxy_audit_log);
    }

#if (NGX_SSL)
    if (xcf->proxy_enable && xcf->proxy_upstream_tls) {
        xcf->proxy_tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (xcf->proxy_tls_ctx == NULL) {
            return NGX_ERROR;
        }
        xcf->proxy_tls_ctx->log = cf->log;
        if (ngx_ssl_create(xcf->proxy_tls_ctx,
                           NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3,
                           NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }

        /* Peer certificate verification (optional; enabled by directive). */
        if (xcf->proxy_upstream_tls_ca.len > 0) {
            if (ngx_ssl_trusted_certificate(cf, xcf->proxy_tls_ctx,
                                             &xcf->proxy_upstream_tls_ca,
                                             5 /* chain depth */)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            /* ngx_ssl_trusted_certificate sets SSL_VERIFY_PEER internally */
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd: proxy upstream TLS CA loaded from \"%V\"",
                &xcf->proxy_upstream_tls_ca);
        }
    }

    /* Upstream redirector TLS (for mid-stream kXR_gotoTLS upgrade). */
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
                                             5 /* chain depth */)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd: upstream redirector TLS CA loaded from \"%V\"",
                &xcf->upstream_tls_ca);
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: upstream redirector TLS enabled (kXR_gotoTLS support)");
    }
#endif

    return NGX_OK;
}
