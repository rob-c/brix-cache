/*
 * shared_conf.h — Shared config preamble struct for nginx-xrootd protocols.
 */

#ifndef NGX_HTTP_BRIX_SHARED_CONF_H
#define NGX_HTTP_BRIX_SHARED_CONF_H

#include <ngx_thread_pool.h>

#include <regex.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "observability/pmark/pmark.h"

/* Default per-user credential store: a RAM-backed (tmpfs) directory, so
 * delegated private keys never persist across a reboot, never land in
 * backups/snapshots, and leave no blocks on real disk. /dev/shm is mounted
 * on effectively every Linux system, so no operator setup is required —
 * the directory itself is created 0700 at config time (see
 * brix_shared_credential_dir_ensure below). Opt out with an explicit
 * `brix_storage_credential_dir "";`. */
#define BRIX_CREDENTIAL_DIR_DEFAULT  "/dev/shm/brix-creds"

#include "shared_conf_types.h"

/*
 * ngx_http_brix_shared_create_loc_conf() — Allocates and initializes a shared
 * preamble struct with NGX_CONF_UNSET sentinel values. Called by each protocol's
 * create_loc_conf function to set the shared fields before returning its own
 * full config struct.
 *
 * WHY: nginx merge macros detect NGX_CONF_UNSET to know which value is unset;
 * every protocol must initialize shared fields this way so parent→child merge
 * works correctly regardless of whether enable/root/allow_write appear in main,
 * server, or location blocks.
 */
static inline void
ngx_http_brix_shared_init(ngx_http_brix_shared_conf_t *conf)
{
    conf->enable             = NGX_CONF_UNSET;
    conf->allow_write        = NGX_CONF_UNSET;
    conf->verify_write       = NGX_CONF_UNSET;
    conf->require_pgwrite    = NGX_CONF_UNSET;
    conf->read_only          = NGX_CONF_UNSET;
    conf->compress           = NGX_CONF_UNSET;
    conf->strict_security    = NGX_CONF_UNSET;
    conf->access_log.len     = 0;
    conf->access_log.data    = NULL;
    conf->access_log_file    = NULL;
    conf->session_log        = NGX_CONF_UNSET;
    conf->ktls               = NGX_CONF_UNSET;
    conf->cache_store_endpoint = NGX_CONF_UNSET;
    conf->storage_staging    = NGX_CONF_UNSET;
    conf->cache_verify_mode  = NGX_CONF_UNSET_UINT;
    conf->thread_pool_name.len  = 0;
    conf->thread_pool_name.data = NULL;
    conf->thread_pool        = NULL;
    conf->storage_backend.len   = 0;
    conf->storage_backend.data  = NULL;
    conf->storage_credential.len  = 0;
    conf->storage_credential.data = NULL;
    conf->storage_credential_dir.len   = 0;
    conf->storage_credential_dir.data  = NULL;
    conf->storage_credential_fallback  = NGX_CONF_UNSET_UINT;
    conf->storage_credential_mint_ca_cert.len   = 0;
    conf->storage_credential_mint_ca_cert.data  = NULL;
    conf->storage_credential_mint_ca_key.len    = 0;
    conf->storage_credential_mint_ca_key.data   = NULL;
    conf->storage_credential_mint_ttl  = NGX_CONF_UNSET_UINT;
    conf->backend_delegation = NGX_CONF_UNSET_UINT;
    conf->backend_token_aud  = NGX_CONF_UNSET_PTR;
    conf->backend_tx_endpoint.len       = 0;
    conf->backend_tx_endpoint.data      = NULL;
    conf->backend_tx_client_id.len      = 0;
    conf->backend_tx_client_id.data     = NULL;
    conf->backend_tx_client_secret.len  = 0;
    conf->backend_tx_client_secret.data = NULL;
    conf->backend_sts_endpoint.len      = 0;
    conf->backend_sts_endpoint.data     = NULL;
    conf->backend_sts_role.len          = 0;
    conf->backend_sts_role.data         = NULL;
    conf->backend_krb5_forwardable      = NGX_CONF_UNSET;
    conf->backend_passthrough_persist   = NGX_CONF_UNSET;
    conf->pblock_block_size  = NGX_CONF_UNSET_SIZE;
    conf->storage_instance   = NULL;   /* built per worker at init_process */
    conf->cache_store.len    = 0;
    conf->cache_store.data   = NULL;
    conf->cache_store_args   = NULL;
    conf->cache_cold_store.len  = 0;
    conf->cache_cold_store.data = NULL;
    conf->cache_cold_store_args = NULL;
    conf->cache_peers        = NULL;
    conf->stage_enable       = NGX_CONF_UNSET;
    conf->stage_store.len    = 0;
    conf->stage_store.data   = NULL;
    conf->stage_store_args   = NULL;
    conf->stage_flush_async  = NGX_CONF_UNSET_UINT;
    conf->backend_async      = NGX_CONF_UNSET;
    conf->backend_async_batch = NGX_CONF_UNSET_UINT;
    conf->backend_async_wait = NGX_CONF_UNSET_MSEC;
    conf->cache_max_object   = NGX_CONF_UNSET;
    conf->cache_evict_at     = NGX_CONF_UNSET_UINT;
    conf->cache_evict_to     = NGX_CONF_UNSET_UINT;
    conf->cache_meta_mode    = NGX_CONF_UNSET_UINT;
    conf->cache_batch_cinfo  = NGX_CONF_UNSET_UINT;
    conf->cache_index_cache  = NGX_CONF_UNSET_SIZE;
    conf->cache_slice_size   = NGX_CONF_UNSET_SIZE;
    conf->rootfd             = -1;   /* opened per worker at init_process */
    /* root_canon zeroed by ngx_pcalloc — no explicit memset needed */
    brix_pmark_conf_init(&conf->pmark);
}

/*
 * brix_shared_apply_read_only() — enforce the hard read-only switch. When
 * common->read_only is on, force allow_write off so EVERY existing write gate
 * (root:// brix_dispatch_require_write, the WebDAV/S3 write-method gate, the
 * write-open gate) rejects writes at the protocol edge - before the VFS, and
 * before token scope (allow_write is checked first), so a write-scoped token
 * cannot bypass it. ngx_http_brix_shared_merge() applies it after the
 * allow_write/read_only merges so no protocol can forget the enforcement;
 * callers with later allow_write-dependent validations (e.g. WebDAV's
 * "writes need auth" check) simply run them after the shared merge.
 */
static inline void
brix_shared_apply_read_only(ngx_http_brix_shared_conf_t *common,
    ngx_log_t *log)
{
    if (common->read_only != 1) {
        return;
    }
    if (common->allow_write == 1 && log != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: read_only on - the export is read-only; all write "
            "operations are rejected at the protocol edge (overrides allow_write)");
    }
    common->allow_write = 0;
}

/*
 * brix_shared_credential_dir_ensure() — Config-time guarantee for
 * brix_storage_credential_dir: create the directory 0700 (chown'd to the
 * worker user when the master runs as root) if it is missing, and shout —
 * NGX_LOG_WARN at parse time — when it cannot be created, is not a
 * directory, is group/other-accessible, or is owned by a user the workers
 * do not run as.
 *
 * WHY: The store holds delegated PRIVATE KEYS, and the default lives on
 * tmpfs (/dev/shm) precisely so nothing persists across reboots or lands in
 * backups — but /dev/shm is world-writable (1777), so the entire security
 * boundary is this directory's 0700 mode + ownership, which must therefore
 * be enforced here rather than left to operator setup. A broken or
 * foreign-owned path must NOT kill startup (the store may be unused, and
 * fallback=allow keeps requests on the service credential), but the admin
 * must be told that credential delegation will not work until it is fixed.
 *
 * HOW: stat(); on ENOENT mkdir(0700) + chown to ccf->user when euid==0
 * (mirroring ngx_create_paths). Every failure and every unsafe pre-existing
 * state warns via ngx_conf_log_error and returns — never fatal. Called from
 * every shared merge (per server/location), so a broken path is shouted per
 * context; the healthy path prints nothing and costs one stat().
 */
/* Resolved POST-de-escalation worker identity (defined in
 * src/auth/impersonate/lifecycle_worker.c; contract in lifecycle.h). Workers
 * are force-dropped to brix_worker_user/nobody when root-capable, so dirs
 * provisioned for them must be owned by THAT identity, not raw ccf->user. */
ngx_int_t brix_imp_worker_runtime_ids(ngx_uid_t conf_uid, ngx_gid_t conf_gid,
    uid_t *uid_out, gid_t *gid_out);

/* The uid/gid worker-writable provisioned dirs must be handed to: the runtime
 * worker identity when the master runs as root, else the invoking user. */
static inline void
brix_shared_worker_dir_ids(ngx_conf_t *cf, uid_t *uid_out, gid_t *gid_out)
{
    ngx_core_conf_t *ccf = (ngx_core_conf_t *)
                               ngx_get_conf(cf->cycle->conf_ctx, ngx_core_module);

    *uid_out = geteuid();
    *gid_out = (gid_t) -1;
    if (geteuid() == 0) {
        (void) brix_imp_worker_runtime_ids(
            (ccf != NULL) ? ccf->user  : (ngx_uid_t) NGX_CONF_UNSET_UINT,
            (ccf != NULL) ? (ngx_gid_t) ccf->group
                          : (ngx_gid_t) NGX_CONF_UNSET_UINT,
            uid_out, gid_out);      /* on failure the invoking-root ids stay */
    }
}

static inline void
brix_shared_credential_dir_ensure(ngx_conf_t *cf, const ngx_str_t *dir)
{
    struct stat       st;
    const char       *path;
    uid_t             want_uid;
    gid_t             want_gid;

    if (dir == NULL || dir->len == 0) {
        return;                 /* explicit "" = per-user store disabled */
    }

    path = (const char *) dir->data;    /* conf tokens are NUL-terminated */
    brix_shared_worker_dir_ids(cf, &want_uid, &want_gid);

    if (stat(path, &st) != 0) {
        if (errno != ENOENT) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: credential store \"%s\" is not accessible — "
                "credential delegation will not work until "
                "brix_storage_credential_dir is fixed", path);
            return;
        }

        if (mkdir(path, 0700) != 0 && errno != EEXIST) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: cannot create credential store \"%s\" — "
                "credential delegation will not work until "
                "brix_storage_credential_dir is fixed", path);
            return;
        }

        if (stat(path, &st) != 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: credential store \"%s\" vanished after create — "
                "credential delegation will not work", path);
            return;
        }

        /* The master parses config as root but the workers write the store
         * as the RUNTIME worker identity (the `user` account, or the
         * de-escalation target for a root-capable worker) — hand the fresh
         * directory to them, as ngx_create_paths does for the temp paths. */
        if (geteuid() == 0 && st.st_uid != want_uid
            && chown(path, want_uid, want_gid) != 0)
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, errno,
                "brix: cannot chown credential store \"%s\" to the worker "
                "user — credential delegation will not work", path);
        }
        return;
    }

    if (!S_ISDIR(st.st_mode)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: credential store \"%s\" is not a directory — "
            "credential delegation will not work until "
            "brix_storage_credential_dir is fixed", path);
        return;
    }

    if ((st.st_mode & 0077) != 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: credential store \"%s\" is group/other-accessible "
            "(mode %04uo) — delegated private keys may be exposed; "
            "chmod 0700", path, (ngx_uint_t) (st.st_mode & 07777));
    }

    if (st.st_uid != want_uid) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: credential store \"%s\" is owned by uid %ud but the "
            "workers run as uid %ud — credential delegation will not work "
            "until ownership or brix_storage_credential_dir is fixed",
            path, (ngx_uint_t) st.st_uid, (ngx_uint_t) want_uid);
    }
}

/*
 * brix_shared_security_gate() — E-1: a valid-but-dangerous config setting is
 * loud at load and refused under strict mode.
 *
 * WHY: several configurations parse cleanly yet leave the export wide open —
 * anonymous S3 (no SigV4/token verification), WebDAV writes with auth optional,
 * an anonymous dashboard. Each is a legitimate choice for a closed lab and a
 * foot-gun in production, so the default must be loud (an operator who never
 * reads the config still sees the warning in the error log at every reload),
 * and a site that wants the guarantee flips `brix_strict_security on` to turn
 * every such setting into a hard `nginx -t` failure — fail-closed, opt-in.
 *
 * HOW: emit NGX_LOG_WARN (default) or NGX_LOG_EMERG (strict) naming the insecure
 * setting `what` and the directive `remedy` that closes it. Return NGX_OK when
 * the merge may proceed (warn-only) and NGX_ERROR when strict mode requires the
 * caller to return NGX_CONF_ERROR. The caller owns the return so the diagnostic
 * points at the offending location's own merge.
 */
static inline ngx_int_t
brix_shared_security_gate(ngx_conf_t *cf, ngx_flag_t strict,
    const char *what, const char *remedy)
{
    ngx_conf_log_error(strict ? NGX_LOG_EMERG : NGX_LOG_WARN, cf, 0,
        "brix: insecure configuration — %s; set %s to close it%s",
        what, remedy,
        strict ? " (refused: brix_strict_security on)" : "");
    return strict ? NGX_ERROR : NGX_OK;
}

/*
 * ngx_http_brix_shared_merge() — Merges shared preamble fields from parent to
 * child using standard nginx merge macros. Called at the top of each protocol's
 * merge_loc_conf function before protocol-specific merge logic runs.
 *
 * WHY: This is the SINGLE audit point for common.* config inheritance — every
 * HTTP protocol (WebDAV, S3, cvmfs) calls it instead of hand-merging the same
 * ~20 fields (which drifted per protocol and dropped the read-only enforcement
 * in cvmfs). Defaults: enable=0, allow_write=0, compress=0, ktls=1,
 * thread_pool_name="", storage_credential_dir=BRIX_CREDENTIAL_DIR_DEFAULT
 * (tmpfs store, ensured 0700 by brix_shared_credential_dir_ensure above),
 * tier grammar defaults as before.
 *
 * HOW: root_default parameterizes the one deliberate per-protocol difference
 * (WebDAV exports default to "/", S3/cvmfs to ""). Ends by applying the hard
 * read-only switch (see brix_shared_apply_read_only above) and merging pmark;
 * returns NGX_CONF_OK or NGX_CONF_ERROR (pmark merge failure).
 */
static inline char *
ngx_http_brix_shared_merge(ngx_conf_t *cf,
                             ngx_http_brix_shared_conf_t *prev,
                             ngx_http_brix_shared_conf_t *conf,
                             const char *root_default)
{
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    /* root_default is a runtime const char* parameter, not a string literal;
     * ngx_conf_merge_str_value computes sizeof(default)-1, which yields the
     * pointer width (7 on 64-bit) rather than the actual string length — the
     * empty-string default used by s3/cvmfs became {len:7,data:""}, so the
     * pure-cache-node root.len==0 → "/" fallback never fired.  Hand-roll. */
    if (conf->root.data == NULL) {
        if (prev->root.data != NULL) {
            conf->root = prev->root;
        } else {
            conf->root.data = (u_char *) root_default;
            conf->root.len = ngx_strlen(root_default);
        }
    }
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_value(conf->verify_write, prev->verify_write, 0);
    ngx_conf_merge_value(conf->require_pgwrite, prev->require_pgwrite, 0);
    ngx_conf_merge_value(conf->read_only, prev->read_only, 0);
    ngx_conf_merge_value(conf->compress, prev->compress, 0);
    ngx_conf_merge_value(conf->strict_security, prev->strict_security, 0);
    ngx_conf_merge_str_value(conf->access_log, prev->access_log, "");
    if (conf->access_log.len > 0
        && ngx_strcmp(conf->access_log.data, (u_char *) "off") != 0)
    {
        conf->access_log_file = ngx_conf_open_file(cf->cycle,
                                                   &conf->access_log);
        if (conf->access_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: cannot register HTTP access log \"%V\"",
                &conf->access_log);
            return NGX_CONF_ERROR;
        }
    } else {
        conf->access_log_file = NULL;
    }
    ngx_conf_merge_value(conf->session_log, prev->session_log, 1);
    ngx_conf_merge_value(conf->ktls, prev->ktls, 1);   /* default ON (offload-gated) */
    /* Trusted cache-store surface: default OFF everywhere, so the reserved-name
     * 404 guard stays in force on every normal client location (default-deny). */
    ngx_conf_merge_value(conf->cache_store_endpoint,
                         prev->cache_store_endpoint, 0);
    ngx_conf_merge_value(conf->storage_staging, prev->storage_staging, 0);
    ngx_conf_merge_str_value(conf->thread_pool_name, prev->thread_pool_name, "");
    ngx_conf_merge_str_value(conf->storage_backend, prev->storage_backend, "");
    ngx_conf_merge_str_value(conf->storage_credential, prev->storage_credential,
                             "");
    /* Defaults to a RAM-backed (tmpfs) store so delegated keys never touch
     * real disk; behaviour-neutral for non-delegated deployments because a
     * lookup miss with fallback=allow (the default) lands on the service
     * credential exactly like an unset dir. `""` opts out entirely. */
    ngx_conf_merge_str_value(conf->storage_credential_dir,
                             prev->storage_credential_dir,
                             BRIX_CREDENTIAL_DIR_DEFAULT);
    brix_shared_credential_dir_ensure(cf, &conf->storage_credential_dir);
    ngx_conf_merge_uint_value(conf->storage_credential_fallback,
                              prev->storage_credential_fallback, 0);
    ngx_conf_merge_str_value(conf->storage_credential_mint_ca_cert,
                             prev->storage_credential_mint_ca_cert, "");
    ngx_conf_merge_str_value(conf->storage_credential_mint_ca_key,
                             prev->storage_credential_mint_ca_key, "");
    ngx_conf_merge_uint_value(conf->storage_credential_mint_ttl,
                              prev->storage_credential_mint_ttl, 3600);
    ngx_conf_merge_uint_value(conf->backend_delegation,
                              prev->backend_delegation, 0);  /* SELECT */
    ngx_conf_merge_ptr_value(conf->backend_token_aud,
                             prev->backend_token_aud, NULL);
    ngx_conf_merge_str_value(conf->backend_tx_endpoint,
                             prev->backend_tx_endpoint, "");
    ngx_conf_merge_str_value(conf->backend_tx_client_id,
                             prev->backend_tx_client_id, "");
    ngx_conf_merge_str_value(conf->backend_tx_client_secret,
                             prev->backend_tx_client_secret, "");
    ngx_conf_merge_str_value(conf->backend_sts_endpoint,
                             prev->backend_sts_endpoint, "");
    ngx_conf_merge_str_value(conf->backend_sts_role,
                             prev->backend_sts_role, "");
    ngx_conf_merge_value(conf->backend_krb5_forwardable,
                         prev->backend_krb5_forwardable, 0);
    ngx_conf_merge_value(conf->backend_passthrough_persist,
                         prev->backend_passthrough_persist, 0);
    ngx_conf_merge_size_value(conf->pblock_block_size, prev->pblock_block_size,
                              0);

    /* phase-64 tier grammar */
    ngx_conf_merge_str_value(conf->cache_store, prev->cache_store, "");
    if (conf->cache_store_args == NULL) {
        conf->cache_store_args = prev->cache_store_args;
    }
    ngx_conf_merge_str_value(conf->cache_cold_store, prev->cache_cold_store, "");
    if (conf->cache_cold_store_args == NULL) {
        conf->cache_cold_store_args = prev->cache_cold_store_args;
    }
    if (conf->cache_peers == NULL) {
        conf->cache_peers = prev->cache_peers;
    }
    /* stage_enable keeps UNSET through the merge: brix_tier_register_stores
     * must tell "never configured" (may auto-provision the default gateway
     * stage store under /tmp/staging) apart from an explicit "brix_stage off"
     * opt-out. Its only reader tests == 1, so UNSET still means off. */
    ngx_conf_merge_value(conf->stage_enable, prev->stage_enable, NGX_CONF_UNSET);
    ngx_conf_merge_str_value(conf->stage_store, prev->stage_store, "");
    if (conf->stage_store_args == NULL) {
        conf->stage_store_args = prev->stage_store_args;
    }
    ngx_conf_merge_uint_value(conf->stage_flush_async, prev->stage_flush_async, 0);
    /* Durable async backend-op queue: default OFF (mutations run inline). When on,
     * batch defaults to 64 ops (min 1) and the time backstop to 200ms. */
    ngx_conf_merge_value(conf->backend_async, prev->backend_async, 0);
    ngx_conf_merge_uint_value(conf->backend_async_batch,
                              prev->backend_async_batch, 64);
    if (conf->backend_async_batch < 1) {
        conf->backend_async_batch = 1;
    }
    ngx_conf_merge_msec_value(conf->backend_async_wait,
                              prev->backend_async_wait, 200);
    ngx_conf_merge_off_value(conf->cache_max_object, prev->cache_max_object, 0);
    /* evict_at/evict_to stay UNSET through the merge (inherit-only): the
     * stream reaper merge must tell an explicit percent pair (which seeds the
     * watermark reaper) apart from the documented 90/80 defaults — those are
     * normalised into the tier policy at brix_tier_register_cache_store. */
    ngx_conf_merge_uint_value(conf->cache_evict_at, prev->cache_evict_at,
                              NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->cache_evict_to, prev->cache_evict_to,
                              NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->cache_meta_mode, prev->cache_meta_mode, 0);
    ngx_conf_merge_uint_value(conf->cache_batch_cinfo, prev->cache_batch_cinfo, 2);
    ngx_conf_merge_size_value(conf->cache_index_cache, prev->cache_index_cache, 0);
    ngx_conf_merge_size_value(conf->cache_slice_size, prev->cache_slice_size, 0);
    /* 0 == BRIX_CACHE_VERIFY_OFF (fs/cache/verify.h; not included here — it
     * drags stream-typed cache internals into every HTTP module conf). */
    ngx_conf_merge_uint_value(conf->cache_verify_mode, prev->cache_verify_mode,
                              0);

    /* Hard read-only: force allow_write off HERE so no protocol merge can
     * forget the enforcement (it must win before token-scope checks). */
    brix_shared_apply_read_only(conf, cf->log);

    return brix_pmark_conf_merge(cf, &prev->pmark, &conf->pmark);
}

static inline ngx_fd_t
brix_http_shared_access_log_fd(const ngx_http_brix_shared_conf_t *conf)
{
    if (conf == NULL || conf->access_log_file == NULL) {
        return NGX_INVALID_FILE;
    }

    return conf->access_log_file->fd;
}

/*
 * brix_tier_register_stores() — register the export's phase-64 composable
 * cache/stage tiers from the common preamble onto the backend registry (which
 * composes the sd_cache / sd_stage decorators per worker). Shared by all three
 * protocol finalisers (§4.4): each calls it with its &conf->common after the
 * storage backend + root_canon are set. Returns NGX_OK, or NGX_ERROR after an
 * [emerg] for an operator error (unknown scheme, bad path, stage-without-store).
 * Defined in config/runtime_server.c.
 */
ngx_int_t brix_tier_register_stores(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common);

/* Rewrite a "posix:<path>" / "pblock://<path>" storage_backend into the export root
 * (common->root) — the composable replacement for brix_root. No-op otherwise.
 * Call BEFORE the export-root prep. Defined in config/runtime_server.c. */
void brix_storage_backend_posix_root(ngx_http_brix_shared_conf_t *common);

/* 1 iff the storage backend is remote (root://, http(s)://, s3://, tape://, ceph):
 * the local root_canon is a namespace anchor only and must not require W_OK. */
int brix_storage_backend_is_remote(const ngx_http_brix_shared_conf_t *common);

/*
 * brix_conf_set_store_slot() — directive setter for a tier store-URL directive
 * (brix_{,webdav_,s3_}{cache,stage}_store). Stores arg[1] (the store URL) into
 * the ngx_str_t at cmd->offset, and any trailing "credential=<n>" / "block_size=<n>"
 * tokens (args[2..]) into the ngx_array_t* whose field offset is carried in
 * cmd->post. The finaliser passes that array to brix_tier_parse_store. Use with
 * NGX_CONF_TAKE1234. Defined in config/runtime_server.c.
 */
char *brix_conf_set_store_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#endif /* NGX_HTTP_BRIX_SHARED_CONF_H */
