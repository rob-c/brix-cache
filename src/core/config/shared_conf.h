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
#include "auth/crypto/store_policy.h"   /* BRIX_SP_MODE_* / BRIX_CRL_MODE_* (W4 x509 merge defaults) */
#include "core/types/tunables.h"        /* BRIX_TOKEN_CLOCK_SKEW_SECS (W4 token merge) */

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
    conf->durable_commit     = NGX_CONF_UNSET;
    conf->verify_write       = NGX_CONF_UNSET;
    conf->require_pgwrite    = NGX_CONF_UNSET;
    conf->data_substreams    = NGX_CONF_UNSET;
    conf->read_only          = NGX_CONF_UNSET;
    conf->read_only_public   = NGX_CONF_UNSET;
    conf->compress           = NGX_CONF_UNSET;
    conf->strict_security    = NGX_CONF_UNSET;
    conf->tls_require        = NGX_CONF_UNSET_UINT;
    conf->access_log.len     = 0;
    conf->access_log.data    = NULL;
    conf->access_log_file    = NULL;
    conf->session_log        = NGX_CONF_UNSET;
    conf->ktls               = NGX_CONF_UNSET;
    conf->cache_store_endpoint = NGX_CONF_UNSET;
    conf->storage_staging    = NGX_CONF_UNSET;
    conf->cache_verify_mode  = NGX_CONF_UNSET_UINT;
    conf->cache_global_cas   = NGX_CONF_UNSET;
    conf->cache_passthrough  = NGX_CONF_UNSET;
    conf->cache_passthrough_max = NGX_CONF_UNSET;
    conf->cache_only_if_cached = NGX_CONF_UNSET;
    conf->cache_uvkeep       = NGX_CONF_UNSET;
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
    conf->storage_credential_mint_ttl  = NGX_CONF_UNSET;   /* time_t/sec_slot (W7) */
    conf->backend_delegation = NGX_CONF_UNSET_UINT;
    conf->backend_token_aud  = NGX_CONF_UNSET_PTR;
    conf->backend_tx_endpoint.len       = 0;
    conf->backend_tx_endpoint.data      = NULL;
    conf->backend_tx_client_id.len      = 0;
    conf->backend_tx_client_id.data     = NULL;
    conf->backend_tx_client_secret.len  = 0;
    conf->backend_tx_client_secret.data = NULL;
    conf->backend_tx_cache              = NULL;   /* lazily created per worker */
    conf->backend_sts_endpoint.len      = 0;
    conf->backend_sts_endpoint.data     = NULL;
    conf->backend_sts_role.len          = 0;
    conf->backend_sts_role.data         = NULL;
    conf->backend_sts_access_key.len    = 0;
    conf->backend_sts_access_key.data   = NULL;
    conf->backend_sts_secret_key.len    = 0;
    conf->backend_sts_secret_key.data   = NULL;
    conf->backend_sts_region.len        = 0;
    conf->backend_sts_region.data       = NULL;
    conf->backend_sts_ttl               = NGX_CONF_UNSET;
    conf->backend_sts_flavor            = NGX_CONF_UNSET_UINT;
    conf->backend_krb5_forwardable      = NGX_CONF_UNSET;
    conf->backend_passthrough_persist   = NGX_CONF_UNSET;
    conf->backend_sss_keytab.len        = 0;
    conf->backend_sss_keytab.data       = NULL;
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
    conf->cache_prefetch     = NGX_CONF_UNSET;
    conf->cache_prefetch_window = NGX_CONF_UNSET_SIZE;
    conf->vfs_spill_max      = NGX_CONF_UNSET_SIZE;   /* phase-107 C1 */
    conf->durable_publish    = NGX_CONF_UNSET;        /* phase-107 C3 */
    conf->lock_enforcement   = NGX_CONF_UNSET_UINT;   /* phase-107 C7 */
    conf->rootfd             = -1;   /* opened per worker at init_process */
    /* root_canon zeroed by ngx_pcalloc — no explicit memset needed */
    brix_pmark_conf_init(&conf->pmark);
    brix_acc_http_init_conf(&conf->acc);   /* phase-101 W2: XrdAcc in the preamble */
    conf->zip_access       = NGX_CONF_UNSET;        /* phase-101 W4 */
    conf->zip_cd_max_bytes = NGX_CONF_UNSET_SIZE;
    conf->upload_resume    = NGX_CONF_UNSET;        /* phase-101 W4 */
    conf->signing_policy_mode = NGX_CONF_UNSET_UINT; /* phase-101 W4 */
    conf->crl_mode           = NGX_CONF_UNSET_UINT;  /* phase-101 W4 */
    conf->token_clock_skew   = NGX_CONF_UNSET;       /* phase-101 W4 */
    conf->vo_rules           = NULL;  /* phase-101 W4: lazily created by the
                                       * brix_require_vo setter; NULL-inherit at
                                       * merge, like cache_store_args/cache_peers. */
    conf->authdb_rules       = NULL;  /* phase-101 W5.2: lazily created by the
                                       * brix_authdb setter; NULL-inherit at merge. */
    conf->protbind           = NULL;  /* phase-101 W4: brix_protbind array; NULL =
                                       * no rules, inherited whole at merge. */
    conf->tpc_allow_local        = NGX_CONF_UNSET;  /* phase-101 W4 (HTTP-TPC SSRF) */
    conf->tpc_allow_private      = NGX_CONF_UNSET;
    conf->tpc_source_guard       = NGX_CONF_UNSET;
    conf->tpc_source_allow       = NULL;
    conf->tpc_require_source_size = NGX_CONF_UNSET;

    /* phase-105 W2/W3/W3.5/W4.1 scalars.  Every field a stock ngx_conf_set_*
     * slot setter writes MUST start at its UNSET sentinel: pcalloc's 0 both
     * makes the first directive use fail as "duplicate" and defeats the merge
     * defaults (introspect 30s/fail-open, verify_depth 10, mirror sample 100). */
    conf->introspect_ttl       = NGX_CONF_UNSET;
    conf->introspect_fail_open = NGX_CONF_UNSET;
    conf->verify_depth         = NGX_CONF_UNSET_UINT;
    conf->delegation_endpoint  = NGX_CONF_UNSET;
    conf->max_delay            = NGX_CONF_UNSET;
    brix_mirror_conf_init(&conf->mirror);
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
    /*
     * brix_read_only_public is the STRICTER posture, so it implies the weaker
     * one: turning read_only on here (rather than only gating queries) means an
     * operator cannot get the introspection restrictions while leaving the
     * export writable, and means every existing write gate keyed on allow_write
     * covers a public gateway without knowing the directive exists.
     */
    if (common->read_only_public == 1 && common->read_only != 1) {
        common->read_only = 1;
        if (log != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "brix: read_only_public on - implies read_only; the export is "
                "read-only and server-introspection queries are refused");
        }
    }

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

#include "shared_conf_creddir.h"


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

/* ngx_http_brix_shared_merge() and its per-family helpers live in
 * shared_conf_merge.h (phase-103 header split).  Included HERE — at the
 * point the old inline function sat — so every name it needs (the conf
 * struct, brix_shared_apply_read_only, brix_shared_credential_dir_ensure)
 * is already visible and every existing includer keeps working unchanged.
 * (A 2026-08 merge had left the pre-split copy in place while nothing
 * included the split file, so the phase-105 W2/W3.5 net-family defaults —
 * verify_depth/introspect/mirror/max_delay/trusted_ca/rate-limit — never
 * ran on any HTTP plane.) */
#include "shared_conf_merge.h"

static inline ngx_fd_t
brix_http_shared_access_log_fd(const ngx_http_brix_shared_conf_t *conf)
{
    if (conf == NULL || conf->access_log_file == NULL) {
        return NGX_INVALID_FILE;
    }

    return conf->access_log_file->fd;
}

/*
 * brix_shared_thread_pool() — resolve the async-I/O thread pool for a merged
 * common loc-conf, lazily and idempotently.
 *
 * WHY: postconfig only wires common.thread_pool for a *server-level* enabled
 * loc-conf (webdav_postconf_setup_thread_pool walks cscf->ctx->loc_conf). A
 * protocol enabled per-`location` (the common production shape for WebDAV TPC
 * and PUT) leaves common.thread_pool NULL, so any path that only NULL-checks it
 * falls back to a synchronous, event-loop-blocking transfer regardless of how
 * many workers are configured. Resolving by name at first use — the pool is
 * fully initialized by the time any request runs — closes that gap for every
 * offload site with one shared helper (previously copy/paste'd into move.c,
 * copy_collection.c, open_or_fill.c, http_serve_offload.c, http_cache_fill.c).
 *
 * HOW: returns the cached handle if already resolved; else looks it up by the
 * configured name (default "default"), caches a hit back onto common, and
 * returns it. NULL means no such pool exists — the caller must run synchronously.
 */
static inline ngx_thread_pool_t *
brix_shared_thread_pool(ngx_http_brix_shared_conf_t *common)
{
    ngx_thread_pool_t *pool;

    if (common == NULL) {
        return NULL;
    }

    pool = common->thread_pool;
    if (pool == NULL) {
        static ngx_str_t default_name = ngx_string("default");
        ngx_str_t *pname = common->thread_pool_name.len > 0
                           ? &common->thread_pool_name : &default_name;
        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
        if (pool != NULL) {
            common->thread_pool = pool;
        }
    }

    return pool;
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
