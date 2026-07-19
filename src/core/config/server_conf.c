/*
 * server_conf.c — server-block config lifecycle: allocate, merge, enable.
 *
 * create_srv_conf() allocates one srv_conf per server block with every field at
 * an NGX_CONF_UNSET sentinel (or NULL), so the merge step can tell an omitted
 * directive from one explicitly set. merge_srv_conf() applies nginx parent→child
 * inheritance (ngx_conf_merge_* for scalars, brix_merge_arrays() for the
 * VO/group/manager-map rule sets); it is a flat orchestrator that delegates each
 * configuration area to a per-area entry point. enable() handles
 * "xrootd on|off;", swapping in our session handler when on.
 *
 * Phase-79 file-size split: the per-area MERGE helpers were moved into three
 * focused sibling files, keeping this file under the 500-line cap. The five
 * area entry points the orchestrator calls are declared in
 * server_conf_internal.h and defined in:
 *   server_conf_merge_security.c   — identity/crypto + storage-plane merges
 *   server_conf_merge_cluster.c    — TPC + cluster/session merges
 *   server_conf_merge_proxy_net.c  — upstream/proxy + network-fault merge
 * The create-side per-area initialisers stay here, beside the creator they serve.
 */

#include "config.h"
#include "server_conf_internal.h"       /* per-area merge entry points */
#include "auth/crypto/store_policy.h"   /* BRIX_SP_MODE_*, BRIX_CRL_MODE_* defaults */
#include "core/compat/af_policy.h"      /* BRIX_AF_AUTO default for origin family */
#include "fs/cache/verify.h"          /* brix_cache_verify_mode_e default */
#include "net/ratelimit/ratelimit.h"   /* phase-59 W3a: throttle zone lookup */
#include "net/cms/cns.h"               /* §6 CNS mode enum */
#include "tpc/engine/key_registry.h"
#include "tpc/common/registry.h"   /* Phase 39 (WS5): registry reaper max-age */
#include "protocols/root/session/registry.h"   /* BRIX_SESSION_REGISTRY_SLOTS default */
#include "net/manager/health_check.h" /* BRIX_HC_TYPE_PING default */
#include "net/manager/registry.h"     /* Phase 39 (WS7): srv staleness setter */

/*
 * WHAT: initialise the identity + crypto fields (auth scheme, GSI/pwd, XrdAcc,
 *       CSI, FRM prep, X.509 material + CRL, session/access logging).
 * WHY:  keeps the create_srv_conf orchestrator short; each concern group is a
 *       single-purpose initialiser so the "unset vs configured" contract for
 *       these fields is reviewable in isolation.
 * HOW:  assigns each merge-participating scalar its NGX_CONF_UNSET* sentinel and
 *       leaves runtime-only objects NULL/invalid (pcalloc already zeroed them).
 */
static void
brix_create_srv_security(ngx_stream_brix_srv_conf_t *conf)
{
    conf->auth         = NGX_CONF_UNSET_UINT;

    /* XrdAcc engine (acc_tables / acc_timer / acc_nisdomain stay NULL/zero). */
    brix_acc_conf_init(&conf->acc);
    brix_csi_conf_init(&conf->csi);
    conf->throttle.max_open_files  = NGX_CONF_UNSET_UINT;
    conf->throttle.max_active_conn = NGX_CONF_UNSET_UINT;
    conf->prepare_command.len  = 0;
    conf->prepare_command.data = NULL;
    brix_frm_conf_init(&conf->frm);   /* Phase 35: FRM tape staging */
    conf->crl_reload   = NGX_CONF_UNSET;
    conf->gsi_cert     = NULL;
    conf->gsi_key      = NULL;
    conf->gsi_store    = NULL;
    conf->gsi_cert_pem = NULL;
    conf->gsi_cert_pem_len = 0;
    conf->gsi_ca_hashes[0] = '\0';
    conf->gsi_signed_dh = NGX_CONF_UNSET_UINT;
    conf->signing_policy_mode = NGX_CONF_UNSET_UINT;
    conf->crl_mode     = NGX_CONF_UNSET_UINT;
    conf->gsi_max_inflight = NGX_CONF_UNSET;
    conf->vo_rules     = NULL;
    conf->group_rules  = NULL;
    conf->session_log  = NGX_CONF_UNSET;
    conf->access_log_fd = NGX_INVALID_FILE;
    conf->metrics_slot = -1;
    conf->rootfd       = -1;
    conf->security_level = NGX_CONF_UNSET_UINT;
    conf->min_sec_level = NGX_CONF_UNSET_UINT;
    conf->opaque_strict = NGX_CONF_UNSET;
    conf->tls          = NGX_CONF_UNSET;
    conf->tls_ktls     = NGX_CONF_UNSET;
    conf->gsi_keypool_size = NGX_CONF_UNSET_UINT;
    conf->gsi_keypool_seed = NGX_CONF_UNSET_UINT;
    conf->jwks_mtime                 = 0;
    conf->token_jwks_refresh_interval = NGX_CONF_UNSET_MSEC;
    conf->jwks_timer                  = NULL;
    conf->token_clock_skew            = NGX_CONF_UNSET;
    conf->sss_lifetime      = NGX_CONF_UNSET;
    conf->sss_keys          = NULL;
    brix_krb5_conf_init(&conf->krb5);
    conf->unix_trust_remote = NGX_CONF_UNSET;
    conf->host_allow        = NGX_CONF_UNSET_PTR;
    brix_ocsp_conf_init(&conf->ocsp);

    /* Phase 20 caches/limits: kv == NULL means the feature is disabled.  The
     * directive setters fill these in; merge inherits the parent block. */
    conf->token_cache_kv  = NULL;
    conf->auth_cache.kv   = NULL;
    conf->auth_cache.ttl_secs = 0;
    conf->rate_limit.kv   = NULL;
    conf->rate_limit.rate = 0;
    conf->rate_limit.burst = 0;
    conf->rate_limit.key_ip = 0;
}

/*
 * WHAT: initialise the storage-plane fields (compression, ZIP, the read-through
 *       cache sizing/eviction/verify, memory budget, readv sizing, io_uring).
 * WHY:  isolates the storage concern group so its sentinels stay reviewable
 *       against the matching brix_merge_srv_storage() defaults.
 * HOW:  sentinels for merge-participating scalars; rootfds start -1 (pcalloc's 0
 *       would collide with stdin); NULL arrays/regex mean "inherit from parent".
 */
static void
brix_create_srv_storage(ngx_stream_brix_srv_conf_t *conf)
{
    conf->read_compress = NGX_CONF_UNSET;
    conf->write_compress = NGX_CONF_UNSET;
    conf->zip_access   = NGX_CONF_UNSET;
    conf->zip_cd_max_bytes = NGX_CONF_UNSET_SIZE;
    conf->zip_force_scratch = NGX_CONF_UNSET;
    conf->zip_stage_max_bytes = NGX_CONF_UNSET_SIZE;
    conf->tls_ctx      = NULL;
    conf->cache        = NGX_CONF_UNSET;
    conf->cache_origin_tls = NGX_CONF_UNSET;
    conf->cache_origin_family = NGX_CONF_UNSET_UINT;
    conf->cache_lock_timeout = NGX_CONF_UNSET;
    conf->cache_eviction_threshold = NGX_CONF_UNSET_UINT;
    conf->cache_max_file_size      = NGX_CONF_UNSET;
    conf->memory_budget            = NGX_CONF_UNSET;
    conf->readv_segment_size       = NGX_CONF_UNSET_SIZE;
    conf->io_uring                 = NGX_CONF_UNSET_UINT;
    conf->seccomp                  = NGX_CONF_UNSET_UINT;
    conf->negcache.threshold       = NGX_CONF_UNSET_UINT;
    conf->negcache.window_ms       = NGX_CONF_UNSET_UINT;
    conf->negcache.backoff_s       = NGX_CONF_UNSET_UINT;
    conf->io_uring_queue_depth     = NGX_CONF_UNSET;
    conf->io_uring_admin           = NGX_CONF_UNSET;
    conf->io_uring_restrict        = NGX_CONF_UNSET;
    conf->include_regex.set  = 0;
    conf->cache_dirty_max_age      = NGX_CONF_UNSET;
    brix_cache_reaper_conf_init(&conf->reaper);
    conf->cache_deny_prefixes      = NULL;
    conf->cache_allow_prefixes     = NULL;
    conf->cache_wt_stage_block_size = NGX_CONF_UNSET_SIZE;
    conf->cache_wt_stage_high_watermark = NGX_CONF_UNSET_UINT;
    conf->cache_wt_stage_low_watermark  = NGX_CONF_UNSET_UINT;
    /* O_PATH rootfds: -1 until brix_cache_storage_init (pcalloc's 0 == stdin). */
    conf->cache_rootfd             = -1;
    conf->cache_state_rootfd       = -1;
    conf->cache_wt_stage_rootfd    = -1;
    conf->cache_wt_store_rootfd    = -1;
    /* cache_state_root left zeroed (ngx_str_t {0,NULL}) by pcalloc */
    conf->cache_verify             = NGX_CONF_UNSET_UINT;
    /* cache_verify_digest left zeroed (ngx_str_t {0,NULL}) by pcalloc */
    conf->advertise.enable          = NGX_CONF_UNSET;
    conf->advertise.interval = NGX_CONF_UNSET_MSEC;
    brix_wt_conf_init(&conf->wt);
}

/*
 * WHAT: initialise the cluster + TPC + session fields (manager mode, uploads,
 *       pipeline/registry/session sizing, health checks, traffic mirror, CMS,
 *       listen port, checksum-scan limits, SSI/CNS, and TPC outbound creds).
 * WHY:  groups the clustering/TPC concern so it lines up with the
 *       brix_merge_srv_cluster()/_tpc() merge helpers.
 * HOW:  sentinels + NULL for arrays/addresses that mean "inherit from parent".
 */
static void
brix_create_srv_cluster(ngx_stream_brix_srv_conf_t *conf)
{
    conf->manager_mode       = NGX_CONF_UNSET;
    brix_node_caps_conf_init(&conf->caps);
    conf->upload_resume      = NGX_CONF_UNSET;
    /* upload_stage_dir: ngx_str_t left zeroed by pcalloc (handled by merge_str). */
    conf->pipeline_depth = NGX_CONF_UNSET_UINT;
    conf->registry_slots = NGX_CONF_UNSET_UINT;
    conf->session_slots  = NGX_CONF_UNSET_UINT;
    conf->redir_cache_slots = NGX_CONF_UNSET_UINT;
    brix_hc_conf_init(&conf->hc);

    /* Phase 24: traffic mirror (targets array NULL until a directive adds one). */
    conf->mirror.enabled     = NGX_CONF_UNSET;
    conf->mirror.targets     = NULL;
    conf->mirror.sample_pct  = NGX_CONF_UNSET_UINT;
    conf->mirror.method_mask = NGX_CONF_UNSET_UINT;
    conf->mirror.opcode_mask = NGX_CONF_UNSET_UINT;
    conf->mirror.opcode_exclude_mask = NGX_CONF_UNSET_UINT;
    conf->mirror.strip_auth  = NGX_CONF_UNSET;
    conf->mirror.log_diverge = NGX_CONF_UNSET;
    conf->mirror.timeout_ms  = NGX_CONF_UNSET_MSEC;
    conf->mirror.mirror_writes = NGX_CONF_UNSET;
    brix_cms_conf_init(&conf->cms);
    conf->http_handoff_addr = NULL;
    conf->relay_addr = NULL;
    conf->relay_guard_enable = NGX_CONF_UNSET;
    conf->listen_port  = NGX_CONF_UNSET;
    conf->ckscan_max_depth = NGX_CONF_UNSET_UINT;
    conf->ckscan_max_files = NGX_CONF_UNSET_UINT;
    conf->tpc_allow_local   = NGX_CONF_UNSET;
    conf->tpc_allow_private = NGX_CONF_UNSET;
    conf->ssi_enable        = NGX_CONF_UNSET;
    conf->ssi_cta_enable    = NGX_CONF_UNSET;
    conf->ssi_max_inflight  = NGX_CONF_UNSET_UINT;
    conf->ssi_request_max   = NGX_CONF_UNSET_SIZE;
    conf->ssi_response_max  = NGX_CONF_UNSET_SIZE;
    conf->ssi_cta_executor  = NGX_CONF_UNSET_UINT;
    conf->cns_mode          = NGX_CONF_UNSET_UINT;
    conf->tpc_key_ttl_ms    = NGX_CONF_UNSET_MSEC;
    conf->tpc_max_transfer_secs = NGX_CONF_UNSET_UINT;
    conf->tpc_require_source_size = NGX_CONF_UNSET;
    conf->tpc_verify_checksum = NGX_CONF_UNSET;
    conf->tpc_outbound_tls  = NGX_CONF_UNSET;
    conf->tpc_delegate      = NGX_CONF_UNSET;
    conf->tpc_outbound_passthrough = NGX_CONF_UNSET;
    conf->tpc_transfer_max_age  = NGX_CONF_UNSET;
    conf->tpc_outbound_bearer_file.len = 0;
    conf->tpc_outbound_bearer_file.data = NULL;
    conf->tpc_outbound_token_endpoint.len = 0;
    conf->tpc_outbound_token_endpoint.data = NULL;
    conf->tpc_outbound_client_id.len = 0;
    conf->tpc_outbound_client_id.data = NULL;
    conf->tpc_outbound_client_secret.len = 0;
    conf->tpc_outbound_client_secret.data = NULL;
    conf->tpc_outbound_scope.len = 0;
    conf->tpc_outbound_scope.data = NULL;
}

/*
 * WHAT: initialise the upstream/proxy + network-fault fields (upstream TLS +
 *       token, transparent proxy, and the Phase-39 network deadlines).
 * WHY:  isolates the proxy/net concern group so it matches
 *       brix_merge_srv_proxy_net()'s defaults one-for-one.
 * HOW:  sentinels for the deadlines/flags; NULL for arrays/addresses inherited
 *       from the parent block during merge.
 */
static void
brix_create_srv_proxy_net(ngx_stream_brix_srv_conf_t *conf)
{
    brix_proxy_conf_init(&conf->proxy);
    conf->upstream_addr = NULL;
    conf->upstream_tls = NGX_CONF_UNSET;
    conf->upstream_ssl_verify = NGX_CONF_UNSET;
#if (NGX_SSL)
    conf->upstream_tls_ctx = NULL;
#endif
    conf->upstream_tls_ca.len    = 0;
    conf->upstream_tls_ca.data   = NULL;
    conf->upstream_tls_name.len  = 0;
    conf->upstream_tls_name.data = NULL;
    conf->upstream_token_file.len  = 0;
    conf->upstream_token_file.data = NULL;

    /* Phase 39: network-fault resilience (off by default). */
    conf->read_timeout      = NGX_CONF_UNSET_MSEC;
    conf->handshake_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_timeout      = NGX_CONF_UNSET_MSEC;
    conf->tcp_user_timeout  = NGX_CONF_UNSET_MSEC;
    conf->tcp_keepalive     = NGX_CONF_UNSET;
    conf->max_connections   = NGX_CONF_UNSET_UINT;
    conf->manager_stale_after = NGX_CONF_UNSET_MSEC;
}

/*
 * This function creates a new server-level configuration object for nginx.
 * It allocates memory and initializes every field to an "unset" or NULL state,
 * allowing the merge step later to distinguish between missing directives and
 * explicitly configured values.
 */
void *
ngx_stream_brix_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_brix_srv_conf_t *conf;

    /*
     * nginx allocates one per-server config object during parsing and then
     * merges parent/child scopes later. Start everything in an explicit
     * "unset" or NULL state so the merge step can tell whether a directive
     * was omitted or configured intentionally.
     *
     * Scalar fields use nginx's UNSET sentinels when they participate in merge
     * logic; runtime-only objects start out NULL/invalid and are created later
     * during postconfiguration once parsing has finished. The per-field init is
     * split into one helper per configuration area, mirroring the merge helpers.
     */
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_brix_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_http_brix_shared_init(&conf->common);
    brix_create_srv_security(conf);
    brix_create_srv_storage(conf);
    brix_create_srv_cluster(conf);
    brix_create_srv_proxy_net(conf);

    return conf;
}

/*
 * Standard nginx parent→child scope inheritance. Delegates to one per-area entry
 * point (each defined in a sibling server_conf_merge_*.c and declared in
 * server_conf_internal.h), invoked in the original linear order so cross-area
 * derivations still observe their already-merged inputs (e.g. writethrough's
 * origin/decision in proxy_net depends on the cache fields settled in storage;
 * CMS timeout derivation in cluster depends on the merged cms_interval). Any
 * entry point returning NGX_CONF_ERROR aborts the merge (the error is already
 * logged).
 */
char *
ngx_stream_brix_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_brix_srv_conf_t *prev = parent;
    ngx_stream_brix_srv_conf_t *conf = child;

    if (brix_merge_srv_security(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (brix_merge_srv_storage(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    brix_merge_srv_tpc(conf, prev);
    if (brix_merge_srv_cluster(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (brix_merge_srv_proxy_net(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
 * ngx_stream_brix_enable - handler for the "xrootd on|off;" directive.
 */
char *
ngx_stream_brix_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_stream_core_srv_conf_t   *cscf;
    char                         *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    /* Explicit `xrootd off;` leaves the server block as a normal stream server. */
    if (!xcf->common.enable) {
        return NGX_CONF_OK;
    }

    /*
     * The stream core owns the accept loop; enabling the directive swaps in
     * our session handler for this server block.
     */
    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_brix_handler;

    return NGX_CONF_OK;
}
