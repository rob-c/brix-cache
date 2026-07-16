/*
 * config.c - WebDAV location config create/merge and startup validation.
 *
 * WHAT: nginx HTTP module location configuration lifecycle — allocates a fresh config struct with all fields set to NGX_CONF_UNSET sentinel values (create_loc_conf), then merges parent→child inheritance chain applying ngx_conf_merge_* macros to resolve defaults (merge_loc_conf). After merging, performs startup validation: canonicalizes the export root path, validates CA/CRL file/directory paths, builds a cached OpenSSL X509_STORE from configured certificates and CRLs, loads JWKS keys for token auth, and validates TPC curl binary paths. Returns NGX_CONF_OK on success or NGX_CONF_ERROR with emerg-level log messages on failure.
 *
 * WHY: WebDAV requires many interdependent config values (CA store, root path, CORS origins, token issuer/audience, upstream URL) that must be validated together before accepting traffic. The merge chain ensures location-level directives inherit from server and main context defaults, while the validation phase catches configuration errors at postconfig time so nginx -t fails early rather than a worker crashing on first request. Building the CA store during config merge (not per-request) eliminates repeated X509_STORE construction cost.
 *
 * HOW: create_loc_conf allocates with ngx_pcalloc and sets every field to NGX_CONF_UNSET or NGX_CONF_UNSET_UINT; merge_loc_conf applies ngx_conf_merge_* macros for each field, then conditionally validates root path, CA/CRL paths, CORS origins, JWKS load, TPC binary paths, and upstream URL parsing. On validation success builds X509_STORE via webdav_build_ca_store() and attaches a pool cleanup handler for automatic deallocation on worker exit. The base-merge/validation and proxy/mirror/token clusters live in the sibling files config_merge.c and config_proxy.c (see config_internal.h); this file keeps the create/merge entrypoints, the CA-store cleanup, CORS validation, and the endpoint startup summary.
 */

#include "webdav.h"
#include "auth/crypto/store_policy.h"      /* BRIX_SP_MODE_*, BRIX_CRL_MODE_* defaults */
#include "core/compat/integrity_info.h"   /* §8.x checksum xattr write format */
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "auth/token/issuer_registry.h"   /* phase-59 W1 multi-issuer registry */
#include "proxy_internal.h"
#include "net/mirror/http_mirror.h"
#include "core/config/config.h"
#include "fs/path/path.h"                  /* brix_finalize_{authdb,vo}_rules */
#include "core/config/root_prepare.h"
#include "core/config/http_rootfd.h"
#include "core/config/http_common.h"      /* unified brix_* directive adoption */
#include "core/config/export_guard.h"     /* brix_assert_dir_outside_export (hard guard) */
#include "core/compat/staged_file.h"
#include "fs/backend/sd.h"           /* SD registry: lazy per-worker instance */
#include "fs/vfs/vfs_backend_registry.h" /* per-export backend config + resolve */

#include <openssl/x509.h>

#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include "core/compat/alloc_guard.h"
#include "core/config/credential_block.h"   /* §14 brix_credential lookup/bearer */

#include "config_internal.h"

#define webdav_validate_path          brix_validate_path
#define WEBDAV_PATH_REGULAR_FILE      BRIX_PATH_REGULAR_FILE
#define WEBDAV_PATH_DIRECTORY         BRIX_PATH_DIRECTORY
#define WEBDAV_PATH_FILE_OR_DIRECTORY BRIX_PATH_FILE_OR_DIRECTORY

/*
 *
 * WHAT: Pool cleanup callback that frees an OpenSSL X509_STORE when the nginx configuration pool is destroyed during worker process exit. Called automatically by ngx_pool_cleanup_add — never invoked directly by application code. Only frees non-NULL store pointers to prevent NULL-deref crashes during error paths in config parsing.
 *
 * WHY: The CA store built by webdav_build_ca_store() must be freed when the nginx worker process shuts down to prevent memory leaks across multiple worker restarts (e.g., graceful shutdown/restart cycles). Attaching this cleanup handler to the configuration pool ensures automatic deallocation without requiring explicit free calls in every config parsing code path. */
void
webdav_x509_store_cleanup(void *data)
{
    X509_STORE *store = data;

    if (store != NULL) {
        X509_STORE_free(store);
    }
}

/*
 * Reject any configured CORS origin that is empty or contains control bytes.
 * These strings are later reflected into Access-Control-Allow-Origin response
 * headers, so a CR/LF in one would enable header injection — validate at config
 * time so a bad value fails `nginx -t` instead of poisoning responses.
 */
ngx_int_t
webdav_validate_cors_origins(ngx_conf_t *cf,
                             ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_str_t  *origins;
    ngx_uint_t  i;

    if (conf->cors_origins == NULL) {
        return NGX_OK;
    }

    origins = conf->cors_origins->elts;
    for (i = 0; i < conf->cors_origins->nelts; i++) {
        if (origins[i].len == 0
            || webdav_tpc_str_has_ctl(origins[i].data, origins[i].len))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix_webdav: invalid CORS origin \"%V\"",
                               &origins[i]);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * Allocate and pre-initialise a WebDAV location config.
 * pcalloc zeroes the struct, so only fields whose "unset" sentinel differs from
 * 0 are assigned here (NGX_CONF_UNSET / _UINT / _PTR / _MSEC), letting
 * merge_loc_conf below distinguish "not configured" from an explicit 0.  Fields
 * that should default to NULL/0 (e.g. the Phase 20/21/24 kv and target pointers)
 * are documented inline but rely on the pcalloc zero-fill.
 */
/*
 * Resolve the export's storage-driver instance, creating a "pblock" backend on
 * first use (per worker). The instance is cached on conf->common.storage_instance;
 * since the loc conf is shared copy-on-write across workers, each worker that
 * writes the field gets its own private pointer and therefore its own SQLite
 * connection (which must never be shared across fork). Allocated on the worker's
 * cycle pool so it outlives the request. "posix"/unset ⇒ NULL ⇒ default POSIX.
 */
void *
brix_webdav_backend_instance(ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_log_t *log)
{
    /* The per-export backend is registered at config time and built per worker by
     * the shared registry; this is now a thin alias kept for the PUT/MOVE offload
     * paths that pass the instance to a thread task. */
    return brix_vfs_backend_resolve(conf->common.root_canon, log);
}

void *
ngx_http_brix_webdav_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_brix_webdav_loc_conf_t *conf;

    BRIX_PCALLOC_OR_RETURN(conf, cf->pool, sizeof(*conf), NULL);

    ngx_http_brix_shared_init(&conf->common);
    conf->verify_depth = NGX_CONF_UNSET_UINT;
    conf->signing_policy_mode = NGX_CONF_UNSET_UINT;
    conf->crl_mode     = NGX_CONF_UNSET_UINT;
    conf->auth         = NGX_CONF_UNSET_UINT;
    brix_acc_http_init_conf(&conf->acc);   /* XrdAcc engine (off by default) */
    conf->proxy_certs  = NGX_CONF_UNSET;
    conf->tape_rest    = NGX_CONF_UNSET;
    conf->upload_resume = NGX_CONF_UNSET;
    conf->ca_store     = NULL;
    conf->cors_origins = NULL;
    conf->cors_credentials = NGX_CONF_UNSET;
    conf->cors_max_age = NGX_CONF_UNSET_UINT;
    conf->lock_timeout = NGX_CONF_UNSET_UINT;
    conf->lock_startup_sweep = NGX_CONF_UNSET;
    conf->zip_access = NGX_CONF_UNSET;
    conf->http_query_token = NGX_CONF_UNSET;
    conf->token_clock_skew = NGX_CONF_UNSET;
    conf->macaroon_max_validity = NGX_CONF_UNSET;
    conf->dig_enable = NGX_CONF_UNSET;
    conf->delegation_endpoint = NGX_CONF_UNSET;
    conf->dig_exports = NGX_CONF_UNSET_PTR;
    conf->authdb_rules = NGX_CONF_UNSET_PTR;   /* created on first brix_webdav_authdb */
    conf->vo_rules = NGX_CONF_UNSET_PTR;       /* created on first brix_webdav_require_vo */
    conf->checksum_xattr_format = NGX_CONF_UNSET_UINT;
    conf->zip_cd_max_bytes = NGX_CONF_UNSET_SIZE;
    conf->open_file_cache = NGX_CONF_UNSET_PTR;
    conf->open_file_cache_valid = NGX_CONF_UNSET_UINT;
    conf->open_file_cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->open_file_cache_errors = NGX_CONF_UNSET;
    conf->open_file_cache_events = NGX_CONF_UNSET;
    ngx_http_brix_webdav_tpc_create_loc_conf(conf);

    conf->upstream_proxy    = NGX_CONF_UNSET;
    conf->proxy_pool_enabled = NGX_CONF_UNSET;
    conf->upstream_auth     = (ngx_uint_t) NGX_CONF_UNSET_UINT;
    conf->upstream_resolved = NULL;
    conf->upstream_conf.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream_conf.send_timeout    = NGX_CONF_UNSET_MSEC;
    conf->upstream_conf.read_timeout    = NGX_CONF_UNSET_MSEC;
    /* Required by ngx_http_upstream_hide_headers_hash() (built in merge); an
     * uninitialised hide_headers_hash makes nginx divide by zero in
     * ngx_http_upstream_process_headers on the first backend response. */
    conf->upstream_conf.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream_conf.pass_headers = NGX_CONF_UNSET_PTR;

    /* Phase 21 Step D: multi-backend proxy. */
    conf->upstream_urls          = NULL;
    conf->upstream_backends      = NULL;
    conf->upstream_max_fails     = NGX_CONF_UNSET_UINT;
    conf->upstream_fail_timeout  = NGX_CONF_UNSET_MSEC;

    /* Phase 20 caches/limits: kv == NULL means disabled (pcalloc zeroed). */
    conf->token_cache_kv   = NULL;
    conf->rate_limit.kv    = NULL;
    conf->rate_limit.rate  = 0;
    conf->rate_limit.burst = 0;
    conf->rate_limit.key_ip = 0;

    /* Phase 21 Step C: introspection (loc.len == 0 means disabled). */
    conf->introspect_ttl       = NGX_CONF_UNSET_UINT;
    conf->introspect_fail_open = NGX_CONF_UNSET;
    conf->revoke_kv            = NULL;

    /* Phase 24: traffic mirror (targets NULL until a directive adds one). */
    conf->mirror.enabled     = NGX_CONF_UNSET;
    conf->mirror.targets     = NULL;
    conf->mirror.sample_pct  = NGX_CONF_UNSET_UINT;
    conf->mirror.method_mask = NGX_CONF_UNSET_UINT;
    conf->mirror.opcode_mask = NGX_CONF_UNSET_UINT;
    conf->mirror.strip_auth  = NGX_CONF_UNSET;
    conf->mirror.log_diverge = NGX_CONF_UNSET;
    conf->mirror.timeout_ms  = NGX_CONF_UNSET_MSEC;
    conf->mirror.mirror_writes = NGX_CONF_UNSET;
    conf->mirror_upstream_conf.hide_headers = NGX_CONF_UNSET_PTR;
    conf->mirror_upstream_conf.pass_headers = NGX_CONF_UNSET_PTR;

    return conf;
}

/*
 * Merge parent (server/outer location) config into this location and run all
 * startup validation.  Three phases: (1) inherit/default every directive via
 * ngx_conf_merge_*; (2) when WebDAV is enabled, resolve+confine the export root,
 * validate CA/CRL/JWKS/TPC paths, and build the cached X509 CA store once;
 * (3) resolve the upstream-proxy and traffic-mirror backends.  Returns
 * NGX_CONF_ERROR (with an emerg log) on any validation failure so `nginx -t`
 * rejects the config rather than a worker failing at request time.
 */
/*
 * WHAT: short human label for the merged brix_webdav_auth mode (for the
 *   startup summary), so the log reads "optional (anonymous allowed)" not "1".
 */
static const char *
webdav_auth_name(ngx_uint_t auth)
{
    switch (auth) {
    case WEBDAV_AUTH_REQUIRED: return "required";
    case WEBDAV_AUTH_OPTIONAL: return "optional (anonymous allowed)";
    default:                   return "none (anonymous)";
    }
}

/*
 * WHAT: is this location's WebDAV config a distinct endpoint, or just inherited
 *   unchanged from its parent location? `brix_webdav on` at server scope is
 *   inherited by every nested location; printing a banner for each would be
 *   noise, so we only print where the user-visible facts differ from the parent.
 */
ngx_uint_t
webdav_summary_is_new(ngx_http_brix_webdav_loc_conf_t *conf,
                      ngx_http_brix_webdav_loc_conf_t *prev)
{
    if (prev == NULL || !prev->common.enable) {
        return 1;
    }
    return (conf->auth != prev->auth
            || conf->common.allow_write != prev->common.allow_write
            || ngx_strcmp(conf->common.root_canon,
                          prev->common.root_canon) != 0);
}

/*
 * WHAT: emit the friendly NOTICE banner for one WebDAV (davs://) endpoint —
 *   export, read/write, auth mode, which credential types are accepted, CRL
 *   posture, and TPC/proxy mode — plus WARN notes for valid-but-risky settings.
 * WHY: give davs:// admins the same first-run confirmation the root:// banner
 *   gives (visible in `nginx -t`), and surface the same foot-guns: revocation
 *   off, anonymous writes, auth-required-but-no-credentials. Logged at merge
 *   time (per location), the only hook that reliably sees every WebDAV location.
 */
static void webdav_log_endpoint_warnings(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_uint_t has_x509,
    ngx_uint_t has_token, ngx_uint_t has_pwd);

void
webdav_log_endpoint_summary(ngx_conf_t *cf,
                            ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_uint_t  has_x509  = (conf->cadir.len > 0 || conf->cafile.len > 0
                             || conf->proxy_certs);
    ngx_uint_t  has_token = (conf->jwks_key_count > 0);
    ngx_uint_t  has_pwd   = (conf->pwd_file.len > 0);

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: WebDAV (davs://) endpoint ready — export \"%V\" (%s), auth: %s",
        &conf->common.root,
        conf->common.allow_write ? "read-write" : "read-only",
        webdav_auth_name(conf->auth));

    if (has_x509 || has_token || has_pwd) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix:   credentials accepted:%s%s%s",
            has_x509 ? " x509/GSI-proxy" : "",
            has_token ? " bearer-token" : "",
            has_pwd ? " basic-password" : "");
    }
    if (conf->crl.len > 0) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix:   revocation: CRL \"%V\"", &conf->crl);
    }
    if (conf->tpc) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix:   third-party copy (TPC COPY) enabled");
    }
    if (conf->upstream_proxy) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix:   mode: proxy — forwards to backend \"%V\"",
            &conf->upstream_url);
    }

    webdav_log_endpoint_warnings(cf, conf, has_x509, has_token, has_pwd);
}

/* Valid-but-noteworthy settings, surfaced explicitly for a first-time admin so
 * that permissive-by-configuration setups (revocation off, anonymous writes,
 * auth-required-but-no-verifier) are never silent. Split out of the endpoint
 * summary to keep each function's branching within the readability gate. */
static void
webdav_log_endpoint_warnings(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_uint_t has_x509,
    ngx_uint_t has_token, ngx_uint_t has_pwd)
{
    if (has_pwd) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix:   NOTE: password (Basic) authentication is enabled — do "
            "NOT rely on password auth in production, it is poor practice "
            "(prefer x509/GSI or bearer tokens, and serve Basic only over "
            "TLS: passwords cross the wire base64-encoded, not encrypted)");
    }
    if (has_x509 && conf->crl.len == 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix:   NOTE: x509/GSI is accepted but no CRL is configured — "
            "REVOKED certificates will be ACCEPTED (set brix_webdav_crl)");
    }
    if (conf->common.allow_write && conf->auth != WEBDAV_AUTH_REQUIRED) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix:   NOTE: writes are enabled but authentication is not "
            "required — anonymous clients may be able to create/modify/delete "
            "files (set brix_webdav_auth required)");
    }
    if (conf->auth == WEBDAV_AUTH_REQUIRED && !has_x509 && !has_token
        && !has_pwd && !conf->upstream_proxy)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix:   NOTE: auth is required but no x509 CA, token JWKS or "
            "password db is configured — every client will be rejected (set "
            "brix_webdav_cadir, brix_webdav_token_jwks and/or "
            "brix_webdav_pwd_file)");
    }
}

char *
ngx_http_brix_webdav_merge_loc_conf(ngx_conf_t *cf,
                                      void *parent, void *child)
{
    ngx_http_brix_webdav_loc_conf_t *prev = parent;
    ngx_http_brix_webdav_loc_conf_t *conf = child;

    if (webdav_merge_base_conf(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (webdav_validate_webdav_enabled(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (webdav_merge_auth_token_conf(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (webdav_merge_upstream_conf(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (webdav_merge_mirror_and_summary(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
