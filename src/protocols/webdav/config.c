/*
 * config.c - WebDAV location config create/merge and startup validation.
 *
 * WHAT: nginx HTTP module location configuration lifecycle — allocates a fresh config struct with all fields set to NGX_CONF_UNSET sentinel values (create_loc_conf), then merges parent→child inheritance chain applying ngx_conf_merge_* macros to resolve defaults (merge_loc_conf). After merging, performs startup validation: canonicalizes the export root path, validates CA/CRL file/directory paths, builds a cached OpenSSL X509_STORE from configured certificates and CRLs, loads JWKS keys for token auth, and validates TPC curl binary paths. Returns NGX_CONF_OK on success or NGX_CONF_ERROR with emerg-level log messages on failure.
 *
 * WHY: WebDAV requires many interdependent config values (CA store, root path, CORS origins, token issuer/audience, upstream URL) that must be validated together before accepting traffic. The merge chain ensures location-level directives inherit from server and main context defaults, while the validation phase catches configuration errors at postconfig time so nginx -t fails early rather than a worker crashing on first request. Building the CA store during config merge (not per-request) eliminates repeated X509_STORE construction cost.
 *
 * HOW: create_loc_conf allocates with ngx_pcalloc and sets every field to NGX_CONF_UNSET or NGX_CONF_UNSET_UINT; merge_loc_conf applies ngx_conf_merge_* macros for each field, then conditionally validates root path, CA/CRL paths, CORS origins, JWKS load, TPC binary paths, and upstream URL parsing. On validation success builds X509_STORE via webdav_build_ca_store() and attaches a pool cleanup handler for automatic deallocation on worker exit.
 */

#include "webdav.h"
#include "core/compat/integrity_info.h"   /* §8.x checksum xattr write format */
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "auth/token/issuer_registry.h"   /* phase-59 W1 multi-issuer registry */
#include "proxy_internal.h"
#include "net/mirror/http_mirror.h"
#include "core/config/config.h"
#include "core/config/root_prepare.h"
#include "core/config/http_rootfd.h"
#include "core/config/http_common.h"      /* unified brix_* directive adoption */
#include "core/compat/staged_file.h"
#include "fs/backend/sd.h"           /* SD registry: lazy per-worker instance */
#include "fs/vfs/vfs_backend_registry.h" /* per-export backend config + resolve */

#include <openssl/x509.h>

#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include "core/compat/alloc_guard.h"
#include "core/config/credential_block.h"   /* §14 brix_credential lookup/bearer */

#define webdav_validate_path          brix_validate_path
#define WEBDAV_PATH_REGULAR_FILE      BRIX_PATH_REGULAR_FILE
#define WEBDAV_PATH_DIRECTORY         BRIX_PATH_DIRECTORY
#define WEBDAV_PATH_FILE_OR_DIRECTORY BRIX_PATH_FILE_OR_DIRECTORY

/*
 *
 * WHAT: Pool cleanup callback that frees an OpenSSL X509_STORE when the nginx configuration pool is destroyed during worker process exit. Called automatically by ngx_pool_cleanup_add — never invoked directly by application code. Only frees non-NULL store pointers to prevent NULL-deref crashes during error paths in config parsing.
 *
 * WHY: The CA store built by webdav_build_ca_store() must be freed when the nginx worker process shuts down to prevent memory leaks across multiple worker restarts (e.g., graceful shutdown/restart cycles). Attaching this cleanup handler to the configuration pool ensures automatic deallocation without requiring explicit free calls in every config parsing code path. */
static void
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
static ngx_int_t
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
    conf->macaroon_max_validity = NGX_CONF_UNSET;
    conf->dig_enable = NGX_CONF_UNSET;
    conf->dig_exports = NGX_CONF_UNSET_PTR;
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
static ngx_uint_t
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
static void
webdav_log_endpoint_summary(ngx_conf_t *cf,
                            ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_uint_t  has_x509  = (conf->cadir.len > 0 || conf->cafile.len > 0
                             || conf->proxy_certs);
    ngx_uint_t  has_token = (conf->jwks_key_count > 0);

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: WebDAV (davs://) endpoint ready — export \"%V\" (%s), auth: %s",
        &conf->common.root,
        conf->common.allow_write ? "read-write" : "read-only",
        webdav_auth_name(conf->auth));

    if (has_x509 || has_token) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix:   credentials accepted:%s%s",
            has_x509 ? " x509/GSI-proxy" : "",
            has_token ? " bearer-token" : "");
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

    /* Valid-but-noteworthy settings, surfaced explicitly for a first-time admin. */
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
        && !conf->upstream_proxy)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix:   NOTE: auth is required but no x509 CA or token JWKS is "
            "configured — every client will be rejected (set "
            "brix_webdav_cadir and/or brix_webdav_token_jwks)");
    }
}

char *
ngx_http_brix_webdav_merge_loc_conf(ngx_conf_t *cf,
                                      void *parent, void *child)
{
    ngx_http_brix_webdav_loc_conf_t *prev = parent;
    ngx_http_brix_webdav_loc_conf_t *conf = child;

    /* Unified directives (brix_export, brix_cache_store, ...) live in the
     * common module; pull the merged values for this location into our
     * embedded preamble before protocol merge applies defaults. */
    brix_http_common_adopt(cf, &conf->common);

    /* Shared common.* preamble (incl. hard read-only enforcement + pmark);
     * WebDAV exports default to "/" (pure cache nodes serve the whole ns). */
    if (ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "/")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_conf_merge_str_value(conf->cache_root, prev->cache_root, "");
    ngx_conf_merge_str_value(conf->vomsdir, prev->vomsdir, "");
    ngx_conf_merge_str_value(conf->tcp_congestion, prev->tcp_congestion, "");
    ngx_conf_merge_str_value(conf->voms_cert_dir, prev->voms_cert_dir, "");
    ngx_conf_merge_str_value(conf->cadir, prev->cadir, "");
    ngx_conf_merge_str_value(conf->cafile, prev->cafile, "");
    ngx_conf_merge_str_value(conf->crl, prev->crl, "");
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 10);
    ngx_conf_merge_uint_value(conf->auth, prev->auth,
                              WEBDAV_AUTH_OPTIONAL);
    brix_acc_http_merge_conf(&conf->acc, &prev->acc);
    ngx_conf_merge_value(conf->proxy_certs, prev->proxy_certs, 0);
    ngx_conf_merge_value(conf->tape_rest, prev->tape_rest, 0);
    /* Uploads staged + resumable by DEFAULT.  Set brix_webdav_upload_resume
     * off to opt out. */
    ngx_conf_merge_value(conf->upload_resume, prev->upload_resume, 1);
    ngx_conf_merge_str_value(conf->upload_stage_dir, prev->upload_stage_dir, "");
    ngx_http_brix_webdav_tpc_merge_loc_conf(conf, prev);
    BRIX_MERGE_PTR(conf, prev, cors_origins);
    ngx_conf_merge_value(conf->cors_credentials, prev->cors_credentials, 0);
    ngx_conf_merge_uint_value(conf->cors_max_age, prev->cors_max_age, 86400);
    ngx_conf_merge_uint_value(conf->lock_timeout, prev->lock_timeout, 600);
    ngx_conf_merge_value(conf->lock_startup_sweep, prev->lock_startup_sweep, 0);
    ngx_conf_merge_value(conf->zip_access, prev->zip_access, 0);
    ngx_conf_merge_value(conf->http_query_token, prev->http_query_token, 1);
    ngx_conf_merge_value(conf->macaroon_max_validity,
                         prev->macaroon_max_validity, 86400);
    ngx_conf_merge_str_value(conf->macaroon_location, prev->macaroon_location, "");
    ngx_conf_merge_str_value(conf->checksum_on_write, prev->checksum_on_write, "");
    ngx_conf_merge_uint_value(conf->checksum_xattr_format,
                              prev->checksum_xattr_format, BRIX_CKS_FMT_TEXT);
    if (conf->checksum_xattr_format != BRIX_CKS_FMT_TEXT) {
        /* §8.x: stock-interoperable binary XrdCksData write format (process-wide). */
        brix_integrity_set_xattr_format(conf->checksum_xattr_format);
    }
    ngx_conf_merge_value(conf->dig_enable, prev->dig_enable, 0);
    ngx_conf_merge_ptr_value(conf->dig_exports, prev->dig_exports, NULL);
    ngx_conf_merge_str_value(conf->dig_auth_file, prev->dig_auth_file, "");
    ngx_conf_merge_size_value(conf->zip_cd_max_bytes, prev->zip_cd_max_bytes,
                              16 * 1024 * 1024);

    /* Phase 20 caches/limits: inherit parent block when not set locally. */
    if (conf->token_cache_kv == NULL) {
        conf->token_cache_kv = prev->token_cache_kv;
    }
    if (conf->rate_limit.kv == NULL) {
        conf->rate_limit = prev->rate_limit;
    }

    /* Phase 21 Step C: introspection inheritance. */
    ngx_conf_merge_str_value(conf->introspect_url, prev->introspect_url, "");
    ngx_conf_merge_str_value(conf->introspect_loc, prev->introspect_loc, "");
    ngx_conf_merge_uint_value(conf->introspect_ttl, prev->introspect_ttl, 30);
    ngx_conf_merge_value(conf->introspect_fail_open,
                         prev->introspect_fail_open, 1);
    if (conf->revoke_kv == NULL) {
        conf->revoke_kv = prev->revoke_kv;
    }

    ngx_conf_merge_ptr_value(conf->open_file_cache,
                              prev->open_file_cache, NULL);
    ngx_conf_merge_uint_value(conf->open_file_cache_valid,
                              prev->open_file_cache_valid, 60);
    ngx_conf_merge_uint_value(conf->open_file_cache_min_uses,
                              prev->open_file_cache_min_uses, 1);
    ngx_conf_merge_value(conf->open_file_cache_errors,
                         prev->open_file_cache_errors, 0);
    ngx_conf_merge_value(conf->open_file_cache_events,
                         prev->open_file_cache_events, 0);

    ngx_conf_merge_str_value(conf->token_jwks, prev->token_jwks, "");
    ngx_conf_merge_str_value(conf->token_issuer, prev->token_issuer, "");
    ngx_conf_merge_str_value(conf->token_audience, prev->token_audience, "");
    ngx_conf_merge_str_value(conf->token_config, prev->token_config, "");
    ngx_conf_merge_ptr_value(conf->token_registry, prev->token_registry, NULL);
    ngx_conf_merge_str_value(conf->token_macaroon_secret,
                             prev->token_macaroon_secret, "");
    ngx_conf_merge_str_value(conf->token_macaroon_secret_old,
                             prev->token_macaroon_secret_old, "");

    if (conf->common.enable) {
        {
            brix_export_root_opts_t root_opts;

            /* posix:<path> backend → the local export tree (composable brix_export). */
            brix_storage_backend_posix_root(&conf->common);

            root_opts.directive_name = "brix_export";
            root_opts.allow_write    = conf->common.allow_write
                                     && !brix_storage_backend_is_remote(&conf->common);
            root_opts.required       = 1;
            root_opts.canon_size     = sizeof(conf->common.root_canon);
            if (brix_prepare_export_root(cf, &conf->common.root, &root_opts,
                                           conf->common.root_canon) != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }
            /* SP4: reap interrupted NON-staged direct-write temps under this root. */
            brix_tmp_reap_register(conf->common.root_canon);
        }

        /* Register the export's selected storage backend so every VFS op resolves
         * to it at request time (brix_vfs_ctx_init): a "root://host:port" URL =
         * a remote root:// primary (WebDAV PUT staged-writes stream through to it);
         * a driver name (pblock) = a local backend; default POSIX is a no-op. */
        if (brix_vfs_backend_config_str(cf, conf->common.root_canon,
                &conf->common.storage_backend, conf->common.pblock_block_size,
                BRIX_AF_AUTO)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
        if (conf->common.storage_staging) {
            brix_vfs_backend_set_staging(conf->common.root_canon, 1);
        }

        /* §14: attach the named brix_credential's bearer to the source backend
         * (consumed by sd_http / sd_xroot). Resolved at config time; a missing
         * credential or unreadable token_file fails loudly. Mirrors runtime_server.c
         * for the stream scope. No brix_webdav_storage_credential ⇒ anonymous. */
        if (conf->common.storage_credential.len > 0) {
            char                       cred_z[256];
            char                       bearer[4096];
            const brix_credential_t *cred;

            ngx_cpystrn((u_char *) cred_z, conf->common.storage_credential.data,
                        ngx_min(conf->common.storage_credential.len + 1,
                                sizeof(cred_z)));
            cred = brix_credential_lookup(cred_z);
            if (cred == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "brix_webdav_storage_credential: no brix_credential \"%V\"",
                    &conf->common.storage_credential);
                return NGX_CONF_ERROR;
            }
            if (brix_credential_bearer(cred, bearer, sizeof(bearer), cf->log)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
            {
                brix_vfs_backend_cred_t bcred;

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
                brix_vfs_backend_set_credential(conf->common.root_canon, &bcred);
            }
        }

        /* Open the persistent confinement rootfd on the freshly-resolved
         * export root (kernel openat2 RESOLVE_BENEATH anchor). */
        if (brix_http_open_rootfd(cf, &conf->common) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        /* Phase-64: register the composable cache/stage tiers (§4.4 mirror). */
        if (brix_tier_register_stores(cf, &conf->common) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* Optional fast-cache upload staging device (cross-device commit). */
        if (conf->upload_stage_dir.len > 0) {
            brix_export_root_opts_t stage_opts;
            stage_opts.directive_name = "brix_webdav_stage_dir";
            stage_opts.allow_write    = 1;
            stage_opts.required       = 0;
            stage_opts.canon_size     = sizeof(conf->upload_stage_dir_canon);
            if (brix_prepare_export_root(cf, &conf->upload_stage_dir,
                    &stage_opts, conf->upload_stage_dir_canon) != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }
            brix_stage_dir_register(conf->upload_stage_dir_canon);
        }

        /*
         * Optional startup lock sweep: when brix_webdav_lock_startup_sweep is
         * on, clear every persisted lock xattr under the freshly-resolved
         * export root so locks do not survive a restart (ephemeral RFC 4918
         * §10.1 semantics).  Done here rather than in postconfiguration because
         * root_canon is resolved per-location at merge time.  Skipped under
         * `nginx -t` so a config test never mutates the filesystem.
         */
        if (conf->lock_startup_sweep && !ngx_test_config
            && conf->common.root_canon[0] != '\0')
        {
            ngx_uint_t removed = webdav_lock_startup_sweep(
                cf->pool, cf->log, conf->common.root_canon);
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "brix_webdav: lock startup sweep removed %ui persisted "
                "lock(s) under \"%s\"", removed, conf->common.root_canon);
        }

        if (conf->cache_root.len > 0) {
            brix_export_root_opts_t cache_opts;
            cache_opts.directive_name = "brix_webdav_cache_root";
            cache_opts.allow_write    = 0;
            cache_opts.required       = 0;
            cache_opts.canon_size     = sizeof(conf->cache_root_canon);
            if (brix_prepare_export_root(cf, &conf->cache_root, &cache_opts,
                                           conf->cache_root_canon) != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        if (conf->auth == WEBDAV_AUTH_OPTIONAL
            || conf->auth == WEBDAV_AUTH_REQUIRED)
        {
            if (conf->cadir.len == 0 && conf->cafile.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "brix_webdav: auth optional/required needs brix_webdav_cadir or brix_webdav_cafile");
                return NGX_CONF_ERROR;
            }
        }

        if (webdav_validate_path(cf, "brix_webdav_cadir", &conf->cadir,
                                 WEBDAV_PATH_DIRECTORY, R_OK | X_OK)
            != NGX_OK
            || webdav_validate_path(cf, "brix_webdav_cafile", &conf->cafile,
                                    WEBDAV_PATH_REGULAR_FILE, R_OK)
               != NGX_OK
            || webdav_validate_path(cf, "brix_webdav_crl", &conf->crl,
                                    WEBDAV_PATH_FILE_OR_DIRECTORY, R_OK)
               != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (webdav_validate_cors_origins(cf, conf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* Build the X509 trust store once at config time (not per request) when
         * cert auth is in play, and tie its lifetime to the conf pool via a
         * cleanup handler so it is freed exactly once on worker exit. */
        if (conf->auth == WEBDAV_AUTH_OPTIONAL
            || conf->auth == WEBDAV_AUTH_REQUIRED)
        {
            X509_STORE         *store;
            ngx_pool_cleanup_t *cln;
            int                 crl_count = 0;

            store = webdav_build_ca_store(cf->log, conf, &crl_count);
            if (store == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "brix_webdav: failed to build cached CA store");
                return NGX_CONF_ERROR;
            }

            (void) webdav_check_pki_consistency(cf->log, conf);

            cln = ngx_pool_cleanup_add(cf->pool, 0);
            if (cln == NULL) {
                X509_STORE_free(store);
                return NGX_CONF_ERROR;
            }

            cln->handler = webdav_x509_store_cleanup;
            cln->data = store;
            conf->ca_store = store;

            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                               "brix_webdav: cached CA store built"
                               " for root=\"%V\" crls=%d",
                               &conf->common.root, crl_count);
        }

        if (conf->token_jwks.len > 0) {
            if (conf->token_issuer.len == 0
                || conf->token_audience.len == 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "brix_webdav: brix_webdav_token_jwks requires brix_webdav_token_issuer and brix_webdav_token_audience");
                return NGX_CONF_ERROR;
            }

            if (webdav_validate_path(cf, "brix_webdav_token_jwks",
                                     &conf->token_jwks,
                                     WEBDAV_PATH_REGULAR_FILE, R_OK)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        if (conf->tpc) {
            if (webdav_validate_path(cf, "brix_webdav_tpc_curl",
                                     &conf->tpc_curl,
                                     WEBDAV_PATH_REGULAR_FILE, X_OK)
                != NGX_OK
                || webdav_validate_path(cf, "brix_webdav_tpc_cert",
                                        &conf->tpc_cert,
                                        WEBDAV_PATH_REGULAR_FILE, R_OK)
                   != NGX_OK
                || webdav_validate_path(cf, "brix_webdav_tpc_key",
                                        &conf->tpc_key,
                                        WEBDAV_PATH_REGULAR_FILE, R_OK)
                   != NGX_OK
                || webdav_validate_path(cf, "brix_webdav_tpc_cadir",
                                        &conf->tpc_cadir,
                                        WEBDAV_PATH_DIRECTORY, R_OK | X_OK)
                   != NGX_OK
                || webdav_validate_path(cf, "brix_webdav_tpc_cafile",
                                        &conf->tpc_cafile,
                                        WEBDAV_PATH_REGULAR_FILE, R_OK)
                   != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (conf->token_jwks.len > 0) {
        int rc;

        rc = brix_jwks_load(cf->log,
                              (const char *) conf->token_jwks.data,
                              conf->jwks_keys, BRIX_MAX_JWKS_KEYS);
        if (rc < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix_webdav: failed to load JWKS from \"%V\"",
                               &conf->token_jwks);
            return NGX_CONF_ERROR;
        }
        conf->jwks_key_count = rc;

        if (rc > 0
            && brix_jwks_register_cleanup(cf->pool, conf->jwks_keys,
                                            &conf->jwks_key_count) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    /* Multi-issuer registry (phase-59 W1) — only build it on a leaf location
     * that actually set brix_webdav_token_config (token_registry stays the
     * inherited value otherwise). */
    if (conf->token_config.len > 0 && conf->token_registry == NULL) {
        brix_token_registry_t *reg = NULL;

        if (brix_token_registry_build(cf,
                (const char *) conf->token_config.data,
                BRIX_AUTHZ_CAPABILITY, &reg) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
        conf->token_registry = reg;
    }

    ngx_conf_merge_value(conf->upstream_proxy, prev->upstream_proxy, 0);
    ngx_conf_merge_str_value(conf->upstream_url, prev->upstream_url, "");
    ngx_conf_merge_uint_value(conf->upstream_auth, prev->upstream_auth,
                              WEBDAV_PROXY_AUTH_ANONYMOUS);
    ngx_conf_merge_str_value(conf->upstream_auth_token,
                             prev->upstream_auth_token, "");
    ngx_conf_merge_msec_value(conf->upstream_conf.connect_timeout,
                              prev->upstream_conf.connect_timeout, 0);
    ngx_conf_merge_msec_value(conf->upstream_conf.send_timeout,
                              prev->upstream_conf.send_timeout, 0);
    ngx_conf_merge_msec_value(conf->upstream_conf.read_timeout,
                              prev->upstream_conf.read_timeout, 0);

    ngx_conf_merge_uint_value(conf->upstream_max_fails,
                              prev->upstream_max_fails, 3);
    ngx_conf_merge_msec_value(conf->upstream_fail_timeout,
                              prev->upstream_fail_timeout, 30000);

    ngx_conf_merge_value(conf->proxy_pool_enabled, prev->proxy_pool_enabled, 0);

    if (conf->upstream_proxy && conf->proxy_pool_enabled) {
        /* Phase 23 dynamic pool: backends live in shared memory, populated at
         * runtime via the admin REST API — no static URL / build_backends. */
        if (webdav_proxy_pool_setup(cf, conf, prev) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (conf->upstream_auth == WEBDAV_PROXY_AUTH_TOKEN
            && conf->upstream_auth_token.len == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix_webdav_proxy_auth token requires a"
                               " non-empty token value");
            return NGX_CONF_ERROR;
        }

    } else if (conf->upstream_proxy && conf->upstream_backends == NULL) {
        /* Inherit the configured URL list / built backends from the parent
         * when this location did not declare its own. */
        if (conf->upstream_urls == NULL && prev->upstream_urls != NULL) {
            conf->upstream_urls = prev->upstream_urls;
        }
        if (conf->upstream_url.len == 0 && prev->upstream_url.len > 0) {
            conf->upstream_url = prev->upstream_url;
        }
        /* Reuse the parent's already-built backends only if this location's
         * effective URL list is identical to the parent's (same array pointer
         * AND same primary URL bytes).  If they differ we must rebuild below so
         * we never serve one location through another location's resolved
         * backends. */
        if (prev->upstream_backends != NULL
            && conf->upstream_urls == prev->upstream_urls
            && prev->upstream_url.len == conf->upstream_url.len
            && (conf->upstream_url.len == 0
                || ngx_memcmp(prev->upstream_url.data, conf->upstream_url.data,
                              conf->upstream_url.len) == 0))
        {
            conf->upstream_backends  = prev->upstream_backends;
            conf->upstream_resolved  = prev->upstream_resolved;
            conf->upstream_host      = prev->upstream_host;
            conf->upstream_url_base  = prev->upstream_url_base;
            conf->upstream_ssl       = prev->upstream_ssl;
            conf->upstream_conf      = prev->upstream_conf;
#if (NGX_HTTP_SSL)
            conf->upstream_ssl_ctx   = prev->upstream_ssl_ctx;
#endif
        }

        if (conf->upstream_backends == NULL) {
            static ngx_str_t  webdav_proxy_hide_headers[] = {
                ngx_null_string
            };
            ngx_hash_init_t   hh;

            if (webdav_proxy_build_backends(cf, conf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            /* Build hide_headers_hash so nginx's upstream header processing has
             * a non-empty hash to probe (otherwise SIGFPE on first response). */
            hh.max_size     = 512;
            hh.bucket_size  = ngx_align(64, ngx_cacheline_size);
            hh.name         = "webdav_proxy_hide_headers_hash";
            hh.pool         = cf->pool;
            hh.temp_pool    = NULL;
            if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream_conf,
                    &prev->upstream_conf, webdav_proxy_hide_headers, &hh)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        if (conf->upstream_auth == WEBDAV_PROXY_AUTH_TOKEN
            && conf->upstream_auth_token.len == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix_webdav_proxy_auth token requires a"
                               " non-empty token value");
            return NGX_CONF_ERROR;
        }
    }

    /* Phase 24: traffic mirror — inherit parent targets, derive enabled, and
     * build the shadow upstream conf (timeouts/TLS/hide-headers) when active. */
    if (conf->mirror.targets == NULL) {
        conf->mirror.targets = prev->mirror.targets;
    }
    ngx_conf_merge_str_value(conf->mirror.token, prev->mirror.token, "");
    ngx_conf_merge_uint_value(conf->mirror.sample_pct,  prev->mirror.sample_pct, 100);
    ngx_conf_merge_uint_value(conf->mirror.method_mask, prev->mirror.method_mask,
                              BRIX_MIRROR_M_DEFAULT);
    ngx_conf_merge_value(conf->mirror.strip_auth,  prev->mirror.strip_auth,  1);
    ngx_conf_merge_value(conf->mirror.log_diverge, prev->mirror.log_diverge, 1);
    ngx_conf_merge_msec_value(conf->mirror.timeout_ms, prev->mirror.timeout_ms, 5000);
    ngx_conf_merge_value(conf->mirror.mirror_writes,
                         prev->mirror.mirror_writes, 0);
    conf->mirror.enabled = (conf->mirror.targets != NULL
                            && conf->mirror.targets->nelts > 0) ? 1 : 0;

    if (conf->mirror.enabled
        && conf->mirror_upstream_conf.connect_timeout == 0)
    {
        if (brix_http_mirror_setup(cf, conf, prev) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Friendly per-endpoint startup summary (visible in `nginx -t` output and
     * at boot). Only for a location that actually enables WebDAV and whose
     * config is not merely inherited unchanged from its parent — see
     * webdav_summary_is_new(). Mirrors the root:// banner in the stream
     * postconfiguration.
     */
    if (conf->common.enable && webdav_summary_is_new(conf, prev)) {
        webdav_log_endpoint_summary(cf, conf);
    }

    return NGX_CONF_OK;
}
