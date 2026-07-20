/* http_common.c — see http_common.h for the WHAT/WHY/HOW. */
#include "core/config/http_common.h"
#include "core/config/tier_directives.h"
#include "core/seccomp/seccomp.h"            /* brix_conf_set_seccomp */
#include "auth/impersonate/lifecycle.h"      /* brix_conf_set_worker_user */
#include "protocols/root/stream/module_enums.h" /* brix_seccomp_modes */
#include "fs/cache/verify.h"               /* brix_cache_verify_mode_e */
#include "fs/backend/sd.h"                 /* BRIX_CRED_* (phase-70 §4) */

#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>                   /* phase-2 T9 mint-CA config-time validation */

static void *brix_http_common_create_loc_conf(ngx_conf_t *cf);
static char *brix_http_common_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child);

static ngx_conf_enum_t  brix_http_ucred_fallback_enum[] = {
    { ngx_string("allow"), 0 },
    { ngx_string("deny"),  1 },
    { ngx_null_string, 0 }
};

/* brix_backend_delegation mode names → BRIX_CRED_* (phase-70 §4). Shared by the
 * HTTP plane here and mirrored by the root:// stream directive table. */
static ngx_conf_enum_t  brix_backend_delegation_enum[] = {
    { ngx_string("select"),      BRIX_CRED_SELECT },
    { ngx_string("passthrough"), BRIX_CRED_PASSTHROUGH },
    { ngx_string("exchange"),    BRIX_CRED_EXCHANGE },
    { ngx_string("delegate"),    BRIX_CRED_DELEGATE },
    { ngx_string("mint"),        BRIX_CRED_MINT },
    { ngx_string("auto"),        BRIX_CRED_AUTO },
    { ngx_null_string, 0 }
};

/*
 * brix_conf_set_mint_ca — setter for "brix_storage_credential_mint_ca <cert>
 * <key>" (phase-2 T9). Validates both PEM files load-parse at config time
 * (nginx -t fails loudly on a bad mint CA instead of every mint request
 * failing at runtime) and stores their paths into the shared preamble's
 * storage_credential_mint_ca_cert / _key fields. TRUST NOTE: configuring this
 * directive means the frontend will sign per-user x509 proxies with this CA
 * key — the ORIGIN must trust this CA for minted credentials to be usable;
 * see src/fs/backend/cred_mint.h for the full trust-model note.
 */
static char *
brix_conf_set_mint_ca(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_common_conf_t *c = conf;
    ngx_str_t                   *value = cf->args->elts;
    FILE                         *f;
    X509                         *cert;
    EVP_PKEY                     *key;

    (void) cmd;

    f = fopen((const char *) value[1].data, "r");
    cert = (f != NULL) ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f != NULL) {
        (void) fclose(f);   /* read-only stream: close failure cannot lose data */
    }
    if (cert == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_credential_mint_ca: cannot parse CA cert \"%V\"",
            &value[1]);
        return NGX_CONF_ERROR;
    }
    X509_free(cert);

    f = fopen((const char *) value[2].data, "r");
    key = (f != NULL) ? PEM_read_PrivateKey(f, NULL, NULL, NULL) : NULL;
    if (f != NULL) {
        (void) fclose(f);   /* read-only stream: close failure cannot lose data */
    }
    if (key == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_credential_mint_ca: cannot parse CA key \"%V\"",
            &value[2]);
        return NGX_CONF_ERROR;
    }
    EVP_PKEY_free(key);

    c->common.storage_credential_mint_ca_cert = value[1];
    c->common.storage_credential_mint_ca_key  = value[2];
    return NGX_CONF_OK;
}

/*
 * brix_conf_set_peers — setter for "brix_cache_peers <member> <member> ..."
 * (phase-85 F8 sibling mesh). Each member is "host:port", with this node's own
 * ring slot written "self=host:port". The tokens are only COLLECTED here (into
 * an ngx_str_t array on the shared preamble); shape validation — exactly one
 * self=, ≥2 members, well-formed authorities — runs at tier registration where
 * the [emerg] can name the export.
 */
static char *
brix_conf_set_peers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_common_conf_t *c = conf;
    ngx_str_t                    *value = cf->args->elts;
    ngx_str_t                    *slot;
    ngx_uint_t                    i;

    (void) cmd;

    if (c->common.cache_peers != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_peers: duplicate directive — list every ring "
            "member in one declaration");
        return NGX_CONF_ERROR;
    }
    c->common.cache_peers = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                             sizeof(ngx_str_t));
    if (c->common.cache_peers == NULL) {
        return NGX_CONF_ERROR;
    }
    for (i = 1; i < cf->args->nelts; i++) {
        slot = ngx_array_push(c->common.cache_peers);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }
        *slot = value[i];
    }
    return NGX_CONF_OK;
}

/*
 * brix_cache_verify values on the HTTP plane.  Only the self-verifying
 * cvmfs-cas scheme is meaningful here today (best-effort/require need an
 * origin-digest hook the HTTP-plane fill does not carry); this mirrors the
 * cvmfs module's enum exactly so owning the bare name here is a pure move, not
 * a grammar change.  Protocol merges validate which values they support.
 */
static ngx_conf_enum_t  brix_http_cache_verify_enum[] = {
    { ngx_string("off"),       BRIX_CACHE_VERIFY_OFF },
    { ngx_string("cvmfs-cas"), BRIX_CACHE_VERIFY_CVMFS_CAS },
    { ngx_null_string, 0 }
};

#define BRIX_HTTP_ALL_CONF \
    (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF)

static ngx_command_t  brix_http_common_commands[] = {

    { ngx_string("brix_export"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.root),
      NULL },

    { ngx_string("brix_storage_backend"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_backend),
      NULL },

    /* Per-worker seccomp-BPF syscall filter for HTTP (WebDAV/S3/cvmfs) servers —
     * off|audit|enforce.  Process-global: the strictest value across ALL brix
     * servers (stream + http) is installed once per worker, so HTTP-only workers
     * are filtered too (not just stream/root:// workers). */
    { ngx_string("brix_seccomp"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_seccomp,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.seccomp),
      &brix_seccomp_modes },

    /* Opt out of the enforce execve/execveat KILL (default off) for WebDAV
     * HTTP-TPC OIDC delegation and similar fork+exec helpers.  ptrace/process_vm_*
     * stay killed.  Process-global (strictest across stream+http; ratchets on). */
    { ngx_string("brix_seccomp_allow_exec"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_seccomp_allow_exec,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Confined account a root-capable worker is force-dropped to at init (default
     * "nobody" + a warning). Process-global; covers HTTP-only (WebDAV/S3) workers
     * too. See brix_imp_worker_deescalate. */
    { ngx_string("brix_worker_user"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_worker_user,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_storage_credential"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential),
      NULL },

    { ngx_string("brix_storage_credential_dir"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_dir),
      NULL },

    { ngx_string("brix_storage_credential_fallback"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_fallback),
      &brix_http_ucred_fallback_enum },

    { ngx_string("brix_storage_credential_mint_ca"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE2,
      brix_conf_set_mint_ca,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_storage_credential_mint_ttl"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_mint_ttl),
      NULL },

    { ngx_string("brix_backend_delegation"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_delegation),
      &brix_backend_delegation_enum },

    { ngx_string("brix_backend_token_audience_ok"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_token_aud),
      NULL },

    { ngx_string("brix_backend_token_exchange_endpoint"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_tx_endpoint),
      NULL },

    { ngx_string("brix_backend_token_exchange_client_id"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_tx_client_id),
      NULL },

    { ngx_string("brix_backend_token_exchange_client_secret"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_tx_client_secret),
      NULL },

    { ngx_string("brix_backend_s3_sts_endpoint"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_endpoint),
      NULL },

    { ngx_string("brix_backend_s3_sts_role"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_role),
      NULL },

    { ngx_string("brix_backend_krb5_forwardable"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_krb5_forwardable),
      NULL },

    { ngx_string("brix_backend_passthrough_persist"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_passthrough_persist),
      NULL },

    { ngx_string("brix_allow_write"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.allow_write),
      NULL },

    /* Read-back CRC verify for whole-object PUT (WebDAV/S3) routed through
     * brix_vfs_writer; off by default. Never applies to ranged/partial PUT. */
    { ngx_string("brix_verify_write"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.verify_write),
      NULL },

    { ngx_string("brix_read_only"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.read_only),
      NULL },

    { ngx_string("brix_compress"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.compress),
      NULL },

    /* E-1: refuse valid-but-dangerous configs at nginx -t rather than only
     * warning (anonymous S3, unauthenticated WebDAV writes, anonymous
     * dashboard). Off by default; see brix_shared_security_gate. */
    { ngx_string("brix_strict_security"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.strict_security),
      NULL },

    { ngx_string("brix_access_log"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.access_log),
      NULL },

    { ngx_string("brix_session_log"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.session_log),
      NULL },

    { ngx_string("brix_thread_pool"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.thread_pool_name),
      NULL },

    { ngx_string("brix_cache_peers"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_1MORE,
      brix_conf_set_peers,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_cache_verify"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.cache_verify_mode),
      &brix_http_cache_verify_enum },

    /* The 11 tier directives: brix_cache_store, brix_cache_cold_store,
     * brix_stage, brix_stage_store, brix_stage_flush, brix_cache_max_object,
     * brix_cache_evict_at, brix_cache_evict_to, brix_cache_index_cache,
     * brix_cache_meta, brix_cache_slice_size. */
    BRIX_TIER_DIRECTIVES("brix_", ngx_http_brix_common_conf_t,
                         BRIX_HTTP_ALL_CONF, NGX_HTTP_LOC_CONF_OFFSET),

      ngx_null_command
};

static ngx_http_module_t  brix_http_common_module_ctx = {
    NULL, NULL,                          /* pre/postconfiguration */
    NULL, NULL,                          /* create/init main conf */
    NULL, NULL,                          /* create/merge srv conf */
    brix_http_common_create_loc_conf,
    brix_http_common_merge_loc_conf
};

ngx_module_t  ngx_http_brix_common_module = {
    NGX_MODULE_V1,
    &brix_http_common_module_ctx,
    brix_http_common_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/*
 * brix_http_common_create_loc_conf() — allocate the common module's location
 * conf and seed the embedded preamble with UNSET sentinels so parent->child
 * inheritance (below) can tell "not configured" from an explicit value.
 */
static void *
brix_http_common_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_brix_common_conf_t  *c;

    c = ngx_pcalloc(cf->pool, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    ngx_http_brix_shared_init(&c->common);
    return c;
}

/*
 * brix_http_common_merge_loc_conf() — inheritance-only merge: propagate parent
 * values into unset child slots and apply NO defaults.  Per-protocol defaults
 * still come from ngx_http_brix_shared_merge() in each protocol's merge, so a
 * field left unset here stays UNSET and lets each protocol pick its own
 * default after adopting the unified value.
 */
static char *
brix_http_common_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brix_common_conf_t  *prev = parent;
    ngx_http_brix_common_conf_t  *conf = child;

    (void) cf;
    brix_shared_adopt_unified(&conf->common, &prev->common);
    return NGX_CONF_OK;
}

#define BRIX_ADOPT_STR(f) \
    do { if (dst->f.data == NULL && src->f.data != NULL) dst->f = src->f; } while (0)
#define BRIX_ADOPT_VAL(f, unset) \
    do { if (dst->f == (unset) && src->f != (unset)) dst->f = src->f; } while (0)
#define BRIX_ADOPT_PTR(f) \
    do { if (dst->f == NULL && src->f != NULL) dst->f = src->f; } while (0)

void
brix_shared_adopt_unified(ngx_http_brix_shared_conf_t *dst,
                          const ngx_http_brix_shared_conf_t *src)
{
    BRIX_ADOPT_STR(root);
    BRIX_ADOPT_STR(storage_backend);
    BRIX_ADOPT_STR(storage_credential);
    BRIX_ADOPT_STR(storage_credential_dir);
    BRIX_ADOPT_VAL(storage_credential_fallback, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_STR(storage_credential_mint_ca_cert);
    BRIX_ADOPT_STR(storage_credential_mint_ca_key);
    BRIX_ADOPT_VAL(storage_credential_mint_ttl, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(backend_delegation, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_STR(backend_tx_endpoint);
    BRIX_ADOPT_STR(backend_tx_client_id);
    BRIX_ADOPT_STR(backend_tx_client_secret);
    BRIX_ADOPT_STR(backend_sts_endpoint);
    BRIX_ADOPT_STR(backend_sts_role);
    BRIX_ADOPT_VAL(backend_krb5_forwardable, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(backend_passthrough_persist, NGX_CONF_UNSET);
    BRIX_ADOPT_STR(thread_pool_name);
    BRIX_ADOPT_STR(access_log);
    BRIX_ADOPT_STR(cache_store);
    BRIX_ADOPT_PTR(cache_store_args);
    BRIX_ADOPT_STR(cache_cold_store);
    BRIX_ADOPT_PTR(cache_cold_store_args);
    BRIX_ADOPT_PTR(cache_peers);
    BRIX_ADOPT_STR(stage_store);
    BRIX_ADOPT_PTR(stage_store_args);
    BRIX_ADOPT_VAL(allow_write,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(read_only,         NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(compress,          NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(strict_security,   NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(session_log,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(stage_enable,      NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(stage_flush_async, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(cache_max_object,  NGX_CONF_UNSET);          /* off_t */
    BRIX_ADOPT_VAL(cache_evict_at,    NGX_CONF_UNSET_UINT);     /* ngx_uint_t */
    BRIX_ADOPT_VAL(cache_evict_to,    NGX_CONF_UNSET_UINT);     /* ngx_uint_t */
    BRIX_ADOPT_VAL(cache_index_cache, (size_t) NGX_CONF_UNSET_SIZE);
    BRIX_ADOPT_VAL(cache_meta_mode,   NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(cache_slice_size,  (size_t) NGX_CONF_UNSET_SIZE);
    BRIX_ADOPT_VAL(cache_verify_mode, NGX_CONF_UNSET_UINT);
}

void
brix_http_common_adopt(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *dst)
{
    ngx_http_brix_common_conf_t  *ucf;

    ucf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_brix_common_module);
    if (ucf == NULL) {
        return;
    }
    brix_shared_adopt_unified(dst, &ucf->common);
}
