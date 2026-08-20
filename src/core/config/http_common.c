/* http_common.c — see http_common.h for the WHAT/WHY/HOW. */
#include "core/config/http_common.h"
#include "core/config/tier_directives.h"
#include "core/seccomp/seccomp.h"            /* brix_conf_set_seccomp */
#include "auth/impersonate/lifecycle.h"      /* brix_conf_set_worker_user */
#include "protocols/root/stream/module_enums.h" /* brix_seccomp_modes */
#include "fs/cache/verify.h"               /* brix_cache_verify_mode_e */
#include "fs/backend/sd.h"                 /* BRIX_CRED_* (phase-70 §4) */
#include "auth/s3/sts.h"                   /* BRIX_STS_FLAVOR_* (phase-70 §5.5) */
#include "core/config/config.h"            /* brix_conf_set_backend_sss_keytab */
#include "fs/vfs/vfs_secgate.h"            /* brix_conf_set_tls_require */

#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>                   /* phase-2 T9 mint-CA config-time validation */
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */

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

/* STS wire dialect for brix_backend_s3_sts_flavor (phase-70 §5.5). */
static ngx_conf_enum_t  brix_sts_flavor_enum[] = {
    { ngx_string("aws"),   BRIX_STS_FLAVOR_AWS },
    { ngx_string("minio"), BRIX_STS_FLAVOR_MINIO },
    { ngx_null_string, 0 }
};

/*
 * brix_cache_verify values on the HTTP plane.  Only the SELF-verifying schemes
 * are meaningful here (best-effort/require need an origin-digest hook the
 * HTTP-plane fill does not carry): cvmfs-cas, whose key names a sha1, and
 * phase-104's oci-digest, whose key names a sha256, and rpm-repodata, whose
 * key is a createrepo `<checksum>-<name>` metadata file.  This mirrors the cvmfs
 * module's enum exactly so owning the bare name here is a pure move, not a
 * grammar change.  Protocol merges validate which values they support.
 */
static ngx_conf_enum_t  brix_http_cache_verify_enum[] = {
    { ngx_string("off"),        BRIX_CACHE_VERIFY_OFF },
    { ngx_string("cvmfs-cas"),  BRIX_CACHE_VERIFY_CVMFS_CAS },
    { ngx_string("oci-digest"), BRIX_CACHE_VERIFY_OCI_DIGEST },
    { ngx_string("rpm-repodata"), BRIX_CACHE_VERIFY_RPM_REPODATA },
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
      brix_conf_set_backend_tx_endpoint,
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
      brix_conf_set_backend_sts_endpoint,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_endpoint),
      NULL },

    { ngx_string("brix_backend_s3_sts_role"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_role),
      NULL },

    { ngx_string("brix_backend_s3_sts_access_key"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_access_key),
      NULL },

    { ngx_string("brix_backend_s3_sts_secret_key"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_secret_key),
      NULL },

    { ngx_string("brix_backend_s3_sts_region"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_region),
      NULL },

    { ngx_string("brix_backend_s3_sts_ttl"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_ttl),
      NULL },

    { ngx_string("brix_backend_s3_sts_flavor"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_flavor),
      &brix_sts_flavor_enum },

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

    /* Phase-70 §5.6 / P90-70.3: SSS identity-injection keytab — the delegation
     * gate re-issues an SSS credential asserting the CALLER's principal to the
     * origin, signed with this keytab (never the keytab's own principal).
     * Load-validated at config time by the setter. */
    { ngx_string("brix_backend_sss_keytab"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_backend_sss_keytab,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sss_keytab),
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

    /* Per-capability TLS gating (stock xrootd.tls parity): ops exercising a
     * listed capability are refused with 403 on cleartext transports. */
    { ngx_string("brix_tls_require"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_1MORE,
      brix_conf_set_tls_require,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.tls_require),
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

    /* The tier directives: brix_cache_store, brix_cache_cold_store,
     * brix_stage, brix_stage_store, brix_stage_flush, brix_cache_max_object,
     * brix_cache_evict_at, brix_cache_evict_to, brix_cache_index_cache,
     * brix_cache_meta, brix_cache_slice_size, brix_cache_global_cas,
     * brix_cache_passthrough, brix_cache_passthrough_max, brix_cache_prefetch,
     * brix_cache_prefetch_window, brix_cache_only_if_cached. */
    BRIX_TIER_DIRECTIVES("brix_", ngx_http_brix_common_conf_t,
                         BRIX_HTTP_ALL_CONF, NGX_HTTP_LOC_CONF_OFFSET),

    /* Durable async backend-op queue (brix_backend_async[_batch|_wait]) — shared
     * with the root:// stream plane, adopted into each http protocol's `common`. */
    BRIX_BACKEND_ASYNC_DIRECTIVES("brix_", ngx_http_brix_common_conf_t,
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
    BRIX_ADOPT_STR(backend_sts_access_key);
    BRIX_ADOPT_STR(backend_sts_secret_key);
    BRIX_ADOPT_STR(backend_sts_region);
    BRIX_ADOPT_VAL(backend_sts_ttl, NGX_CONF_UNSET);
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
    BRIX_ADOPT_VAL(tls_require,       NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(session_log,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(stage_enable,      NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(stage_flush_async, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(backend_async,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(backend_async_batch, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(backend_async_wait,  NGX_CONF_UNSET_MSEC);
    BRIX_ADOPT_VAL(cache_max_object,  NGX_CONF_UNSET);          /* off_t */
    BRIX_ADOPT_VAL(cache_evict_at,    NGX_CONF_UNSET_UINT);     /* ngx_uint_t */
    BRIX_ADOPT_VAL(cache_evict_to,    NGX_CONF_UNSET_UINT);     /* ngx_uint_t */
    BRIX_ADOPT_VAL(cache_index_cache, (size_t) NGX_CONF_UNSET_SIZE);
    BRIX_ADOPT_VAL(cache_meta_mode,   NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(cache_slice_size,  (size_t) NGX_CONF_UNSET_SIZE);
    BRIX_ADOPT_VAL(cache_prefetch,    NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_prefetch_window, (size_t) NGX_CONF_UNSET_SIZE);
    BRIX_ADOPT_VAL(cache_verify_mode, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(cache_global_cas,  NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_passthrough, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_passthrough_max, NGX_CONF_UNSET);      /* off_t */
    BRIX_ADOPT_VAL(cache_only_if_cached, NGX_CONF_UNSET);
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
