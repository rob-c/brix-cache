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
#include "core/config/credential_block.h"  /* brix_conf_credential_block (phase-105 W2) */
#include "core/shm/kv.h"                   /* brix_kv_zone_directive (phase-105 W1) */
#include "core/shm/rate_limit.h"           /* brix_rate_limit_directive */
#include "auth/token/token_cache.h"        /* brix_token_cache_directive */
#include "net/ratelimit/ratelimit.h"       /* brix_rl_{zone,rule,bw,conc}_directive */
#include "net/mirror/http_mirror.h"        /* brix_http_mirror_set_{url,methods} (phase-105 W2) */
#include "core/http/http_variables.h"   /* brix_http_add_variables (phase-106 W1) */

#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>                   /* phase-2 T9 mint-CA config-time validation */
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */
#include "auth/crypto/store_policy.h"  /* BRIX_SP_MODE_* / BRIX_CRL_MODE_* (W4 x509) */

/* CRL enforcement + GSI signing-policy enums (phase-101 W4): the whole x509 CRL
 * family is bare on the stream plane; owning the bare names here mirrors those
 * value sets exactly (a pure move, not a grammar change). */
static ngx_conf_enum_t  brix_http_signing_policy_modes[] = {
    { ngx_string("off"),     BRIX_SP_MODE_OFF     },
    { ngx_string("on"),      BRIX_SP_MODE_ON      },
    { ngx_string("require"), BRIX_SP_MODE_REQUIRE },
    { ngx_null_string, 0 }
};
static ngx_conf_enum_t  brix_http_crl_modes[] = {
    { ngx_string("off"),     BRIX_CRL_MODE_OFF     },
    { ngx_string("try"),     BRIX_CRL_MODE_TRY     },
    { ngx_string("require"), BRIX_CRL_MODE_REQUIRE },
    { ngx_null_string, 0 }
};

static void *brix_http_common_create_loc_conf(ngx_conf_t *cf);
static void *brix_http_common_create_main_conf(ngx_conf_t *cf);
static char *brix_http_common_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child);
static char *brix_http_conf_tpc_source_allow(ngx_conf_t *cf,
                                             ngx_command_t *cmd, void *conf);
static ngx_int_t brix_http_common_init_process(ngx_cycle_t *cycle);

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

    /* ---- core runtime + credentials + access policy ---- */
#include "http_directives_core.h"

    /* ---- authorization, x509/VOMS, TPC guard, tokens ---- */
#include "http_directives_auth.h"

    /* ---- pmark, mirror, limits, tier/async families ---- */
#include "http_directives_ops.h"


      ngx_null_command
};

/* phase-106 W1: the common module owns the $brix_* variable surface, so one
 * registration serves every HTTP protocol and a variable's existence does not
 * depend on which protocol module is loaded. */
static ngx_int_t
brix_http_common_preconfiguration(ngx_conf_t *cf)
{
    return brix_http_add_variables(cf);
}


static ngx_http_module_t  brix_http_common_module_ctx = {
    brix_http_common_preconfiguration,   /* preconfiguration */
    NULL,                                /* postconfiguration */
    brix_http_common_create_main_conf, NULL,
    NULL, NULL,                          /* create/merge srv conf */
    brix_http_common_create_loc_conf,
    brix_http_common_merge_loc_conf
};

ngx_module_t  ngx_http_brix_common_module = {
    NGX_MODULE_V1,
    &brix_http_common_module_ctx,
    brix_http_common_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, brix_http_common_init_process, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/*
 * brix_http_common_create_loc_conf() — allocate the common module's location
 * conf and seed the embedded preamble with UNSET sentinels so parent->child
 * inheritance (below) can tell "not configured" from an explicit value.
 */
static void *
brix_http_common_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_brix_common_main_conf_t *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(*mcf));
    return mcf;
}

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
    BRIX_ADOPT_STR(n2n_scheme);
    BRIX_ADOPT_STR(n2n_pool);
    BRIX_ADOPT_STR(n2n_prefix);
    BRIX_ADOPT_STR(storage_credential);
    BRIX_ADOPT_STR(storage_credential_dir);
    BRIX_ADOPT_VAL(storage_credential_fallback, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_STR(storage_credential_mint_ca_cert);
    BRIX_ADOPT_STR(storage_credential_mint_ca_key);
    BRIX_ADOPT_VAL(storage_credential_mint_ttl, NGX_CONF_UNSET);   /* time_t (W7) */
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
    BRIX_ADOPT_STR(cache_root);   /* W8: legacy read-through cache root (canon is
                                   * derived per-protocol after this adopt) */
    BRIX_ADOPT_PTR(cache_store_args);
    BRIX_ADOPT_STR(cache_cold_store);
    BRIX_ADOPT_PTR(cache_cold_store_args);
    BRIX_ADOPT_PTR(cache_peers);
    BRIX_ADOPT_STR(stage_store);
    BRIX_ADOPT_PTR(stage_store_args);
    BRIX_ADOPT_VAL(allow_write,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(durable_commit,    NGX_CONF_UNSET);
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
    BRIX_ADOPT_VAL(cache_uvkeep,      NGX_CONF_UNSET);          /* time_t */

    /* phase-101 W2: kTLS + trusted cache-store endpoint (were dual-conf pokes). */
    BRIX_ADOPT_VAL(ktls,                 NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_store_endpoint, NGX_CONF_UNSET);

    /* phase-101 W2: XrdAcc engine — the 11 config-time settings ONLY. The
     * per-worker tables/timer/timer_armed tail is lazily built after fork and
     * MUST NOT be adopted (copying an embedded ngx_event_t between confs is
     * actively wrong — see acc.h). */
    BRIX_ADOPT_VAL(acc.format,        NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(acc.audit,         NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(acc.refresh,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(acc.gidlifetime,   NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(acc.pgo,           NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(acc.resolve_hosts, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(acc.encoding,      NGX_CONF_UNSET);
    BRIX_ADOPT_STR(acc.authdb);
    BRIX_ADOPT_STR(acc.nisdomain);
    BRIX_ADOPT_STR(acc.spacechar);
    BRIX_ADOPT_STR(acc.gidretran);

    /* phase-105 W3: HTTP maxdelay (xrootd maxdelay analog — was
     * brix_webdav_maxdelay; the stream plane already spells it bare). */
    BRIX_ADOPT_VAL(max_delay, NGX_CONF_UNSET);

    /* phase-105 W2: delegation-endpoint flag + front-leg client-CA store. */
    BRIX_ADOPT_VAL(delegation_endpoint, NGX_CONF_UNSET);
    BRIX_ADOPT_STR(client_ca_store);

    /* phase-105 W2/W3.5: auth-layer verify source, chain-depth cap,
     * congestion alg. */
    BRIX_ADOPT_STR(trusted_ca);
    BRIX_ADOPT_STR(trusted_ca_dir);
    BRIX_ADOPT_VAL(verify_depth, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_STR(tcp_congestion);

    /* phase-105 W4.1: introspection quad. */
    BRIX_ADOPT_STR(introspect_url);
    BRIX_ADOPT_STR(introspect_loc);
    BRIX_ADOPT_VAL(introspect_ttl, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(introspect_fail_open, NGX_CONF_UNSET);

    /* phase-105 W2: traffic-mirror settings (targets/token/masks/flags). */
    BRIX_ADOPT_PTR(mirror.targets);
    BRIX_ADOPT_STR(mirror.token);
    BRIX_ADOPT_VAL(mirror.sample_pct,  NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(mirror.method_mask, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(mirror.strip_auth,  NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(mirror.log_diverge, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(mirror.timeout_ms,  NGX_CONF_UNSET_MSEC);
    BRIX_ADOPT_VAL(mirror.mirror_writes, NGX_CONF_UNSET);

    /* phase-105 W1: token cache + rate limiting + shaping rules. The
     * rate_limit engine conf is a plain settings struct (kv/rate/burst/key_ip)
     * — adopted whole when the destination is unset (kv==NULL). */
    BRIX_ADOPT_PTR(token_cache_kv);
    if (dst->rate_limit.kv == NULL && src->rate_limit.kv != NULL) {
        dst->rate_limit = src->rate_limit;
    }
    BRIX_ADOPT_PTR(rl_rules);

    /* phase-101 W4: ZIP member serving (was the webdav + s3 zip twins). */
    BRIX_ADOPT_VAL(zip_access,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(zip_cd_max_bytes, (size_t) NGX_CONF_UNSET_SIZE);

    /* phase-101 W4: HTTP basic-auth password db (was brix_webdav_pwd_file). */
    BRIX_ADOPT_STR(pwd_file);
    /* phase-101 W4: resumable PUT (was brix_webdav_upload_resume). */
    BRIX_ADOPT_VAL(upload_resume, NGX_CONF_UNSET);
    /* phase-101 W4: macaroon HMAC secrets (were brix_webdav_macaroon_secret*). */
    BRIX_ADOPT_STR(token_macaroon_secret);
    BRIX_ADOPT_STR(token_macaroon_secret_old);
    /* phase-101 W4: upload staging dir (was brix_webdav_stage_dir). */
    BRIX_ADOPT_STR(upload_stage_dir);
    /* phase-107 C1: writer reorder-spill scratch. */
    BRIX_ADOPT_STR(vfs_spill_path);
    BRIX_ADOPT_VAL(vfs_spill_max, (size_t) NGX_CONF_UNSET_SIZE);
    /* phase-107 C3: durable-publish barrier flag. */
    BRIX_ADOPT_VAL(durable_publish, NGX_CONF_UNSET);
    /* phase-107 C7: cross-protocol lock enforcement mode. */
    BRIX_ADOPT_VAL(lock_enforcement, NGX_CONF_UNSET_UINT);
    /* phase-108 C12: authorization-backstop rollout mode. */
    BRIX_ADOPT_VAL(authz_backstop, NGX_CONF_UNSET_UINT);
    /* phase-101 W4: pblock stripe size (was brix_webdav_pblock_block_size). */
    BRIX_ADOPT_VAL(pblock_block_size, (size_t) NGX_CONF_UNSET_SIZE);
    /* phase-101 W4: x509 CRL family (was brix_webdav_crl/_crl_mode/_signing_policy). */
    BRIX_ADOPT_STR(crl);
    BRIX_ADOPT_VAL(signing_policy_mode, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(crl_mode,            NGX_CONF_UNSET_UINT);
    /* phase-101 W4: VOMS trust dirs (was brix_webdav_vomsdir/_voms_cert_dir). */
    BRIX_ADOPT_STR(vomsdir);
    BRIX_ADOPT_STR(voms_cert_dir);
    BRIX_ADOPT_PTR(vo_rules);
    BRIX_ADOPT_PTR(authdb_rules);   /* phase-101 W5.2: native u/g/p READ ACL */
    BRIX_ADOPT_PTR(protbind);
    BRIX_ADOPT_VAL(tpc_allow_local,        NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(tpc_allow_private,      NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(tpc_source_guard,       NGX_CONF_UNSET);
    BRIX_ADOPT_PTR(tpc_source_allow);
    BRIX_ADOPT_VAL(tpc_require_source_size, NGX_CONF_UNSET);
    BRIX_ADOPT_STR(tpc_verify_checksum);
    BRIX_ADOPT_VAL(tpc_outbound_tls, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(tpc_outbound_passthrough, NGX_CONF_UNSET);
    BRIX_ADOPT_STR(tpc_outbound_bearer_file);
    BRIX_ADOPT_STR(tpc_outbound_token_endpoint);
    BRIX_ADOPT_STR(tpc_outbound_client_id);
    BRIX_ADOPT_STR(tpc_outbound_client_secret);
    BRIX_ADOPT_STR(tpc_outbound_scope);
    BRIX_ADOPT_STR(certificate);
    BRIX_ADOPT_STR(certificate_key);
    /* phase-101 W4: WLCG token trust quartet (collapsed webdav+s3 twins). */
    BRIX_ADOPT_STR(token_jwks);
    BRIX_ADOPT_VAL(token_jwks_refresh_interval, NGX_CONF_UNSET_MSEC);
    BRIX_ADOPT_STR(token_issuer);
    BRIX_ADOPT_STR(token_audience);
    BRIX_ADOPT_STR(token_config);
    BRIX_ADOPT_VAL(token_clock_skew, NGX_CONF_UNSET);

    /* SciTags pmark (phase-101 W1) — the 13 config-time fields only.  The
     * runtime tail (rt_ready/rt_ok/dest_sa/exp_rules_r/act_rules_r) is per-worker
     * lazily-built state behind pmark.h's "never merged" contract and MUST NOT be
     * adopted.  Because http_common's own inheritance merge routes through this
     * same function, this one block covers BOTH location inheritance and each
     * protocol's adopt-at-merge. */
    BRIX_ADOPT_VAL(pmark.enable,         NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.firefly,        NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.flowlabel,      NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.scitag_cgi,     NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.firefly_origin, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.http_plain,     NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.echo,           NGX_CONF_UNSET_MSEC);
    BRIX_ADOPT_VAL(pmark.domain,         NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_STR(pmark.appname);
    BRIX_ADOPT_STR(pmark.defsfile);
    BRIX_ADOPT_PTR(pmark.firefly_dest);
    BRIX_ADOPT_PTR(pmark.exp_rules);
    BRIX_ADOPT_PTR(pmark.act_rules);
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

ngx_int_t
brix_http_common_register_jwks_refresh(ngx_conf_t *cf, const ngx_str_t *path,
    brix_jwks_key_t *keys, int *key_count, ngx_msec_t interval)
{
    ngx_http_brix_common_main_conf_t *mcf;
    brix_jwks_refresh_spec_t          *spec;
    struct stat                        st;

    if (path == NULL || path->len == 0 || keys == NULL || key_count == NULL
        || interval == 0
        || interval == (ngx_msec_t) NGX_CONF_UNSET_MSEC)
    {
        return NGX_OK;
    }
    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_brix_common_module);
    if (mcf == NULL) {
        return NGX_ERROR;
    }
    if (mcf->jwks_refresh_specs == NULL) {
        mcf->jwks_refresh_specs = ngx_array_create(cf->pool, 4,
                                      sizeof(brix_jwks_refresh_spec_t));
        if (mcf->jwks_refresh_specs == NULL) {
            return NGX_ERROR;
        }
    }
    spec = ngx_array_push(mcf->jwks_refresh_specs);
    if (spec == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(spec, sizeof(*spec));
    spec->path = *path;
    spec->keys = keys;
    spec->key_count = key_count;
    spec->interval = interval;
    if (stat((const char *) path->data, &st) == 0) {
        spec->mtime = st.st_mtime;
    }
    return NGX_OK;
}

static ngx_int_t
brix_http_common_init_process(ngx_cycle_t *cycle)
{
    ngx_http_brix_common_main_conf_t *mcf;
    brix_jwks_refresh_spec_t          *specs;
    ngx_uint_t                         i;

    mcf = ngx_http_cycle_get_module_main_conf(cycle,
                                               ngx_http_brix_common_module);
    if (mcf == NULL || mcf->jwks_refresh_specs == NULL) {
        return NGX_OK;
    }
    specs = mcf->jwks_refresh_specs->elts;
    for (i = 0; i < mcf->jwks_refresh_specs->nelts; i++) {
        if (brix_token_jwks_schedule(cycle, &specs[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* brix_tpc_source_allow <host>... on the HTTP planes (phase-101 W4): append EVERY
 * argument to common.tpc_source_allow.  A custom setter (not the stock str_array
 * slot, which silently keeps only the first arg) because this is a SECURITY
 * allowlist — dropping hosts after the first would widen egress.  `common` is
 * member 0 of the common-module conf, so the cast to the preamble type is valid.
 * Mirrors the stream-side brix_tpc_conf_source_allow. */
static char *
brix_http_conf_tpc_source_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_shared_conf_t *sc = conf;
    ngx_str_t                   *value, *slot;
    ngx_uint_t                   i;

    (void) cmd;

    if (sc->tpc_source_allow == NULL) {
        sc->tpc_source_allow = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (sc->tpc_source_allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        slot = ngx_array_push(sc->tpc_source_allow);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }
        *slot = value[i];
    }
    return NGX_CONF_OK;
}
