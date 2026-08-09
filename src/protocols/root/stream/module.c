/*
 * stream/module.c
 *
 * nginx stream module implementing the XRootD root:// protocol.
 * Acts as a kXR_DataServer at the TCP level, with optional write support.
 *
 * loc-lint: exempt — ~95% of this file is the single declarative ngx_command_t
 * directive table (one C array, terminated by ngx_null_command) plus the
 * module_enums.h value maps; the conf logic is already split out into
 * config/server_conf.c (create/merge) and stream/module_definition.c (the
 * ngx_module_t struct).  A flat declarative table cannot be sharded across files
 * without ugly macro re-assembly, and per-directive doc-blocks are the bulk.
 * See docs/refactor/phase-38-file-size-unix-modularity.md §2.6/§6.10.
 */

#include "core/ngx_brix_module.h"
#include "net/proxy/proxy.h"
#include "net/proxy/proxy_internal.h"
#include "protocols/root/handoff/handoff.h"
#include "protocols/root/relay/relay.h"
#include "auth/token/token_cache.h"   /* brix_token_cache_directive */
#include "net/manager/health_check.h" /* BRIX_HC_TYPE_* */
#include "net/mirror/stream_mirror.h" /* Phase 24: traffic mirror directives */
#include "net/ratelimit/ratelimit.h"  /* Phase 25: advanced rate-limit directives */
#include "core/negcache/negcache.h"   /* E-4: brix_negcache_backoff setter */
#include "core/config/config.h"       /* brix_conf_set_backend_sss_keytab */
#include "auth/impersonate/lifecycle.h" /* Phase 40: impersonation directives */
#include "net/cms/cns.h"               /* §6 CNS mode enum */
#include "core/config/credential_block.h" /* §14 brix_credential block directive */
#include "module_enums.h"   /* directive enum value tables */
#include "core/seccomp/seccomp.h"   /* brix_conf_set_seccomp (brix_seccomp directive) */
#include "fs/backend/sd.h"  /* BRIX_CRED_* (phase-70 §4) */
#include "auth/s3/sts.h"    /* BRIX_STS_FLAVOR_* (phase-70 §5.5) */
#include "core/config/tier_directives.h"   /* shared tier-grammar X-macro */
#include "fs/vfs/vfs_secgate.h"            /* brix_conf_set_tls_require */

#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>   /* phase-3 T1: mint-CA config-time validation */
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */

/* §7 SSI: brix_ssi_cta_executor — simulated (test) vs real tier/frm (prod). */
static ngx_conf_enum_t  brix_ssi_executor_enum[] = {
    { ngx_string("test"), 0 },
    { ngx_string("prod"), 1 },
    { ngx_null_string,    0 }
};

/* Phase 2 Task 6: brix_storage_credential_fallback allow|deny on the stream
 * (root://) plane — mirrors brix_http_ucred_fallback_enum (http_common.c)
 * exactly; a stream-local copy because the HTTP one is file-static. */
/* Phase-70 §4: brix_backend_delegation mode names → BRIX_CRED_* on the stream
 * (root://) plane — mirrors brix_backend_delegation_enum (http_common.c); a
 * stream-local copy because the HTTP one is file-static. */
static ngx_conf_enum_t  brix_stream_backend_delegation_enum[] = {
    { ngx_string("select"),      BRIX_CRED_SELECT },
    { ngx_string("passthrough"), BRIX_CRED_PASSTHROUGH },
    { ngx_string("exchange"),    BRIX_CRED_EXCHANGE },
    { ngx_string("delegate"),    BRIX_CRED_DELEGATE },
    { ngx_string("mint"),        BRIX_CRED_MINT },
    { ngx_string("auto"),        BRIX_CRED_AUTO },
    { ngx_null_string,           0 }
};

/* Phase-70 §5.5: brix_backend_s3_sts_flavor aws|minio on the stream (root://)
 * plane — mirrors brix_sts_flavor_enum (http_common.c); a stream-local copy
 * because the HTTP one is file-static. */
static ngx_conf_enum_t  brix_stream_sts_flavor_enum[] = {
    { ngx_string("aws"),   BRIX_STS_FLAVOR_AWS },
    { ngx_string("minio"), BRIX_STS_FLAVOR_MINIO },
    { ngx_null_string,     0 }
};

static ngx_conf_enum_t  brix_stream_credential_fallback_enum[] = {
    { ngx_string("allow"), 0 },
    { ngx_string("deny"),  1 },
    { ngx_null_string,     0 }
};

/*
 * brix_conf_set_stream_mint_ca — setter for "brix_storage_credential_mint_ca
 * <cert> <key>" on the stream (root://) plane (phase-3 T1). Mirrors
 * brix_conf_set_mint_ca (src/core/config/http_common.c) exactly — a
 * stream-local copy is required because the HTTP setter is file-static and
 * the two conf struct types differ. Validates both PEM files load-parse at
 * config time (nginx -t fails loudly on a bad mint CA instead of every mint
 * request failing at runtime) and stores their paths into the shared
 * preamble's storage_credential_mint_ca_cert / _key fields. TRUST NOTE:
 * configuring this directive means the frontend will sign per-user x509
 * proxies with this CA key — the ORIGIN must trust this CA for minted
 * credentials to be usable; see src/fs/backend/cred_mint.h for the full
 * trust-model note.
 */
static char *
brix_conf_set_stream_mint_ca(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value = cf->args->elts;
    FILE                          *f;
    X509                          *cert;
    EVP_PKEY                      *key;

    (void) cmd;

    f = fopen((const char *) value[1].data, "r");
    cert = (f != NULL) ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f != NULL) {
        (void) fclose(f); /* read-only stream; the PEM parse result is the gate */
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
        (void) fclose(f); /* read-only stream; the PEM parse result is the gate */
    }
    if (key == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_credential_mint_ca: cannot parse CA key \"%V\"",
            &value[2]);
        return NGX_CONF_ERROR;
    }
    brix_evp_pkey_free(key);

    xcf->common.storage_credential_mint_ca_cert = value[1];
    xcf->common.storage_credential_mint_ca_key  = value[2];
    return NGX_CONF_OK;
}

/*
 * brix_ssi_service <name> — enable a non-default SSI provider. The built-in
 * test/reference services always resolve; the flagship CTA tape service is opt-in
 * (it exposes a storage-control surface). Extend the recognised-name list here as
 * more native services gain config gating.
 */
static char *
brix_ssi_service_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value = cf->args->elts;

    (void) cmd;
    if (value[1].len == 3 && ngx_strncmp(value[1].data, "cta", 3) == 0) {
        xcf->ssi_cta_enable = 1;
        return NGX_CONF_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown SSI service \"%V\" (known: cta)", &value[1]);
    return NGX_CONF_ERROR;
}

/* brix_tpc_source_allow <host> [host ...] — append EVERY argument to the TPC
 * source-host allowlist. The stock ngx_conf_set_str_array_slot keeps only the
 * first argument per directive, which for a SECURITY allowlist silently drops
 * every host after the first on a space-separated line (the same footgun that
 * bit brix_cvmfs_upstream_allow in the field). Both forms now work: one
 * directive per host, or one directive listing them all. */
char *
brix_tpc_conf_source_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value, *slot;
    ngx_uint_t                    i;

    (void) cmd;

    if (xcf->tpc_source_allow == NGX_CONF_UNSET_PTR) {
        xcf->tpc_source_allow = ngx_array_create(cf->pool, 4,
                                                 sizeof(ngx_str_t));
        if (xcf->tpc_source_allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        slot = ngx_array_push(xcf->tpc_source_allow);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }
        *slot = value[i];
    }
    return NGX_CONF_OK;
}

/*
 * Directive table.  Entries are grouped by feature (enable+root -> auth ->
 * security/TLS -> TPC -> write/observability -> cluster roles -> health ->
 * mirror -> rate-limit -> upstream -> cache/proxy -> write-through -> CMS ->
 * proxy mode -> OCSP -> SHM zones), demarcated by the inline comments below.
 * Most directives are NGX_STREAM_SRV_CONF; the SHM-zone ones
 * (brix_rate_limit_zone, brix_kv_zone) are NGX_STREAM_MAIN_CONF.
 * Enum value tables live in module_enums.c.
 */
ngx_command_t ngx_stream_brix_commands[] = {

    { ngx_string("brix_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      /* Custom setter because enabling the module also installs the handler. */
      ngx_stream_brix_enable,
      /* Store the parsed flag in the per-server stream config. */
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.enable),
      NULL },

    /* Accept kXR_bind secondary data connections (parallel reads).  ON by
     * default; set off to refuse bind so clients stream every request inline on
     * the primary connection (pathid 0) — required when fronting a client that
     * streams WRITE payloads on a substream, which BriX does not yet service. */
    { ngx_string("brix_data_substreams"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.data_substreams),
      NULL },

    /* Filesystem/export settings used by nearly every request handler. */
    { ngx_string("brix_export"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Single string argument copied into srv_conf->common.root. */
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.root),
      NULL },

    /* Marks this server as a trusted remote cache-STORE surface: internal
     * sidecar names (<key>.cinfo/.meta) become legitimate open/stat targets so a
     * cache node using `brix_cache_store root://...` with `brix_cache_meta
     * sidecar` can persist and re-read them. The HTTP planes carry the same
     * directive (module_commands.c); default OFF keeps every client-facing
     * export answering kXR_NotFound for a reserved name. */
    { ngx_string("brix_cache_store_endpoint"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.cache_store_endpoint),
      NULL },

    /* Selects the storage backend for this export: "posix" (default) or
     * "pblock" (block-based, rooted at brix_export; needs the sqlite build). */
    { ngx_string("brix_storage_backend"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.storage_backend),
      NULL },

    /* Names the brix_credential block (§14) the source backend authenticates
     * with; "" = anonymous. Today threads a bearer token into the sd_http source. */
    { ngx_string("brix_storage_credential"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.storage_credential),
      NULL },

    /* Phase 2 Task 6: per-user backend credentials on the root:// plane.
     * Directory of per-principal x509 proxy PEMs, keyed the same way as the
     * HTTP-plane feature (brix_sd_ucred_key); "" (default) = feature off. */
    { ngx_string("brix_storage_credential_dir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.storage_credential_dir),
      NULL },

    /* allow (default): fall back to the static service credential when no
     * per-user credential is found/valid. deny: refuse with EACCES/
     * kXR_NotAuthorized before the origin is ever contacted. */
    { ngx_string("brix_storage_credential_fallback"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.storage_credential_fallback),
      &brix_stream_credential_fallback_enum },

    /* Phase-70 §4: backend-leg credential strategy on the root:// plane —
     * mirrors brix_backend_delegation on the HTTP plane; enum → BRIX_CRED_*
     * stored on the shared `common` preamble. Default (SELECT) = today's
     * directory-lookup behaviour. */
    { ngx_string("brix_backend_delegation"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.backend_delegation),
      &brix_stream_backend_delegation_enum },

    /* Phase-70 §5.6 / P90-70.3: SSS identity-injection keytab — the delegation
     * gate re-issues an SSS credential asserting the CALLER's principal to the
     * origin, signed with this keytab (never the keytab's own principal).
     * Load-validated at config time; twin of the HTTP-plane directive. */
    { ngx_string("brix_backend_sss_keytab"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_backend_sss_keytab,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.backend_sss_keytab),
      NULL },

    /* Phase-70 §5.5: S3 STS credential EXCHANGE on the root:// plane — the
     * root://→s3:// origin leg authenticated AS the caller by trading the
     * node's S3 SERVICE credential (endpoint + ak + sk, optional role/region/
     * ttl) for temporary creds scoped to the caller's identity. Twins of the
     * HTTP-plane directives; the endpoint is load-validated at config time. */
    { ngx_string("brix_backend_s3_sts_endpoint"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_backend_sts_endpoint,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.backend_sts_endpoint),
      NULL },

    { ngx_string("brix_backend_s3_sts_role"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.backend_sts_role),
      NULL },

    { ngx_string("brix_backend_s3_sts_access_key"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.backend_sts_access_key),
      NULL },

    { ngx_string("brix_backend_s3_sts_secret_key"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.backend_sts_secret_key),
      NULL },

    { ngx_string("brix_backend_s3_sts_region"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.backend_sts_region),
      NULL },

    { ngx_string("brix_backend_s3_sts_ttl"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.backend_sts_ttl),
      NULL },

    { ngx_string("brix_backend_s3_sts_flavor"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.backend_sts_flavor),
      &brix_stream_sts_flavor_enum },

    /* Phase-70 §5.7: enable krb5 GSSAPI credential forwarding to the origin on
     * the root:// plane (where krb5 auth actually runs). Default off — the
     * gateway keeps SELECT/service-credential behaviour until an operator opts
     * in, at which point a forwardable inbound ticket is captured and replayed
     * to the backend AS the user. The flag lives on the shared `common`
     * preamble, mirroring the HTTP-plane directive in http_common.c. */
    { ngx_string("brix_backend_krb5_forwardable"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.backend_krb5_forwardable),
      NULL },

    /* Phase-3 Task 1: opt-in credential minting on the root:// plane — mirrors
     * brix_storage_credential_mint_ca/_mint_ttl on the HTTP plane (Phase-2 T9)
     * exactly. The mint fields live on the shared `common` preamble, so this
     * directive just needs its own stream-local setter (the HTTP one is
     * file-static) plus the num-slot for the TTL. No-op (minting stays off)
     * unless configured. */
    { ngx_string("brix_storage_credential_mint_ca"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
      brix_conf_set_stream_mint_ca,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_storage_credential_mint_ttl"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.storage_credential_mint_ttl),
      NULL },

    /* The reusable `brix_credential <name> { … }` identity block (§14), declared
     * once inside stream{} and referenced by brix_storage_credential. */
    { ngx_string("brix_credential"),
      NGX_STREAM_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
      brix_conf_credential_block,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* pblock stripe size for newly-written files (e.g. 64m); 0/unset = 64 MiB. */
    { ngx_string("brix_pblock_block_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.pblock_block_size),
      NULL },

    /* ---- tier-grammar directives (split into directives_tier.h) ---- */
#include "directives_tier.h"
    /* ---- authentication directives (split into directives_auth.h) ---- */
#include "directives_auth.h"

    /* ---- wire security + codec directives (split into directives_security.h) ---- */
#include "directives_security.h"

    /* ---- TPC directives (split into directives_tpc.h) ---- */
#include "directives_tpc.h"
    /* Optional observability and runtime-tuning directives. */
    { ngx_string("brix_access_log"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Path to the module-specific access log, opened during postconfiguration. */
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, access_log),
      NULL },

    { ngx_string("brix_session_log"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, session_log),
      NULL },

    /* Manager-mode: static prefix -> backend mapping (manager/redirector). */
    { ngx_string("brix_manager_map"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
      brix_conf_set_manager_map,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Dynamic manager mode: query server registry in kXR_open / kXR_locate. */
    { ngx_string("brix_manager_mode"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, manager_mode),
      NULL },

    /* ---- node capability directives (split into directives_caps.h) ---- */
#include "directives_caps.h"

    /* Per-connection in-flight pipeline window (out_ring + rd_pool slots).  A
     * deeper pipeline absorbs more wire latency/jitter (packet reordering,
     * high-BDP links) at a per-slot memory cost.  Clamped to [MIN,MAX] at merge. */
    { ngx_string("brix_pipeline_depth"),
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, pipeline_depth),
      NULL },

    /* Phase 20: session registry capacity (brix_session_slots). */
    { ngx_string("brix_session_slots"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, session_slots),
      NULL },

    /* ---- durable async backend-op queue (brix_backend_async{,_batch,_wait}) ----
     * Route backend mutations through the durable coalescing queue; park the client
     * until the batch flushes in bulk to the backend. */
    { ngx_string("brix_backend_async"),
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, backend_async),
      NULL },
    { ngx_string("brix_backend_async_batch"),
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, backend_async_batch),
      NULL },
    { ngx_string("brix_backend_async_wait"),
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, backend_async_wait),
      NULL },

    /* ---- clustering/proxy/traffic directives (split into directives_net.h) ---- */
#include "directives_net.h"

    /* ---- read-through cache directives (split into directives_cache.h) ---- */
#include "directives_cache.h"

    /* ---- write-through directives (split into directives_writethrough.h) ---- */
#include "directives_writethrough.h"
    /* ---- CMS clustering directives (split into directives_cms.h) ---- */
#include "directives_cms.h"

    /* (legacy brix_proxy_path_rewrite removed — see the note above) */

    /* OCSP certificate status checking and stapling. */
    { ngx_string("brix_ocsp_enable"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ocsp.enable),
      NULL },

    { ngx_string("brix_ocsp_soft_fail"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ocsp.soft_fail),
      NULL },

    /* A-6 item 2: hard-fail a nonce-less OCSP response (replay guard); opt-in. */
    { ngx_string("brix_ocsp_require_nonce"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ocsp.require_nonce),
      NULL },

    { ngx_string("brix_ocsp_stapling"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ocsp.stapling),
      NULL },

    /* ---- SHM zone directives (split into directives_zones.h) ---- */
#include "directives_zones.h"

    /* ---- SciTags pmark directives (split into directives_pmark.h) ---- */
#include "directives_pmark.h"

    /* Required terminator so nginx knows where the directive table ends. */
    ngx_null_command
};
