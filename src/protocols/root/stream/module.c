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

#include "core/ngx_xrootd_module.h"
#include "net/proxy/proxy.h"
#include "net/proxy/proxy_internal.h"
#include "protocols/root/handoff/handoff.h"
#include "protocols/root/relay/relay.h"
#include "auth/token/token_cache.h"   /* xrootd_token_cache_directive */
#include "net/manager/health_check.h" /* XROOTD_HC_TYPE_* */
#include "net/mirror/stream_mirror.h" /* Phase 24: traffic mirror directives */
#include "net/ratelimit/ratelimit.h"  /* Phase 25: advanced rate-limit directives */
#include "auth/impersonate/lifecycle.h" /* Phase 40: impersonation directives */
#include "net/cms/cns.h"               /* §6 CNS mode enum */
#include "core/config/credential_block.h" /* §14 xrootd_credential block directive */
#include "module_enums.h"   /* directive enum value tables */

/* phase-64: xrootd_stage_flush sync|async value map (0 = sync, 1 = async). */
static ngx_conf_enum_t  xrootd_stage_flush_enum[] = {
    { ngx_string("sync"),  0 },
    { ngx_string("async"), 1 },
    { ngx_null_string,     0 }
};

/* phase-64: xrootd_cache_meta map (XROOTD_CMETA_* in cache/cstore.h). */
static ngx_conf_enum_t  xrootd_cache_meta_enum[] = {
    { ngx_string("auto"),    0 },
    { ngx_string("local"),   1 },
    { ngx_string("xattr"),   2 },
    { ngx_string("sidecar"), 3 },
    { ngx_null_string,       0 }
};

/* §7 SSI: xrootd_ssi_cta_executor — simulated (test) vs real tier/frm (prod). */
static ngx_conf_enum_t  xrootd_ssi_executor_enum[] = {
    { ngx_string("test"), 0 },
    { ngx_string("prod"), 1 },
    { ngx_null_string,    0 }
};

/*
 * xrootd_ssi_service <name> — enable a non-default SSI provider. The built-in
 * test/reference services always resolve; the flagship CTA tape service is opt-in
 * (it exposes a storage-control surface). Extend the recognised-name list here as
 * more native services gain config gating.
 */
static char *
xrootd_ssi_service_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
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

/*
 * Directive table.  Entries are grouped by feature (enable+root -> auth ->
 * security/TLS -> TPC -> write/observability -> cluster roles -> health ->
 * mirror -> rate-limit -> upstream -> cache/proxy -> write-through -> CMS ->
 * proxy mode -> OCSP -> SHM zones), demarcated by the inline comments below.
 * Most directives are NGX_STREAM_SRV_CONF; the SHM-zone ones
 * (xrootd_rate_limit_zone, xrootd_kv_zone) are NGX_STREAM_MAIN_CONF.
 * Enum value tables live in module_enums.c.
 */
ngx_command_t ngx_stream_xrootd_commands[] = {

    { ngx_string("xrootd"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      /* Custom setter because enabling the module also installs the handler. */
      ngx_stream_xrootd_enable,
      /* Store the parsed flag in the per-server stream config. */
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.enable),
      NULL },

    /* Filesystem/export settings used by nearly every request handler. */
    { ngx_string("xrootd_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Single string argument copied into srv_conf->common.root. */
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.root),
      NULL },

    /* Selects the storage backend for this export: "posix" (default) or
     * "pblock" (block-based, rooted at xrootd_root; needs the sqlite build). */
    { ngx_string("xrootd_storage_backend"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.storage_backend),
      NULL },

    /* Names the xrootd_credential block (§14) the source backend authenticates
     * with; "" = anonymous. Today threads a bearer token into the sd_http source. */
    { ngx_string("xrootd_storage_credential"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.storage_credential),
      NULL },

    /* The reusable `xrootd_credential <name> { … }` identity block (§14), declared
     * once inside stream{} and referenced by xrootd_storage_credential. */
    { ngx_string("xrootd_credential"),
      NGX_STREAM_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
      xrootd_conf_credential_block,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* pblock stripe size for newly-written files (e.g. 64m); 0/unset = 64 MiB. */
    { ngx_string("xrootd_pblock_block_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.pblock_block_size),
      NULL },

    /* ---- phase-64 composable tier grammar (read-cache + write-stage tiers) ----
     * A cache/stage store URL composes an sd_cache / sd_stage decorator over the
     * storage backend (any driver). SP1 wires local posix stores; remote stores +
     * the credential=/block_size= store params land in SP2/SP3. */
    { ngx_string("xrootd_cache_store"),      /* <store-url> [credential=][block_size=] */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1234,
      xrootd_conf_set_store_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.cache_store),
      (void *) offsetof(ngx_stream_xrootd_srv_conf_t, common.cache_store_args) },

    { ngx_string("xrootd_stage"),            /* on|off: enable the write-stage tier */
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.stage_enable),
      NULL },

    { ngx_string("xrootd_stage_store"),      /* <store-url> [credential=][block_size=] */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1234,
      xrootd_conf_set_store_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.stage_store),
      (void *) offsetof(ngx_stream_xrootd_srv_conf_t, common.stage_store_args) },

    { ngx_string("xrootd_stage_flush"),      /* sync|async write-back to the backend */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.stage_flush_async),
      xrootd_stage_flush_enum },

    { ngx_string("xrootd_cache_max_object"), /* <size>: skip caching larger objects */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.cache_max_object),
      NULL },

    { ngx_string("xrootd_cache_evict_at"),   /* <pct> full -> begin evicting */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.cache_evict_at),
      NULL },

    { ngx_string("xrootd_cache_evict_to"),   /* <pct>: eviction target */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.cache_evict_to),
      NULL },

    { ngx_string("xrootd_cache_index_cache"),/* <n>: per-worker cinfo L1 entries */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.cache_index_cache),
      NULL },

    { ngx_string("xrootd_cache_meta"),       /* auto|local|xattr|sidecar */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.cache_meta_mode),
      xrootd_cache_meta_enum },

    { ngx_string("xrootd_cache_slice_size"), /* <size>: per-block slice fill (0=whole) */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.cache_slice_size),
      NULL },

    /*
     * Per-request UNIX impersonation (phase 40).  These write to a process-global
     * settings block (at most one identity broker per nginx instance), so the
     * custom setters ignore the conf object; the conf field is present only to
     * satisfy nginx's setter-call convention and the offset carries an
     * XROOTD_IMP_F_* selector for the multiplexed string/number setters.  Default
     * is `off` — nothing is spawned and no I/O is rerouted.
     */
    { ngx_string("xrootd_impersonation"),                 /* off | single | map */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_mode,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_impersonation_user"),            /* SINGLE: account */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      XROOTD_IMP_F_SINGLE_USER,
      NULL },

    { ngx_string("xrootd_impersonation_socket"),          /* MAP: broker socket */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      XROOTD_IMP_F_SOCKET,
      NULL },

    { ngx_string("xrootd_impersonation_export"),          /* MAP: confinement root */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      XROOTD_IMP_F_EXPORT_ROOT,
      NULL },

    { ngx_string("xrootd_gridmap"),                       /* MAP: DN->user file */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      XROOTD_IMP_F_GRIDMAP,
      NULL },

    { ngx_string("xrootd_idmap_default_user"),            /* MAP: squash account */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      XROOTD_IMP_F_DEFAULT_USER,
      NULL },

    { ngx_string("xrootd_idmap_min_uid"),                 /* MAP: reserved floor */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_num,
      NGX_STREAM_SRV_CONF_OFFSET,
      XROOTD_IMP_F_MIN_UID,
      NULL },

    { ngx_string("xrootd_idmap_cache_ttl"),               /* MAP: cache TTL secs */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_num,
      NGX_STREAM_SRV_CONF_OFFSET,
      XROOTD_IMP_F_CACHE_TTL,
      NULL },

    { ngx_string("xrootd_impersonation_broker_user"),     /* MAP: non-root broker acct */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      XROOTD_IMP_F_BROKER_USER,
      NULL },

    { ngx_string("xrootd_idmap_forbidden_users"),         /* deny-list target accounts */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      XROOTD_IMP_F_FORBIDDEN_USERS,
      NULL },

    { ngx_string("xrootd_idmap_forbidden_groups"),        /* deny-list privileged groups */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      XROOTD_IMP_F_FORBIDDEN_GROUPS,
      NULL },

    /* Selects the login/auth flow the dispatcher advertises to clients. */
    { ngx_string("xrootd_auth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Maps "none" / "gsi" onto XROOTD_AUTH_* constants via xrootd_auth_modes. */
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, auth),
      xrootd_auth_modes },

    /* The next three directives are only consumed when xrootd_auth=gsi. */
    /* PEM file containing the server certificate presented during GSI auth. */
    { ngx_string("xrootd_certificate"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, certificate),
      NULL },

    /* Matching private key used to sign the GSI handshake. */
    { ngx_string("xrootd_certificate_key"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, certificate_key),
      NULL },

    /* Trust store used to verify client proxy certificates. */
    { ngx_string("xrootd_trusted_ca"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, trusted_ca),
      NULL },

    /* GSI signed-DH policy: off (default) | auto | require.  Consulted only
     * when xrootd_auth=gsi; selects the RSA-signed-DH wire variant (phase-48). */
    { ngx_string("xrootd_gsi_signed_dh"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, gsi_signed_dh),
      xrootd_signed_dh_modes },

    /* Phase 51 (E4): per-worker concurrent in-flight GSI-handshake cap. */
    { ngx_string("xrootd_gsi_max_inflight_handshakes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, gsi_max_inflight),
      NULL },

    /* Per-worker ephemeral-DH keypool warm target (filled off-thread at boot). */
    { ngx_string("xrootd_gsi_keypool_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, gsi_keypool_size),
      NULL },

    /* Keys generated synchronously at worker start (rest fill off-thread). */
    { ngx_string("xrootd_gsi_keypool_seed"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, gsi_keypool_seed),
      NULL },

    /* Phase 52 (WS-A): GSI session-cipher advertise preference list. */
    { ngx_string("xrootd_gsi_ciphers"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, gsi_ciphers),
      NULL },

    { ngx_string("xrootd_vomsdir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, vomsdir),
      NULL },

    { ngx_string("xrootd_voms_cert_dir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, voms_cert_dir),
      NULL },

    /* PEM file or directory containing CRLs for certificate revocation checking. */
    { ngx_string("xrootd_crl"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, crl),
      NULL },

    /* Interval (seconds) to re-scan xrootd_crl and rebuild the CA/CRL store. */
    { ngx_string("xrootd_crl_reload"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, crl_reload),
      NULL },

    { ngx_string("xrootd_require_vo"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
      xrootd_conf_set_require_vo,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_authdb"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_authdb,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* XrdAcc engine selector + tunables (default: native engine). */
    { ngx_string("xrootd_authdb_format"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, acc_format),
      xrootd_authdb_format_modes },

    { ngx_string("xrootd_authdb_audit"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, acc_audit),
      xrootd_authdb_audit_modes },

    { ngx_string("xrootd_authdb_refresh"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, acc_refresh),
      NULL },

    { ngx_string("xrootd_acc_gidlifetime"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, acc_gidlifetime),
      NULL },

    { ngx_string("xrootd_acc_pgo"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, acc_pgo),
      NULL },

    { ngx_string("xrootd_acc_nisdomain"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, acc_nisdomain),
      NULL },

    { ngx_string("xrootd_acc_resolve_hosts"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, acc_resolve_hosts),
      NULL },

    { ngx_string("xrootd_acc_spacechar"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, acc_spacechar),
      NULL },

    { ngx_string("xrootd_acc_encoding"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, acc_encoding),
      NULL },

    { ngx_string("xrootd_acc_gidretran"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, acc_gidretran),
      NULL },

    { ngx_string("xrootd_inherit_parent_group"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_inherit_parent_group,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* JWT / WLCG bearer-token directives (used when xrootd_auth = token|both). */
    { ngx_string("xrootd_token_jwks"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, token_jwks),
      NULL },

    /* Millisecond interval for mtime-poll JWKS hot refresh (0 = disabled). */
    { ngx_string("xrootd_token_jwks_refresh_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, token_jwks_refresh_interval),
      NULL },

    { ngx_string("xrootd_token_issuer"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, token_issuer),
      NULL },

    { ngx_string("xrootd_token_audience"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, token_audience),
      NULL },

    { ngx_string("xrootd_token_config"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, token_config),
      NULL },

    { ngx_string("xrootd_throttle_zone"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, throttle_zone_name),
      NULL },

    { ngx_string("xrootd_throttle_max_open_files"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, throttle_max_open_files),
      NULL },

    { ngx_string("xrootd_throttle_max_active_connections"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, throttle_max_active_conn),
      NULL },

    { ngx_string("xrootd_csi"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, csi_enable),
      NULL },

    { ngx_string("xrootd_csi_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, csi_prefix),
      NULL },

    { ngx_string("xrootd_csi_fill"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, csi_fill),
      NULL },

    { ngx_string("xrootd_csi_require"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, csi_require),
      NULL },

    { ngx_string("xrootd_csi_loose"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, csi_loose),
      NULL },
 
    { ngx_string("xrootd_macaroon_secret"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, token_macaroon_secret),
      NULL },

    { ngx_string("xrootd_macaroon_secret_old"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, token_macaroon_secret_old),
      NULL },

    /* XRootD Simple Shared Secret keytab (generated by xrdsssadmin). */
    { ngx_string("xrootd_sss_keytab"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, sss_keytab),
      NULL },

    /* Kerberos 5 service principal and optional keytab for XrdSeckrb5. */
    { ngx_string("xrootd_krb5_principal"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, krb5_principal),
      NULL },

    { ngx_string("xrootd_krb5_keytab"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, krb5_keytab),
      NULL },

    { ngx_string("xrootd_krb5_ip_check"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, krb5_ip_check),
      NULL },

    /* Upstream-compatible unix credentials are self-asserted; keep remote
     * peers disabled unless an operator explicitly trusts the network. */
    /* Phase 52 (WS-C): host-auth reverse-DNS allowlist (exact or ".suffix"). */
    { ngx_string("xrootd_host_allow"),
      NGX_STREAM_SRV_CONF | NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, host_allow),
      NULL },

    /* Phase 52 (WS-B): XrdSecpwd password database (opt-in; deny if unset). */
    { ngx_string("xrootd_pwd_file"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, pwd_file),
      NULL },

    { ngx_string("xrootd_unix_trust_remote"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, unix_trust_remote),
      NULL },

    /* Minimum signing level: none, compatible, standard, intense, pedantic. */
    { ngx_string("xrootd_security_level"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, security_level),
      xrootd_security_levels },

    /* Enable kXR_ableTLS in-protocol TLS upgrade using xrootd_certificate/key. */
    { ngx_string("xrootd_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tls),
      NULL },

    /* Enable kernel-TLS (SSL_OP_ENABLE_KTLS) so TLS reads can use sendfile.
     * Default off — only beneficial with hardware TLS-offload NICs; software
     * kTLS is slower than userspace OpenSSL on AES-NI CPUs (Phase 29). */
    { ngx_string("xrootd_ktls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tls_ktls),
      NULL },

    /* Enable root:// inline read compression (phase-42 W4). Opt-in, off by
     * default and invisible to stock peers: advertises codecs via Qconfig
     * "cmpread" and compresses kXR_read responses for clients that open with
     * "?xrootd.compress=<codec>".  pgread/readv remain plaintext. */
    { ngx_string("xrootd_read_compress"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, read_compress),
      NULL },

    /* Enable root:// inline write decompression (phase-42 W5). Opt-in, off by
     * default and invisible to stock peers: advertises codecs via Qconfig
     * "cmpwrite" and decompresses kXR_write payloads for clients that open for
     * write with "?xrootd.compress=<codec>".  pgwrite remains plaintext. */
    { ngx_string("xrootd_write_compress"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, write_compress),
      NULL },

    /* Enable ZIP member access (phase-57 W2). Opt-in, off by default: a read
     * open with "?xrdcl.unzip=<member>" serves that member of the archive as a
     * standalone read-only file. */
    { ngx_string("xrootd_zip_access"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, zip_access),
      NULL },

    /* Cap the ZIP central-directory read (bomb guard); default 16 MiB. */
    { ngx_string("xrootd_zip_cd_max_bytes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, zip_cd_max_bytes),
      NULL },

    /* Materialize-to-scratch for ZIP member access (a no-kernel-fd backend, or a
     * test): copy the archive into this local POSIX scratch dir and read there. */
    { ngx_string("xrootd_zip_stage_dir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, zip_stage_dir),
      NULL },

    /* Force the archive through scratch even on a POSIX export (tests / policy). */
    { ngx_string("xrootd_zip_force_scratch"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, zip_force_scratch),
      NULL },

    /* Decline staging archives larger than this (default 512 MiB). */
    { ngx_string("xrootd_zip_stage_max_bytes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, zip_stage_max_bytes),
      NULL },

    /* Allow TPC pulls from loopback / link-local addresses (default: off). */
    { ngx_string("xrootd_tpc_allow_local"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_allow_local),
      NULL },

    /* Allow TPC pulls from RFC-1918 private addresses (default: on). */
    { ngx_string("xrootd_tpc_allow_private"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_allow_private),
      NULL },

    /* §7 unary XrdSsi request/response over /.ssi/<service> (default: off). */
    { ngx_string("xrootd_ssi"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ssi_enable),
      NULL },

    /* §7 SSI: enable a non-default provider (cta). Opt-in. */
    { ngx_string("xrootd_ssi_service"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_ssi_service_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* §7 SSI: concurrent requests per session (<= compile-time max). */
    { ngx_string("xrootd_ssi_max_inflight"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ssi_max_inflight),
      NULL },

    /* §7 SSI: per-request / per-response byte caps. */
    { ngx_string("xrootd_ssi_request_max"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ssi_request_max),
      NULL },

    { ngx_string("xrootd_ssi_response_max"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ssi_response_max),
      NULL },

    /* §7 SSI: flagship CTA service — restart journal + executor backend. */
    { ngx_string("xrootd_ssi_cta_journal"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ssi_cta_journal),
      NULL },

    { ngx_string("xrootd_ssi_cta_executor"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ssi_cta_executor),
      &xrootd_ssi_executor_enum },

    /* §6 Composite Cluster Name Space: off | emit (data server) | collect (mgr). */
    { ngx_string("xrootd_cns"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cns_mode),
      &xrootd_cns_modes },

    /* phase-57 §F5: upgrade the TPC pull to TLS when the source sends
     * kXR_gotoTLS (advertise kXR_ableTLS outbound). Default: off. */
    { ngx_string("xrootd_tpc_outbound_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_outbound_tls),
      NULL },

    /* phase-57 §F6: X.509 proxy delegation (capture client proxy → present to
     * source as the user). Default: off. Reserved — crypto pending its stock
     * -dlgpxy:request interop gate (tests/test_tpc_delegation.py). */
    { ngx_string("xrootd_tpc_delegate"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_delegate),
      NULL },

    /* TPC rendezvous key lifetime in the shared registry (default: 60s). */
    { ngx_string("xrootd_tpc_key_ttl"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_key_ttl_ms),
      NULL },

    /* Phase 39 (WS4): wall-clock cap on a native TPC pull (0 = no cap). */
    { ngx_string("xrootd_tpc_max_transfer_secs"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_max_transfer_secs),
      NULL },

    /* Phase 39 (WS5): abandoned-TPC-slot reaper age in seconds (0 = disabled). */
    { ngx_string("xrootd_tpc_transfer_max_age"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_transfer_max_age),
      NULL },

    /* JWT file for outbound native TPC pulls when the source requires ztn. */
    { ngx_string("xrootd_tpc_outbound_bearer_file"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_outbound_bearer_file),
      NULL },

    /* OAuth2/OIDC token endpoint for RFC 8693 token exchange on TPC pulls. */
    { ngx_string("xrootd_tpc_outbound_token_endpoint"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_outbound_token_endpoint),
      NULL },

    /* OAuth2 client ID for confidential client token exchange. */
    { ngx_string("xrootd_tpc_outbound_client_id"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_outbound_client_id),
      NULL },

    /* OAuth2 client secret for confidential client token exchange. */
    { ngx_string("xrootd_tpc_outbound_client_secret"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_outbound_client_secret),
      NULL },

    /* Scope string for token exchange (default: "storage.read"). */
    { ngx_string("xrootd_tpc_outbound_scope"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_outbound_scope),
      NULL },

    /* Write handlers still perform per-op auth checks; this only enables the feature. */
    { ngx_string("xrootd_allow_write"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      /* Standard boolean setter writing into srv_conf->common.allow_write. */
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.allow_write),
      NULL },

    /* Hard read-only: when on, forces allow_write off so all writes are rejected
     * at the protocol edge (before the VFS, before token scope). Overrides
     * xrootd_allow_write on. */
    { ngx_string("xrootd_read_only"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.read_only),
      NULL },

    /* Optional observability and runtime-tuning directives. */
    { ngx_string("xrootd_access_log"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Path to the module-specific access log, opened during postconfiguration. */
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, access_log),
      NULL },

    /* Manager-mode: static prefix -> backend mapping (manager/redirector). */
    { ngx_string("xrootd_manager_map"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
      xrootd_conf_set_manager_map,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Dynamic manager mode: query server registry in kXR_open / kXR_locate. */
    { ngx_string("xrootd_manager_mode"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, manager_mode),
      NULL },

    /* Phase 2 capability-flag role directives. */
    { ngx_string("xrootd_metadata_only"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, metadata_only),
      NULL },

    { ngx_string("xrootd_supervisor"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, supervisor),
      NULL },

    { ngx_string("xrootd_virtual_redirector"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, virtual_redirector),
      NULL },

    /* Phase 3 behavioral capability flag directives. */
    { ngx_string("xrootd_collapse_redir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, collapse_redir),
      NULL },

    { ngx_string("xrootd_collapse_redir_ttl"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, collapse_redir_ttl),
      NULL },

    { ngx_string("xrootd_recover_writes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, recover_writes),
      NULL },

    { ngx_string("xrootd_upload_resume"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, upload_resume),
      NULL },

    { ngx_string("xrootd_stage_dir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, upload_stage_dir),
      NULL },

    { ngx_string("xrootd_registry_slots"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, registry_slots),
      NULL },

    /* Per-connection in-flight pipeline window (out_ring + rd_pool slots).  A
     * deeper pipeline absorbs more wire latency/jitter (packet reordering,
     * high-BDP links) at a per-slot memory cost.  Clamped to [MIN,MAX] at merge. */
    { ngx_string("xrootd_pipeline_depth"),
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, pipeline_depth),
      NULL },

    /* Phase 20: session registry capacity (xrootd_session_slots). */
    { ngx_string("xrootd_session_slots"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, session_slots),
      NULL },

    /* Phase 20: manager redirect-collapse cache capacity
     * (xrootd_redir_cache_slots). */
    { ngx_string("xrootd_redir_cache_slots"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, redir_cache_slots),
      NULL },

    /* Phase 22: active health checks (off by default) */    { ngx_string("xrootd_health_check"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, hc_enabled),
      NULL },

    { ngx_string("xrootd_health_check_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, hc_interval_ms),
      NULL },

    { ngx_string("xrootd_health_check_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, hc_timeout_ms),
      NULL },

    { ngx_string("xrootd_health_check_threshold"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, hc_threshold),
      NULL },

    { ngx_string("xrootd_health_check_blacklist"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, hc_blacklist_ms),
      NULL },

    { ngx_string("xrootd_health_check_type"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, hc_type),
      xrootd_hc_types },

    /* Phase 24: traffic mirroring (off by default) */    { ngx_string("xrootd_stream_mirror_url"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_stream_mirror_set_url,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_mirror_opcodes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_1MORE,
      xrootd_stream_mirror_set_opcodes,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_mirror_exclude_opcodes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_1MORE,
      xrootd_stream_mirror_set_exclude_opcodes,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_mirror_sample"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, mirror.sample_pct),
      NULL },

    { ngx_string("xrootd_mirror_strip_auth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, mirror.strip_auth),
      NULL },

    /* Opt-in gate for replaying WRITE/mutation opcodes to the shadow.  Off by
     * default; the shadow MUST be an isolated namespace (a separate server/root),
     * never the primary's backing store. */
    { ngx_string("xrootd_mirror_writes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, mirror.mirror_writes),
      NULL },

    { ngx_string("xrootd_mirror_log_diverge"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, mirror.log_diverge),
      NULL },

    { ngx_string("xrootd_mirror_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, mirror.timeout_ms),
      NULL },

    /* Phase 25: advanced rate limiting / traffic shaping */    { ngx_string("xrootd_rate_limit_zone"),     /* stream main: zone=NAME:SIZE */
      NGX_STREAM_MAIN_CONF | NGX_CONF_1MORE,
      xrootd_rl_zone_directive,
      0,
      0,
      NULL },

    { ngx_string("xrootd_rate_limit_rule"),     /* srv: request-rate rule */
      NGX_STREAM_SRV_CONF | NGX_CONF_2MORE,
      xrootd_rl_rule_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, rl_rules),
      NULL },

    { ngx_string("xrootd_bandwidth_limit"),     /* srv: bandwidth rule */
      NGX_STREAM_SRV_CONF | NGX_CONF_2MORE,
      xrootd_rl_bw_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, rl_rules),
      NULL },

    { ngx_string("xrootd_concurrency_limit"),   /* srv: W7 in-flight cap */
      NGX_STREAM_SRV_CONF | NGX_CONF_2MORE,
      xrootd_rl_conc_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, rl_rules),
      NULL },

    /* Dynamic upstream XRootD redirector (host:port to query for redirects). */
    { ngx_string("xrootd_upstream"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_upstream,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_upstream_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, upstream_tls),
      NULL },

    { ngx_string("xrootd_upstream_tls_ca"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, upstream_tls_ca),
      NULL },

    { ngx_string("xrootd_upstream_tls_name"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, upstream_tls_name),
      NULL },

    { ngx_string("xrootd_upstream_token_file"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, upstream_token_file),
      NULL },

    /* kXR_prepare / kXR_stage tape-backend dispatch hook */
    { ngx_string("xrootd_prepare_command"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, prepare_command),
      NULL },

    /* ---- legacy FRM directives (xrootd_frm*) DISABLED 2026-06-30 -------------
     * The Phase-35 FRM durable-tape-staging directive surface (xrootd_frm,
     * _queue_path, _max_inflight, _max_per_source, _stagecmd, _copycmd, _copymax,
     * _stage_ttl, _xfrhold, _stage_wait, _async_recall, _fail_backoff,
     * _fail_retries, _residency_cmd, _stage_dir, _force_scratch, _control_dir,
     * _copy_timeout, _migrate_copycmd, _purge_watermark, _purge_interval) is
     * removed ahead of deleting the now-unused FRM implementation. It is superseded
     * by the phase-64 tier/nearline backend (sd_frm). A config still using any of
     * these now fails with nginx "unknown directive". The frm.* conf fields,
     * handlers and runtime remain temporarily (no longer reachable from config) and
     * are scheduled for removal. */

    /* cache/proxy directives (merged into ngx_stream_xrootd_commands[]) */
    /* Read-through cache mode: serve from a local cache_root and fill misses. */
    { ngx_string("xrootd_cache"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache),
      NULL },

    { ngx_string("xrootd_cache_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_root),
      NULL },

    /* §14 (phase-64): the legacy cache-origin config model is RETIRED. The
     * directives xrootd_cache_origin{,_tls,_proxy,_cadir,_client,_token_file,
     * _forward_token,_s3_*} are deleted — a cache's source is the export's
     * xrootd_storage_backend, its identity a named xrootd_credential attached
     * via xrootd_storage_credential (x509_proxy/ca_dir, token, s3_access_key/
     * s3_secret_key/s3_region, sss_keytab), and the physical cache is
     * xrootd_cache_store. cache_origin_family survives below: it is the connect
     * address-family policy for the tier root:// backend, not an origin knob. */

    { ngx_string("xrootd_cache_origin_family"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_origin_family,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_cache_lock_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_lock_timeout),
      NULL },

    { ngx_string("xrootd_cache_eviction_threshold"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_eviction_threshold,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Files larger than this are not cached unless their basename matches the
     * include regex below.  Accepts bytes with optional k/m/g suffix.  0 = no limit. */
    { ngx_string("xrootd_cache_max_file_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_max_file_size,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Unified cache-state engine: where .cinfo persistence records live ("" ⇒
     * cache_root), how long a dirty write-back staging file may sit before the
     * reaper removes it (secs; 0 = off), and read-cache admission prefixes (parity
     * with xrootd_wt_{allow,deny}_prefix). */
    { ngx_string("xrootd_cache_state_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_state_root),
      NULL },

    { ngx_string("xrootd_cache_dirty_max_age"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_dirty_max_age),
      NULL },

    /* Watermark-driven LRU reaper: a background timer purges the read cache
     * oldest-first when filesystem occupancy crosses the HIGH watermark, down to
     * the LOW watermark (hysteresis). Watermarks accept 0.9 or 90%; the interval
     * is in seconds. cache_eviction_threshold remains the on-fill safety net and
     * the default for HIGH when these are unset. */
    { ngx_string("xrootd_cache_high_watermark"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_watermark,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_high_watermark),
      NULL },

    { ngx_string("xrootd_cache_low_watermark"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_watermark,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_low_watermark),
      NULL },

    { ngx_string("xrootd_cache_reap_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_reap_interval),
      NULL },

    { ngx_string("xrootd_cache_deny_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_deny_prefix,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_cache_allow_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_allow_prefix,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* §14 (phase-64): xrootd_cache_storage_backend/_block_size are RETIRED —
     * a driver-backed cache is the tier grammar's xrootd_cache_store
     * ("pblock:<dir> block_size=<n>", any driver), cinfo carried in-store. */

    { ngx_string("xrootd_cache_wt_stage_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_wt_stage_root),
      NULL },

    { ngx_string("xrootd_cache_wt_stage_backend"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_wt_stage_backend),
      NULL },

    { ngx_string("xrootd_cache_wt_stage_block_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_wt_stage_block_size),
      NULL },

    /* Two-tier write-back-staging backpressure: occupancy of the staging
     * filesystem in [low,high) delays new write-opens/PUTs (kXR_wait/503); at/
     * above high they are rejected (kXR_Overloaded/429) until it drains below
     * low. Reads are never throttled. Accepts 0.9 or 90%. No-op unless a staging
     * root is configured. */
    { ngx_string("xrootd_wt_stage_high_watermark"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_watermark,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_wt_stage_high_watermark),
      NULL },

    { ngx_string("xrootd_wt_stage_low_watermark"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_watermark,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_wt_stage_low_watermark),
      NULL },

    /* Phase 31 W4: SHM-global transfer-heap budget.  A read that would push the
     * live transfer-buffer total past this is deferred with kXR_wait.  Accepts
     * bytes with optional k/m/g suffix.  0 = no cap.  Default 768m. */
    { ngx_string("xrootd_memory_budget"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, memory_budget),
      NULL },

    /* Max bytes served per kXR_readv element (the official "maxReadv_ior"). A
     * segment requesting more is capped to this and the client re-reads the tail.
     * Accepts bytes with optional k/m/g suffix. Default 2097136 (stock XRootD:
     * maxBuffsz 2 MiB - 16-byte readahead_list). */
    { ngx_string("xrootd_readv_segment_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, readv_segment_size),
      NULL },

    /* Phase 44: optional io_uring disk-I/O backend (off/auto/on; default auto).
     * `on` requires the backend — startup fails if it is not compiled in or the
     * runtime probe fails (xrootd_uring_validate_conf, §32 fail-fast). */
    { ngx_string("xrootd_io_uring"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, io_uring),
      &xrootd_io_uring_modes },

    { ngx_string("xrootd_io_uring_queue_depth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, io_uring_queue_depth),
      NULL },

    { ngx_string("xrootd_io_uring_panic_file"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, io_uring_panic_file),
      NULL },

    { ngx_string("xrootd_io_uring_admin"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, io_uring_admin),
      NULL },

    { ngx_string("xrootd_io_uring_restrict"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, io_uring_restrict),
      NULL },

    /* §14 (phase-64): the legacy xrootd_cache_slice is RETIRED — slice/partial
     * caching is the tier grammar's xrootd_cache_slice_size (same 1 MiB-multiple
     * validation), served by the composed sd_cache partial path (§6.5). */

    /* POSIX extended regular expression matched against the path basename.
     * Matching files are admitted to cache even if they exceed the size limit. */
    { ngx_string("xrootd_cache_include_regex"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_include_regex,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* write-through mode directives (mirrors XrdPfc configuration from
     * /tmp/xrootd-src/src/XrdPfc/README) ---- */

    { ngx_string("xrootd_write_through"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      xrootd_conf_set_wt_enable,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_wt_mode"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_wt_mode,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_wt_origin"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_wt_origin,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Names the xrootd_credential block (§14) the write-back flush authenticates to
     * the wt_origin with (ztn bearer); "" = anonymous. Composes C-3-token + C-5 for
     * an authenticated write-back round-trip. */
    { ngx_string("xrootd_wt_credential"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, wt_credential),
      NULL },

    /* Repeatable: path prefix that is NEVER write-through (deny list). */
    { ngx_string("xrootd_wt_deny_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_wt_deny_prefix,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Repeatable: path prefix that is ALWAYS write-through (allow list). */
    { ngx_string("xrootd_wt_allow_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_wt_allow_prefix,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Optional CMS manager registration/heartbeat. */
    { ngx_string("xrootd_cms_manager"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cms_manager,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_cms_paths"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_paths),
      NULL },

    { ngx_string("xrootd_cms_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_interval),
      NULL },

    { ngx_string("xrootd_cms_locate_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_locate_timeout),
      NULL },

    /* Phase 50: CMS client (node->manager) resilience deadlines. */
    { ngx_string("xrootd_cms_read_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_read_timeout),
      NULL },

    { ngx_string("xrootd_cms_send_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_send_timeout),
      NULL },

    /* Fast cold-start mesh settling (pre-first-login window only). */
    { ngx_string("xrootd_cms_initial_delay"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_initial_delay),
      NULL },

    { ngx_string("xrootd_cms_connect_retry"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_connect_retry),
      NULL },

    { ngx_string("xrootd_cms_tcp_keepalive"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_tcp_keepalive),
      NULL },

    { ngx_string("xrootd_cms_tcp_user_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_tcp_user_timeout),
      NULL },

    { ngx_string("xrootd_listen_port"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, listen_port),
      NULL },

    { ngx_string("xrootd_ckscan_depth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ckscan_max_depth),
      NULL },

    { ngx_string("xrootd_ckscan_max_files"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ckscan_max_files),
      NULL },

    /*
     * Async pread/pwrite support is only compiled when nginx itself was built
     * with thread-pool support.
     */
    { ngx_string("xrootd_thread_pool"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Names an nginx thread_pool block to service async disk I/O. */
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.thread_pool_name),
      NULL },

    /* ---- legacy stream proxy directives (xrootd_proxy*) DISABLED 2026-06-30 ----
     * The legacy stream cache-origin proxy directive surface (xrootd_proxy,
     * _upstream, _upstream_tls[_ca|_name], _auth, _login_user, _audit_log,
     * _reconnect_attempts, _connect_timeout, _read_timeout, _write_timeout,
     * _keepalive_interval, _path_rewrite) is removed ahead of deleting the unused
     * proxy implementation; a config using any of them now fails with nginx
     * "unknown directive". Handlers/runtime remain temporarily, scheduled for
     * removal. NOT affected: xrootd_http_handoff (single-port handoff, retained
     * below) and xrootd_cache_origin_proxy (phase-64 tier origin). */

    /* single-port protocol handoff: splice a non-XRootD (HTTP/TLS) client on
     * this stream port to a local HTTP/WebDAV listener (host:port). */
    { ngx_string("xrootd_http_handoff"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_http_handoff,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* transparent pass-through relay: relay every connection on this port
     * verbatim to an upstream XRootD server while a tap decodes the cleartext
     * frames (src/relay/relay.c). */
    { ngx_string("xrootd_transparent_proxy"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_transparent_proxy,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* bad-actor guard on the transparent relay: classify each tapped frame
     * (src/net/guard/), drop junk-signature / off-grammar connections, and
     * audit notfound/authfail responses for fail2ban (relay/relay_guard.c). */
    { ngx_string("xrootd_guard_stream"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, relay_guard_enable),
      NULL },

    /* terminating tap proxy (src/proxy/): authenticate the client locally, then
     * re-authenticate upstream as the user (anonymous/ztn/SSS/username) and
     * forward opcode-by-opcode while the tap decodes the now-plaintext frames. */
    { ngx_string("xrootd_tap_proxy"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_enable),
      NULL },

    { ngx_string("xrootd_tap_proxy_upstream"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE12,
      xrootd_conf_set_proxy_upstream,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_tap_proxy_auth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_proxy_auth,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_tap_proxy_login_user"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_proxy_login_user,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_tap_proxy_audit_log"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_audit_log),
      NULL },

    { ngx_string("xrootd_tap_proxy_upstream_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_upstream_tls),
      NULL },

    /* (legacy xrootd_proxy_* directives removed here — see the note above) */

    /* Phase 39: network-fault resilience (all off by default; 0 = disabled). */
    { ngx_string("xrootd_read_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, read_timeout),
      NULL },

    { ngx_string("xrootd_handshake_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, handshake_timeout),
      NULL },

    { ngx_string("xrootd_send_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, send_timeout),
      NULL },

    { ngx_string("xrootd_tcp_user_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tcp_user_timeout),
      NULL },

    /* Per-socket TCP congestion control at accept (e.g. "bbr") — the sender's CC
     * governs download throughput; BBR ignores reordering's spurious loss signals. */
    { ngx_string("xrootd_tcp_congestion"),
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tcp_congestion),
      NULL },

    { ngx_string("xrootd_tcp_keepalive"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tcp_keepalive),
      NULL },

    { ngx_string("xrootd_max_connections"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, max_connections),
      NULL },

    /* Phase 39 (WS7): data-server staleness threshold for cluster selection. */
    { ngx_string("xrootd_manager_stale_after"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, manager_stale_after),
      NULL },

    /* (legacy xrootd_proxy_path_rewrite removed — see the note above) */

    /* OCSP certificate status checking and stapling. */
    { ngx_string("xrootd_ocsp_enable"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ocsp_enable),
      NULL },

    { ngx_string("xrootd_ocsp_soft_fail"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ocsp_soft_fail),
      NULL },

    { ngx_string("xrootd_ocsp_stapling"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ocsp_stapling),
      NULL },

    /* Phase 20: shared-memory KV zones, caches, and rate limiting */
    /* xrootd_kv_zone <name> <size> key=<bytes> val=<bytes>;  (stream main) */
    { ngx_string("xrootd_kv_zone"),
      NGX_STREAM_MAIN_CONF | NGX_CONF_2MORE,
      xrootd_kv_zone_directive,
      0,
      0,
      NULL },

    /* xrootd_token_cache zone=<name>; */
    { ngx_string("xrootd_token_cache"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_token_cache_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, token_cache_kv),
      NULL },

    /* xrootd_auth_cache zone=<name> [ttl=<seconds>]; */
    { ngx_string("xrootd_auth_cache"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE12,
      xrootd_auth_cache_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, auth_cache),
      NULL },

    /* xrootd_rate_limit zone=<name> rate=<N>r/s burst=<N> [key=dn|ip]; */
    { ngx_string("xrootd_rate_limit"),
      NGX_STREAM_SRV_CONF | NGX_CONF_2MORE,
      xrootd_rate_limit_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, rate_limit),
      NULL },

    /* SciTags packet marking (src/pmark/) — see phase-34 doc */    { ngx_string("xrootd_pmark"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.pmark.enable), NULL },
    { ngx_string("xrootd_pmark_firefly"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.pmark.firefly), NULL },
    { ngx_string("xrootd_pmark_flowlabel"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.pmark.flowlabel), NULL },
    { ngx_string("xrootd_pmark_scitag_cgi"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.pmark.scitag_cgi), NULL },
    { ngx_string("xrootd_pmark_firefly_origin"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.pmark.firefly_origin), NULL },
    { ngx_string("xrootd_pmark_http_plain"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.pmark.http_plain), NULL },
    { ngx_string("xrootd_pmark_echo"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.pmark.echo), NULL },
    { ngx_string("xrootd_pmark_appname"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.pmark.appname), NULL },
    { ngx_string("xrootd_pmark_defsfile"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.pmark.defsfile), NULL },
    { ngx_string("xrootd_pmark_domain"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, xrootd_pmark_set_domain,
      NGX_STREAM_SRV_CONF_OFFSET, 0, NULL },
    { ngx_string("xrootd_pmark_firefly_dest"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, xrootd_pmark_set_firefly_dest,
      NGX_STREAM_SRV_CONF_OFFSET, 0, NULL },
    { ngx_string("xrootd_pmark_map_experiment"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE23, xrootd_pmark_set_map_experiment,
      NGX_STREAM_SRV_CONF_OFFSET, 0, NULL },
    { ngx_string("xrootd_pmark_map_activity"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE3 | NGX_CONF_TAKE4,
      xrootd_pmark_set_map_activity,
      NGX_STREAM_SRV_CONF_OFFSET, 0, NULL },

    /* Required terminator so nginx knows where the directive table ends. */
    ngx_null_command
};
