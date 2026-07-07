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
#include "auth/impersonate/lifecycle.h" /* Phase 40: impersonation directives */
#include "net/cms/cns.h"               /* §6 CNS mode enum */
#include "core/config/credential_block.h" /* §14 brix_credential block directive */
#include "module_enums.h"   /* directive enum value tables */
#include "core/config/tier_directives.h"   /* shared tier-grammar X-macro */

/* §7 SSI: brix_ssi_cta_executor — simulated (test) vs real tier/frm (prod). */
static ngx_conf_enum_t  brix_ssi_executor_enum[] = {
    { ngx_string("test"), 0 },
    { ngx_string("prod"), 1 },
    { ngx_null_string,    0 }
};

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

    /* Filesystem/export settings used by nearly every request handler. */
    { ngx_string("brix_export"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Single string argument copied into srv_conf->common.root. */
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.root),
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

    /* ---- tier-grammar directives (split into directives_tier.inc) ---- */
#include "directives_tier.inc"
    /* ---- authentication directives (split into directives_auth.inc) ---- */
#include "directives_auth.inc"

    /* ---- wire security + codec directives (split into directives_security.inc) ---- */
#include "directives_security.inc"

    /* ---- TPC directives (split into directives_tpc.inc) ---- */
#include "directives_tpc.inc"
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

    /* ---- node capability directives (split into directives_caps.inc) ---- */
#include "directives_caps.inc"

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

    /* ---- clustering/proxy/traffic directives (split into directives_net.inc) ---- */
#include "directives_net.inc"

    /* ---- read-through cache directives (split into directives_cache.inc) ---- */
#include "directives_cache.inc"

    /* ---- write-through directives (split into directives_writethrough.inc) ---- */
#include "directives_writethrough.inc"
    /* ---- CMS clustering directives (split into directives_cms.inc) ---- */
#include "directives_cms.inc"

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

    { ngx_string("brix_ocsp_stapling"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ocsp.stapling),
      NULL },

    /* ---- SHM zone directives (split into directives_zones.inc) ---- */
#include "directives_zones.inc"

    /* ---- SciTags pmark directives (split into directives_pmark.inc) ---- */
#include "directives_pmark.inc"

    /* Required terminator so nginx knows where the directive table ends. */
    ngx_null_command
};
