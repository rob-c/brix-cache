/*
 * stream/module.c
 *
 * nginx stream module implementing the XRootD root:// protocol.
 * Acts as a kXR_DataServer at the TCP level, with optional write support.
 */

#include "ngx_xrootd_module.h"
#include "proxy/proxy.h"
#include "proxy/proxy_internal.h"

/* ------------------------------------------------------------------ */
/* Module directives                                                    */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* WHAT: Authentication mode enum table                                 */
/* WHY: Provides nginx with selectable auth policy options mapped to    */
/*      internal constants. The dispatcher uses this during handshake   */
/*      to advertise available login methods to clients.               */
/* HOW: Maps textual config values ("none"/"gsi"/"token"/"both"/"sss") */
/*      onto XROOTD_AUTH_* enum constants used by the session/login     */
/*      subsystem. "both" enables dual authentication (GSI+token).     */
/* ------------------------------------------------------------------ */
/* Text values accepted by `xrootd_auth` in nginx.conf. */
static ngx_conf_enum_t xrootd_auth_modes[] = {
    { ngx_string("none"),  XROOTD_AUTH_NONE  },
    { ngx_string("gsi"),   XROOTD_AUTH_GSI   },
    { ngx_string("token"), XROOTD_AUTH_TOKEN },
    { ngx_string("both"),  XROOTD_AUTH_BOTH  },
    { ngx_string("sss"),   XROOTD_AUTH_SSS   },
    { ngx_null_string,     0                 }
};

/* ------------------------------------------------------------------ */
/* WHAT: Security/ signing level enum table                             */
/* WHY: Controls kXR_sigver (HMAC-SHA256 request signing) enforcement  */
/*      granularity. Higher levels require more rigorous signature      */
/*      verification but may reject legacy clients that don't sign     */
/*      requests.                                                      */
/* HOW: Levels progress from "none" (no signing required) through       */
/*      "compatible" (legacy tolerance), "standard" (default),          */
/*      "intense" (strict), to "pedantic" (maximum enforcement).       */
/* ------------------------------------------------------------------ */
/* Security level enum for xrootd_security_level. */
static ngx_conf_enum_t xrootd_security_levels[] = {
    { ngx_string("none"),       0 },
    { ngx_string("compatible"), 1 },
    { ngx_string("standard"),   2 },
    { ngx_string("intense"),    3 },
    { ngx_string("pedantic"),   4 },
    { ngx_null_string,          0 }
};

/* ------------------------------------------------------------------ */
/* WHAT: Complete nginx stream module directive configuration table     */
/* WHY: Consolidates all XRootD configuration options into a single    */
/*      array so the nginx event loop can parse them during startup.   */
/*      The table is organized by feature group (core → auth → cache)  */
/*      for readability and future maintenance.                      */
/* HOW: Each entry follows nginx convention: directive name, config     */
/*      level flag, setter function, offset into srv_conf struct,      */
/*      optional enum/table reference. Terminator is ngx_null_command.*/
/* ------------------------------------------------------------------ */
/* Combined directive table: core + cache/proxy directives. */
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

    /* TPC rendezvous key lifetime in the shared registry (default: 60s). */
    { ngx_string("xrootd_tpc_key_ttl"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, tpc_key_ttl_ms),
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

    { ngx_string("xrootd_registry_slots"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, registry_slots),
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

    /* ---- cache/proxy directives (merged into ngx_stream_xrootd_commands[]) ---- */

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

    { ngx_string("xrootd_cache_origin"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_origin,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_cache_origin_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_origin_tls),
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

    /* POSIX extended regular expression matched against the path basename.
     * Matching files are admitted to cache even if they exceed the size limit. */
    { ngx_string("xrootd_cache_include_regex"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_include_regex,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* ---- write-through mode directives (mirrors XrdPfc configuration from
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

    /* ---- transparent proxy mode ---- */

    { ngx_string("xrootd_proxy"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_enable),
      NULL },

    { ngx_string("xrootd_proxy_upstream"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE12,
      xrootd_conf_set_proxy_upstream,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_proxy_upstream_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_upstream_tls),
      NULL },

    { ngx_string("xrootd_proxy_auth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_proxy_auth,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_proxy_login_user"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_proxy_login_user,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_proxy_audit_log"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_audit_log),
      NULL },

    { ngx_string("xrootd_proxy_upstream_tls_ca"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_upstream_tls_ca),
      NULL },

    { ngx_string("xrootd_proxy_upstream_tls_name"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_upstream_tls_name),
      NULL },

    { ngx_string("xrootd_proxy_reconnect_attempts"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_reconnect_attempts),
      NULL },

    { ngx_string("xrootd_proxy_connect_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_connect_timeout),
      NULL },

    { ngx_string("xrootd_proxy_read_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_read_timeout),
      NULL },

    { ngx_string("xrootd_proxy_keepalive_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_keepalive_interval),
      NULL },

    { ngx_string("xrootd_proxy_path_rewrite"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
      xrootd_conf_set_proxy_path_rewrite,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

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

    /* Required terminator so nginx knows where the directive table ends. */
    ngx_null_command
};
