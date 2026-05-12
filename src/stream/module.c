/*
 * stream/module.c
 *
 * nginx stream module implementing the XRootD root:// protocol.
 * Acts as a kXR_DataServer at the TCP level, with optional write support.
 *
 * Read operations (always available when logged in):
 *   handshake / protocol negotiation
 *   kXR_protocol   — negotiate capabilities and security mode
 *   kXR_login      — accept username; triggers GSI auth when configured
 *   kXR_auth       — GSI/x509 proxy certificate authentication
 *   kXR_ping       — liveness check
 *   kXR_stat       — path-based and handle-based stat
 *   kXR_open       — open files for reading or writing
 *   kXR_read       — read file data (chunked with kXR_oksofar)
 *   kXR_readv      — scatter-gather vector read (up to 1024 segments)
 *   kXR_close      — close an open handle (logs throughput)
 *   kXR_dirlist    — list a directory (with optional kXR_dstat per-entry stat)
 *   kXR_query      — kXR_Qcksum (adler32), kXR_Qspace (statvfs), kXR_Qconfig
 *   kXR_endsess    — graceful session termination
 *
 * Write operations (require xrootd_allow_write on):
 *   kXR_pgwrite    — paged write with CRC32c integrity (used by xrdcp v5)
 *   kXR_write      — raw write at offset (v3/v4 clients)
 *   kXR_sync       — fsync an open handle
 *   kXR_truncate   — truncate by path or open handle
 *   kXR_mkdir      — create directory; recursive with kXR_mkdirpath
 *   kXR_rmdir      — remove an empty directory
 *   kXR_rm         — remove a file
 *   kXR_mv         — rename/move a file or directory
 *   kXR_chmod      — change permission bits
 *
 * -------------------------------------------------------------------------
 * Build
 * -------------------------------------------------------------------------
 *
 *   ./configure --with-stream --add-module=/path/to/nginx-xrootd
 *   make && make install
 */

#include "ngx_xrootd_module.h"
#include "proxy/proxy.h"
#include "proxy/proxy_internal.h"

/* ------------------------------------------------------------------ */
/* Module directives                                                    */
/* ------------------------------------------------------------------ */

/*
 * Text values accepted by `xrootd_auth` in nginx.conf.
 * nginx's enum setter walks this table until it hits ngx_null_string.
 */
static ngx_conf_enum_t xrootd_auth_modes[] = {
    { ngx_string("none"),  XROOTD_AUTH_NONE  },
    { ngx_string("gsi"),   XROOTD_AUTH_GSI   },
    { ngx_string("token"), XROOTD_AUTH_TOKEN },
    { ngx_string("both"),  XROOTD_AUTH_BOTH  },
    { ngx_string("sss"),   XROOTD_AUTH_SSS   },
    { ngx_null_string,     0                 }
};

/*
 * Directive table for the stream module.
 *
 * Most entries use nginx's stock setters plus an offsetof() into
 * ngx_stream_xrootd_srv_conf_t, so parsing writes config values directly into
 * the per-server config struct created in ngx_stream_xrootd_create_srv_conf().
 *
 * Entry fields follow nginx's usual pattern:
 *   1. directive name as it appears in nginx.conf
 *   2. where the directive is legal and how many arguments it takes
 *   3. setter callback
 *   4. which config object the setter should write into
 *   5. byte offset of the destination field inside that config object
 *   6. optional extra data for the setter (for example enum tables)
 */
static ngx_command_t ngx_stream_xrootd_commands[] = {

    { ngx_string("xrootd"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      /* Custom setter because enabling the module also installs the handler. */
      ngx_stream_xrootd_enable,
      /* Store the parsed flag in the per-server stream config. */
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, enable),
      NULL },

    /* Filesystem/export settings used by nearly every request handler. */
    { ngx_string("xrootd_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Single string argument copied into srv_conf->root. */
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, root),
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
      /* Standard boolean setter writing into srv_conf->allow_write. */
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, allow_write),
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

#if (NGX_THREADS)
    /*
     * Async pread/pwrite support is only compiled when nginx itself was built
     * with thread-pool support.
     */
    { ngx_string("xrootd_thread_pool"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Names an nginx thread_pool block to service async disk I/O. */
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, thread_pool_name),
      NULL },
#endif

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

    { ngx_string("xrootd_proxy_path_rewrite"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
      xrootd_conf_set_proxy_path_rewrite,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Required terminator so nginx knows where the directive table ends. */
    ngx_null_command
};

/* ------------------------------------------------------------------ */
/* Module context                                                       */
/* ------------------------------------------------------------------ */

static ngx_stream_module_t ngx_stream_xrootd_module_ctx = {
    /* No global parser rewrites are needed before nginx reads stream blocks. */
    NULL,                                 /* preconfiguration  */
    /* Final validation and resource setup once all stream servers are parsed. */
    ngx_stream_xrootd_postconfiguration,  /* postconfiguration */
    /* This module keeps no stream-wide main configuration object. */
    NULL,                                 /* create main conf  */
  /* Therefore there is also nothing to normalize/validate at main-conf level. */
    NULL,                                 /* init main conf    */
    /* Per-server config object allocation and parent/child merging hooks. */
    ngx_stream_xrootd_create_srv_conf,    /* create srv conf   */
    ngx_stream_xrootd_merge_srv_conf,     /* merge srv conf    */
};

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

/*
 * Static module descriptor consumed by nginx at startup. Once linked into the
 * binary, this is how nginx discovers our directive table and lifecycle hooks.
 * NGX_STREAM_MODULE tells nginx which subsystem owns the callbacks above.
 */
ngx_module_t ngx_stream_xrootd_module = {
  NGX_MODULE_V1,
  &ngx_stream_xrootd_module_ctx,
  ngx_stream_xrootd_commands,
  NGX_STREAM_MODULE,
  /* No master/module init hooks beyond the stream-specific callbacks above. */
    NULL, NULL,
    ngx_stream_xrootd_init_process,         /* init process       */
    NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};
