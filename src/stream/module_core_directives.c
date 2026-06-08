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
    { ngx_string("unix"),  XROOTD_AUTH_UNIX  },
    { ngx_string("krb5"),  XROOTD_AUTH_KRB5  },
    { ngx_null_string,     0                 }
};

/* ------------------------------------------------------------------ */
/* Security level enum                                                  */
/* ------------------------------------------------------------------ */

/* Values for xrootd_security_level — map to kXR_sec* constants.
 * Operators choose how strictly the server enforces request signing:
 * none (no signing), compatible, standard, intense, or pedantic. */
static ngx_conf_enum_t xrootd_security_levels[] = {
    { ngx_string("none"),       0 },  /* kXR_secNone       */
    { ngx_string("compatible"), 1 },  /* kXR_secCompatible */
    { ngx_string("standard"),   2 },  /* kXR_secStandard   */
    { ngx_string("intense"),    3 },  /* kXR_secIntense    */
    { ngx_string("pedantic"),   4 },  /* kXR_secPedantic   */
    { ngx_null_string,          0 }
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

    /* OCSP certificate revocation checking (Feature 8e) */
    /* Query the OCSP responder URL in each client certificate after chain verify. */
    { ngx_string("xrootd_ocsp_enable"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ocsp_enable),
      NULL },

    /* If on (default), treat network errors and UNKNOWN status as pass. */
    { ngx_string("xrootd_ocsp_soft_fail"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ocsp_soft_fail),
      NULL },

    /* Fetch an OCSP staple for the server certificate and serve via TLS. */
    { ngx_string("xrootd_ocsp_stapling"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, ocsp_stapling),
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

    /* Metadata-only: serve namespace ops (stat/dirlist/locate) but reject kXR_open. */
    { ngx_string("xrootd_metadata_only"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, metadata_only),
      NULL },

    /* Supervisor role: top-tier manager in a three-level CMS hierarchy. */
    { ngx_string("xrootd_supervisor"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, supervisor),
      NULL },

    /* Virtual redirector: static path mapping with no live CMS. */
    { ngx_string("xrootd_virtual_redirector"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, virtual_redirector),
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
