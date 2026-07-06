/*
 * module.c - (kept) routing + shared helpers
 * Phase-38 split of module.c; behavior-identical.
 */
#include "webdav_module_internal.h"
#include "core/config/credential_block.h"   /* §14 brix_credential block directive */
#include "auth/crypto/store_policy.h"        /* BRIX_SP_MODE_*, BRIX_CRL_MODE_* */

ngx_conf_enum_t  webdav_auth_values[] = {
    { ngx_string("none"),     WEBDAV_AUTH_NONE     },
    { ngx_string("optional"), WEBDAV_AUTH_OPTIONAL },
    { ngx_string("required"), WEBDAV_AUTH_REQUIRED },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t  brix_webdav_signing_policy_modes[] = {
    { ngx_string("off"),     BRIX_SP_MODE_OFF     },
    { ngx_string("on"),      BRIX_SP_MODE_ON      },
    { ngx_string("require"), BRIX_SP_MODE_REQUIRE },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t  brix_webdav_crl_modes[] = {
    { ngx_string("off"),     BRIX_CRL_MODE_OFF     },
    { ngx_string("try"),     BRIX_CRL_MODE_TRY     },
    { ngx_string("require"), BRIX_CRL_MODE_REQUIRE },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t  brix_webdav_cks_xattr_formats[] = {
    { ngx_string("text"),   BRIX_CKS_FMT_TEXT   },
    { ngx_string("xrdcks"), BRIX_CKS_FMT_XRDCKS },
    { ngx_null_string, 0 }
};

ngx_command_t ngx_http_brix_webdav_commands[] = {

    { ngx_string("brix_webdav"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.enable),
      NULL },

    /* Kernel-TLS (SSL_OP_ENABLE_KTLS) for the HTTPS data path — HTTPS GET
     * sendfiles over kTLS, PUT decrypts in-kernel. Default ON; transparent
     * no-op when the negotiated cipher/kernel cannot offload. Registered once
     * but the shared setter writes BOTH the WebDAV and S3 loc-confs' common.ktls
     * (an S3-only location still needs it); enabled per brix server in
     * postconfiguration. */
    { ngx_string("brix_ktls"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      brix_http_set_ktls,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* XrdAcc engine — registered once here; the shared setters populate both
     * the WebDAV and S3 loc-confs (valid in any http location). */
    { ngx_string("brix_authdb"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_authdb, 0, 0, NULL },

    { ngx_string("brix_authdb_format"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_format, 0, 0, NULL },

    { ngx_string("brix_authdb_audit"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_audit, 0, 0, NULL },

    { ngx_string("brix_authdb_refresh"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_refresh, 0, 0, NULL },

    { ngx_string("brix_acc_gidlifetime"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_gidlifetime, 0, 0, NULL },

    { ngx_string("brix_acc_pgo"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_pgo, 0, 0, NULL },

    { ngx_string("brix_acc_nisdomain"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_nisdomain, 0, 0, NULL },

    { ngx_string("brix_acc_resolve_hosts"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_resolve_hosts, 0, 0, NULL },

    { ngx_string("brix_acc_spacechar"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_spacechar, 0, 0, NULL },

    { ngx_string("brix_acc_encoding"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_encoding, 0, 0, NULL },

    { ngx_string("brix_acc_gidretran"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_acc_http_set_gidretran, 0, 0, NULL },

    /* ---- storage/tier directives (split into directives_storage.inc) ---- */
#include "directives_storage.inc"

    { ngx_string("brix_webdav_vomsdir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, vomsdir),
      NULL },

    /* Per-socket TCP congestion control (e.g. "bbr") for the HTTP data path — the
     * sender's CC governs download throughput; BBR ignores reordering's spurious
     * loss signals.  Same directive name as the stream module, different context. */
    { ngx_string("brix_tcp_congestion"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tcp_congestion),
      NULL },

    { ngx_string("brix_webdav_voms_cert_dir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, voms_cert_dir),
      NULL },

    { ngx_string("brix_webdav_cadir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, cadir),
      NULL },

    { ngx_string("brix_webdav_cafile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, cafile),
      NULL },

    /* Native authorization (read parity with root://): per-DN/VO/host authdb +
     * VO ACL, enforced for READ methods in the access phase (covers cached GET). */
    { ngx_string("brix_webdav_authdb"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      webdav_conf_authdb,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_webdav_require_vo"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      webdav_conf_require_vo,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_webdav_crl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, crl),
      NULL },

    { ngx_string("brix_webdav_signing_policy"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, signing_policy_mode),
      brix_webdav_signing_policy_modes },

    { ngx_string("brix_webdav_crl_mode"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, crl_mode),
      brix_webdav_crl_modes },

    { ngx_string("brix_webdav_verify_depth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, verify_depth),
      NULL },

    { ngx_string("brix_webdav_auth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, auth),
      &webdav_auth_values },

    { ngx_string("brix_webdav_proxy_certs"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, proxy_certs),
      NULL },

    /* brix_allow_write / brix_read_only are owned by ngx_http_brix_common_module. */

    { ngx_string("brix_webdav_upload_resume"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, upload_resume),
      NULL },

    { ngx_string("brix_webdav_stage_dir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, upload_stage_dir),
      NULL },

    /* phase-42 outbound GET compression (brix_compress) is owned by
     * ngx_http_brix_common_module. */

    { ngx_string("brix_webdav_tpc"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc),
      NULL },

    { ngx_string("brix_webdav_tape_rest"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tape_rest),
      NULL },

    { ngx_string("brix_webdav_tpc_allow_local"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_allow_local),
      NULL },

    { ngx_string("brix_webdav_tpc_allow_private"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_allow_private),
      NULL },

    { ngx_string("brix_webdav_tpc_curl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_curl),
      NULL },

    { ngx_string("brix_webdav_tpc_cert"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cert),
      NULL },

    { ngx_string("brix_webdav_tpc_key"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_key),
      NULL },

    { ngx_string("brix_webdav_tpc_cadir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cadir),
      NULL },

    { ngx_string("brix_webdav_tpc_cafile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cafile),
      NULL },

    { ngx_string("brix_webdav_tpc_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_timeout),
      NULL },

    /* Phase 39 (WS4): HTTP-TPC low-speed stall abort (both 0 = off). */
    { ngx_string("brix_webdav_tpc_low_speed_bytes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_low_speed_bytes),
      NULL },

    { ngx_string("brix_webdav_tpc_low_speed_secs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_low_speed_secs),
      NULL },

    { ngx_string("brix_webdav_tpc_marker_interval"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_marker_interval),
      NULL },

    { ngx_string("brix_webdav_tpc_max_streams"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_max_streams),
      NULL },

    { ngx_string("brix_webdav_tpc_token_endpoint"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cred.token_endpoint),
      NULL },

    { ngx_string("brix_webdav_tpc_token_client_id"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cred.token_client_id),
      NULL },

    { ngx_string("brix_webdav_tpc_token_client_secret"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cred.token_client_secret),
      NULL },

    { ngx_string("brix_webdav_tpc_token_scope"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cred.token_scope),
      NULL },

    { ngx_string("brix_webdav_token_jwks"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, token_jwks),
      NULL },

    { ngx_string("brix_webdav_token_issuer"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, token_issuer),
      NULL },

    { ngx_string("brix_webdav_token_config"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, token_config),
      NULL },

    { ngx_string("brix_webdav_token_audience"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, token_audience),
      NULL },

    { ngx_string("brix_webdav_token_clock_skew"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, token_clock_skew),
      NULL },

    { ngx_string("brix_webdav_macaroon_secret"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, token_macaroon_secret),
      NULL },

    { ngx_string("brix_webdav_macaroon_secret_old"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, token_macaroon_secret_old),
      NULL },

    /* brix_thread_pool is owned by ngx_http_brix_common_module. */

    { ngx_string("brix_webdav_cors_origin"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      webdav_conf_add_cors_origin,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_webdav_cors_credentials"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, cors_credentials),
      NULL },

    { ngx_string("brix_webdav_cors_max_age"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, cors_max_age),
      NULL },
    { ngx_string("brix_webdav_lock_timeout"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, lock_timeout),
      NULL },

    { ngx_string("brix_webdav_lock_startup_sweep"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, lock_startup_sweep),
      NULL },

    /* ZIP member access over HTTP GET (phase-57 W2). Opt-in, off by default. */
    { ngx_string("brix_webdav_zip_access"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, zip_access),
      NULL },

    { ngx_string("brix_http_query_token"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, http_query_token),
      NULL },

    { ngx_string("brix_webdav_macaroon_max_validity"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, macaroon_max_validity),
      NULL },

    { ngx_string("brix_webdav_macaroon_location"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, macaroon_location),
      NULL },

    { ngx_string("brix_webdav_checksum_on_write"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, checksum_on_write),
      NULL },

    { ngx_string("brix_webdav_checksum_xattr_format"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, checksum_xattr_format),
      &brix_webdav_cks_xattr_formats },

    { ngx_string("brix_webdav_dig"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, dig_enable),
      NULL },

    { ngx_string("brix_webdav_dig_export"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      webdav_conf_dig_export,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_webdav_dig_auth"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, dig_auth_file),
      NULL },

    { ngx_string("brix_webdav_zip_cd_max_bytes"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, zip_cd_max_bytes),
      NULL },

    { ngx_string("brix_webdav_open_file_cache"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_ANY,
      webdav_conf_open_file_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, open_file_cache),
      NULL },

    { ngx_string("brix_webdav_open_file_cache_valid"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, open_file_cache_valid),
      NULL },

    { ngx_string("brix_webdav_open_file_cache_min_uses"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, open_file_cache_min_uses),
      NULL },

    { ngx_string("brix_webdav_open_file_cache_errors"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, open_file_cache_errors),
      NULL },

    { ngx_string("brix_webdav_open_file_cache_events"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, open_file_cache_events),
      NULL },

    /* ---- clustering/traffic directives (split into directives_net.inc) ---- */
#include "directives_net.inc"
    /* ---- SHM zone + pmark directives (split into directives_zones.inc) ---- */
#include "directives_zones.inc"

    ngx_null_command
};

ngx_module_t ngx_http_brix_webdav_module = {
    NGX_MODULE_V1,
    &ngx_http_brix_webdav_module_ctx,
    ngx_http_brix_webdav_commands,
    NGX_HTTP_MODULE,
    NULL,  /* init_master */
    NULL,  /* init_module */
    ngx_http_brix_webdav_init_process,  /* init_process */
    NULL,  /* init_thread */
    NULL,  /* exit_thread */
    ngx_http_brix_webdav_exit_process,  /* exit_process */
    NULL,  /* exit_master */
    NGX_MODULE_V1_PADDING
};
ngx_http_module_t ngx_http_brix_webdav_module_ctx = {
    ngx_http_brix_webdav_preconfiguration,  /* preconfiguration */
    ngx_http_brix_webdav_postconfiguration, /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */
    ngx_http_brix_webdav_create_loc_conf,   /* create location config */
    ngx_http_brix_webdav_merge_loc_conf,    /* merge location config */
};
