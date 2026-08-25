/*
 * module_commands.c - WebDAV directive command table + enum value arrays.
 * Phase-38 split of module.c; behavior-identical (verbatim move). The
 * ngx_http_brix_webdav_commands[] table and its enum value arrays live here;
 * the ngx_module_t glue + ngx_http_module_t context stay in module.c. Cross-TU
 * externs are declared in webdav_module_internal.h.
 */
#include "webdav_module_internal.h"
#include "core/config/credential_block.h"   /* §14 brix_credential block directive */
#include "auth/crypto/store_policy.h"        /* BRIX_SP_MODE_*, BRIX_CRL_MODE_* */
#include "protocols/root/stream/module_enums.h"  /* shared brix_signing_policy_modes
                                                    + brix_crl_modes tables */

ngx_conf_enum_t  webdav_auth_values[] = {
    { ngx_string("none"),     WEBDAV_AUTH_NONE     },
    { ngx_string("optional"), WEBDAV_AUTH_OPTIONAL },
    { ngx_string("required"), WEBDAV_AUTH_REQUIRED },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t  brix_webdav_cks_xattr_formats[] = {
    { ngx_string("text"),   BRIX_CKS_FMT_TEXT   },
    { ngx_string("xrdcks"), BRIX_CKS_FMT_XRDCKS },
    { ngx_null_string, 0 }
};

/* §6.1: scheme of the redirect Location URL — the manager cannot probe the
 * data servers' TLS posture, so the operator states it. */
ngx_conf_enum_t  brix_webdav_redirect_schemes[] = {
    { ngx_string("http"),  BRIX_WEBDAV_RDR_HTTP  },
    { ngx_string("https"), BRIX_WEBDAV_RDR_HTTPS },
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
     * no-op when the negotiated cipher/kernel cannot offload. */
    /* brix_ktls + brix_cache_store_endpoint moved to http_common.c (phase-101 W2)
     * — they were dual-conf-poking setters (webdav+s3 only, cvmfs excluded); now
     * registered once for the whole HTTP plane on the standard flag slot and
     * adopted into every protocol conf. */

    /* XrdAcc engine (brix_authdb* / brix_acc_*) moved to http_common.c on the
     * standard generic slots (phase-101 W2); the acc block now lives in the
     * shared preamble (common.acc) and is adopted into every HTTP protocol,
     * cvmfs included.  module_acc_directives.{c,h} is deleted. */

    /* ---- storage/tier directives (split into directives_storage.h) ---- */
#include "directives_storage.h"

    /* brix_vomsdir moved to http_common.c (phase-101 W4). */

    /* Per-socket TCP congestion control (e.g. "bbr") for the HTTP data path — the
     * sender's CC governs download throughput; BBR ignores reordering's spurious
     * loss signals.  Same directive name as the stream module, different context. */
    /* phase-105 W2: -> http_common (shared file-serve engine) */

    /* brix_voms_cert_dir moved to http_common.c (phase-101 W4). */

    /* phase-105 W2: -> http_common (auth-layer verify source) */

    /* phase-105 W2: -> http_common */

    /* brix_authdb (native u/g/p/h READ ACL) -> owned by the common module
     * (phase-101 W5.2): registered on http_common at BRIX_HTTP_ALL_CONF into the
     * shared preamble (common.authdb_rules); webdav's AND s3's access phases read
     * it from there (W5.2c). The XrdAcc engine stays at brix_acc_authdb. cvmfs is
     * not gated (read-through/CAS path model). */

    /* brix_webdav_require_vo -> bare brix_require_vo on the common module
     * (phase-101 W4); the array now lives in common.vo_rules. */

    /* brix_webdav_protbind -> bare brix_protbind on the common module
     * (phase-101 W4); the array now lives in common.protbind. */




    /* phase-105 W3.5: -> bare brix_verify_depth on http_common */

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

    /* brix_client_ca_store -> http_common (phase-105 W2); the postconfig
     * hook below still loads it into the server SSL_CTX, reading the
     * adopted common.client_ca_store. */

    /* Parse-time auto-pick of ssl_client_certificate from a hashed CA dir:
     * resolves the <hash>.N file matching the issuer of the server's own
     * ssl_certificate leaf and hands it to the stock directive machinery.
     * Server-level only; must appear after ssl_certificate (handler enforces). */
    { ngx_string("brix_client_certificate_folder"),
      NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
      webdav_conf_client_cert_folder,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Hashed CA dir for the proxy back leg (proxy_ssl_verify): seeds the
     * stock proxy_ssl_trusted_certificate with one <hash>.N file at parse
     * time and adds the whole dir to the upstream SSL_CTX at postconfig.
     * Location-exact — deliberately not merged/inherited. */
    { ngx_string("brix_backend_ca_dir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      webdav_conf_proxy_ssl_capath,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* brix_allow_write / brix_read_only are owned by ngx_http_brix_common_module. */

    /* brix_upload_resume moved to http_common.c (phase-101 W4). */

    /* brix_stage_dir moved to http_common.c (phase-101 W4). */

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

    /* brix_delegation_endpoint -> http_common (phase-105 W2); readers gate
     * on common.delegation_endpoint (dispatch.c / delegation.c). */

#include "directives_tpc.h"

    /* brix_pwd_file moved to http_common.c (phase-101 W4). */

    /* brix_token_jwks moved to http_common.c (W4). */

    /* brix_token_issuer + brix_token_config moved to http_common.c (W4). */

    /* brix_token_audience moved to http_common.c (W4). */

    /* brix_token_clock_skew moved to http_common.c (W4). */

    /* brix_macaroon_secret moved to http_common.c (phase-101 W4). */

    /* brix_macaroon_secret_old moved to http_common.c (phase-101 W4). */

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
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, cors_max_age),
      NULL },
    { ngx_string("brix_webdav_lock_timeout"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, lock_timeout),
      NULL },

    { ngx_string("brix_webdav_lock_startup_sweep"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, lock_startup_sweep),
      NULL },

    /* brix_zip_access moved to http_common.c (phase-101 W4) — one bare name for
     * every HTTP protocol; brix_webdav_zip_access is retired. */

    { ngx_string("brix_webdav_query_token"),
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

    { ngx_string("brix_webdav_require_digest"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, require_digest),
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

    /* brix_zip_cd_max_bytes moved to http_common.c (phase-101 W4). */

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

    /* ---- clustering/traffic directives (split into directives_net.h) ---- */
#include "directives_net.h"
    /* ---- SHM zone + pmark directives (split into directives_zones.h) ---- */
#include "directives_zones.h"

    ngx_null_command
};
