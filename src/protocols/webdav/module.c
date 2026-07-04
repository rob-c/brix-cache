/*
 * module.c - (kept) routing + shared helpers
 * Phase-38 split of module.c; behavior-identical.
 */
#include "webdav_module_internal.h"
#include "core/config/credential_block.h"   /* §14 brix_credential block directive */

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

/* phase-64: brix_webdav_stage_flush sync|async (0 = sync, 1 = async). */
static ngx_conf_enum_t  brix_webdav_stage_flush_enum[] = {
    { ngx_string("sync"),  0 },
    { ngx_string("async"), 1 },
    { ngx_null_string,     0 }
};

/* phase-64: brix_webdav_cache_meta map (BRIX_CMETA_* in cache/cstore.h). */
static ngx_conf_enum_t  brix_webdav_cache_meta_enum[] = {
    { ngx_string("auto"),    0 },
    { ngx_string("local"),   1 },
    { ngx_string("xattr"),   2 },
    { ngx_string("sidecar"), 3 },
    { ngx_null_string,       0 }
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

    { ngx_string("brix_webdav_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.root),
      NULL },

    /* Storage backend for this export: "posix" (default) or "pblock"
     * (block-based, rooted at brix_webdav_root; needs the sqlite build). */
    { ngx_string("brix_webdav_storage_backend"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.storage_backend),
      NULL },

    /* Names the brix_credential block (§14) the source backend authenticates with;
     * "" = anonymous. Threads a bearer into the sd_http / sd_xroot source. Shares the
     * process-wide credential registry with the stream-scope block. */
    { ngx_string("brix_webdav_storage_credential"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.storage_credential),
      NULL },

    /* ---- phase-64 composable tier grammar mirrors (§4.4) ---- */
    { ngx_string("brix_webdav_cache_store"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
      brix_conf_set_store_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.cache_store),
      (void *) offsetof(ngx_http_brix_webdav_loc_conf_t,
                        common.cache_store_args) },
    { ngx_string("brix_webdav_stage"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.stage_enable),
      NULL },
    { ngx_string("brix_webdav_stage_store"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
      brix_conf_set_store_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.stage_store),
      (void *) offsetof(ngx_http_brix_webdav_loc_conf_t,
                        common.stage_store_args) },
    { ngx_string("brix_webdav_stage_flush"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.stage_flush_async),
      brix_webdav_stage_flush_enum },
    { ngx_string("brix_webdav_cache_max_object"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.cache_max_object),
      NULL },
    { ngx_string("brix_webdav_cache_evict_at"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.cache_evict_at),
      NULL },
    { ngx_string("brix_webdav_cache_evict_to"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.cache_evict_to),
      NULL },
    { ngx_string("brix_webdav_cache_index_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.cache_index_cache),
      NULL },
    { ngx_string("brix_webdav_cache_meta"),   /* auto|local|xattr|sidecar */
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.cache_meta_mode),
      brix_webdav_cache_meta_enum },
    { ngx_string("brix_webdav_cache_slice_size"),  /* <size> (0 = whole-file) */
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.cache_slice_size),
      NULL },

    /* The reusable `brix_credential <name> { … }` identity block (§14) at http
     * scope — declared once inside http{} and referenced by the directive above. */
    { ngx_string("brix_credential"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
      brix_conf_credential_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* Write-back staging for a remote (root://) backend: stage uploads to the
     * local export and promote them on commit (vs Mode A passthrough). */
    { ngx_string("brix_webdav_storage_staging"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.storage_staging),
      NULL },

    /* pblock stripe size for newly-written files (e.g. 64m); 0/unset = 64 MiB. */
    { ngx_string("brix_webdav_pblock_block_size"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pblock_block_size),
      NULL },

    { ngx_string("brix_webdav_cache_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, cache_root),
      NULL },

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

    { ngx_string("brix_webdav_crl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, crl),
      NULL },

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

    { ngx_string("brix_webdav_allow_write"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.allow_write),
      NULL },
    { ngx_string("brix_webdav_read_only"),    /* hard read-only (overrides allow_write) */
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.read_only),
      NULL },

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

    /* phase-42: opt-in outbound GET response compression (Accept-Encoding). */
    { ngx_string("brix_webdav_compress"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.compress),
      NULL },

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

    { ngx_string("brix_webdav_thread_pool"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.thread_pool_name),
      NULL },

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

    /* ---- legacy WebDAV reverse-proxy directives DISABLED 2026-06-30 ----
     * (brix_webdav_proxy, _dynamic, _upstream, _max_fails, _fail_timeout,
     * _auth, _connect_timeout, _send_timeout, _read_timeout) are removed ahead of
     * deleting the unused WebDAV upstream-proxy implementation; a config using any
     * of them now fails with nginx "unknown directive". Handlers/runtime remain
     * temporarily, scheduled for removal. NOT affected: brix_webdav_proxy_certs
     * (GSI X.509 RFC-3820 proxy-cert acceptance — an AUTH directive, retained). */

    /* Phase 24: traffic mirroring (off by default) */    { ngx_string("brix_mirror_url"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_http_mirror_set_url,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_mirror_methods"),
      NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      brix_http_mirror_set_methods,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_mirror_sample"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.sample_pct),
      NULL },

    { ngx_string("brix_mirror_strip_auth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.strip_auth),
      NULL },

    /* Opt-in gate for mirroring WRITE methods (PUT/DELETE/MKCOL/MOVE/COPY) to the
     * shadow.  Off by default; the shadow MUST be an isolated namespace, never the
     * primary's backing store. */
    { ngx_string("brix_mirror_writes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.mirror_writes),
      NULL },

    { ngx_string("brix_mirror_log_diverge"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.log_diverge),
      NULL },

    { ngx_string("brix_mirror_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.timeout_ms),
      NULL },

    { ngx_string("brix_mirror_token"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.token),
      NULL },

    /* Phase 25: advanced rate limiting / traffic shaping */    { ngx_string("brix_rate_limit_zone"),     /* http main: zone=NAME:SIZE */
      NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
      brix_rl_zone_directive,
      0,
      0,
      NULL },

    { ngx_string("brix_rate_limit_rule"),     /* loc: request-rate rule */
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      brix_rl_rule_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, rl_rules),
      NULL },

    { ngx_string("brix_bandwidth_limit"),     /* loc: bandwidth rule */
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      brix_rl_bw_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, rl_rules),
      NULL },

    { ngx_string("brix_concurrency_limit"),   /* loc: per-principal in-flight cap (W7) */
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      brix_rl_conc_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, rl_rules),
      NULL },

    /* (legacy brix_webdav_proxy_*_timeout directives removed — see note above) */

    /* Phase 20: shared-memory KV zones, token cache, rate limiting */
    /* brix_kv_zone <name> <size> key=<bytes> val=<bytes>;  (http main) */
    { ngx_string("brix_kv_zone"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE,
      brix_kv_zone_directive,
      0,
      0,
      NULL },

    /* brix_token_cache zone=<name>; */
    { ngx_string("brix_token_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_token_cache_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, token_cache_kv),
      NULL },

    /* brix_rate_limit zone=<name> rate=<N>r/s burst=<N> [key=dn|ip]; */
    { ngx_string("brix_rate_limit"),
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      brix_rate_limit_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, rate_limit),
      NULL },

    /* Phase 21 Step C: OIDC token introspection (revocation) */
    /* Informational: the IdP /introspect endpoint URL (the actual request is
     * made by the operator-defined internal location). */
    { ngx_string("brix_webdav_token_introspect_url"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, introspect_url),
      NULL },

    /* Internal location URI that proxy_passes to the IdP; enables the check. */
    { ngx_string("brix_webdav_token_introspect_loc"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, introspect_loc),
      NULL },

    { ngx_string("brix_webdav_token_introspect_ttl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, introspect_ttl),
      NULL },

    { ngx_string("brix_webdav_token_introspect_fail_open"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, introspect_fail_open),
      NULL },

    /* brix_webdav_revoke_cache zone=<name>; */
    { ngx_string("brix_webdav_revoke_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      webdav_conf_revoke_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* SciTags packet marking (src/pmark/) — see phase-34 doc */    { ngx_string("brix_pmark"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pmark.enable), NULL },
    { ngx_string("brix_pmark_firefly"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pmark.firefly), NULL },
    { ngx_string("brix_pmark_flowlabel"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pmark.flowlabel), NULL },
    { ngx_string("brix_pmark_scitag_cgi"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pmark.scitag_cgi), NULL },
    { ngx_string("brix_pmark_firefly_origin"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pmark.firefly_origin), NULL },
    { ngx_string("brix_pmark_http_plain"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pmark.http_plain), NULL },
    { ngx_string("brix_pmark_echo"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pmark.echo), NULL },
    { ngx_string("brix_pmark_appname"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pmark.appname), NULL },
    { ngx_string("brix_pmark_defsfile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pmark.defsfile), NULL },
    { ngx_string("brix_pmark_domain"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, brix_pmark_set_domain,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_firefly_dest"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, brix_pmark_set_firefly_dest,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_map_experiment"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE23, brix_pmark_set_map_experiment,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_map_activity"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE3 | NGX_CONF_TAKE4,
      brix_pmark_set_map_activity,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

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
