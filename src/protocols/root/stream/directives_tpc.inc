/*
 * directives_tpc.inc — third-party-copy (TPC) SSRF policy + OAuth2 delegation directives
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
    /* Allow TPC pulls from loopback / link-local addresses (default: off). */
    { ngx_string("brix_tpc_allow_local"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_allow_local),
      NULL },

    /* Allow TPC pulls from RFC-1918 private addresses (default: on). */
    { ngx_string("brix_tpc_allow_private"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_allow_private),
      NULL },

    /* §7 unary XrdSsi request/response over /.ssi/<service> (default: off). */
    { ngx_string("brix_ssi"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ssi_enable),
      NULL },

    /* §7 SSI: enable a non-default provider (cta). Opt-in. */
    { ngx_string("brix_ssi_service"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_ssi_service_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* §7 SSI: concurrent requests per session (<= compile-time max). */
    { ngx_string("brix_ssi_max_inflight"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ssi_max_inflight),
      NULL },

    /* §7 SSI: per-request / per-response byte caps. */
    { ngx_string("brix_ssi_request_max"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ssi_request_max),
      NULL },

    { ngx_string("brix_ssi_response_max"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ssi_response_max),
      NULL },

    /* §7 SSI: flagship CTA service — restart journal + executor backend. */
    { ngx_string("brix_ssi_cta_journal"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ssi_cta_journal),
      NULL },

    { ngx_string("brix_ssi_cta_executor"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ssi_cta_executor),
      &brix_ssi_executor_enum },

    /* §6 Composite Cluster Name Space: off | emit (data server) | collect (mgr). */
    { ngx_string("brix_cns"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cns_mode),
      &brix_cns_modes },

    /* phase-57 §F5: upgrade the TPC pull to TLS when the source sends
     * kXR_gotoTLS (advertise kXR_ableTLS outbound). Default: off. */
    { ngx_string("brix_tpc_outbound_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_outbound_tls),
      NULL },

    /* phase-57 §F6: X.509 proxy delegation (capture client proxy → present to
     * source as the user). Default: off. Reserved — crypto pending its stock
     * -dlgpxy:request interop gate (tests/test_tpc_delegation.py). */
    { ngx_string("brix_tpc_delegate"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_delegate),
      NULL },

    /* TPC rendezvous key lifetime in the shared registry (default: 60s). */
    { ngx_string("brix_tpc_key_ttl"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_key_ttl_ms),
      NULL },

    /* Phase 39 (WS4): wall-clock cap on a native TPC pull (0 = no cap). */
    { ngx_string("brix_tpc_max_transfer_secs"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_max_transfer_secs),
      NULL },

    /* Phase 39 (WS5): abandoned-TPC-slot reaper age in seconds (0 = disabled). */
    { ngx_string("brix_tpc_transfer_max_age"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_transfer_max_age),
      NULL },

    /* JWT file for outbound native TPC pulls when the source requires ztn. */
    { ngx_string("brix_tpc_outbound_bearer_file"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_outbound_bearer_file),
      NULL },

    /* Phase-70: forward the client's inbound bearer JWT verbatim to the TPC
     * source (opportunistic "passthrough-opt" token_mode) so the source
     * authenticates the end user. Default ON; an inbound token is forwarded when
     * present, its absence falls back to bearer-file/GSI/anonymous (never a new
     * denial). An explicit client tpc.token_mode=passthrough stays fail-closed. */
    { ngx_string("brix_tpc_outbound_passthrough"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_outbound_passthrough),
      NULL },

    /* OAuth2/OIDC token endpoint for RFC 8693 token exchange on TPC pulls. */
    { ngx_string("brix_tpc_outbound_token_endpoint"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_outbound_token_endpoint),
      NULL },

    /* OAuth2 client ID for confidential client token exchange. */
    { ngx_string("brix_tpc_outbound_client_id"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_outbound_client_id),
      NULL },

    /* OAuth2 client secret for confidential client token exchange. */
    { ngx_string("brix_tpc_outbound_client_secret"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_outbound_client_secret),
      NULL },

    /* Scope string for token exchange (default: "storage.read"). */
    { ngx_string("brix_tpc_outbound_scope"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tpc_outbound_scope),
      NULL },

    /* Write handlers still perform per-op auth checks; this only enables the feature. */
    { ngx_string("brix_allow_write"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      /* Standard boolean setter writing into srv_conf->common.allow_write. */
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.allow_write),
      NULL },

    /* Hard read-only: when on, forces allow_write off so all writes are rejected
     * at the protocol edge (before the VFS, before token scope). Overrides
     * brix_allow_write on. */
    { ngx_string("brix_read_only"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.read_only),
      NULL },

