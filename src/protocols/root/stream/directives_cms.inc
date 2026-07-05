/*
 * directives_cms.inc — CMS clustering directives (manager registration/heartbeat + node->manager resilience deadlines)
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
    /* Optional CMS manager registration/heartbeat. */
    { ngx_string("brix_cms_manager"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cms_manager,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_cms_paths"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cms.paths),
      NULL },

    { ngx_string("brix_cms_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cms.interval),
      NULL },

    { ngx_string("brix_cms_locate_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cms.locate_timeout),
      NULL },

    /* Phase 50: CMS client (node->manager) resilience deadlines. */
    { ngx_string("brix_cms_read_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cms.read_timeout),
      NULL },

    { ngx_string("brix_cms_send_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cms.send_timeout),
      NULL },

    /* Fast cold-start mesh settling (pre-first-login window only). */
    { ngx_string("brix_cms_initial_delay"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cms.initial_delay),
      NULL },

    { ngx_string("brix_cms_connect_retry"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cms.connect_retry),
      NULL },

    { ngx_string("brix_cms_tcp_keepalive"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cms.tcp_keepalive),
      NULL },

    { ngx_string("brix_cms_tcp_user_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cms.tcp_user_timeout),
      NULL },

    { ngx_string("brix_listen_port"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, listen_port),
      NULL },

    { ngx_string("brix_ckscan_depth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ckscan_max_depth),
      NULL },

    { ngx_string("brix_ckscan_max_files"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, ckscan_max_files),
      NULL },

    /*
     * Async pread/pwrite support is only compiled when nginx itself was built
     * with thread-pool support.
     */
    { ngx_string("brix_thread_pool"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Names an nginx thread_pool block to service async disk I/O. */
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, common.thread_pool_name),
      NULL },

    /* ---- legacy stream proxy directives (brix_proxy*) DISABLED 2026-06-30 ----
     * The legacy stream cache-origin proxy directive surface (brix_proxy,
     * _upstream, _upstream_tls[_ca|_name], _auth, _login_user, _audit_log,
     * _reconnect_attempts, _connect_timeout, _read_timeout, _write_timeout,
     * _keepalive_interval, _path_rewrite) is removed ahead of deleting the unused
     * proxy implementation; a config using any of them now fails with nginx
     * "unknown directive". Handlers/runtime remain temporarily, scheduled for
     * removal. NOT affected: brix_http_handoff (single-port handoff, retained
     * below) and brix_cache_origin_proxy (phase-64 tier origin). */

    /* single-port protocol handoff: splice a non-XRootD (HTTP/TLS) client on
     * this stream port to a local HTTP/WebDAV listener (host:port). */
    { ngx_string("brix_http_handoff"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_http_handoff,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* transparent pass-through relay: relay every connection on this port
     * verbatim to an upstream XRootD server while a tap decodes the cleartext
     * frames (src/relay/relay.c). */
    { ngx_string("brix_transparent_proxy"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_transparent_proxy,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* bad-actor guard on the transparent relay: classify each tapped frame
     * (src/net/guard/), drop junk-signature / off-grammar connections, and
     * audit notfound/authfail responses for fail2ban (relay/relay_guard.c). */
    { ngx_string("brix_guard_stream"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, relay_guard_enable),
      NULL },

    /* terminating tap proxy (src/proxy/): authenticate the client locally, then
     * re-authenticate upstream as the user (anonymous/ztn/SSS/username) and
     * forward opcode-by-opcode while the tap decodes the now-plaintext frames. */
    { ngx_string("brix_tap_proxy"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, proxy.enable),
      NULL },

    { ngx_string("brix_tap_proxy_upstream"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE12,
      brix_conf_set_proxy_upstream,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_tap_proxy_auth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_proxy_auth,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_tap_proxy_login_user"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_proxy_login_user,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_tap_proxy_audit_log"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, proxy.audit_log),
      NULL },

    { ngx_string("brix_tap_proxy_upstream_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, proxy.upstream_tls),
      NULL },

    /* (legacy brix_proxy_* directives removed here — see the note above) */

    /* Phase 39: network-fault resilience (all off by default; 0 = disabled). */
    { ngx_string("brix_read_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, read_timeout),
      NULL },

    { ngx_string("brix_handshake_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, handshake_timeout),
      NULL },

    { ngx_string("brix_send_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, send_timeout),
      NULL },

    { ngx_string("brix_tcp_user_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tcp_user_timeout),
      NULL },

    /* Per-socket TCP congestion control at accept (e.g. "bbr") — the sender's CC
     * governs download throughput; BBR ignores reordering's spurious loss signals. */
    { ngx_string("brix_tcp_congestion"),
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tcp_congestion),
      NULL },

    { ngx_string("brix_tcp_keepalive"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tcp_keepalive),
      NULL },

    { ngx_string("brix_max_connections"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, max_connections),
      NULL },

    /* Phase 39 (WS7): data-server staleness threshold for cluster selection. */
    { ngx_string("brix_manager_stale_after"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, manager_stale_after),
      NULL },
