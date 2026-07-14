/*
 * srv_conf_fields_net.inc: access log, metrics, upstream redirector/proxy, TPC SSRF policy, TPC OAuth2/OIDC delegation, cache-origin — a field-declaration fragment of ngx_stream_brix_srv_conf_t, split
 * (phase-79 file-size burndown) out of config.h via the repo's established .inc
 * struct-fragment pattern (cf. module_commands.c / directives_*.inc). Included
 * INSIDE the struct body in config.h — the struct assembles byte-identically, so
 * ZERO ABI change and every `conf->field` access is unchanged. Not a standalone
 * TU; do not #include anywhere but the srv_conf struct body. */

    /* ---- access log ---- */
    ngx_str_t   access_log;     /* [brix_access_log /var/log/xrootd-access.log] */
    ngx_flag_t  session_log;    /* [brix_session_log on|off] lifecycle SESS lines */
    ngx_fd_t    access_log_fd;  /* opened fd; NGX_INVALID_FILE if not configured.
                                   Captured per-worker from access_log_file->fd. */
    ngx_open_file_t *access_log_file;  /* nginx-managed handle (cycle->open_files):
                                          opened by the master, reopened on USR1, and
                                          closed cleanly across reload. NULL if off. */

    /* ---- Prometheus metrics ---- */
    ngx_int_t   metrics_slot;  /* index into the shared-memory metrics array;
                                   -1 if the server has no bound listen address yet */

    /* ---- upstream redirector ---- */
    ngx_str_t   upstream_host;  /* [brix_upstream host:port] — hostname/IP */
    uint16_t    upstream_port;  /* TCP port of the upstream redirector */
    ngx_addr_t *upstream_addr;  /* pre-resolved at config time; avoids per-request getaddrinfo */

    /* Upstream redirector outbound TLS (for kXR_gotoTLS mid-stream upgrade). */
    ngx_flag_t  upstream_tls;      /* [brix_upstream_tls on|off] — accept kXR_gotoTLS */
    ngx_str_t   upstream_tls_ca;   /* [brix_upstream_tls_ca /path/ca.pem] — verify upstream cert */
    ngx_str_t   upstream_tls_name; /* [brix_upstream_tls_name host] — SNI override */
#if (NGX_SSL)
    ngx_ssl_t  *upstream_tls_ctx;  /* SSL_CTX built at postconfiguration; NULL if tls off */
#endif

    /* Upstream redirector outbound token auth (for kXR_authmore / ztn). */
    ngx_str_t   upstream_token_file; /* [brix_upstream_token_file /path/token]
                                        Path to a file containing a WLCG bearer token
                                        (JWT).  Read synchronously when kXR_authmore
                                        is received; file may be refreshed externally. */

    /* ---- TPC SSRF policy ---- */
    ngx_flag_t  tpc_allow_local;    /* [brix_tpc_allow_local on|off] — allow
                                       TPC pulls from loopback (127/8, ::1) and
                                       link-local (169.254/16, fe80::/10) addresses.
                                       Default off: these cannot be legitimate
                                       XRootD federation nodes and are a SSRF surface. */
    ngx_flag_t  tpc_allow_private;  /* [brix_tpc_allow_private on|off] — allow
                                       TPC pulls from RFC-1918 private addresses
                                       (10/8, 172.16/12, 192.168/16).
                                       Default on: storage federation nodes commonly
                                       live on private networks. */
    ngx_flag_t  ssi_enable;         /* [brix_ssi on|off] — §7 XrdSsi
                                       request/response over /.ssi/<service>. */
    ngx_flag_t  ssi_cta_enable;     /* [brix_ssi_service cta] — gate the flagship
                                       CTA tape service (off by default). */
    ngx_uint_t  ssi_max_inflight;   /* [brix_ssi_max_inflight N] — concurrent
                                       requests per session (<= compile-time max). */
    size_t      ssi_request_max;    /* [brix_ssi_request_max SIZE] per-request cap. */
    size_t      ssi_response_max;   /* [brix_ssi_response_max SIZE] per-response cap. */
    ngx_str_t   ssi_cta_journal;    /* [brix_ssi_cta_journal PATH] restart journal. */
    ngx_uint_t  ssi_cta_executor;   /* [brix_ssi_cta_executor test|prod] (0=test). */
    ngx_uint_t  cns_mode;           /* [brix_cns off|emit|collect] — §6 Composite
                                       Cluster Name Space (data-server emit / manager
                                       inventory). BRIX_CNS_OFF/EMIT/COLLECT. */
    ngx_msec_t  tpc_key_ttl_ms;     /* [brix_tpc_key_ttl 60s] — lifetime of
                                       in-flight TPC rendezvous keys in the shared
                                       registry (source-side register / consume). */
    ngx_uint_t  tpc_max_transfer_secs; /* [brix_tpc_max_transfer_secs 0]
                                       Phase 39 (WS4): wall-clock cap on a native
                                       root:// TPC pull, sampled per 1 MiB chunk
                                       (no per-frame syscall).  Bounds a slow-drip
                                       remote that keeps resetting the per-recv
                                       SO_RCVTIMEO idle timer.  0 = no cap. */
    ngx_flag_t  tpc_outbound_tls;   /* [brix_tpc_outbound_tls on|off] — phase-57
                                       §F5: advertise kXR_ableTLS on the TPC pull and
                                       perform an in-protocol TLS upgrade when the
                                       source answers kXR_gotoTLS, so TLS-requiring
                                       sources can be pulled from. Default off:
                                       behaviour identical to today (no gotoTLS). */
    ngx_flag_t  tpc_delegate;       /* [brix_tpc_delegate on|off] — phase-57 §F6:
                                       X.509 proxy delegation. When on, the inbound
                                       GSI login captures the client's delegated
                                       proxy (kXGS_pxyreq/kXGC_sigpxy) and the TPC
                                       pull presents it to the source so the source
                                       authorises as the USER, not the gateway.
                                       Default off. NOTE: the delegation crypto is
                                       not yet implemented (gated on a stock
                                       -dlgpxy:request interop test, see
                                       tests/test_tpc_delegation.py); the flag parses
                                       and is reserved so the gate config loads. */
    ngx_int_t   tpc_transfer_max_age;  /* [brix_tpc_transfer_max_age 0]
                                       Phase 39 (WS5): seconds with no progress
                                       after which an in-flight TPC registry slot
                                       is reclaimed (abandoned-transfer reaper),
                                       preventing permanent "registry full" 503
                                       starvation.  Applied to the shared registry
                                       via brix_tpc_registry_set_max_age().
                                       0 = disabled.  Recommended 3600. */
    ngx_str_t   tpc_outbound_bearer_file; /* [brix_tpc_outbound_bearer_file path]
                                            JWT for outbound TPC kXR_auth ztn when
                                            the remote source advertises token auth. */

    ngx_flag_t  tpc_outbound_passthrough; /* [brix_tpc_outbound_passthrough on|off]
                                             Phase-70: forward the client's own
                                             inbound bearer JWT (ctx->bearer_token)
                                             verbatim to the TPC source, so the
                                             source authenticates the END USER — not
                                             a static service credential. Selects the
                                             OPPORTUNISTIC "passthrough-opt" token_mode
                                             for every native root:// TPC pull opened
                                             on this server: an inbound token is
                                             forwarded when present, but its absence
                                             falls back to bearer-file/GSI proxy
                                             delegation/anonymous — never a new denial.
                                             (An explicit client tpc.token_mode=
                                             passthrough is still STRICT/fail-closed.)
                                             Default ON; set `off` to disable. */

    /* ---- TPC OAuth2/OIDC token delegation ---- */
    ngx_str_t   tpc_outbound_token_endpoint; /* [brix_tpc_outbound_token_endpoint URL]
                                                 OAuth2 token endpoint for RFC 8693
                                                 token exchange when delegating credentials
                                                 to a protected TPC source. */
    ngx_str_t   tpc_outbound_client_id;       /* [brix_tpc_outbound_client_id ID]
                                                  OAuth2 client ID for confidential
                                                  client token exchange. */
    ngx_str_t   tpc_outbound_client_secret;   /* [brix_tpc_outbound_client_secret SECRET]
                                                  OAuth2 client secret for confidential
                                                  client token exchange. */
    ngx_str_t   tpc_outbound_scope;           /* [brix_tpc_outbound_scope SCOPE]
                                                  Scope to request during token exchange
                                                  (e.g. "storage.read"). */

    /*
     * ---- read-through cache ----
     *
     * On a cache miss (kXR_open for a path not in cache_root), the worker
     * connects to cache_origin, downloads the file, writes it to cache_root
     * under the same relative path, and then serves the cached copy.
     * A lock file prevents multiple workers from filling the same path.
     */
    ngx_flag_t  cache;              /* [brix_cache on|off] */
    ngx_str_t   cache_root;         /* [brix_cache_root /srv/xrd-cache] */
    ngx_str_t   cache_origin;       /* [brix_cache_origin host:port] — raw directive */
    ngx_str_t   cache_origin_host;  /* parsed hostname / IP */
    uint16_t    cache_origin_port;  /* parsed TCP port */
    ngx_flag_t  cache_origin_tls;   /* [brix_cache_origin_tls on] — TLS to origin */
    ngx_uint_t  cache_origin_family; /* [brix_cache_origin_family auto|inet|inet6]
                                        brix_af_policy_t for the origin connect;
                                        default BRIX_AF_AUTO (AF_UNSPEC). */
    /* §14 (phase-64): the legacy cache_origin credential/scheme/S3 fields are
     * DELETED with their directives — a cache source's identity is a named
     * brix_credential. The fields below remain as the sd_xroot SYNTHETIC-conf
     * parameter block for the in-process origin wire client. */
    ngx_str_t   cache_origin_bearer;        /* §14/C-3: in-process bearer token the
                                               root:// origin login presents via ztn
                                               (XrdSecztn). Set on sd_xroot's synthetic
                                               conf from the credential; "" = anonymous. */
    ngx_str_t   cache_origin_x509_proxy;    /* §14/C-3 GSI: X.509 proxy PEM path the
                                               root:// origin login presents via the
                                               in-process XrdSecgsi handshake; "" = no
                                               GSI. Set on sd_xroot's synthetic conf.
                                               Holds the cert (chain) source: a combined
                                               proxy PEM, OR a cert-only PEM paired with
                                               cache_origin_x509_key below. */
    ngx_str_t   cache_origin_x509_key;      /* §14/C-3 GSI: separate private-key PEM,
                                               used when the credential supplies
                                               x509_cert + x509_key rather than a single
                                               combined x509_proxy; "" = the key lives in
                                               cache_origin_x509_proxy (combined proxy). */
    ngx_str_t   cache_origin_ca_dir;        /* §14/C-3 GSI: CA file/hashed-dir used to
                                               VERIFY the origin's server cert (MITM
                                               protection); "" = no verification. */
    ngx_str_t   cache_origin_sss_keytab;    /* §14 SSS: shared-secret keytab path the
                                               root:// origin login presents via the
                                               XrdSecsss protocol; "" = no SSS. Set on
                                               sd_xroot's synthetic conf from the
                                               credential (sss_keytab field). */
