/*
 * srv_conf_fields_net.h: access log, metrics, upstream redirector/proxy, TPC SSRF policy, TPC OAuth2/OIDC delegation, cache-origin — a field-declaration fragment of ngx_stream_brix_srv_conf_t, split
 * (phase-79 file-size burndown) out of config.h via the repo's established .h
 * struct-fragment pattern (cf. module_commands.c / directives_*.h). Included
 * INSIDE the struct body in config.h — the struct assembles byte-identically, so
 * ZERO ABI change and every `conf->field` access is unchanged. Not a standalone
 * TU; do not #include anywhere but the srv_conf struct body. */
#pragma once

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
    ngx_addr_t *upstream_addr;  /* registry-owned (phase-116): socklen 0 until resolved */
    struct brix_dns_target_s *upstream_dns; /* runtime DNS target behind upstream_addr */

    /* Upstream redirector outbound TLS (for kXR_gotoTLS mid-stream upgrade). */
    ngx_flag_t  upstream_tls;      /* [brix_upstream_tls on|off] — accept kXR_gotoTLS */
    ngx_str_t   upstream_tls_ca;   /* [brix_upstream_tls_ca /path/ca.pem] — verify upstream cert */
    ngx_str_t   upstream_tls_name; /* [brix_upstream_tls_name host] — SNI override */
    ngx_flag_t  upstream_ssl_verify;/* [brix_upstream_tls_verify on|off] A-1: default on,
                                     * nginx -t refuses upstream_tls without a CA unless off */
#if (NGX_SSL)
    ngx_ssl_t  *upstream_tls_ctx;  /* SSL_CTX built at postconfiguration; NULL if tls off */
#endif

    /* Upstream redirector outbound token auth (for kXR_authmore / ztn). */
    ngx_str_t   upstream_token_file; /* [brix_upstream_token_file /path/token]
                                        Path to a file containing a WLCG bearer token
                                        (JWT).  Read synchronously when kXR_authmore
                                        is received; file may be refreshed externally. */
    ngx_str_t   upstream_x509_proxy; /* [brix_upstream_x509_proxy /path/proxy.pem]
                                        X.509 proxy (or EEC) chain the upstream
                                        connector presents when the upstream
                                        advertises `gsi` (phase 115 W2.4). */
    ngx_str_t   upstream_x509_key;   /* [brix_upstream_x509_key /path/key.pem]
                                        Separate private key; defaults to the
                                        proxy PEM (which carries its own key). */

    /* ---- TPC root-specific controls (shared policy lives in common) ---- */
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
    ngx_uint_t  tpc_max_hops;       /* [brix_tpc_max_hops 4] — F7: kXR_redirect
                                       hops the native pull follows from the
                                       client-named source (0 = refuse any;
                                       ceiling BRIX_TPC_HOPS_MAX). */
    ngx_uint_t  tpc_streams;        /* [brix_tpc_streams 1] — F7: cap on the
                                       parallel kXR_bind read streams one pull
                                       may open toward its source (the client's
                                       tpc.str is clamped to it). */
    /* tpc_verify_checksum moved to the shared preamble (common.tpc_verify_checksum)
     * in phase-101 W4 — unified on|off|<alg> grammar across planes; the native path
     * reads it as a boolean gate (kXR_Qcksum negotiates its own algorithm). */
    ngx_flag_t  tpc_push;           /* [brix_tpc_push on|off] — F16: operator
                                       opt-in for the BriX native root:// PUSH
                                       dialect (tpc.stage=push).  Off by default:
                                       with it off this server neither accepts a
                                       push-target write-open nor originates a
                                       push, and every push-tagged open is
                                       refused kXR_Unsupported.  Governs BOTH
                                       roles because a push makes the SOURCE dial
                                       out — the egress posture an operator opts
                                       into — and makes the DESTINATION accept
                                       bytes from a server rather than a client. */
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
    /*
     * ---- read-through cache ----
     *
     * On a cache miss (kXR_open for a path not in the cache store), the worker
     * connects to the export's registered root:// storage backend, downloads the
     * file, writes it to the store under the same relative path, and then serves
     * the cached copy. A lock file prevents multiple workers from filling the
     * same path.
     */
    ngx_flag_t  cache;              /* [brix_cache on|off] */
    ngx_str_t   cache_root;         /* [brix_cache_export /srv/xrd-cache] */

    /*
     * SYNTHETIC-CONF ONLY (§14, phase-64) — the four fields below are written by
     * NO directive. brix_cache_origin{,_tls} were retired with the legacy origin
     * config model; the endpoint now comes from brix_storage_backend. They stay
     * because sd_xroot (and gsi_upstream_login) build a synthetic srv_conf as the
     * parameter block for the in-process origin wire client, which reads them off
     * t->conf. Never gate a runtime feature on them: outside a synthetic conf they
     * are always empty/zero, which silently disarms whatever reads them (2.0
     * closed six such sites — see release-2.0-readiness.md §(c.4)). To learn a
     * backend's endpoint from a real conf, use brix_sd_xroot_endpoint().
     */
    ngx_str_t   cache_origin;       /* unused; kept for struct-shape stability */
    ngx_str_t   cache_origin_host;  /* synthetic: origin hostname / IP */
    uint16_t    cache_origin_port;  /* synthetic: origin TCP port */
    ngx_flag_t  cache_origin_tls;   /* synthetic: roots:// backend ⇒ TLS to origin */
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

    /* ---- durable async backend-op queue (brix_backend_async) ----
     * When enabled, backend MUTATIONS (unlink/rmdir/rename/mkdir/write-commit) are
     * routed through the per-worker durable coalescing queue instead of running
     * inline: the op is journalled (fsync, survives reboot), the client is PARKED,
     * and the batch is flushed in bulk to the backend when it reaches
     * backend_async_batch ops OR backend_async_wait ms elapse — whichever first;
     * the client is then answered with the real backend result (it may time out
     * waiting). Reads/stats/lists always pass through synchronously. The http-plane
     * S3/WebDAV modules carry a parallel loc-conf triple (tier_directives.h). */
    ngx_flag_t  backend_async;        /* [brix_backend_async on|off] */
    ngx_uint_t  backend_async_batch;  /* [brix_backend_async_batch N] flush at N ops */
    ngx_msec_t  backend_async_wait;   /* [brix_backend_async_wait 200ms] coalesce cap */
