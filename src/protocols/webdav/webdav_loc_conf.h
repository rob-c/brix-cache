#ifndef NGX_HTTP_BRIX_WEBDAV_LOC_CONF_H
#define NGX_HTTP_BRIX_WEBDAV_LOC_CONF_H

/*
 * webdav_loc_conf.h — the ngx_http_brix_webdav_loc_conf_t location-config struct,
 * split (phase-79 file-size burndown) out of the oversized webdav.h with ZERO
 * ABI change (the struct type is identical; every consumer sees it via webdav.h,
 * which includes this at the same point the struct used to be defined). Included
 * at that point in webdav.h and DEPENDS on the types declared above it there
 * (ngx_http_brix_shared_conf_t, the lock/export structs, ngx/openssl includes) —
 * do not include directly; include "webdav.h".
 */

typedef struct {
    ngx_http_brix_shared_conf_t common; /* enable, root, root_canon, allow_write,
                                             thread_pool_name, thread_pool */

    /* --- Optional read-through cache root --- */
    ngx_str_t   cache_root;               /* [brix_webdav_cache_root /path] */
    char        cache_root_canon[PATH_MAX]; /* realpath-resolved form; "" = disabled */

    /* --- VOMS VO extraction (optional; requires libvomsapi) --- */
    ngx_str_t   vomsdir;       /* [brix_webdav_vomsdir /etc/grid-security/vomsdir] */
    ngx_str_t   voms_cert_dir; /* [brix_webdav_voms_cert_dir /etc/grid-security/certificates] */

    /* --- X.509 / GSI authentication --- */
    ngx_str_t      cadir;           /* directory of trusted CA PEM files */
    ngx_str_t      cafile;          /* single trusted CA bundle PEM file */
    ngx_str_t      crl;             /* directory of CRL PEM files */
    ngx_uint_t     signing_policy_mode; /* [brix_webdav_signing_policy] BRIX_SP_MODE_* */
    ngx_uint_t     crl_mode;        /* [brix_webdav_crl_mode] BRIX_CRL_MODE_* */
    ngx_uint_t     verify_depth;    /* max proxy chain depth for VOMS proxies;
                                     * RFC 3820 §4 recommends <= 3 for WLCG */
    ngx_uint_t     auth;            /* webdav_auth_t: NONE/OPTIONAL/REQUIRED */
    ngx_flag_t     proxy_certs;     /* 1 to accept RFC 3820 proxy certificates */
    X509_STORE    *ca_store;        /* loaded trust store; built at postconfiguration;
                                     * NULL if no CA dir/file configured */

    /* --- Write permissions / TPC --- */
    ngx_flag_t     tpc;             /* 1 to allow HTTP-TPC (third-party copy) */
    ngx_flag_t     tape_rest;       /* 1 to serve the WLCG /api/v1 Tape REST API */
    ngx_flag_t     upload_resume;   /* [brix_webdav_upload_resume on|off] default
                                     * ON.  When on, a Content-Range PUT writes its
                                     * chunk to a persistent identity-keyed partial
                                     * at the given offset and commits only when the
                                     * upload is complete; a 409 reports X-Upload-
                                     * Offset.  Lets a davs:// upload resume across
                                     * an nginx restart.  See src/webdav/put.c. */
    ngx_str_t      upload_stage_dir;      /* [brix_webdav_stage_dir <path>] optional
                                     * fast-cache staging device; empty = stage
                                     * adjacent to the destination. */
    char           upload_stage_dir_canon[PATH_MAX];

    /* --- HTTP-TPC SSRF policy --- */
    ngx_flag_t     tpc_allow_local;   /* 0: reject loopback+link-local targets */
    ngx_flag_t     tpc_allow_private; /* 0: reject RFC-1918 / ULA targets */

    /* --- HTTP-TPC (curl-based pull) settings --- */
    ngx_str_t      tpc_curl;        /* path to curl binary */
    ngx_str_t      tpc_cert;        /* client cert PEM for TPC pull */
    ngx_str_t      tpc_key;         /* private key PEM for TPC pull */
    ngx_str_t      tpc_cadir;       /* CA dir for TPC pull verification */
    ngx_str_t      tpc_cafile;      /* CA bundle for TPC pull verification */
    ngx_uint_t     tpc_timeout;     /* curl --max-time in seconds */
    /* Phase 39 (WS4): HTTP-TPC stall bounding for a slow/black-holed remote.
     * Both default 0 (off) = current behaviour.  When both > 0 they map to
     * CURLOPT_LOW_SPEED_LIMIT/TIME: abort a transfer that stays below
     * tpc_low_speed_bytes B/s for tpc_low_speed_secs, WITHOUT killing a
     * slow-but-progressing one.  (A fixed CURLOPT_CONNECTTIMEOUT + TCP keepalive
     * are always applied — see tpc_curl_apply_stall_bounds.) */
    ngx_uint_t     tpc_low_speed_bytes; /* CURLOPT_LOW_SPEED_LIMIT (B/s); 0 = off */
    ngx_uint_t     tpc_low_speed_secs;  /* CURLOPT_LOW_SPEED_TIME (s);   0 = off */
    ngx_uint_t     tpc_marker_interval; /* seconds between Perf Markers; 0 = 201 only */
    ngx_uint_t     tpc_max_streams;     /* max parallel streams per pull; 0 = single */

    /* [brix_webdav_tpc_credential_forward on|off] default ON.  When on, a TPC
     * PULL acts as the END USER against the source by default: it resolves the
     * requesting identity's delegated x509 proxy (webdav_tpc_user_proxy_resolve)
     * and, when the client did not explicitly delegate one, forwards the raw
     * bearer the request authenticated with (rctx->bearer_token).  Opportunistic:
     * the absence of any per-user credential falls back to conf->tpc_cert /
     * anonymous exactly as before — never a new denial.  Off = service-cert-only
     * (pre-forwarding behaviour).  Independent of brix_backend_delegation, which
     * governs the data-plane backend leg, not TPC. */
    ngx_flag_t     tpc_credential_forward;

    /* --- HTTP-TPC OAuth2/OIDC credential delegation --- */
    ngx_http_brix_tpc_conf_t tpc_cred;

    /* --- Bearer token (WLCG/SciToken) settings --- */
    ngx_str_t      token_jwks;      /* path to JWKS file for RS256 validation */
    ngx_str_t      token_issuer;    /* required "iss" claim; "" to skip check */
    ngx_str_t      token_audience;  /* required "aud" claim; "" to skip check */
    ngx_int_t      token_clock_skew; /* [brix_webdav_token_clock_skew 30] seconds of
                                        exp grace; NGX_CONF_UNSET = inherit/default
                                        (BRIX_TOKEN_CLOCK_SKEW_SECS); max 300 */
    ngx_str_t      token_config;    /* [brix_webdav_token_config <scitokens.cfg>]
                                       multi-issuer registry (phase-59 W1) */
    void          *token_registry;  /* brix_token_registry_t* or NULL */
    ngx_str_t      token_macaroon_secret;     /* [brix_webdav_macaroon_secret <hex>] */
    ngx_str_t      token_macaroon_secret_old; /* [brix_webdav_macaroon_secret_old <hex>]
                                                 grace-period key accepted alongside the
                                                 primary secret during key rotation. */
    brix_jwks_key_t  jwks_keys[BRIX_MAX_JWKS_KEYS]; /* loaded RSA pub keys */
    int                 jwks_key_count;  /* number of valid entries in jwks_keys */
    ngx_flag_t          http_query_token; /* accept ?authz=<token> (default on) */
    ngx_int_t           macaroon_max_validity; /* seconds cap for macaroon-request */
    ngx_str_t           macaroon_location;      /* location: caveat (issuer URI) */
    ngx_str_t           checksum_on_write; /* §8.3 alg list to persist at PUT (off="") */
    ngx_uint_t          checksum_xattr_format; /* §8.x BRIX_CKS_FMT_TEXT|XRDCKS */
    ngx_flag_t          dig_enable;        /* §3 XrdDig remote diagnostics (default off) */
    ngx_array_t        *dig_exports;       /* §3 of brix_dig_export_t (name→canon dir) */
    ngx_str_t           dig_auth_file;     /* §3 principal→export allow-file (fail-closed) */

    /* Phase-2 Task 8: opt-in authenticated proxy-upload delegation endpoint.
     * When on, a GSI-cert-authenticated PUT/POST to
     * /.well-known/brix-delegation with body = the client's own RFC-3820
     * proxy PEM validates and stores it under storage_credential_dir so
     * Phase-1 per-user credential selection picks it up. Default off. */
    ngx_flag_t          delegation_endpoint;

    /* --- CORS settings --- */
    ngx_array_t        *cors_origins;    /* allowed origins (ngx_str_t array) */
    ngx_flag_t          cors_credentials; /* Access-Control-Allow-Credentials */
    ngx_uint_t          cors_max_age;     /* Access-Control-Max-Age in seconds */

    /* --- ZIP member access (phase-57 W2) ---
     * [brix_webdav_zip_access on|off] — opt-in, off by default.  A GET whose
     * query carries "?xrdcl.unzip=<member>" serves that member of the archive
     * (stored + deflate).  Unlike root://, an HTTP client cannot self-inflate,
     * so the server must extract.  zip_cd_max_bytes caps the central-directory
     * read (bomb guard; default 16 MiB). */
    ngx_flag_t          zip_access;
    size_t              zip_cd_max_bytes;

    /* --- WebDAV LOCK --- */
    ngx_uint_t          lock_timeout;    /* max lock timeout in seconds */
    ngx_flag_t          lock_startup_sweep; /* on = remove all persisted lock
                                             * xattrs under the export root at
                                             * startup (restores ephemeral,
                                             * RFC 4918 §10.1 semantics). off by
                                             * default: locks survive restart */

    /* --- Open file cache --- */
    ngx_open_file_cache_t  *open_file_cache;
    ngx_uint_t              open_file_cache_valid;
    ngx_uint_t              open_file_cache_min_uses;
    ngx_flag_t              open_file_cache_errors;
    ngx_flag_t              open_file_cache_events;

    /* --- Upstream HTTP(S) proxy --- */
    ngx_flag_t                    upstream_proxy;      /* brix_webdav_proxy on/off */
    ngx_str_t                     upstream_url;        /* brix_webdav_proxy_upstream URL */
    ngx_str_t                     upstream_host;       /* host[:port] for Host: header */
    ngx_str_t                     upstream_url_base;   /* scheme://host:port */
    ngx_uint_t                    upstream_auth;       /* webdav_proxy_auth_t */
    ngx_str_t                     upstream_auth_token; /* Bearer token value (TOKEN mode) */
    ngx_flag_t                    upstream_ssl;        /* 1 if https:// upstream */
    ngx_http_upstream_conf_t      upstream_conf;       /* timeouts, buffer_size, etc. */
    ngx_http_upstream_resolved_t *upstream_resolved;   /* pre-resolved address (backend[0]) */
#if (NGX_HTTP_SSL)
    ngx_ssl_t                    *upstream_ssl_ctx;    /* SSL context for https upstream */
#endif

    /* ---- Phase 21 Step D: multi-backend proxy (round-robin + health) ---- */
    ngx_array_t                  *upstream_urls;       /* ngx_str_t[] from the directive */
    ngx_array_t                  *upstream_backends;   /* brix_webdav_backend_t[] */
    ngx_atomic_t                  upstream_rr;         /* per-worker round-robin cursor */
    ngx_uint_t                    upstream_max_fails;  /* [brix_webdav_proxy_max_fails N] */
    ngx_msec_t                    upstream_fail_timeout; /* [..._proxy_fail_timeout Ns] */

    /* ---- Phase 23: dynamic SHM backend pool (runtime add/remove/drain) ---- */
    ngx_flag_t                    proxy_pool_enabled;  /* [brix_webdav_proxy_dynamic on] */

    /* ---- Phase 20: shared-memory caches & rate limiting ---- */
    brix_kv_t                  *token_cache_kv; /* [brix_token_cache zone=]
                                                     JWT validation cache (L2/SHM); NULL = off */
    /* Phase 50: always-on per-worker L1 token-validation cache (lockless),
     * lazily created on first token auth — see token/worker_cache.h. */
    struct brix_token_l1_s     *token_l1;
    brix_rate_limit_conf_t      rate_limit;     /* [brix_rate_limit zone= rate= burst= key=]
                                                     per-IP request throttle; kv NULL = off */

    /* ---- Phase 21 Step C: OIDC token introspection (revocation) ---- */
    ngx_str_t      introspect_url;       /* [..._token_introspect_url <url>] (display/doc) */
    ngx_str_t      introspect_loc;       /* [..._token_introspect_loc /internal] internal URI */
    ngx_uint_t     introspect_ttl;       /* [..._token_introspect_ttl N] revoke-cache TTL (s) */
    ngx_flag_t     introspect_fail_open; /* [..._token_introspect_fail_open on|off] */
    brix_kv_t   *revoke_kv;            /* [..._revoke_cache zone=] revoked-token cache */

    /* ---- Phase 24: traffic mirroring (off by default) ---- */
    brix_mirror_conf_t      mirror;            /* [brix_mirror_url, _mirror_*] */
    ngx_http_upstream_conf_t  mirror_upstream_conf; /* shadow upstream defaults */
#if (NGX_HTTP_SSL)
    ngx_ssl_t                *mirror_ssl_ctx;    /* TLS ctx for https shadow targets */
#endif

    /* ---- Phase 25: advanced rate limiting (off by default) ---- */
    ngx_array_t              *rl_rules;          /* brix_rl_rule_t[] from
                                                  [brix_rate_limit_rule /
                                                   _bandwidth_limit]; NULL = off */

    /* ---- XrdAcc authorization engine (off by default) ---- */
    brix_acc_http_t         acc;               /* settings + per-worker state */

    /* ---- Native authorization (read parity with root://) ----
     * Enforced for READ methods in the access phase (webdav_access), so a
     * cached GET is gated the same as a miss. Empty => not configured (no-op). */
    ngx_array_t            *authdb_rules;      /* [brix_webdav_authdb <file>] u/g/p rules   */
    ngx_array_t            *vo_rules;          /* [brix_webdav_require_vo <path> <vo>] VO ACL */

    /* Per-socket TCP congestion control (e.g. "bbr") applied to the HTTP
     * connection before the GET body is served; empty = kernel default.  The
     * sender's CC governs download throughput, and BBR ignores the spurious loss
     * signals packet reordering induces. [brix_tcp_congestion] */
    ngx_str_t                 tcp_congestion;
} ngx_http_brix_webdav_loc_conf_t;

#endif /* NGX_HTTP_BRIX_WEBDAV_LOC_CONF_H */
