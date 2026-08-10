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

    /* cache_root + cache_root_canon moved to the shared preamble (common.*) —
     * phase-101 W8; brix_cache_root is registered by the common module. */

    /* --- VOMS VO extraction (optional; requires libvomsapi) --- */
    /* vomsdir/voms_cert_dir moved to common preamble (phase-101 W4). */

    /* --- X.509 / GSI authentication --- */
    ngx_str_t      cadir;           /* directory of trusted CA PEM files */
    ngx_str_t      cafile;          /* single trusted CA bundle PEM file */
    /* crl/crl_mode/signing_policy_mode moved to common preamble (phase-101 W4). */
    ngx_uint_t     verify_depth;    /* max proxy chain depth for VOMS proxies;
                                     * RFC 3820 §4 recommends <= 3 for WLCG */
    ngx_uint_t     auth;            /* webdav_auth_t: NONE/OPTIONAL/REQUIRED */
    /* protbind moved to the shared preamble (common.protbind) — phase-101 W4;
     * brix_protbind now registered by the common module, adopted here. */
    ngx_flag_t     proxy_certs;     /* 1 to accept RFC 3820 proxy certificates */
    ngx_str_t      ssl_client_capath; /* [brix_client_ca_store <dir>] OpenSSL
                                     * hashed CA directory (IGTF layout, e.g.
                                     * /etc/grid-security/certificates) ADDED to
                                     * the server's TLS client-verify store at
                                     * postconfiguration, so ssl_verify_client
                                     * can trust a hash dir that stock nginx's
                                     * file-only ssl_client_certificate cannot
                                     * express.  Server-level; "" = off. */
    ngx_str_t      proxy_ssl_capath; /* [brix_backend_ca_dir <dir>] OpenSSL
                                     * hashed CA directory ADDED to this
                                     * location's upstream (proxy_ssl) trust
                                     * store at postconfiguration; the handler
                                     * also injects one <hash>.N file as the
                                     * stock proxy_ssl_trusted_certificate so
                                     * proxy_ssl_verify's mandatory-file check
                                     * passes.  Location-exact (deliberately
                                     * NOT merged/inherited); "" = off. */
    X509_STORE    *ca_store;        /* loaded trust store; built at postconfiguration;
                                     * NULL if no CA dir/file configured */

    /* --- Write permissions / TPC --- */
    ngx_flag_t     tpc;             /* 1 to allow HTTP-TPC (third-party copy) */
    ngx_flag_t     tape_rest;       /* 1 to serve the WLCG /api/v1 Tape REST API */
    /* upload_resume moved to common preamble (phase-101 W4). */
    /* upload_stage_dir moved to common preamble (W4); *_canon stays here. */
    char           upload_stage_dir_canon[PATH_MAX];

    /* --- HTTP-TPC SSRF policy: allow_local/allow_private/source_guard/
     * source_allow moved to the shared preamble (common.tpc_*) — phase-101 W4;
     * bare brix_tpc_* registered by the common module, adopted here. --- */

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
    ngx_uint_t     tpc_xfr;             /* [brix_webdav_tpc_xfr N] §6.9 explicit
                                           concurrent-transfer cap; 0 = bound only
                                           by the registry slot ceiling (default) */
    time_t         maxdelay;            /* [brix_webdav_maxdelay <time>] §6.11
                                           http.maxdelay analog: CAP on the
                                           Retry-After seconds a 202 "staging"
                                           (tape-recall) response tells the client
                                           to wait. 0 = off (emit the default 10s). */

    /* --- HTTP-TPC pull completion gate.  Both halves are evaluated after the
     * last byte lands in the staged temp and before it is committed, so a refused
     * pull leaves no file behind.
     *   common.tpc_require_source_size  [brix_tpc_require_source_size on|off]
     *       (phase-101 W4: moved to the shared preamble) off (default): a source
     *       that declares no Content-Length is pulled anyway; on: such a pull is
     *       refused as unverifiable.  Whenever the source DOES declare a length it
     *       is always compared against the bytes received — needs no opt-in.
     *   common.tpc_verify_checksum  [brix_tpc_verify_checksum on|off|<alg>]
     *       (phase-101 W4: unified onto the shared preamble) "" = off; otherwise a
     *       canonical RFC-3230 algorithm name sent as Want-Digest on the completion
     *       probe, recomputed over the staged temp, fail-closed on mismatch.  "on"
     *       normalizes to "adler32" (the XRootD/WLCG default). */

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

    /* --- HTTP Basic password auth (pwd db) ---
     * pwd_file moved to the common preamble (common.pwd_file) in phase-101 W4;
     * brix_webdav_pwd_file is now the bare brix_pwd_file. */

    /* --- Bearer token (WLCG/SciToken) settings ---
     * token_jwks/issuer/audience/clock_skew/config moved to the common preamble
     * (common.token_*) in phase-101 W4. */
    void          *token_registry;  /* brix_token_registry_t* or NULL — the built
                                       registry stays webdav-local; the source path
                                       is common.token_config (W4). */
    /* token_macaroon_secret[_old] moved to the common preamble
     * (common.token_macaroon_secret[_old]) in phase-101 W4. */
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
    time_t              cors_max_age;     /* [brix_webdav_cors_max_age] Access-Control-
                                           * Max-Age; sec_slot (phase-101 W7): accepts
                                           * nginx time units, e.g. 1h == 3600 */

    /* --- ZIP member access (phase-57 W2) ---
     * [brix_webdav_zip_access on|off] — opt-in, off by default.  A GET whose
     * query carries "?xrdcl.unzip=<member>" serves that member of the archive
     * (stored + deflate).  Unlike root://, an HTTP client cannot self-inflate,
     * so the server must extract.  zip_cd_max_bytes caps the central-directory
     * read (bomb guard; default 16 MiB). */
    /* zip_access/zip_cd_max_bytes moved to common preamble (W4). */

    /* --- WebDAV LOCK --- */
    time_t              lock_timeout;    /* [brix_webdav_lock_timeout] max lock
                                          * timeout; sec_slot (phase-101 W7): accepts
                                          * nginx time units, e.g. 5m == 300 */
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

    /* XrdAcc authorization engine moved to the shared preamble (common.acc) in
     * phase-101 W2 — registered once on the common module, read via common.acc. */

    /* ---- Native authorization (read parity with root://) ----
     * Enforced for READ methods in the access phase (webdav_access), so a
     * cached GET is gated the same as a miss. Empty => not configured (no-op). */
    /* authdb_rules moved to common.authdb_rules (phase-101 W5.2) — shared across
     * all HTTP planes, enforced in each protocol's access phase. */
    /* vo_rules moved to the shared preamble (common.vo_rules) — phase-101 W4;
     * brix_require_vo now registered by the common module, adopted here. */

    /* Per-socket TCP congestion control (e.g. "bbr") applied to the HTTP
     * connection before the GET body is served; empty = kernel default.  The
     * sender's CC governs download throughput, and BBR ignores the spurious loss
     * signals packet reordering induces. [brix_tcp_congestion] */
    ngx_str_t                 tcp_congestion;

    /* Client->server PUT ingest integrity: when on, a PUT that carries no usable
     * ingest digest (RFC-3230 Digest / legacy Content-MD5) is refused, for
     * deployments that decline writes they cannot verify.  Default off.  A digest
     * that IS present is always verified over the staged bytes before commit,
     * regardless of this flag. */
    ngx_flag_t                require_digest;

    /* ---- §6.1: HTTP redirect-to-dataserver + signed-CGI handoff ----
     * Manager side: with redirect_dataserver on (and the stream module's CMS
     * registry populated), a GET/HEAD/PUT is answered 307 to the registry-
     * selected data server instead of served locally.  http_secretkey (both
     * sides) signs the authenticated identity into the redirect CGI
     * (brixrdr.exp/usr/vo/mac, HMAC-SHA256) so the data server can adopt it
     * without a second authentication round; the data-server side verifies
     * fail-closed within redirect_window seconds.  redirect_port 0 = the
     * registry entry's (root://) port — the stock shared-port model;
     * deployments running HTTP on its own port set it explicitly.
     * Placed last to keep the struct's ABI stable. */
    ngx_flag_t                redirect_dataserver;
    ngx_int_t                 redirect_port;
    ngx_uint_t                redirect_scheme;  /* BRIX_WEBDAV_RDR_* */
    ngx_int_t                 redirect_window;  /* seconds; default 120 */
    ngx_str_t                 http_secretkey;

    /* §6.6 HTML directory listing on GET (the XrdHttp "Listing" analog).
     * html_listing off (default) keeps the stock listingdeny posture: a GET on
     * a directory is 403.  On renders an escaped HTML index (name/size/mtime)
     * from the same VFS readdir seam PROPFIND uses.  listing_redirect, when
     * set, is the listingredir analog: a GET on a directory 301-redirects
     * there (with the request path appended) instead of listing — checked
     * before html_listing. */
    ngx_flag_t                html_listing;
    ngx_str_t                 listing_redirect;
} ngx_http_brix_webdav_loc_conf_t;

#define BRIX_WEBDAV_RDR_HTTP   0
#define BRIX_WEBDAV_RDR_HTTPS  1

#endif /* NGX_HTTP_BRIX_WEBDAV_LOC_CONF_H */
