#pragma once

/*
 * Module configuration types (ngx_stream_xrootd_srv_conf_t and its helpers).
 *
 * One ngx_stream_xrootd_srv_conf_t per `server {}` block containing `xrootd on;`.
 * nginx allocates it via create_srv_conf and merges parent into child in
 * merge_srv_conf.
 *
 * Requires: tunables.h, token/token.h, metrics/metrics.h, and nginx/OpenSSL
 *           headers before inclusion.
 */

/* ---- Helper structs used inside ngx_stream_xrootd_srv_conf_t ---- */

typedef struct {
    int64_t  id;
    time_t   exp;
    int      opts;
    size_t   key_len;
    u_char   key[XROOTD_SSS_KEY_MAX];
    char     name[XROOTD_SSS_NAME_MAX];
    char     user[XROOTD_SSS_USER_MAX];
    char     group[XROOTD_SSS_GROUP_MAX];
} xrootd_sss_key_t;

typedef enum {
    XROOTD_AUTH_USER  = 'u',
    XROOTD_AUTH_GROUP = 'g',
    XROOTD_AUTH_HOST  = 'p',
    XROOTD_AUTH_ALL   = 'a'
} xrootd_auth_type_t;

#define XROOTD_AUTH_READ    0x01  /* 'r' */
#define XROOTD_AUTH_LOOKUP  0x02  /* 'l' */
#define XROOTD_AUTH_UPDATE  0x04  /* 'w' or 'a' */
#define XROOTD_AUTH_DELETE  0x08  /* 'd' */
#define XROOTD_AUTH_MKDIR   0x10  /* 'm' */
#define XROOTD_AUTH_ADMIN   0x20  /* 'k' */

typedef struct {
    xrootd_auth_type_t type;
    ngx_str_t          id;       /* user DN, VO name, or hostname */
    ngx_str_t          path;
    uint32_t           privs;    /* bitmask */
    char               resolved[PATH_MAX];
} xrootd_authdb_rule_t;

typedef struct {
    ngx_str_t  path;
    ngx_str_t  vo;
    char       resolved[PATH_MAX];
} xrootd_vo_rule_t;

typedef struct {
    ngx_str_t  path;
    char       resolved[PATH_MAX];
} xrootd_group_rule_t;

typedef struct {
    ngx_str_t  prefix;   /* normalized policy-style prefix (NUL-terminated) */
    ngx_str_t  host;     /* backend host (text) */
    uint16_t   port;     /* backend port */
} xrootd_manager_map_t;

typedef struct {
    ngx_str_t  host;
    uint16_t   port;
    ngx_int_t  auth;                            /* XROOTD_PROXY_AUTH_* or -1 = inherit global */
    char       sss_keyname[XROOTD_SSS_NAME_MAX]; /* "" = use first key in conf->sss_keys       */
} xrootd_proxy_upstream_t;

/*
 * Per-server configuration block.
 * Directive names in square brackets show which nginx.conf directive
 * populates each field.
 */
typedef struct {
    ngx_flag_t  enable;  /* [xrootd on|off] — 0 until xrootd_enable sets it */

    /* ---- export root ---- */
    ngx_str_t   root;    /* [xrootd_root /data/xrd] — filesystem root for
                            all path resolution; client paths are restricted
                            to this subtree by xrootd_resolve_path() */

    /* ---- authentication ---- */
    ngx_uint_t  auth;    /* [xrootd_auth none|gsi|token|both] — one of the
                            XROOTD_AUTH_* constants in tunables.h */

    /* ---- GSI / x509 settings (used when auth = gsi or both) ---- */
    ngx_str_t   certificate;      /* [xrootd_certificate /etc/grid.pem] */
    ngx_str_t   certificate_key;  /* [xrootd_certificate_key /etc/grid.key] */
    ngx_str_t   trusted_ca;       /* [xrootd_trusted_ca /etc/grid-security/certificates]
                                     PEM file or directory of trusted CA certs */
    ngx_str_t   vomsdir;          /* [xrootd_vomsdir /etc/grid-security/vomsdir]
                                     VOMS LSC directory for attribute cert verification */
    ngx_str_t   voms_cert_dir;    /* [xrootd_voms_cert_dir /etc/grid-security/certificates]
                                     CA cert directory for VOMS server certificate chains */
    ngx_str_t   crl;              /* [xrootd_crl /etc/grid-security/certificates]
                                     PEM CRL file or directory; reloaded on crl_timer */
    time_t      crl_reload;       /* [xrootd_crl_reload 3600] — seconds between CRL
                                     re-scans; 0 = never reload */

    /* ---- VO access-control lists ---- */
    ngx_array_t  *vo_rules;     /* xrootd_vo_rule_t[] from xrootd_require_vo */
    ngx_str_t     authdb;       /* [xrootd_authdb /etc/xrootd/authdb] */
    ngx_array_t  *authdb_rules; /* xrootd_authdb_rule_t[] parsed from authdb */
    ngx_array_t  *group_rules;  /* xrootd_group_rule_t[] from xrootd_inherit_parent_group */
    ngx_array_t  *manager_map;  /* xrootd_manager_map_t[] from xrootd_manager_map */

    /* ---- Loaded OpenSSL objects (populated at postconfiguration / init_process) ---- */
    X509        *gsi_cert;     /* server certificate parsed from 'certificate' */
    EVP_PKEY    *gsi_key;      /* server private key parsed from 'certificate_key' */
    X509_STORE  *gsi_store;    /* combined CA + CRL trust store for verification */
    u_char      *gsi_cert_pem; /* PEM form cached for kXGS_cert responses */
    size_t       gsi_cert_pem_len;
    uint32_t     gsi_ca_hash;  /* subject name hash of our CA cert (sent to clients) */

    /* Timer that fires crl_reload-seconds after init to rebuild gsi_store */
    ngx_event_t *crl_timer;   /* heap-allocated in init_process; NULL if disabled */

    /* ---- write operations ---- */
    ngx_flag_t   allow_write;  /* [xrootd_allow_write on|off] — gates all mutation
                                   opcodes; per-op token scope checks still apply */

    /* ---- JWT / WLCG bearer-token settings (used when auth = token or both) ---- */
    ngx_str_t   token_jwks;      /* [xrootd_token_jwks /etc/xrd/jwks.json] */
    ngx_str_t   token_issuer;    /* [xrootd_token_issuer https://cilogon.org] */
    ngx_str_t   token_audience;  /* [xrootd_token_audience https://storage.example.org] */
    ngx_str_t   token_macaroon_secret;     /* [xrootd_macaroon_secret <hex>] */
    ngx_str_t   token_macaroon_secret_old; /* [xrootd_macaroon_secret_old <hex>]
                                              grace-period key: tokens signed with
                                              this key are also accepted so that
                                              in-flight tokens survive nginx -s reload
                                              while the operator rotates secrets. */

    /* JWKS keys parsed at postconfiguration from token_jwks */
    xrootd_jwks_key_t  jwks_keys[XROOTD_MAX_JWKS_KEYS];
    int                 jwks_key_count;  /* 0 if token auth is not configured */

    /* ---- Simple Shared Secret settings (used when auth = sss) ---- */
    ngx_str_t    sss_keytab;    /* [xrootd_sss_keytab /etc/xrootd/sss.keytab] */
    time_t       sss_lifetime;  /* credential lifetime in seconds; default 13 */
    ngx_array_t *sss_keys;      /* xrootd_sss_key_t[] parsed from sss_keytab */

    /* ---- access log ---- */
    ngx_str_t   access_log;     /* [xrootd_access_log /var/log/xrootd-access.log] */
    ngx_fd_t    access_log_fd;  /* opened fd; NGX_INVALID_FILE if not configured */

    /* ---- Prometheus metrics ---- */
    ngx_int_t   metrics_slot;  /* index into the shared-memory metrics array;
                                   -1 if the server has no bound listen address yet */

    /* ---- upstream redirector ---- */
    ngx_str_t   upstream_host;  /* [xrootd_upstream host:port] — hostname/IP */
    uint16_t    upstream_port;  /* TCP port of the upstream redirector */

    /* ---- TPC SSRF policy ---- */
    ngx_flag_t  tpc_allow_local;    /* [xrootd_tpc_allow_local on|off] — allow
                                       TPC pulls from loopback (127/8, ::1) and
                                       link-local (169.254/16, fe80::/10) addresses.
                                       Default off: these cannot be legitimate
                                       XRootD federation nodes and are a SSRF surface. */
    ngx_flag_t  tpc_allow_private;  /* [xrootd_tpc_allow_private on|off] — allow
                                       TPC pulls from RFC-1918 private addresses
                                       (10/8, 172.16/12, 192.168/16).
                                       Default on: storage federation nodes commonly
                                       live on private networks. */
    ngx_msec_t  tpc_key_ttl_ms;     /* [xrootd_tpc_key_ttl 60s] — lifetime of
                                       in-flight TPC rendezvous keys in the shared
                                       registry (source-side register / consume). */
    ngx_str_t   tpc_outbound_bearer_file; /* [xrootd_tpc_outbound_bearer_file path]
                                            JWT for outbound TPC kXR_auth ztn when
                                            the remote source advertises token auth. */

    /* ---- TPC OAuth2/OIDC token delegation ---- */
    ngx_str_t   tpc_outbound_token_endpoint; /* [xrootd_tpc_outbound_token_endpoint URL]
                                                 OAuth2 token endpoint for RFC 8693
                                                 token exchange when delegating credentials
                                                 to a protected TPC source. */
    ngx_str_t   tpc_outbound_client_id;       /* [xrootd_tpc_outbound_client_id ID]
                                                  OAuth2 client ID for confidential
                                                  client token exchange. */
    ngx_str_t   tpc_outbound_client_secret;   /* [xrootd_tpc_outbound_client_secret SECRET]
                                                  OAuth2 client secret for confidential
                                                  client token exchange. */
    ngx_str_t   tpc_outbound_scope;           /* [xrootd_tpc_outbound_scope SCOPE]
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
    ngx_flag_t  cache;              /* [xrootd_cache on|off] */
    ngx_str_t   cache_root;         /* [xrootd_cache_root /srv/xrd-cache] */
    ngx_str_t   cache_origin;       /* [xrootd_cache_origin host:port] — raw directive */
    ngx_str_t   cache_origin_host;  /* parsed hostname / IP */
    uint16_t    cache_origin_port;  /* parsed TCP port */
    ngx_flag_t  cache_origin_tls;   /* [xrootd_cache_origin_tls on] — TLS to origin */
    time_t      cache_lock_timeout; /* [xrootd_cache_lock_timeout 30] — how long to
                                       wait for another worker's fill before giving up */
    ngx_uint_t  cache_eviction_threshold; /* [xrootd_cache_eviction_threshold 0.9]
                                             filesystem occupancy ratio in ppm */
    off_t       cache_max_file_size;      /* [xrootd_cache_max_file_size 1g]
                                             Files larger than this are not admitted
                                             to cache unless their basename matches
                                             cache_include_regex.  0 = no limit. */
    ngx_str_t   cache_include_regex_str;  /* [xrootd_cache_include_regex "\.root$"]
                                             POSIX extended regular expression matched
                                             against the path basename; a match always
                                             admits the file regardless of size. */
    regex_t     cache_include_regex;      /* compiled POSIX ERE; valid only when
                                             cache_include_regex_set is 1 */
    ngx_flag_t  cache_include_regex_set;  /* 1 after a successful regcomp() */

    /* ---- in-protocol TLS upgrade (kXR_ableTLS) ---- */
    ngx_flag_t  tls;      /* [xrootd_tls on|off] — advertise kXR_haveTLS */
    ngx_ssl_t  *tls_ctx;  /* SSL_CTX built from certificate/key at postconfiguration */

    /* ---- cluster / redirector mode ---- */
    ngx_flag_t  manager_mode;  /* [xrootd_manager_mode on|off] — query the
                                   server registry in kXR_open and kXR_locate
                                   before attempting local resolution */
    ngx_uint_t  registry_slots; /* [xrootd_registry_slots N] — shared-memory
                                    registry capacity; default 128 */

    /* ---- CMS manager heartbeat ---- */
    ngx_msec_t            cms_locate_timeout; /* [xrootd_cms_locate_timeout 5s]
                                                  how long to wait for a kYR_select
                                                  reply before returning an error */
    ngx_str_t             cms_manager;   /* [xrootd_cms_manager host:port] — raw directive */
    ngx_addr_t           *cms_addr;      /* resolved manager address */
    ngx_str_t             cms_paths;     /* [xrootd_cms_paths /data] — exported path list */
    time_t                cms_interval;  /* [xrootd_cms_interval 60] — heartbeat period */
    ngx_int_t             listen_port;   /* [xrootd_listen_port 1094] — port advertised to CMS manager */
    ngx_xrootd_cms_ctx_t *cms_ctx;       /* runtime connection / timer state (heap) */
    ngx_uint_t            cms_suspended; /* set by kYR_status suspend; cleared by resume */

#if (NGX_THREADS)
    /* ---- async I/O thread pool ---- */
    ngx_thread_pool_t  *thread_pool;       /* resolved pool handle */
    ngx_str_t           thread_pool_name;  /* [xrootd_thread_pool xrd_io] */
#endif

    /* ---- transparent proxy mode ---- */
    ngx_flag_t  proxy_enable;  /* [xrootd_proxy on|off] */
    ngx_str_t   proxy_host;    /* [xrootd_proxy_upstream host] */
    ngx_int_t   proxy_port;    /* [xrootd_proxy_upstream host:port] */

    /* Wrap the outbound TCP socket in TLS before sending the bootstrap. */
    ngx_flag_t  proxy_upstream_tls;    /* [xrootd_proxy_upstream_tls on|off] */
#if (NGX_SSL)
    ngx_ssl_t  *proxy_tls_ctx;         /* SSL_CTX built at postconfiguration */
#endif

    /* Auth forwarding policy. */
    ngx_uint_t  proxy_auth;            /* [xrootd_proxy_auth anonymous|forward|sss] */
#define XROOTD_PROXY_AUTH_ANONYMOUS  0
#define XROOTD_PROXY_AUTH_FORWARD    1
#define XROOTD_PROXY_AUTH_SSS        2

    /* One JSON line per closed/abandoned upstream file handle. */
    ngx_str_t   proxy_audit_log;       /* [xrootd_proxy_audit_log <path>|off] */
    ngx_fd_t    proxy_audit_log_fd;    /* opened fd; NGX_INVALID_FILE if off */

    /* Upstream TLS certificate verification (requires proxy_upstream_tls on). */
    ngx_str_t   proxy_upstream_tls_ca;    /* [xrootd_proxy_upstream_tls_ca /etc/pki/ca.pem]
                                             PEM CA bundle to verify upstream certificate */
    ngx_str_t   proxy_upstream_tls_name;  /* [xrootd_proxy_upstream_tls_name host]
                                             SNI hostname override; defaults to proxy_host */

    /* Reconnect on upstream drop (0 = disabled). */
    ngx_uint_t  proxy_reconnect_attempts; /* [xrootd_proxy_reconnect_attempts N]
                                             reconnect budget per connection when upstream
                                             drops while idle with no open file handles */

    /* Multiple upstream endpoints — round-robin selected at connect time. */
    ngx_array_t *proxy_upstreams;          /* xrootd_proxy_upstream_t[]; may be NULL */

    /* Path prefix rewriting applied to all outbound path-bearing opcodes. */
    ngx_str_t   proxy_path_strip;          /* [xrootd_proxy_path_rewrite strip add] */
    ngx_str_t   proxy_path_add;

    /* Upstream connect and idle-read timeouts. */
    ngx_msec_t  proxy_connect_timeout;    /* [xrootd_proxy_connect_timeout 10s] */
    ngx_msec_t  proxy_read_timeout;       /* [xrootd_proxy_read_timeout 60s] */
} ngx_stream_xrootd_srv_conf_t;
