#ifndef XROOTD_TYPES_CONFIG_H
#define XROOTD_TYPES_CONFIG_H

/* ---- File: config.h — Per-server configuration struct + helper type definitions ----
 *
 * WHAT: Defines ngx_stream_xrootd_srv_conf_t (per-server configuration block) and five helper types used within it: xrootd_sss_key_t (Simple Shared Secret credential key with id/expiration/opts/key_bytes/name/user/group), xrootd_auth_type_t (enum — user DN, VO name, hostname, or all-match for ACL rules), xrootd_authdb_rule_t (ACL rule with auth type + identity/path + privilege bitmask + resolved path), xrootd_vo_rule_t (VO access rule with path prefix + VOMS VO name + resolved path), xrootd_group_rule_t (group inheritance rule with path prefix + resolved path), xrootd_manager_map_t (CMS manager map entry with policy-style prefix + backend host/port). Main struct fields annotated with directive names in brackets showing which nginx.conf directive populates each field. Includes OpenSSL objects (X509/EVP_PKEY/X509_STORE for GSI cert/key/trust store), timer events (crl_timer/jwks_timer), array types (vo_rules/authdb_rules/group_rules/manager_map/proxy_upstreams/wt_deny_prefixes/wt_allow_prefixes), and compiled regex (cache_include_regex).
 *
 * WHY: One srv_conf per `server {}` block — nginx allocates via create_srv_conf, merges parent config into child in merge_srv_conf. This single struct encapsulates all tunables for a server instance: authentication mode (GSI/token/SSS/anonymous), TLS settings (certificate/key/trusted CA/CRL/VOMS dirs), token auth (JWKS file/issuer/audience/macaroon secrets with grace-period rotation), VO ACLs, access log, Prometheus metrics slot, upstream redirector config, TPC SSRF policy + bearer file + OAuth2 delegation endpoints, read-through cache origin + eviction + size limits + include regex, write-through mode (sync/async) origin + deny/allow prefixes + decision callback, CMS manager heartbeat, transparent proxy mode (upstream TLS/auth/login user/audit log/reconnect attempts/multiple upstreams with path rewriting), OCSP stapling. Inline bracket annotations let contributors map each field back to its nginx directive without searching directives.c.
 *
 * HOW: Struct layout — helper typedefs first (lines 16-64) → includes tunables.h/shared_conf.h → main struct typedef (line 81) with sectioned fields in order: common shared conf, auth mode, GSI/x509 settings, VO ACL arrays, loaded OpenSSL objects + crl_timer, prepare_command hook, JWT/WLCG token settings + JWKS parsed keys + refresh interval + timer, SSS keytab + keys array, access log fd, Prometheus metrics slot, upstream redirector host/port/addr/tls_ctx/token_file, TPC SSRF flags + TTL + bearer file + OAuth2 endpoints, read-through cache (cache flag/root/origin/host:port/tls/lock timeout/eviction threshold/max size/include regex), write-through enable/mode/sync-async constants/origin/wt prefixes/decision callback, security level, in-protocol TLS flag/tls_ctx, manager_mode/registry_slots, CMS heartbeat fields, ckscan depth/files limits, proxy mode (enable/host/port/upstream_tls/tls_ctx/auth/login user/name/audit log/reconnect attempts/multiple upstreams/path rewrite/connect/read timeouts/keepalive interval), OCSP enable/soft_fail/stapling + staple data. */

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

/* Phase 24 — shared mirror config block embedded below (self-contained;
 * pulls only ngx_core, so safe to include from this header). */
#include "mirror/mirror.h"

/* Tape/stage directive config block (xrootd_frm_conf_t). Pulls only ngx_core, so
 * it is safe to include from this header. (FRM-dissolution: was ../frm/frm.h.) */
#include "core/config/tape_stage_conf.h"

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
    XROOTD_AUTHDB_HOST = 'p',   /* authdb rule type; distinct from the
                                 * XROOTD_AUTH_HOST auth-mode macro (tunables.h) */
    XROOTD_AUTH_ALL   = 'a'
} xrootd_auth_type_t;

#define XROOTD_AUTH_READ    0x01  /* 'r' */
#define XROOTD_AUTH_LOOKUP  0x02  /* 'l' */
#define XROOTD_AUTH_UPDATE  0x04  /* 'w' or 'a' */
#define XROOTD_AUTH_DELETE  0x08  /* 'd' */
#define XROOTD_AUTH_MKDIR   0x10  /* 'm' */
#define XROOTD_AUTH_ADMIN   0x20  /* 'k' */

/* The XrdAcc engine selector + audit constants live in src/acc/privs.h (pure,
 * shared by the stream / WebDAV / S3 modules); pulled in via the include below. */
#include "auth/authz/acc/privs.h"

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

#include "cache/writethrough_decision.h"
#include "core/config/shared_conf.h"

/* Phase 20 — shared-memory KV consumers (token cache, auth cache, rate limit).
 * These headers are lightweight (ngx core only) so embedding their config
 * structs here introduces no include cycle. */
#include "core/shm/kv.h"
#include "auth/authz/auth_cache.h"
#include "core/shm/rate_limit.h"

/*
 * Per-server configuration block.
 * Directive names in square brackets show which nginx.conf directive
 * populates each field.
 */
typedef struct {
    ngx_http_xrootd_shared_conf_t common; /* enable, root, root_canon, allow_write,
                                             thread_pool_name, thread_pool */

    /* ---- worker-process runtime infrastructure ---- */
    int  rootfd;          /* O_PATH fd on export root; -1 until worker init */

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
    time_t      crl_mtime;        /* Phase 51 (E5): st_mtime of `crl` at last
                                     successful store rebuild; the reload timer
                                     skips the (possibly large/slow) CRL re-parse
                                     when an unchanged regular-file CRL would just
                                     reproduce the same store. 0 = not yet loaded */

    /* ---- VO access-control lists ---- */
    ngx_array_t  *vo_rules;     /* xrootd_vo_rule_t[] from xrootd_require_vo */
    ngx_str_t     authdb;       /* [xrootd_authdb /etc/xrootd/authdb] */
    ngx_array_t  *authdb_rules; /* xrootd_authdb_rule_t[] parsed from authdb (native) */

    /* ---- XrdAcc engine (selected by `xrootd_authdb_format xrdacc`) ---- */
    ngx_uint_t    acc_format;        /* 0=native (default), 1=xrdacc */
    ngx_uint_t    acc_audit;         /* 0=none 1=deny 2=grant 3=all */
    ngx_int_t     acc_refresh;       /* authdb hot-reload interval, s; 0=off */
    ngx_int_t     acc_gidlifetime;   /* Unix group cache TTL, s */
    ngx_flag_t    acc_pgo;           /* resolve primary Unix group only */
    ngx_str_t     acc_nisdomain;     /* NIS domain for netgroup lookups */
    ngx_flag_t    acc_resolve_hosts; /* reverse-DNS peer for 'h' host rules */
    ngx_str_t     acc_spacechar;     /* legacy: char substituted for spaces in ids */
    ngx_flag_t    acc_encoding;      /* legacy: URI-decode authdb path tokens */
    ngx_str_t     acc_gidretran;     /* legacy: gids to skip in group resolution */
    struct xrootd_acc_tables_s *acc_tables; /* per-worker tables (init_process) */
    ngx_event_t  *acc_timer;         /* per-worker authdb refresh timer */
    ngx_array_t  *group_rules;  /* xrootd_group_rule_t[] from xrootd_inherit_parent_group */
    ngx_array_t  *manager_map;  /* xrootd_manager_map_t[] from xrootd_manager_map */

    /* ---- Loaded OpenSSL objects (populated at postconfiguration / init_process) ---- */
    X509        *gsi_cert;     /* server certificate parsed from 'certificate' */
    EVP_PKEY    *gsi_key;      /* server private key parsed from 'certificate_key' */
    X509_STORE  *gsi_store;    /* combined CA + CRL trust store for verification */
    u_char      *gsi_cert_pem; /* PEM form cached for kXGS_cert responses */
    size_t       gsi_cert_pem_len;
    uint32_t     gsi_ca_hash;  /* subject name hash of our CA cert (sent to clients) */

    /*
     * GSI signed-DH policy [xrootd_gsi_signed_dh off|auto|require] (phase-48).
     * Controls whether the server uses the modern RSA-signed-DH wire variant
     * (>=XrdSecgsiVersDHsigned/10400) instead of the universally-interoperable
     * unsigned-DH default.  Stored as XROOTD_GSI_SDH_* (see context.h dispatch):
     *   OFF (0, default) — always emit unsigned kXRS_puk (today's behaviour;
     *                      interoperates with every official client).
     *   AUTO (1)         — emit signed kXRS_cipher when the client advertises
     *                      version >= 10400, else fall back to unsigned.
     *   REQUIRE (2)      — signed only; reject clients that advertise < 10400.
     * NGX_CONF_UNSET until merged.
     */
    ngx_uint_t   gsi_signed_dh;

    /* Phase 51 (E4): per-worker cap on concurrently in-flight GSI handshakes.
     * A GSI handshake is multi-round-trip and CPU-heavy; under a flood of
     * simultaneous handshakes this sheds the excess (kXR_wait) so the event loop
     * is not buried.  Default 256 (far above normal load — only a genuine flood
     * trips it); 0 = unlimited. [xrootd_gsi_max_inflight_handshakes] */
    ngx_int_t    gsi_max_inflight;

    /* Per-worker ephemeral-DH keypool sizing (see src/gsi/keypool.c). At worker
     * start only `gsi_keypool_seed` keys are generated synchronously (keeping the
     * event thread free at boot); the pool is then filled off-thread up to
     * `gsi_keypool_size`.  Defaults 64 / 4.  size is clamped to the compile-time
     * ceiling XROOTD_GSI_KEYPOOL_CAP and seed to [1, size].
     * [xrootd_gsi_keypool_size N] [xrootd_gsi_keypool_seed N] */
    ngx_uint_t   gsi_keypool_size;
    ngx_uint_t   gsi_keypool_seed;

    /* Phase 52 (WS-A): [xrootd_gsi_ciphers "aes-256-cbc:aes-128-cbc:..."] the GSI
     * session-cipher preference list the server advertises (kXRS_cipher_alg).
     * Empty = the built-in default (aes-128-cbc first → unchanged behaviour).
     * The advertised list is filtered to ciphers this build can actually key, so
     * a client never selects one the server cannot decrypt. */
    ngx_str_t    gsi_ciphers;

    /* Timer that fires crl_reload-seconds after init to rebuild gsi_store */
    ngx_event_t *crl_timer;   /* heap-allocated in init_process; NULL if disabled */

    /* ---- tape staging hook ---- */
    ngx_str_t    prepare_command; /* [xrootd_prepare_command /path/to/stage.sh]
                                     Shell command invoked fire-and-forget when a
                                     kXR_prepare request has the kXR_stage flag set.
                                     argv: cmd  path1  path2  ...  (absolute, NUL-
                                     terminated resolved paths under xrootd_root).
                                     Empty = staging hint silently accepted (no-op). */

    /* ---- Phase 35: FRM durable tape-staging (off by default) ---- */
    xrootd_frm_conf_t  frm;       /* [xrootd_frm, xrootd_frm_queue_path, ...]
                                     durable stage-request queue + residency;
                                     frm.enable == 0 = no-op (legacy
                                     prepare_command path still fires). */

    /* ---- JWT / WLCG bearer-token settings (used when auth = token or both) ---- */
    ngx_str_t   token_jwks;      /* [xrootd_token_jwks /etc/xrd/jwks.json] */
    ngx_str_t   token_issuer;    /* [xrootd_token_issuer https://cilogon.org] */
    ngx_str_t   token_audience;  /* [xrootd_token_audience https://storage.example.org] */
    ngx_str_t   token_config;    /* [xrootd_token_config /etc/xrd/scitokens.cfg]
                                    multi-issuer registry (phase-59 W1); when set
                                    it overrides the single-issuer fields above */
    void       *token_registry;  /* xrootd_token_registry_t* built at postconfig;
                                    NULL = single-issuer path.  void* keeps
                                    issuer_registry.h out of this header. */

    /* ---- Phase-59 W3a: XrdThrottle contract (off by default) ---- */
    ngx_str_t   throttle_zone_name;  /* [xrootd_throttle_zone <rate-limit zone>] */
    void       *throttle_zone;       /* xrootd_rl_zone_t* resolved at postconfig */
    ngx_uint_t  throttle_max_open_files;     /* [xrootd_throttle_max_open_files] */
    ngx_uint_t  throttle_max_active_conn;    /* [xrootd_throttle_max_active_connections] */

    /* ---- Phase-59 W2: CSI per-page checksum tagstore (off by default) ---- */
    ngx_flag_t  csi_enable;      /* [xrootd_csi on|off] */
    ngx_str_t   csi_prefix;      /* [xrootd_csi_prefix /.xrdt] ("" = inline) */
    ngx_flag_t  csi_fill;        /* [xrootd_csi_fill on|off] tag hole pages */
    ngx_flag_t  csi_require;     /* [xrootd_csi_require on|off] missing tags=err */
    ngx_flag_t  csi_loose;       /* [xrootd_csi_loose on|off] recover retries */

    ngx_str_t   token_macaroon_secret;     /* [xrootd_macaroon_secret <hex>] */
    ngx_str_t   token_macaroon_secret_old; /* [xrootd_macaroon_secret_old <hex>]
                                              grace-period key: tokens signed with
                                              this key are also accepted so that
                                              in-flight tokens survive nginx -s reload
                                              while the operator rotates secrets. */

    /* JWKS keys parsed at postconfiguration from token_jwks */
    xrootd_jwks_key_t  jwks_keys[XROOTD_MAX_JWKS_KEYS];
    int                 jwks_key_count;  /* 0 if token auth is not configured */
    time_t              jwks_mtime;      /* st_mtime of token_jwks at last successful load */
    ngx_msec_t          token_jwks_refresh_interval; /* [xrootd_token_jwks_refresh_interval 60000ms]
                                                        Polling interval (ms) for mtime-based JWKS
                                                        hot refresh. NGX_CONF_UNSET_MSEC = disabled. */
    ngx_event_t        *jwks_timer;     /* per-worker timer event; NULL if not scheduled */

    /* ---- Phase 20: shared-memory caches & rate limiting ---- */
    xrootd_kv_t              *token_cache_kv;  /* [xrootd_token_cache zone=]
                                                  JWT validation cache (L2/SHM); NULL = off */
    /* Phase 50: always-on per-worker L1 token-validation cache (lockless),
     * lazily created on first token auth.  Collapses repeated token validation
     * (crypto + JSON parse, and the L2 spinlock) to an O(1) probe so token auth
     * does not stall the event loop under load.  See token/worker_cache.h. */
    struct xrootd_token_l1_s *token_l1;
    xrootd_auth_cache_conf_t  auth_cache;      /* [xrootd_auth_cache zone= ttl=]
                                                  auth-gate result cache (L2/SHM); kv NULL = off */
    /* Phase 51 (E2): per-worker L1 in front of auth_cache.kv, lazily created when
     * the auth cache is enabled.  An L1 hit returns the verdict without the SHM
     * spinlock — removes the cross-worker contention GSI-heavy load hits hardest.
     * See path/auth_gate_l1.h. */
    struct xrootd_auth_l1_s  *auth_l1;
    xrootd_rate_limit_conf_t  rate_limit;      /* [xrootd_rate_limit zone= rate= burst= key=]
                                                  per-DN request throttle; kv NULL = off */

    /* ---- Simple Shared Secret settings (used when auth = sss) ---- */
    ngx_str_t    sss_keytab;    /* [xrootd_sss_keytab /etc/xrootd/sss.keytab] */
    time_t       sss_lifetime;  /* credential lifetime in seconds; default 13 */
    ngx_array_t *sss_keys;      /* xrootd_sss_key_t[] parsed from sss_keytab */

    /* ---- Kerberos 5 settings (used when auth = krb5) ---- */
    ngx_str_t    krb5_principal; /* [xrootd_krb5_principal xrootd/host@REALM] */
    ngx_str_t    krb5_keytab;    /* [xrootd_krb5_keytab FILE:/etc/xrootd.keytab]
                                    Empty = Kerberos default keytab. */
    ngx_flag_t   krb5_ip_check;  /* [xrootd_krb5_ip_check on|off]
                                    Default off, matching upstream XrdSeckrb5. */
#if (XROOTD_HAVE_KRB5)
    krb5_context   krb5_context;
    krb5_keytab    krb5_keytab_obj;
    krb5_principal krb5_principal_obj;
#endif

    /* ---- Unix auth settings (used when auth = unix) ---- */
    ngx_flag_t   unix_trust_remote; /* [xrootd_unix_trust_remote on|off]
                                       Default off: only loopback peers may use
                                       upstream-compatible self-asserted unix
                                       credentials. */

    /* ---- Host auth settings (used when auth = host) — Phase 52 WS-C ---- */
    ngx_array_t *host_allow;        /* [xrootd_host_allow <pattern>...] ngx_str_t[]
                                       of exact hostnames or ".suffix" domain
                                       suffixes; the reverse-resolved peer host
                                       must match one.  NULL/empty = deny all. */

    /* ---- Pwd auth settings (used when auth = pwd) — Phase 52 WS-B ---- */
    ngx_str_t    pwd_file;          /* [xrootd_pwd_file <path>] password database:
                                       one "user:salthex:hashhex" line per user,
                                       hash = PBKDF2-HMAC-SHA1(pw,salt,10000,24B).
                                       Empty = pwd auth disabled (deny all). */

    /* ---- access log ---- */
    ngx_str_t   access_log;     /* [xrootd_access_log /var/log/xrootd-access.log] */
    ngx_fd_t    access_log_fd;  /* opened fd; NGX_INVALID_FILE if not configured.
                                   Captured per-worker from access_log_file->fd. */
    ngx_open_file_t *access_log_file;  /* nginx-managed handle (cycle->open_files):
                                          opened by the master, reopened on USR1, and
                                          closed cleanly across reload. NULL if off. */

    /* ---- Prometheus metrics ---- */
    ngx_int_t   metrics_slot;  /* index into the shared-memory metrics array;
                                   -1 if the server has no bound listen address yet */

    /* ---- upstream redirector ---- */
    ngx_str_t   upstream_host;  /* [xrootd_upstream host:port] — hostname/IP */
    uint16_t    upstream_port;  /* TCP port of the upstream redirector */
    ngx_addr_t *upstream_addr;  /* pre-resolved at config time; avoids per-request getaddrinfo */

    /* Upstream redirector outbound TLS (for kXR_gotoTLS mid-stream upgrade). */
    ngx_flag_t  upstream_tls;      /* [xrootd_upstream_tls on|off] — accept kXR_gotoTLS */
    ngx_str_t   upstream_tls_ca;   /* [xrootd_upstream_tls_ca /path/ca.pem] — verify upstream cert */
    ngx_str_t   upstream_tls_name; /* [xrootd_upstream_tls_name host] — SNI override */
#if (NGX_SSL)
    ngx_ssl_t  *upstream_tls_ctx;  /* SSL_CTX built at postconfiguration; NULL if tls off */
#endif

    /* Upstream redirector outbound token auth (for kXR_authmore / ztn). */
    ngx_str_t   upstream_token_file; /* [xrootd_upstream_token_file /path/token]
                                        Path to a file containing a WLCG bearer token
                                        (JWT).  Read synchronously when kXR_authmore
                                        is received; file may be refreshed externally. */

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
    ngx_flag_t  ssi_enable;         /* [xrootd_ssi on|off] — §7 XrdSsi
                                       request/response over /.ssi/<service>. */
    ngx_flag_t  ssi_cta_enable;     /* [xrootd_ssi_service cta] — gate the flagship
                                       CTA tape service (off by default). */
    ngx_uint_t  ssi_max_inflight;   /* [xrootd_ssi_max_inflight N] — concurrent
                                       requests per session (<= compile-time max). */
    size_t      ssi_request_max;    /* [xrootd_ssi_request_max SIZE] per-request cap. */
    size_t      ssi_response_max;   /* [xrootd_ssi_response_max SIZE] per-response cap. */
    ngx_str_t   ssi_cta_journal;    /* [xrootd_ssi_cta_journal PATH] restart journal. */
    ngx_uint_t  ssi_cta_executor;   /* [xrootd_ssi_cta_executor test|prod] (0=test). */
    ngx_uint_t  cns_mode;           /* [xrootd_cns off|emit|collect] — §6 Composite
                                       Cluster Name Space (data-server emit / manager
                                       inventory). XROOTD_CNS_OFF/EMIT/COLLECT. */
    ngx_msec_t  tpc_key_ttl_ms;     /* [xrootd_tpc_key_ttl 60s] — lifetime of
                                       in-flight TPC rendezvous keys in the shared
                                       registry (source-side register / consume). */
    ngx_uint_t  tpc_max_transfer_secs; /* [xrootd_tpc_max_transfer_secs 0]
                                       Phase 39 (WS4): wall-clock cap on a native
                                       root:// TPC pull, sampled per 1 MiB chunk
                                       (no per-frame syscall).  Bounds a slow-drip
                                       remote that keeps resetting the per-recv
                                       SO_RCVTIMEO idle timer.  0 = no cap. */
    ngx_flag_t  tpc_outbound_tls;   /* [xrootd_tpc_outbound_tls on|off] — phase-57
                                       §F5: advertise kXR_ableTLS on the TPC pull and
                                       perform an in-protocol TLS upgrade when the
                                       source answers kXR_gotoTLS, so TLS-requiring
                                       sources can be pulled from. Default off:
                                       behaviour identical to today (no gotoTLS). */
    ngx_flag_t  tpc_delegate;       /* [xrootd_tpc_delegate on|off] — phase-57 §F6:
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
    ngx_int_t   tpc_transfer_max_age;  /* [xrootd_tpc_transfer_max_age 0]
                                       Phase 39 (WS5): seconds with no progress
                                       after which an in-flight TPC registry slot
                                       is reclaimed (abandoned-transfer reaper),
                                       preventing permanent "registry full" 503
                                       starvation.  Applied to the shared registry
                                       via xrootd_tpc_registry_set_max_age().
                                       0 = disabled.  Recommended 3600. */
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
    ngx_uint_t  cache_origin_family; /* [xrootd_cache_origin_family auto|inet|inet6]
                                        xrootd_af_policy_t for the origin connect;
                                        default XROOTD_AF_AUTO (AF_UNSPEC). */
    /* §14 (phase-64): the legacy cache_origin credential/scheme/S3 fields are
     * DELETED with their directives — a cache source's identity is a named
     * xrootd_credential. The fields below remain as the sd_xroot SYNTHETIC-conf
     * parameter block for the in-process origin wire client. */
    ngx_str_t   cache_origin_bearer;        /* §14/C-3: in-process bearer token the
                                               root:// origin login presents via ztn
                                               (XrdSecztn). Set on sd_xroot's synthetic
                                               conf from the credential; "" = anonymous. */
    ngx_str_t   cache_origin_x509_proxy;    /* §14/C-3 GSI: X.509 proxy PEM path the
                                               root:// origin login presents via the
                                               in-process XrdSecgsi handshake; "" = no
                                               GSI. Set on sd_xroot's synthetic conf. */
    ngx_str_t   cache_origin_ca_dir;        /* §14/C-3 GSI: CA file/hashed-dir used to
                                               VERIFY the origin's server cert (MITM
                                               protection); "" = no verification. */
    ngx_str_t   cache_origin_sss_keytab;    /* §14 SSS: shared-secret keytab path the
                                               root:// origin login presents via the
                                               XrdSecsss protocol; "" = no SSS. Set on
                                               sd_xroot's synthetic conf from the
                                               credential (sss_keytab field). */
    /* ---- Pelican cache registration / advertisement (origin/pelican_register.c) ----
     * When enabled, this node periodically POSTs a signed OriginAdvertiseV2 to the
     * federation Director's /api/v1.0/director/registerCache so it is discoverable
     * as a cache. The advertise JWT (scope pelican.advertise) is ES256-signed with
     * cache_advertise_key; the cache's public key must be registered with the
     * federation registry out of band (the prerequisite handshake). */
    ngx_flag_t  cache_advertise;            /* [xrootd_cache_advertise on] */
    ngx_str_t   cache_advertise_key;        /* [..._key <ec-p256.pem>] signing key */
    ngx_str_t   cache_data_url;             /* [..._data_url https://cache:8443] public data URL (data-url) */
    ngx_str_t   cache_web_url;              /* [..._web_url https://cache:8444] (web-url) */
    ngx_str_t   cache_sitename;             /* [..._sitename MyCache] → registry-prefix /caches/<name> */
    ngx_str_t   cache_issuer_url;           /* [..._issuer <url>] advertise token iss */
    ngx_msec_t  cache_advertise_interval;   /* [..._interval 60s] re-advertise period (>=60s) */
    ngx_array_t *cache_advertise_ns;        /* ngx_str_t[] namespace prefixes advertised */
    void        *cache_advertise_key_pkey;  /* loaded EVP_PKEY* (init_process) */
    void        *cache_advertise_timer;     /* ngx_event_t* periodic timer */
    char        cache_advertise_instance[40];/* hex UUID instanceID, set at init */
    uint64_t    cache_advertise_gen;        /* monotonic generationID */
    time_t      cache_lock_timeout; /* [xrootd_cache_lock_timeout 30] — how long to
                                       wait for another worker's fill before giving up */
    ngx_uint_t  cache_eviction_threshold; /* [xrootd_cache_eviction_threshold 0.9]
                                             filesystem occupancy ratio in ppm */
    off_t       cache_max_file_size;      /* [xrootd_cache_max_file_size 1g]
                                             Files larger than this are not admitted
                                             to cache unless their basename matches
                                             cache_include_regex.  0 = no limit. */
    off_t       memory_budget;            /* [xrootd_memory_budget 768m] Phase 31 W4
                                             SHM-global cap on transfer-heap bytes;
                                             a read that would exceed it is deferred
                                             with kXR_wait.  0 = no cap. */
    size_t      readv_segment_size;       /* [xrootd_readv_segment_size 2097136]
                                             max bytes served per kXR_readv element
                                             (the official "maxReadv_ior"); a segment
                                             requesting more is capped to this and the
                                             client re-reads the tail. Default matches
                                             stock XRootD: maxBuffsz(2MiB) - 16. */
    ngx_str_t   cache_include_regex_str;  /* [xrootd_cache_include_regex "\.root$"]
                                             POSIX extended regular expression matched
                                             against the path basename; a match always
                                             admits the file regardless of size. */
    regex_t     cache_include_regex;      /* compiled POSIX ERE; valid only when
                                             cache_include_regex_set is 1 */
    ngx_flag_t  cache_include_regex_set;  /* 1 after a successful regcomp() */

    /* ---- unified cache-state engine (src/cache/cinfo.h v3) ----
     * cache_state_root: where the per-file .cinfo persistence records live; "" ⇒
     * default to cache_root. cache_dirty_max_age: a write-back staging file dirty
     * for longer than this (secs) is reaped (default 7 days; 0 = off). The
     * cache_{deny,allow}_prefixes mirror the write-through lists for read-cache
     * admission parity (consumed via the shared filter, cache_admit.h). */
    ngx_str_t    cache_state_root;        /* [xrootd_cache_state_root] */
    time_t       cache_dirty_max_age;     /* [xrootd_cache_dirty_max_age] secs; 0=off */
    ngx_event_t *cache_reap_timer;        /* per-worker stale-dirty reaper; NULL if off */
    ngx_array_t *cache_deny_prefixes;     /* xrootd_wt_prefix_entry_t[] — read admission */
    ngx_array_t *cache_allow_prefixes;    /* same; whitelist when non-empty */

    /* ---- watermark-driven LRU reaper (src/cache/reap_watermark.h) ----
     * A background per-worker timer purges the read cache oldest-first when
     * occupancy crosses cache_high_watermark, down to cache_low_watermark
     * (hysteresis). Watermarks are filesystem occupancy in ppm (0-1000000), the
     * same unit as cache_eviction_threshold (which maps to high for back-compat).
     * cache_reap_interval is the timer period in seconds. */
    ngx_uint_t   cache_high_watermark;    /* [xrootd_cache_high_watermark] ppm; start purge above */
    ngx_uint_t   cache_low_watermark;     /* [xrootd_cache_low_watermark] ppm; purge down to */
    time_t       cache_reap_interval;     /* [xrootd_cache_reap_interval] secs between ticks */
    ngx_event_t *cache_watermark_timer;   /* per-worker watermark reaper; NULL if off */

    /* ---- exclusively-VFS cache storage (src/cache/cache_storage.h) ----
     * The cache does ALL disk byte-I/O through an SD driver instance per role
     * (read cache, sidecar/state, write-back staging) — the POSIX driver bound to
     * a per-worker O_PATH rootfd by default, or a configured driver (pblock).
     * Built once at worker init (xrootd_cache_storage_init), torn down at exit.
     * The *_inst pointers are xrootd_sd_instance_t* (void* here to keep config.h
     * free of the sd.h include). _backend "" ⇒ POSIX on the role's rootfd. */
    /* §14: cache_storage_backend/_block_size deleted (tier xrootd_cache_store). */
    ngx_str_t  cache_wt_stage_root;       /* [xrootd_cache_wt_stage_root] */
    ngx_str_t  cache_wt_stage_backend;    /* [xrootd_cache_wt_stage_backend] */
    size_t     cache_wt_stage_block_size; /* [xrootd_cache_wt_stage_block_size] */
    /* Two-tier write-back-staging backpressure: when the staging filesystem
     * (cache_wt_stage_root) occupancy enters [low,high) new write-opens/PUTs are
     * delayed (kXR_wait / 503); at/above high they are rejected (kXR_Overloaded /
     * 429) until it drains below low. Reads are never throttled. ppm (0-1e6);
     * 0 = unset/off (no staging backpressure). */
    ngx_uint_t cache_wt_stage_high_watermark; /* [xrootd_wt_stage_high_watermark] ppm */
    ngx_uint_t cache_wt_stage_low_watermark;  /* [xrootd_wt_stage_low_watermark] ppm */
    int        cache_rootfd;              /* O_PATH on cache_root; -1 until init */
    int        cache_state_rootfd;        /* O_PATH on cache_state_root (or cache_root) */
    int        cache_wt_stage_rootfd;     /* O_PATH on cache_wt_stage_root; -1 if none */
    void      *cache_storage_inst;        /* read-cache xrootd_sd_instance_t* */
    void      *cache_state_inst;          /* sidecar/state instance (POSIX) */
    void      *cache_wt_stage_inst;       /* write-back staging instance; NULL if none */
    /* Policy-layer cstore adapter built over cache_storage_inst at config time
     * (eviction / reaper / free-space drive the store through this, never the
     * bare driver — phase-64 P3/G5). NULL when the read cache is off. */
    void      *cache_storage_cstore;      /* xrootd_cstore_t* */
    /* Whole-file cache SOURCE built from the legacy cache_origin config (xroot/s3),
     * so every fill runs through the one xrootd_cache_fill_from_source spine
     * (phase-64 §6.5 fold). NULL for http/pelican (libcurl) or no legacy origin. */
    void      *cache_source_inst;         /* xrootd_sd_instance_t* (bare origin) */
    /* Write-through as one mechanism (Option A): sd_stage(source=wt_origin,
     * store=export backend). A write-open routes through this so a write buffers on
     * the local store and flushes to the origin on close — replacing run_flush. NULL
     * when write-through is off or the store backend is unavailable. */
    void      *cache_wt_stage_sd_inst;    /* xrootd_sd_instance_t* (sd_stage) */
    int        cache_wt_store_rootfd;     /* O_PATH fd for a posix-export wt store; -1 */

    /* ---- checksum-on-fill integrity (src/cache/verify.h) ----
     * After a fill downloads a file into its .part staging file, recompute its
     * content checksum and compare against the digest the origin advertised
     * (kXR_Qcksum for root://, a Digest header for HTTP/Pelican). A mismatch
     * discards the part so a corrupted transfer never becomes a cache entry. */
    ngx_uint_t  cache_verify;          /* [xrootd_cache_verify off|best-effort|require]
                                          xrootd_cache_verify_mode_e; default
                                          best-effort. 0=off, 1=best-effort, 2=require. */
    ngx_str_t   cache_verify_digest;   /* [xrootd_cache_verify_digest crc32c]
                                          preferred algorithm to request from an
                                          HTTP origin (Want-Digest); empty = take
                                          whatever the origin reports. */

    /* §14: the legacy cache_slice_size field is deleted — slice/partial caching
     * is common.cache_slice_size (xrootd_cache_slice_size, tier grammar). */

    /* ---- write-through mode ----
     *
     * On a write-mode open, if wt_enable is set the decision callback evaluates
     * whether writes should be propagated back to an origin XRootD server. The
     * cached decision (wt_policy) is applied at close time: sync flush blocks
     * until complete; async flush schedules a background task and returns
     * immediately to the client.
     *
     * Mirrors XrdPfc's two-mode design: full-file prefetch vs block-based mode
     * is replaced here by sync-close-flush vs async-thread-pool-flush.
     */

    /* Write-through configuration (mirrors XrdPfcDecision pattern from
     * /tmp/xrootd-src/src/XrdPfc/XrdPfcDecision.hh). */
    ngx_flag_t               wt_enable;            /* [xrootd_write_through on|off] */
    uint8_t                  wt_mode;              /* [xrootd_wt_mode sync|async] — XROOTD_WT_MODE_* */
#define XROOTD_WT_MODE_SYNC  0
#define XROOTD_WT_MODE_ASYNC 1
#define XROOTD_WT_MODE_UNSET 255
    ngx_str_t                wt_origin_host;       /* [xrootd_wt_origin host:port] — defaults to cache_origin */
    uint16_t                 wt_origin_port;       /* parsed TCP port for write-back target */
    ngx_str_t                wt_credential;        /* [xrootd_wt_credential <name>] — §14 credential
                                                    * the write-back authenticates with (→ ztn). */
    ngx_array_t             *wt_deny_prefixes;     /* xrootd_wt_prefix_entry[] paths excluded from WT */
    ngx_array_t             *wt_allow_prefixes;    /* same, always included in WT regardless of size */

    /* Decision configuration — populated at postconfiguration. The fn pointer
     * points to the default policy engine (xrootd_wt_default_decide) unless an
     * external plugin overrides it via a future extension point. */
    xrootd_wt_decision_cfg_t wt_decision;          /* decision callback + config block */

    /* ---- request signing / security level ---- */
    ngx_uint_t  security_level;  /* [xrootd_security_level none|compatible|standard|intense|pedantic]
                                     kXR_secNone=0 .. kXR_secPedantic=4; 0 = no enforcement */

    /* ---- in-protocol TLS upgrade (kXR_ableTLS) ---- */
    ngx_flag_t  tls;      /* [xrootd_tls on|off] — advertise kXR_haveTLS */
    ngx_flag_t  tls_ktls; /* [xrootd_ktls on|off] — SSL_OP_ENABLE_KTLS so TLS reads
                           * can sendfile (Phase 29). Default off: only a win with
                           * hardware TLS-offload NICs — software kTLS is SLOWER than
                           * userspace OpenSSL on AES-NI CPUs (measured 2-5x). */
    ngx_ssl_t  *tls_ctx;  /* SSL_CTX built from certificate/key at postconfiguration */

    /* ---- root:// inline read compression (phase-42 W4) ----
     * [xrootd_read_compress on|off] — opt-in, off by default and invisible to
     * stock XRootD peers.  When on, the server advertises available codecs via
     * kXR_Qconfig "cmpread" and honours a client open opaque
     * "?xrootd.compress=<codec>" by compressing each kXR_read response with that
     * codec (pgread/readv stay plaintext — the CRC32c invariant is preserved).
     * A stock client never sends the opaque, so the uncompressed path is
     * byte-identical. */
    ngx_flag_t  read_compress;

    /* ---- root:// inline write decompression (phase-42 W5) ----
     * [xrootd_write_compress on|off] — opt-in, off by default and invisible to
     * stock peers.  When on, the server advertises codecs via kXR_Qconfig
     * "cmpwrite" and honours a client WRITE open opaque "?xrootd.compress=<codec>"
     * by decompressing each kXR_write payload (bomb-guarded) before storing it
     * plaintext on disk.  pgwrite stays plaintext.  A stock client never sends the
     * opaque, so the uncompressed write path is byte-identical. */
    ngx_flag_t  write_compress;

    /* ---- ZIP member access (phase-57 W2) ----
     * [xrootd_zip_access on|off] — opt-in, off by default.  When on, a read
     * open whose opaque carries "?xrdcl.unzip=<member>" serves that member of
     * the archive as a standalone read-only file (stored + deflate), matching
     * XrdZip.  zip_cd_max_bytes caps the central-directory read (bomb guard;
     * default 16 MiB). */
    ngx_flag_t  zip_access;
    size_t      zip_cd_max_bytes;
    /* Materialize-to-scratch for ZIP member access: zip serves a member by
     * random-access pread (+ sendfile for stored members) over the archive fd,
     * which a backend with no kernel fd cannot provide.  When staging is in
     * effect, the archive is copied into a local POSIX scratch and read there.
     * Off by default (a POSIX export reads the confined fd in place). */
    ngx_str_t   zip_stage_dir;        /* [xrootd_zip_stage_dir <path>]          */
    ngx_flag_t  zip_force_scratch;    /* [xrootd_zip_force_scratch on|off]      */
    size_t      zip_stage_max_bytes;  /* [xrootd_zip_stage_max_bytes <size>]    */

    /* ---- cluster / redirector mode ---- */
    ngx_flag_t  manager_mode;  /* [xrootd_manager_mode on|off] — query the
                                   server registry in kXR_open and kXR_locate
                                   before attempting local resolution */
    ngx_uint_t  pipeline_depth; /* [xrootd_pipeline_depth N] — per-connection
                                    in-flight response/read window (out_ring +
                                    rd_pool slots).  A deeper pipeline absorbs more
                                    wire latency/jitter (packet reordering, high-BDP
                                    links) at a per-slot memory cost.  Default
                                    XROOTD_PIPELINE_DEPTH_DEFAULT; clamped to
                                    [MIN, MAX]. */
    ngx_uint_t  registry_slots; /* [xrootd_registry_slots N] — shared-memory
                                    registry capacity; default 128 */
    ngx_uint_t  session_slots;  /* [xrootd_session_slots N] — session registry
                                    capacity; default XROOTD_SESSION_REGISTRY_SLOTS */
    ngx_uint_t  redir_cache_slots; /* [xrootd_redir_cache_slots N] — manager
                                    redirect-collapse cache capacity;
                                    default XROOTD_REDIR_CACHE_SLOTS */

    /* ---- Phase 22: active health checks (off by default) ---- */
    ngx_flag_t  hc_enabled;      /* [xrootd_health_check on|off] */
    ngx_msec_t  hc_interval_ms;  /* [xrootd_health_check_interval 30s] */
    ngx_msec_t  hc_timeout_ms;   /* [xrootd_health_check_timeout 5s] */
    ngx_uint_t  hc_threshold;    /* [xrootd_health_check_threshold 3] */
    ngx_msec_t  hc_blacklist_ms; /* [xrootd_health_check_blacklist 60s] */
    ngx_uint_t  hc_type;         /* [xrootd_health_check_type ping|stat] */

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

    /* ---- Phase 50: CMS client (node->manager) network-fault resilience ----
     * The CMS heartbeat client never armed a steady-state read/send deadline, so a
     * black-holed / half-open manager was never detected and the node never failed
     * over.  These bound that.  Unset auto-derives a generous default ON (safe with
     * real cmsd, which pings within its interval); an explicit 0 disables.  All
     * resolved at merge time from cms_interval and cached on the ctx at start. */
    ngx_msec_t            cms_read_timeout;     /* [xrootd_cms_read_timeout] manager
                                                   inactivity deadline; unset =>
                                                   max(3*cms_interval, 90s). 0 = off. */
    ngx_msec_t            cms_send_timeout;     /* [xrootd_cms_send_timeout] heartbeat
                                                   send-stall deadline; unset => 10s.
                                                   0 = off. */
    ngx_flag_t            cms_tcp_keepalive;    /* [xrootd_cms_tcp_keepalive on]
                                                   SO_KEEPALIVE + tight probes on the
                                                   manager socket. */
    ngx_msec_t            cms_tcp_user_timeout; /* [xrootd_cms_tcp_user_timeout]
                                                   TCP_USER_TIMEOUT (ms); unset =>
                                                   read-timeout backstop. 0 = off. */
    /* Fast cold-start mesh settling.  Both default by manager-locality profile when
     * left unset (see src/cms/connect.c): a loopback manager settles most
     * aggressively.  Only affect the PRE-FIRST-LOGIN window — once a node has
     * registered, reconnects use the normal exponential backoff. */
    ngx_msec_t            cms_initial_delay;    /* [xrootd_cms_initial_delay] delay
                                                   before the first connect attempt;
                                                   unset => 0 (loopback) / 10ms. */
    ngx_msec_t            cms_connect_retry;    /* [xrootd_cms_connect_retry] interval
                                                   between connect retries while the
                                                   manager is not yet listening; unset
                                                   => 10ms (loopback) / 75ms. */

    /* ---- bounded recursive query walks ---- */
    ngx_uint_t  ckscan_max_depth; /* [xrootd_ckscan_depth N] — maximum
                                      recursive directory depth for kXR_Qckscan */
    ngx_uint_t  ckscan_max_files; /* [xrootd_ckscan_max_files N] — maximum
                                      regular files emitted by one kXR_Qckscan */

    /* ---- single-port protocol handoff ---- */
    /* [xrootd_http_handoff host:port] — when a non-XRootD (HTTP/TLS) client
     * lands on this stream port, splice it to this local HTTP/WebDAV listener.
     * Lets a single registered port serve both root:// and WebDAV so a stock
     * XrdHttp redirector (which redirects HTTP to the data port) can reach an
     * nginx data node.  NULL = off (legacy: a non-XRootD client is closed). */
    ngx_addr_t *http_handoff_addr;
    ngx_str_t   http_handoff_name;

    /* [xrootd_transparent_proxy host:port] — relay every connection on this port
     * verbatim to an upstream XRootD server (auth handshake travels end-to-end)
     * while a tap decodes the cleartext frames (src/relay/relay.c). NULL = off. */
    ngx_addr_t *relay_addr;
    ngx_str_t   relay_name;

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
#define XROOTD_PROXY_AUTH_GSI        3   /* phase-4b: present the user's delegated
                                          * X.509 proxy to the upstream GSI auth */

    /* Username placed in the upstream kXR_login frame. */
    ngx_uint_t  proxy_login_user;      /* [xrootd_proxy_login_user anonymous|passthrough|fixed:<n>] */
#define XROOTD_PROXY_LOGIN_ANONYMOUS   0   /* default: "xrd" */
#define XROOTD_PROXY_LOGIN_PASSTHROUGH 1   /* copy client's authenticated username */
#define XROOTD_PROXY_LOGIN_FIXED       2   /* literal name from proxy_login_user_name */
    char        proxy_login_user_name[9];  /* NUL-terminated, max 8 chars (kXR_login limit) */

    /* One JSON line per closed/abandoned upstream file handle. */
    ngx_str_t   proxy_audit_log;       /* [xrootd_proxy_audit_log <path>|off] */
    ngx_fd_t    proxy_audit_log_fd;    /* opened fd; NGX_INVALID_FILE if off.
                                          Captured per-worker from proxy_audit_log_file->fd. */
    ngx_open_file_t *proxy_audit_log_file;  /* nginx-managed handle; see access_log_file. */

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
    ngx_msec_t  proxy_connect_timeout;      /* [xrootd_proxy_connect_timeout 10s] */
    ngx_msec_t  proxy_read_timeout;         /* [xrootd_proxy_read_timeout 60s] */
    ngx_msec_t  proxy_write_timeout;        /* [xrootd_proxy_write_timeout 0]
                                               Phase 39 (PXY-2): upstream write-stall
                                               deadline — bounds a backpressured /
                                               slow upstream that stops accepting the
                                               forwarded request.  0 = off. */

    /* Interval between kXR_ping keepalives on pooled idle connections. */
    ngx_msec_t  proxy_keepalive_interval;   /* [xrootd_proxy_keepalive_interval 15s] */

    /* ---- node topology role flags (Phase 2 capability flags) ---- */
    ngx_flag_t  metadata_only;     /* [xrootd_metadata_only on|off]
                                      Advertise kXR_attrMeta.  kXR_open is rejected
                                      (kXR_Unsupported) unless a manager_map redirects
                                      it to a data server.  Stat/dirlist/locate work
                                      normally from the local root. */
    ngx_flag_t  supervisor;        /* [xrootd_supervisor on|off]
                                      Top-tier manager in a three-level CMS hierarchy.
                                      Advertises kXR_isManager | kXR_attrSuper.
                                      Requires xrootd_manager_mode on (no local root). */
    ngx_flag_t  virtual_redirector; /* [xrootd_virtual_redirector on|off]
                                       Static path-mapping redirector (no live CMS).
                                       Advertises kXR_isManager | kXR_attrVirtRdr.
                                       Also auto-set when manager_map != NULL and
                                       cms_addr == NULL (static-only routing). */

    /* ---- Phase 3 behavioral capability flags ---- */
    ngx_flag_t  collapse_redir;     /* [xrootd_collapse_redir on|off]
                                       Cache recent (path→DS) redirect targets so
                                       repeat requests skip the CMS round-trip.
                                       Advertises kXR_collapseRedir. Default off. */
    ngx_msec_t  collapse_redir_ttl; /* [xrootd_collapse_redir_ttl <time>]
                                       Per-entry TTL for the redirect collapse cache.
                                       Default 30000 ms (30 s). */
    ngx_flag_t  recover_writes;     /* [xrootd_recover_writes on|off]
                                       RESERVED — blocked on kXR_attn write journal.
                                       Directive accepted to allow forward config
                                       preparation; kXR_recoverWrts flag is NOT
                                       advertised until the backend is implemented. */
    ngx_str_t   upload_stage_dir;   /* [xrootd_stage_dir <path>] optional fast-cache
                                       staging device; empty = stage adjacent to the
                                       destination.  Canonicalized into
                                       upload_stage_dir_canon at config time. */
    char        upload_stage_dir_canon[PATH_MAX];
    ngx_flag_t  upload_resume;      /* [xrootd_upload_resume on|off] default ON.
                                       When on, writable opens stage to a
                                       DETERMINISTIC identity-keyed partial that
                                       survives a disconnect/restart, so a
                                       reconnecting client resumes the upload from
                                       its offset; commit (rename->final) happens
                                       only on a clean kXR_close.  See
                                       src/compat/tmp_path.c xrootd_make_resume_path. */

    /* ---- OCSP certificate revocation checking (Feature 8e) ---- */
    ngx_flag_t  ocsp_enable;      /* [xrootd_ocsp_enable on|off]
                                     Query OCSP responder for each client certificate
                                     after GSI chain verification.  Default off. */
    ngx_flag_t  ocsp_soft_fail;   /* [xrootd_ocsp_soft_fail on|off]
                                     If on (default), network errors and UNKNOWN status
                                     are treated as GOOD (non-blocking).
                                     REVOKED always fails regardless. */
    ngx_flag_t  ocsp_stapling;    /* [xrootd_ocsp_stapling on|off]
                                     Fetch an OCSP staple for the server certificate
                                     at init time and serve it via the TLS status_request
                                     extension (RFC 6066).  Default off. */
    u_char     *ocsp_staple_data; /* Cached DER-encoded OCSP response for stapling;
                                     NULL if not yet fetched or stapling is disabled. */
    size_t      ocsp_staple_len;  /* Byte length of ocsp_staple_data. */

    /* ---- Phase 24: traffic mirroring (off by default) ---- */
    xrootd_mirror_conf_t  mirror;  /* [xrootd_stream_mirror_url, xrootd_mirror_*]
                                      fire-and-forget read-request replay to a
                                      shadow XRootD server; enabled == 0 = no-op */

    /* ---- Phase 25: advanced rate limiting (off by default) ---- */
    ngx_array_t  *rl_rules;        /* xrootd_rl_rule_t[] from
                                      [xrootd_rate_limit_rule / _bandwidth_limit];
                                      NULL = no limits */

    /* ---- Phase 39: network-fault resilience (all OFF by default) ----
     * Steady-state per-connection deadlines on root:// — armed/disarmed only at
     * PDU/drain boundaries (src/connection/recv.c, send.c), never per-byte and
     * never inside the Phase-29 pipelining keep-reading branches.  0 = disabled
     * (byte-for-byte current behaviour); a half-open / slowloris / silently-
     * stalled peer is otherwise never timed out on the steady-state path.
     * Exceeds official XRootD, which arms no steady-state read/write deadline. */
    ngx_msec_t  read_timeout;       /* [xrootd_read_timeout 0] per-incomplete-PDU
                                       receive deadline (also bounds a slow write/
                                       auth/prepare payload drain). 0 = off. */
    ngx_msec_t  handshake_timeout;  /* [xrootd_handshake_timeout 0] tighter pre-auth
                                       deadline so an unauthenticated stall cannot
                                       squat a connection slot. 0 = off. */
    ngx_msec_t  send_timeout;       /* [xrootd_send_timeout 0] response-drain
                                       deadline: sheds a slow/half-open consumer
                                       holding parked out_ring slots. 0 = off. */
    ngx_msec_t  tcp_user_timeout;   /* [xrootd_tcp_user_timeout 0] setsockopt
                                       TCP_USER_TIMEOUT (ms) at accept — kernel
                                       reaps a silently-dropped peer with unacked
                                       in-flight data even during a parked
                                       AIO/SENDING window.  MUST be >> send_timeout.
                                       0 = leave the kernel default. */
    ngx_flag_t  tcp_keepalive;      /* [xrootd_tcp_keepalive off] SO_KEEPALIVE +
                                       tight TCP_KEEPIDLE/INTVL/CNT at accept for
                                       seconds-scale dead-peer detection.  off =
                                       leave the kernel default (2h first probe). */
    ngx_str_t   tcp_congestion;     /* [xrootd_tcp_congestion ""] setsockopt
                                       TCP_CONGESTION at accept (e.g. "bbr") — the
                                       sender's congestion control governs download
                                       throughput, and BBR ignores the spurious
                                       loss signals packet reordering induces.
                                       Empty = leave the kernel default. */
    ngx_msec_t  manager_stale_after; /* [xrootd_manager_stale_after 0] WS7: ms with
                                       no heartbeat after which a registered data
                                       server is de-preferred in cluster selection
                                       (xrootd_srv_select falls back to it only if
                                       every replica is stale).  Applied to the
                                       shared registry via xrootd_srv_set_stale_after.
                                       0 = disabled.  Recommended ~3x cms_interval. */
    ngx_uint_t  max_connections;    /* [xrootd_max_connections 0] WS9: pre-identity
                                       admission cap checked at accept against the
                                       per-listener connections_active gauge.  Over
                                       the cap the connection is refused with a plain
                                       TCP close (no streamid exists pre-login for a
                                       framed kXR_wait).  0 = unlimited (no change).
                                       Requires the metrics zone (where the gauge
                                       lives). */

    /* ---- Phase 44: optional io_uring disk-I/O backend ----
     * All off by default.  The data path is byte-for-byte identical to the
     * thread-pool tier; only the syscall location differs.  See src/aio/uring.c
     * and docs/refactor/phase-44-io-uring-backend.md. */
    ngx_uint_t  io_uring;            /* [xrootd_io_uring auto] enum: OFF/ON/AUTO.
                                        ON makes startup fail (nginx -t error,
                                        master exits non-zero) if io_uring is not
                                        compiled in or the runtime probe fails. */
    ngx_int_t   io_uring_queue_depth;/* [xrootd_io_uring_queue_depth 256] per-worker
                                        ring SQ/CQ entries = max in-flight SQEs. */
    ngx_str_t   io_uring_panic_file; /* [xrootd_io_uring_panic_file ""] kill switch:
                                        when this file exists every worker treats
                                        io_uring as disabled and falls back on the
                                        next op (polled, no reload). "" = unset. */
    ngx_flag_t  io_uring_admin;      /* [xrootd_io_uring_admin off] expose
                                        POST /xrootd/api/v1/admin/io_uring to flip
                                        the cross-worker SHM disable flag. */
    ngx_flag_t  io_uring_restrict;   /* [xrootd_io_uring_restrict on] lock each ring
                                        to fd-only data opcodes via
                                        io_uring_register_restrictions() (>=5.10). */
} ngx_stream_xrootd_srv_conf_t;

/*
 * Per-worker init of the xrdacc authorization engine for one server: parses the
 * authdb into xcf->acc_tables and arms the hot-reload timer.  No-op unless the
 * server uses `xrootd_authdb_format xrdacc`.  Implemented in src/acc/config.c.
 */
ngx_int_t xrootd_acc_init_server(ngx_stream_xrootd_srv_conf_t *xcf,
    ngx_cycle_t *cycle);

#endif /* XROOTD_TYPES_CONFIG_H */
