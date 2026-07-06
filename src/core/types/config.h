#ifndef BRIX_TYPES_CONFIG_H
#define BRIX_TYPES_CONFIG_H

/* ---- File: config.h — Per-server configuration struct + helper type definitions ----
 *
 * WHAT: Defines ngx_stream_brix_srv_conf_t (per-server configuration block) and five helper types used within it: brix_sss_key_t (Simple Shared Secret credential key with id/expiration/opts/key_bytes/name/user/group), brix_auth_type_t (enum — user DN, VO name, hostname, or all-match for ACL rules), brix_authdb_rule_t (ACL rule with auth type + identity/path + privilege bitmask + resolved path), brix_vo_rule_t (VO access rule with path prefix + VOMS VO name + resolved path), brix_group_rule_t (group inheritance rule with path prefix + resolved path), brix_manager_map_t (CMS manager map entry with policy-style prefix + backend host/port). Main struct fields annotated with directive names in brackets showing which nginx.conf directive populates each field. Includes OpenSSL objects (X509/EVP_PKEY/X509_STORE for GSI cert/key/trust store), timer events (crl_timer/jwks_timer), array types (vo_rules/authdb_rules/group_rules/manager_map/proxy_upstreams/wt_deny_prefixes/wt_allow_prefixes), and compiled regex (cache_include_regex).
 *
 * WHY: One srv_conf per `server {}` block — nginx allocates via create_srv_conf, merges parent config into child in merge_srv_conf. This single struct encapsulates all tunables for a server instance: authentication mode (GSI/token/SSS/anonymous), TLS settings (certificate/key/trusted CA/CRL/VOMS dirs), token auth (JWKS file/issuer/audience/macaroon secrets with grace-period rotation), VO ACLs, access log, Prometheus metrics slot, upstream redirector config, TPC SSRF policy + bearer file + OAuth2 delegation endpoints, read-through cache origin + eviction + size limits + include regex, write-through mode (sync/async) origin + deny/allow prefixes + decision callback, CMS manager heartbeat, transparent proxy mode (upstream TLS/auth/login user/audit log/reconnect attempts/multiple upstreams with path rewriting), OCSP stapling. Inline bracket annotations let contributors map each field back to its nginx directive without searching directives.c.
 *
 * HOW: Struct layout — helper typedefs first (lines 16-64) → includes tunables.h/shared_conf.h → main struct typedef (line 81) with sectioned fields in order: common shared conf, auth mode, GSI/x509 settings, VO ACL arrays, loaded OpenSSL objects + crl_timer, prepare_command hook, JWT/WLCG token settings + JWKS parsed keys + refresh interval + timer, SSS keytab + keys array, access log fd, Prometheus metrics slot, upstream redirector host/port/addr/tls_ctx/token_file, TPC SSRF flags + TTL + bearer file + OAuth2 endpoints, read-through cache (cache flag/root/origin/host:port/tls/lock timeout/eviction threshold/max size/include regex), write-through enable/mode/sync-async constants/origin/wt prefixes/decision callback, security level, in-protocol TLS flag/tls_ctx, manager_mode/registry_slots, CMS heartbeat fields, ckscan depth/files limits, proxy mode (enable/host/port/upstream_tls/tls_ctx/auth/login user/name/audit log/reconnect attempts/multiple upstreams/path rewrite/connect/read timeouts/keepalive interval), OCSP enable/soft_fail/stapling + staple data. */

/*
 * Module configuration types (ngx_stream_brix_srv_conf_t and its helpers).
 *
 * One ngx_stream_brix_srv_conf_t per `server {}` block containing `xrootd on;`.
 * nginx allocates it via create_srv_conf and merges parent into child in
 * merge_srv_conf.
 *
 * Requires: tunables.h, token/token.h, metrics/metrics.h, and nginx/OpenSSL
 *           headers before inclusion.
 */

/* Phase 24 — shared mirror config block embedded below (self-contained;
 * pulls only ngx_core, so safe to include from this header). */
#include "net/mirror/mirror.h"

/* Tape/stage directive config block (brix_frm_conf_t). Pulls only ngx_core, so
 * it is safe to include from this header. (FRM-dissolution: was ../frm/frm.h.) */
#include "core/config/tape_stage_conf.h"

/* ---- Helper structs used inside ngx_stream_brix_srv_conf_t ---- */

typedef struct {
    int64_t  id;
    time_t   exp;
    int      opts;
    size_t   key_len;
    u_char   key[BRIX_SSS_KEY_MAX];
    char     name[BRIX_SSS_NAME_MAX];
    char     user[BRIX_SSS_USER_MAX];
    char     group[BRIX_SSS_GROUP_MAX];
} brix_sss_key_t;

typedef enum {
    BRIX_AUTH_USER  = 'u',
    BRIX_AUTH_GROUP = 'g',
    BRIX_AUTHDB_HOST = 'p',   /* authdb rule type; distinct from the
                                 * BRIX_AUTH_HOST auth-mode macro (tunables.h) */
    BRIX_AUTH_ALL   = 'a'
} brix_auth_type_t;

#define BRIX_AUTH_READ    0x01  /* 'r' */
#define BRIX_AUTH_LOOKUP  0x02  /* 'l' */
#define BRIX_AUTH_UPDATE  0x04  /* 'w' or 'a' */
#define BRIX_AUTH_DELETE  0x08  /* 'd' */
#define BRIX_AUTH_MKDIR   0x10  /* 'm' */
#define BRIX_AUTH_ADMIN   0x20  /* 'k' */

/* The XrdAcc engine selector + audit constants live in src/acc/privs.h (pure,
 * shared by the stream / WebDAV / S3 modules); pulled in via the include below. */
#include "auth/authz/acc/privs.h"

typedef struct {
    brix_auth_type_t type;
    ngx_str_t          id;       /* user DN, VO name, or hostname */
    ngx_str_t          path;
    uint32_t           privs;    /* bitmask */
    char               resolved[PATH_MAX];
} brix_authdb_rule_t;

typedef struct {
    ngx_str_t  path;
    ngx_str_t  vo;
    char       resolved[PATH_MAX];
} brix_vo_rule_t;

typedef struct {
    ngx_str_t  path;
    char       resolved[PATH_MAX];
} brix_group_rule_t;

typedef struct {
    ngx_str_t  prefix;   /* normalized policy-style prefix (NUL-terminated) */
    ngx_str_t  host;     /* backend host (text) */
    uint16_t   port;     /* backend port */
} brix_manager_map_t;

typedef struct {
    ngx_str_t  host;
    uint16_t   port;
    ngx_int_t  auth;                            /* BRIX_PROXY_AUTH_* or -1 = inherit global */
    char       sss_keyname[BRIX_SSS_NAME_MAX]; /* "" = use first key in conf->sss_keys       */
} brix_proxy_upstream_t;

#include "fs/cache/writethrough_decision.h"
#include "core/config/shared_conf.h"

/* Phase 20 — shared-memory KV consumers (token cache, auth cache, rate limit).
 * These headers are lightweight (ngx core only) so embedding their config
 * structs here introduces no include cycle. */
#include "core/shm/kv.h"
#include "auth/authz/auth_cache.h"
#include "core/shm/rate_limit.h"

#include "conf_structs.h"

/*
 * Per-server configuration block.
 * Directive names in square brackets show which nginx.conf directive
 * populates each field.
 */
typedef struct {
    ngx_http_brix_shared_conf_t common; /* enable, root, root_canon, allow_write,
                                             thread_pool_name, thread_pool */

    /* ---- worker-process runtime infrastructure ---- */
    int  rootfd;          /* O_PATH fd on export root; -1 until worker init */

    /* ---- authentication ---- */
    ngx_uint_t  auth;    /* [brix_auth none|gsi|token|both] — one of the
                            BRIX_AUTH_* constants in tunables.h */

    /* ---- GSI / x509 settings (used when auth = gsi or both) ---- */
    ngx_str_t   certificate;      /* [brix_certificate /etc/grid.pem] */
    ngx_str_t   certificate_key;  /* [brix_certificate_key /etc/grid.key] */
    ngx_str_t   trusted_ca;       /* [brix_trusted_ca /etc/grid-security/certificates]
                                     PEM file or directory of trusted CA certs */
    ngx_str_t   vomsdir;          /* [brix_vomsdir /etc/grid-security/vomsdir]
                                     VOMS LSC directory for attribute cert verification */
    ngx_str_t   voms_cert_dir;    /* [brix_voms_cert_dir /etc/grid-security/certificates]
                                     CA cert directory for VOMS server certificate chains */
    ngx_str_t   crl;              /* [brix_crl /etc/grid-security/certificates]
                                     PEM CRL file or directory; reloaded on crl_timer */
    time_t      crl_reload;       /* [brix_crl_reload 3600] — seconds between CRL
                                     re-scans; 0 = never reload */
    time_t      crl_mtime;        /* Phase 51 (E5): st_mtime of `crl` at last
                                     successful store rebuild; the reload timer
                                     skips the (possibly large/slow) CRL re-parse
                                     when an unchanged regular-file CRL would just
                                     reproduce the same store. 0 = not yet loaded */
    ngx_uint_t  signing_policy_mode; /* [brix_signing_policy on|off|require]
                                     BRIX_SP_MODE_*; default ON (enforce when a
                                     <hash>.signing_policy file is present) */
    ngx_uint_t  crl_mode;         /* [brix_crl_mode off|try|require]
                                     BRIX_CRL_MODE_*; default TRY */

    /* ---- VO access-control lists ---- */
    ngx_array_t  *vo_rules;     /* brix_vo_rule_t[] from brix_require_vo */
    ngx_str_t     authdb;       /* [brix_authdb /etc/xrootd/authdb] */
    ngx_array_t  *authdb_rules; /* brix_authdb_rule_t[] parsed from authdb (native) */

    /* ---- XrdAcc engine (selected by `brix_authdb_format xrdacc`) ---- */
    brix_acc_conf_t  acc;  /* [brix_authdb_format, brix_authdb_audit, ...]
                              — see brix_acc_conf_t. */
    ngx_array_t  *group_rules;  /* brix_group_rule_t[] from brix_inherit_parent_group */
    ngx_array_t  *manager_map;  /* brix_manager_map_t[] from brix_manager_map */

    /* ---- Loaded OpenSSL objects (populated at postconfiguration / init_process) ---- */
    X509        *gsi_cert;     /* server certificate parsed from 'certificate' */
    EVP_PKEY    *gsi_key;      /* server private key parsed from 'certificate_key' */
    X509_STORE  *gsi_store;    /* combined CA + CRL trust store for verification */
    u_char      *gsi_cert_pem; /* PEM form cached for kXGS_cert responses */
    size_t       gsi_cert_pem_len;
    uint32_t     gsi_ca_hash;  /* subject name hash of our CA cert (sent to clients) */

    /*
     * GSI signed-DH policy [brix_gsi_signed_dh off|auto|require] (phase-48).
     * Controls whether the server uses the modern RSA-signed-DH wire variant
     * (>=XrdSecgsiVersDHsigned/10400) instead of the universally-interoperable
     * unsigned-DH default.  Stored as BRIX_GSI_SDH_* (see context.h dispatch):
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
     * trips it); 0 = unlimited. [brix_gsi_max_inflight_handshakes] */
    ngx_int_t    gsi_max_inflight;

    /* Per-worker ephemeral-DH keypool sizing (see src/gsi/keypool.c). At worker
     * start only `gsi_keypool_seed` keys are generated synchronously (keeping the
     * event thread free at boot); the pool is then filled off-thread up to
     * `gsi_keypool_size`.  Defaults 64 / 4.  size is clamped to the compile-time
     * ceiling BRIX_GSI_KEYPOOL_CAP and seed to [1, size].
     * [brix_gsi_keypool_size N] [brix_gsi_keypool_seed N] */
    ngx_uint_t   gsi_keypool_size;
    ngx_uint_t   gsi_keypool_seed;

    /* Phase 52 (WS-A): [brix_gsi_ciphers "aes-256-cbc:aes-128-cbc:..."] the GSI
     * session-cipher preference list the server advertises (kXRS_cipher_alg).
     * Empty = the built-in default (aes-128-cbc first → unchanged behaviour).
     * The advertised list is filtered to ciphers this build can actually key, so
     * a client never selects one the server cannot decrypt. */
    ngx_str_t    gsi_ciphers;

    /* Timer that fires crl_reload-seconds after init to rebuild gsi_store */
    ngx_event_t *crl_timer;   /* heap-allocated in init_process; NULL if disabled */

    /* ---- tape staging hook ---- */
    ngx_str_t    prepare_command; /* [brix_prepare_command /path/to/stage.sh]
                                     Shell command invoked fire-and-forget when a
                                     kXR_prepare request has the kXR_stage flag set.
                                     argv: cmd  path1  path2  ...  (absolute, NUL-
                                     terminated resolved paths under brix_root).
                                     Empty = staging hint silently accepted (no-op). */

    /* ---- Phase 35: FRM durable tape-staging (off by default) ---- */
    brix_frm_conf_t  frm;       /* [brix_frm, brix_frm_queue_path, ...]
                                     durable stage-request queue + residency;
                                     frm.enable == 0 = no-op (legacy
                                     prepare_command path still fires). */

    /* ---- JWT / WLCG bearer-token settings (used when auth = token or both) ---- */
    ngx_str_t   token_jwks;      /* [brix_token_jwks /etc/xrd/jwks.json] */
    ngx_str_t   token_issuer;    /* [brix_token_issuer https://cilogon.org] */
    ngx_str_t   token_audience;  /* [brix_token_audience https://storage.example.org] */
    ngx_int_t   token_clock_skew; /* [brix_token_clock_skew 30] seconds of exp grace;
                                     NGX_CONF_UNSET = inherit/default
                                     (BRIX_TOKEN_CLOCK_SKEW_SECS); max 300 */
    ngx_str_t   token_config;    /* [brix_token_config /etc/xrd/scitokens.cfg]
                                    multi-issuer registry (phase-59 W1); when set
                                    it overrides the single-issuer fields above */
    void       *token_registry;  /* brix_token_registry_t* built at postconfig;
                                    NULL = single-issuer path.  void* keeps
                                    issuer_registry.h out of this header. */

    /* ---- Phase-59 W3a: XrdThrottle contract (off by default) ---- */
    brix_throttle_conf_t  throttle;  /* [brix_throttle_zone, brix_throttle_max_*]
                                        — see brix_throttle_conf_t. */

    /* ---- CSI block-checksum integrity on the xmeta record (ON by default) ---- */
    brix_csi_conf_t  csi;  /* [brix_csi, brix_csi_block, brix_csi_require,
                              brix_csi_trust_fs] — see brix_csi_conf_t. */

    ngx_str_t   token_macaroon_secret;     /* [brix_macaroon_secret <hex>] */
    ngx_str_t   token_macaroon_secret_old; /* [brix_macaroon_secret_old <hex>]
                                              grace-period key: tokens signed with
                                              this key are also accepted so that
                                              in-flight tokens survive nginx -s reload
                                              while the operator rotates secrets. */

    /* JWKS keys parsed at postconfiguration from token_jwks */
    brix_jwks_key_t  jwks_keys[BRIX_MAX_JWKS_KEYS];
    int                 jwks_key_count;  /* 0 if token auth is not configured */
    time_t              jwks_mtime;      /* st_mtime of token_jwks at last successful load */
    ngx_msec_t          token_jwks_refresh_interval; /* [brix_token_jwks_refresh_interval 60000ms]
                                                        Polling interval (ms) for mtime-based JWKS
                                                        hot refresh. NGX_CONF_UNSET_MSEC = disabled. */
    ngx_event_t        *jwks_timer;     /* per-worker timer event; NULL if not scheduled */

    /* ---- Phase 20: shared-memory caches & rate limiting ---- */
    brix_kv_t              *token_cache_kv;  /* [brix_token_cache zone=]
                                                  JWT validation cache (L2/SHM); NULL = off */
    /* Phase 50: always-on per-worker L1 token-validation cache (lockless),
     * lazily created on first token auth.  Collapses repeated token validation
     * (crypto + JSON parse, and the L2 spinlock) to an O(1) probe so token auth
     * does not stall the event loop under load.  See token/worker_cache.h. */
    struct brix_token_l1_s *token_l1;
    brix_auth_cache_conf_t  auth_cache;      /* [brix_auth_cache zone= ttl=]
                                                  auth-gate result cache (L2/SHM); kv NULL = off */
    /* Phase 51 (E2): per-worker L1 in front of auth_cache.kv, lazily created when
     * the auth cache is enabled.  An L1 hit returns the verdict without the SHM
     * spinlock — removes the cross-worker contention GSI-heavy load hits hardest.
     * See path/auth_gate_l1.h. */
    struct brix_auth_l1_s  *auth_l1;
    brix_rate_limit_conf_t  rate_limit;      /* [brix_rate_limit zone= rate= burst= key=]
                                                  per-DN request throttle; kv NULL = off */

    /* ---- Simple Shared Secret settings (used when auth = sss) ---- */
    ngx_str_t    sss_keytab;    /* [brix_sss_keytab /etc/xrootd/sss.keytab] */
    time_t       sss_lifetime;  /* credential lifetime in seconds; default 13 */
    ngx_array_t *sss_keys;      /* brix_sss_key_t[] parsed from sss_keytab */

    /* ---- Kerberos 5 settings (used when auth = krb5) ---- */
    brix_krb5_conf_t  krb5;  /* [brix_krb5_principal, brix_krb5_keytab,
                                brix_krb5_ip_check] + loaded libkrb5 objects. */

    /* ---- Unix auth settings (used when auth = unix) ---- */
    ngx_flag_t   unix_trust_remote; /* [brix_unix_trust_remote on|off]
                                       Default off: only loopback peers may use
                                       upstream-compatible self-asserted unix
                                       credentials. */

    /* ---- Host auth settings (used when auth = host) — Phase 52 WS-C ---- */
    ngx_array_t *host_allow;        /* [brix_host_allow <pattern>...] ngx_str_t[]
                                       of exact hostnames or ".suffix" domain
                                       suffixes; the reverse-resolved peer host
                                       must match one.  NULL/empty = deny all. */

    /* ---- Pwd auth settings (used when auth = pwd) — Phase 52 WS-B ---- */
    ngx_str_t    pwd_file;          /* [brix_pwd_file <path>] password database:
                                       one "user:salthex:hashhex" line per user,
                                       hash = PBKDF2-HMAC-SHA1(pw,salt,10000,24B).
                                       Empty = pwd auth disabled (deny all). */

    /* ---- access log ---- */
    ngx_str_t   access_log;     /* [brix_access_log /var/log/xrootd-access.log] */
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
                                               GSI. Set on sd_xroot's synthetic conf. */
    ngx_str_t   cache_origin_ca_dir;        /* §14/C-3 GSI: CA file/hashed-dir used to
                                               VERIFY the origin's server cert (MITM
                                               protection); "" = no verification. */
    ngx_str_t   cache_origin_sss_keytab;    /* §14 SSS: shared-secret keytab path the
                                               root:// origin login presents via the
                                               XrdSecsss protocol; "" = no SSS. Set on
                                               sd_xroot's synthetic conf from the
                                               credential (sss_keytab field). */
    /* ---- Pelican cache registration / advertisement (origin/pelican_register.c) ---- */
    brix_cache_advertise_conf_t  advertise;  /* [brix_cache_advertise, ..._key,
                                                ..._data_url, ..._sitename, ...]
                                                — see brix_cache_advertise_conf_t. */
    time_t      cache_lock_timeout; /* [brix_cache_lock_timeout 30] — how long to
                                       wait for another worker's fill before giving up */
    ngx_uint_t  cache_eviction_threshold; /* [brix_cache_eviction_threshold 0.9]
                                             filesystem occupancy ratio in ppm */
    off_t       cache_max_file_size;      /* [brix_cache_max_file_size 1g]
                                             Files larger than this are not admitted
                                             to cache unless their basename matches
                                             cache_include_regex.  0 = no limit. */
    off_t       memory_budget;            /* [brix_memory_budget 768m] Phase 31 W4
                                             SHM-global cap on transfer-heap bytes;
                                             a read that would exceed it is deferred
                                             with kXR_wait.  0 = no cap. */
    size_t      readv_segment_size;       /* [brix_readv_segment_size 2097136]
                                             max bytes served per kXR_readv element
                                             (the official "maxReadv_ior"); a segment
                                             requesting more is capped to this and the
                                             client re-reads the tail. Default matches
                                             stock XRootD: maxBuffsz(2MiB) - 16. */
    brix_cache_include_regex_conf_t  include_regex;  /* [brix_cache_include_regex]
                                                        — see brix_cache_include_regex_conf_t. */

    /* ---- unified cache-state engine (src/cache/cinfo.h v3) ----
     * cache_state_root: where the per-file .cinfo persistence records live; "" ⇒
     * default to cache_root. cache_dirty_max_age: a write-back staging file dirty
     * for longer than this (secs) is reaped (default 7 days; 0 = off). The
     * cache_{deny,allow}_prefixes mirror the write-through lists for read-cache
     * admission parity (consumed via the shared filter, cache_admit.h). */
    ngx_str_t    cache_state_root;        /* [brix_cache_state_root] */
    time_t       cache_dirty_max_age;     /* [brix_cache_dirty_max_age] secs; 0=off */
    ngx_event_t *cache_reap_timer;        /* per-worker stale-dirty reaper; NULL if off */
    ngx_array_t *cache_deny_prefixes;     /* brix_wt_prefix_entry_t[] — read admission */
    ngx_array_t *cache_allow_prefixes;    /* same; whitelist when non-empty */

    /* ---- watermark-driven LRU reaper (src/cache/reap_watermark.h) ----
     * A background per-worker timer purges the read cache oldest-first when
     * occupancy crosses cache_high_watermark, down to cache_low_watermark
     * (hysteresis). Watermarks are filesystem occupancy in ppm (0-1000000), the
     * same unit as cache_eviction_threshold (which maps to high for back-compat).
     * cache_reap_interval is the timer period in seconds. */
    brix_cache_reaper_conf_t  reaper;  /* [brix_cache_high_watermark, ..._low_watermark,
                                          ..._reap_interval] — see brix_cache_reaper_conf_t. */

    /* ---- exclusively-VFS cache storage (src/cache/cache_storage.h) ----
     * The cache does ALL disk byte-I/O through an SD driver instance per role
     * (read cache, sidecar/state, write-back staging) — the POSIX driver bound to
     * a per-worker O_PATH rootfd by default, or a configured driver (pblock).
     * Built once at worker init (brix_cache_storage_init), torn down at exit.
     * The *_inst pointers are brix_sd_instance_t* (void* here to keep config.h
     * free of the sd.h include). _backend "" ⇒ POSIX on the role's rootfd. */
    /* §14: cache_storage_backend/_block_size deleted (tier brix_cache_store). */
    ngx_str_t  cache_wt_stage_root;       /* [brix_cache_wt_stage_root] */
    ngx_str_t  cache_wt_stage_backend;    /* [brix_cache_wt_stage_backend] */
    size_t     cache_wt_stage_block_size; /* [brix_cache_wt_stage_block_size] */
    /* Two-tier write-back-staging backpressure: when the staging filesystem
     * (cache_wt_stage_root) occupancy enters [low,high) new write-opens/PUTs are
     * delayed (kXR_wait / 503); at/above high they are rejected (kXR_Overloaded /
     * 429) until it drains below low. Reads are never throttled. ppm (0-1e6);
     * 0 = unset/off (no staging backpressure). */
    ngx_uint_t cache_wt_stage_high_watermark; /* [brix_wt_stage_high_watermark] ppm */
    ngx_uint_t cache_wt_stage_low_watermark;  /* [brix_wt_stage_low_watermark] ppm */
    int        cache_rootfd;              /* O_PATH on cache_root; -1 until init */
    int        cache_state_rootfd;        /* O_PATH on cache_state_root (or cache_root) */
    int        cache_wt_stage_rootfd;     /* O_PATH on cache_wt_stage_root; -1 if none */
    void      *cache_storage_inst;        /* read-cache brix_sd_instance_t* */
    void      *cache_state_inst;          /* sidecar/state instance (POSIX) */
    void      *cache_wt_stage_inst;       /* write-back staging instance; NULL if none */
    /* Policy-layer cstore adapter built over cache_storage_inst at config time
     * (eviction / reaper / free-space drive the store through this, never the
     * bare driver — phase-64 P3/G5). NULL when the read cache is off. */
    void      *cache_storage_cstore;      /* brix_cstore_t* */
    /* Whole-file cache SOURCE built from the legacy cache_origin config (xroot/s3),
     * so every fill runs through the one brix_cache_fill_from_source spine
     * (phase-64 §6.5 fold). NULL for http/pelican (libcurl) or no legacy origin. */
    void      *cache_source_inst;         /* brix_sd_instance_t* (bare origin) */
    /* Write-through as one mechanism (Option A): sd_stage(source=wt_origin,
     * store=export backend). A write-open routes through this so a write buffers on
     * the local store and flushes to the origin on close — replacing run_flush. NULL
     * when write-through is off or the store backend is unavailable. */
    void      *cache_wt_stage_sd_inst;    /* brix_sd_instance_t* (sd_stage) */
    int        cache_wt_store_rootfd;     /* O_PATH fd for a posix-export wt store; -1 */

    /* ---- checksum-on-fill integrity (src/cache/verify.h) ----
     * After a fill downloads a file into its .part staging file, recompute its
     * content checksum and compare against the digest the origin advertised
     * (kXR_Qcksum for root://, a Digest header for HTTP/Pelican). A mismatch
     * discards the part so a corrupted transfer never becomes a cache entry. */
    ngx_uint_t  cache_verify;          /* [brix_cache_verify off|best-effort|require]
                                          brix_cache_verify_mode_e; default
                                          best-effort. 0=off, 1=best-effort, 2=require. */
    ngx_str_t   cache_verify_digest;   /* [brix_cache_verify_digest crc32c]
                                          preferred algorithm to request from an
                                          HTTP origin (Want-Digest); empty = take
                                          whatever the origin reports. */

    /* §14: the legacy cache_slice_size field is deleted — slice/partial caching
     * is common.cache_slice_size (brix_cache_slice_size, tier grammar). */

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

    /* ---- write-through mode ---- */
    brix_wt_conf_t  wt;  /* [brix_write_through, brix_wt_mode, brix_wt_origin,
                            brix_wt_credential, ...] — see brix_wt_conf_t. */

    /* ---- request signing / security level ---- */
    ngx_uint_t  security_level;  /* [brix_security_level none|compatible|standard|intense|pedantic]
                                     kXR_secNone=0 .. kXR_secPedantic=4; 0 = no enforcement */

    /* ---- in-protocol TLS upgrade (kXR_ableTLS) ---- */
    ngx_flag_t  tls;      /* [brix_tls on|off] — advertise kXR_haveTLS */
    ngx_flag_t  tls_ktls; /* [brix_ktls on|off] — SSL_OP_ENABLE_KTLS so TLS reads
                           * can sendfile (Phase 29). Default off: only a win with
                           * hardware TLS-offload NICs — software kTLS is SLOWER than
                           * userspace OpenSSL on AES-NI CPUs (measured 2-5x). */
    ngx_ssl_t  *tls_ctx;  /* SSL_CTX built from certificate/key at postconfiguration */

    /* ---- root:// inline read compression (phase-42 W4) ----
     * [brix_read_compress on|off] — opt-in, off by default and invisible to
     * stock XRootD peers.  When on, the server advertises available codecs via
     * kXR_Qconfig "cmpread" and honours a client open opaque
     * "?xrootd.compress=<codec>" by compressing each kXR_read response with that
     * codec (pgread/readv stay plaintext — the CRC32c invariant is preserved).
     * A stock client never sends the opaque, so the uncompressed path is
     * byte-identical. */
    ngx_flag_t  read_compress;

    /* ---- root:// inline write decompression (phase-42 W5) ----
     * [brix_write_compress on|off] — opt-in, off by default and invisible to
     * stock peers.  When on, the server advertises codecs via kXR_Qconfig
     * "cmpwrite" and honours a client WRITE open opaque "?xrootd.compress=<codec>"
     * by decompressing each kXR_write payload (bomb-guarded) before storing it
     * plaintext on disk.  pgwrite stays plaintext.  A stock client never sends the
     * opaque, so the uncompressed write path is byte-identical. */
    ngx_flag_t  write_compress;

    /* ---- ZIP member access (phase-57 W2) ----
     * [brix_zip_access on|off] — opt-in, off by default.  When on, a read
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
    ngx_str_t   zip_stage_dir;        /* [brix_zip_stage_dir <path>]          */
    ngx_flag_t  zip_force_scratch;    /* [brix_zip_force_scratch on|off]      */
    size_t      zip_stage_max_bytes;  /* [brix_zip_stage_max_bytes <size>]    */

    /* ---- cluster / redirector mode ---- */
    ngx_flag_t  manager_mode;  /* [brix_manager_mode on|off] — query the
                                   server registry in kXR_open and kXR_locate
                                   before attempting local resolution */
    ngx_uint_t  pipeline_depth; /* [brix_pipeline_depth N] — per-connection
                                    in-flight response/read window (out_ring +
                                    rd_pool slots).  A deeper pipeline absorbs more
                                    wire latency/jitter (packet reordering, high-BDP
                                    links) at a per-slot memory cost.  Default
                                    BRIX_PIPELINE_DEPTH_DEFAULT; clamped to
                                    [MIN, MAX]. */
    ngx_uint_t  registry_slots; /* [brix_registry_slots N] — shared-memory
                                    registry capacity; default 128 */
    ngx_uint_t  session_slots;  /* [brix_session_slots N] — session registry
                                    capacity; default BRIX_SESSION_REGISTRY_SLOTS */
    ngx_uint_t  redir_cache_slots; /* [brix_redir_cache_slots N] — manager
                                    redirect-collapse cache capacity;
                                    default BRIX_REDIR_CACHE_SLOTS */

    /* ---- Phase 22: active health checks (off by default) ---- */
    brix_hc_conf_t  hc;  /* [brix_health_check, brix_health_check_*] — see brix_hc_conf_t. */

    /* ---- CMS manager heartbeat + client network-fault resilience ---- */
    brix_cms_conf_t  cms;  /* [brix_cms_manager, brix_cms_paths, brix_cms_interval,
                              brix_cms_*_timeout, ...] — see brix_cms_conf_t. */
    ngx_int_t        listen_port;  /* [brix_listen_port 1094] — port advertised to CMS manager */

    /* ---- bounded recursive query walks ---- */
    ngx_uint_t  ckscan_max_depth; /* [brix_ckscan_depth N] — maximum
                                      recursive directory depth for kXR_Qckscan */
    ngx_uint_t  ckscan_max_files; /* [brix_ckscan_max_files N] — maximum
                                      regular files emitted by one kXR_Qckscan */

    /* ---- single-port protocol handoff ---- */
    /* [brix_http_handoff host:port] — when a non-XRootD (HTTP/TLS) client
     * lands on this stream port, splice it to this local HTTP/WebDAV listener.
     * Lets a single registered port serve both root:// and WebDAV so a stock
     * XrdHttp redirector (which redirects HTTP to the data port) can reach an
     * nginx data node.  NULL = off (legacy: a non-XRootD client is closed). */
    ngx_addr_t *http_handoff_addr;
    ngx_str_t   http_handoff_name;

    /* [brix_transparent_proxy host:port] — relay every connection on this port
     * verbatim to an upstream XRootD server (auth handshake travels end-to-end)
     * while a tap decodes the cleartext frames (src/relay/relay.c). NULL = off. */
    ngx_addr_t *relay_addr;
    ngx_str_t   relay_name;

    /* [brix_guard_stream on|off] — bad-actor guard on the transparent relay:
     * classify each tapped frame (src/net/guard/), drop the connection on junk
     * signatures / grammar violations, audit notfound/authfail responses. */
    ngx_flag_t  relay_guard_enable;

    /* ---- transparent proxy mode ---- */
    brix_proxy_conf_t  proxy;  /* [brix_proxy, brix_proxy_upstream, brix_proxy_auth,
                                  brix_proxy_login_user, brix_proxy_*_timeout, ...]
                                  — see brix_proxy_conf_t. */

    /* ---- node topology + behavioral capability flags (Phase 2/3) ---- */
    brix_node_caps_conf_t  caps;  /* [brix_metadata_only, brix_supervisor,
                                     brix_virtual_redirector, brix_collapse_redir,
                                     brix_collapse_redir_ttl, brix_recover_writes]
                                     — see brix_node_caps_conf_t. */
    ngx_str_t   upload_stage_dir;   /* [brix_stage_dir <path>] optional fast-cache
                                       staging device; empty = stage adjacent to the
                                       destination.  Canonicalized into
                                       upload_stage_dir_canon at config time. */
    char        upload_stage_dir_canon[PATH_MAX];
    ngx_flag_t  upload_resume;      /* [brix_upload_resume on|off] default ON.
                                       When on, writable opens stage to a
                                       DETERMINISTIC identity-keyed partial that
                                       survives a disconnect/restart, so a
                                       reconnecting client resumes the upload from
                                       its offset; commit (rename->final) happens
                                       only on a clean kXR_close.  See
                                       src/compat/tmp_path.c brix_make_resume_path. */

    /* ---- OCSP certificate revocation checking (Feature 8e) ---- */
    brix_ocsp_conf_t  ocsp;  /* [brix_ocsp_enable, brix_ocsp_soft_fail,
                                brix_ocsp_stapling] revocation + stapling state;
                                staple_data/len populated at init_process. */

    /* ---- Phase 24: traffic mirroring (off by default) ---- */
    brix_mirror_conf_t  mirror;  /* [brix_stream_mirror_url, brix_mirror_*]
                                      fire-and-forget read-request replay to a
                                      shadow XRootD server; enabled == 0 = no-op */

    /* ---- Phase 25: advanced rate limiting (off by default) ---- */
    ngx_array_t  *rl_rules;        /* brix_rl_rule_t[] from
                                      [brix_rate_limit_rule / _bandwidth_limit];
                                      NULL = no limits */

    /* ---- Phase 39: network-fault resilience (all OFF by default) ----
     * Steady-state per-connection deadlines on root:// — armed/disarmed only at
     * PDU/drain boundaries (src/connection/recv.c, send.c), never per-byte and
     * never inside the Phase-29 pipelining keep-reading branches.  0 = disabled
     * (byte-for-byte current behaviour); a half-open / slowloris / silently-
     * stalled peer is otherwise never timed out on the steady-state path.
     * Exceeds official XRootD, which arms no steady-state read/write deadline. */
    ngx_msec_t  read_timeout;       /* [brix_read_timeout 0] per-incomplete-PDU
                                       receive deadline (also bounds a slow write/
                                       auth/prepare payload drain). 0 = off. */
    ngx_msec_t  handshake_timeout;  /* [brix_handshake_timeout 0] tighter pre-auth
                                       deadline so an unauthenticated stall cannot
                                       squat a connection slot. 0 = off. */
    ngx_msec_t  send_timeout;       /* [brix_send_timeout 0] response-drain
                                       deadline: sheds a slow/half-open consumer
                                       holding parked out_ring slots. 0 = off. */
    ngx_msec_t  tcp_user_timeout;   /* [brix_tcp_user_timeout 0] setsockopt
                                       TCP_USER_TIMEOUT (ms) at accept — kernel
                                       reaps a silently-dropped peer with unacked
                                       in-flight data even during a parked
                                       AIO/SENDING window.  MUST be >> send_timeout.
                                       0 = leave the kernel default. */
    ngx_flag_t  tcp_keepalive;      /* [brix_tcp_keepalive off] SO_KEEPALIVE +
                                       tight TCP_KEEPIDLE/INTVL/CNT at accept for
                                       seconds-scale dead-peer detection.  off =
                                       leave the kernel default (2h first probe). */
    ngx_str_t   tcp_congestion;     /* [brix_tcp_congestion ""] setsockopt
                                       TCP_CONGESTION at accept (e.g. "bbr") — the
                                       sender's congestion control governs download
                                       throughput, and BBR ignores the spurious
                                       loss signals packet reordering induces.
                                       Empty = leave the kernel default. */
    ngx_msec_t  manager_stale_after; /* [brix_manager_stale_after 0] WS7: ms with
                                       no heartbeat after which a registered data
                                       server is de-preferred in cluster selection
                                       (brix_srv_select falls back to it only if
                                       every replica is stale).  Applied to the
                                       shared registry via brix_srv_set_stale_after.
                                       0 = disabled.  Recommended ~3x cms_interval. */
    ngx_uint_t  max_connections;    /* [brix_max_connections 0] WS9: pre-identity
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
    ngx_uint_t  io_uring;            /* [brix_io_uring auto] enum: OFF/ON/AUTO.
                                        ON makes startup fail (nginx -t error,
                                        master exits non-zero) if io_uring is not
                                        compiled in or the runtime probe fails. */
    ngx_int_t   io_uring_queue_depth;/* [brix_io_uring_queue_depth 256] per-worker
                                        ring SQ/CQ entries = max in-flight SQEs. */
    ngx_str_t   io_uring_panic_file; /* [brix_io_uring_panic_file ""] kill switch:
                                        when this file exists every worker treats
                                        io_uring as disabled and falls back on the
                                        next op (polled, no reload). "" = unset. */
    ngx_flag_t  io_uring_admin;      /* [brix_io_uring_admin off] expose
                                        POST /xrootd/api/v1/admin/io_uring to flip
                                        the cross-worker SHM disable flag. */
    ngx_flag_t  io_uring_restrict;   /* [brix_io_uring_restrict on] lock each ring
                                        to fd-only data opcodes via
                                        io_uring_register_restrictions() (>=5.10). */
} ngx_stream_brix_srv_conf_t;

/*
 * Per-worker init of the xrdacc authorization engine for one server: parses the
 * authdb into xcf->acc.tables and arms the hot-reload timer.  No-op unless the
 * server uses `brix_authdb_format xrdacc`.  Implemented in src/acc/config.c.
 */
ngx_int_t brix_acc_init_server(ngx_stream_brix_srv_conf_t *xcf,
    ngx_cycle_t *cycle);

#endif /* BRIX_TYPES_CONFIG_H */
