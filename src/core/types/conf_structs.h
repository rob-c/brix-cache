/*
 * core/types/conf_structs.h
 *
 * Per-server config sub-struct helper types, grouped out of the main
 * ngx_stream_brix_srv_conf_t definition so config.h reads as a set of named
 * concept groups rather than a flat wall of fields.  Every field is reached as
 * conf-><group>.<field> (e.g. conf->proxy.audit_log, conf->acc.tables).
 *
 * NOT self-contained: included by config.h at the point AFTER its prerequisite
 * includes (writethrough_decision.h, shared_conf.h, kv.h, auth_cache.h,
 * rate_limit.h) and after the translation unit has pulled in ngx core, OpenSSL
 * (NGX_SSL), krb5 (BRIX_HAVE_KRB5), and <regex.h>, exactly where these typedefs
 * previously lived inline.  Do not include it directly — include config.h.
 */

#ifndef BRIX_TYPES_CONF_STRUCTS_H
#define BRIX_TYPES_CONF_STRUCTS_H

/* OCSP certificate revocation checking (Feature 8e) — see auth/crypto/ocsp.c.
 * Grouped as one sub-struct so the per-server config block stays navigable and
 * every OCSP field is reached as conf->ocsp.<field>. */
typedef struct {
    ngx_flag_t  enable;      /* [brix_ocsp on|off]
                                Query OCSP responder for each client certificate
                                after GSI chain verification.  Default off. */
    ngx_flag_t  soft_fail;   /* [brix_ocsp_soft_fail on|off]
                                If on (default), network errors and UNKNOWN status
                                are treated as GOOD (non-blocking).
                                REVOKED always fails regardless. */
    ngx_flag_t  require_nonce;/* [brix_ocsp_require_nonce on|off]
                                If on, an OCSP response that omits the nonce our
                                request carried is a hard failure (replay guard,
                                A-6 item 2).  Default off — most CA responders
                                serve pre-signed, nonce-less responses. */
    ngx_flag_t  stapling;    /* [brix_ocsp_stapling on|off]
                                Fetch an OCSP staple for the server certificate
                                at init time and serve it via the TLS status_request
                                extension (RFC 6066).  Default off. */
    u_char     *staple_data; /* Cached DER-encoded OCSP response for stapling;
                                NULL if not yet fetched or stapling is disabled. */
    size_t      staple_len;  /* Byte length of staple_data. */
} brix_ocsp_conf_t;

/* Kerberos 5 settings + loaded libkrb5 objects (used when auth = krb5).  Grouped
 * as one sub-struct so the per-server config block stays navigable; every field
 * is reached as conf->krb5.<field>.  The libkrb5 object handles are only present
 * when built with Kerberos support. */
typedef struct {
    ngx_str_t    principal; /* [brix_krb5_principal xrootd/host@REALM] */
    ngx_str_t    keytab;    /* [brix_krb5_keytab FILE:/etc/xrootd.keytab]
                               Empty = Kerberos default keytab. */
    ngx_flag_t   ip_check;  /* [brix_krb5_ip_check on|off]
                               Default off, matching upstream XrdSeckrb5. */
    ngx_flag_t   delegate;  /* [brix_krb5_delegate on|off]
                               When on, a verified krb5 login is answered with a
                               kXR_authmore "fwdtgt" continuation that requests the
                               client forward its TGT (phase-70 §5.7 inbound
                               two-round capture).  Default off — delegation is
                               opt-in and demands a forwardable-TGT-capable client. */
#if (BRIX_HAVE_KRB5)
    krb5_context   context;
    krb5_keytab    keytab_obj;
    krb5_principal principal_obj;
#endif
} brix_krb5_conf_t;

/* Write-through configuration (mirrors the XrdPfcDecision pattern).  Grouped as
 * one sub-struct so the per-server config block stays navigable; every field is
 * reached as conf->wt.<field>. */
#define BRIX_WT_MODE_SYNC  0
#define BRIX_WT_MODE_ASYNC 1
#define BRIX_WT_MODE_UNSET 255
typedef struct {
    ngx_flag_t               enable;         /* [brix_write_through on|off] */
    uint8_t                  mode;           /* [brix_wt_mode sync|async] — BRIX_WT_MODE_* */
    ngx_str_t                origin_host;    /* [brix_wt_origin host:port] — defaults to cache_origin */
    uint16_t                 origin_port;    /* parsed TCP port for write-back target */
    ngx_str_t                credential;     /* [brix_wt_credential <name>] — §14 credential
                                              * the write-back authenticates with (→ ztn). */
    ngx_array_t             *deny_prefixes;  /* brix_wt_prefix_entry[] paths excluded from WT */
    ngx_array_t             *allow_prefixes; /* same, always included in WT regardless of size */
    brix_wt_decision_cfg_t   decision;       /* decision callback + config block (postconfig) */
} brix_wt_conf_t;

/* Explicit CMS cluster role for the upward (node->manager) leg, Phase-61 W7:
 * Pander-parity login Mode bits + the inbound valid-ops table for frames from
 * the parent.  AUTO keeps the legacy derivation (server, or server|manager
 * when manager_mode) with the permissive dispatch table. */
#define BRIX_CMS_ROLE_AUTO        0
#define BRIX_CMS_ROLE_SERVER      1   /* kYR_server (0x8) */
#define BRIX_CMS_ROLE_MANAGER     2   /* kYR_manager (0x2), manVOps inbound */
#define BRIX_CMS_ROLE_SUPERVISOR  3   /* kYR_manager|kYR_server (0xA), supVOps */
#define BRIX_CMS_ROLE_PEER        4   /* §2.17: kYR_peer — overflow cluster
                                         consulted only on a local miss */
#define BRIX_CMS_ROLE_PROXY       5   /* §2.17: kYR_proxy|kYR_server — proxy
                                         data server (selectable normally) */

/* One configured CMS manager endpoint (an entry of brix_cms_conf_t.managers).
 * The raw string is NUL-terminated (brix_copy_conf_string) so log/action sites
 * can borrow it as a C string. */
typedef struct {
    ngx_str_t    raw;    /* directive text, e.g. "127.0.0.1:1213" */
    ngx_addr_t  *addr;   /* resolved address (first A record) */
} brix_cms_manager_ent_t;

/* Redundant-manager cap — stock cmsd client parity (XrdCmsFinder.hh MaxMan). */
#define NGX_BRIX_CMS_MAX_MANAGERS  15

/* CMS manager heartbeat + client-side network-fault resilience.  Grouped as one
 * sub-struct so the per-server config block stays navigable; every field is
 * reached as conf->cms.<field>.  (The advertised listen_port stays a top-level
 * field — it is not CMS-specific.) */
typedef struct {
    ngx_msec_t          locate_timeout;   /* [brix_cms_locate_timeout 5s] */
    ngx_str_t           manager;          /* first manager's raw host:port (role/gate logs) */
    ngx_addr_t         *addr;             /* first manager's resolved address — the
                                             "has upstream" gate everywhere */
    ngx_array_t        *managers;         /* brix_cms_manager_ent_t[] — ALL managers from
                                             [brix_cms_manager h:p ...] (repeatable);
                                             NULL when the directive is absent */
    ngx_str_t           paths;            /* [brix_cms_paths /data] — exported path list */
    time_t              interval;         /* [brix_cms_interval 60] — heartbeat period */
    ngx_brix_cms_ctx_t **ctxs;            /* runtime: one heartbeat ctx per manager (heap;
                                             worker 0 only — NULL elsewhere) */
    ngx_uint_t          nctxs;            /* runtime: live ctx count; the "CMS client
                                             started on this worker" gate */
    ngx_uint_t          rr;               /* runtime: round-robin cursor for locate
                                             rotation across logged-in managers */
    ngx_uint_t          suspended;        /* set by kYR_status suspend; cleared by resume */
    ngx_msec_t          read_timeout;     /* [brix_cms_read_timeout] manager inactivity
                                             deadline; unset => max(3*interval, 90s). 0=off */
    ngx_msec_t          send_timeout;     /* [brix_cms_send_timeout] heartbeat send-stall
                                             deadline; unset => 10s. 0=off */
    ngx_flag_t          tcp_keepalive;    /* [brix_cms_tcp_keepalive on] SO_KEEPALIVE +
                                             tight probes on the manager socket */
    ngx_msec_t          tcp_user_timeout; /* [brix_cms_tcp_user_timeout] TCP_USER_TIMEOUT
                                             (ms); unset => read-timeout backstop. 0=off */
    ngx_msec_t          initial_delay;    /* [brix_cms_initial_delay] delay before the
                                             first connect; unset => 0 (loopback) / 10ms */
    ngx_msec_t          connect_retry;    /* [brix_cms_connect_retry] retry interval while
                                             the manager is not yet listening */
    ngx_str_t           vnid;             /* [brix_cms_vnid <id>] Phase-89 W9: virtual
                                             network id advertised in LOGIN envCGI
                                             ("vnid=<id>"); empty => envCGI stays empty */
    ngx_int_t           load_weight;      /* [brix_cms_load_weight 0-100] Phase-89 W4:
                                             manager-side selection weight for the
                                             heartbeat machine load; 0 = space/util
                                             only (byte-identical legacy scoring) */
    ngx_flag_t          affinity;         /* [brix_cms_affinity on] Phase-89 W5: pin
                                             repeated selections of a path to ONE
                                             eligible (fresh, non-blacklisted)
                                             server; drained hosts never sticky */
    ngx_flag_t          locate_multi;     /* [brix_cms_locate_multi on] Phase-89 W5:
                                             answer kXR_locate with the FULL live
                                             server set (kXR_ok, lateral redirect)
                                             instead of a single kXR_redirect */
    ngx_flag_t          fanout;           /* [brix_cms_fanout on] Phase-89 W8:
                                             fan a client kXR_rm/kXR_rmdir out to
                                             EVERY holder node (this worker's CMS
                                             conns) instead of redirecting to one */
    ngx_msec_t          fanout_window;    /* [brix_cms_fanout_window] W8 reply
                                             window: no kYR_error from any node
                                             within it => kXR_ok; unset => 500ms */
    ngx_uint_t          role;             /* [brix_cms_role auto|server|manager|
                                             supervisor] Phase-61 W7: BRIX_CMS_ROLE_*
                                             — explicit Pander login Mode + inbound
                                             valid-ops parity; auto = legacy */
    ngx_flag_t          state_relay;      /* [brix_cms_state_relay on] Phase-61 W7:
                                             on a registry miss, relay a parent
                                             manager's kYR_state down to this
                                             tier's own nodes and echo the first
                                             kYR_have up (multi-tier recursion);
                                             off = registry-only legacy */
    ngx_int_t           delay_servers;    /* [brix_cms_delay_servers <n>] §2.2:
                                             SUPCount floor — hold selects until
                                             >= n data servers registered; 0=off */
    ngx_int_t           delay_hold;       /* [brix_cms_delay_hold <secs>] §2.2:
                                             kXR_wait seconds while below the
                                             floor; default 5 */
    ngx_int_t           sched_cpu;        /* [brix_cms_sched cpu N io N runq N
                                             mem N pag N space N fuzz N
                                             maxload N] §2.3 component weights;
                                             all UNSET/0 = legacy scoring */
    ngx_int_t           sched_io;
    ngx_int_t           sched_runq;
    ngx_int_t           sched_mem;
    ngx_int_t           sched_pag;
    ngx_int_t           sched_space;
    ngx_int_t           sched_fuzz;
    ngx_int_t           sched_maxload;
    ngx_flag_t          stage_select;     /* [brix_cms_stage_select on] §2.5:
                                             reads of a file no node holds go to
                                             the roomiest stage-capable node */
    ngx_msec_t          fxhold;           /* [brix_cms_fxhold <time>] §2.6: loc
                                             cache positive TTL (unset = 30s
                                             legacy; stock default is 8h) */
    ngx_msec_t          emptylife;        /* [brix_cms_emptylife <time>] §2.6:
                                             negative location-cache TTL; 0=off */
    ngx_flag_t          dfs;              /* [brix_cms_dfs on] §2.8: shared-FS
                                             cluster — skip the per-file state
                                             fan-out; select purely by load */
    ngx_str_t           perf_pgm;         /* [brix_cms_perf_pgm <cmd>] §2.11:
                                             external load-feed program; its
                                             stdout lines "cpu net xeq mem pag"
                                             override the /proc meter */
    ngx_msec_t          perf_int;         /* [brix_cms_perf_interval <time>]
                                             §2.11: freshness window (a line
                                             older than 2x this falls back to
                                             /proc); default 30s */
    ngx_str_t           altds;            /* [brix_cms_altds <port> [monitor]]
                                             §2.12: advertise a co-located
                                             foreign data server's port as this
                                             node's data port */
    ngx_int_t           altds_port;       /* parsed from the directive; 0=off */
    ngx_flag_t          altds_monitor;    /* liveness-probe the altds and drive
                                             kYR_status suspend/resume */
    ngx_msec_t          altds_interval;   /* probe cadence; default 10s */
    ngx_int_t           min_free_mb;      /* [brix_cms_min_free <MB>] §2.4: the
                                             mSpace policy floor advertised in the
                                             kYR_login payload — the free space
                                             (MB) below which the manager should
                                             stop selecting this node for writes.
                                             Default 100 (byte-identical to the
                                             prior hardcoded constant). */
} brix_cms_conf_t;

/* Active upstream health-check settings (Phase 22, off by default).  Grouped as
 * one sub-struct so the per-server config block stays navigable; every field is
 * reached as conf->hc.<field>. */
typedef struct {
    ngx_flag_t  enabled;      /* [brix_health_check on|off] */
    ngx_msec_t  interval_ms;  /* [brix_health_check_interval 30s] */
    ngx_msec_t  timeout_ms;   /* [brix_health_check_timeout 5s] */
    ngx_uint_t  threshold;    /* [brix_health_check_threshold 3] */
    ngx_msec_t  blacklist_ms; /* [brix_health_check_blacklist 60s] */
    ngx_uint_t  type;         /* [brix_health_check_type ping|stat] — BRIX_HC_TYPE_* */
} brix_hc_conf_t;

/* Node topology role flags (Phase 2) + behavioral capability flags (Phase 3).
 * Grouped as one sub-struct so the per-server config block stays navigable;
 * every field is reached as conf->caps.<field>. */
typedef struct {
    ngx_flag_t  metadata_only;      /* [brix_metadata_only on|off] advertise kXR_attrMeta;
                                       kXR_open rejected unless manager_map redirects. */
    ngx_flag_t  supervisor;         /* [brix_supervisor on|off] top-tier CMS manager
                                       (kXR_isManager|kXR_attrSuper); needs manager_mode. */
    ngx_flag_t  virtual_redirector; /* [brix_virtual_redirector on|off] static path-mapping
                                       redirector (kXR_isManager|kXR_attrVirtRdr). Also auto
                                       when manager_map != NULL and cms.addr == NULL. */
    ngx_flag_t  collapse_redir;     /* [brix_collapse_redir on|off] cache (path→DS) redirect
                                       targets (kXR_collapseRedir). Default off. */
    ngx_msec_t  collapse_redir_ttl; /* [brix_collapse_redir_ttl <time>] per-entry TTL for the
                                       redirect collapse cache. Default 30000 ms. */
    ngx_flag_t  recover_writes;     /* [brix_recover_writes on|off] RESERVED — accepted for
                                       forward config; kXR_recoverWrts not yet advertised. */
    ngx_msec_t  cms_locate_window;  /* [brix_cms_locate_window <time>] Phase-89 W3: on a
                                       loc-cache miss, kYR_state fan-out to registered nodes
                                       and park the client this long for the first kYR_have.
                                       0 (default) = off — prefix selection only. */
    ngx_uint_t  cms_state_fanout;   /* [brix_cms_state_fanout <n>] W3: max nodes probed per
                                       locate miss. Default 8. */
} brix_node_caps_conf_t;

/* Transparent proxy mode: terminate root:// and forward opcodes to an upstream.
 * Grouped as one sub-struct so the per-server config block stays navigable;
 * every field is reached as conf->proxy.<field>. */
#define BRIX_PROXY_AUTH_ANONYMOUS  0
#define BRIX_PROXY_AUTH_FORWARD    1
#define BRIX_PROXY_AUTH_SSS        2
#define BRIX_PROXY_AUTH_GSI        3   /* phase-4b: present the user's delegated
                                          * X.509 proxy to the upstream GSI auth */
#define BRIX_PROXY_LOGIN_ANONYMOUS   0   /* default: "xrd" */
#define BRIX_PROXY_LOGIN_PASSTHROUGH 1   /* copy client's authenticated username */
#define BRIX_PROXY_LOGIN_FIXED       2   /* literal name from proxy.login_user_name */
typedef struct {
    ngx_flag_t   enable;             /* [brix_proxy on|off] */
    ngx_str_t    host;               /* [brix_proxy_upstream host] */
    ngx_int_t    port;               /* [brix_proxy_upstream host:port] */
    ngx_flag_t   upstream_tls;       /* [brix_proxy_upstream_tls on|off] */
#if (NGX_SSL)
    ngx_ssl_t   *tls_ctx;            /* SSL_CTX built at postconfiguration */
#endif
    ngx_uint_t   auth;               /* [brix_proxy_auth ...] — BRIX_PROXY_AUTH_* */
    ngx_uint_t   login_user;         /* [brix_proxy_login_user ...] — BRIX_PROXY_LOGIN_* */
    char         login_user_name[9]; /* NUL-terminated, max 8 chars (kXR_login limit) */
    ngx_str_t    audit_log;          /* [brix_proxy_audit_log <path>|off] */
    ngx_fd_t     audit_log_fd;       /* opened fd; NGX_INVALID_FILE if off */
    ngx_open_file_t *audit_log_file; /* nginx-managed handle */
    ngx_str_t    upstream_tls_ca;    /* [brix_tap_proxy_upstream_tls_ca /etc/pki/ca.pem] */
    ngx_str_t    upstream_tls_name;  /* [brix_tap_proxy_upstream_tls_name host] — SNI override */
    ngx_flag_t   upstream_ssl_verify;/* [brix_tap_proxy_upstream_tls_verify on|off] A-1: default on,
                                      * nginx -t refuses upstream_tls without a CA unless off */
    ngx_uint_t   reconnect_attempts; /* [brix_proxy_reconnect_attempts N] */
    ngx_array_t *upstreams;          /* brix_proxy_upstream_t[]; may be NULL */
    ngx_str_t    path_strip;         /* [brix_proxy_path_rewrite strip add] */
    ngx_str_t    path_add;
    ngx_msec_t   connect_timeout;    /* [brix_proxy_connect_timeout 10s] */
    ngx_msec_t   read_timeout;       /* [brix_proxy_read_timeout 60s] */
    ngx_msec_t   write_timeout;      /* [brix_proxy_write_timeout 0] upstream write-stall */
    ngx_msec_t   keepalive_interval; /* [brix_proxy_keepalive_interval 15s] */
} brix_proxy_conf_t;

/* XrdThrottle contract (Phase-59 W3a, off by default): bound per-user open-file
 * and active-connection counts against a shared rate-limit zone.  Grouped as one
 * sub-struct so the per-server config block stays navigable; every field is
 * reached as conf->throttle.<field>. */
typedef struct {
    ngx_str_t   zone_name;       /* [brix_throttle_zone <rate-limit zone>] */
    void       *zone;            /* brix_rl_zone_t* resolved at postconfig */
    ngx_uint_t  max_open_files;  /* [brix_throttle_max_open_files] */
    /* phase-92: XrdBwm-style bandwidth reservation (default off). A read open
     * reserves its file size against the named per-worker byte budget; over-budget
     * opens are refused with kXR_Overloaded. Engine: net/ratelimit/reservation.c. */
    ngx_str_t   bwm_zone_name;   /* [brix_throttle_bandwidth_zone <name>] "" = off */
    size_t      bwm_budget;      /* [brix_throttle_bandwidth_budget <size>] 0 = off */
} brix_throttle_conf_t;

/* CSI block-checksum integrity on the xmeta record (ON by default).  Grouped as
 * one sub-struct so the per-server config block stays navigable; every field is
 * reached as conf->csi.<field>. */
typedef struct {
    ngx_flag_t  enable;    /* [brix_csi on|off] default ON */
    size_t      block;     /* [brix_csi_block 1m] granule for NEW records */
    ngx_flag_t  require;   /* [brix_csi_require on|off] no record = err */
    ngx_flag_t  trust_fs;  /* [brix_csi_trust_fs on|off] fs self-checksums: skip read-verify */
    time_t      scrub_interval; /* [brix_csi_scrub_interval] secs between at-rest
                                 * sweeps of the export root; 0 = off (default) */
} brix_csi_conf_t;

/* XrdAcc authorization engine (selected by `brix_authdb_format xrdacc`).  Grouped
 * as one sub-struct so the per-server config block stays navigable; every field
 * is reached as conf->acc.<field>. */
typedef struct {
    ngx_uint_t    format;        /* 0=native (default), 1=xrdacc */
    ngx_uint_t    audit;         /* 0=none 1=deny 2=grant 3=all */
    ngx_int_t     refresh;       /* authdb hot-reload interval, s; 0=off */
    ngx_int_t     gidlifetime;   /* Unix group cache TTL, s */
    ngx_flag_t    pgo;           /* resolve primary Unix group only */
    ngx_str_t     nisdomain;     /* NIS domain for netgroup lookups */
    ngx_flag_t    resolve_hosts; /* reverse-DNS peer for 'h' host rules */
    ngx_str_t     spacechar;     /* legacy: char substituted for spaces in ids */
    ngx_flag_t    encoding;      /* legacy: URI-decode authdb path tokens */
    ngx_str_t     gidretran;     /* legacy: gids to skip in group resolution */
    struct brix_acc_tables_s *tables; /* per-worker tables (init_process) */
    ngx_event_t  *timer;         /* per-worker authdb refresh timer */
} brix_acc_conf_t;

/* Pelican cache registration / advertisement (origin/pelican_register.c): a node
 * periodically POSTs a signed OriginAdvertiseV2 to the federation Director so it
 * is discoverable as a cache.  Grouped as one sub-struct so the per-server config
 * block stays navigable; every field is reached as conf->advertise.<field>. */
typedef struct {
    ngx_flag_t   enable;       /* [brix_cache_advertise on] */
    ngx_str_t    key;          /* [..._key <ec-p256.pem>] ES256 signing key */
    ngx_str_t    data_url;     /* [..._data_url https://cache:8443] public data URL */
    ngx_str_t    web_url;      /* [..._web_url https://cache:8444] */
    ngx_str_t    sitename;     /* [..._sitename MyCache] → registry-prefix /caches/<name> */
    ngx_str_t    issuer_url;   /* [..._issuer <url>] advertise token iss */
    ngx_msec_t   interval;     /* [..._interval 60s] re-advertise period (>=60s) */
    ngx_array_t *ns;           /* ngx_str_t[] namespace prefixes advertised */
    void        *key_pkey;     /* loaded EVP_PKEY* (init_process) */
    void        *timer;        /* ngx_event_t* periodic timer */
    char         instance[40]; /* hex UUID instanceID, set at init */
    uint64_t     gen;          /* monotonic generationID */
} brix_cache_advertise_conf_t;

/* Watermark-driven LRU read-cache reaper (src/cache/reap_watermark.h): a
 * per-worker timer purges oldest-first when occupancy crosses the high mark, down
 * to the low mark (hysteresis; ppm units).  Grouped as one sub-struct so the
 * per-server config block stays navigable; every field is conf->reaper.<field>. */
typedef struct {
    ngx_uint_t   high_watermark;  /* [brix_cache_high_watermark] ppm; start purge above */
    ngx_uint_t   low_watermark;   /* [brix_cache_low_watermark] ppm; purge down to */
    time_t       reap_interval;   /* [brix_cache_reap_interval] secs between ticks */
    off_t        max_bytes;       /* [brix_cache_max_bytes] cap on cache-OWNED bytes
                                   * (pfc.diskusage files); distinct from the ppm FS
                                   * watermark — bounds a cache sharing a mount with
                                   * other data. 0 = off. */
    ngx_event_t *timer;           /* per-worker watermark reaper; NULL if off */
} brix_cache_reaper_conf_t;

/* Cache include-regex admission filter: a path-basename match always admits the
 * file regardless of size.  Grouped as one sub-struct so the per-server config
 * block stays navigable; every field is reached as conf->include_regex.<field>. */
typedef struct {
    ngx_str_t   str;  /* [brix_cache_include_regex "\.root$"] POSIX ERE source */
    regex_t     re;   /* compiled POSIX ERE; valid only when set == 1 */
    ngx_flag_t  set;  /* 1 after a successful regcomp() */
} brix_cache_include_regex_conf_t;

/* ---- create_srv_conf() init helpers ------------------------------------
 * One per sub-struct: set the NGX_CONF_UNSET* sentinels + non-zero handles that
 * merge_srv_conf() distinguishes from an explicit value.  The enclosing srv_conf
 * is ngx_pcalloc'd, so fields that default to 0/NULL are left untouched.
 * Co-located with the types so a reviewer audits one concern's init in one place
 * instead of scanning create_srv_conf's flat wall of assignments. */

static ngx_inline void
brix_ocsp_conf_init(brix_ocsp_conf_t *c)
{
    c->enable    = NGX_CONF_UNSET;
    c->soft_fail = NGX_CONF_UNSET;
    c->require_nonce = NGX_CONF_UNSET;
    c->stapling  = NGX_CONF_UNSET;
}

static ngx_inline void
brix_krb5_conf_init(brix_krb5_conf_t *c)
{
    c->ip_check = NGX_CONF_UNSET;
    c->delegate = NGX_CONF_UNSET;
}

static ngx_inline void
brix_wt_conf_init(brix_wt_conf_t *c)
{
    c->enable = NGX_CONF_UNSET;
    c->mode   = BRIX_WT_MODE_UNSET;
    ngx_memzero(&c->decision, sizeof(c->decision));
}

static ngx_inline void
brix_cms_conf_init(brix_cms_conf_t *c)
{
    c->locate_timeout   = NGX_CONF_UNSET_MSEC;
    c->interval         = NGX_CONF_UNSET;
    c->read_timeout     = NGX_CONF_UNSET_MSEC;
    c->send_timeout     = NGX_CONF_UNSET_MSEC;
    c->tcp_keepalive    = NGX_CONF_UNSET;
    c->tcp_user_timeout = NGX_CONF_UNSET_MSEC;
    c->initial_delay    = NGX_CONF_UNSET_MSEC;
    c->connect_retry    = NGX_CONF_UNSET_MSEC;
    c->load_weight      = NGX_CONF_UNSET;
    c->affinity         = NGX_CONF_UNSET;
    c->locate_multi     = NGX_CONF_UNSET;
    c->fanout           = NGX_CONF_UNSET;
    c->fanout_window    = NGX_CONF_UNSET_MSEC;
    c->role             = NGX_CONF_UNSET_UINT;
    c->state_relay      = NGX_CONF_UNSET;
    c->delay_servers    = NGX_CONF_UNSET;
    c->delay_hold       = NGX_CONF_UNSET;
    c->sched_cpu        = NGX_CONF_UNSET;
    c->sched_io         = NGX_CONF_UNSET;
    c->sched_runq       = NGX_CONF_UNSET;
    c->sched_mem        = NGX_CONF_UNSET;
    c->sched_pag        = NGX_CONF_UNSET;
    c->sched_space      = NGX_CONF_UNSET;
    c->sched_fuzz       = NGX_CONF_UNSET;
    c->sched_maxload    = NGX_CONF_UNSET;
    c->stage_select     = NGX_CONF_UNSET;
    c->fxhold           = NGX_CONF_UNSET_MSEC;
    c->emptylife        = NGX_CONF_UNSET_MSEC;
    c->dfs              = NGX_CONF_UNSET;
    c->perf_int         = NGX_CONF_UNSET_MSEC;
    c->altds_port       = NGX_CONF_UNSET;
    c->altds_monitor    = NGX_CONF_UNSET;
    c->altds_interval   = NGX_CONF_UNSET_MSEC;
    c->min_free_mb      = NGX_CONF_UNSET;
}

static ngx_inline void
brix_hc_conf_init(brix_hc_conf_t *c)
{
    c->enabled      = NGX_CONF_UNSET;
    c->interval_ms  = NGX_CONF_UNSET_MSEC;
    c->timeout_ms   = NGX_CONF_UNSET_MSEC;
    c->threshold    = NGX_CONF_UNSET_UINT;
    c->blacklist_ms = NGX_CONF_UNSET_MSEC;
    c->type         = NGX_CONF_UNSET_UINT;
}

static ngx_inline void
brix_node_caps_conf_init(brix_node_caps_conf_t *c)
{
    c->metadata_only      = NGX_CONF_UNSET;
    c->supervisor         = NGX_CONF_UNSET;
    c->virtual_redirector = NGX_CONF_UNSET;
    c->collapse_redir     = NGX_CONF_UNSET;
    c->collapse_redir_ttl = NGX_CONF_UNSET_MSEC;
    c->recover_writes     = NGX_CONF_UNSET;
    c->cms_locate_window  = NGX_CONF_UNSET_MSEC;
    c->cms_state_fanout   = NGX_CONF_UNSET_UINT;
}

static ngx_inline void
brix_proxy_conf_init(brix_proxy_conf_t *c)
{
    c->enable             = NGX_CONF_UNSET;
    c->port               = NGX_CONF_UNSET;
    c->upstream_tls       = NGX_CONF_UNSET;
    c->upstream_ssl_verify = NGX_CONF_UNSET;
    c->auth               = NGX_CONF_UNSET_UINT;
    c->login_user         = NGX_CONF_UNSET_UINT;
    c->login_user_name[0] = '\0';
    c->audit_log_fd       = NGX_INVALID_FILE;
    c->reconnect_attempts = NGX_CONF_UNSET_UINT;
    c->connect_timeout    = NGX_CONF_UNSET_MSEC;
    c->read_timeout       = NGX_CONF_UNSET_MSEC;
    c->write_timeout      = NGX_CONF_UNSET_MSEC;
    c->keepalive_interval = NGX_CONF_UNSET_MSEC;
}

static ngx_inline void
brix_csi_conf_init(brix_csi_conf_t *c)
{
    c->enable   = NGX_CONF_UNSET;
    c->block    = NGX_CONF_UNSET_SIZE;
    c->require  = NGX_CONF_UNSET;
    c->trust_fs = NGX_CONF_UNSET;
    c->scrub_interval = NGX_CONF_UNSET;
}

static ngx_inline void
brix_acc_conf_init(brix_acc_conf_t *c)
{
    c->format        = NGX_CONF_UNSET_UINT;
    c->audit         = NGX_CONF_UNSET_UINT;
    c->refresh       = NGX_CONF_UNSET;
    c->gidlifetime   = NGX_CONF_UNSET;
    c->pgo           = NGX_CONF_UNSET;
    c->resolve_hosts = NGX_CONF_UNSET;
    c->encoding      = NGX_CONF_UNSET;
}

static ngx_inline void
brix_cache_reaper_conf_init(brix_cache_reaper_conf_t *c)
{
    c->high_watermark = NGX_CONF_UNSET_UINT;
    c->low_watermark  = NGX_CONF_UNSET_UINT;
    c->reap_interval  = NGX_CONF_UNSET;
    c->max_bytes      = NGX_CONF_UNSET;
}

/* ---- merge_srv_conf() helpers (literal-default groups) ------------------
 * Apply parent->child inheritance + defaults, one per sub-struct, so a reviewer
 * audits a concern's merge in one place.  Only groups whose defaults are literals
 * live here (this header is widely included and cannot see feature constants such
 * as BRIX_HC_TYPE_*); groups with constant/computed defaults merge in
 * server_conf.c. */

static ngx_inline void
brix_ocsp_conf_merge(brix_ocsp_conf_t *c, brix_ocsp_conf_t *p)
{
    ngx_conf_merge_value(c->enable,    p->enable,    0);
    ngx_conf_merge_value(c->soft_fail, p->soft_fail, 1);
    ngx_conf_merge_value(c->require_nonce, p->require_nonce, 0);
    ngx_conf_merge_value(c->stapling,  p->stapling,  0);
}

static ngx_inline void
brix_node_caps_conf_merge(brix_node_caps_conf_t *c, brix_node_caps_conf_t *p)
{
    ngx_conf_merge_value(c->metadata_only,      p->metadata_only,      0);
    ngx_conf_merge_value(c->supervisor,         p->supervisor,         0);
    ngx_conf_merge_value(c->virtual_redirector, p->virtual_redirector, 0);
    ngx_conf_merge_value(c->collapse_redir,     p->collapse_redir,     0);
    ngx_conf_merge_msec_value(c->collapse_redir_ttl, p->collapse_redir_ttl, 30000);
    ngx_conf_merge_value(c->recover_writes,     p->recover_writes,     0);
    ngx_conf_merge_msec_value(c->cms_locate_window, p->cms_locate_window, 0);
    ngx_conf_merge_uint_value(c->cms_state_fanout,  p->cms_state_fanout,  8);
}

static ngx_inline void
brix_csi_conf_merge(brix_csi_conf_t *c, brix_csi_conf_t *p)
{
    ngx_conf_merge_value(c->enable,   p->enable,   1);
    ngx_conf_merge_size_value(c->block, p->block, 1024 * 1024); /* 1MiB cinfo default */
    ngx_conf_merge_value(c->require,  p->require,  0);
    ngx_conf_merge_value(c->trust_fs, p->trust_fs, 0);
    ngx_conf_merge_value(c->scrub_interval, p->scrub_interval, 0); /* 0 = off */
}

#endif /* BRIX_TYPES_CONF_STRUCTS_H */
