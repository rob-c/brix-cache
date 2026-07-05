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
    ngx_flag_t  enable;      /* [brix_ocsp_enable on|off]
                                Query OCSP responder for each client certificate
                                after GSI chain verification.  Default off. */
    ngx_flag_t  soft_fail;   /* [brix_ocsp_soft_fail on|off]
                                If on (default), network errors and UNKNOWN status
                                are treated as GOOD (non-blocking).
                                REVOKED always fails regardless. */
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

/* CMS manager heartbeat + client-side network-fault resilience.  Grouped as one
 * sub-struct so the per-server config block stays navigable; every field is
 * reached as conf->cms.<field>.  (The advertised listen_port stays a top-level
 * field — it is not CMS-specific.) */
typedef struct {
    ngx_msec_t          locate_timeout;   /* [brix_cms_locate_timeout 5s] */
    ngx_str_t           manager;          /* [brix_cms_manager host:port] — raw directive */
    ngx_addr_t         *addr;             /* resolved manager address */
    ngx_str_t           paths;            /* [brix_cms_paths /data] — exported path list */
    time_t              interval;         /* [brix_cms_interval 60] — heartbeat period */
    ngx_brix_cms_ctx_t *ctx;              /* runtime connection / timer state (heap) */
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
    ngx_str_t    upstream_tls_ca;    /* [brix_proxy_upstream_tls_ca /etc/pki/ca.pem] */
    ngx_str_t    upstream_tls_name;  /* [brix_proxy_upstream_tls_name host] — SNI override */
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
    ngx_uint_t  max_active_conn; /* [brix_throttle_max_active_connections] */
} brix_throttle_conf_t;

/* CSI block-checksum integrity on the xmeta record (ON by default).  Grouped as
 * one sub-struct so the per-server config block stays navigable; every field is
 * reached as conf->csi.<field>. */
typedef struct {
    ngx_flag_t  enable;    /* [brix_csi on|off] default ON */
    size_t      block;     /* [brix_csi_block 1m] granule for NEW records */
    ngx_flag_t  require;   /* [brix_csi_require on|off] no record = err */
    ngx_flag_t  trust_fs;  /* [brix_csi_trust_fs on|off] fs self-checksums: skip read-verify */
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
    c->stapling  = NGX_CONF_UNSET;
}

static ngx_inline void
brix_krb5_conf_init(brix_krb5_conf_t *c)
{
    c->ip_check = NGX_CONF_UNSET;
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
}

static ngx_inline void
brix_proxy_conf_init(brix_proxy_conf_t *c)
{
    c->enable             = NGX_CONF_UNSET;
    c->port               = NGX_CONF_UNSET;
    c->upstream_tls       = NGX_CONF_UNSET;
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
}

static ngx_inline void
brix_csi_conf_merge(brix_csi_conf_t *c, brix_csi_conf_t *p)
{
    ngx_conf_merge_value(c->enable,   p->enable,   1);
    ngx_conf_merge_size_value(c->block, p->block, 1024 * 1024); /* 1MiB cinfo default */
    ngx_conf_merge_value(c->require,  p->require,  0);
    ngx_conf_merge_value(c->trust_fs, p->trust_fs, 0);
}

#endif /* BRIX_TYPES_CONF_STRUCTS_H */
