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

/* E-4 negative-path backoff rule (brix_negcache_conf_t). Pulls only ngx_core. */
#include "core/negcache/negcache.h"

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
    /* The ~690 field declarations of this struct are split (phase-79 file-size
     * burndown) into concern-grouped .inc fragments included here, following the
     * repo's established .inc struct-fragment pattern. The struct assembles
     * byte-identically — ZERO ABI change, and every `conf->field` access is
     * unchanged. The fragments are NOT standalone translation units. */
#include "srv_conf_fields_auth.inc"
#include "srv_conf_fields_net.inc"
#include "srv_conf_fields_cache.inc"
} ngx_stream_brix_srv_conf_t;

/*
 * Per-worker init of the xrdacc authorization engine for one server: parses the
 * authdb into xcf->acc.tables and arms the hot-reload timer.  No-op unless the
 * server uses `brix_authdb_format xrdacc`.  Implemented in src/acc/config.c.
 */
ngx_int_t brix_acc_init_server(ngx_stream_brix_srv_conf_t *xcf,
    ngx_cycle_t *cycle);

#endif /* BRIX_TYPES_CONFIG_H */
