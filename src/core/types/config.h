#ifndef BRIX_TYPES_CONFIG_H
#define BRIX_TYPES_CONFIG_H

/* ---- File: config.h — Per-server configuration struct (ngx_stream_brix_srv_conf_t) ----
 *
 * PURPOSE:
 *   One ngx_stream_brix_srv_conf_t per `server {}` block.
 *   nginx allocates via create_srv_conf, merges in merge_srv_conf.
 *   Encapsulates all tunables for a server instance.
 *
 * HELPER TYPES:
 * - brix_sss_key_t: SSS credential key (id/exp/opts/key/name/user/group)
 * - brix_auth_type_t: ACL rule type (user DN, VO, hostname, all-match)
 * - brix_authdb_rule_t: ACL rule with auth type + identity + privileges
 * - brix_vo_rule_t: VO access rule (path prefix + VOMS VO name)
 * - brix_group_rule_t: Group inheritance rule (path prefix)
 * - brix_manager_map_t: CMS manager map (prefix + host/port)
 *
 * CONFIGURATION AREAS:
 * 1. Authentication: GSI/token/SSS/anonymous mode
 * 2. TLS: cert/key/trusted CA/CRL/VOMS dirs, OCSP stapling
 * 3. Token Auth: JWKS/issuer/audience, macaroon secrets (grace rotation)
 * 4. VO ACLs: path prefix + VO name arrays
 * 5. Access Log: file descriptor
 * 6. Metrics: Prometheus slot
 * 7. Upstream Redirector: host/port/addr/tls_ctx/token_file
 * 8. TPC: SSRF policy + bearer file + OAuth2 endpoints
 * 9. Read-through Cache: origin/eviction/size limits/include regex
 * 10. Write-through: mode (sync/async) + origin + deny/allow prefixes
 * 11. CMS Manager: heartbeat fields
 * 12. Transparent Proxy: upstream TLS/auth/login/audit/reconnect/path rewrite
 * 13. Security Level: enforcement mode
 * 14. In-Protocol TLS: flag + tls_ctx
 * 15. Manager Mode: registry slots
 * 16. ckscan: depth/files limits
 *
 * DESIGN DECISIONS:
 * - Inline bracket annotations map fields to nginx directives
 * - OpenSSL objects (X509/EVP_PKEY/X509_STORE) for GSI
 * - Timer events (crl_timer/jwks_timer) for cert refresh
 * - Compiled regex (cache_include_regex) for cache filtering
 * - Arrays for VO ACLs, authdb rules, group rules, proxy upstreams
 *
 * LIFECYCLE:
 *   Create: ngx_stream_brix_create_srv_conf()
 *   Merge:  ngx_stream_brix_merge_srv_conf() (parent → child)
 *   Free:   ngx_stream_brix_free_srv_conf() (on server reload)
 */

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
    BRIX_AUTH_ALL   = 'a',
    /* 2.0 F20: the two VOMS-attribute selectors.  They exist ONLY in the native
     * engine's field-1 alphabet (the xrdacc port spells the same two concepts
     * `o` and `r`, and its grammar is frozen byte-for-byte against XrdAcc).
     * `l` was chosen for the role selector because `r` is already the READ
     * privilege letter in field 4 and reusing it across fields reads wrong. */
    BRIX_AUTH_VORG  = 'v',    /* VOMS virtual organisation (identity acc_vorg) */
    BRIX_AUTH_ROLE  = 'l'     /* VOMS role               (identity acc_role)  */
} brix_auth_type_t;

#define BRIX_AUTH_READ    0x01  /* 'r' */
#define BRIX_AUTH_LOOKUP  0x02  /* 'l' */
#define BRIX_AUTH_UPDATE  0x04  /* 'w' or 'a' */
#define BRIX_AUTH_DELETE  0x08  /* 'd' */
#define BRIX_AUTH_MKDIR   0x10  /* 'm' */
#define BRIX_AUTH_ADMIN   0x20  /* 'k' */
#define BRIX_AUTH_STAGE   0x40  /* 'x' — drive a tape/nearline recall or evict */

/* 2.0 F20: a native authdb rule may AND together up to this many identity
 * selectors in field 1 (`u g p a v l`, each at most once).  Six is the size of
 * the alphabet, so the cap can never reject a well-formed line. */
#define BRIX_AUTHDB_MAX_SELECTORS  6

/* The XrdAcc engine selector + audit constants live in src/acc/privs.h (pure,
 * shared by the stream / WebDAV / S3 modules); pulled in via the include below. */
#include "auth/authz/acc/privs.h"

/*
 * One native-engine authdb rule.
 *
 * `nsel` selectors are AND-ed: the rule applies only to a subject that
 * satisfies EVERY sel[i]/sel_id[i] pair.  A single-selector rule (the only
 * shape that existed before 2.0 F20) takes its id verbatim, so a DN containing
 * any character at all keeps working; a compound rule splits its id token on
 * '|' into exactly `nsel` values, positionally aligned with the selectors.
 *
 * `type` / `id` are kept as the selector-0 alias so every reader that predates
 * the compound form still sees what it saw before.
 */
typedef struct {
    brix_auth_type_t type;       /* == sel[0] */
    ngx_str_t          id;       /* == sel_id[0]: user DN, VO name, hostname... */
    ngx_str_t          path;
    uint32_t           privs;    /* bitmask */
    ngx_uint_t         nsel;     /* 1..BRIX_AUTHDB_MAX_SELECTORS */
    brix_auth_type_t   sel[BRIX_AUTHDB_MAX_SELECTORS];
    ngx_str_t          sel_id[BRIX_AUTHDB_MAX_SELECTORS];
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
     * burndown) into concern-grouped .h fragments included here, following the
     * repo's established .h struct-fragment pattern. The struct assembles
     * byte-identically — ZERO ABI change, and every `conf->field` access is
     * unchanged. The fragments are NOT standalone translation units. */
#include "srv_conf_fields_auth.h"
#include "srv_conf_fields_net.h"
#include "srv_conf_fields_cache.h"
} ngx_stream_brix_srv_conf_t;

/*
 * Per-worker init of the xrdacc authorization engine for one server: parses the
 * authdb into xcf->acc.tables and arms the hot-reload timer.  No-op unless the
 * server uses `brix_authdb_engine xrdacc`.  Implemented in src/acc/config.c.
 */
ngx_int_t brix_acc_init_server(ngx_stream_brix_srv_conf_t *xcf,
    ngx_cycle_t *cycle);

#endif /* BRIX_TYPES_CONFIG_H */
