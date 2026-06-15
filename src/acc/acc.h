/*
 * acc.h — nginx-facing umbrella header for the `xrdacc` authorization engine.
 *
 * WHAT: the public surface of src/acc/ — a faithful re-implementation of
 *   XRootD's XrdAcc authorization framework, selectable at runtime via
 *   `xrootd_authdb_format xrdacc;`.  This header re-exports the pure privilege
 *   algebra (privs.h) and will declare the entity, tables, and Access() engine
 *   as the milestones land.
 *
 * WHY: the module's original authdb (src/path/authdb.c, the `native` engine) is
 *   a 6-bit, single-rule, root://-only ACL.  XrdAcc is a 9-bit additive model
 *   with negative privileges, templates, exclusive/compound rules, OS/NIS group
 *   resolution, hot-reload, and audit, applied uniformly to every protocol.
 *   `src/acc/` ports that engine alongside `native` (the directive picks which).
 *
 * HOW: leaf algebra in privs.h (no nginx deps, unit-testable); the nginx-coupled
 *   engine (entity/tables/access/groups/audit/config/refresh) builds on top and
 *   is reached through xrootd_acc_access(tables, entity, path, op) from the
 *   root://, WebDAV, and S3 authorization call sites.
 */

#ifndef NGX_XROOTD_ACC_H
#define NGX_XROOTD_ACC_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>   /* full ngx_event_t for the embedded hot-reload timer */

#include "privs.h"

/* ------------------------------------------------------------------ */
/* Data model — the in-memory authorization tables                    */
/* ------------------------------------------------------------------ */

/*
 * xrootd_acc_cap_t — one path/template capability (XrdAccCapability).
 *
 * A capability either references a named template (`tmpl` set, path fields
 * unused) or carries a concrete path prefix + the privilege caps it grants.
 * Capabilities chain via `next` to form one identity's ordered cap list; XrdAcc
 * applies the FIRST prefix match in the list (not longest), so order matters.
 * `pins`/`prem` describe a `@=` template-substitution point inside `path`.
 */
typedef struct xrootd_acc_cap_s {
    struct xrootd_acc_cap_s  *next;   /* next capability in this list */
    struct xrootd_acc_cap_s  *tmpl;   /* template indirection (a T-list caplist) */
    char                     *path;   /* prefix path, NUL-terminated (pool-owned) */
    int                       plen;   /* strlen(path) */
    int                       pins;   /* index of "@=" in path, 0 if none */
    int                       prem;   /* bytes after "@=" */
    xrootd_acc_priv_caps_t    caps;
} xrootd_acc_cap_t;

/*
 * xrootd_acc_named_t — a name -> capability-list binding.  One per entry in the
 * user/group/host/netgroup/org/role/template categories (XrdAcc's per-category
 * hashes).  Also used for the domain (.suffix) list (name = ".cern.ch").
 */
typedef struct xrootd_acc_named_s {
    struct xrootd_acc_named_s *next;
    char                      *name;
    int                        nlen;
    xrootd_acc_cap_t          *caps;
} xrootd_acc_named_t;

/*
 * xrootd_acc_idrule_t — a compound-identity rule (from a `=` definition plus an
 * `x` exclusive or `s` inclusive reference).  Selectors are AND-ed; a NULL
 * selector is unconstrained.  `host` beginning with '.' is a domain suffix.
 * `rule` >= 0 orders exclusive rules; -1 marks inclusive.
 */
typedef struct xrootd_acc_idrule_s {
    struct xrootd_acc_idrule_s *next;
    char                       *name;
    char                       *user;
    char                       *host;
    char                       *org;
    char                       *role;
    char                       *grp;
    int                         hlen;   /* strlen(host) for domain suffix match */
    int                         rule;   /* exclusive order, or -1 = inclusive */
    xrootd_acc_cap_t           *caps;
} xrootd_acc_idrule_t;

/*
 * xrootd_acc_tables_t — the full table set built from one authdb file.  All
 * nodes are allocated from `pool`, so a refresh frees the whole generation with
 * one ngx_destroy_pool() and swaps in a new pointer atomically.
 */
typedef struct xrootd_acc_tables_s {
    ngx_pool_t          *pool;       /* owns every allocation below */
    xrootd_acc_named_t  *g_list;     /* groups       (g) */
    xrootd_acc_named_t  *h_list;     /* hosts exact  (h <name>) */
    xrootd_acc_named_t  *n_list;     /* netgroups    (n) */
    xrootd_acc_named_t  *o_list;     /* orgs         (o) */
    xrootd_acc_named_t  *r_list;     /* roles        (r) */
    xrootd_acc_named_t  *t_list;     /* templates    (t) */
    xrootd_acc_named_t  *u_list;     /* users        (u <name>) */
    xrootd_acc_named_t  *d_list;     /* domains      (h .suffix) */
    xrootd_acc_cap_t    *z_list;     /* default      (u *) */
    xrootd_acc_cap_t    *x_list;     /* fungible      (u =) */
    xrootd_acc_idrule_t *id_defs;    /* all `=` definitions, by name */
    xrootd_acc_idrule_t *sx_list;    /* exclusive rules (x), ordered */
    xrootd_acc_idrule_t *sy_list;    /* inclusive rules (s) */
    ngx_uint_t           rule_count; /* parsed identity/path rules (diagnostics) */
    time_t               mtime;      /* source mtime, for hot-reload */
    /* Parse-time inputs (legacy XrdAcc tunables; transient, consulted only
     * while this generation is being built — see xrootd_acc_authfile_parse). */
    char                 parse_spacechar; /* spacechar: 0=off else ->' ' in ids */
    ngx_flag_t           parse_uridecode; /* encoding pct path: URI-decode paths */
} xrootd_acc_tables_t;

/* ------------------------------------------------------------------ */
/* Entity — the authenticated identity, expanded to attribute tuples  */
/* ------------------------------------------------------------------ */

/* One (vorg, role, grup) attribute combination (XrdAccEntityInfo). */
typedef struct {
    const char *vorg;
    const char *role;
    const char *grup;
} xrootd_acc_attr_t;

/*
 * xrootd_acc_entity_t — the request identity.  `name`/`host` are scalar;
 * `tuples` is the positional expansion of the multi-valued VO/role/group
 * attributes (built by entity.c from xrootd_identity_t).
 */
typedef struct {
    const char         *name;     /* user name (DN / subject) or "*" */
    const char         *host;     /* peer host or "?" */
    int                 isuser;   /* name is a concrete user (not "*") */
    ngx_array_t        *tuples;   /* of xrootd_acc_attr_t (>= 1 entry) */
    ngx_pool_t         *pool;     /* scratch pool (for the netgroup resolver) */
} xrootd_acc_entity_t;

/*
 * OS/NIS group hooks — installed by groups.c (M4).  When unset, `n` (netgroup)
 * records never match and no Unix-group expansion occurs, which keeps the access
 * engine fully testable without the OS layer.
 *   - unixgrp: resolve a user to the array of (char *) Unix group names it
 *     belongs to (getpwnam + getgrouplist), matched against the `g` records in
 *     addition to the entity's own supplied groups.
 *   - netgrp:  test NIS netgroup membership for (netgroup, user, host) — the
 *     innetgr() predicate; the engine probes each `n` record with it.
 */
typedef ngx_array_t *(*xrootd_acc_unixgrp_fn)(ngx_pool_t *pool, const char *user);
typedef int          (*xrootd_acc_netgrp_fn)(const char *netgroup,
                                             const char *user, const char *host);
void xrootd_acc_set_group_resolvers(xrootd_acc_unixgrp_fn ug,
                                    xrootd_acc_netgrp_fn ng);

/* groups.c (M4) — install the real OS/NIS resolvers + their tunables. */
void xrootd_acc_groups_init(void);
void xrootd_acc_groups_set_gidlifetime(time_t secs);
void xrootd_acc_groups_set_primary_only(ngx_int_t on);
void xrootd_acc_groups_set_nisdomain(const char *domain);
/* gidretran <gids>: space-separated gids whose group name is ambiguous (shared)
 * and must be skipped during Unix-group resolution (XrdAccGroups::Dotran). */
void xrootd_acc_groups_set_gidretran(const char *gidlist);

/*
 * config.c (M5/RB2) — parse `authdb_path` into a fresh table generation and
 * install the OS/NIS group tunables + resolvers.  `gidretran` is the shared-gid
 * skip list; `spacechar` (0=off) substitutes a char for spaces in identity
 * names; `encoding` URI-decodes path tokens.  Returns NULL on a fatal error.
 */
xrootd_acc_tables_t *xrootd_acc_build(const char *authdb_path,
    ngx_int_t gidlifetime, ngx_int_t pgo, const char *nisdomain,
    const char *gidretran, char spacechar, ngx_int_t encoding, ngx_log_t *log);

/* audit.c (M5) — emit a grant/deny audit line (level: 1=deny, 2=grant). */
void xrootd_acc_audit(ngx_log_t *log, ngx_uint_t level, int granted,
    const char *op, const char *id, const char *host, const char *path);

/*
 * resolve.c — reverse-DNS the peer for `h <host>`/`h .domain` rule matching
 * (XrdAccAccess::Resolve).  Returns `buf` (the FQDN) on success, NULL on
 * failure (no PTR record / bad address) so the caller falls back to the IP.
 * Opt-in via xrootd_acc_resolve_hosts; the caller caches per connection.
 */
const char *xrootd_acc_resolve_peer(struct sockaddr *sa, socklen_t salen,
    char *buf, size_t buflen);

/*
 * xrootd_acc_http_t — the XrdAcc engine settings + per-worker state shared by
 * the WebDAV and S3 HTTP loc-confs.  Both embed it as a member named `acc`, so
 * the shared directive setters, the lazy table build, the hot-reload timer and
 * the authorize helper all operate on ONE type regardless of which HTTP module
 * owns the location.  The stream side keeps its flat srv-conf fields; this is
 * the HTTP analogue of that group.
 *
 * The `tables`/`timer` state is per-worker: nginx forks after config load, so
 * the first write in each worker (lazy build, timer arm) COW-privatises the
 * page — every worker keeps its own tables and its own refresh timer with no
 * locking, exactly like the stream srv conf.
 */
typedef struct {
    ngx_uint_t   format;        /* [xrootd_authdb_format] native|xrdacc */
    ngx_uint_t   audit;         /* [xrootd_authdb_audit] */
    ngx_str_t    authdb;        /* [xrootd_authdb <path>] */
    ngx_int_t    refresh;       /* [xrootd_authdb_refresh] secs; 0=off */
    ngx_int_t    gidlifetime;   /* [xrootd_acc_gidlifetime] */
    ngx_flag_t   pgo;           /* [xrootd_acc_pgo] primary group only */
    ngx_str_t    nisdomain;     /* [xrootd_acc_nisdomain] */
    ngx_flag_t   resolve_hosts; /* [xrootd_acc_resolve_hosts] reverse DNS */
    ngx_str_t    spacechar;     /* [xrootd_acc_spacechar] legacy id space char */
    ngx_flag_t   encoding;      /* [xrootd_acc_encoding] legacy URI-decode paths */
    ngx_str_t    gidretran;     /* [xrootd_acc_gidretran] legacy shared-gid skip */
    struct xrootd_acc_tables_s *tables;  /* per-worker, built lazily */
    ngx_event_t  timer;         /* per-worker refresh timer (embedded) */
    unsigned     timer_armed:1; /* this worker has armed `timer` */
} xrootd_acc_http_t;

/*
 * config.c (M7/RB1) — shared WebDAV/S3 authorization helper.  Lazily builds the
 * per-worker tables on first use (honouring the gidlifetime/pgo/nisdomain
 * tunables), arms the hot-reload timer when `refresh` is set, evaluates the
 * identity against `op`+`path`, and audits.  Returns NGX_OK (allow), NGX_ERROR
 * (deny), or NGX_DECLINED when the engine is not selected (format != xrdacc),
 * so the caller keeps its own token-scope/write-gate checks.
 */
ngx_int_t xrootd_acc_http_authorize(ngx_pool_t *pool, ngx_log_t *log,
    xrootd_acc_http_t *acc, const char *name, const char *host,
    const char *vorg, const char *role, const char *grp,
    xrootd_acc_op_t op, const char *path);

/* config.c (RB1) — default-init / merge an HTTP acc block (loc-conf helpers). */
void xrootd_acc_http_init_conf(xrootd_acc_http_t *acc);
void xrootd_acc_http_merge_conf(xrootd_acc_http_t *conf, xrootd_acc_http_t *prev);

/* Shared directive enum tables for `xrootd_authdb_format` / `_audit`. */
extern ngx_conf_enum_t  xrootd_acc_format_modes[];
extern ngx_conf_enum_t  xrootd_acc_audit_modes[];

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

/* capability.c */
int  xrootd_acc_cap_privs(xrootd_acc_cap_t *cap, xrootd_acc_priv_caps_t *out,
                          const char *path, int plen, const char *pathsub);

/* tables.c — name lookups (linked-list, strcmp; authdb files are small) */
xrootd_acc_cap_t *xrootd_acc_named_find(xrootd_acc_named_t *list, const char *name);
xrootd_acc_cap_t *xrootd_acc_domain_find(xrootd_acc_named_t *dlist, const char *host);

/* authfile.c — parse an authdb file into a fresh table generation (own pool).
 * Returns NULL on a fatal parse/IO error (already logged). */
xrootd_acc_tables_t *xrootd_acc_authfile_parse(ngx_log_t *log, const char *file,
    char spacechar, ngx_int_t uri_decode);
void                 xrootd_acc_tables_free(xrootd_acc_tables_t *tabs);

/* entity.c (M2) */
xrootd_acc_entity_t *xrootd_acc_entity_build(ngx_pool_t *pool,
                                             const char *name, const char *host,
                                             int isuser,
                                             const char *vorg_csv,
                                             const char *role_csv,
                                             const char *grp_csv);

/* access.c (M2) — the decision engine.  Returns granted privileges (0 = deny);
 * for op == XROOTD_AOP_ANY returns the effective privilege set. */
xrootd_acc_privs_t xrootd_acc_access(xrootd_acc_tables_t *tabs,
                                     const xrootd_acc_entity_t *ent,
                                     const char *path, xrootd_acc_op_t op);

#endif /* NGX_XROOTD_ACC_H */
