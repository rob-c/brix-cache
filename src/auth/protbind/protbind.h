/*
 * protbind.h — per-host authentication-protocol binding policy (XRootD
 * `sec.protbind`), expressed protocol-agnostically.
 *
 * WHAT: Declares the rule/result types and the pure engine that turns an
 *       ordered list of `<host-template> [none | [only] <proto>...]` rules
 *       plus a fallback protocol set into the ORDERED set of authentication
 *       protocols a particular peer may use.
 *
 * WHY:  BriX historically bound exactly one auth scheme per listener
 *        (`brix_auth`), with `both` as the single hard-coded composition of
 *        ztn+gsi.  Stock XRootD instead binds an arbitrary ORDERED protocol
 *        list per host template, which is what sites use to say "grid hosts
 *        must use gsi, the local batch farm may use sss or unix, everyone
 *        else gets tokens".  Expressing that as one generic engine — with no
 *        dependency on the root:// session, the HTTP request, or any storage
 *        backend — lets every VFS frontend share ONE policy implementation and
 *        one config grammar instead of growing a private copy each.
 *
 * HOW:  Callers build a *base* set (what the listener would allow with no
 *       protbind rules at all — `brix_protbind_base_set` does that for the
 *       stream `brix_auth` modes, `brix_protbind_http_base` for the HTTP
 *       credential sources), then call `brix_protbind_resolve` with the peer's
 *       hostname and/or IP.  The first matching rule wins; `none` yields an
 *       empty set with require_auth == 0, `only` yields exactly the listed
 *       protocols, and the default form yields the listed protocols followed
 *       by the base protocols not already named.  `brix_protbind_allows` then
 *       gates an offered credential and the ordered `protos[]` drives whatever
 *       the frontend advertises (the root:// "&P=" sec token, the order HTTP
 *       credential sources are tried in).
 *
 * Requires: nginx core headers (ngx_config.h / ngx_core.h) and
 *           core/types/tunables.h (BRIX_AUTH_*) before inclusion.
 */

#ifndef BRIX_AUTH_PROTBIND_H
#define BRIX_AUTH_PROTBIND_H

/* Upper bound on protocols in one rule / one resolved set.  Seven schemes
 * exist (gsi, ztn, sss, unix, krb5, host, pwd); 8 leaves one slot of slack
 * and keeps both structs small enough to live on the stack. */
#define BRIX_PROTBIND_MAX_PROTOS  8

/* Rule modes — the three shapes of the directive's tail. */
#define BRIX_PROTBIND_ALL   0  /* listed protocols first, then the base set */
#define BRIX_PROTBIND_ONLY  1  /* listed protocols and nothing else        */
#define BRIX_PROTBIND_NONE  2  /* matching hosts authenticate with nothing */

/*
 * brix_protbind_rule_t — one parsed `brix_protbind` directive.
 *
 * host_tpl is the raw template (`*`, `*.cern.ch`, `lxplus*`, `pps*.gridpp.uk`,
 * or a literal name/address); protos[] holds `count` BRIX_AUTH_* ids in the
 * order they were written, which IS the advertisement order.
 */
typedef struct {
    ngx_str_t   host_tpl;
    ngx_uint_t  mode;                            /* BRIX_PROTBIND_*   */
    ngx_uint_t  count;                           /* protocols listed  */
    ngx_uint_t  protos[BRIX_PROTBIND_MAX_PROTOS];/* BRIX_AUTH_* ids   */
} brix_protbind_rule_t;

/*
 * brix_protbind_set_t — the resolved, ordered protocol set for one peer.
 *
 * require_auth is 0 only for the `none` outcome (and for a base set built from
 * an auth-less listener): the caller must then complete the session
 * anonymously rather than advertising an empty credential list.
 */
typedef struct {
    ngx_uint_t  count;
    ngx_uint_t  protos[BRIX_PROTBIND_MAX_PROTOS];
    ngx_flag_t  require_auth;
} brix_protbind_set_t;

/* ---- name/id mapping (match.c) ---- */

/* Map a directive token ("gsi", "ztn"/"token", "sss", "unix", "krb5", "host",
 * "pwd") to its BRIX_AUTH_* id; NGX_OK on success, NGX_DECLINED if unknown. */
ngx_int_t brix_protbind_proto_id(const ngx_str_t *name, ngx_uint_t *out);

/* Does `host` match one template?  A single `*` acts as a wildcard span, so
 * "*", "pref*", "*suffix" and "pref*suffix" all work (XrdOucNList semantics);
 * any further `*` is literal.  Matching is case-insensitive.  A bare "*"
 * matches even a NULL/empty host, so `*` rules never need a DNS lookup. */
ngx_flag_t brix_protbind_host_match(const ngx_str_t *tpl, const char *host);

/* Would evaluating `rules` ever need a resolved peer HOSTNAME (i.e. is any
 * template something other than a bare "*")?  Lets callers skip reverse DNS
 * entirely for the overwhelmingly common `brix_protbind * ...` config. */
ngx_flag_t brix_protbind_needs_hostname(ngx_array_t *rules);

/* Does ANY rule name `proto`?  The listener-static question "could this server
 * ever run protocol X", asked by the per-scheme startup loaders: a protocol a
 * rule can select must have its keys/certs/principal loaded even when
 * `brix_auth` did not select it. */
ngx_flag_t brix_protbind_any_names(ngx_array_t *rules, ngx_uint_t proto);

/* ---- policy (policy.c) ---- */

/* Build the base set a stream listener would allow from its `brix_auth` mode:
 * NONE → empty/anonymous, BOTH → {ztn, gsi}, otherwise the single mode. */
void brix_protbind_base_set(ngx_uint_t base_auth, brix_protbind_set_t *out);

/* Build the base set for an HTTP frontend: the three credential sources it can
 * actually run, in historical strength order {gsi, ztn, pwd}.  `require_auth`
 * carries the location's own auth=none/optional/required decision. */
void brix_protbind_http_base(ngx_flag_t require_auth, brix_protbind_set_t *out);

/* Resolve the effective set for a peer.  `rules` may be NULL/empty (→ *out =
 * *base).  `peer_host` may be NULL when no rule needs a hostname; `peer_ip`
 * may be NULL.  First matching rule wins. */
void brix_protbind_resolve(ngx_array_t *rules, const brix_protbind_set_t *base,
    const char *peer_host, const char *peer_ip, brix_protbind_set_t *out);

/* Is `proto` (a BRIX_AUTH_* id) a member of the resolved set? */
ngx_flag_t brix_protbind_allows(const brix_protbind_set_t *set,
    ngx_uint_t proto);

/* ---- configuration (config.c) ---- */

/* Parse one `<directive> <template> [none | [only] <proto>...]` into *rules
 * (created on first use from cf->pool).  Returns NGX_CONF_OK, or NGX_CONF_ERROR
 * after logging an [emerg] prefixed with cmd->name — so a module setter is a
 * single tail call and the two frontends cannot report differently. */
char *brix_protbind_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    ngx_array_t **rules);

/* ---- root:// stream binding (peer.c) ---- */

struct brix_ctx_s;

/* Reverse-resolved peer hostname for ANY host-template policy (protbind rules,
 * XrdAcc `h` records), resolved at most once per connection and cached on the
 * session context; NULL when the peer has no PTR record. */
const char *brix_protbind_peer_host_cached(struct brix_ctx_s *ctx,
    ngx_connection_t *c);

/* As above, but returns NULL without resolving when every configured template
 * is a bare "*" and therefore cannot consult a hostname. */
const char *brix_protbind_peer_host(struct brix_ctx_s *ctx,
    ngx_connection_t *c, ngx_array_t *rules);

/* Resolve the effective set for a root:// session: builds the base set from
 * `base_auth`, supplies the (lazily resolved) peer hostname and the peer IP
 * already recorded on the context, and fills *out. */
void brix_protbind_resolve_ctx(struct brix_ctx_s *ctx, ngx_connection_t *c,
    ngx_array_t *rules, ngx_uint_t base_auth, brix_protbind_set_t *out);

#endif /* BRIX_AUTH_PROTBIND_H */
