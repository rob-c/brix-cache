#ifndef BRIX_TPC_IDENTITY_MATRIX_H
#define BRIX_TPC_IDENTITY_MATRIX_H

/*
 * identity_matrix.h — the TPC identity matrix (2.0 F18), BriX's spelling of
 * XRootD's `ofs.tpc allow|require|restrict|oids`.
 *
 * WHAT: a second, INNER authorization plane for third-party copy, expressed
 *   over the *initiating identity* rather than over the host this server would
 *   dial.  Four controls:
 *     brix_tpc_allow_identity dn|group|host|vo <pattern> [...]  — who may TPC
 *     brix_tpc_require all|client|dest <auth>                   — how they authed
 *     brix_tpc_restrict <path>...                               — where
 *     brix_tpc_oids on|off                                      — object-id paths
 *
 * WHY: today's TPC confinement is entirely host-plane — brix_tpc_source_guard /
 *   _source_allow name the peers this server may originate to, and
 *   brix_tpc_allow_local / _allow_private bound the address ranges.  That
 *   answers "which machines", never "which users".  An operator running a
 *   shared gateway wants "only the CMS VO, only over GSI, only under /store"
 *   — the identity matrix stock xrootd has had for years.  It layers ON TOP of
 *   the host plane and can only ever NARROW: the host verdict is evaluated
 *   first and a matrix rule is never consulted after a host denial, so no
 *   identity rule can widen an egress decision.
 *
 * HOW: the whole verdict is a pure, allocation-free, nginx-free function
 *   (brix_tpc_matrix_evaluate) over borrowed C strings, so every branch is
 *   proven offline by identity_matrix_unittest.c — the same split
 *   egress_guard.c uses.  The ngx layer behind XRDPROTO_NO_NGX only adapts an
 *   identity + a conf into that call and renders the refusal text.  Rules are
 *   stored in the conf arrays AS the pure structs (conf tokens are already
 *   NUL-terminated and live for the cycle), so there is no per-request
 *   conversion and no second spelling of a rule.
 *
 * Evaluation order is a SECURITY order, not a stylistic one:
 *   1. oids   — a `*`-prefixed (object-id) path is refused unless opted in.
 *   2. allow  — the subject must match at least one rule when any is configured.
 *   3. require— the subject's auth method must be one of those demanded of its
 *               party when any rule names that party.
 *   4. restrict — the path must sit under one of the configured prefixes.
 * Each stage is default-permit when it is UNCONFIGURED (so the matrix is a
 * no-op for deployments that do not opt in) and fail-closed once configured
 * (an unmatched subject is DENIED, never defaulted).  The one exception is
 * `oids`, which is default-DENY exactly as in stock xrootd: BriX has no
 * object-id namespace at all, so a `*`-prefixed TPC path is nonsense here and
 * refusing it is a pure narrowing.
 */

#include <stddef.h>

/*
 * The two parties a `require` rule can name.  The distinction is the whole
 * point of the directive and is decided by ONE wire fact: a native TPC leg
 * carrying tpc.org was opened by the peer SERVER on the client's behalf and
 * therefore presents the SERVER's credential; a leg without tpc.org was opened
 * by the initiating CLIENT and presents the client's own.  `require dest` is
 * therefore not satisfiable by a client credential, and vice versa.
 */
#define BRIX_TPC_PARTY_CLIENT  0
#define BRIX_TPC_PARTY_DEST    1
#define BRIX_TPC_PARTY_ALL     2   /* only ever a RULE's party, never a subject's */

/*
 * One `brix_tpc_allow_identity` line.  Every non-empty field must match (AND
 * within a rule); rules OR across lines — stock xrootd's semantics for
 * `ofs.tpc allow [dn ..] [group ..] [host ..] [vo ..]`.  A rule with no field
 * set matches NOTHING (it cannot be written: the setter demands a pair).
 * NULL and "" are both "field not set".
 */
typedef struct {
    const char *dn;      /* exact subject DN */
    const char *group;   /* one member of the subject's group CSV */
    const char *host;    /* egress_guard host pattern: exact, or '.'-suffix */
    const char *vo;      /* one member of the subject's VO CSV */
} brix_tpc_allow_rule_t;

/* One `brix_tpc_require <party> <auth>` line. */
typedef struct {
    int         party;   /* BRIX_TPC_PARTY_{CLIENT,DEST,ALL} */
    const char *auth;    /* auth-method label, matched case-insensitively */
} brix_tpc_require_rule_t;

/*
 * The subject a leg presents.  Borrowed strings, never owned; NULL is read as
 * "" everywhere, so an unauthenticated or unresolved field simply fails to
 * match any rule that names it (fail-closed).
 */
typedef struct {
    const char *dn;      /* subject DN ("" when none) */
    const char *groups;  /* comma-separated group paths */
    const char *vos;     /* comma-separated VO names */
    const char *host;    /* reverse-resolved peer FQDN ("" when unknown) */
    const char *auth;    /* auth-method label: GSI / TOKEN / SSS / ... / NONE */
} brix_tpc_subject_t;

/* Why the matrix refused.  OK is 0 so `if (verdict)` reads as "refused". */
typedef enum {
    BRIX_TPC_MATRIX_OK = 0,
    BRIX_TPC_MATRIX_DENY_OID,
    BRIX_TPC_MATRIX_DENY_IDENTITY,
    BRIX_TPC_MATRIX_DENY_AUTH,
    BRIX_TPC_MATRIX_DENY_PATH
} brix_tpc_matrix_verdict_t;

/*
 * The matrix as the pure evaluator sees it: borrowed rule vectors, already in
 * their final form.  `paths` are cleaned LOGICAL prefixes (see
 * brix_tpc_restrict_match).
 */
typedef struct {
    const brix_tpc_allow_rule_t   *allow;
    size_t                         nallow;
    const brix_tpc_require_rule_t *require_rules;
    size_t                         nrequire;
    const char *const             *paths;
    size_t                         npaths;
    int                            oids;      /* non-zero = permit `*` paths */
} brix_tpc_matrix_t;

/*
 * brix_tpc_csv_member — 1 if `name` is a member of the comma-separated `csv`.
 * Surrounding whitespace on each element is trimmed; the comparison is
 * case-SENSITIVE (VO and group names are, in both VOMS and WLCG tokens) and
 * exact — no prefix, no wildcard.  Empty `csv` or empty `name` → 0.
 */
int brix_tpc_csv_member(const char *csv, const char *name);

/*
 * brix_tpc_auth_name_eq — 1 if two auth-method labels are the same, compared
 * case-insensitively so an operator may write `gsi`, `GSI` or `Gsi`.
 */
int brix_tpc_auth_name_eq(const char *a, const char *b);

/*
 * brix_tpc_allow_rule_match — 1 if `subj` satisfies EVERY field `rule` sets.
 * A rule that sets no field returns 0 (fail-closed).
 */
int brix_tpc_allow_rule_match(const brix_tpc_allow_rule_t *rule,
    const brix_tpc_subject_t *subj);

/* brix_tpc_require_rule_applies — 1 if `rule` speaks about `party`. */
int brix_tpc_require_rule_applies(const brix_tpc_require_rule_t *rule,
    int party);

/*
 * brix_tpc_restrict_match — component-aware prefix test.
 *
 * 1 when `path` IS `prefix` or sits strictly beneath it at a '/' boundary.
 * Deliberately NARROWER than stock xrootd's plain string prefix: `/data` does
 * NOT match `/database`.  The narrower direction is the safe one — an operator
 * who wrote `/data` meant the directory — and the difference is documented in
 * the user guide rather than hidden.  A `prefix` of "/" matches every absolute
 * path.  Trailing slashes on `prefix` are ignored.  Both arguments are cleaned
 * LOGICAL paths (traversal already removed), so no `..` can dodge the test.
 */
int brix_tpc_restrict_match(const char *prefix, const char *path);

/*
 * brix_tpc_path_is_oid — 1 if `path` is an XRootD object-id reference, i.e.
 * begins with '*'.  BriX exports no object-id namespace; the predicate exists
 * so `brix_tpc_oids off` (the default) can refuse the SYNTAX explicitly rather
 * than let it fall through to the path resolver as a stray filename.
 */
int brix_tpc_path_is_oid(const char *path);

/*
 * brix_tpc_matrix_evaluate — the whole verdict, in the security order
 * documented at the top of this header.  `path` may be NULL/"" (a leg with no
 * path of its own), in which case the oid and restrict stages are skipped.
 */
brix_tpc_matrix_verdict_t brix_tpc_matrix_evaluate(const brix_tpc_matrix_t *m,
    int party, const brix_tpc_subject_t *subj, const char *path);

/*
 * brix_tpc_matrix_verdict_text — a stable, LOW-CARDINALITY refusal phrase for
 * a verdict.  Never interpolates a DN, VO, host or path: the text reaches the
 * client and the access log, and must never become a metric label
 * (INVARIANT 8).
 */
const char *brix_tpc_matrix_verdict_text(brix_tpc_matrix_verdict_t v);

#ifndef XRDPROTO_NO_NGX
#include <ngx_config.h>
#include <ngx_core.h>

#include "core/types/identity.h"

/*
 * The conf view of the matrix.  The three arrays hold the PURE structs above
 * (brix_tpc_allow_rule_t / brix_tpc_require_rule_t / ngx_str_t), so the ngx
 * layer never re-spells a rule.
 */
typedef struct {
    ngx_array_t *allow;          /* brix_tpc_allow_rule_t[]   (NULL = none) */
    ngx_array_t *require_rules;  /* brix_tpc_require_rule_t[] (NULL = none) */
    ngx_array_t *paths;          /* ngx_str_t[] logical prefixes (NULL = none) */
    ngx_flag_t   oids;
} brix_tpc_matrix_conf_t;

/* Hard cap on `brix_tpc_restrict` prefixes, enforced at nginx -t so the
 * per-request pointer vector is a fixed stack array with no allocation. */
#define BRIX_TPC_RESTRICT_MAX  64

/*
 * brix_tpc_matrix_configured — 1 if the operator wrote ANY allow / require /
 * restrict rule.  `brix_tpc_oids` alone does not count: it is default-deny and
 * always in force.
 */
int brix_tpc_matrix_configured(const brix_tpc_matrix_conf_t *mc);

/*
 * brix_tpc_matrix_needs_hostname — 1 if any rule in `allow` (a
 * brix_tpc_allow_rule_t array, NULL tolerated) names a `host`, so the planes
 * that must WAIT for a PTR answer before deciding know to do so: the root://
 * accept-time wait (protocols/root/connection/peer_name.c) and the HTTP
 * PREACCESS wait (core/http/http_peer_name.c).  Without this a host rule would
 * silently deny every connection whose PTR had not yet landed.
 */
ngx_flag_t brix_tpc_matrix_needs_hostname(ngx_array_t *allow);

/*
 * brix_tpc_matrix_subject_from_identity — fill `out` from an identity plus the
 * already-resolved peer hostname (NULL when unknown).  Every field is a
 * borrowed pointer valid for the connection.
 */
void brix_tpc_matrix_subject_from_identity(const brix_identity_t *id,
    const char *peer_host, brix_tpc_subject_t *out);

/*
 * brix_tpc_matrix_check — the ngx entry point: adapt the conf arrays into a
 * brix_tpc_matrix_t and return brix_tpc_matrix_evaluate()'s verdict.  Pure
 * adaptation, no allocation and no I/O, so it is safe anywhere on the event
 * loop and cannot park.
 */
brix_tpc_matrix_verdict_t brix_tpc_matrix_check(const brix_tpc_matrix_conf_t *mc,
    int party, const brix_tpc_subject_t *subj, const char *path);

/* ---- directive setters (identity_matrix_conf.c) ----
 * One setter per directive for EVERY plane: the shared conf preamble
 * (ngx_http_brix_shared_conf_t) is member 0 of both ngx_stream_brix_srv_conf_t
 * and ngx_http_brix_common_conf_t, so the cast is valid on either. */
char *brix_tpc_conf_allow_identity(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *brix_tpc_conf_require(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_tpc_conf_restrict(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#endif /* !XRDPROTO_NO_NGX */

#endif /* BRIX_TPC_IDENTITY_MATRIX_H */
