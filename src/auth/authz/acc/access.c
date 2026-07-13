/*
 * access.c — the authorization decision engine (XrdAccAccess::Access).
 *
 * WHAT: brix_acc_access() computes the privileges an entity holds for a path
 *   and tests them against the requested operation.  It walks the identity
 *   tables in XRootD's exact precedence order, OR-ing every matching rule's
 *   positive and negative privileges, then grants iff (pprivs & ~nprivs)
 *   satisfies the operation.
 *
 * WHY: faithful port of XrdAccAccess::Access()/Access2()/Applies().  The order
 *   and the additive accumulation are the defining XrdAcc semantics: an exclusive
 *   (`x`) rule short-circuits to a single decision, otherwise privileges add up
 *   across default, domain, host, netgroup, fungible, user, group, org, role and
 *   inclusive-rule matches.
 *
 * HOW: exclusive list first (first applicable rule wins) → default (`u *`) →
 *   host domain → host exact → netgroups → fungible (`u =`) → user → then, per
 *   attribute tuple, group/org/role/inclusive rules; finally pprivs & ~nprivs and
 *   the operation test (privs.c).  Auditing is layered on in M5.
 */

#include "acc.h"

/* OS/NIS group hooks — installed by groups.c (M4); NULL = OS layer absent. */
static brix_acc_unixgrp_fn  acc_unixgrp_resolver = NULL;
static brix_acc_netgrp_fn   acc_netgrp_member    = NULL;

void
brix_acc_set_group_resolvers(brix_acc_unixgrp_fn ug, brix_acc_netgrp_fn ng)
{
    acc_unixgrp_resolver = ug;
    acc_netgrp_member    = ng;
}

/*
 * acc_sel_ctx_t — the inputs a single selector predicate tests: the rule whose
 * selectors are being checked, plus the request identity (one attribute tuple,
 * scalar user name, scalar host).  Bundled so every predicate shares one
 * signature and the predicate table below can be uniform.
 */
typedef struct {
    const brix_acc_idrule_t  *rule;
    const brix_acc_attr_t    *attr;
    const char               *name;
    const char               *host;
} acc_sel_ctx_t;

/*
 * WHAT: predicate — the rule's `o` (org) selector is satisfied by this tuple.
 * WHY: an unset selector is unconstrained (always satisfied); a set selector
 *   requires the tuple to carry that exact org.
 * HOW: NULL selector ⇒ pass; else the tuple must have a vorg equal to it.
 */
static int
acc_sel_org(const acc_sel_ctx_t *s)
{
    return s->rule->org == NULL
        || (s->attr->vorg != NULL && ngx_strcmp(s->rule->org, s->attr->vorg) == 0);
}

/*
 * WHAT: predicate — the rule's `r` (role) selector is satisfied by this tuple.
 * WHY/HOW: as acc_sel_org, over the tuple's role.
 */
static int
acc_sel_role(const acc_sel_ctx_t *s)
{
    return s->rule->role == NULL
        || (s->attr->role != NULL && ngx_strcmp(s->rule->role, s->attr->role) == 0);
}

/*
 * WHAT: predicate — the rule's `g` (group) selector is satisfied by this tuple.
 * WHY/HOW: as acc_sel_org, over the tuple's group.
 */
static int
acc_sel_group(const acc_sel_ctx_t *s)
{
    return s->rule->grp == NULL
        || (s->attr->grup != NULL && ngx_strcmp(s->rule->grp, s->attr->grup) == 0);
}

/*
 * WHAT: predicate — the rule's user selector is satisfied by this identity.
 * WHY/HOW: as acc_sel_org, over the entity's scalar user name.
 */
static int
acc_sel_user(const acc_sel_ctx_t *s)
{
    return s->rule->user == NULL
        || (s->name != NULL && ngx_strcmp(s->rule->user, s->name) == 0);
}

/*
 * WHAT: predicate — the rule's host selector is satisfied by this identity.
 * WHY: a host beginning with '.' is a domain suffix that must match the tail of
 *   the entity host (and be strictly shorter than it); otherwise it is an exact
 *   host name.  A NULL selector is unconstrained.
 * HOW: NULL ⇒ pass; suffix form ⇒ compare against host tail of length hlen (host
 *   must be longer than the suffix); exact form ⇒ full-string compare.
 */
static int
acc_sel_host(const acc_sel_ctx_t *s)
{
    const char *hn;

    if (s->rule->host == NULL) {
        return 1;
    }
    if (s->rule->host[0] == '.') {
        int elen = (s->host != NULL) ? (int) ngx_strlen(s->host) : 0;
        if (elen <= s->rule->hlen) {
            return 0;
        }
        hn = s->host + (elen - s->rule->hlen);
    } else {
        hn = s->host;
    }
    return hn != NULL && ngx_strcmp(s->rule->host, hn) == 0;
}

/*
 * acc_sel_predicates — the selector-predicate table.  A compound rule matches
 * iff every predicate passes (logical AND); ordering is immaterial to the
 * result and mirrors XrdAccAccess_ID::Applies()'s selector set.
 */
typedef int (*acc_sel_fn)(const acc_sel_ctx_t *s);

static const acc_sel_fn  acc_sel_predicates[] = {
    acc_sel_org,
    acc_sel_role,
    acc_sel_group,
    acc_sel_user,
    acc_sel_host,
};

/*
 * WHAT: acc_applies — does a compound rule's selector set match this (attr,
 *   name, host)?
 * WHY: faithful port of XrdAccAccess_ID::Applies(); a rule applies only when all
 *   of its selectors are satisfied.
 * HOW: run every predicate in acc_sel_predicates; short-circuit to 0 on the
 *   first failure, else 1.
 */
static int
acc_applies(const brix_acc_idrule_t *r, const brix_acc_attr_t *attr,
            const char *name, const char *host)
{
    acc_sel_ctx_t  s = { r, attr, name, host };
    ngx_uint_t     k;

    for (k = 0; k < sizeof(acc_sel_predicates) / sizeof(acc_sel_predicates[0]); k++) {
        if (!acc_sel_predicates[k](&s)) {
            return 0;
        }
    }
    return 1;
}

/* Final composite + operation test (XrdAccAccess::Access2). */
static brix_acc_privs_t
acc_access2(const brix_acc_priv_caps_t *caps, brix_acc_op_t op)
{
    brix_acc_privs_t  eff = (brix_acc_privs_t) (caps->pprivs & ~caps->nprivs);

    if (op == BRIX_AOP_ANY) {
        return eff;
    }
    return brix_acc_test(eff, op) ? eff : BRIX_ACC_PRIV_NONE;
}

/*
 * acc_eval_t — the shared, read-mostly state threaded through the grant phases
 * of one brix_acc_access() call: the table set, the request identity (with its
 * pre-fetched tuple array), the path and its length, and the accumulating
 * privilege caps.  Bundled so each grant helper takes one context pointer rather
 * than a six-parameter list.
 */
typedef struct {
    brix_acc_tables_t        *tabs;
    const brix_acc_entity_t  *ent;
    const brix_acc_attr_t    *tuples;
    const char               *path;
    int                       plen;
    brix_acc_priv_caps_t     *caps;
} acc_eval_t;

/*
 * WHAT: acc_match_exclusive — apply the exclusive-rule list (`x`), whose first
 *   applicable rule is the sole decision.
 * WHY: XrdAcc semantics: an exclusive match short-circuits the whole engine to a
 *   single rule's privileges (no additive accumulation).
 * HOW: walk sx_list in order; for the first rule that applies to any of the
 *   entity's tuples, fold its caps into e->caps and return 1.  Return 0 if none
 *   apply (caps is left untouched, the caller falls through to the additive
 *   pipeline).
 */
static int
acc_match_exclusive(const acc_eval_t *e)
{
    brix_acc_idrule_t  *r;
    ngx_uint_t          i;

    for (r = e->tabs->sx_list; r != NULL; r = r->next) {
        for (i = 0; i < e->ent->tuples->nelts; i++) {
            if (acc_applies(r, &e->tuples[i], e->ent->name, e->ent->host)) {
                brix_acc_cap_privs(r->caps, e->caps, e->path, e->plen, NULL);
                return 1;
            }
        }
    }
    return 0;
}

/*
 * WHAT: acc_grant_host — fold the host-scoped grants (default, domain, exact
 *   host, netgroups) into e->caps.
 * WHY: steps (2)–(5) of XrdAccAccess::Access() — host/site identity, independent
 *   of whether the entity is a real user.
 * HOW: default (`u *`), domain (`h .suffix`), exact host (`h <name>`), then each
 *   netgroup record whose (user, host) membership resolves — in that order.
 */
static void
acc_grant_host(const acc_eval_t *e)
{
    brix_acc_tables_t       *tabs = e->tabs;
    const brix_acc_entity_t *ent  = e->ent;
    brix_acc_cap_t          *cp;
    brix_acc_named_t        *nn;

    if (tabs->z_list) {                                     /* (2) default */
        brix_acc_cap_privs(tabs->z_list, e->caps, e->path, e->plen, NULL);
    }
    if ((cp = brix_acc_domain_find(tabs->d_list, ent->host))) {   /* (3) domain */
        brix_acc_cap_privs(cp, e->caps, e->path, e->plen, NULL);
    }
    if ((cp = brix_acc_named_find(tabs->h_list, ent->host))) {    /* (4) exact host */
        brix_acc_cap_privs(cp, e->caps, e->path, e->plen, NULL);
    }
    if (tabs->n_list && acc_netgrp_member != NULL               /* (5) netgroups */
        && ent->host && ent->host[0] != '?')
    {
        for (nn = tabs->n_list; nn != NULL; nn = nn->next) {
            if (acc_netgrp_member(nn->name, ent->name, ent->host)) {
                brix_acc_cap_privs(nn->caps, e->caps, e->path, e->plen, NULL);
            }
        }
    }
}

/*
 * WHAT: acc_grant_user — fold the user-scoped grants (OS gidlist, fungible user,
 *   specific user) into e->caps.
 * WHY: steps (5b)–(7) of XrdAccAccess::Access() — grants keyed on the entity
 *   being a real, named user.
 * HOW: expand the user's OS group list against `g` records, then the fungible
 *   user (`u =`, with @= substitution), then the specific user (`u <name>`).
 *   No-op when the entity is not a user.
 */
static void
acc_grant_user(const acc_eval_t *e)
{
    brix_acc_tables_t       *tabs = e->tabs;
    const brix_acc_entity_t *ent  = e->ent;
    brix_acc_cap_t          *cp;
    ngx_array_t             *ugs;
    ngx_uint_t               i;

    if (!ent->isuser) {
        return;
    }
    if (tabs->g_list && acc_unixgrp_resolver != NULL       /* (5b) OS gidlist */
        && (ugs = acc_unixgrp_resolver(ent->pool, ent->name)) != NULL)
    {
        char **gn = ugs->elts;
        for (i = 0; i < ugs->nelts; i++) {
            if ((cp = brix_acc_named_find(tabs->g_list, gn[i]))) {
                brix_acc_cap_privs(cp, e->caps, e->path, e->plen, NULL);
            }
        }
    }
    if (tabs->x_list) {                                     /* (6) fungible user */
        brix_acc_cap_privs(tabs->x_list, e->caps, e->path, e->plen, ent->name);
    }
    if ((cp = brix_acc_named_find(tabs->u_list, ent->name))) {   /* (7) specific user */
        brix_acc_cap_privs(cp, e->caps, e->path, e->plen, NULL);
    }
}

/*
 * WHAT: acc_grant_tuples — fold the per-attribute-tuple grants (group, org,
 *   role, inclusive rules) into e->caps.
 * WHY: step (8) of XrdAccAccess::Access() — the attribute-driven grants, one
 *   pass per (group, org, role) tuple the entity presents.
 * HOW: for each tuple add its `g`/`o`/`r` record (org and role deduped against
 *   the previous tuple to mirror the reference), then every inclusive rule
 *   (`s`) that applies.
 */
static void
acc_grant_tuples(const acc_eval_t *e)
{
    brix_acc_tables_t  *tabs = e->tabs;
    const char         *vorg_prev = NULL, *role_prev = NULL;
    brix_acc_cap_t     *cp;
    brix_acc_idrule_t  *r;
    ngx_uint_t          i;

    for (i = 0; i < e->ent->tuples->nelts; i++) {
        const brix_acc_attr_t *a = &e->tuples[i];

        if (a->grup && (cp = brix_acc_named_find(tabs->g_list, a->grup))) {
            brix_acc_cap_privs(cp, e->caps, e->path, e->plen, NULL);
        }
        if (a->vorg && a->vorg != vorg_prev) {
            vorg_prev = a->vorg;
            if ((cp = brix_acc_named_find(tabs->o_list, a->vorg))) {
                brix_acc_cap_privs(cp, e->caps, e->path, e->plen, NULL);
            }
        }
        if (a->role && a->role != role_prev) {
            role_prev = a->role;
            if ((cp = brix_acc_named_find(tabs->r_list, a->role))) {
                brix_acc_cap_privs(cp, e->caps, e->path, e->plen, NULL);
            }
        }
        for (r = tabs->sy_list; r != NULL; r = r->next) {
            if (acc_applies(r, a, e->ent->name, e->ent->host)) {
                brix_acc_cap_privs(r->caps, e->caps, e->path, e->plen, NULL);
            }
        }
    }
}

/*
 * WHAT: brix_acc_access — compute the entity's effective privileges for a path
 *   and test them against the requested operation.
 * WHY: faithful port of XrdAccAccess::Access(); default-deny — an unknown or
 *   empty identity yields no privileges.
 * HOW: exclusive rules first (first match is the whole answer), else fold the
 *   host, user and per-tuple grants additively into caps and return the
 *   composite-then-operation verdict (acc_access2).  Behaviour is unchanged; the
 *   phases are just factored into named helpers.
 */
brix_acc_privs_t
brix_acc_access(brix_acc_tables_t *tabs, const brix_acc_entity_t *ent,
                  const char *path, brix_acc_op_t op)
{
    brix_acc_priv_caps_t   caps = { BRIX_ACC_PRIV_NONE, BRIX_ACC_PRIV_NONE };
    acc_eval_t             e;

    if (tabs == NULL || ent == NULL) {
        return BRIX_ACC_PRIV_NONE;
    }

    e.tabs   = tabs;
    e.ent    = ent;
    e.tuples = ent->tuples->elts;
    e.path   = path;
    e.plen   = (int) ngx_strlen(path);
    e.caps   = &caps;

    if (acc_match_exclusive(&e)) {
        return acc_access2(&caps, op);
    }

    acc_grant_host(&e);
    acc_grant_user(&e);
    acc_grant_tuples(&e);

    return acc_access2(&caps, op);
}
