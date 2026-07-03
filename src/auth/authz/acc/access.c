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
 * acc_applies — does a compound rule's selector set match this (attr, name,
 * host)?  A NULL selector is unconstrained.  Host beginning with '.' is a domain
 * suffix.  Ports XrdAccAccess_ID::Applies().
 */
static int
acc_applies(const brix_acc_idrule_t *r, const brix_acc_attr_t *attr,
            const char *name, const char *host)
{
    if (r->org  && (attr->vorg == NULL || ngx_strcmp(r->org,  attr->vorg))) {
        return 0;
    }
    if (r->role && (attr->role == NULL || ngx_strcmp(r->role, attr->role))) {
        return 0;
    }
    if (r->grp  && (attr->grup == NULL || ngx_strcmp(r->grp,  attr->grup))) {
        return 0;
    }
    if (r->user && (name == NULL || ngx_strcmp(r->user, name))) {
        return 0;
    }
    if (r->host) {
        const char *hn;
        if (r->host[0] == '.') {
            int elen = (host != NULL) ? (int) ngx_strlen(host) : 0;
            if (elen <= r->hlen) {
                return 0;
            }
            hn = host + (elen - r->hlen);
        } else {
            hn = host;
        }
        if (hn == NULL || ngx_strcmp(r->host, hn)) {
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

brix_acc_privs_t
brix_acc_access(brix_acc_tables_t *tabs, const brix_acc_entity_t *ent,
                  const char *path, brix_acc_op_t op)
{
    brix_acc_priv_caps_t  caps = { BRIX_ACC_PRIV_NONE, BRIX_ACC_PRIV_NONE };
    brix_acc_cap_t       *cp;
    int                     plen = (int) ngx_strlen(path);
    const char             *vorg_prev = NULL, *role_prev = NULL;
    ngx_uint_t              i;
    brix_acc_attr_t      *tuples;

    if (tabs == NULL || ent == NULL) {
        return BRIX_ACC_PRIV_NONE;
    }
    tuples = ent->tuples->elts;

    /* (1) Exclusive rules — only the first applicable rule applies. */
    {
        brix_acc_idrule_t *r;
        for (r = tabs->sx_list; r != NULL; r = r->next) {
            for (i = 0; i < ent->tuples->nelts; i++) {
                if (acc_applies(r, &tuples[i], ent->name, ent->host)) {
                    brix_acc_cap_privs(r->caps, &caps, path, plen, NULL);
                    return acc_access2(&caps, op);
                }
            }
        }
    }

    /* (2) Default privileges (u *). */
    if (tabs->z_list) {
        brix_acc_cap_privs(tabs->z_list, &caps, path, plen, NULL);
    }

    /* (3) Host domain (h .suffix). */
    if ((cp = brix_acc_domain_find(tabs->d_list, ent->host))) {
        brix_acc_cap_privs(cp, &caps, path, plen, NULL);
    }

    /* (4) Host exact (h <name>). */
    if ((cp = brix_acc_named_find(tabs->h_list, ent->host))) {
        brix_acc_cap_privs(cp, &caps, path, plen, NULL);
    }

    /* (5) Netgroups (n) — probe each record for (user, host) membership. */
    if (tabs->n_list && acc_netgrp_member != NULL
        && ent->host && ent->host[0] != '?')
    {
        brix_acc_named_t *nn;
        for (nn = tabs->n_list; nn != NULL; nn = nn->next) {
            if (acc_netgrp_member(nn->name, ent->name, ent->host)) {
                brix_acc_cap_privs(nn->caps, &caps, path, plen, NULL);
            }
        }
    }

    /* (5b) Unix groups — expand the user's OS gidlist and match `g` records,
     * in addition to the entity's own supplied groups handled in step (8). */
    if (ent->isuser && tabs->g_list && acc_unixgrp_resolver != NULL) {
        ngx_array_t *ugs = acc_unixgrp_resolver(ent->pool, ent->name);
        if (ugs != NULL) {
            char **gn = ugs->elts;
            for (i = 0; i < ugs->nelts; i++) {
                if ((cp = brix_acc_named_find(tabs->g_list, gn[i]))) {
                    brix_acc_cap_privs(cp, &caps, path, plen, NULL);
                }
            }
        }
    }

    /* (6) Fungible user (u =), with the user name substituted into @=. */
    if (ent->isuser && tabs->x_list) {
        brix_acc_cap_privs(tabs->x_list, &caps, path, plen, ent->name);
    }

    /* (7) Specific user (u <name>). */
    if (ent->isuser && (cp = brix_acc_named_find(tabs->u_list, ent->name))) {
        brix_acc_cap_privs(cp, &caps, path, plen, NULL);
    }

    /* (8) Per attribute tuple: group, org, role, then inclusive rules. */
    for (i = 0; i < ent->tuples->nelts; i++) {
        brix_acc_attr_t   *a = &tuples[i];
        brix_acc_idrule_t *r;

        if (a->grup && (cp = brix_acc_named_find(tabs->g_list, a->grup))) {
            brix_acc_cap_privs(cp, &caps, path, plen, NULL);
        }
        if (a->vorg && a->vorg != vorg_prev) {
            vorg_prev = a->vorg;
            if ((cp = brix_acc_named_find(tabs->o_list, a->vorg))) {
                brix_acc_cap_privs(cp, &caps, path, plen, NULL);
            }
        }
        if (a->role && a->role != role_prev) {
            role_prev = a->role;
            if ((cp = brix_acc_named_find(tabs->r_list, a->role))) {
                brix_acc_cap_privs(cp, &caps, path, plen, NULL);
            }
        }
        for (r = tabs->sy_list; r != NULL; r = r->next) {
            if (acc_applies(r, a, ent->name, ent->host)) {
                brix_acc_cap_privs(r->caps, &caps, path, plen, NULL);
            }
        }
    }

    return acc_access2(&caps, op);
}
