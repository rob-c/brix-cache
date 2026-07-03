/*
 * entity.c — expand an authenticated identity into attribute tuples.
 *
 * WHAT: brix_acc_entity_build() turns scalar name/host plus the comma-separated
 *   VO/role/group lists into an brix_acc_entity_t whose `tuples` array holds
 *   one (vorg, role, grup) combination per index — the form the access engine
 *   iterates (XrdAccEntity / XrdAccEntityInfo).
 *
 * WHY: VOMS / token identities carry parallel multi-valued attributes (e.g. two
 *   FQANs each with its own VO+role).  XrdAcc pairs them POSITIONALLY — the i-th
 *   VO with the i-th role and i-th group — not as a cartesian product, so a
 *   `cms`/`production` credential does not accidentally gain `atlas`/`production`.
 *
 * HOW: split each list on commas, then build N = max(list lengths) tuples; a
 *   singleton list broadcasts to every tuple, a longer list contributes element
 *   i (or NULL past its end).  At least one tuple is always produced so that
 *   user/host-only rules still evaluate for attribute-less identities.
 */

#include "acc.h"
#include "core/compat/alloc_guard.h"

/*
 * Split a comma-separated string into an array of tokens (pool-owned).  Empty
 * fields are preserved as NULL entries so that parallel attribute lists (VO,
 * role, group derived from the same FQANs) stay index-aligned for the positional
 * tuple build.  Empty/NULL input yields an empty array.
 */
static ngx_array_t *
acc_split_csv(ngx_pool_t *pool, const char *csv)
{
    ngx_array_t *out = ngx_array_create(pool, 4, sizeof(char *));
    const char  *p, *start;

    if (out == NULL) {
        return NULL;
    }
    if (csv == NULL || *csv == '\0') {
        return out;
    }

    p = start = csv;
    for (;;) {
        if (*p == ',' || *p == '\0') {
            const char *s = start;
            size_t      len = (size_t) (p - start);
            char      **slot;
            /* trim surrounding spaces */
            while (len > 0 && (*s == ' ' || *s == '\t')) { s++; len--; }
            while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) { len--; }

            slot = ngx_array_push(out);
            if (slot == NULL) {
                return NULL;
            }
            if (len == 0) {
                *slot = NULL;                 /* empty field -> absent attribute */
            } else {
                char *tok = ngx_pnalloc(pool, len + 1);
                if (tok == NULL) {
                    return NULL;
                }
                ngx_memcpy(tok, s, len);
                tok[len] = '\0';
                *slot = tok;
            }
            if (*p == '\0') {
                break;
            }
            start = p + 1;
        }
        p++;
    }
    return out;
}

/* Positional pick: element i, broadcasting a singleton, NULL past the end. */
static const char *
acc_pick(ngx_array_t *a, ngx_uint_t i)
{
    char **e;

    if (a == NULL || a->nelts == 0) {
        return NULL;
    }
    e = a->elts;
    if (a->nelts == 1) {
        return e[0];
    }
    return (i < a->nelts) ? e[i] : NULL;
}

brix_acc_entity_t *
brix_acc_entity_build(ngx_pool_t *pool, const char *name, const char *host,
                        int isuser, const char *vorg_csv, const char *role_csv,
                        const char *grp_csv)
{
    brix_acc_entity_t *ent;
    ngx_array_t         *vorgs, *roles, *grps;
    ngx_uint_t           n, i;

    BRIX_PCALLOC_OR_RETURN(ent, pool, sizeof(*ent), NULL);
    ent->pool   = pool;
    ent->name   = (name != NULL && *name != '\0') ? name : "*";
    ent->host   = (host != NULL && *host != '\0') ? host : "?";
    ent->isuser = isuser && name != NULL && *name != '\0';

    vorgs = acc_split_csv(pool, vorg_csv);
    roles = acc_split_csv(pool, role_csv);
    grps  = acc_split_csv(pool, grp_csv);
    if (vorgs == NULL || roles == NULL || grps == NULL) {
        return NULL;
    }

    n = vorgs->nelts;
    if (roles->nelts > n) { n = roles->nelts; }
    if (grps->nelts  > n) { n = grps->nelts;  }
    if (n == 0) { n = 1; }   /* always at least one (possibly empty) tuple */

    ent->tuples = ngx_array_create(pool, n, sizeof(brix_acc_attr_t));
    if (ent->tuples == NULL) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        brix_acc_attr_t *a = ngx_array_push(ent->tuples);
        if (a == NULL) {
            return NULL;
        }
        a->vorg = acc_pick(vorgs, i);
        a->role = acc_pick(roles, i);
        a->grup = acc_pick(grps, i);
    }

    return ent;
}
