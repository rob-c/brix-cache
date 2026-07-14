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

/* ---- Trim leading/trailing ASCII blanks from a [s, s+len) slice ----
 *
 * WHAT: advances *s and shrinks *len so the slice excludes surrounding spaces
 *   and tabs; a slice that is all blanks collapses to length 0.
 *
 * WHY: CSV fields may carry decorative whitespace ("cms, atlas"); the access
 *   engine compares attribute strings byte-for-byte, so blanks must be stripped
 *   before a token is stored or a field is judged empty.  Kept separate so the
 *   trim rule lives in one place and the emit helper stays flat.
 *
 * HOW: (1) skip leading blanks by advancing *s / decrementing *len; (2) drop
 *   trailing blanks by decrementing *len while the last byte is blank.
 */
static void
acc_csv_trim(const char **s, size_t *len)
{
    const char *b = *s;
    size_t      n = *len;

    while (n > 0 && (*b == ' ' || *b == '\t')) { b++; n--; }
    while (n > 0 && (b[n - 1] == ' ' || b[n - 1] == '\t')) { n--; }

    *s   = b;
    *len = n;
}

/* ---- Trim then push one CSV field onto the token array ----
 *
 * WHAT: trims the [field, field+len) slice and appends one element to `out` —
 *   NULL for an empty field, otherwise a NUL-terminated pool copy of the token.
 *   Returns NGX_OK on success or NGX_ERROR if any pool allocation fails.
 *
 * WHY: empty fields MUST be preserved as NULL entries so parallel attribute
 *   lists (VO, role, group from the same FQANs) stay index-aligned for the
 *   positional tuple build — an absent attribute is not the same as a shifted
 *   one, and dropping it would mis-pair credentials in the access decision.
 *
 * HOW: (1) trim the slice; (2) push a slot; (3) empty -> store NULL; else copy
 *   len bytes plus a terminator into pool memory and store the pointer.
 */
static ngx_int_t
acc_csv_push_field(ngx_pool_t *pool, ngx_array_t *out,
                   const char *field, size_t len)
{
    const char *s = field;
    char      **slot;
    char       *tok;

    acc_csv_trim(&s, &len);

    slot = ngx_array_push(out);
    if (slot == NULL) {
        return NGX_ERROR;
    }
    if (len == 0) {
        *slot = NULL;                 /* empty field -> absent attribute */
        return NGX_OK;
    }

    tok = ngx_pnalloc(pool, len + 1);
    if (tok == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(tok, s, len);
    tok[len] = '\0';
    *slot = tok;
    return NGX_OK;
}

/* ---- Split a comma-separated string into a pool-owned token array ----
 *
 * WHAT: returns an ngx_array_t of char* (one element per comma-separated field,
 *   empty fields kept as NULL), or NULL on allocation failure.  Empty/NULL
 *   input yields an empty (zero-element) array.
 *
 * WHY: VOMS / token identities carry comma-joined multi-valued attributes; the
 *   positional tuple build needs them as index-aligned arrays, empties included.
 *
 * HOW: (1) create the array; (2) short-circuit empty input; (3) scan for each
 *   ',' or the terminating NUL, delegating each [start, p) slice to
 *   acc_csv_push_field; (4) stop after the field ending at the NUL.
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
            if (acc_csv_push_field(pool, out, start,
                                   (size_t) (p - start)) != NGX_OK) {
                return NULL;
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

/* ---- Populate an entity's scalar identity fields ----
 *
 * WHAT: sets ent->pool/name/host/isuser from the raw name/host/isuser inputs,
 *   substituting the wildcard sentinels the access engine expects when a scalar
 *   is absent: name -> "*", host -> "?".
 *
 * WHY: the access rules match "*"/"?" as any-name/any-host; an empty or NULL
 *   scalar MUST become that sentinel, and isuser is only honoured when a real
 *   name is present so an anonymous identity never claims user-tier access.
 *   Preserving these mappings verbatim keeps the grant/deny decision unchanged.
 *
 * HOW: (1) record the pool; (2) name/host each fall back to their sentinel when
 *   NULL or empty; (3) isuser is true only if requested AND name is non-empty.
 */
static void
acc_entity_init_scalars(brix_acc_entity_t *ent, ngx_pool_t *pool,
                        const char *name, const char *host, int isuser)
{
    ent->pool   = pool;
    ent->name   = (name != NULL && *name != '\0') ? name : "*";
    ent->host   = (host != NULL && *host != '\0') ? host : "?";
    ent->isuser = isuser && name != NULL && *name != '\0';
}

/* ---- Number of positional tuples the attribute lists require ----
 *
 * WHAT: returns max(vorgs->nelts, roles->nelts, grps->nelts), clamped to a
 *   minimum of 1.
 *
 * WHY: XrdAcc pairs attributes POSITIONALLY, so the tuple count is the longest
 *   list length; at least one tuple is always produced so that user/host-only
 *   rules still evaluate for attribute-less identities.
 *
 * HOW: (1) start from the VO count; (2) raise to the role then group count if
 *   larger; (3) floor the result at 1.
 */
static ngx_uint_t
acc_entity_tuple_count(ngx_array_t *vorgs, ngx_array_t *roles,
                       ngx_array_t *grps)
{
    ngx_uint_t n = vorgs->nelts;

    if (roles->nelts > n) { n = roles->nelts; }
    if (grps->nelts  > n) { n = grps->nelts;  }
    if (n == 0) { n = 1; }   /* always at least one (possibly empty) tuple */
    return n;
}

/* ---- Build the entity's positional (vorg, role, grup) tuple array ----
 *
 * WHAT: creates ent->tuples with n entries, filling tuple i by positionally
 *   picking element i of each attribute list (singleton broadcast, NULL past
 *   the end).  Returns NGX_OK on success or NGX_ERROR on allocation failure.
 *
 * WHY: this positional pairing is the security-load-bearing step — the i-th VO
 *   is bound to the i-th role and i-th group so a `cms`/`production` credential
 *   cannot gain `atlas`/`production`.  acc_pick is applied to each list
 *   independently and unchanged to preserve that exact pairing.
 *
 * HOW: (1) create the n-slot array; (2) for each i push a tuple and set its
 *   vorg/role/grup via acc_pick(list, i).
 */
static ngx_int_t
acc_entity_fill_tuples(ngx_pool_t *pool, brix_acc_entity_t *ent,
                       ngx_array_t *vorgs, ngx_array_t *roles,
                       ngx_array_t *grps, ngx_uint_t n)
{
    ngx_uint_t i;

    ent->tuples = ngx_array_create(pool, n, sizeof(brix_acc_attr_t));
    if (ent->tuples == NULL) {
        return NGX_ERROR;
    }
    for (i = 0; i < n; i++) {
        brix_acc_attr_t *a = ngx_array_push(ent->tuples);
        if (a == NULL) {
            return NGX_ERROR;
        }
        a->vorg = acc_pick(vorgs, i);
        a->role = acc_pick(roles, i);
        a->grup = acc_pick(grps, i);
    }
    return NGX_OK;
}

brix_acc_entity_t *
brix_acc_entity_build(ngx_pool_t *pool, const char *name, const char *host,
                        int isuser, const char *vorg_csv, const char *role_csv,
                        const char *grp_csv)
{
    brix_acc_entity_t *ent;
    ngx_array_t         *vorgs, *roles, *grps;
    ngx_uint_t           n;

    BRIX_PCALLOC_OR_RETURN(ent, pool, sizeof(*ent), NULL);
    acc_entity_init_scalars(ent, pool, name, host, isuser);

    vorgs = acc_split_csv(pool, vorg_csv);
    roles = acc_split_csv(pool, role_csv);
    grps  = acc_split_csv(pool, grp_csv);
    if (vorgs == NULL || roles == NULL || grps == NULL) {
        return NULL;
    }

    n = acc_entity_tuple_count(vorgs, roles, grps);

    if (acc_entity_fill_tuples(pool, ent, vorgs, roles, grps, n) != NGX_OK) {
        return NULL;
    }

    return ent;
}
