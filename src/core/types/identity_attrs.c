#include "identity_internal.h"

#include <string.h>

/*
 * identity_attrs.c — VOMS-FQAN → xrdacc (vorg, role, group) attribute derivation.
 *
 * WHAT: Implements brix_identity_derive_attrs and its two per-field helpers
 *       (brix_identity_trim_ws, brix_identity_parse_fqan).  Given the flat
 *       comma-separated VO/group CSV, it produces the three index-aligned
 *       attribute CSVs (acc_vorg_csv / acc_role_csv / acc_group_csv) the XrdAcc
 *       engine pairs positionally.
 *
 * WHY:  Turning "/cms/Role=production/Capability=NULL" into vorg="cms",
 *       role="production", group="/cms" is the single most intricate piece of
 *       identity building — a self-contained substring parser with no
 *       dependencies on the setters/accessors in identity.c.  Splitting it out
 *       keeps both files focused and under the 500-line file-size cap while
 *       leaving the parsing/attribute semantics untouched in one place.
 *
 * HOW:  brix_identity_derive_attrs owns only tokenisation and index-aligned CSV
 *       assembly; each field is trimmed by brix_identity_trim_ws and decomposed
 *       by brix_identity_parse_fqan.  Every output is a prefix/substring of the
 *       input, so an strlen(vo_csv)-sized buffer always suffices.  identity.c
 *       reaches this via the brix_identity_derive_attrs declaration in
 *       identity_internal.h.
 */

/*
 * WHAT: Strip leading and trailing ASCII spaces/tabs from the [*tok, *tok+*tl)
 *       slice in place, advancing *tok and shrinking *tl to the trimmed span.
 * WHY:  A VOMS FQAN / group CSV field may carry incidental whitespace around
 *       each comma-separated entry; the xrdacc views must store the bare token.
 * HOW:  Advance the start pointer past leading blanks, then pull the length in
 *       past trailing blanks — both guarded by a nonzero remaining length so an
 *       all-blank or empty field collapses to length 0.
 */
static void
brix_identity_trim_ws(const char **tok, size_t *tl)
{
    const char *t = *tok;
    size_t      n = *tl;

    while (n > 0 && (*t == ' ' || *t == '\t')) { t++; n--; }
    while (n > 0 && (t[n - 1] == ' ' || t[n - 1] == '\t')) { n--; }

    *tok = t;
    *tl = n;
}

/*
 * WHAT: Parse one trimmed FQAN/group token [tok, tok+tl) into three substring
 *       spans — group (*grp,*glen), role (*role,*rlen), vorg (*vorg,*vlen) —
 *       each pointing into the original token buffer.
 * WHY:  An FQAN like "/cms/Role=production/Capability=NULL" must decompose into
 *       vorg="cms", role="production", group="/cms"; "Role=NULL" and a plain
 *       group name ("cms") must yield an empty role.  Centralising this keeps
 *       the CSV-assembly loop simple and the field semantics in one place.
 * HOW:  The group defaults to the whole token; a "/Role=" marker truncates the
 *       group there and captures the role up to the next '/' (dropping a literal
 *       "NULL"), else a "/Capability=" marker just truncates the trailing
 *       capability.  The vorg is the group with any leading '/' removed and cut
 *       at its first interior '/'.
 */
static void
brix_identity_parse_fqan(const char *tok, size_t tl,
    const char **grp, size_t *glen,
    const char **role, size_t *rlen,
    const char **vorg, size_t *vlen)
{
    const char *rp, *cp, *vstart, *vend;
    size_t      g = tl, r = 0, v;

    *role = NULL;
    *grp = tok;

    rp = memmem(tok, tl, "/Role=", 6);
    if (rp != NULL) {
        const char *rs = rp + 6, *re;
        g = (size_t) (rp - tok);                    /* group = before /Role= */
        re = memchr(rs, '/', (size_t) ((tok + tl) - rs));
        if (re == NULL) { re = tok + tl; }
        *role = rs;
        r = (size_t) (re - rs);
        if (r == 4 && ngx_strncmp(rs, "NULL", 4) == 0) { r = 0; }
    } else if ((cp = memmem(tok, tl, "/Capability=", 12)) != NULL) {
        g = (size_t) (cp - tok);                    /* strip trailing capability */
    }

    vstart = tok;
    v = g;
    if (v > 0 && *vstart == '/') { vstart++; v--; }
    vend = memchr(vstart, '/', v);
    if (vend != NULL) { v = (size_t) (vend - vstart); }

    *glen = g;
    *rlen = r;
    *vorg = vstart;
    *vlen = v;
}

/*
 * brix_identity_derive_attrs — split each comma-separated VOMS FQAN / token
 * group into (vorg, role, group) and store them as three index-aligned CSVs for
 * the xrdacc engine.  Each output is a prefix/substring of the input, so an
 * strlen(vo_csv)-sized buffer always suffices.  Per-field parsing is delegated
 * to brix_identity_trim_ws + brix_identity_parse_fqan; this function owns only
 * the tokenisation and index-aligned CSV assembly.
 */
ngx_int_t
brix_identity_derive_attrs(brix_identity_t *id, ngx_pool_t *pool,
    const char *vo_csv)
{
    size_t   inlen = (vo_csv != NULL) ? ngx_strlen(vo_csv) : 0;
    u_char  *vb, *rb, *gb;
    size_t   vl = 0, rl = 0, gl = 0;
    const char *p, *toks;
    int      first = 1;

    ngx_str_null(&id->acc_vorg_csv);
    ngx_str_null(&id->acc_role_csv);
    ngx_str_null(&id->acc_group_csv);
    if (inlen == 0) {
        return NGX_OK;
    }

    vb = ngx_pnalloc(pool, inlen + 1);
    rb = ngx_pnalloc(pool, inlen + 1);
    gb = ngx_pnalloc(pool, inlen + 1);
    if (vb == NULL || rb == NULL || gb == NULL) {
        return NGX_ERROR;
    }

    p = toks = vo_csv;
    for (;;) {
        if (*p == ',' || *p == '\0') {
            const char *tok = toks, *grp, *role, *vorg;
            size_t      tl = (size_t) (p - toks), glen, rlen, vlen;

            brix_identity_trim_ws(&tok, &tl);
            brix_identity_parse_fqan(tok, tl, &grp, &glen, &role, &rlen,
                                     &vorg, &vlen);

            if (!first) { vb[vl++] = ','; rb[rl++] = ','; gb[gl++] = ','; }
            first = 0;
            if (vlen) { ngx_memcpy(vb + vl, vorg, vlen); vl += vlen; }
            if (rlen) { ngx_memcpy(rb + rl, role, rlen); rl += rlen; }
            if (glen) { ngx_memcpy(gb + gl, grp, glen);  gl += glen; }

            if (*p == '\0') { break; }
            toks = p + 1;
        }
        p++;
    }
    vb[vl] = '\0'; rb[rl] = '\0'; gb[gl] = '\0';
    id->acc_vorg_csv.data  = vb; id->acc_vorg_csv.len  = vl;
    id->acc_role_csv.data  = rb; id->acc_role_csv.len  = rl;
    id->acc_group_csv.data = gb; id->acc_group_csv.len = gl;
    return NGX_OK;
}
