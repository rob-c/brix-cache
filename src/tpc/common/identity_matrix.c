/*
 * identity_matrix.c — the TPC identity matrix (2.0 F18).
 *
 * See identity_matrix.h for the rationale and the evaluation order.  The pure
 * half below carries no nginx dependency and is proven branch-by-branch by
 * identity_matrix_unittest.c; the ngx half (behind XRDPROTO_NO_NGX) only
 * adapts conf arrays and an identity into the pure call.
 */
#include "identity_matrix.h"

#include <string.h>
#include <strings.h>   /* strcasecmp — pure, ngx-free */

#include "egress_guard.h"   /* brix_tpc_host_pattern_match: ONE host spelling */

/* NULL-tolerant view of a borrowed field: every rule and subject slot is
 * optional, and an absent one must read as "" so it fails to match rather than
 * faulting.  Used by every predicate below. */
static const char *
tpc_str(const char *s)
{
    return s != NULL ? s : "";
}


/* ---- CSV membership ----
 *
 * WHAT: exact, whitespace-trimmed membership of `name` in a comma-separated
 *   list, case-sensitive.
 *
 * WHY: `allow vo` and `allow group` select ONE name out of the identity's
 *   VO/group CSV views.  A substring or prefix test here would let "cms" match
 *   "cmsuser" and silently widen the rule, so the element boundaries are
 *   honoured explicitly.
 *
 * HOW: walk the CSV element by element, trim each end, compare the exact span.
 */
int
brix_tpc_csv_member(const char *csv, const char *name)
{
    const char *p;
    size_t      nlen;

    csv = tpc_str(csv);
    name = tpc_str(name);
    nlen = strlen(name);

    if (nlen == 0 || csv[0] == '\0') {
        return 0;
    }

    for (p = csv; *p != '\0'; ) {
        const char *end = strchr(p, ',');
        const char *stop = (end != NULL) ? end : p + strlen(p);
        const char *lo = p;

        while (lo < stop && (*lo == ' ' || *lo == '\t')) {
            lo++;
        }
        while (stop > lo && (stop[-1] == ' ' || stop[-1] == '\t')) {
            stop--;
        }
        if ((size_t) (stop - lo) == nlen && memcmp(lo, name, nlen) == 0) {
            return 1;
        }
        if (end == NULL) {
            break;
        }
        p = end + 1;
    }
    return 0;
}


/* Case-insensitive equality of two auth-method labels; empty never matches. */
int
brix_tpc_auth_name_eq(const char *a, const char *b)
{
    a = tpc_str(a);
    b = tpc_str(b);
    if (a[0] == '\0' || b[0] == '\0') {
        return 0;
    }
    return strcasecmp(a, b) == 0 ? 1 : 0;
}


/* One field of an allow rule: unset (NULL/"") is "no constraint" and yields 1
 * so the AND below is unaffected; set means the supplied predicate decides. */
static int
tpc_field_ok(const char *rule_field, int matched)
{
    return (tpc_str(rule_field)[0] == '\0') ? 1 : matched;
}


/* ---- one allow rule ----
 *
 * WHAT: AND over the fields the rule actually sets; a rule that sets none
 *   matches nothing.
 *
 * WHY: stock `ofs.tpc allow [dn ..] [group ..] [host ..] [vo ..]` is a
 *   conjunction, and OR comes from writing more lines.  The empty-rule case is
 *   unreachable from the grammar but is spelled out anyway so a future caller
 *   that builds rules programmatically cannot get a match-everything rule for
 *   free.
 *
 * HOW: four tpc_field_ok() guards, then the "did it constrain anything" test.
 */
int
brix_tpc_allow_rule_match(const brix_tpc_allow_rule_t *rule,
    const brix_tpc_subject_t *subj)
{
    int any;

    if (rule == NULL || subj == NULL) {
        return 0;
    }

    any = tpc_str(rule->dn)[0] != '\0' || tpc_str(rule->group)[0] != '\0'
          || tpc_str(rule->host)[0] != '\0' || tpc_str(rule->vo)[0] != '\0';
    if (!any) {
        return 0;
    }

    if (!tpc_field_ok(rule->dn,
                      strcmp(tpc_str(rule->dn), tpc_str(subj->dn)) == 0)) {
        return 0;
    }
    if (!tpc_field_ok(rule->group,
                      brix_tpc_csv_member(subj->groups, rule->group))) {
        return 0;
    }
    if (!tpc_field_ok(rule->vo,
                      brix_tpc_csv_member(subj->vos, rule->vo))) {
        return 0;
    }
    if (!tpc_field_ok(rule->host,
                      brix_tpc_host_pattern_match(rule->host,
                                                  tpc_str(subj->host)))) {
        return 0;
    }
    return 1;
}


/* 1 when the rule speaks about this party: its own, or `all`. */
int
brix_tpc_require_rule_applies(const brix_tpc_require_rule_t *rule, int party)
{
    if (rule == NULL) {
        return 0;
    }
    return (rule->party == BRIX_TPC_PARTY_ALL || rule->party == party) ? 1 : 0;
}


/* ---- restrict prefix ----
 *
 * WHAT: `path` is `prefix`, or lies strictly beneath it at a '/' boundary.
 *
 * WHY: a plain strncmp() prefix — which is what stock does — makes `/data`
 *   admit `/database`, a silent widening of an operator's directory rule.  The
 *   boundary test is the narrower reading, and narrowing is the safe direction
 *   for a confinement control.
 *
 * HOW: ignore trailing slashes on the prefix; "/" admits any absolute path;
 *   otherwise compare the span and require the next byte to be NUL or '/'.
 *   A NULL or empty prefix matches NOTHING — the directive setter can never
 *   produce one, and a confinement rule that lost its argument must fail
 *   closed rather than degrade into "/".
 */
int
brix_tpc_restrict_match(const char *prefix, const char *path)
{
    size_t plen;

    prefix = tpc_str(prefix);
    path = tpc_str(path);

    plen = strlen(prefix);
    while (plen > 1 && prefix[plen - 1] == '/') {
        plen--;
    }

    if (path[0] == '\0' || plen == 0) {
        return 0;
    }
    if (plen == 1 && prefix[0] == '/') {
        return path[0] == '/' ? 1 : 0;
    }
    if (strncmp(path, prefix, plen) != 0) {
        return 0;
    }
    return (path[plen] == '\0' || path[plen] == '/') ? 1 : 0;
}


/* An XRootD object-id reference: a path whose first byte is '*'. */
int
brix_tpc_path_is_oid(const char *path)
{
    return tpc_str(path)[0] == '*' ? 1 : 0;
}


/* Stage 2. Configured and unmatched → deny; unconfigured → permit. */
static int
tpc_matrix_allow_stage(const brix_tpc_matrix_t *m,
    const brix_tpc_subject_t *subj)
{
    size_t i;

    if (m->allow == NULL || m->nallow == 0) {
        return 1;
    }
    for (i = 0; i < m->nallow; i++) {
        if (brix_tpc_allow_rule_match(&m->allow[i], subj)) {
            return 1;
        }
    }
    return 0;
}


/* Stage 3. Only rules naming this party constrain it; if none does, the party
 * is unconstrained even when the other party is heavily constrained. */
static int
tpc_matrix_require_stage(const brix_tpc_matrix_t *m, int party,
    const brix_tpc_subject_t *subj)
{
    size_t i;
    int    applicable = 0;

    if (m->require_rules == NULL || m->nrequire == 0) {
        return 1;
    }
    for (i = 0; i < m->nrequire; i++) {
        if (!brix_tpc_require_rule_applies(&m->require_rules[i], party)) {
            continue;
        }
        applicable = 1;
        if (brix_tpc_auth_name_eq(m->require_rules[i].auth, subj->auth)) {
            return 1;
        }
    }
    return applicable ? 0 : 1;
}


/* Stage 4. Configured and unmatched → deny; unconfigured → permit. */
static int
tpc_matrix_restrict_stage(const brix_tpc_matrix_t *m, const char *path)
{
    size_t i;

    if (m->paths == NULL || m->npaths == 0) {
        return 1;
    }
    for (i = 0; i < m->npaths; i++) {
        if (brix_tpc_restrict_match(m->paths[i], path)) {
            return 1;
        }
    }
    return 0;
}


/* ---- the whole verdict ----
 *
 * WHAT: run the four stages in their documented security order and name the
 *   first that refuses.
 *
 * WHY: one function owns the order so no call site can reorder it, and the
 *   unittest can prove the order itself (a subject that fails two stages
 *   reports the earlier one).
 *
 * HOW: oid → allow → require → restrict.  A leg with no path of its own skips
 *   the two path stages; it still faces allow and require.
 */
brix_tpc_matrix_verdict_t
brix_tpc_matrix_evaluate(const brix_tpc_matrix_t *m, int party,
    const brix_tpc_subject_t *subj, const char *path)
{
    brix_tpc_subject_t empty;
    int                has_path;

    if (m == NULL) {
        return BRIX_TPC_MATRIX_OK;
    }
    if (subj == NULL) {
        memset(&empty, 0, sizeof(empty));
        subj = &empty;
    }

    has_path = tpc_str(path)[0] != '\0';

    if (has_path && !m->oids && brix_tpc_path_is_oid(path)) {
        return BRIX_TPC_MATRIX_DENY_OID;
    }
    if (!tpc_matrix_allow_stage(m, subj)) {
        return BRIX_TPC_MATRIX_DENY_IDENTITY;
    }
    if (!tpc_matrix_require_stage(m, party, subj)) {
        return BRIX_TPC_MATRIX_DENY_AUTH;
    }
    if (has_path && !tpc_matrix_restrict_stage(m, path)) {
        return BRIX_TPC_MATRIX_DENY_PATH;
    }
    return BRIX_TPC_MATRIX_OK;
}


/* ---- refusal text ----
 *
 * Fixed phrases, one per verdict.  Nothing from the request is interpolated:
 * the string reaches the client, the access log AND (via the refusal counter's
 * neighbours) operator dashboards, so it must stay low-cardinality and must
 * never leak a DN, VO, hostname or path (INVARIANT 8).
 */
const char *
brix_tpc_matrix_verdict_text(brix_tpc_matrix_verdict_t v)
{
    switch (v) {
    case BRIX_TPC_MATRIX_DENY_OID:
        return "TPC object-id paths are not permitted (brix_tpc_oids off)";
    case BRIX_TPC_MATRIX_DENY_IDENTITY:
        return "TPC identity not permitted (brix_tpc_allow_identity)";
    case BRIX_TPC_MATRIX_DENY_AUTH:
        return "TPC authentication method not permitted (brix_tpc_require)";
    case BRIX_TPC_MATRIX_DENY_PATH:
        return "TPC path not permitted (brix_tpc_restrict)";
    case BRIX_TPC_MATRIX_OK:
    default:
        return "";
    }
}


#ifndef XRDPROTO_NO_NGX

/* 1 when the operator wrote any allow / require / restrict rule. */
int
brix_tpc_matrix_configured(const brix_tpc_matrix_conf_t *mc)
{
    if (mc == NULL) {
        return 0;
    }
    return ((mc->allow != NULL && mc->allow->nelts > 0)
            || (mc->require_rules != NULL && mc->require_rules->nelts > 0)
            || (mc->paths != NULL && mc->paths->nelts > 0)) ? 1 : 0;
}


/* 1 when any allow rule names a host, so the plane must have a PTR answer (or
 * a definitive "no PTR") before it decides. */
ngx_flag_t
brix_tpc_matrix_needs_hostname(ngx_array_t *allow)
{
    brix_tpc_allow_rule_t *rules;
    ngx_uint_t             i;

    if (allow == NULL) {
        return 0;
    }
    rules = allow->elts;
    for (i = 0; i < allow->nelts; i++) {
        if (rules[i].host != NULL && rules[i].host[0] != '\0') {
            return 1;
        }
    }
    return 0;
}


/* Borrowed views of an identity, in the matrix's vocabulary.  The VO and group
 * CSVs are the XrdAcc attribute views (acc_vorg / acc_group), which are the
 * parsed FQAN fields rather than the raw claim, so `allow vo cms` means the VO
 * and not "any FQAN containing cms". */
void
brix_tpc_matrix_subject_from_identity(const brix_identity_t *id,
    const char *peer_host, brix_tpc_subject_t *out)
{
    if (out == NULL) {
        return;
    }
    ngx_memzero(out, sizeof(*out));
    out->dn     = brix_identity_dn_cstr(id);
    out->groups = brix_identity_acc_group_cstr(id);
    out->vos    = brix_identity_acc_vorg_cstr(id);
    out->auth   = brix_identity_auth_label(id);
    out->host   = peer_host != NULL ? peer_host : "";
}


/* Adapt the conf arrays into the pure matrix and return its verdict.  The
 * restrict prefixes are the only conversion: conf holds ngx_str_t (already
 * NUL-terminated conf tokens), the evaluator wants a C-string vector, and the
 * setter's BRIX_TPC_RESTRICT_MAX cap keeps that vector a fixed stack array. */
brix_tpc_matrix_verdict_t
brix_tpc_matrix_check(const brix_tpc_matrix_conf_t *mc, int party,
    const brix_tpc_subject_t *subj, const char *path)
{
    brix_tpc_matrix_t  m;
    const char        *pv[BRIX_TPC_RESTRICT_MAX];
    ngx_str_t         *paths;
    ngx_uint_t         i;
    ngx_uint_t         n = 0;

    if (mc == NULL) {
        return BRIX_TPC_MATRIX_OK;
    }

    ngx_memzero(&m, sizeof(m));
    m.oids = mc->oids ? 1 : 0;

    if (mc->allow != NULL) {
        m.allow = mc->allow->elts;
        m.nallow = mc->allow->nelts;
    }
    if (mc->require_rules != NULL) {
        m.require_rules = mc->require_rules->elts;
        m.nrequire = mc->require_rules->nelts;
    }
    if (mc->paths != NULL) {
        paths = mc->paths->elts;
        for (i = 0; i < mc->paths->nelts && n < BRIX_TPC_RESTRICT_MAX; i++) {
            pv[n++] = (const char *) paths[i].data;
        }
        m.paths = pv;
        m.npaths = n;
    }

    return brix_tpc_matrix_evaluate(&m, party, subj, path);
}

#endif /* !XRDPROTO_NO_NGX */
