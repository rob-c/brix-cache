/*
 * frm_purge_policy_conf.c — 2.0 F4: brix_frm_purge_policy / brix_frm_purge_polprog.
 *
 * WHAT: Parse `brix_frm_purge_policy {*|<group>} <hi> <lo> [hold <time>]
 *       [polprog]` into brix_frm_conf_t.purge_policies, inherit + cross-check
 *       the table at merge, and hold the policy program to the rule
 *       brix_frm_stagecmd already applies (brix_frm_check_program).
 *
 * WHY:  frm_purged's `purge.policy` + `frm.purge.polprog` are the per-space
 *       purge surface sites reach for; the engine had only the export-wide
 *       watermark pair and cap (release-2.0 register F4).
 *
 * HOW:  Thresholds are sizes (`2g`) or `<n>%` of the group's brix_oss_space
 *       quota — both of one kind, lo <= hi; `*` (every group without its own
 *       line, and the ungrouped rest) has no quota, so sizes only. `hold` is
 *       an nginx time; `polprog` marks the group for the program. A named
 *       group must exist as a brix_oss_space of the same server, checked by
 *       brix_frm_purge_policy_check() once the server merge has inherited the
 *       space table (it settles AFTER the frm merge, in the auth tail).
 */

#include "config.h"
#include "tape_stage_conf.h"
#include "space_group_conf.h"

#include <stdlib.h>

static int
policy_is_default(const ngx_str_t *g)
{
    return g->len == 1 && g->data[0] == '*';
}

/* 1 = "<n>%" of the group quota (ppm filled), 0 = a size (bytes filled),
 * -1 = neither. */
static int
policy_parse_threshold(const ngx_str_t *arg, off_t *bytes, ngx_uint_t *ppm)
{
    ngx_str_t  size = *arg;
    char       buf[32];
    char      *end;
    double     v;

    *bytes = 0;
    *ppm   = 0;
    if (arg->len == 0) {
        return -1;
    }
    if (arg->data[arg->len - 1] != '%') {
        *bytes = ngx_parse_offset(&size);
        return (*bytes == (off_t) NGX_ERROR || *bytes < 0) ? -1 : 0;
    }
    if (arg->len - 1 >= sizeof(buf)) {
        return -1;
    }
    ngx_memcpy(buf, arg->data, arg->len - 1);
    buf[arg->len - 1] = '\0';
    v = strtod(buf, &end);
    if (end == buf || *end != '\0' || v < 0.0 || v > 100.0) {
        return -1;
    }
    *ppm = (ngx_uint_t) (v * 10000.0 + 0.5);
    return 1;
}

static char *
policy_parse_thresholds(ngx_conf_t *cf, ngx_str_t *value,
    brix_frm_purge_policy_t *p)
{
    int hk = policy_parse_threshold(&value[2], &p->hi, &p->hi_ppm);
    int lk = policy_parse_threshold(&value[3], &p->lo, &p->lo_ppm);

    if (hk < 0 || lk < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_purge_policy \"%V\": thresholds are sizes (\"2g\") or "
            "percentages of the group quota (\"90%%\"), got \"%V\" \"%V\"",
            &p->group, &value[2], &value[3]);
        return NGX_CONF_ERROR;
    }
    if (hk != lk) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_purge_policy \"%V\": <hi> and <lo> must both be sizes "
            "or both percentages", &p->group);
        return NGX_CONF_ERROR;
    }
    if (hk == 1 && policy_is_default(&p->group)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_purge_policy \"*\" has no quota to scale percentages "
            "against; use sizes");
        return NGX_CONF_ERROR;
    }
    p->percent = (hk == 1);
    if ((hk == 1 && p->lo_ppm > p->hi_ppm) || (hk == 0 && p->lo > p->hi)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_purge_policy \"%V\": low (%V) must not exceed high (%V)",
            &p->group, &value[3], &value[2]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
policy_parse_hold(ngx_conf_t *cf, ngx_array_t *args, ngx_uint_t i,
    brix_frm_purge_policy_t *p)
{
    ngx_str_t *value = args->elts;
    ngx_int_t  secs;

    if (i + 1 >= args->nelts) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_purge_policy \"%V\": hold needs a time", &p->group);
        return NGX_CONF_ERROR;
    }
    secs = ngx_parse_time(&value[i + 1], 1);
    if (secs == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_purge_policy \"%V\": hold \"%V\" is not a time",
            &p->group, &value[i + 1]);
        return NGX_CONF_ERROR;
    }
    p->hold_s = (time_t) secs;
    return NGX_CONF_OK;
}

static char *
policy_parse_options(ngx_conf_t *cf, ngx_array_t *args,
    brix_frm_purge_policy_t *p)
{
    ngx_str_t  *value = args->elts;
    ngx_uint_t  i;

    for (i = 4; i < args->nelts; i++) {
        if (value[i].len == 7 && ngx_strncmp(value[i].data, "polprog", 7) == 0) {
            p->polprog = 1;
            continue;
        }
        if (value[i].len == 4 && ngx_strncmp(value[i].data, "hold", 4) == 0) {
            if (policy_parse_hold(cf, args, i, p) != NGX_CONF_OK) {
                return NGX_CONF_ERROR;
            }
            i++;
            continue;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_purge_policy \"%V\": unknown option \"%V\" (expected "
            "hold <time> or polprog)", &p->group, &value[i]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
policy_check_group(ngx_conf_t *cf, const ngx_array_t *pols, const ngx_str_t *g)
{
    const brix_frm_purge_policy_t *p;
    ngx_uint_t                     i;

    if (!policy_is_default(g) && !brix_oss_space_name_ok(g)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_purge_policy: group name \"%V\" is not a valid "
            "brix_oss_space name (or \"*\")", g);
        return NGX_CONF_ERROR;
    }
    if (pols == NGX_CONF_UNSET_PTR || pols == NULL) {
        return NGX_CONF_OK;
    }
    p = pols->elts;
    for (i = 0; i < pols->nelts; i++) {
        if (p[i].group.len == g->len
            && ngx_memcmp(p[i].group.data, g->data, g->len) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_frm_purge_policy: group \"%V\" already has a policy", g);
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}

char *
brix_frm_set_purge_policy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_frm_conf_t          *frm   = (brix_frm_conf_t *)
                                        ((char *) conf + cmd->offset);
    ngx_str_t                *value = cf->args->elts;
    brix_frm_purge_policy_t   p, *slot;

    ngx_memzero(&p, sizeof(p));
    p.group = value[1];
    if (policy_check_group(cf, frm->purge_policies, &p.group) != NGX_CONF_OK
        || policy_parse_thresholds(cf, value, &p) != NGX_CONF_OK
        || policy_parse_options(cf, cf->args, &p) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    if (frm->purge_policies == NGX_CONF_UNSET_PTR) {
        frm->purge_policies = ngx_array_create(cf->pool, 4, sizeof(p));
        if (frm->purge_policies == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    slot = ngx_array_push(frm->purge_policies);
    if (slot == NULL) {
        return NGX_CONF_ERROR;
    }
    *slot = p;
    return NGX_CONF_OK;
}

static ngx_uint_t
policy_count_polprog(const ngx_array_t *pols)
{
    const brix_frm_purge_policy_t *p;
    ngx_uint_t                     i, n = 0;

    if (pols == NULL) {
        return 0;
    }
    p = pols->elts;
    for (i = 0; i < pols->nelts; i++) {
        n += p[i].polprog ? 1 : 0;
    }
    return n;
}

char *
brix_frm_purge_policy_merge(ngx_conf_t *cf, brix_frm_conf_t *conf,
    brix_frm_conf_t *prev)
{
    ngx_uint_t n;

    ngx_conf_merge_ptr_value(conf->purge_policies, prev->purge_policies, NULL);
    ngx_conf_merge_str_value(conf->purge_polprog, prev->purge_polprog, "");
    if (brix_frm_check_program(cf, "brix_frm_purge_polprog",
                               &conf->purge_polprog,
                               "the purge engine runs it as <program> "
                               "<candidates-file> <decision-file>")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    n = policy_count_polprog(conf->purge_policies);
    if (n > 0 && conf->purge_polprog.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_purge_policy: %ui rule(s) say polprog but no "
            "brix_frm_purge_polprog is configured", n);
        return NGX_CONF_ERROR;
    }
    if (n == 0 && conf->purge_polprog.len > 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix_frm_purge_polprog \"%V\" is set but no brix_frm_purge_policy "
            "line says polprog; the program never runs", &conf->purge_polprog);
    }
    return NGX_CONF_OK;
}

char *
brix_frm_purge_policy_check(ngx_conf_t *cf, const ngx_array_t *spaces,
    const brix_frm_conf_t *frm)
{
    const brix_frm_purge_policy_t *p;
    const brix_oss_space_t        *sp;
    ngx_uint_t                     i;

    if (frm->purge_policies == NULL) {
        return NGX_CONF_OK;
    }
    p = frm->purge_policies->elts;
    for (i = 0; i < frm->purge_policies->nelts; i++) {
        if (policy_is_default(&p[i].group)) {
            continue;
        }
        sp = brix_oss_space_by_name(spaces, p[i].group.data, p[i].group.len);
        if (sp == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_frm_purge_policy: group \"%V\" is not a brix_oss_space "
                "of this server", &p[i].group);
            return NGX_CONF_ERROR;
        }
        if (p[i].percent && sp->quota <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_frm_purge_policy: group \"%V\" has no positive quota= "
                "to scale percentage thresholds against", &p[i].group);
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}
