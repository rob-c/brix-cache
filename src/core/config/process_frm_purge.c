/*
 * process_frm_purge.c — phase-115 W3.2: arm + drive the tape-buffer purge
 * timer for a server whose export chain carries a tape:// tier.
 *
 * WHAT: brix_init_server_frm_purge_timer() (called from the per-server init
 *       ladder in process_server_init.c) resolves the export's driver chain,
 *       finds the frm tier, and arms a worker-0 timer that runs
 *       brix_sd_frm_purge() every brix_frm_purge_interval with the policy the
 *       brix_frm_purge_watermark / brix_frm_purge_max_bytes directives set.
 *
 * WHY:  Those two directives were accepted-only since the FRM dissolution
 *       (§13b): parsed, merged, never read. The engine itself is pure libc in
 *       src/fs/backend/frm/sd_frm_purge.c; this TU is the only place that
 *       knows about nginx timers, the server conf and the stage registry.
 *
 * HOW:  1. Skip unless a local export root resolves, at least one arm is
 *          configured (0 < hi_ppm < 1e6, or max_bytes > 0), and this is
 *          worker 0 (one engine per host, not N racing walks).
 *       2. Walk the chain head -> decorator sources for a CAP_NEARLINE tier
 *          whose driver is "frm"; WARN + return when there is none (the
 *          directives are set but cannot act).
 *       3. pcalloc the timer, first tick = brix_cache_reap_delay(5000 ms).
 *       4. Each tick: statvfs the online root (arm 1 input), run one pass
 *          with the stage registry as the pin oracle, re-arm unless exiting.
 *       2.0 F4: the brix_frm_purge_policy table becomes the engine's rule
 *          array once at arm time (percent thresholds scaled by the
 *          group's brix_oss_space quota); rule_of() answers the rule of a
 *          buffer key by longest-prefix group, "*" for the rest.
 */

#include "config.h"
#include "process_internal.h"
#include "fs/vfs/vfs_backend_registry.h"      /* brix_vfs_backend_resolve */
#include "fs/vfs/vfs_internal.h"              /* brix_vfs_decorator_source */
#include "fs/backend/sd_accessors.h"          /* brix_sd_caps */
#include "fs/backend/frm/sd_frm.h"            /* brix_sd_frm_purge */
#include "fs/cache/evict_internal.h"          /* brix_cache_fs_usage */
#include "fs/xfer/stage_request_registry.h"   /* brix_stage_request_find_by_path */
#include "space_group_conf.h"                 /* brix_oss_space_for_path (F4) */

#include <limits.h>
#include <stdio.h>

#define BRIX_FRM_PURGE_MIN_INTERVAL_MS  1000
/* 2.0 F4: the policy program's deadline when brix_frm_copy_timeout is unset */
#define BRIX_FRM_POLPROG_TIMEOUT_MS     30000

typedef struct {
    ngx_event_t                  ev;
    ngx_stream_brix_srv_conf_t  *xcf;
    brix_sd_instance_t          *frm;
    /* 2.0 F4: the rule table built from brix_frm_purge_policy at arm time */
    brix_sd_frm_purge_rule_t    *rules;
    size_t                       nrules;
    int                          default_rule;   /* index of "*", -1 = none */
    const char                  *polprog;        /* NULL = no program */
} brix_frm_purge_timer_t;

/* The tape tier of an export's chain: the first CAP_NEARLINE instance whose
 * driver is the frm backend, walking head -> decorator sources. */
static brix_sd_instance_t *
brix_frm_purge_find_tier(brix_sd_instance_t *head)
{
    brix_sd_instance_t *inst;

    for (inst = head; inst != NULL; inst = brix_vfs_decorator_source(inst)) {
        if ((brix_sd_caps(inst) & BRIX_SD_CAP_NEARLINE)
            && inst->driver != NULL
            && ngx_strcmp(inst->driver->name, "frm") == 0)
        {
            return inst;
        }
    }
    return NULL;
}

/* Pin oracle: a key is pinned while a live stage request names it. The
 * registry keys requests by the confined ABSOLUTE lfn (<root_canon><key>). */
static int
brix_frm_purge_is_pinned(void *ud, const char *key)
{
    brix_frm_purge_timer_t     *t   = ud;
    ngx_stream_brix_srv_conf_t *xcf = t->xcf;
    brix_stage_registry_t      *reg = brix_stage_registry_singleton();
    char                        lfn[PATH_MAX];
    char                        reqid[40];

    if (reg == NULL) {
        return 0;
    }
    if (snprintf(lfn, sizeof(lfn), "%s%s", xcf->common.root_canon, key)
        >= (int) sizeof(lfn))
    {
        return 1;                              /* unrepresentable: keep it */
    }
    return brix_stage_request_find_by_path(reg, lfn, reqid, sizeof(reqid),
                                           t->ev.log) == NGX_OK;
}

/* 2.0 F4 — the rule a buffer key falls under: its longest-prefix
 * brix_oss_space group's own rule, else the "*" rule (which also covers
 * ungrouped keys), else none. A nested group is its own space, so a key of a
 * group without a rule never inherits the parent group's rule. */
static int
brix_frm_purge_rule_of(void *ud, const char *key)
{
    brix_frm_purge_timer_t *t  = ud;
    const brix_oss_space_t *sp = brix_oss_space_for_path(t->xcf->oss_spaces,
                                                         key, ngx_strlen(key));
    size_t                  i;

    if (sp == NULL) {
        return t->default_rule;
    }
    for (i = 0; i < t->nrules; i++) {
        if (sp->name.len == ngx_strlen(t->rules[i].name)
            && ngx_strncmp(sp->name.data, t->rules[i].name, sp->name.len) == 0)
        {
            return (int) i;
        }
    }
    return t->default_rule;
}

/* A size threshold is used as is; a percentage is scaled by the group's
 * brix_oss_space quota (the merge refused a percentage without one). */
static uint64_t
brix_frm_purge_rule_bytes(const ngx_stream_brix_srv_conf_t *xcf,
    const brix_frm_purge_policy_t *p, off_t bytes, ngx_uint_t ppm)
{
    const brix_oss_space_t *sp;

    if (!p->percent) {
        return (uint64_t) bytes;
    }
    sp = brix_oss_space_by_name(xcf->oss_spaces, p->group.data, p->group.len);
    if (sp == NULL || sp->quota <= 0) {
        return 0;
    }
    return (uint64_t) ((double) sp->quota * (double) ppm / 1000000.0);
}

static ngx_int_t
brix_frm_purge_build_rules(ngx_cycle_t *cycle, brix_frm_purge_timer_t *t)
{
    const ngx_array_t             *pols = t->xcf->frm.purge_policies;
    const brix_frm_purge_policy_t *p;
    brix_sd_frm_purge_rule_t      *r;
    ngx_uint_t                     i;

    t->default_rule = -1;
    t->polprog = (t->xcf->frm.purge_polprog.len > 0)
                 ? (const char *) t->xcf->frm.purge_polprog.data : NULL;
    if (pols == NULL || pols->nelts == 0) {
        return NGX_OK;
    }
    r = ngx_pcalloc(cycle->pool, pols->nelts * sizeof(*r));
    if (r == NULL) {
        return NGX_ERROR;
    }
    p = pols->elts;
    for (i = 0; i < pols->nelts; i++) {
        u_char *name = ngx_pnalloc(cycle->pool, p[i].group.len + 1);

        if (name == NULL) {
            return NGX_ERROR;
        }
        ngx_cpystrn(name, p[i].group.data, p[i].group.len + 1);
        r[i].name     = (const char *) name;
        r[i].hi_bytes = brix_frm_purge_rule_bytes(t->xcf, &p[i], p[i].hi,
                                                  p[i].hi_ppm);
        r[i].lo_bytes = brix_frm_purge_rule_bytes(t->xcf, &p[i], p[i].lo,
                                                  p[i].lo_ppm);
        r[i].hold_s   = p[i].hold_s;
        r[i].polprog  = p[i].polprog ? 1 : 0;
        if (p[i].group.len == 1 && p[i].group.data[0] == '*') {
            t->default_rule = (int) i;
        }
    }
    t->rules  = r;
    t->nrules = pols->nelts;
    return NGX_OK;
}

static int
brix_frm_purge_armed(const brix_frm_conf_t *frm)
{
    return (frm->purge_hi_ppm > 0 && frm->purge_hi_ppm < 1000000)
           || frm->purge_max_bytes > 0
           || (frm->purge_policies != NULL && frm->purge_policies->nelts > 0);
}

static void
brix_frm_purge_tick(ngx_event_t *ev)
{
    brix_frm_purge_timer_t      *t   = ev->data;
    ngx_stream_brix_srv_conf_t  *xcf = t->xcf;
    brix_sd_frm_purge_policy_t   pol;
    brix_sd_frm_purge_report_t   rep;
    brix_cache_fs_usage_t        usage;
    char                         online[PATH_MAX];
    ngx_msec_t                   interval;

    ngx_memzero(&pol, sizeof(pol));
    pol.hi_ppm    = xcf->frm.purge_hi_ppm;
    pol.lo_ppm    = xcf->frm.purge_lo_ppm;
    pol.max_bytes = xcf->frm.purge_max_bytes;
    pol.min_age_s = BRIX_FRM_PURGE_MIN_AGE_S;
    pol.is_pinned = brix_frm_purge_is_pinned;
    pol.ud        = t;
    pol.rules     = t->rules;                          /* 2.0 F4 */
    pol.nrules    = t->nrules;
    pol.rule_of   = brix_frm_purge_rule_of;
    pol.polprog   = t->polprog;
    pol.polprog_timeout_ms = xcf->frm.copy_timeout > 0
                             ? xcf->frm.copy_timeout
                             : BRIX_FRM_POLPROG_TIMEOUT_MS;
    if (brix_sd_frm_online_root(t->frm, online, sizeof(online)) == NGX_OK
        && brix_cache_fs_usage(online, &usage) == NGX_OK)
    {
        pol.fs_total = usage.total;
        pol.fs_used  = usage.used;
    }

    if (brix_sd_frm_purge(t->frm, &pol, &rep, ev->log) == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, ev->log, 0,
            "brix: tape purge \"%s\" skipped: another pass holds the lock",
            online);
    }

    if (!ngx_exiting) {
        interval = xcf->frm.purge_interval_ms;
        if (interval < BRIX_FRM_PURGE_MIN_INTERVAL_MS) {
            interval = BRIX_FRM_PURGE_MIN_INTERVAL_MS;
        }
        ngx_add_timer(ev, interval);
    }
}

ngx_int_t
brix_init_server_frm_purge_timer(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *xcf)
{
    brix_frm_purge_timer_t *t;
    brix_sd_instance_t     *head, *frm;

    if (xcf->common.root_canon[0] == '\0' || !brix_frm_purge_armed(&xcf->frm)
        || ngx_worker != 0)
    {
        return NGX_OK;
    }
    head = brix_vfs_backend_resolve(xcf->common.root_canon, cycle->log);
    frm  = brix_frm_purge_find_tier(head);
    if (frm == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
            "brix: brix_frm_purge_* configured but export \"%s\" has no "
            "tape:// tier; purge engine not armed",
            xcf->common.root_canon);
        return NGX_OK;
    }

    t = ngx_pcalloc(cycle->pool, sizeof(*t));
    if (t == NULL) {
        return NGX_ERROR;
    }
    t->xcf = xcf;
    t->frm = frm;
    if (brix_frm_purge_build_rules(cycle, t) != NGX_OK) {
        return NGX_ERROR;
    }
    t->ev.handler    = brix_frm_purge_tick;
    t->ev.data       = t;
    t->ev.log        = cycle->log;
    t->ev.cancelable = 1;                      /* don't delay graceful shutdown */
    ngx_add_timer(&t->ev, brix_cache_reap_delay(BRIX_FRM_PURGE_FIRST_MS));

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
        "brix: tape purge engine armed for export \"%s\" (hi=%ui lo=%ui ppm, "
        "max_bytes=%O, interval=%M ms)",
        xcf->common.root_canon, xcf->frm.purge_hi_ppm, xcf->frm.purge_lo_ppm,
        xcf->frm.purge_max_bytes, xcf->frm.purge_interval_ms);
    if (t->nrules > 0) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
            "brix: tape purge policy for export \"%s\": %uz rule(s), "
            "program \"%s\"", xcf->common.root_canon, t->nrules,
            t->polprog ? t->polprog : "(none)");
    }
    return NGX_OK;
}
