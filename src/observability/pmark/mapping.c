/*
 * mapping.c — resolve (experiment, activity) for a transfer + first-use runtime.
 *
 * WHAT: Two things.  (1) brix_pmark_runtime_ensure() lazily builds a pmark
 *   config's runtime data the first time a flow needs it (per worker): load the
 *   defsfile, resolve every map_experiment/map_activity NAME to its numeric id,
 *   and resolve every firefly_dest "host[:port]" string to a sockaddr.  (2)
 *   brix_pmark_map_codes() picks the (experiment, activity) for one flow.
 *
 * WHY: This is the nginx analogue of XRootD's XrdNetPMarkCfg::getCodes
 *   (XrdNetPMarkCfg.cc:774-843).  Resolution is deferred to first use so it works
 *   uniformly for the stream and HTTP modules without walking every server/
 *   location conf at startup; the result is cached on the conf (COW per worker).
 *
 * HOW: Code priority matches XRootD — client scitag.flow (override) → path glob →
 *   VO → default experiment; then activity user → role (parsed from the VOMS
 *   FQAN) → per-experiment default → 1.  Everything is fail-open: an unmappable
 *   flow returns NGX_DECLINED and is simply not marked.
 */

#include "pmark.h"
#include "core/compat/cstr.h"
#include "net/dns/dns.h"       /* async collector resolution (phase-116) */

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>


/* Prefix/glob match: a trailing '*' is stripped, then `path` must start with the
 * (remaining) pattern.  An empty pattern never matches. */
static int
pmark_path_match(const char *path, ngx_str_t *pat)
{
    size_t n;

    if (path == NULL || pat->len == 0) {
        return 0;
    }
    n = pat->len;
    if (pat->data[n - 1] == '*') {
        n--;
    }
    if (n == 0) {
        return 1;                 /* bare "*" matches everything */
    }
    return ngx_strncmp(path, pat->data, n) == 0;
}


/* CSV-token exact match: is `needle` one of the comma-separated tokens in csv? */
static int
pmark_csv_has(const char *csv, ngx_str_t *needle)
{
    const char *p, *start;
    size_t      tok;

    if (csv == NULL || needle->len == 0) {
        return 0;
    }
    p = start = csv;
    for (;;) {
        if (*p == ',' || *p == '\0') {
            tok = (size_t) (p - start);
            if (tok == needle->len
                && ngx_strncmp(start, needle->data, tok) == 0)
            {
                return 1;
            }
            if (*p == '\0') {
                return 0;
            }
            start = p + 1;
        }
        p++;
    }
}


/* Extract the VOMS Role from an FQAN-bearing CSV (looks for "Role=<value>").
 * Writes the value into out[] (NUL-terminated) and returns 1, or 0 if absent. */
static int
pmark_extract_role(const char *vo_csv, char *out, size_t outlen)
{
    const char *r, *e;
    size_t      n;

    if (vo_csv == NULL) {
        return 0;
    }
    r = strstr(vo_csv, "Role=");
    if (r == NULL) {
        return 0;
    }
    r += 5;                                   /* past "Role=" */
    for (e = r; *e && *e != '/' && *e != ','; e++) { /* value end */ }
    n = (size_t) (e - r);
    if (n == 0 || n >= outlen) {
        return 0;
    }
    ngx_memcpy(out, r, n);
    out[n] = '\0';
    return 1;
}


/* One in-flight firefly collector resolution (phase-116: async, never
 * getaddrinfo on the event loop).  Lives in the worker's cycle pool for the
 * worker's lifetime, like the dest_sa array it feeds. */
typedef struct {
    brix_dns_req_t      req;
    brix_pmark_conf_t  *pm;
    ngx_str_t           spec;
    u_char              host[256];
} pmark_dns_t;


/* Split "host[:port]" (default port 10514).  For a bracketed IPv6 literal
 * "[::1]:port" the colon after ']' is the separator; otherwise the last
 * colon is.  Returns NGX_ERROR on an over-long or malformed spec. */
static ngx_int_t
pmark_split_dest(ngx_str_t *spec, u_char *host, size_t hostsz,
    in_port_t *port)
{
    u_char     *colon, *end, *rb;
    size_t      hlen;
    ngx_int_t   n;

    if (spec->len == 0 || spec->len >= hostsz) {
        return NGX_ERROR;
    }
    end = spec->data + spec->len;
    colon = ngx_strlchr(spec->data, end, ':');
    if (spec->data[0] == '[') {
        rb = ngx_strlchr(spec->data, end, ']');
        colon = (rb && rb + 1 < end && rb[1] == ':') ? rb + 1 : NULL;
        hlen = rb ? (size_t) (rb - spec->data - 1) : spec->len;
        ngx_memcpy(host, spec->data + 1, hlen);
    } else {
        hlen = colon ? (size_t) (colon - spec->data) : spec->len;
        ngx_memcpy(host, spec->data, hlen);
    }
    host[hlen] = '\0';

    if (colon && colon + 1 < end) {
        n = ngx_atoi(colon + 1, (size_t) (end - (colon + 1)));
        if (n <= 0 || n > BRIX_PMARK_PORT_MAX) {
            return NGX_ERROR;
        }
        *port = (in_port_t) n;
    } else {
        *port = BRIX_PMARK_FF_PORT;
    }
    return NGX_OK;
}


/* Resolution landed: append the collector (first answer) to dest_sa. */
static void
pmark_dest_resolved(brix_dns_req_t *req)
{
    pmark_dns_t        *d = req->data;
    brix_pmark_dest_t  *dst;

    if (req->rc != NGX_OK || req->naddrs == 0) {
        ngx_log_error(NGX_LOG_WARN, req->log, 0,
            "pmark: cannot resolve firefly dest \"%V\": %s", &d->spec,
            req->error ? req->error : "unknown");
        return;
    }
    dst = ngx_array_push(d->pm->dest_sa);
    if (dst == NULL) {
        return;
    }
    ngx_memzero(dst, sizeof(*dst));
    ngx_memcpy(&dst->ss, &req->addrs[0].ss, req->addrs[0].len);
    dst->len    = req->addrs[0].len;
    dst->family = dst->ss.ss_family;
}


/* Start resolving one "host[:port]" collector spec (UDP).  A literal lands
 * synchronously; a hostname lands from the driver later — fireflies for a
 * collector that is still resolving are dropped, never blocked on. */
static ngx_int_t
pmark_resolve_dest(ngx_str_t *spec, brix_pmark_conf_t *pm, ngx_pool_t *pool,
    ngx_log_t *log)
{
    pmark_dns_t  *d;
    in_port_t     port;

    d = ngx_pcalloc(pool, sizeof(pmark_dns_t));
    if (d == NULL) {
        return NGX_ERROR;
    }
    if (pmark_split_dest(spec, d->host, sizeof(d->host), &port) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "pmark: malformed firefly dest \"%V\"", spec);
        return NGX_OK;
    }
    d->pm = pm;
    d->spec = *spec;
    d->req.name.data = d->host;
    d->req.name.len = ngx_strlen(d->host);
    d->req.port = port;
    d->req.af = BRIX_AF_AUTO;
    d->req.socktype = SOCK_DGRAM;
    d->req.log = log;
    d->req.handler = pmark_dest_resolved;
    d->req.data = d;
    if (brix_dns_resolve(&d->req) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "pmark: cannot start resolving firefly dest \"%V\": %s", spec,
            d->req.error ? d->req.error : "unknown");
    }
    return NGX_OK;
}


/* Load the scitags registry (optional; only needed for named mappings).
 * A load failure is fail-open: named mappings are disabled with a WARN and
 * NULL is returned. */
static ngx_array_t *
pmark_load_defs(brix_pmark_conf_t *pm, ngx_pool_t *pool, ngx_log_t *log)
{
    ngx_array_t *defs = NULL;
    char         path[BRIX_PMARK_PATH_BUF];

    if (pm->defsfile.len == 0) {
        return NULL;
    }
    if (brix_str_cbuf(path, sizeof(path), &pm->defsfile) == NULL) {
        return NULL;
    }
    if (brix_pmark_defsfile_load(path, pool, &defs, log) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "pmark: defsfile load failed; named mappings disabled");
    }
    return defs;
}


/* Resolve experiment rules: name → id (rules that don't resolve are dropped
 * with a WARN).  NGX_ERROR only on allocation failure. */
static ngx_int_t
pmark_resolve_exp_rules(brix_pmark_conf_t *pm, ngx_array_t *defs,
    ngx_pool_t *pool, ngx_log_t *log)
{
    brix_pmark_exp_rule_t *src;
    ngx_uint_t             i;

    if (pm->exp_rules == NULL || pm->exp_rules->nelts == 0) {
        return NGX_OK;
    }
    src = pm->exp_rules->elts;
    pm->exp_rules_r = ngx_array_create(pool, pm->exp_rules->nelts,
                                       sizeof(brix_pmark_exp_rule_r_t));
    if (pm->exp_rules_r == NULL) {
        return NGX_ERROR;
    }
    for (i = 0; i < pm->exp_rules->nelts; i++) {
        ngx_uint_t id = brix_pmark_defs_exp_id(defs, &src[i].exp_name);
        brix_pmark_exp_rule_r_t *r;
        if (id == 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "pmark: experiment \"%V\" not in defsfile; rule ignored",
                &src[i].exp_name);
            continue;
        }
        r = ngx_array_push(pm->exp_rules_r);
        if (r == NULL) {
            return NGX_ERROR;
        }
        r->kind = src[i].kind;
        r->match = src[i].match;
        r->exp_id = id;
    }
    return NGX_OK;
}


/* Resolve activity rules: (exp,act) names → ids (rules that don't resolve are
 * dropped with a WARN).  NGX_ERROR only on allocation failure. */
static ngx_int_t
pmark_resolve_act_rules(brix_pmark_conf_t *pm, ngx_array_t *defs,
    ngx_pool_t *pool, ngx_log_t *log)
{
    brix_pmark_act_rule_t *src;
    ngx_uint_t             i;

    if (pm->act_rules == NULL || pm->act_rules->nelts == 0) {
        return NGX_OK;
    }
    src = pm->act_rules->elts;
    pm->act_rules_r = ngx_array_create(pool, pm->act_rules->nelts,
                                       sizeof(brix_pmark_act_rule_r_t));
    if (pm->act_rules_r == NULL) {
        return NGX_ERROR;
    }
    for (i = 0; i < pm->act_rules->nelts; i++) {
        ngx_uint_t eid = brix_pmark_defs_exp_id(defs, &src[i].exp_name);
        ngx_uint_t aid = brix_pmark_defs_act_id(defs, eid, &src[i].act_name);
        brix_pmark_act_rule_r_t *r;
        if (eid == 0 || aid == 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "pmark: activity \"%V/%V\" not in defsfile; rule ignored",
                &src[i].exp_name, &src[i].act_name);
            continue;
        }
        r = ngx_array_push(pm->act_rules_r);
        if (r == NULL) {
            return NGX_ERROR;
        }
        r->exp_id = eid;
        r->kind = src[i].kind;
        r->match = src[i].match;
        r->act_id = aid;
    }
    return NGX_OK;
}


/* Start resolving the firefly collector "host[:port]" specs (phase-116:
 * async; each answer is appended to dest_sa when it lands).  Unresolvable
 * specs are skipped with a WARN; "origin" is handled per-flow against the
 * client peer, not here.  NGX_ERROR only on allocation failure. */
static ngx_int_t
pmark_resolve_dests(brix_pmark_conf_t *pm, ngx_pool_t *pool, ngx_log_t *log)
{
    ngx_str_t  *spec;
    ngx_uint_t  i;

    if (!pm->firefly || pm->firefly_dest == NULL
        || pm->firefly_dest->nelts == 0)
    {
        return NGX_OK;
    }
    spec = pm->firefly_dest->elts;
    pm->dest_sa = ngx_array_create(pool, pm->firefly_dest->nelts,
                                   sizeof(brix_pmark_dest_t));
    if (pm->dest_sa == NULL) {
        return NGX_ERROR;
    }
    for (i = 0; i < pm->firefly_dest->nelts; i++) {
        if (spec[i].len == 6
            && ngx_strncmp(spec[i].data, "origin", 6) == 0)
        {
            continue;
        }
        if (pmark_resolve_dest(&spec[i], pm, pool, log) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


ngx_int_t
brix_pmark_runtime_ensure(brix_pmark_conf_t *pm, ngx_pool_t *pool,
    ngx_log_t *log)
{
    ngx_array_t *defs;

    if (pm->rt_ready) {
        return pm->rt_ok ? NGX_OK : NGX_DECLINED;
    }
    pm->rt_ready = 1;
    pm->rt_ok    = 0;

    if (!pm->enable) {
        return NGX_DECLINED;
    }

    defs = pmark_load_defs(pm, pool, log);

    if (pmark_resolve_exp_rules(pm, defs, pool, log) != NGX_OK) {
        return NGX_DECLINED;
    }
    if (pmark_resolve_act_rules(pm, defs, pool, log) != NGX_OK) {
        return NGX_DECLINED;
    }
    if (pmark_resolve_dests(pm, pool, log) != NGX_OK) {
        return NGX_DECLINED;
    }

    pm->rt_ok = 1;
    return NGX_OK;
}


/* Exact match of a NUL-terminated string against a non-empty ngx_str_t
 * pattern.  NULL string or empty pattern never match. */
static int
pmark_str_eq(const char *s, ngx_str_t *pat)
{
    return s != NULL && pat->len != 0
        && ngx_strlen(s) == pat->len
        && ngx_strncmp(s, pat->data, pat->len) == 0;
}


/* Pick the experiment code for one flow: path glob > VO > default (first
 * matching rule of each kind wins).  Returns 0 when nothing maps. */
static ngx_uint_t
pmark_map_experiment(brix_pmark_conf_t *pm, const char *vo_csv,
    const char *path)
{
    ngx_uint_t  e_path = 0, e_vo = 0, e_def = 0;
    ngx_uint_t  i;

    if (pm->exp_rules_r == NULL) {
        return 0;
    }
    brix_pmark_exp_rule_r_t *r = pm->exp_rules_r->elts;
    for (i = 0; i < pm->exp_rules_r->nelts; i++) {
        switch (r[i].kind) {
        case BRIX_PMARK_EXP_PATH:
            if (!e_path && pmark_path_match(path, &r[i].match)) {
                e_path = r[i].exp_id;
            }
            break;
        case BRIX_PMARK_EXP_VO:
            if (!e_vo && pmark_csv_has(vo_csv, &r[i].match)) {
                e_vo = r[i].exp_id;
            }
            break;
        case BRIX_PMARK_EXP_DEFAULT:
            if (!e_def) {
                e_def = r[i].exp_id;
            }
            break;
        }
    }
    return e_path ? e_path : (e_vo ? e_vo : e_def);
}


/* Pick the activity code for experiment `e`: user > VOMS role > per-experiment
 * default (first matching rule of each kind wins).  Returns 0 when no rule for
 * this experiment maps (the caller applies the XRootD fallback). */
static ngx_uint_t
pmark_map_activity(brix_pmark_conf_t *pm, ngx_uint_t e, const char *vo_csv,
    const char *user)
{
    ngx_uint_t  a_user = 0, a_role = 0, a_def = 0;
    ngx_uint_t  i;
    char        role[128];

    if (pm->act_rules_r == NULL) {
        return 0;
    }
    role[0] = '\0';                      /* empty → matches no rule */
    (void) pmark_extract_role(vo_csv, role, sizeof(role));

    brix_pmark_act_rule_r_t *r = pm->act_rules_r->elts;
    for (i = 0; i < pm->act_rules_r->nelts; i++) {
        if (r[i].exp_id != e) {
            continue;
        }
        switch (r[i].kind) {
        case BRIX_PMARK_ACTR_USER:
            if (!a_user && pmark_str_eq(user, &r[i].match)) {
                a_user = r[i].act_id;
            }
            break;
        case BRIX_PMARK_ACTR_ROLE:
            if (!a_role && pmark_str_eq(role, &r[i].match)) {
                a_role = r[i].act_id;
            }
            break;
        case BRIX_PMARK_ACTR_DEFAULT:
            if (!a_def) {
                a_def = r[i].act_id;
            }
            break;
        }
    }
    return a_user ? a_user : (a_role ? a_role : a_def);
}


ngx_int_t
brix_pmark_map_codes(brix_pmark_conf_t *pm,
    const brix_pmark_flow_id_t *flow, ngx_uint_t *exp, ngx_uint_t *act)
{
    ngx_uint_t  e, a;

    *exp = 0;
    *act = 0;

    /* 1) client scitag.flow override (provides BOTH codes). */
    if (pm->scitag_cgi && flow->cgi
        && brix_pmark_parse_scitag(flow->cgi, exp, act) == NGX_OK)
    {
        return NGX_OK;
    }

    /* 2) experiment: path glob > VO > default. */
    e = pmark_map_experiment(pm, flow->vo_csv, flow->path);
    if (e == 0) {
        return NGX_DECLINED;            /* nothing maps → not marked */
    }

    /* 3) activity: user > role > per-experiment default; fallback 1. */
    a = pmark_map_activity(pm, e, flow->vo_csv, flow->user);
    if (a == 0) {
        a = 1;                          /* XRootD default activity */
    }

    if (brix_pmark_codes_valid(e, a) != NGX_OK) {
        return NGX_DECLINED;
    }
    *exp = e;
    *act = a;
    return NGX_OK;
}
