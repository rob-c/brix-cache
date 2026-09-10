/*
 * directive.c — `brix_resolver` and `brix_dns_retry` setters (phase-116 W1).
 *
 * WHAT: Parses `brix_resolver auto|off [path=] [valid=] [min_ttl=] [max_ttl=]
 *       [negative_ttl=] [ipv4=] [ipv6=] [search=]` into a brix_dns_policy_t,
 *       builds the nginx resolver from the resolv.conf it names, and — the
 *       whole point — fills the enclosing scope's nginx resolver slot when
 *       the operator has not written `resolver` there.  `brix_dns_retry`
 *       parses the target-registry backoff pair.
 * WHY:  Stock nginx creates an inert "dummy" resolver for every scope without
 *       an explicit `resolver`, so `proxy_pass $var`, `server … resolve` and
 *       OCSP all fail at runtime.  Seeding the slot at parse time (not merge
 *       time) matters: the upstream module reads the http{}-level resolver in
 *       its init_main_conf, which runs BEFORE any merge hook.
 * HOW:  One setter serves both planes — `common` is member 0 of every brix
 *       module conf, and cf->module_type says which core module owns the
 *       slot.  "Fills, never overrides": a slot that already holds a
 *       resolver is left alone with a notice.  (The core-conf pokes are the
 *       R4-allowlisted seam of this file.)
 */
#include <ngx_http.h>
#include <ngx_stream.h>
#include <ngx_thread_pool.h>

#include "net/dns/dns.h"
#include "core/config/shared_conf.h"


static char *
dns_parse_time_arg(ngx_conf_t *cf, ngx_str_t *arg, size_t plen,
    time_t *out)
{
    ngx_str_t  v;
    time_t     t;

    v.data = arg->data + plen;
    v.len = arg->len - plen;
    t = ngx_parse_time(&v, 1);
    if (t == (time_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_resolver: invalid time in \"%V\"", arg);
        return NGX_CONF_ERROR;
    }
    *out = t;
    return NGX_CONF_OK;
}


static char *
dns_parse_flag_arg(ngx_conf_t *cf, ngx_str_t *arg, size_t plen,
    ngx_flag_t *out)
{
    ngx_str_t  v;

    v.data = arg->data + plen;
    v.len = arg->len - plen;
    if (v.len == 2 && ngx_strncmp(v.data, "on", 2) == 0) {
        *out = 1;
        return NGX_CONF_OK;
    }
    if (v.len == 3 && ngx_strncmp(v.data, "off", 3) == 0) {
        *out = 0;
        return NGX_CONF_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "brix_resolver: expected on|off in \"%V\"", arg);
    return NGX_CONF_ERROR;
}


/* One "key=value" argument; unknown keys are config errors. */
static char *
dns_parse_option(ngx_conf_t *cf, brix_dns_policy_t *pol, ngx_str_t *arg)
{
    time_t  t = 0;
    char   *rc;

    if (ngx_strncmp(arg->data, "path=", 5) == 0) {
        pol->path.data = arg->data + 5;
        pol->path.len = arg->len - 5;
        /* absolute only: a relative name would be read against the
         * process cwd, which differs between `nginx -t` and the master */
        if (pol->path.len == 0 || pol->path.data[0] != '/') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix_resolver: path must be absolute in \"%V\"",
                               arg);
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }
    if (ngx_strncmp(arg->data, "valid=", 6) == 0) {
        rc = dns_parse_time_arg(cf, arg, 6, &t);
        pol->valid = (ngx_msec_t) t * 1000;
        return rc;
    }
    if (ngx_strncmp(arg->data, "min_ttl=", 8) == 0) {
        return dns_parse_time_arg(cf, arg, 8, &pol->min_ttl);
    }
    if (ngx_strncmp(arg->data, "max_ttl=", 8) == 0) {
        return dns_parse_time_arg(cf, arg, 8, &pol->max_ttl);
    }
    if (ngx_strncmp(arg->data, "negative_ttl=", 13) == 0) {
        return dns_parse_time_arg(cf, arg, 13, &pol->negative_ttl);
    }
    if (ngx_strncmp(arg->data, "ipv4=", 5) == 0) {
        return dns_parse_flag_arg(cf, arg, 5, &pol->ipv4);
    }
    if (ngx_strncmp(arg->data, "ipv6=", 5) == 0) {
        return dns_parse_flag_arg(cf, arg, 5, &pol->ipv6);
    }
    if (ngx_strncmp(arg->data, "search=", 7) == 0) {
        return dns_parse_flag_arg(cf, arg, 7, &pol->search);
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "brix_resolver: unknown parameter \"%V\"", arg);
    return NGX_CONF_ERROR;
}


static brix_dns_policy_t *
dns_policy_create(ngx_conf_t *cf)
{
    brix_dns_policy_t  *pol;

    pol = ngx_pcalloc(cf->pool, sizeof(brix_dns_policy_t));
    if (pol == NULL) {
        return NULL;
    }
    ngx_str_set(&pol->path, BRIX_RESOLV_DEFAULT_PATH);
    pol->min_ttl = BRIX_DNS_MIN_TTL_DEFAULT;
    pol->max_ttl = BRIX_DNS_MAX_TTL_DEFAULT;
    pol->negative_ttl = BRIX_DNS_NEG_TTL_DEFAULT;
    pol->ipv4 = 1;
    pol->ipv6 = 1;
    pol->search = 1;
    return pol;
}


/* Fill the enclosing core scope's resolver slot when it is still empty. */
static void
dns_seed_core_slot(ngx_conf_t *cf, brix_dns_policy_t *pol)
{
    ngx_resolver_t  **slot = NULL;
    const char       *plane = "?";

    if (cf->module_type == NGX_HTTP_MODULE) {
        ngx_http_core_loc_conf_t *clcf;
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        slot = &clcf->resolver;
        plane = "http";
    } else if (cf->module_type == NGX_STREAM_MODULE) {
        ngx_stream_core_srv_conf_t *cscf;
        cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
        slot = &cscf->resolver;
        plane = "stream";
    }
    if (slot == NULL) {
        return;
    }
    if (*slot != NULL) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix_resolver: %s scope already has an explicit resolver; "
            "keeping it (brix targets still use resolv.conf)", plane);
        return;
    }
    *slot = pol->resolver;
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix_resolver: %s resolver seeded from %V (%ui nameserver%s, "
        "%ui search domain%s, ndots %ui)", plane, &pol->path,
        (ngx_uint_t) pol->rc.nnameservers,
        pol->rc.nnameservers == 1 ? "" : "s",
        (ngx_uint_t) pol->rc.nsearch, pol->rc.nsearch == 1 ? "" : "s",
        (ngx_uint_t) pol->rc.ndots);
}


static char *
dns_policy_activate(ngx_conf_t *cf, brix_dns_policy_t *pol)
{
    u_char  path[NGX_MAX_PATH];

    ngx_cpystrn(path, pol->path.data,
                ngx_min(pol->path.len + 1, sizeof(path)));
    if (brix_resolv_conf_load(&pol->rc, (const char *) path) != 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix_resolver: cannot read \"%V\" — using the libc defaults "
            "(nameserver 127.0.0.1); the server still starts", &pol->path);
    }
    if (pol->max_ttl < pol->min_ttl) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_resolver: max_ttl is below min_ttl");
        return NGX_CONF_ERROR;
    }
    pol->resolver = brix_dns_resolver_build(cf, pol);
    if (pol->resolver != NULL) {
        dns_seed_core_slot(cf, pol);
    }
#if (NGX_THREADS)
    /* the libc fallback path needs the default pool to exist */
    if (ngx_thread_pool_add(cf, NULL) == NULL) {
        return NGX_CONF_ERROR;
    }
#endif
    return NGX_CONF_OK;
}


char *
brix_conf_set_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_shared_conf_t  *c = conf;      /* member 0 of every brix module conf */
    ngx_str_t           *value = cf->args->elts;
    brix_dns_policy_t   *pol;
    ngx_uint_t           i;
    char                *rc;

    (void) cmd;
    if (c->dns.policy != NULL) {
        return "is duplicate";
    }
    pol = dns_policy_create(cf);
    if (pol == NULL) {
        return NGX_CONF_ERROR;
    }
    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        if (cf->args->nelts != 2) {
            return "off takes no parameters";
        }
        pol->mode = BRIX_DNS_MODE_OFF;
        c->dns.policy = pol;
        return NGX_CONF_OK;
    }
    if (value[1].len != 4 || ngx_strncmp(value[1].data, "auto", 4) != 0) {
        return "expects auto|off";
    }
    pol->mode = BRIX_DNS_MODE_AUTO;
    for (i = 2; i < cf->args->nelts; i++) {
        rc = dns_parse_option(cf, pol, &value[i]);
        if (rc != NGX_CONF_OK) {
            return rc;
        }
    }
    rc = dns_policy_activate(cf, pol);
    if (rc != NGX_CONF_OK) {
        return rc;
    }
    c->dns.policy = pol;
    return NGX_CONF_OK;
}


char *
brix_conf_set_dns_retry(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_shared_conf_t  *c = conf;
    ngx_str_t           *value = cf->args->elts;
    ngx_msec_t           initial, max;

    (void) cmd;
    if (c->dns.retry_initial != NGX_CONF_UNSET_MSEC) {
        return "is duplicate";
    }
    initial = ngx_parse_time(&value[1], 0);
    max = ngx_parse_time(&value[2], 0);
    if (initial == (ngx_msec_t) NGX_ERROR || max == (ngx_msec_t) NGX_ERROR) {
        return "invalid time value";
    }
    if (initial == 0 || max < initial) {
        return "expects <initial> <= <max>, both > 0";
    }
    c->dns.retry_initial = initial;
    c->dns.retry_max = max;
    return NGX_CONF_OK;
}


/*
 * brix_dns_cache_max <n> — bound both per-worker DNS answer caches.
 *
 * WHAT: parse the entry cap into the block's DNS conf and apply it to the
 *       forward and reverse caches straight away.
 * WHY:  the caches are per-process singletons.  Applying the bound when a
 *       runtime target is armed (the first shape of this knob) left it inert
 *       in a block that registers no hostname — including the reverse-DNS
 *       case, whose key space is the PEER's address and therefore the one
 *       that most needs a bound.
 * HOW:  parse time, in the master, so every forked worker inherits the value;
 *       one process holds one cache, so the last value parsed wins.
 */
char *
brix_conf_set_dns_cache_max(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_shared_conf_t  *c = conf;
    ngx_str_t           *value = cf->args->elts;
    ngx_int_t            n;

    (void) cmd;
    if (c->dns.cache_max != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }
    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR || n <= 0) {
        return "invalid number";
    }
    c->dns.cache_max = (ngx_uint_t) n;
    brix_dns_cache_set_max(c->dns.cache_max);
    brix_dns_reverse_cache_set_max(c->dns.cache_max);
    return NGX_CONF_OK;
}


/*
 * Config-time: guarantee that this configuration will have a runtime DNS
 * backend, for a feature that resolves a name brix_dns_target_register() never
 * saw — a peer's PTR (XrdAcc `h` rules, a protbind host template, `brix_auth
 * host`), a pmark firefly destination, a proxy upstream or a WebDAV proxy-pool
 * backend added through the admin API.
 *
 * WHY: with no `brix_resolver` the only backend either direction has is the
 *      thread-pool libc call, and ngx_thread_pool_get() declines when no pool
 *      was declared anywhere in the configuration.  brix_dns_resolve() and
 *      brix_dns_reverse() then answer "no resolver and no thread pool
 *      available", the failure is negative-cached, and the consumer silently
 *      degrades — an `h` rule stops granting, a firefly destination is never
 *      reached, a proxy backend is marked dead.  Before phase 116 the same
 *      lookups were blocking libc calls on the event loop, so they answered
 *      (and stalled the worker, which is why they had to go).
 * HOW: the same ngx_thread_pool_add(cf, NULL) that brix_conf_set_resolver()
 *      and brix_dns_target_register() already perform, so a config that
 *      resolves anything behaves identically however the name got there.  The
 *      pool is left at threads == 0 for ngx_thread_pool_init_conf() to fill
 *      with nginx's own defaults — pre-setting it would make a later
 *      `thread_pool default ...` directive fail as a duplicate.  Idempotent.
 *      Threadless builds keep the pre-existing degrade behaviour: they have no
 *      non-blocking backend to offer.
 */
char *
brix_dns_backend_prepare(ngx_conf_t *cf)
{
#if (NGX_THREADS)
    if (ngx_thread_pool_add(cf, NULL) == NULL) {
        return NGX_CONF_ERROR;
    }
#else
    (void) cf;
#endif
    return NGX_CONF_OK;
}
