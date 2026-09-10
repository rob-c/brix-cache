/*
 * resolver_build.c — nginx resolver from resolv.conf (phase-116 W1.2).
 *
 * WHAT: brix_dns_resolver_build() turns a parsed brix_resolv_conf_t plus the
 *       directive's TTL/family knobs into an ngx_resolver_t exactly as a
 *       hand-written `resolver a b c valid=... ipv4=... ipv6=...;` would.
 * WHY:  Reusing ngx_resolver_create() keeps the wire client, caching,
 *       resend and TCP-fallback logic nginx's own; brix only supplies the
 *       arguments the operator used to type.
 * HOW:  Build the argument vector (bare IPv6 nameservers re-bracketed,
 *       `ip:port` tokens passed through, the resolv.conf `timeout` mapped to
 *       resend_timeout), call
 *       ngx_resolver_create(), then set the post-create fields the directive
 *       grammar cannot express.  A resolv.conf with zero usable nameservers
 *       (all four dropped/invalid) yields NULL and the caller falls back to
 *       the thread-pool libc path — never a start failure.
 */
#include "net/dns/dns.h"

#define DNS_RESOLVER_MAX_ARGS  (BRIX_RESOLV_MAX_NS + 3)


/* One `resolver` argument per resolv.conf nameserver token.  Verbatim for
 * IPv4, for an already-bracketed IPv6 and for the brix `ip:port` extension
 * (exactly one colon: glibc has no port syntax, but a local forwarder or an
 * unprivileged test stub needs one); a bare IPv6 token is bracketed so nginx
 * does not split it as host:port.  NGX_ERROR only when it will not fit. */
static ngx_int_t
dns_build_nameserver_arg(ngx_conf_t *cf, const char *ns, ngx_str_t *out)
{
    size_t       len = ngx_strlen(ns);
    u_char      *p;
    const char  *colon = ngx_strchr(ns, ':');

    if (colon == NULL || ns[0] == '[' || ngx_strchr(colon + 1, ':') == NULL) {
        out->data = (u_char *) ns;
        out->len = len;
        return NGX_OK;
    }
    p = ngx_pnalloc(cf->pool, len + 3);
    if (p == NULL) {
        return NGX_ERROR;
    }
    out->data = p;
    out->len = ngx_sprintf(p, "[%s]", ns) - p;
    return NGX_OK;
}


static ngx_int_t
dns_build_option_args(ngx_conf_t *cf, const brix_dns_policy_t *pol,
    ngx_str_t *names, ngx_uint_t *n)
{
    u_char  *p;

    if (pol->valid >= 1000) {
        p = ngx_pnalloc(cf->pool, 32);
        if (p == NULL) {
            return NGX_ERROR;
        }
        names[*n].data = p;
        /* ngx_resolver_create parses valid= in whole seconds (no ms unit) */
        names[*n].len = ngx_sprintf(p, "valid=%Ts", (time_t) (pol->valid / 1000)) - p;
        (*n)++;
    }
    if (!pol->ipv4) {
        ngx_str_set(&names[*n], "ipv4=off");
        (*n)++;
    }
    if (!pol->ipv6) {
        ngx_str_set(&names[*n], "ipv6=off");
        (*n)++;
    }
    return NGX_OK;
}


ngx_resolver_t *
brix_dns_resolver_build(ngx_conf_t *cf, brix_dns_policy_t *pol)
{
    ngx_str_t       names[DNS_RESOLVER_MAX_ARGS];
    ngx_uint_t      i, n = 0;
    ngx_resolver_t *r;

    for (i = 0; i < pol->rc.nnameservers; i++) {
        if (dns_build_nameserver_arg(cf, pol->rc.nameservers[i], &names[n])
            != NGX_OK)
        {
            return NULL;
        }
        n++;
    }
    if (n == 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix_resolver: no nameserver in \"%V\" — hostnames fall back "
            "to the libc resolver on the thread pool", &pol->path);
        return NULL;
    }
    if (dns_build_option_args(cf, pol, names, &n) != NGX_OK) {
        return NULL;
    }

    r = ngx_resolver_create(cf, names, n);
    if (r == NULL) {
        return NULL;
    }
    /* resolv.conf `options timeout:N` is the per-query resend interval */
    r->resend_timeout = (time_t) pol->rc.timeout;
    return r;
}
