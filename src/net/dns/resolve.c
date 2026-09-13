/*
 * resolve.c — the async resolve driver (phase-116 W2).
 *
 * WHAT: brix_dns_resolve(): IP-literal short-circuit, cache lookup, then
 *       either nginx's resolver (with resolv.conf search/ndots expansion and
 *       glibc-style attempts) or the thread-pool libc backend; answers are
 *       family-filtered, port-stamped, TTL-clamped and cached before the
 *       caller's handler runs.  brix_dns_resolve_cancel() abandons a request
 *       whose owner is going away.  Also the pool-free literal parser and
 *       numeric formatter every other layer shares.
 * WHY:  nginx's resolver knows nothing about search lists — `ngx_resolve_name`
 *       on "storage01" asks for the literal label and fails where `getent`
 *       succeeds.  Driving the candidate list here gives every brix hostname
 *       the same semantics as the host resolver (I-DNS-3) while staying fully
 *       asynchronous (I-DNS-4).  ngx_parse_addr() allocates from a pool, which
 *       a per-resolve caller cannot afford — hence the pool-free literal path.
 * HOW:  Candidates follow glibc: with >= ndots dots (or a trailing dot) the
 *       absolute name is tried first, then each search suffix; otherwise the
 *       search suffixes come first and the absolute name last.  NXDOMAIN moves
 *       to the next candidate; TIMEDOUT/SERVFAIL retries the same candidate
 *       up to `attempts` times.  Each hop is re-entered through a posted
 *       event so the next ngx_resolve_name() never runs inside the previous
 *       resolver callback.  The in-flight nginx ctx is kept in req->rctx so a
 *       cancel can ngx_resolve_name_done() it; ngx_resolve_name() frees the
 *       ctx itself on NGX_ERROR and may run the handler inline on a resolver
 *       cache hit, so rctx is cleared inside the handler, never after the
 *       call.  The handler is invoked exactly once per request.
 */
#include "net/dns/dns.h"

#define DNS_TIMEOUT_FLOOR_MS  BRIX_DNS_TIMEOUT_FLOOR_MS


const char *
brix_dns_state_name(ngx_uint_t state)
{
    switch (state) {
    case BRIX_DNS_STATE_RESOLVED:  return "resolved";
    case BRIX_DNS_STATE_FAILED:    return "failed";
    default:                       return "resolving";
    }
}


void
brix_dns_conf_init(brix_dns_conf_t *dns)
{
    dns->policy = NULL;
    dns->retry_initial = NGX_CONF_UNSET_MSEC;
    dns->retry_max = NGX_CONF_UNSET_MSEC;
    dns->cache_max = NGX_CONF_UNSET_UINT;
    ngx_str_null(&dns->status_zone);
}


void
brix_dns_conf_adopt(brix_dns_conf_t *dst, const brix_dns_conf_t *src)
{
    if (dst->policy == NULL) {
        dst->policy = src->policy;
    }
    if (dst->retry_initial == NGX_CONF_UNSET_MSEC) {
        dst->retry_initial = src->retry_initial;
    }
    if (dst->retry_max == NGX_CONF_UNSET_MSEC) {
        dst->retry_max = src->retry_max;
    }
    if (dst->cache_max == NGX_CONF_UNSET_UINT) {
        dst->cache_max = src->cache_max;
    }
    if (dst->status_zone.data == NULL) {
        dst->status_zone = src->status_zone;
    }
}


ngx_resolver_t *
brix_dns_policy_resolver(const brix_dns_policy_t *policy)
{
    ngx_resolver_t  *r;

    if (policy == NULL || policy->mode != BRIX_DNS_MODE_AUTO) {
        return NULL;
    }
    r = policy->resolver;
    if (r == NULL || r->connections.nelts == 0) {
        return NULL;
    }
    return r;
}


/* ---- address helpers ----------------------------------------------------- */

ngx_int_t
brix_dns_parse_literal(const ngx_str_t *name, brix_dns_addr_t *out)
{
    u_char               *p = name->data;
    size_t                len = name->len;
    struct sockaddr_in   *sin;
    in_addr_t             inaddr;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
    struct in6_addr       in6;
#endif

    if (len == 0) {
        return NGX_DECLINED;
    }
    if (len > 2 && p[0] == '[' && p[len - 1] == ']') {
        p++;
        len -= 2;
    }
    ngx_memzero(out, sizeof(*out));
    inaddr = ngx_inet_addr(p, len);
    if (inaddr != INADDR_NONE) {
        sin = (struct sockaddr_in *) &out->ss;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = inaddr;
        out->len = sizeof(struct sockaddr_in);
        return NGX_OK;
    }
#if (NGX_HAVE_INET6)
    if (ngx_inet6_addr(p, len, in6.s6_addr) == NGX_OK) {
        sin6 = (struct sockaddr_in6 *) &out->ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = in6;
        out->len = sizeof(struct sockaddr_in6);
        return NGX_OK;
    }
#endif
    return NGX_DECLINED;
}


size_t
brix_dns_addr_ntop(const brix_dns_addr_t *addr, char *buf, size_t sz)
{
    size_t  n;

    if (sz == 0) {
        return 0;
    }
    n = ngx_sock_ntop((struct sockaddr *) &addr->ss, addr->len,
                      (u_char *) buf, sz - 1, 0);
    buf[n] = '\0';
    return n;
}


/* ---- request completion -------------------------------------------------- */

/* Terminal step shared by every backend: shape, cache, notify. */
void
brix_dns_req_finish(brix_dns_req_t *req)
{
    ngx_uint_t  i;

    req->rctx = NULL;
    req->task = NULL;
    if (req->rc == NGX_OK) {
        for (i = 0; i < req->naddrs; i++) {
            ngx_inet_set_port((struct sockaddr *) &req->addrs[i].ss,
                              req->port);
        }
    }
    if (!req->cached && !req->literal) {
        brix_dns_cache_store(req);
    }
    req->handler(req);
}


static ngx_int_t
dns_try_literal(brix_dns_req_t *req)
{
    brix_dns_addr_t  a;

    if (brix_dns_parse_literal(&req->name, &a) != NGX_OK) {
        return NGX_DECLINED;
    }
    if ((req->af == BRIX_AF_INET && a.ss.ss_family != AF_INET)
        || (req->af == BRIX_AF_INET6 && a.ss.ss_family != AF_INET6))
    {
        req->rc = NGX_ERROR;
        req->error = "address family excluded by policy";
        req->naddrs = 0;
    } else {
        req->addrs[0] = a;
        req->naddrs = 1;
        req->rc = NGX_OK;
    }
    req->literal = 1;
    req->ttl = 0;
    return NGX_OK;
}


static ngx_resolver_t *
dns_usable_resolver(const brix_dns_req_t *req)
{
    ngx_resolver_t  *r = brix_dns_policy_resolver(req->policy);

    if (r != NULL) {
        return r;
    }
    r = req->resolver;
    if (r == NULL || r->connections.nelts == 0) {
        return NULL;
    }
    return r;
}


/* glibc candidate ordering (see file header). */
static ngx_uint_t
dns_candidate_count(const brix_dns_req_t *req)
{
    const brix_resolv_conf_t *rc;

    if (req->policy == NULL || !req->policy->search) {
        return 1;
    }
    rc = &req->policy->rc;
    return 1 + rc->nsearch;
}


static void
dns_candidate_name(brix_dns_req_t *req, ngx_uint_t idx)
{
    const brix_resolv_conf_t *rc;
    unsigned                  dots, absolute_first;
    ngx_uint_t                suffix;
    size_t                    len = req->name.len;

    if (len > 0 && req->name.data[len - 1] == '.') {
        len--;
    }
    if (req->policy == NULL || !req->policy->search || idx >= req->ncand) {
        ngx_memcpy(req->cbuf, req->name.data, len);
        req->cname.data = req->cbuf;
        req->cname.len = len;
        return;
    }
    rc = &req->policy->rc;
    dots = brix_resolv_conf_count_dots((const char *) req->name.data,
                                       req->name.len);
    absolute_first = (dots >= rc->ndots)
                     || (req->name.len > 0
                         && req->name.data[req->name.len - 1] == '.');

    if ((absolute_first && idx == 0) || (!absolute_first && idx == rc->nsearch)) {
        ngx_memcpy(req->cbuf, req->name.data, len);
        req->cname.data = req->cbuf;
        req->cname.len = len;
        return;
    }
    suffix = absolute_first ? idx - 1 : idx;
    req->cname.data = req->cbuf;
    req->cname.len = ngx_sprintf(req->cbuf, "%*s.%s", len, req->name.data,
                                 rc->search[suffix]) - req->cbuf;
}


static void dns_ngx_step(ngx_event_t *ev);


static void
dns_ngx_fail(brix_dns_req_t *req, ngx_int_t state)
{
    req->rc = NGX_ERROR;
    req->state = state;
    req->error = (const char *) ngx_resolver_strerror(state);
    req->naddrs = 0;
    req->ttl = req->policy ? req->policy->negative_ttl
                           : BRIX_DNS_NEG_TTL_DEFAULT;
    /* only a definitive "no such name" is worth negative-caching */
    if (state != NGX_RESOLVE_NXDOMAIN) {
        req->ttl = 0;
    }
    brix_dns_req_finish(req);
}


static void
dns_ngx_copy_answer(brix_dns_req_t *req, ngx_resolver_ctx_t *ctx)
{
    ngx_uint_t  i, n = 0;
    time_t      ttl;

    for (i = 0; i < ctx->naddrs && n < BRIX_DNS_MAX_ADDRS; i++) {
        struct sockaddr *sa = ctx->addrs[i].sockaddr;

        if ((req->af == BRIX_AF_INET && sa->sa_family != AF_INET)
            || (req->af == BRIX_AF_INET6 && sa->sa_family != AF_INET6)
            || ctx->addrs[i].socklen > sizeof(req->addrs[n].ss))
        {
            continue;
        }
        ngx_memcpy(&req->addrs[n].ss, sa, ctx->addrs[i].socklen);
        req->addrs[n].len = ctx->addrs[i].socklen;
        n++;
    }
    req->naddrs = n;
    ttl = ctx->valid - ngx_time();
    if (req->policy != NULL) {
        if (ttl < req->policy->min_ttl) {
            ttl = req->policy->min_ttl;
        }
        if (ttl > req->policy->max_ttl) {
            ttl = req->policy->max_ttl;
        }
    } else if (ttl < BRIX_DNS_MIN_TTL_DEFAULT) {
        ttl = BRIX_DNS_MIN_TTL_DEFAULT;
    }
    req->ttl = ttl;
}


/* metric class of one completed nginx-resolver query */
static ngx_uint_t
dns_ngx_result(ngx_int_t state, ngx_uint_t naddrs)
{
    if (state == NGX_OK) {
        return naddrs > 0 ? BRIX_DNS_RESULT_OK : BRIX_DNS_RESULT_NXDOMAIN;
    }
    if (state == NGX_RESOLVE_NXDOMAIN) {
        return BRIX_DNS_RESULT_NXDOMAIN;
    }
    if (state == NGX_RESOLVE_TIMEDOUT) {
        return BRIX_DNS_RESULT_TIMEOUT;
    }
    return BRIX_DNS_RESULT_ERROR;
}


/* nginx resolver callback: decide, release the ctx, then re-enter via a
 * posted event so the next ngx_resolve_name() runs outside this callback. */
static void
dns_ngx_handler(ngx_resolver_ctx_t *ctx)
{
    brix_dns_req_t  *req = ctx->data;
    ngx_int_t        state = ctx->state;
    ngx_uint_t       attempts = req->policy ? req->policy->rc.attempts : 1;

    req->rctx = NULL;
    brix_dns_lookup_note(dns_ngx_result(state, ctx->naddrs));
    if (state == NGX_OK && ctx->naddrs > 0) {
        dns_ngx_copy_answer(req, ctx);
        ngx_resolve_name_done(ctx);
        if (req->naddrs == 0) {
            req->rc = NGX_ERROR;
            req->error = "no address in the requested family";
            req->naddrs = 0;
            brix_dns_req_finish(req);
            return;
        }
        req->rc = NGX_OK;
        req->error = NULL;
        brix_dns_req_finish(req);
        return;
    }
    ngx_resolve_name_done(ctx);

    if ((state == NGX_RESOLVE_TIMEDOUT || state == NGX_RESOLVE_SERVFAIL)
        && req->attempt + 1 < attempts)
    {
        req->attempt++;                      /* retry the same candidate */
    } else if (req->cand + 1 < req->ncand) {
        req->cand++;                         /* next search candidate */
        req->attempt = 0;
    } else {
        dns_ngx_fail(req, state == NGX_OK ? NGX_RESOLVE_NXDOMAIN : state);
        return;
    }
    req->ev.handler = dns_ngx_step;
    req->ev.data = req;
    req->ev.log = req->log;
    ngx_post_event(&req->ev, &ngx_posted_events);
}


static void
dns_ngx_step(ngx_event_t *ev)
{
    brix_dns_req_t      *req = ev->data;
    ngx_resolver_t      *r = dns_usable_resolver(req);
    ngx_resolver_ctx_t  *ctx, temp;
    ngx_msec_t           timeout;

    if (r == NULL) {
        dns_ngx_fail(req, NGX_RESOLVE_TIMEDOUT);
        return;
    }
    dns_candidate_name(req, req->cand);
    temp.name = req->cname;
    ctx = ngx_resolve_start(r, &temp);
    if (ctx == NULL || ctx == NGX_NO_RESOLVER) {
        dns_ngx_fail(req, NGX_RESOLVE_TIMEDOUT);
        return;
    }
    timeout = (ngx_msec_t) (req->policy ? req->policy->rc.timeout : 5) * BRIX_CMS_SEC_TO_MS_MULTIPLIER;
    if (timeout < BRIX_DNS_TIMEOUT_FLOOR_MS) {
        timeout = BRIX_DNS_TIMEOUT_FLOOR_MS;
    }
    ctx->name = req->cname;
    ctx->handler = dns_ngx_handler;
    ctx->data = req;
    ctx->timeout = timeout;
    req->rctx = ctx;
    if (ngx_resolve_name(ctx) != NGX_OK) {
        /* nginx freed the ctx and did not run the handler */
        req->rctx = NULL;
        dns_ngx_fail(req, NGX_RESOLVE_TIMEDOUT);
    }
}


ngx_int_t
brix_dns_resolve(brix_dns_req_t *req)
{
    ngx_int_t  rc;

    req->rc = NGX_ERROR;
    req->error = NULL;
    req->naddrs = 0;
    req->ttl = 0;
    req->cached = 0;
    req->literal = 0;
    req->negative = 0;
    req->cand = 0;
    req->attempt = 0;
    req->rctx = NULL;
    req->task = NULL;
    if (req->socktype == 0) {
        req->socktype = SOCK_STREAM;
    }
    if (req->log == NULL) {
        req->log = ngx_cycle->log;
    }
    if (req->name.len == 0 || req->name.len >= BRIX_RESOLV_DOMAIN_LEN) {
        req->error = "empty or over-long hostname";
        brix_dns_req_finish(req);
        return NGX_OK;
    }

    if (dns_try_literal(req) == NGX_OK || brix_dns_cache_lookup(req) == NGX_OK) {
        brix_dns_req_finish(req);
        return NGX_OK;
    }

    if (dns_usable_resolver(req) != NULL) {
        req->ncand = dns_candidate_count(req);
        req->ev.handler = dns_ngx_step;
        req->ev.data = req;
        req->ev.log = req->log;
        dns_ngx_step(&req->ev);
        return NGX_OK;
    }

    rc = brix_dns_resolve_via_thread(req);
    if (rc == NGX_OK) {
        return NGX_OK;
    }
    if (rc == NGX_DECLINED) {
        req->error = "no resolver and no thread pool available";
        brix_dns_req_finish(req);
        return NGX_OK;
    }
    return NGX_ERROR;
}


void
brix_dns_resolve_cancel(brix_dns_req_t *req)
{
    if (req->rctx != NULL) {
        ngx_resolve_name_done(req->rctx);
        req->rctx = NULL;
    }
    if (req->ev.posted) {
        ngx_delete_posted_event(&req->ev);
    }
    brix_dns_thread_detach(req);
}
