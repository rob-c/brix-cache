/*
 * reverse.c — the reverse (PTR) resolve driver (phase-116 W7).
 *
 * WHAT: brix_dns_reverse(): address-keyed cache probe, then either the
 *       policy's nginx resolver (ngx_resolve_addr, async) or a thread-pool
 *       getnameinfo(NI_NAMEREQD) — the ONLY such call in src/ (guard
 *       tools/ci/check_dns_seam.py).  brix_dns_reverse_cached() is the
 *       never-blocking probe the event loop uses at decision time,
 *       brix_dns_reverse_prefetch() warms the cache from the accept/login
 *       hooks, and brix_dns_reverse_sync() is the blocking flavour for
 *       thread-pool code (cache -> loop resolver via the bridge -> libc).
 * WHY:  XrdAcc `h` rules, protbind hostname templates, `host` auth and the
 *       TPC origin id all need the peer's FQDN.  Resolving it inline on the
 *       event loop stalled the whole worker on a slow nameserver (I-DNS-1);
 *       a per-connection thread hop would still serialize every decision
 *       behind a round trip.  Warming an address-keyed cache from the accept
 *       path makes the common case a lookup, and consumers degrade to the
 *       peer IP — never to a stall — when the answer is not ready.
 * HOW:  Mirrors resolve.c/resolve_thread.c: the nginx ctx is kept in
 *       req->rctx so a cancel can ngx_resolve_addr_done() it; ngx_resolve_addr
 *       frees the ctx itself on NGX_ERROR and may run the handler inline for
 *       a cached node (ctx->name is then a resolver-owned copy released after
 *       the handler returns, so it is copied out by length).  The thread task
 *       owns its allocation and the body reads only its copies.  Every
 *       failure is negative-cached for the policy's negative TTL so a dead
 *       PTR zone is asked once per TTL, not once per connection; positive
 *       answers keep the record TTL clamped to the policy window.
 */
#include "net/dns/dns.h"
#include "core/aio/aio.h"

#include <netdb.h>

#define DNS_REV_TIMEOUT_FLOOR_MS  1000

typedef struct {
    brix_dns_rev_req_t       *req;   /* loop-only; NULL once cancelled */
    ngx_pool_t               *pool;  /* owns the task + this ctx */
    struct sockaddr_storage   ss;
    socklen_t                 len;
    char                      name[BRIX_DNS_REVERSE_NAME_LEN];
    ngx_int_t                 rc;
} dns_rev_thread_ctx_t;


static time_t
dns_rev_negative_ttl(const brix_dns_policy_t *policy)
{
    return policy ? policy->negative_ttl : BRIX_DNS_NEG_TTL_DEFAULT;
}


static time_t
dns_rev_clamp_ttl(const brix_dns_policy_t *policy, time_t ttl)
{
    if (policy != NULL) {
        if (ttl < policy->min_ttl) {
            ttl = policy->min_ttl;
        }
        if (ttl > policy->max_ttl) {
            ttl = policy->max_ttl;
        }
        return ttl;
    }
    return ttl < BRIX_DNS_MIN_TTL_DEFAULT ? BRIX_DNS_MIN_TTL_DEFAULT : ttl;
}


/* The libc reverse lookup.  NGX_OK name / NGX_DECLINED no PTR / NGX_ERROR. */
static ngx_int_t
dns_libc_reverse(const struct sockaddr *sa, socklen_t len, char *buf,
    size_t buflen)
{
    int  rc = getnameinfo(sa, len, buf, buflen, NULL, 0, NI_NAMEREQD);

    if (rc == 0) {
        return NGX_OK;
    }
    return rc == EAI_NONAME ? NGX_DECLINED : NGX_ERROR;
}


static unsigned
dns_rev_addr_supported(const struct sockaddr_storage *ss, socklen_t len)
{
    if (ss->ss_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        return 1;
    }
#if (NGX_HAVE_INET6)
    if (ss->ss_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
        return 1;
    }
#endif
    return 0;
}


/* ---- request completion -------------------------------------------------- */

void
brix_dns_rev_req_finish(brix_dns_rev_req_t *req)
{
    req->rctx = NULL;
    req->task = NULL;
    if (req->rc != NGX_OK) {
        req->name[0] = '\0';
    }
    if (!req->cached && req->ttl > 0) {
        brix_dns_rcache_store((struct sockaddr *) &req->ss, req->len,
                              req->rc == NGX_OK ? req->name : NULL, req->ttl);
    }
    req->handler(req);
}


static void
dns_rev_fail(brix_dns_rev_req_t *req, ngx_int_t rc, const char *error)
{
    req->rc = rc;
    req->error = error;
    req->ttl = dns_rev_negative_ttl(req->policy);
    brix_dns_rev_req_finish(req);
}


/* ---- nginx resolver backend --------------------------------------------- */

static void
dns_rev_ngx_handler(ngx_resolver_ctx_t *ctx)
{
    brix_dns_rev_req_t  *req = ctx->data;
    size_t               n;

    req->rctx = NULL;
    if (ctx->state != NGX_OK || ctx->name.len == 0) {
        ngx_int_t  rc = ctx->state == NGX_RESOLVE_NXDOMAIN ? NGX_DECLINED
                                                           : NGX_ERROR;
        const char *error = ngx_resolver_strerror(ctx->state);

        ngx_resolve_addr_done(ctx);
        dns_rev_fail(req, rc, error);
        return;
    }
    n = ngx_min(ctx->name.len, sizeof(req->name) - 1);
    ngx_memcpy(req->name, ctx->name.data, n);
    req->name[n] = '\0';
    req->ttl = dns_rev_clamp_ttl(req->policy, ctx->valid - ngx_time());
    req->rc = NGX_OK;
    req->error = NULL;
    ngx_resolve_addr_done(ctx);
    brix_dns_rev_req_finish(req);
}


static ngx_int_t
dns_rev_ngx_start(brix_dns_rev_req_t *req, ngx_resolver_t *r)
{
    ngx_resolver_ctx_t  *ctx;
    ngx_msec_t           timeout;

    ctx = ngx_resolve_start(r, NULL);
    if (ctx == NULL || ctx == NGX_NO_RESOLVER) {
        dns_rev_fail(req, NGX_ERROR, "resolver unavailable");
        return NGX_OK;
    }
    timeout = (ngx_msec_t) (req->policy ? req->policy->rc.timeout : 5) * 1000;
    if (timeout < DNS_REV_TIMEOUT_FLOOR_MS) {
        timeout = DNS_REV_TIMEOUT_FLOOR_MS;
    }
    ctx->addr.sockaddr = (struct sockaddr *) &req->ss;
    ctx->addr.socklen = req->len;
    ctx->handler = dns_rev_ngx_handler;
    ctx->data = req;
    ctx->timeout = timeout;
    req->rctx = ctx;
    if (ngx_resolve_addr(ctx) != NGX_OK) {
        /* nginx freed the ctx and did not run the handler */
        req->rctx = NULL;
        dns_rev_fail(req, NGX_ERROR, "resolver could not be started");
    }
    return NGX_OK;
}


/* ---- public: async ------------------------------------------------------- */

ngx_int_t
brix_dns_reverse(brix_dns_rev_req_t *req)
{
    ngx_resolver_t  *r;
    ngx_int_t        rc;

    req->rc = NGX_ERROR;
    req->error = NULL;
    req->name[0] = '\0';
    req->ttl = 0;
    req->cached = 0;
    req->rctx = NULL;
    req->task = NULL;
    if (req->log == NULL) {
        req->log = ngx_cycle->log;
    }
    if (!dns_rev_addr_supported(&req->ss, req->len)) {
        req->rc = NGX_DECLINED;
        req->error = "peer is not an IP address";
        brix_dns_rev_req_finish(req);
        return NGX_OK;
    }
    rc = brix_dns_rcache_lookup((struct sockaddr *) &req->ss, req->len,
                                req->name, sizeof(req->name));
    if (rc != NGX_AGAIN) {
        req->cached = 1;
        req->rc = rc;
        req->error = rc == NGX_OK ? NULL : "no PTR record (negative cache)";
        brix_dns_rev_req_finish(req);
        return NGX_OK;
    }
    r = brix_dns_policy_resolver(req->policy);
    if (r != NULL) {
        return dns_rev_ngx_start(req, r);
    }
    rc = brix_dns_reverse_via_thread(req);
    if (rc == NGX_OK) {
        return NGX_OK;
    }
    if (rc == NGX_DECLINED) {
        dns_rev_fail(req, NGX_ERROR, "no resolver and no thread pool available");
        return NGX_OK;
    }
    return NGX_ERROR;
}


void
brix_dns_reverse_cancel(brix_dns_rev_req_t *req)
{
    if (req->rctx != NULL) {
        ngx_resolve_addr_done(req->rctx);
        req->rctx = NULL;
    }
    brix_dns_reverse_thread_detach(req);
}


/* ---- public: event-loop probe + prefetch --------------------------------- */

ngx_int_t
brix_dns_reverse_cached(const struct sockaddr *sa, socklen_t len, char *buf,
    size_t buflen)
{
    return brix_dns_rcache_lookup(sa, len, buf, buflen);
}


static void
dns_rev_prefetch_done(brix_dns_rev_req_t *req)
{
    if (req->rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_INFO, req->log, 0,
                      "brix dns: reverse lookup failed: %s",
                      req->error ? req->error : "unknown");
    }
    ngx_free(req);
}


void
brix_dns_reverse_prefetch(const brix_dns_policy_t *policy,
    const struct sockaddr *sa, socklen_t len)
{
    brix_dns_rev_req_t  *req;
    time_t               hold = BRIX_DNS_PENDING_HOLD;

    if (sa == NULL || len == 0 || len > sizeof(req->ss)) {
        return;
    }
    if (policy != NULL) {
        time_t  budget = (time_t) policy->rc.timeout * policy->rc.attempts + 1;

        hold = ngx_max(hold, budget);
    }
    if (!brix_dns_rcache_mark_pending(sa, len, hold)) {
        return;                              /* cached, negative or in flight */
    }
    req = ngx_calloc(sizeof(brix_dns_rev_req_t), ngx_cycle->log);
    if (req == NULL) {
        return;
    }
    ngx_memcpy(&req->ss, sa, len);
    req->len = len;
    req->policy = policy;
    req->log = ngx_cycle->log;         /* the fill may outlive its caller */
    req->handler = dns_rev_prefetch_done;
    if (brix_dns_reverse(req) != NGX_OK) {
        ngx_free(req);                       /* handler did not run */
    }
}


/* ---- public: blocking (thread-pool code) --------------------------------- */

ngx_int_t
brix_dns_reverse_sync(const brix_dns_policy_t *policy,
    const struct sockaddr *sa, socklen_t len, char *buf, size_t buflen)
{
    ngx_int_t  rc, answer = NGX_ERROR;
    time_t     ttl;

    if (buf == NULL || buflen == 0) {
        return NGX_ERROR;
    }
    buf[0] = '\0';
    if (sa == NULL || !dns_rev_addr_supported((const struct sockaddr_storage *)
                                              sa, len))
    {
        return NGX_DECLINED;
    }
    rc = brix_dns_rcache_lookup(sa, len, buf, buflen);
    if (rc != NGX_AGAIN) {
        return rc;
    }
    if (brix_dns_bridge_reverse(policy, sa, len, buf, buflen, &answer)
        == NGX_OK)
    {
        return answer;                       /* the loop driver cached it */
    }
    rc = dns_libc_reverse(sa, len, buf, buflen);
    ttl = rc == NGX_OK ? dns_rev_clamp_ttl(policy, BRIX_DNS_THREAD_TTL)
                       : dns_rev_negative_ttl(policy);
    brix_dns_rcache_store(sa, len, rc == NGX_OK ? buf : NULL, ttl);
    return rc;
}


/* ---- thread-pool backend of brix_dns_reverse() --------------------------- */

#if (NGX_THREADS)

static void
dns_rev_thread_run(void *data, ngx_log_t *log)
{
    dns_rev_thread_ctx_t  *tc = data;

    (void) log;
    tc->rc = dns_libc_reverse((struct sockaddr *) &tc->ss, tc->len, tc->name,
                              sizeof(tc->name));
}


static void
dns_rev_thread_done(ngx_event_t *ev)
{
    ngx_thread_task_t     *task = ev->data;
    dns_rev_thread_ctx_t  *tc = task->ctx;
    brix_dns_rev_req_t    *req = tc->req;
    ngx_pool_t            *pool = tc->pool;

    if (req == NULL) {
        ngx_destroy_pool(pool);              /* cancelled while in flight */
        return;
    }
    req->task = NULL;
    if (tc->rc == NGX_OK) {
        ngx_cpystrn((u_char *) req->name, (u_char *) tc->name,
                    sizeof(req->name));
        req->rc = NGX_OK;
        req->error = NULL;
        req->ttl = dns_rev_clamp_ttl(req->policy, BRIX_DNS_THREAD_TTL);
        brix_dns_rev_req_finish(req);
    } else {
        dns_rev_fail(req, tc->rc, tc->rc == NGX_DECLINED
                                  ? "no PTR record" : "getnameinfo failed");
    }
    ngx_destroy_pool(pool);
}

#endif


ngx_int_t
brix_dns_reverse_via_thread(brix_dns_rev_req_t *req)
{
#if (NGX_THREADS)
    ngx_thread_task_t     *task;
    dns_rev_thread_ctx_t  *tc;
    ngx_thread_pool_t     *tp;
    ngx_pool_t            *pool;
    ngx_int_t              rc;

    rc = brix_dns_thread_task_new(req->log, sizeof(dns_rev_thread_ctx_t),
                                  &tp, &pool, &task);
    if (rc != NGX_OK) {
        return rc;
    }
    tc = task->ctx;
    tc->req = req;
    tc->pool = pool;
    ngx_memcpy(&tc->ss, &req->ss, req->len);
    tc->len = req->len;
    brix_task_bind(task, dns_rev_thread_run, dns_rev_thread_done);
    task->event.log = req->log;
    return brix_dns_thread_task_post(tp, task, pool, &req->task);
#else
    (void) req;
    return NGX_DECLINED;
#endif
}


void
brix_dns_reverse_thread_detach(brix_dns_rev_req_t *req)
{
#if (NGX_THREADS)
    ngx_thread_task_t     *task = req->task;
    dns_rev_thread_ctx_t  *tc;

    if (task == NULL) {
        return;
    }
    tc = task->ctx;
    tc->req = NULL;                          /* the completion frees the pool */
    req->task = NULL;
#else
    req->task = NULL;
#endif
}
