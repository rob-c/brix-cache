/*
 * resolve_thread.c — the one libc resolver call, and the blocking entry
 * point thread-pool code uses (phase-116 W4 + Appendix A).
 *
 * WHAT: dns_libc_resolve() is the ONLY getaddrinfo() in src/ (guard
 *       tools/ci/check_dns_seam.py).  Two callers use it:
 *         - the thread-pool backend of brix_dns_resolve() (no usable nginx
 *           resolver in scope): a task posted to the "default" pool whose
 *           body resolves and whose completion finishes the request on the
 *           event loop;
 *         - brix_dns_resolve_sync(): the blocking flavour for thread-pool
 *           code (net_target pin, TPC/cache-origin/gsiftp connects, cvmfs
 *           probes, curl pinning), which tries an IP literal, the per-worker
 *           cache, the loop's nginx resolver via the bridge, and only then
 *           libc — so with `brix_resolver auto` even blocking callers follow
 *           the resolv.conf the operator pointed brix at.
 * WHY:  I-DNS-4: no getaddrinfo on the event loop.  Where the operator has
 *       not enabled brix_resolver, libc is still the right authority — it
 *       reads resolv.conf, nsswitch and /etc/hosts — it just may not block a
 *       worker.  Confining the call to one file makes the seam auditable.
 * HOW:  The thread task owns its allocation (a private pool destroyed by the
 *       completion) so a request needs no pool and can be cancelled: cancel
 *       clears tc->req and the completion finds nothing to finish.  The
 *       thread body reads only the copies in its ctx, never the request.
 *       libc answers carry no TTL, so they are cached for BRIX_DNS_THREAD_TTL
 *       seconds; only a definitive "no such name" is negative-cached.
 */
#include "net/dns/dns.h"
#include "core/aio/aio.h"

#include <netdb.h>

typedef struct {
    brix_dns_req_t   *req;          /* loop-only; NULL once cancelled */
    ngx_pool_t       *pool;         /* owns the task + this ctx */
    char              host[BRIX_RESOLV_DOMAIN_LEN];
    in_port_t         port;
    brix_af_policy_t  af;
    int               socktype;
    char              err[BRIX_DNS_ERROR_LEN];
    ngx_uint_t        naddrs;
    brix_dns_addr_t   addrs[BRIX_DNS_MAX_ADDRS];
    unsigned          definitive:1; /* failure was NXDOMAIN-class */
} dns_thread_ctx_t;


/* EAI_* -> BRIX_DNS_RESULT_* : NXDOMAIN is the only class safe to
 * negative-cache; EAI_AGAIN is the libc spelling of a timed-out query. */
static ngx_uint_t
dns_libc_result(int rc)
{
    if (rc == EAI_NONAME
#ifdef EAI_NODATA
        || rc == EAI_NODATA
#endif
        )
    {
        return BRIX_DNS_RESULT_NXDOMAIN;
    }
    return rc == EAI_AGAIN ? BRIX_DNS_RESULT_TIMEOUT : BRIX_DNS_RESULT_ERROR;
}


/* The libc resolver — the one getaddrinfo() call in src/ (the DNS seam).
 * Answers carry `port`; *result is the BRIX_DNS_RESULT_* class of the
 * outcome, and every call is counted once in brix_dns_lookups_total. */
static ngx_uint_t
dns_libc_resolve(const char *host, in_port_t port, brix_af_policy_t af,
    int socktype, brix_dns_addr_t *addrs, ngx_uint_t max, char *err,
    size_t errsz, ngx_uint_t *result)
{
    struct addrinfo  hints, *res, *ai;
    char             portstr[8];
    ngx_uint_t       n = 0;
    int              rc;

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family   = (int) af;
    hints.ai_socktype = socktype ? socktype : SOCK_STREAM;
    (void) ngx_snprintf((u_char *) portstr, sizeof(portstr), "%d%Z",
                        (int) port);

    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0 || res == NULL) {
        if (err != NULL && errsz > 0) {
            (void) ngx_snprintf((u_char *) err, errsz, "%s%Z",
                                rc == EAI_SYSTEM ? strerror(errno)
                                                 : gai_strerror(rc));
        }
        *result = dns_libc_result(rc);
        brix_dns_lookup_note(*result);
        return 0;
    }
    for (ai = res; ai != NULL && n < max; ai = ai->ai_next) {
        if (ai->ai_addrlen > sizeof(addrs[n].ss)) {
            continue;
        }
        ngx_memcpy(&addrs[n].ss, ai->ai_addr, ai->ai_addrlen);
        addrs[n].len = ai->ai_addrlen;
        n++;
    }
    freeaddrinfo(res);
    if (n == 0 && err != NULL && errsz > 0) {
        (void) ngx_snprintf((u_char *) err, errsz, "no usable address%Z");
    }
    *result = n > 0 ? BRIX_DNS_RESULT_OK : BRIX_DNS_RESULT_ERROR;
    brix_dns_lookup_note(*result);
    return n;
}


/* ---- blocking entry point ------------------------------------------------ */

static void
dns_sync_req_init(brix_dns_req_t *req, const brix_dns_policy_t *policy,
    const char *host, in_port_t port, brix_af_policy_t af, int socktype)
{
    ngx_memzero(req, sizeof(*req));
    req->name.data = (u_char *) host;
    req->name.len = ngx_strlen(host);
    req->port = port;
    req->af = af;
    req->socktype = socktype ? socktype : SOCK_STREAM;
    req->policy = policy;
    req->log = ngx_cycle->log;
}


static ngx_uint_t
dns_sync_copy(const brix_dns_req_t *req, brix_dns_addr_t *addrs,
    ngx_uint_t max, char *err, size_t errsz)
{
    ngx_uint_t  i, n = ngx_min(req->naddrs, max);

    if (req->rc != NGX_OK || n == 0) {
        if (err != NULL && errsz > 0) {
            (void) ngx_snprintf((u_char *) err, errsz, "%s%Z",
                                req->error ? req->error : "no usable address");
        }
        return 0;
    }
    for (i = 0; i < n; i++) {
        addrs[i] = req->addrs[i];
    }
    return n;
}


static void
dns_sync_cache_libc(brix_dns_req_t *req, const brix_dns_addr_t *addrs,
    ngx_uint_t n, unsigned definitive)
{
    ngx_uint_t  i;

    if (n > 0) {
        req->rc = NGX_OK;
        req->naddrs = ngx_min(n, (ngx_uint_t) BRIX_DNS_MAX_ADDRS);
        for (i = 0; i < req->naddrs; i++) {
            req->addrs[i] = addrs[i];
        }
        req->ttl = BRIX_DNS_THREAD_TTL;
        if (req->policy != NULL && req->ttl > req->policy->max_ttl) {
            req->ttl = req->policy->max_ttl;
        }
    } else {
        req->rc = NGX_ERROR;
        req->naddrs = 0;
        req->ttl = definitive
                   ? (req->policy ? req->policy->negative_ttl
                                  : BRIX_DNS_NEG_TTL_DEFAULT)
                   : 0;
    }
    brix_dns_cache_store(req);
}


/* IP literal fast path: 1 = one answer stored (carrying `port`), 0 = the
 * literal's family is excluded by policy (*err set), NGX_DECLINED = not a
 * literal at all. */
static ngx_int_t
dns_sync_literal(const ngx_str_t *name, in_port_t port, brix_af_policy_t af,
    brix_dns_addr_t *addrs, char *err, size_t errsz)
{
    brix_dns_addr_t  lit;

    if (brix_dns_parse_literal(name, &lit) != NGX_OK) {
        return NGX_DECLINED;
    }
    if ((af == BRIX_AF_INET && lit.ss.ss_family != AF_INET)
        || (af == BRIX_AF_INET6 && lit.ss.ss_family != AF_INET6))
    {
        brix_dns_set_err(err, errsz, "address family excluded by policy");
        return 0;
    }
    ngx_inet_set_port((struct sockaddr *) &lit.ss, port);
    addrs[0] = lit;
    return 1;
}


ngx_uint_t
brix_dns_resolve_sync(const brix_dns_policy_t *policy, const char *host,
    in_port_t port, brix_af_policy_t af, int socktype, brix_dns_addr_t *addrs,
    ngx_uint_t max, char *err, size_t errsz)
{
    brix_dns_req_t   req;
    ngx_uint_t       n;
    ngx_int_t        rc;
    ngx_uint_t       result;

    brix_dns_set_err(err, errsz, "");
    if (host == NULL || host[0] == '\0' || max == 0) {
        brix_dns_set_err(err, errsz, "empty hostname");
        return 0;
    }
    dns_sync_req_init(&req, policy, host, port, af, socktype);

    rc = dns_sync_literal(&req.name, port, af, addrs, err, errsz);
    if (rc != NGX_DECLINED) {
        return (ngx_uint_t) rc;
    }

    if (brix_dns_cache_lookup(&req) == NGX_OK) {
        return dns_sync_copy(&req, addrs, max, err, errsz);
    }

    rc = brix_dns_bridge_resolve(policy, host, port, af, req.socktype, addrs,
                                 max, &n, err, errsz);
    if (rc == NGX_OK) {
        return n;
    }

    n = dns_libc_resolve(host, port, af, req.socktype, addrs, max, err, errsz,
                         &result);
    dns_sync_cache_libc(&req, addrs, n, result == BRIX_DNS_RESULT_NXDOMAIN);
    return n;
}


/* ---- thread-pool backend of brix_dns_resolve() --------------------------- */

#if (NGX_THREADS)

static void
dns_thread_run(void *data, ngx_log_t *log)
{
    dns_thread_ctx_t  *tc = data;
    ngx_uint_t         result;

    (void) log;
    tc->err[0] = '\0';
    tc->naddrs = dns_libc_resolve(tc->host, tc->port, tc->af, tc->socktype,
                                  tc->addrs, BRIX_DNS_MAX_ADDRS, tc->err,
                                  sizeof(tc->err), &result);
    tc->definitive = (result == BRIX_DNS_RESULT_NXDOMAIN);
}


static void
dns_thread_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    dns_thread_ctx_t   *tc = task->ctx;
    brix_dns_req_t     *req = tc->req;
    ngx_pool_t         *pool = tc->pool;
    ngx_uint_t          i;

    if (req == NULL) {
        ngx_destroy_pool(pool);              /* cancelled while in flight */
        return;
    }
    req->task = NULL;
    if (tc->naddrs == 0) {
        req->rc = NGX_ERROR;
        req->error = "getaddrinfo failed";
        req->naddrs = 0;
        ngx_log_error(NGX_LOG_INFO, req->log, 0,
                      "brix dns: \"%V\" via libc: %s", &req->name, tc->err);
        req->ttl = 0;
        if (tc->definitive) {
            req->ttl = req->policy ? req->policy->negative_ttl
                                   : BRIX_DNS_NEG_TTL_DEFAULT;
        }
    } else {
        req->naddrs = tc->naddrs;
        for (i = 0; i < tc->naddrs; i++) {
            req->addrs[i] = tc->addrs[i];
        }
        req->rc = NGX_OK;
        req->error = NULL;
        req->ttl = BRIX_DNS_THREAD_TTL;
        if (req->policy != NULL && req->ttl > req->policy->max_ttl) {
            req->ttl = req->policy->max_ttl;
        }
    }
    /* the handler may release the request; the ctx is ours until here */
    brix_dns_req_finish(req);
    ngx_destroy_pool(pool);
}


ngx_int_t
brix_dns_thread_task_new(ngx_log_t *log, size_t ctx_size,
    ngx_thread_pool_t **tp, ngx_pool_t **pool, ngx_thread_task_t **task)
{
    ngx_str_t  pname = ngx_string("default");

    *tp = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &pname);
    if (*tp == NULL) {
        return NGX_DECLINED;
    }
    *pool = ngx_create_pool(512, log);
    if (*pool == NULL) {
        return NGX_ERROR;
    }
    *task = ngx_thread_task_alloc(*pool, ctx_size);
    if (*task == NULL) {
        ngx_destroy_pool(*pool);
        *pool = NULL;
        return NGX_ERROR;
    }
    return NGX_OK;
}


ngx_int_t
brix_dns_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task,
    ngx_pool_t *pool, void **owner)
{
    *owner = task;
    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        *owner = NULL;
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }
    return NGX_OK;
}

#endif


ngx_int_t
brix_dns_resolve_via_thread(brix_dns_req_t *req)
{
#if (NGX_THREADS)
    ngx_thread_task_t  *task;
    dns_thread_ctx_t   *tc;
    ngx_thread_pool_t  *tp;
    ngx_pool_t         *pool;
    ngx_int_t           rc;

    rc = brix_dns_thread_task_new(req->log, sizeof(dns_thread_ctx_t),
                                  &tp, &pool, &task);
    if (rc != NGX_OK) {
        return rc;
    }
    tc = task->ctx;
    tc->req = req;
    tc->pool = pool;
    tc->port = req->port;
    tc->af = req->af;
    tc->socktype = req->socktype;
    ngx_cpystrn((u_char *) tc->host, req->name.data,
                ngx_min(req->name.len + 1, sizeof(tc->host)));
    brix_task_bind(task, dns_thread_run, dns_thread_done);
    task->event.log = req->log;
    return brix_dns_thread_task_post(tp, task, pool, &req->task);
#else
    (void) req;
    return NGX_DECLINED;
#endif
}


void
brix_dns_thread_detach(brix_dns_req_t *req)
{
#if (NGX_THREADS)
    ngx_thread_task_t  *task = req->task;
    dns_thread_ctx_t   *tc;

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
