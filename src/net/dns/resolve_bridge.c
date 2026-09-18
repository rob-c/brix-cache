/*
 * resolve_bridge.c — thread-pool -> event-loop resolver bridge (phase-116
 * Appendix A: "zero blocking sites outside the driver").
 *
 * WHAT: Lets a thread-pool task resolve a hostname through the event loop's
 *       nginx resolver (the one `brix_resolver auto` built from resolv.conf)
 *       and block only on a condition variable until the answer is back.
 *       brix_dns_resolve_sync() calls brix_dns_bridge_resolve() and
 *       brix_dns_reverse_sync() calls brix_dns_bridge_reverse(); both return
 *       NGX_DECLINED — "use libc" — when the calling thread IS the event loop,
 *       when the bridge is not armed, or when the policy has no usable
 *       resolver, so the caller always has a path.
 * WHY:  Blocking callers (TPC pins, cache-origin/gsiftp connects, cvmfs
 *       probes, libcurl pinning) would otherwise fall back to libc and drift
 *       from the resolver policy the operator configured: different search
 *       semantics, a different resolv.conf when `path=` is set, no shared
 *       cache.  With the bridge every resolution in the worker — async or
 *       blocking — flows through one driver (I-DNS-2/3).
 * HOW:  A per-process singleton (origin_probe precedent) holding an eventfd
 *       registered with the event loop (the uring_bringup connection pattern),
 *       a mutex-guarded pending list and an in-flight queue.  A thread
 *       allocates an item on the heap, links it, writes the eventfd and waits
 *       on the item's condvar in 100 ms slices so it can observe the worker's
 *       exit flags (ngx_thread_pool_destroy would otherwise stall behind a
 *       waiting thread).  The loop drains the eventfd, splices the pending
 *       list and drives each item through brix_dns_resolve(); the completion
 *       sets `done` and signals.  Whoever observes the other side gone frees
 *       the item: a thread that timed out marks it abandoned (or unlinks it
 *       if still pending) and the completion releases it; a completion that
 *       finds `abandoned` releases it itself.  Items always carry a usable
 *       resolver so the loop never takes the thread-pool path for them.
 */
#include "core/types/tunables.h"
#include "net/dns/dns.h"
#include "platform/platform_api.h"

#if (NGX_THREADS)

#include <pthread.h>
#include <time.h>

#define DNS_BRIDGE_SLICE_MS      100
#define DNS_BRIDGE_DEADLINE_MIN  BRIX_DNS_DEADLINE_MIN_MS
#define DNS_BRIDGE_DEADLINE_MAX  BRIX_DNS_DEADLINE_MAX_MS

typedef struct dns_bridge_item_s  dns_bridge_item_t;

struct dns_bridge_item_s {
    dns_bridge_item_t  *next;        /* pending list (under mu) */
    ngx_queue_t         inflight;    /* loop-only */
    brix_dns_req_t      req;         /* driven on the loop; read by the
                                        thread only after `done` */
    brix_dns_rev_req_t  rev;         /* the reverse flavour (reverse == 1) */
    pthread_cond_t      cv;
    unsigned            done:1;      /* under mu */
    unsigned            abandoned:1; /* under mu */
    unsigned            pending:1;   /* under mu: still on the pending list */
    unsigned            reverse:1;   /* set by the thread before enqueue */
};

typedef struct {
    int                 efd;        /* wake read end (the loop's event fd) */
    int                 efd_write;  /* wake write end (== efd on eventfd hosts) */
    ngx_connection_t   *conn;
    pthread_mutex_t     mu;
    dns_bridge_item_t  *head;
    dns_bridge_item_t  *tail;
    ngx_queue_t         inflight;
    ngx_tid_t           loop_tid;
    ngx_uint_t          requests;
    ngx_uint_t          timeouts;
    unsigned            ready:1;
} dns_bridge_t;

/* per-process singleton — see file header */
static dns_bridge_t  dns_bridge = { .mu = PTHREAD_MUTEX_INITIALIZER,
                                    .efd = -1, .efd_write = -1 };


static void
dns_bridge_item_free(dns_bridge_item_t *item)
{
    pthread_cond_destroy(&item->cv);
    ngx_free(item);
}


/* Loop side: a driven request finished (possibly inline in dispatch). */
static void
dns_bridge_item_done(dns_bridge_item_t *item)
{
    unsigned  abandoned;

    ngx_queue_remove(&item->inflight);
    pthread_mutex_lock(&dns_bridge.mu);
    abandoned = item->abandoned;
    item->done = 1;
    if (!abandoned) {
        pthread_cond_signal(&item->cv);
    }
    pthread_mutex_unlock(&dns_bridge.mu);
    if (abandoned) {
        dns_bridge_item_free(item);
    }
}


static void
dns_bridge_done(brix_dns_req_t *req)
{
    dns_bridge_item_done(req->data);
}


static void
dns_bridge_rev_done(brix_dns_rev_req_t *req)
{
    dns_bridge_item_done(req->data);
}


static void
dns_bridge_dispatch_reverse(dns_bridge_item_t *item)
{
    item->rev.log = ngx_cycle->log;
    item->rev.handler = dns_bridge_rev_done;
    item->rev.data = item;
    if (brix_dns_reverse(&item->rev) != NGX_OK) {
        item->rev.rc = NGX_ERROR;
        item->rev.error = "resolver could not be started";
        dns_bridge_item_done(item);
    }
}


static void
dns_bridge_dispatch(dns_bridge_item_t *item)
{
    ngx_queue_insert_tail(&dns_bridge.inflight, &item->inflight);
    if (item->reverse) {
        dns_bridge_dispatch_reverse(item);
        return;
    }
    item->req.log = ngx_cycle->log;
    item->req.handler = dns_bridge_done;
    item->req.data = item;
    if (brix_dns_resolve(&item->req) != NGX_OK) {
        item->req.rc = NGX_ERROR;
        item->req.naddrs = 0;
        item->req.error = "resolver could not be started";
        dns_bridge_done(&item->req);
    }
}


static void
dns_bridge_read(ngx_event_t *rev)
{
    ngx_connection_t   *c = rev->data;
    dns_bridge_item_t  *item, *next;

    (void) brix_plat_wakefd_drain(c->fd);

    pthread_mutex_lock(&dns_bridge.mu);
    item = dns_bridge.head;
    dns_bridge.head = NULL;
    dns_bridge.tail = NULL;
    for (next = item; next != NULL; next = next->next) {
        next->pending = 0;
    }
    pthread_mutex_unlock(&dns_bridge.mu);

    for ( ; item != NULL; item = next) {
        next = item->next;
        item->next = NULL;
        dns_bridge_dispatch(item);       /* may free `item` */
    }
}


/* Release both wake ends (one close on an eventfd host). */
static void
dns_bridge_close_wakefd(void)
{
    brix_plat_wakefd_close(dns_bridge.efd, dns_bridge.efd_write);
    dns_bridge.efd = -1;
    dns_bridge.efd_write = -1;
}


ngx_int_t
brix_dns_bridge_init_worker(ngx_cycle_t *cycle)
{
    ngx_connection_t  *c;

    if (dns_bridge.ready) {
        return NGX_OK;
    }
    ngx_queue_init(&dns_bridge.inflight);
    if (brix_plat_wakefd_open(&dns_bridge.efd, &dns_bridge.efd_write,
                              BRIX_EVENTFD_NONBLOCK | BRIX_EVENTFD_CLOEXEC) != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "brix dns: eventfd() failed, thread resolves use libc");
        return NGX_OK;                        /* degraded, not fatal */
    }
    c = ngx_get_connection(dns_bridge.efd, cycle->log);
    if (c == NULL) {
        dns_bridge_close_wakefd();
        return NGX_OK;
    }
    c->read->handler = dns_bridge_read;
    c->read->log = cycle->log;
    c->data = &dns_bridge;
    if (ngx_add_event(c->read, NGX_READ_EVENT, 0) != NGX_OK) {
        ngx_free_connection(c);
        dns_bridge_close_wakefd();
        return NGX_OK;
    }
    dns_bridge.conn = c;
    dns_bridge.loop_tid = ngx_thread_tid();
    dns_bridge.ready = 1;
    return NGX_OK;
}


/* Thread side ------------------------------------------------------------- */

static ngx_msec_t
dns_bridge_deadline_ms(const brix_dns_policy_t *policy)
{
    ngx_msec_t  ms, ncand = 1;

    if (policy->search) {
        ncand += policy->rc.nsearch;
    }
    ms = (ngx_msec_t) policy->rc.timeout * policy->rc.attempts * ncand * BRIX_CMS_SEC_TO_MS_MULTIPLIER
         + BRIX_DNS_TIMEOUT_FLOOR_MS;
    if (ms < BRIX_DNS_DEADLINE_MIN_MS) {
        ms = BRIX_DNS_DEADLINE_MIN_MS;
    }
    if (ms > BRIX_DNS_DEADLINE_MAX_MS) {
        ms = BRIX_DNS_DEADLINE_MAX_MS;
    }
    return ms;
}


static void
dns_bridge_enqueue(dns_bridge_item_t *item)
{
    pthread_mutex_lock(&dns_bridge.mu);
    item->pending = 1;
    if (dns_bridge.tail != NULL) {
        dns_bridge.tail->next = item;
    } else {
        dns_bridge.head = item;
    }
    dns_bridge.tail = item;
    dns_bridge.requests++;
    pthread_mutex_unlock(&dns_bridge.mu);
    if (brix_plat_wakefd_signal(dns_bridge.efd_write) != 0) {
        /* only a saturated eventfd counter refuses a +1: the item is queued
         * and the next wakeup drains it, so log rather than fail */
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "brix dns bridge: eventfd wakeup write failed");
    }
}


/* Unlink a still-pending item (mu held).  1 if it was unlinked. */
static unsigned
dns_bridge_unlink_pending(dns_bridge_item_t *item)
{
    dns_bridge_item_t  **pp, *prev = NULL;

    for (pp = &dns_bridge.head; *pp != NULL; prev = *pp, pp = &(*pp)->next) {
        if (*pp == item) {
            *pp = item->next;
            if (dns_bridge.tail == item) {
                dns_bridge.tail = prev;
            }
            item->pending = 0;
            return 1;
        }
    }
    return 0;
}


/* Wait for `done` up to deadline_ms; the wait is sliced so a worker exit is
 * observed promptly.  1 = done, 0 = gave up (item marked/unlinked). */
static unsigned
dns_bridge_wait(dns_bridge_item_t *item, ngx_msec_t deadline_ms)
{
    struct timespec  ts;
    ngx_msec_t       waited = 0;

    pthread_mutex_lock(&dns_bridge.mu);
    while (!item->done) {
        if (waited >= deadline_ms || ngx_exiting || ngx_quit || ngx_terminate) {
            if (item->pending) {
                (void) dns_bridge_unlink_pending(item);
                pthread_mutex_unlock(&dns_bridge.mu);
                dns_bridge_item_free(item);
                return 0;
            }
            item->abandoned = 1;
            dns_bridge.timeouts++;
            pthread_mutex_unlock(&dns_bridge.mu);
            return 0;
        }
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += DNS_BRIDGE_SLICE_MS * BRIX_DNS_NS_PER_MS;
        if (ts.tv_nsec >= BRIX_DNS_NS_PER_SEC) {
            ts.tv_sec += 1;
            ts.tv_nsec -= BRIX_DNS_NS_PER_SEC;
        }
        (void) pthread_cond_timedwait(&item->cv, &dns_bridge.mu, &ts);
        waited += DNS_BRIDGE_SLICE_MS;
    }
    pthread_mutex_unlock(&dns_bridge.mu);
    return 1;
}


ngx_int_t
brix_dns_bridge_resolve(const brix_dns_policy_t *policy, const char *host,
    in_port_t port, brix_af_policy_t af, int socktype, brix_dns_addr_t *addrs,
    ngx_uint_t max, ngx_uint_t *naddrs, char *err, size_t errsz)
{
    dns_bridge_item_t  *item;
    ngx_uint_t          i, n;

    *naddrs = 0;
    if (!dns_bridge.ready || brix_dns_policy_resolver(policy) == NULL
        || ngx_thread_tid() == dns_bridge.loop_tid)
    {
        return NGX_DECLINED;
    }
    item = ngx_calloc(sizeof(dns_bridge_item_t), ngx_cycle->log);
    if (item == NULL) {
        return NGX_ERROR;
    }
    pthread_cond_init(&item->cv, NULL);
    item->req.name.data = (u_char *) host;
    item->req.name.len = ngx_strlen(host);
    item->req.port = port;
    item->req.af = af;
    item->req.socktype = socktype;
    item->req.policy = policy;

    dns_bridge_enqueue(item);
    if (!dns_bridge_wait(item, dns_bridge_deadline_ms(policy))) {
        if (err != NULL && errsz > 0) {
            (void) ngx_snprintf((u_char *) err, errsz,
                                "resolver timed out (event loop)%Z");
        }
        return NGX_OK;                        /* answered: failure */
    }

    n = ngx_min(item->req.naddrs, max);
    if (item->req.rc == NGX_OK && n > 0) {
        for (i = 0; i < n; i++) {
            addrs[i] = item->req.addrs[i];
        }
        *naddrs = n;
    } else if (err != NULL && errsz > 0) {
        (void) ngx_snprintf((u_char *) err, errsz, "%s%Z",
                            item->req.error ? item->req.error
                                            : "no usable address");
    }
    dns_bridge_item_free(item);
    return NGX_OK;
}


ngx_int_t
brix_dns_bridge_reverse(const brix_dns_policy_t *policy,
    const struct sockaddr *sa, socklen_t len, char *buf, size_t buflen,
    ngx_int_t *answer)
{
    dns_bridge_item_t  *item;

    *answer = NGX_ERROR;
    if (!dns_bridge.ready || brix_dns_policy_resolver(policy) == NULL
        || ngx_thread_tid() == dns_bridge.loop_tid || len > sizeof(item->rev.ss))
    {
        return NGX_DECLINED;
    }
    item = ngx_calloc(sizeof(dns_bridge_item_t), ngx_cycle->log);
    if (item == NULL) {
        return NGX_DECLINED;
    }
    pthread_cond_init(&item->cv, NULL);
    item->reverse = 1;
    ngx_memcpy(&item->rev.ss, sa, len);
    item->rev.len = len;
    item->rev.policy = policy;

    dns_bridge_enqueue(item);
    if (!dns_bridge_wait(item, dns_bridge_deadline_ms(policy))) {
        return NGX_OK;                        /* answered: failure */
    }
    *answer = item->rev.rc;
    if (item->rev.rc == NGX_OK) {
        ngx_cpystrn((u_char *) buf, (u_char *) item->rev.name, buflen);
    }
    dns_bridge_item_free(item);
    return NGX_OK;
}


void
brix_dns_bridge_stats(ngx_uint_t *requests, ngx_uint_t *timeouts)
{
    pthread_mutex_lock(&dns_bridge.mu);
    *requests = dns_bridge.requests;
    *timeouts = dns_bridge.timeouts;
    pthread_mutex_unlock(&dns_bridge.mu);
}

#else  /* !NGX_THREADS: no thread-pool callers exist, nothing to bridge */

ngx_int_t
brix_dns_bridge_init_worker(ngx_cycle_t *cycle)
{
    (void) cycle;
    return NGX_OK;
}


ngx_int_t
brix_dns_bridge_resolve(const brix_dns_policy_t *policy, const char *host,
    in_port_t port, brix_af_policy_t af, int socktype, brix_dns_addr_t *addrs,
    ngx_uint_t max, ngx_uint_t *naddrs, char *err, size_t errsz)
{
    (void) policy; (void) host; (void) port; (void) af; (void) socktype;
    (void) addrs; (void) max; (void) err; (void) errsz;
    *naddrs = 0;
    return NGX_DECLINED;
}


ngx_int_t
brix_dns_bridge_reverse(const brix_dns_policy_t *policy,
    const struct sockaddr *sa, socklen_t len, char *buf, size_t buflen,
    ngx_int_t *answer)
{
    (void) policy; (void) sa; (void) len; (void) buf; (void) buflen;
    *answer = NGX_ERROR;
    return NGX_DECLINED;
}


void
brix_dns_bridge_stats(ngx_uint_t *requests, ngx_uint_t *timeouts)
{
    *requests = 0;
    *timeouts = 0;
}

#endif
