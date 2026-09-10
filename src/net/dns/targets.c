/*
 * targets.c — config-time DNS target registry (phase-116 W3 + W5).
 *
 * WHAT: Every brix directive that names a peer (brix_cms_manager,
 *       brix_mirror_url, brix_upstream, brix_pmark_firefly_dest, …)
 *       registers its host:port here at parse time and gets back a
 *       brix_dns_target_t whose published ngx_addr_t it keeps.  Each worker
 *       resolves the registry from init_process with exponential backoff,
 *       refreshes an answer when its TTL lapses or a consumer reports a
 *       connect failure, and rotates through the answer set round-robin.
 * WHY:  I-DNS-1: a hostname that does not resolve at `nginx -t` (typical in
 *       a container that starts before its DNS) must not stop the server; it
 *       starts "resolving" and heals itself.  Consumers see socklen == 0 and
 *       treat the peer as temporarily unreachable — the same path a down
 *       peer already takes.
 * HOW:  Per-process static array (origin_probe precedent: written by the
 *       master's parse, inherited by the fork, reset when a new cycle parses).
 *       IP literals are published immediately and never scheduled.  Timers
 *       are per worker; the request state machine is brix_dns_resolve().
 */
#include <ngx_thread_pool.h>

#include "net/dns/dns.h"

#define DNS_TARGETS_MAX      256
#define DNS_FIRST_JITTER_MS  200
#define DNS_FAILURE_REFRESH_MS 500

typedef struct {
    brix_dns_target_t  targets[DNS_TARGETS_MAX];
    ngx_uint_t         n;
    ngx_cycle_t       *cycle;      /* registration cycle */
    unsigned           armed:1;
} dns_registry_t;

/* per-process singleton — see file header */
static dns_registry_t  dns_registry;


static void
dns_registry_reset(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    if (dns_registry.cycle == cycle) {
        return;
    }
    /* a single-process reload parses in the running worker: nothing armed
     * may keep pointing into the zeroed array */
    for (i = 0; i < dns_registry.n; i++) {
        brix_dns_target_t *t = &dns_registry.targets[i];

        if (t->timer.timer_set) {
            ngx_del_timer(&t->timer);
        }
        if (t->inflight) {
            brix_dns_resolve_cancel(&t->req);
        }
    }
    ngx_memzero(&dns_registry, sizeof(dns_registry));
    dns_registry.cycle = cycle;
}


static brix_dns_target_t *
dns_target_find(const ngx_str_t *host, in_port_t port, brix_af_policy_t af,
    int socktype)
{
    ngx_uint_t  i;

    for (i = 0; i < dns_registry.n; i++) {
        brix_dns_target_t *t = &dns_registry.targets[i];

        if (t->port == port && t->af == af && t->socktype == socktype
            && t->host.len == host->len
            && ngx_strncasecmp(t->host.data, host->data, host->len) == 0)
        {
            return t;
        }
    }
    return NULL;
}


/* An IP literal is final at parse time: publish and never schedule. */
static void
dns_target_try_literal(brix_dns_target_t *t)
{
    brix_dns_addr_t  a;

    if (brix_dns_parse_literal(&t->host, &a) != NGX_OK) {
        return;
    }
    ngx_inet_set_port((struct sockaddr *) &a.ss, t->port);
    ngx_memcpy(&t->addr_ss, &a.ss, a.len);
    t->addr.socklen = a.len;
    t->addrs[0] = a;
    t->naddrs = 1;
    t->literal = 1;
    t->state = BRIX_DNS_STATE_RESOLVED;
}


brix_dns_target_t *
brix_dns_target_register(ngx_conf_t *cf, const char *directive,
    const ngx_str_t *host, in_port_t port, brix_af_policy_t af, int socktype,
    const brix_dns_conf_t *dns)
{
    brix_dns_target_t  *t;
    u_char             *p;

    dns_registry_reset(cf->cycle);
    if (socktype == 0) {
        socktype = SOCK_STREAM;
    }
    t = dns_target_find(host, port, af, socktype);
    if (t != NULL) {
        return t;
    }
    if (dns_registry.n >= DNS_TARGETS_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%s: more than %d distinct DNS targets", directive,
            DNS_TARGETS_MAX);
        return NULL;
    }
    p = ngx_pnalloc(cf->pool, host->len + 1);
    if (p == NULL) {
        return NULL;
    }
    ngx_memcpy(p, host->data, host->len);
    p[host->len] = '\0';

    t = &dns_registry.targets[dns_registry.n];
    ngx_memzero(t, sizeof(*t));
    t->directive = directive;
    t->host.data = p;
    t->host.len = host->len;
    t->port = port;
    t->af = af;
    t->socktype = socktype;
    t->dns = dns;
    t->cycle = cf->cycle;
    t->addr.sockaddr = (struct sockaddr *) &t->addr_ss;
    t->addr.socklen = 0;
    t->addr.name = t->host;
    t->state = BRIX_DNS_STATE_RESOLVING;
    dns_target_try_literal(t);
    dns_registry.n++;

#if (NGX_THREADS)
    if (!t->literal && ngx_thread_pool_add(cf, NULL) == NULL) {
        return NULL;
    }
#endif
    if (!t->literal) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "%s: \"%V:%d\" will be resolved at runtime", directive, host,
            (int) port);
    }
    return t;
}


static ngx_msec_t
dns_target_retry_initial(const brix_dns_target_t *t)
{
    if (t->dns != NULL && t->dns->retry_initial != NGX_CONF_UNSET_MSEC) {
        return t->dns->retry_initial;
    }
    return BRIX_DNS_RETRY_INITIAL_MS;
}


static ngx_msec_t
dns_target_retry_max(const brix_dns_target_t *t)
{
    if (t->dns != NULL && t->dns->retry_max != NGX_CONF_UNSET_MSEC) {
        return t->dns->retry_max;
    }
    return BRIX_DNS_RETRY_MAX_MS;
}


static void
dns_target_schedule(brix_dns_target_t *t, ngx_msec_t delay)
{
    if (ngx_exiting || ngx_quit || ngx_terminate) {
        return;
    }
    t->next_retry = ngx_current_msec + delay;
    ngx_add_timer(&t->timer, delay);
}


/* Publish answer i as the round-robin "current" address. */
static void
dns_target_publish(brix_dns_target_t *t, ngx_uint_t i)
{
    ngx_memcpy(&t->addr_ss, &t->addrs[i].ss, t->addrs[i].len);
    t->addr.socklen = t->addrs[i].len;
}


/*
 * WHAT: The index the new answer set should publish: the address that is
 *      published now if it survived the re-resolution, else the first.
 * WHY:  phase-116: a refused dial advances the published address
 *      (brix_dns_target_note_failure) *and* schedules an early refresh.
 *      Restarting the rotation at addrs[0] on every answer threw that advance
 *      away, so a consumer that dials the published address (the CMS client)
 *      was dragged back onto a dead first member after each refresh and stayed
 *      out of the cluster for as long as the dead member was in the record.
 * HOW:  Byte-compare the published sockaddr against the incoming set — both
 *      are built by the same resolver path, and a miss simply starts the new
 *      set at 0, which is the right answer for a record that really changed.
 */
static ngx_uint_t
dns_target_carry_index(const brix_dns_target_t *t, const brix_dns_req_t *req)
{
    ngx_uint_t  i;

    if (t->addr.socklen == 0) {
        return 0;
    }
    for (i = 0; i < req->naddrs; i++) {
        if (req->addrs[i].len == t->addr.socklen
            && ngx_memcmp(&req->addrs[i].ss, &t->addr_ss,
                          (size_t) t->addr.socklen) == 0)
        {
            return i;
        }
    }
    return 0;
}


static void
dns_target_on_success(brix_dns_target_t *t, const brix_dns_req_t *req)
{
    ngx_uint_t  i, keep, prev_state = t->state;
    ngx_msec_t  ttl_ms;

    keep = dns_target_carry_index(t, req);
    for (i = 0; i < req->naddrs; i++) {
        t->addrs[i] = req->addrs[i];
    }
    t->naddrs = req->naddrs;
    /* rr points *past* the published address so the next rotation hands out a
     * different one rather than repeating what is already in use. */
    t->rr = keep + 1;
    dns_target_publish(t, keep);
    t->state = BRIX_DNS_STATE_RESOLVED;
    t->last_error[0] = '\0';
    t->backoff = 0;
    t->resolutions++;
    t->expires = ngx_time() + (req->ttl > 0 ? req->ttl : BRIX_DNS_THREAD_TTL);

    if (prev_state != BRIX_DNS_STATE_RESOLVED || t->resolutions == 1) {
        ngx_log_error(NGX_LOG_NOTICE, t->req.log, 0,
            "brix dns: %s \"%V:%d\" resolved (%ui address%s, ttl %Ts%s)",
            t->directive, &t->host, (int) t->port, t->naddrs,
            t->naddrs == 1 ? "" : "es", (time_t) (t->expires - ngx_time()),
            req->cached ? ", cached" : "");
    }
    ttl_ms = (ngx_msec_t) (t->expires - ngx_time()) * 1000;
    dns_target_schedule(t, ttl_ms > 0 ? ttl_ms : 1000);
}


static void
dns_target_on_failure(brix_dns_target_t *t, const brix_dns_req_t *req)
{
    ngx_msec_t  next, max = dns_target_retry_max(t);
    ngx_uint_t  level;

    t->failures++;
    (void) ngx_snprintf((u_char *) t->last_error, sizeof(t->last_error),
                        "%s%Z", req->error ? req->error : "unknown");
    if (t->naddrs == 0) {
        t->state = BRIX_DNS_STATE_FAILED;      /* never had an answer */
    }
    /* a stale answer stays published: better a last-known-good peer than none */
    t->backoff = t->backoff == 0 ? dns_target_retry_initial(t) : t->backoff * 2;
    if (t->backoff > max) {
        t->backoff = max;
    }
    next = t->backoff + (ngx_msec_t) (ngx_random() % 250);
    level = (t->failures == 1 || t->failures % 10 == 0)
            ? NGX_LOG_WARN : NGX_LOG_INFO;

    ngx_log_error(level, t->req.log, 0,
        "brix dns: %s \"%V:%d\" not resolved: %s (attempt %ui, retry in %Mms%s)",
        t->directive, &t->host, (int) t->port, t->last_error, t->failures,
        next, t->naddrs ? ", keeping the last answer" : "");
    dns_target_schedule(t, next);
}


static void
dns_target_done(brix_dns_req_t *req)
{
    brix_dns_target_t  *t = req->data;

    t->inflight = 0;
    if (req->rc == NGX_OK && req->naddrs > 0) {
        dns_target_on_success(t, req);
    } else {
        dns_target_on_failure(t, req);
    }
}


static void
dns_target_fire(ngx_event_t *ev)
{
    brix_dns_target_t  *t = ev->data;

    if (t->inflight || ngx_exiting) {
        return;
    }
    t->req.name = t->host;
    t->req.port = t->port;
    t->req.af = t->af;
    t->req.socktype = t->socktype;
    t->req.policy = t->dns ? t->dns->policy : NULL;
    t->req.resolver = NULL;
    t->req.log = ev->log;
    t->req.handler = dns_target_done;
    t->req.data = t;
    t->inflight = 1;
    if (brix_dns_resolve(&t->req) != NGX_OK) {
        t->inflight = 0;
        dns_target_schedule(t, dns_target_retry_initial(t));
    }
}


static ngx_int_t
dns_target_arm(ngx_cycle_t *cycle, brix_dns_target_t *t)
{
    if (t->literal || t->armed) {
        return NGX_OK;
    }
    t->timer.handler = dns_target_fire;
    t->timer.data = t;
    t->timer.log = cycle->log;
    t->armed = 1;
    dns_target_schedule(t, (ngx_msec_t) (ngx_random() % DNS_FIRST_JITTER_MS) + 1);
    return NGX_OK;
}


ngx_int_t
brix_dns_targets_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    /* the bridge is per process, not per cycle: arm it before the
     * registry's cycle check so a thread-pool caller always has it */
    if (brix_dns_bridge_init_worker(cycle) != NGX_OK) {
        return NGX_ERROR;
    }
    if (dns_registry.cycle != cycle || dns_registry.armed) {
        return NGX_OK;
    }
    dns_registry.armed = 1;
    for (i = 0; i < dns_registry.n; i++) {
        if (dns_target_arm(cycle, &dns_registry.targets[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


ngx_int_t
brix_dns_target_next(brix_dns_target_t *t, struct sockaddr_storage *sa,
    socklen_t *len)
{
    ngx_uint_t  i;

    if (t == NULL || t->naddrs == 0) {
        return NGX_DECLINED;
    }
    i = t->rr % t->naddrs;
    t->rr++;
    ngx_memcpy(sa, &t->addrs[i].ss, t->addrs[i].len);
    *len = t->addrs[i].len;
    dns_target_publish(t, i);
    return NGX_OK;
}


void
brix_dns_target_note_failure(brix_dns_target_t *t)
{
    if (t == NULL || t->literal || !t->armed || t->inflight) {
        return;
    }
    if (t->naddrs > 1) {
        (void) brix_dns_target_next(t, &t->addr_ss, &t->addr.socklen);
    }
    if (t->timer.timer_set) {
        ngx_del_timer(&t->timer);
    }
    dns_target_schedule(t, DNS_FAILURE_REFRESH_MS
                           + (ngx_msec_t) (ngx_random() % 250));
}


void
brix_dns_targets_count(ngx_uint_t counts[BRIX_DNS_STATE_COUNT])
{
    ngx_uint_t  i;

    ngx_memzero(counts, sizeof(ngx_uint_t) * BRIX_DNS_STATE_COUNT);
    for (i = 0; i < dns_registry.n; i++) {
        counts[dns_registry.targets[i].state % BRIX_DNS_STATE_COUNT]++;
    }
}


ngx_uint_t
brix_dns_targets_n(void)
{
    return dns_registry.n;
}


const brix_dns_target_t *
brix_dns_target_at(ngx_uint_t i)
{
    return i < dns_registry.n ? &dns_registry.targets[i] : NULL;
}
