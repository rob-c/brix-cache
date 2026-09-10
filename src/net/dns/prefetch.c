/*
 * prefetch.c — never-blocking forward probe + background fill (phase-116 W7).
 *
 * WHAT: brix_dns_lookup_cached() answers from the IP-literal parser or the
 *       per-worker cache and otherwise starts one background fill and reports
 *       NGX_AGAIN; brix_dns_prefetch() is that fill on its own.
 * WHY:  Some event-loop decisions want a hostname's addresses but must not
 *       wait for them: the loop-side TPC source preflight answers from the
 *       cache and parks the kXR_open on its own async request otherwise
 *       (brix_dns_cache_probe: no fill), while warm-up sites want the fill
 *       started for a later probe (brix_dns_lookup_cached).  Without a probe
 *       those sites would either block (I-DNS-1) or resolve twice.
 * HOW:  The fill is a self-owned brix_dns_req_t (ngx_calloc, hostname copied
 *       behind it) whose handler frees it; the driver stores the answer in
 *       brix_dns_req_finish().  brix_dns_cache_mark_pending() dedups fills
 *       for the same (name, af) while one is in flight.
 */
#include "net/dns/dns.h"


static void
dns_prefetch_done(brix_dns_req_t *req)
{
    if (req->rc != NGX_OK && !req->negative) {
        ngx_log_error(NGX_LOG_INFO, req->log, 0,
                      "brix dns: prefetch of \"%V\" failed: %s", &req->name,
                      req->error ? req->error : "unknown");
    }
    ngx_free(req);
}


void
brix_dns_prefetch(const brix_dns_policy_t *policy, const char *host,
    in_port_t port, brix_af_policy_t af)
{
    brix_dns_req_t  *req;
    ngx_str_t        name;
    ngx_log_t       *log = ngx_cycle->log;   /* the fill may outlive its caller */
    time_t           hold = BRIX_DNS_PENDING_HOLD;

    if (host == NULL || host[0] == '\0') {
        return;
    }
    name.data = (u_char *) host;
    name.len = ngx_strlen(host);
    if (name.len >= BRIX_RESOLV_DOMAIN_LEN) {
        return;
    }
    if (policy != NULL) {
        time_t  budget = (time_t) policy->rc.timeout * policy->rc.attempts
                         * (1 + (policy->search ? policy->rc.nsearch : 0)) + 1;

        hold = ngx_max(hold, budget);
    }
    if (!brix_dns_cache_mark_pending(&name, af, hold)) {
        return;                              /* cached, negative or in flight */
    }
    req = ngx_calloc(sizeof(brix_dns_req_t) + name.len + 1, log);
    if (req == NULL) {
        return;
    }
    req->name.data = (u_char *) (req + 1);
    ngx_memcpy(req->name.data, name.data, name.len);
    req->name.data[name.len] = '\0';
    req->name.len = name.len;
    req->port = port;
    req->af = af;
    req->socktype = SOCK_STREAM;
    req->policy = policy;
    req->log = log;
    req->handler = dns_prefetch_done;
    if (brix_dns_resolve(req) != NGX_OK) {
        ngx_free(req);                       /* handler did not run */
    }
}


static ngx_int_t
dns_lookup_literal(brix_dns_req_t *req, brix_dns_addr_t *addrs,
    ngx_uint_t *naddrs, char *err, size_t errsz)
{
    brix_dns_addr_t  lit;

    if (brix_dns_parse_literal(&req->name, &lit) != NGX_OK) {
        return NGX_AGAIN;                    /* not a literal */
    }
    if ((req->af == BRIX_AF_INET && lit.ss.ss_family != AF_INET)
        || (req->af == BRIX_AF_INET6 && lit.ss.ss_family != AF_INET6))
    {
        if (err != NULL && errsz > 0) {
            (void) ngx_snprintf((u_char *) err, errsz,
                                "address family excluded by policy%Z");
        }
        return NGX_DECLINED;
    }
    ngx_inet_set_port((struct sockaddr *) &lit.ss, req->port);
    addrs[0] = lit;
    *naddrs = 1;
    return NGX_OK;
}


/* Literal -> cache, no fill.  NGX_OK / NGX_DECLINED / NGX_AGAIN (unknown). */
ngx_int_t
brix_dns_cache_probe(const brix_dns_policy_t *policy, const char *host,
    in_port_t port, brix_af_policy_t af, brix_dns_addr_t *addrs,
    ngx_uint_t max, ngx_uint_t *naddrs, char *err, size_t errsz)
{
    brix_dns_req_t  req;
    ngx_uint_t      i;
    ngx_int_t       rc;

    *naddrs = 0;
    brix_dns_set_err(err, errsz, "");
    if (host == NULL || host[0] == '\0' || max == 0) {
        brix_dns_set_err(err, errsz, "empty hostname");
        return NGX_DECLINED;
    }
    ngx_memzero(&req, sizeof(req));
    req.name.data = (u_char *) host;
    req.name.len = ngx_strlen(host);
    req.port = port;
    req.af = af;
    req.socktype = SOCK_STREAM;
    req.policy = policy;
    req.log = ngx_cycle->log;

    rc = dns_lookup_literal(&req, addrs, naddrs, err, errsz);
    if (rc != NGX_AGAIN) {
        return rc;
    }
    if (brix_dns_cache_lookup(&req) != NGX_OK) {
        brix_dns_set_err(err, errsz, "no cached answer");
        return NGX_AGAIN;
    }
    if (req.rc != NGX_OK || req.naddrs == 0) {
        brix_dns_set_err(err, errsz,
                         req.error ? req.error : "no usable address");
        return NGX_DECLINED;
    }
    *naddrs = ngx_min(req.naddrs, max);
    for (i = 0; i < *naddrs; i++) {
        addrs[i] = req.addrs[i];
    }
    return NGX_OK;
}


ngx_int_t
brix_dns_lookup_cached(const brix_dns_policy_t *policy, const char *host,
    in_port_t port, brix_af_policy_t af, brix_dns_addr_t *addrs,
    ngx_uint_t max, ngx_uint_t *naddrs, char *err, size_t errsz)
{
    ngx_int_t  rc;

    rc = brix_dns_cache_probe(policy, host, port, af, addrs, max, naddrs,
                              err, errsz);
    if (rc != NGX_AGAIN) {
        return rc;
    }
    brix_dns_prefetch(policy, host, port, af);
    if (err != NULL && errsz > 0) {
        (void) ngx_snprintf((u_char *) err, errsz,
                            "resolution in progress%Z");
    }
    return NGX_AGAIN;
}
