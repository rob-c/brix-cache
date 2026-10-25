/* Standalone STS runtime: no nginx event loop or worker DNS cache.
 * Names still resolve through the REAL resolve_thread.c libc seam, and the
 * REAL curl_pin.c validates and pins them. Never stub successful DNS answers.
 */
#include "net/dns/dns.h"

ngx_int_t
brix_dns_cache_lookup(brix_dns_req_t *req)
{
    (void) req;
    return NGX_DECLINED;
}

void
brix_dns_cache_store(const brix_dns_req_t *req)
{
    (void) req;
}

void
brix_dns_lookup_note(ngx_uint_t result)
{
    (void) result;
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
