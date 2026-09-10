/*
 * curl_pin.h — CURLOPT_RESOLVE pinning for libcurl callers (phase-116 App. A).
 *
 * WHAT: brix_dns_curl_pin() resolves the host of `url` through
 *       brix_dns_resolve_sync() and pins the answer into the easy handle
 *       with CURLOPT_RESOLVE, so libcurl never runs its own resolver.
 *       brix_dns_curl_pin_entry() is the shared "host:port:ip1,ip2" formatter
 *       (also used by the WebDAV TPC pin, which has its own policy check).
 * WHY:  libcurl resolves with getaddrinfo (or c-ares) on whatever thread
 *       performs the transfer — a second resolver path with its own cache and
 *       its own idea of resolv.conf.  Pinning keeps every lookup in the one
 *       driver (I-DNS-2/3) and makes the seam guard's rule mechanical: a
 *       CURLOPT_URL without a pin call is a defect.
 * HOW:  Thread-pool code only (the sync resolver blocks).  The slist the
 *       caller receives must outlive curl_easy_perform() and be freed after
 *       it; every pin call first clears CURLOPT_RESOLVE, so a warm per-thread
 *       handle never keeps a pointer to a list its previous request freed,
 *       and a literal host after a named one pins nothing.
 *       brix_dns_curl_perform_pinned() is the transfer loop for callers that
 *       used to set CURLOPT_FOLLOWLOCATION: libcurl would resolve each
 *       Location host itself, so the helper follows redirects by hand and
 *       re-pins every hop through the same driver.
 */
#ifndef BRIX_NET_DNS_CURL_PIN_H
#define BRIX_NET_DNS_CURL_PIN_H

#include <curl/curl.h>

#include "net/dns/dns.h"

/* Format one CURLOPT_RESOLVE entry ("host:port:ip[,ip…]", IPv6 bracketed).
 * Returns the length written, 0 on overflow. */
size_t brix_dns_curl_pin_entry(const char *host, in_port_t port,
    const brix_dns_addr_t *addrs, ngx_uint_t naddrs, char *out, size_t sz);

/* Resolve the host in `url` and pin it.  NGX_OK: *resolve_out holds the list
 * to free after the transfer; NGX_ERROR: err filled, nothing pinned.  A URL
 * whose host is an IP literal pins nothing and returns NGX_OK with a NULL
 * list. */
ngx_int_t brix_dns_curl_pin(CURL *curl, const brix_dns_policy_t *policy,
    const char *url, struct curl_slist **resolve_out, char *err,
    size_t errsz);

/* Longest URL (initial or Location) a pinned transfer follows. */
#define BRIX_DNS_CURL_URL_MAX  2048

/* Total wall-clock ceiling a pinned transfer gets when the caller names none.
 * Never 0: libcurl reads 0 as "no timeout", and an unbounded blocking perform
 * on a black-holed endpoint hangs the thread-pool thread for ever.  Matches
 * the S3 origin's own fallback ceiling.  Left overridable at compile time for
 * one caller only: tests/c/curl_pin_budget_test.c proves the fallback bounds a
 * black hole without the unit waiting a minute to do it. */
#ifndef BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT
#define BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT  60000
#endif

/* One pinned transfer that may redirect.  `on_hop` (optional) runs before
 * every attempt so the caller can rewind its response sink; `err` receives
 * the resolution failure text when the result is CURLE_COULDNT_RESOLVE_HOST. */
typedef struct {
    const brix_dns_policy_t  *policy;
    const char               *url;
    ngx_uint_t                max_redirects;
    /* Total ms for the whole transfer, redirects included.  <= 0 takes
     * BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT; the loop spends it down hop by hop, so
     * a chain of N redirects cannot cost N times the caller's timeout. */
    long                      timeout_ms;
    void                    (*on_hop)(void *data);
    void                     *hop_data;
    char                     *err;
    size_t                    errsz;
} brix_dns_curl_transfer_t;

/* Perform `t->url` on `curl`, re-pinning each redirect hop (Location taken
 * from CURLINFO_REDIRECT_URL) through the driver.  Method and body options
 * stay as the caller set them, so a POST is re-issued as a POST (307/308
 * semantics).  Returns the last curl_easy_perform() result, or
 * CURLE_TOO_MANY_REDIRECTS / CURLE_URL_MALFORMAT / CURLE_COULDNT_RESOLVE_HOST
 * / CURLE_OPERATION_TIMEDOUT from the loop itself.  The caller must NOT set
 * CURLOPT_FOLLOWLOCATION or CURLOPT_URL, and need not set a timeout: the loop
 * owns the budget and overrides CURLOPT_TIMEOUT_MS / CURLOPT_CONNECTTIMEOUT_MS
 * on every hop with what is left of `timeout_ms`. */
CURLcode brix_dns_curl_perform_pinned(CURL *curl,
    const brix_dns_curl_transfer_t *t);

#endif /* BRIX_NET_DNS_CURL_PIN_H */
