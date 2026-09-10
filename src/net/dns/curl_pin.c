/*
 * curl_pin.c — CURLOPT_RESOLVE pinning (phase-116 Appendix A).  See curl_pin.h.
 */
#include "net/dns/curl_pin.h"
#include "core/compat/net_target.h"
#include "core/compat/host_format.h"

#define CURL_PIN_DEFAULT_HTTPS  443
#define CURL_PIN_DEFAULT_HTTP   80


size_t
brix_dns_curl_pin_entry(const char *host, in_port_t port,
    const brix_dns_addr_t *addrs, ngx_uint_t naddrs, char *out, size_t sz)
{
    char        ip[BRIX_DNS_NTOP_LEN];
    size_t      n;
    ngx_uint_t  i;

    n = brix_format_host_port(host, port, out, sz);
    if (n == 0 || naddrs == 0) {
        return 0;
    }
    for (i = 0; i < naddrs; i++) {
        if (brix_dns_addr_ntop(&addrs[i], ip, sizeof(ip)) == 0) {
            continue;
        }
        if (n + 1 + ngx_strlen(ip) + 1 > sz) {
            return 0;
        }
        out[n++] = (i == 0) ? ':' : ',';
        n += ngx_cpystrn((u_char *) out + n, (u_char *) ip, sz - n)
             - ((u_char *) out + n);
    }
    return n;
}


static in_port_t
curl_pin_port(const brix_net_target_t *t)
{
    if (t->has_port) {
        return t->port;
    }
    if (t->scheme.len == 4 && ngx_strncasecmp(t->scheme.data,
                                              (u_char *) "http", 4) == 0)
    {
        return CURL_PIN_DEFAULT_HTTP;
    }
    return CURL_PIN_DEFAULT_HTTPS;
}


ngx_int_t
brix_dns_curl_pin(CURL *curl, const brix_dns_policy_t *policy, const char *url,
    struct curl_slist **resolve_out, char *err, size_t errsz)
{
    brix_net_target_t   tgt;
    brix_dns_addr_t     addrs[BRIX_DNS_MAX_ADDRS], lit;
    ngx_str_t           url_str, host;
    char                hostz[BRIX_RESOLV_DOMAIN_LEN];
    char                entry[BRIX_RESOLV_DOMAIN_LEN + 8
                              + BRIX_DNS_MAX_ADDRS * BRIX_DNS_NTOP_LEN];
    struct curl_slist  *list;
    ngx_uint_t          n;
    in_port_t           port;

    *resolve_out = NULL;
    /* a reused handle must never keep a list its previous request freed */
    (void) curl_easy_setopt(curl, CURLOPT_RESOLVE, NULL);
    url_str.data = (u_char *) url;
    url_str.len = ngx_strlen(url);
    if (brix_net_target_parse(NULL, &url_str, &tgt, err, errsz) != NGX_OK) {
        return NGX_ERROR;
    }
    host = tgt.host;
    if (host.len == 0 || host.len >= sizeof(hostz)) {
        (void) ngx_snprintf((u_char *) err, errsz, "invalid URL host%Z");
        return NGX_ERROR;
    }
    if (brix_dns_parse_literal(&host, &lit) == NGX_OK) {
        return NGX_OK;                        /* literal: libcurl needs no DNS */
    }
    ngx_cpystrn((u_char *) hostz, host.data, host.len + 1);
    port = curl_pin_port(&tgt);

    n = brix_dns_resolve_sync(policy, hostz, port, BRIX_AF_AUTO, SOCK_STREAM,
                              addrs, BRIX_DNS_MAX_ADDRS, err, errsz);
    if (n == 0) {
        return NGX_ERROR;
    }
    if (brix_dns_curl_pin_entry(hostz, port, addrs, n, entry, sizeof(entry))
        == 0)
    {
        (void) ngx_snprintf((u_char *) err, errsz, "resolve entry overflow%Z");
        return NGX_ERROR;
    }
    list = curl_slist_append(NULL, entry);
    if (list == NULL) {
        (void) ngx_snprintf((u_char *) err, errsz, "curl_slist_append failed%Z");
        return NGX_ERROR;
    }
    if (curl_easy_setopt(curl, CURLOPT_RESOLVE, list) != CURLE_OK) {
        curl_slist_free_all(list);
        (void) ngx_snprintf((u_char *) err, errsz, "CURLOPT_RESOLVE failed%Z");
        return NGX_ERROR;
    }
    *resolve_out = list;
    return NGX_OK;
}


static CURLcode
curl_pin_copy_target(const char *src, char *target, size_t sz, char *err,
    size_t errsz)
{
    if (ngx_strlen(src) >= sz) {
        (void) ngx_snprintf((u_char *) err, errsz, "URL too long%Z");
        return CURLE_URL_MALFORMAT;
    }
    ngx_cpystrn((u_char *) target, (u_char *) src, sz);
    return CURLE_OK;
}


/* WHAT: the transfer's total ms budget — the caller's, or the default.
 * WHY:  a caller that names none must still be bounded; 0 would mean
 *       "for ever" to libcurl, which is the denial-of-service this guards. */
static long
curl_pin_budget(const brix_dns_curl_transfer_t *t)
{
    return (t->timeout_ms > 0) ? t->timeout_ms
                               : (long) BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT;
}


/* WHAT: what is left of the budget, 0 once it is spent.
 * HOW:  `spent_us` is the sum of CURLINFO_TOTAL_TIME_T over the hops already
 *       performed — libcurl's own clock, so the loop needs none of its own
 *       (ngx_current_msec does not advance on a thread-pool thread). */
static long
curl_pin_remaining(long budget_ms, curl_off_t spent_us)
{
    long  spent_ms = (long) (spent_us / 1000);

    return (spent_ms >= budget_ms) ? 0 : budget_ms - spent_ms;
}


/* WHAT: microseconds the attempt just performed took, 0 if libcurl cannot say.
 */
static curl_off_t
curl_pin_spent(CURL *curl)
{
    curl_off_t  us = 0;

    if (curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME_T, &us) != CURLE_OK) {
        return 0;
    }
    return (us > 0) ? us : 0;
}


/* WHAT: bound this hop.
 * WHY:  the wrapper performs on a handle it did not create, so the bound has
 *       to be set here rather than trusted to the caller; NOSIGNAL keeps
 *       libcurl from raising SIGALRM on a thread-pool thread. */
static void
curl_pin_bound(CURL *curl, long timeout_ms)
{
    (void) curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    (void) curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    (void) curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);
}


/* WHAT: one attempt of the pinned loop — pin, aim, rewind the sink, perform,
 *       and read the Location libcurl would have followed.
 * HOW:  *next is NULL unless the response was a redirect; it points into the
 *       handle and is valid until the next perform, so the caller copies it
 *       before looping. */
static CURLcode
curl_pin_attempt(CURL *curl, const brix_dns_curl_transfer_t *t,
    const char *target, long timeout_ms, char **next)
{
    struct curl_slist  *resolve;
    CURLcode            res;

    *next = NULL;
    if (brix_dns_curl_pin(curl, t->policy, target, &resolve, t->err, t->errsz)
        != NGX_OK)
    {
        return CURLE_COULDNT_RESOLVE_HOST;
    }
    curl_easy_setopt(curl, CURLOPT_URL, target);
    curl_pin_bound(curl, timeout_ms);
    if (t->on_hop != NULL) {
        t->on_hop(t->hop_data);
    }
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, next);
    }
    curl_slist_free_all(resolve);
    return res;
}


CURLcode
brix_dns_curl_perform_pinned(CURL *curl, const brix_dns_curl_transfer_t *t)
{
    char        target[BRIX_DNS_CURL_URL_MAX];
    char       *next;
    CURLcode    res;
    ngx_uint_t  hop;
    long        budget, left;
    curl_off_t  spent;

    if (t->err != NULL && t->errsz > 0) {
        t->err[0] = '\0';
    }
    budget = curl_pin_budget(t);
    spent = 0;
    res = curl_pin_copy_target(t->url, target, sizeof(target), t->err,
                               t->errsz);
    for (hop = 0; res == CURLE_OK; hop++) {
        left = curl_pin_remaining(budget, spent);
        if (left == 0) {
            (void) ngx_snprintf((u_char *) t->err, t->errsz,
                                "timeout budget spent after %ui hop(s)%Z", hop);
            return CURLE_OPERATION_TIMEDOUT;
        }
        res = curl_pin_attempt(curl, t, target, left, &next);
        spent += curl_pin_spent(curl);
        if (res != CURLE_OK || next == NULL) {
            return res;
        }
        if (hop >= t->max_redirects) {
            (void) ngx_snprintf((u_char *) t->err, t->errsz,
                                "too many redirects (%ui)%Z", hop);
            return CURLE_TOO_MANY_REDIRECTS;
        }
        res = curl_pin_copy_target(next, target, sizeof(target), t->err,
                                   t->errsz);
    }
    return res;
}
