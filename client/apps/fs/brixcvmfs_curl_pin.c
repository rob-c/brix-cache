/*
 * brixcvmfs_curl_pin.c — see brixcvmfs_curl_pin.h.
 *
 * HOW:  pin_split() takes "scheme://user:pw@host:port/path" or a bare
 *       "host:port" (proxy form, "[v6]:port" allowed) apart; pin_entry()
 *       resolves the host through brix_resolve() and formats libcurl's
 *       "host:port:ip1,ip2" CURLOPT_RESOLVE entry (literals need no entry —
 *       libcurl never resolves them); pin_attempt() installs the list for
 *       exactly one hop and clears it again so a pooled handle carries no
 *       stale pin into its next borrower.
 */
#include "brixcvmfs_curl_pin.h"
#include "brix.h"          /* brix_netpref_family() via brix_net.h */
#include "brix_net.h"
#include "net/resolve.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define PIN_HOST_MAX  256
#define PIN_ENTRY_MAX (PIN_HOST_MAX + 8 + BRIX_RESOLVE_MAX * (BRIX_RESOLVE_NTOP_LEN + 3))


/* default port of a scheme (1080 = libcurl's proxy default) */
static int
pin_default_port(const char *target, size_t scheme_len, int proxy)
{
    if (scheme_len == 5 && strncasecmp(target, "https", 5) == 0) {
        return 443;
    }
    return proxy ? 1080 : 80;
}


/* host + port of a URL or "host[:port]" target; 0 / -1 (malformed) */
static int
pin_split(const char *target, int proxy, char *host, size_t hostsz, int *port)
{
    const char *p = target, *sep = strstr(target, "://");
    const char *end, *colon, *at;
    size_t      scheme_len = 0, hlen;

    if (sep != NULL) {
        scheme_len = (size_t) (sep - target);
        p = sep + 3;
    }
    end = p + strcspn(p, "/?#");
    at = memchr(p, '@', (size_t) (end - p));
    if (at != NULL) {
        p = at + 1;                          /* drop user:pw@ */
    }
    *port = pin_default_port(target, scheme_len, proxy);
    if (*p == '[') {                         /* [v6]:port */
        const char *close = memchr(p, ']', (size_t) (end - p));
        if (close == NULL) {
            return -1;
        }
        hlen = (size_t) (close - p - 1);
        p++;
        colon = (close + 1 < end && close[1] == ':') ? close + 1 : NULL;
    } else {
        colon = memchr(p, ':', (size_t) (end - p));
        hlen = colon != NULL ? (size_t) (colon - p) : (size_t) (end - p);
    }
    if (hlen == 0 || hlen >= hostsz) {
        return -1;
    }
    if (colon != NULL) {
        char *e = NULL;
        long  v = strtol(colon + 1, &e, 10);
        if (e == colon + 1 || e != end || v <= 0 || v > 65535) {
            return -1;
        }
        *port = (int) v;
    }
    memcpy(host, p, hlen);
    host[hlen] = '\0';
    return 0;
}


static int
pin_is_literal(const char *host)
{
    struct in_addr  a4;
    struct in6_addr a6;
    return inet_pton(AF_INET, host, &a4) == 1
           || inet_pton(AF_INET6, host, &a6) == 1;
}


/* "host:port:ip1,ip2" for one target; 1 = entry written, 0 = literal (no
 * entry needed), -1 = the name has no address */
static int
pin_entry(const char *target, int proxy, char *out, size_t outsz)
{
    char               host[PIN_HOST_MAX], ip[BRIX_RESOLVE_NTOP_LEN];
    int                port, n, i;
    size_t             off;
    brix_resolve_addr  addrs[BRIX_RESOLVE_MAX];

    if (pin_split(target, proxy, host, sizeof(host), &port) != 0) {
        return -1;
    }
    if (pin_is_literal(host)) {
        return 0;
    }
    n = brix_resolve(host, port, brix_netpref_family(), SOCK_STREAM,
                     BRIX_RESOLVE_ADDRCONFIG, addrs, BRIX_RESOLVE_MAX, NULL);
    if (n <= 0) {
        return -1;
    }
    off = (size_t) snprintf(out, outsz, "%s:%d:", host, port);
    for (i = 0; i < n && off < outsz; i++) {
        brix_resolve_ntop((struct sockaddr *) &addrs[i].ss, addrs[i].len,
                          ip, sizeof(ip));
        off += (size_t) snprintf(out + off, outsz - off,
                                 addrs[i].family == AF_INET6 ? "%s[%s]" : "%s%s",
                                 i > 0 ? "," : "", ip);
    }
    return off < outsz ? 1 : -1;
}


/* resolve list for the hop: the target and, when set, the proxy */
static CURLcode
pin_build(const cvmfs_curl_transfer *t, const char *url,
          struct curl_slist **list)
{
    char  entry[PIN_ENTRY_MAX];
    int   rc;

    *list = NULL;
    if (t->proxy != NULL && t->proxy[0] != '\0') {
        rc = pin_entry(t->proxy, 1, entry, sizeof(entry));
        if (rc < 0) {
            return CURLE_COULDNT_RESOLVE_PROXY;
        }
        if (rc > 0) {
            *list = curl_slist_append(*list, entry);
        }
    }
    rc = pin_entry(url, 0, entry, sizeof(entry));
    if (rc < 0) {
        curl_slist_free_all(*list);
        *list = NULL;
        return CURLE_COULDNT_RESOLVE_HOST;
    }
    if (rc > 0) {
        *list = curl_slist_append(*list, entry);
    }
    return CURLE_OK;
}


/* one hop: pin, perform, report the redirect target (owned by libcurl until
 * the next perform — the caller copies it) */
static CURLcode
pin_attempt(CURL *c, const cvmfs_curl_transfer *t, const char *url,
            char *next, size_t nextsz)
{
    struct curl_slist *list = NULL;
    char              *redir = NULL;
    CURLcode           rc;

    next[0] = '\0';
    rc = pin_build(t, url, &list);
    if (rc != CURLE_OK) {
        return rc;
    }
    curl_easy_setopt(c, CURLOPT_RESOLVE, list);
    curl_easy_setopt(c, CURLOPT_URL, url);
    if (t->on_hop != NULL) {
        t->on_hop(t->ud);
    }
    rc = curl_easy_perform(c);
    if (rc == CURLE_OK
        && curl_easy_getinfo(c, CURLINFO_REDIRECT_URL, &redir) == CURLE_OK
        && redir != NULL)
    {
        snprintf(next, nextsz, "%s", redir);
    }
    curl_easy_setopt(c, CURLOPT_RESOLVE, NULL);   /* before the free */
    curl_slist_free_all(list);
    return rc;
}


CURLcode
cvmfs_curl_perform_pinned(CURL *c, const cvmfs_curl_transfer *t,
                          const char *url)
{
    char      cur[1024], next[1024];
    long      hops;
    CURLcode  rc;

    snprintf(cur, sizeof(cur), "%s", url);
    for (hops = 0; ; hops++) {
        rc = pin_attempt(c, t, cur, next, sizeof(next));
        if (rc != CURLE_OK || next[0] == '\0') {
            return rc;
        }
        if (hops >= t->max_redirects) {
            return CURLE_TOO_MANY_REDIRECTS;
        }
        memcpy(cur, next, sizeof(cur));
    }
}
