/*
 * resolve.c — the client's one getaddrinfo() (phase-116).  See resolve.h.
 *
 * HOW:  brix_resolve() = cache probe → getaddrinfo() → copy the chain into
 *       fixed sockaddr_storage slots → cache store.  The cache is a small
 *       array of slots replaced round-robin under a mutex: cheap, bounded,
 *       and enough to turn the cvmfs per-object GET storm into one lookup a
 *       minute per mirror (libcurl's own default DNS cache TTL).  Negative
 *       answers are not cached — a name that is not there yet (a fleet
 *       coming up) must not stay "not there" for a minute.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1               /* AI_ADDRCONFIG / AI_NUMERICSERV, strcasecmp */
#endif
#include "net/resolve.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define RESOLVE_CACHE_SLOTS   32
#define RESOLVE_HOST_MAX      256

typedef struct {
    char               host[RESOLVE_HOST_MAX];
    int                port, family, socktype;
    unsigned           flags;
    time_t             expires;           /* CLOCK_MONOTONIC seconds */
    int                n;
    brix_resolve_addr  addrs[BRIX_RESOLVE_MAX];
} resolve_slot;

/* per-process answer cache (netpref.c precedent: process-wide net state) */
static resolve_slot     g_cache[RESOLVE_CACHE_SLOTS];
static unsigned         g_cache_next;
static long             g_cache_ttl = -1;     /* -1 = env not read yet */
static pthread_mutex_t  g_cache_mu = PTHREAD_MUTEX_INITIALIZER;


static time_t
resolve_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}


/* TTL in seconds, read once from the environment (0 disables the cache);
 * called under g_cache_mu only. */
static long
resolve_cache_ttl(void)
{
    if (g_cache_ttl < 0) {
        const char *e = getenv("XRDC_RESOLVE_CACHE_S");
        g_cache_ttl = (e != NULL) ? strtol(e, NULL, 10) : BRIX_RESOLVE_CACHE_S;
        if (g_cache_ttl < 0) {
            g_cache_ttl = 0;
        }
    }
    return g_cache_ttl;
}


static int
resolve_slot_matches(const resolve_slot *s, const char *host, int port,
                     int family, int socktype, unsigned flags)
{
    return s->n > 0 && s->port == port && s->family == family
           && s->socktype == socktype && s->flags == flags
           && strcasecmp(s->host, host) == 0;
}


/* copy a live cached answer into out; its count, or 0 on a miss */
static int
resolve_cache_get(const char *host, int port, int family, int socktype,
                  unsigned flags, brix_resolve_addr *out, int max)
{
    time_t  now = resolve_now();
    int     n = 0, i;

    pthread_mutex_lock(&g_cache_mu);
    for (i = 0; i < RESOLVE_CACHE_SLOTS && n == 0; i++) {
        const resolve_slot *s = &g_cache[i];
        if (s->expires > now
            && resolve_slot_matches(s, host, port, family, socktype, flags))
        {
            n = (s->n < max) ? s->n : max;
            memcpy(out, s->addrs, (size_t) n * sizeof(*out));
        }
    }
    pthread_mutex_unlock(&g_cache_mu);
    return n;
}


static void
resolve_cache_put(const char *host, int port, int family, int socktype,
                  unsigned flags, const brix_resolve_addr *addrs, int n)
{
    long  ttl;

    pthread_mutex_lock(&g_cache_mu);
    ttl = resolve_cache_ttl();
    if (ttl > 0 && strlen(host) < RESOLVE_HOST_MAX) {
        resolve_slot *s = &g_cache[g_cache_next++ % RESOLVE_CACHE_SLOTS];
        snprintf(s->host, sizeof(s->host), "%s", host);
        s->port = port;
        s->family = family;
        s->socktype = socktype;
        s->flags = flags;
        s->n = n;
        memcpy(s->addrs, addrs, (size_t) n * sizeof(*addrs));
        s->expires = resolve_now() + ttl;
    }
    pthread_mutex_unlock(&g_cache_mu);
}


static int
resolve_hint_flags(unsigned flags)
{
    int ai = AI_NUMERICSERV;               /* the port is always decimal */

    if (flags & BRIX_RESOLVE_ADDRCONFIG) {
        ai |= AI_ADDRCONFIG;
    }
    if (flags & BRIX_RESOLVE_PASSIVE) {
        ai |= AI_PASSIVE;
    }
    if (flags & BRIX_RESOLVE_NUMERIC) {
        ai |= AI_NUMERICHOST;
    }
    return ai;
}


static int
resolve_copy_chain(const struct addrinfo *res, brix_resolve_addr *out, int max)
{
    const struct addrinfo *ai;
    int                    n = 0;

    for (ai = res; ai != NULL && n < max; ai = ai->ai_next) {
        if (ai->ai_addr == NULL || ai->ai_addrlen > sizeof(out[n].ss)) {
            continue;
        }
        memset(&out[n], 0, sizeof(out[n]));
        memcpy(&out[n].ss, ai->ai_addr, ai->ai_addrlen);
        out[n].len = ai->ai_addrlen;
        out[n].family = ai->ai_family;
        out[n].socktype = ai->ai_socktype;
        out[n].protocol = ai->ai_protocol;
        n++;
    }
    return n;
}


int
brix_resolve(const char *host, int port, int family, int socktype,
             unsigned flags, brix_resolve_addr *out, int max,
             brix_resolve_err *err)
{
    struct addrinfo  hints, *res = NULL;
    char             portstr[16];
    const char      *key = (host != NULL) ? host : "";
    int              gai, n;

    if (err != NULL) {
        err->transient = 0;
        err->text = NULL;
    }
    if (out == NULL || max <= 0 || port < 0 || port > 65535
        || (host == NULL && !(flags & BRIX_RESOLVE_PASSIVE)))
    {
        return -1;
    }
    n = resolve_cache_get(key, port, family, socktype, flags, out, max);
    if (n > 0) {
        return n;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = socktype;
    hints.ai_flags    = resolve_hint_flags(flags);
    snprintf(portstr, sizeof(portstr), "%d", port);
    gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0) {
        if (err != NULL) {
            err->transient = (gai == EAI_AGAIN);
            err->text = gai_strerror(gai);
        }
        return 0;
    }
    n = resolve_copy_chain(res, out, max);
    freeaddrinfo(res);
    if (n == 0) {
        if (err != NULL) {
            err->text = "no usable address";
        }
        return 0;
    }
    if (!(flags & BRIX_RESOLVE_NUMERIC)) {
        resolve_cache_put(key, port, family, socktype, flags, out, n);
    }
    return n;
}


const char *
brix_resolve_ntop(const struct sockaddr *sa, socklen_t len, char *buf,
                  size_t buflen)
{
    const void *src = NULL;

    if (buf == NULL || buflen == 0) {
        return "";
    }
    buf[0] = '\0';
    if (sa == NULL) {
        return buf;
    }
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        src = &((const struct sockaddr_in *) sa)->sin_addr;
    } else if (sa->sa_family == AF_INET6
               && len >= sizeof(struct sockaddr_in6))
    {
        src = &((const struct sockaddr_in6 *) sa)->sin6_addr;
    }
    if (src == NULL
        || inet_ntop(sa->sa_family, src, buf, (socklen_t) buflen) == NULL)
    {
        buf[0] = '\0';
    }
    return buf;
}


int
brix_resolve_port(const struct sockaddr *sa, socklen_t len)
{
    if (sa == NULL) {
        return -1;
    }
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        return ntohs(((const struct sockaddr_in *) sa)->sin_port);
    }
    if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
        return ntohs(((const struct sockaddr_in6 *) sa)->sin6_port);
    }
    return -1;
}
