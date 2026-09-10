/*
 * client_resolve_test.c — brix_resolve() unit (phase-116 client DNS seam).
 *
 * WHAT: Exercises client/lib/net/resolve.c hermetically: literal v4/v6
 *       answers with the port carried through, the NUMERIC / PASSIVE flags,
 *       argument validation, the positive-answer cache (one libc call per
 *       key per TTL window; a port, family or flag change is a new key) and
 *       the never-cached classes (literals under NUMERIC, EAI_AGAIN, NXDOMAIN).
 * WHY:  The seam is only worth pinning if its contract is checked without a
 *       resolver: getaddrinfo()/freeaddrinfo() are interposed in this
 *       executable (the static link binds resolve.c's calls here), so no
 *       resolv.conf, nameserver or network is involved and the call count
 *       is exact.
 * HOW:  `argv[1] == "nocache"` asserts the harness exported
 *       XRDC_RESOLVE_CACHE_S=0 and expects one libc call per brix_resolve();
 *       the default mode expects the 60 s cache to absorb the repeats.
 */
#define _GNU_SOURCE 1
#include "net/resolve.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int  g_calls;
static int  g_failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
            g_failures++;                                                    \
        }                                                                    \
    } while (0)


static struct addrinfo *
fake_ai(int family, const void *addr, int port, int socktype)
{
    struct addrinfo     *ai = calloc(1, sizeof(*ai));
    struct sockaddr_in  *sin;
    struct sockaddr_in6 *sin6;

    if (ai == NULL) {
        return NULL;
    }
    ai->ai_family = family;
    ai->ai_socktype = socktype ? socktype : SOCK_STREAM;
    if (family == AF_INET) {
        sin = calloc(1, sizeof(*sin));
        sin->sin_family = AF_INET;
        sin->sin_port = htons((unsigned short) port);
        memcpy(&sin->sin_addr, addr, sizeof(sin->sin_addr));
        ai->ai_addr = (struct sockaddr *) sin;
        ai->ai_addrlen = sizeof(*sin);
    } else {
        sin6 = calloc(1, sizeof(*sin6));
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((unsigned short) port);
        memcpy(&sin6->sin6_addr, addr, sizeof(sin6->sin6_addr));
        ai->ai_addr = (struct sockaddr *) sin6;
        ai->ai_addrlen = sizeof(*sin6);
    }
    return ai;
}


/* Interposed libc resolver: literals via inet_pton (AI_NUMERICHOST honoured),
 * "again.test" -> EAI_AGAIN, "two.test" -> two A records, anything else ->
 * EAI_NONAME.  Counts every call. */
int
getaddrinfo(const char *node, const char *service,
            const struct addrinfo *hints, struct addrinfo **res)
{
    int              flags = hints ? hints->ai_flags : 0;
    int              family = hints ? hints->ai_family : AF_UNSPEC;
    int              socktype = hints ? hints->ai_socktype : 0;
    int              port = service ? atoi(service) : 0;
    struct in_addr   a4;
    struct in6_addr  a6;

    g_calls++;
    *res = NULL;
    if (node == NULL) {
        if (!(flags & AI_PASSIVE)) {
            return EAI_NONAME;
        }
        node = (family == AF_INET6) ? "::" : "0.0.0.0";
    }
    if (inet_pton(AF_INET, node, &a4) == 1) {
        if (family == AF_INET6) {
            return EAI_NONAME;
        }
        *res = fake_ai(AF_INET, &a4, port, socktype);
        return 0;
    }
    if (inet_pton(AF_INET6, node, &a6) == 1) {
        if (family == AF_INET) {
            return EAI_NONAME;
        }
        *res = fake_ai(AF_INET6, &a6, port, socktype);
        return 0;
    }
    if (flags & AI_NUMERICHOST) {
        return EAI_NONAME;
    }
    if (strcmp(node, "again.test") == 0) {
        return EAI_AGAIN;
    }
    if (strcmp(node, "two.test") == 0 && family != AF_INET6) {
        inet_pton(AF_INET, "10.1.1.1", &a4);
        *res = fake_ai(AF_INET, &a4, port, socktype);
        inet_pton(AF_INET, "10.1.1.2", &a4);
        (*res)->ai_next = fake_ai(AF_INET, &a4, port, socktype);
        return 0;
    }
    return EAI_NONAME;
}


void
freeaddrinfo(struct addrinfo *res)
{
    while (res != NULL) {
        struct addrinfo *next = res->ai_next;
        free(res->ai_addr);
        free(res);
        res = next;
    }
}


static const char *
ntop(const brix_resolve_addr *a, char *buf)
{
    return brix_resolve_ntop((const struct sockaddr *) &a->ss, a->len, buf,
                             BRIX_RESOLVE_NTOP_LEN);
}


static void
test_literals(void)
{
    brix_resolve_addr  out[4];
    brix_resolve_err   err;
    char               buf[BRIX_RESOLVE_NTOP_LEN];

    CHECK(brix_resolve("127.0.0.1", 1094, AF_UNSPEC, SOCK_STREAM,
                       BRIX_RESOLVE_NUMERIC, out, 4, &err) == 1);
    CHECK(out[0].family == AF_INET);
    CHECK(strcmp(ntop(&out[0], buf), "127.0.0.1") == 0);
    CHECK(brix_resolve_port((struct sockaddr *) &out[0].ss, out[0].len)
          == 1094);

    CHECK(brix_resolve("::1", 443, AF_UNSPEC, SOCK_STREAM,
                       BRIX_RESOLVE_NUMERIC, out, 4, &err) == 1);
    CHECK(out[0].family == AF_INET6);
    CHECK(strcmp(ntop(&out[0], buf), "::1") == 0);
    CHECK(brix_resolve_port((struct sockaddr *) &out[0].ss, out[0].len)
          == 443);

    /* a family filter that excludes the literal is "no address", not -1 */
    CHECK(brix_resolve("::1", 443, AF_INET, SOCK_STREAM, BRIX_RESOLVE_NUMERIC,
                       out, 4, &err) == 0);
    CHECK(err.transient == 0 && err.text != NULL);

    /* NUMERIC on a name never reaches DNS: the fake refuses with NONAME */
    CHECK(brix_resolve("two.test", 1, AF_UNSPEC, SOCK_STREAM,
                       BRIX_RESOLVE_NUMERIC, out, 4, &err) == 0);
    CHECK(err.transient == 0);

    /* PASSIVE with a NULL host is the wildcard bind address */
    CHECK(brix_resolve(NULL, 8080, AF_INET, SOCK_STREAM, BRIX_RESOLVE_PASSIVE,
                       out, 4, &err) == 1);
    CHECK(strcmp(ntop(&out[0], buf), "0.0.0.0") == 0);
}


static void
test_bad_args(void)
{
    brix_resolve_addr  out[2];
    int                before = g_calls;

    CHECK(brix_resolve(NULL, 80, AF_UNSPEC, SOCK_STREAM, 0, out, 2, NULL)
          == -1);
    CHECK(brix_resolve("two.test", 80, AF_UNSPEC, SOCK_STREAM, 0, NULL, 2,
                       NULL) == -1);
    CHECK(brix_resolve("two.test", 80, AF_UNSPEC, SOCK_STREAM, 0, out, 0,
                       NULL) == -1);
    CHECK(brix_resolve("two.test", 70000, AF_UNSPEC, SOCK_STREAM, 0, out, 2,
                       NULL) == -1);
    CHECK(brix_resolve("two.test", -1, AF_UNSPEC, SOCK_STREAM, 0, out, 2,
                       NULL) == -1);
    CHECK(g_calls == before);                  /* rejected before libc */

    /* ntop / port on garbage never crash and never consult a resolver */
    CHECK(strcmp(brix_resolve_ntop(NULL, 0, out[0].ss.__ss_padding, 8), "")
          == 0);
    CHECK(brix_resolve_port(NULL, 0) == -1);
}


static void
test_cache(int cache_on)
{
    brix_resolve_addr  out[4];
    brix_resolve_err   err;
    char               buf[BRIX_RESOLVE_NTOP_LEN];
    int                before = g_calls;

    CHECK(brix_resolve("two.test", 1094, AF_UNSPEC, SOCK_STREAM, 0, out, 4,
                       &err) == 2);
    CHECK(strcmp(ntop(&out[0], buf), "10.1.1.1") == 0);
    CHECK(strcmp(ntop(&out[1], buf), "10.1.1.2") == 0);
    CHECK(g_calls == before + 1);

    /* the same key again: served from the cache when it is on */
    CHECK(brix_resolve("two.test", 1094, AF_UNSPEC, SOCK_STREAM, 0, out, 4,
                       &err) == 2);
    CHECK(brix_resolve_port((struct sockaddr *) &out[1].ss, out[1].len)
          == 1094);
    CHECK(g_calls == before + (cache_on ? 1 : 2));

    /* a different port, family or flag set is a different key */
    before = g_calls;
    CHECK(brix_resolve("two.test", 1095, AF_UNSPEC, SOCK_STREAM, 0, out, 4,
                       &err) == 2);
    CHECK(brix_resolve("two.test", 1094, AF_INET, SOCK_STREAM, 0, out, 4,
                       &err) == 2);
    CHECK(brix_resolve("two.test", 1094, AF_UNSPEC, SOCK_STREAM,
                       BRIX_RESOLVE_ADDRCONFIG, out, 4, &err) == 2);
    CHECK(g_calls == before + 3);

    /* `max` clamps the copy, never the libc call */
    CHECK(brix_resolve("two.test", 2000, AF_UNSPEC, SOCK_STREAM, 0, out, 1,
                       &err) == 1);
}


static void
test_never_cached(void)
{
    brix_resolve_addr  out[4];
    brix_resolve_err   err;
    int                before = g_calls;

    /* transient: reported as such, and the next call asks again */
    CHECK(brix_resolve("again.test", 80, AF_UNSPEC, SOCK_STREAM, 0, out, 4,
                       &err) == 0);
    CHECK(err.transient == 1 && err.text != NULL);
    CHECK(brix_resolve("again.test", 80, AF_UNSPEC, SOCK_STREAM, 0, out, 4,
                       &err) == 0);
    CHECK(g_calls == before + 2);

    /* permanent failure: not transient, and not cached either */
    before = g_calls;
    CHECK(brix_resolve("nope.test", 80, AF_UNSPEC, SOCK_STREAM, 0, out, 4,
                       &err) == 0);
    CHECK(err.transient == 0 && err.text != NULL);
    CHECK(brix_resolve("nope.test", 80, AF_UNSPEC, SOCK_STREAM, 0, out, 4,
                       &err) == 0);
    CHECK(g_calls == before + 2);

    /* literals under NUMERIC bypass the cache both ways */
    before = g_calls;
    CHECK(brix_resolve("10.9.9.9", 80, AF_UNSPEC, SOCK_STREAM,
                       BRIX_RESOLVE_NUMERIC, out, 4, &err) == 1);
    CHECK(brix_resolve("10.9.9.9", 80, AF_UNSPEC, SOCK_STREAM,
                       BRIX_RESOLVE_NUMERIC, out, 4, &err) == 1);
    CHECK(g_calls == before + 2);
}


int
main(int argc, char **argv)
{
    int          nocache = (argc > 1 && strcmp(argv[1], "nocache") == 0);
    const char  *env = getenv("XRDC_RESOLVE_CACHE_S");

    if (nocache && (env == NULL || strcmp(env, "0") != 0)) {
        fprintf(stderr, "nocache mode needs XRDC_RESOLVE_CACHE_S=0\n");
        return 2;
    }
    if (!nocache && env != NULL) {
        fprintf(stderr, "cache mode must not inherit XRDC_RESOLVE_CACHE_S\n");
        return 2;
    }

    test_literals();
    test_bad_args();
    test_cache(!nocache);
    test_never_cached();

    if (g_failures != 0) {
        fprintf(stderr, "client_resolve unittest: %d check(s) failed\n",
                g_failures);
        return 1;
    }
    printf("client_resolve unittest: all checks passed (%s)\n",
           nocache ? "cache off" : "cache on");
    return 0;
}
