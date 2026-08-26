/*
 * gai_shim.c — LD_PRELOAD getaddrinfo override for the IPv6→IPv4 fallback test.
 *
 * WHAT: For the sentinel host "dualstack.invalid" it synthesises a dual-stack
 *       result — ::1 first, then 127.0.0.1, both on the requested port — so a
 *       connect exercises the real happy-eyeballs + auto-downgrade path in
 *       brix_tcp_connect (sock.c) regardless of how the host resolves localhost.
 *       It also honours the ai_family hint, returning ONLY the IPv4 record when
 *       the caller pins AF_INET — exactly what netpref does after demotion — so
 *       the test can prove the resolver stops offering v6 once demoted.
 * WHY:  CI hosts vary wildly in whether "localhost" carries a ::1 record; a shim
 *       makes the test deterministic and host-independent (needs only a working
 *       ::1 loopback, near-universal on Linux).
 * HOW:  Each result node is one calloc block with the sockaddr inline and
 *       ai_canonname == NULL, so the process's real freeaddrinfo frees it safely.
 *       Any other host name delegates to the real getaddrinfo via dlsym.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char SENTINEL[] = "dualstack.invalid";   /* [::1, 127.0.0.1] */
static const char V6ONLY[]   = "v6only.invalid";      /* ::1 only (no A record) */

typedef int (*gai_fn)(const char *, const char *,
                      const struct addrinfo *, struct addrinfo **);

static struct addrinfo *
mk_node(int family, int port)
{
    size_t addrlen = (family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                          : sizeof(struct sockaddr_in);
    struct addrinfo *ai = calloc(1, sizeof(*ai) + addrlen);
    if (ai == NULL) {
        return NULL;
    }
    ai->ai_family   = family;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addrlen  = (socklen_t) addrlen;
    ai->ai_addr     = (struct sockaddr *) (ai + 1);   /* inline, frees with node */
    ai->ai_canonname = NULL;

    if (family == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) ai->ai_addr;
        s6->sin6_family = AF_INET6;
        s6->sin6_port   = htons((uint16_t) port);
        s6->sin6_addr   = in6addr_loopback;            /* ::1 */
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *) ai->ai_addr;
        s4->sin_family      = AF_INET;
        s4->sin_port        = htons((uint16_t) port);
        s4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);  /* 127.0.0.1 */
    }
    return ai;
}

/* Resolve the real downstream getaddrinfo, ONCE, rejecting any candidate that
 * resolves back into THIS shim's own load object.
 *
 * dlsym(RTLD_NEXT, "getaddrinfo") has been observed to return this library's
 * LOAD BASE (the ELF header address) rather than libc's symbol in some loader
 * states — not NULL, and not equal to our own getaddrinfo entry, so a plain
 * `== NULL || == getaddrinfo` guard passes it through; calling it then jumps to
 * our header and segfaults the whole preloaded process (the recurring
 * "gai_shim.so[…]: segfault … ip==base"). dladdr lets us compare load-object
 * bases and refuse ANY self-referential pointer (the base, our own function, or
 * any other in-shim address). Returns NULL when no valid downstream exists. */
static gai_fn
resolve_real_gai(void)
{
    void   *cand = dlsym(RTLD_NEXT, "getaddrinfo");
    Dl_info self, next;

    if (cand == NULL) {
        return NULL;
    }
    if (dladdr((void *) &getaddrinfo, &self) && dladdr(cand, &next)
        && self.dli_fbase == next.dli_fbase) {
        return NULL;                       /* candidate lives inside this shim */
    }
    return (gai_fn) cand;
}

int
getaddrinfo(const char *node, const char *service,
            const struct addrinfo *hints, struct addrinfo **res)
{
    /* Synthesised sentinels never need the real resolver — handle them first so
     * a broken RTLD_NEXT can never affect the paths the test actually drives. */
    if (node != NULL && strcmp(node, SENTINEL) == 0) {
        int port = (service != NULL) ? atoi(service) : 0;
        int fam  = (hints != NULL) ? hints->ai_family : AF_UNSPEC;
        struct addrinfo *head = NULL, *tail = NULL;

        if (fam == AF_UNSPEC || fam == AF_INET6) {
            head = tail = mk_node(AF_INET6, port);   /* v6 first */
        }
        if (fam == AF_UNSPEC || fam == AF_INET) {
            struct addrinfo *v4 = mk_node(AF_INET, port);
            if (tail != NULL) {
                tail->ai_next = v4;
            } else {
                head = v4;
            }
        }
        if (head == NULL) {
            return EAI_NONAME;
        }
        *res = head;
        return 0;
    }

    /* IPv6-only host: only AAAA exists. An AF_INET query (a demoted session)
     * gets EAI_NONAME, which must drive the self-heal revert back to dual-stack. */
    if (node != NULL && strcmp(node, V6ONLY) == 0) {
        int port = (service != NULL) ? atoi(service) : 0;
        int fam  = (hints != NULL) ? hints->ai_family : AF_UNSPEC;
        if (fam == AF_INET) {
            return EAI_NONAME;
        }
        *res = mk_node(AF_INET6, port);
        return (*res != NULL) ? 0 : EAI_MEMORY;
    }

    /* Every other host delegates to the real resolver. Resolve it once and
     * cache it; if no valid downstream exists, fail cleanly rather than crash. */
    {
        static gai_fn real;
        static int    tried;

        if (!tried) {
            real = resolve_real_gai();
            tried = 1;
        }
        if (real == NULL) {
            return EAI_SYSTEM;
        }
        return real(node, service, hints, res);
    }
}
