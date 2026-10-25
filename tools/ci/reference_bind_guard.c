/* External test-oracle adapter, never linked into or preloaded into BriX.
 * Constrain ordinary libc IP binds to loopback without changing protocol bytes.
 * A dyld interpose descriptor is required on Darwin; LD_PRELOAD on ELF hosts.
 * This is not a sandbox against malicious code making direct system calls.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>

static int
reference_bind_address(struct sockaddr_storage *copy)
{
    if (copy->ss_family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *) copy;
        if (v4->sin_addr.s_addr == htonl(INADDR_ANY)) {
            v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
        return (ntohl(v4->sin_addr.s_addr) >> 24) == 127;
    }
    if (copy->ss_family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *) copy;
        if (IN6_IS_ADDR_UNSPECIFIED(&v6->sin6_addr)) {
            v6->sin6_addr = in6addr_loopback;
        }
        return IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr);
    }
    return copy->ss_family == AF_UNIX;
}

#if defined(__APPLE__)
#define REFERENCE_BIND reference_loopback_bind
#else
#define REFERENCE_BIND bind
#endif

int
REFERENCE_BIND(int descriptor, const struct sockaddr *address, socklen_t length)
{
    struct sockaddr_storage copy;
    int (*original)(int, const struct sockaddr *, socklen_t);
#if defined(__APPLE__)
    /* dyld excludes this image's own direct reference from interposition. */
    original = bind;
#else
    original = dlsym(RTLD_NEXT, "bind");
#endif
    if (original == NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (address == NULL || length > sizeof(copy)
        || length < sizeof(struct sockaddr)) {
        errno = EINVAL;
        return -1;
    }
    memset(&copy, 0, sizeof(copy));
    memcpy(&copy, address, length);
    if ((copy.ss_family == AF_INET && length < sizeof(struct sockaddr_in))
        || (copy.ss_family == AF_INET6 && length < sizeof(struct sockaddr_in6))) {
        errno = EINVAL;
        return -1;
    }
    if (!reference_bind_address(&copy)) {
        errno = EACCES;
        return -1;
    }
    return original(descriptor, (const struct sockaddr *) &copy, length);
}

#if defined(__APPLE__)
/* Immutable loader metadata, not mutable state or an algorithm substitute. */
__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } reference_bind_pair = {
    (const void *) &reference_loopback_bind, (const void *) &bind
};
#endif
