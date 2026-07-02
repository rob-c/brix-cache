/*
 * flowlabel.c — in-band IPv6 Flow Label marking (REQUIRED SciTags technique).
 *
 * WHAT: Stamp the SciTags flow-id into the 20-bit IPv6 Flow Label of a connected
 *   socket's egress packets, so routers/NRENs can classify the traffic without
 *   seeing the out-of-band firefly.  This is the path XRootD declared but never
 *   implemented (its marking site is an empty `// { TODO??? }` at
 *   XrdNetPMarkCfg.cc:240-248); we provide the real Linux kernel calls.
 *
 * WHY: The flow label is the per-packet technique; firefly is per-flow reporting.
 *   The phase-34 design requires BOTH.  Marking is fail-open: IPv4, IPv4-mapped,
 *   a disabled config, or a kernel that refuses the specific label all degrade to
 *   "not labelled" (firefly still runs) and NEVER fail a transfer.
 *
 * HOW: Reserve the exact label for the connected peer via
 *   setsockopt(IPV6_FLOWLABEL_MGR) with IPV6_FL_A_GET|IPV6_FL_F_CREATE, then
 *   enable IPV6_FLOWINFO_SEND so the kernel writes it into outgoing headers.  The
 *   struct/constants live only in <linux/in6.h>, which clashes with
 *   <netinet/in.h>; to avoid the conflict we declare the (stable, append-only)
 *   kernel ABI here under private names.  A one-time per-worker probe records
 *   whether this host even permits setting a specific label (needs the right
 *   net.ipv6 sysctls / CAP_NET_ADMIN for some ranges).
 */

#include "pmark.h"
#include "metrics/metrics.h"
#include "metrics/metrics_macros.h"
#include "core/compat/log_diag.h"

#if defined(__linux__)

#include <sys/socket.h>
#include <netinet/in.h>

/* Kernel ABI (from <linux/in6.h>, which conflicts with <netinet/in.h>).  Values
 * and layout are stable.  Guard the macros in case a libc does export them. */
#ifndef IPV6_FLOWLABEL_MGR
#define IPV6_FLOWLABEL_MGR   32
#endif
#ifndef IPV6_FLOWINFO_SEND
#define IPV6_FLOWINFO_SEND   33
#endif
#define PMARK_FL_A_GET        0
#define PMARK_FL_F_CREATE     1
#define PMARK_FL_S_EXCL       1

struct pmark_flowlabel_req {
    struct in6_addr  flr_dst;
    uint32_t         flr_label;     /* network byte order, low 20 bits */
    uint8_t          flr_action;
    uint8_t          flr_share;
    uint16_t         flr_flags;
    uint16_t         flr_expires;
    uint16_t         flr_linger;
    uint32_t         __flr_pad;
};

/* Per-worker probe cache: -1 unknown, 0 unusable, 1 usable. */
static int  pmark_fl_usable = -1;


ngx_int_t
xrootd_pmark_flowlabel_usable(ngx_log_t *log)
{
    int                        fd;
    struct pmark_flowlabel_req fl;

    if (pmark_fl_usable >= 0) {
        return pmark_fl_usable ? NGX_OK : NGX_DECLINED;
    }
    pmark_fl_usable = 0;

    fd = (int) ngx_socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        XROOTD_DIAG(NGX_LOG_NOTICE, log, ngx_errno,
            "pmark: IPv6 flow-label marking disabled (no AF_INET6 socket)",
            "this host has IPv6 disabled, so SciTags cannot set the IPv6 "
            "flow label; packet marking falls back to firefly UDP only",
            "if you want flow-label marking, enable IPv6 on the host; "
            "otherwise this is expected and firefly marking still works");
        return NGX_DECLINED;
    }

    /* Try to lease a specific label toward the loopback address.  If the kernel
     * refuses (EPERM / sysctl off), specific-label marking is not possible. */
    ngx_memzero(&fl, sizeof(fl));
    fl.flr_dst   = in6addr_loopback;
    /* A representative in-range structural label (exp/act minima) just to learn
     * whether the kernel will lease a SPECIFIC label on this host at all. */
    fl.flr_label = htonl(xrootd_pmark_flowlabel_encode(XROOTD_PMARK_EXP_MIN,
                                                       XROOTD_PMARK_ACT_MIN));
    fl.flr_action = PMARK_FL_A_GET;
    fl.flr_flags  = PMARK_FL_F_CREATE;
    fl.flr_share  = PMARK_FL_S_EXCL;

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, &fl, sizeof(fl)) == 0) {
        pmark_fl_usable = 1;
    } else {
        ngx_log_error(NGX_LOG_NOTICE, log, ngx_errno,
            "pmark: IPv6 flow-label marking unavailable "
            "(check net.ipv6.flowlabel_state_ranges / CAP_NET_ADMIN); "
            "firefly-only");
    }

    ngx_close_socket(fd);
    return pmark_fl_usable ? NGX_OK : NGX_DECLINED;
}


/* Lease the encoded label on `fd` toward IPv6 destination `dst6` and enable
 * IPV6_FLOWINFO_SEND.  Shared by the connected (getpeername) and explicit-dest
 * (libcurl opensocket) entry points. */
static ngx_int_t
pmark_flowlabel_lease(int fd, const struct in6_addr *dst6, ngx_uint_t exp,
    ngx_uint_t act, ngx_log_t *log)
{
    struct pmark_flowlabel_req fl;
    uint32_t                   label;
    int                        on = 1;

    /* Structural bits (community + activity) plus 5 random entropy bits, set once
     * here per flow so same-(exp,act) flows hash differently for ECMP (spec §4). */
    label = xrootd_pmark_flowlabel_encode(exp, act)
            | ((uint32_t) ngx_random() & XROOTD_PMARK_FL_ENTROPY_MASK);

    ngx_memzero(&fl, sizeof(fl));
    fl.flr_dst    = *dst6;
    fl.flr_label  = htonl(label);
    fl.flr_action = PMARK_FL_A_GET;
    fl.flr_flags  = PMARK_FL_F_CREATE;
    fl.flr_share  = PMARK_FL_S_EXCL;

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, &fl, sizeof(fl)) != 0) {
        XROOTD_PMARK_METRIC_INC(pmark_flowlabel_failed_total);
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, ngx_errno,
            "pmark: flow-label lease failed (label=0x%05xui)", label);
        return NGX_DECLINED;
    }
    (void) setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof(on));

    XROOTD_PMARK_METRIC_INC(pmark_flowlabel_set_total);
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
        "pmark: stamped IPv6 flow label 0x%05xui", label);
    return NGX_OK;
}


ngx_int_t
xrootd_pmark_flowlabel_apply(ngx_connection_t *c, int fd, ngx_uint_t exp,
    ngx_uint_t act, ngx_log_t *log)
{
    struct sockaddr_storage    ss;
    socklen_t                  len = sizeof(ss);
    struct sockaddr_in6       *sin6;

    (void) c;

    if (fd < 0 || xrootd_pmark_flowlabel_usable(log) != NGX_OK) {
        return NGX_DECLINED;
    }
    if (getpeername(fd, (struct sockaddr *) &ss, &len) != 0
        || ss.ss_family != AF_INET6)
    {
        return NGX_DECLINED;          /* IPv4 (or no peer) → firefly only */
    }
    sin6 = (struct sockaddr_in6 *) &ss;
    if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
        return NGX_DECLINED;          /* ::ffff: → not real IPv6 */
    }
    return pmark_flowlabel_lease(fd, &sin6->sin6_addr, exp, act, log);
}


ngx_int_t
xrootd_pmark_flowlabel_apply_addr(int fd, const struct sockaddr *dst,
    socklen_t dstlen, ngx_uint_t exp, ngx_uint_t act, ngx_log_t *log)
{
    const struct sockaddr_in6 *sin6;

    if (fd < 0 || dst == NULL || dstlen < (socklen_t) sizeof(*sin6)
        || dst->sa_family != AF_INET6
        || xrootd_pmark_flowlabel_usable(log) != NGX_OK)
    {
        return NGX_DECLINED;
    }
    sin6 = (const struct sockaddr_in6 *) dst;
    if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
        return NGX_DECLINED;
    }
    return pmark_flowlabel_lease(fd, &sin6->sin6_addr, exp, act, log);
}

#else  /* !__linux__ */

ngx_int_t
xrootd_pmark_flowlabel_usable(ngx_log_t *log)
{
    (void) log;
    return NGX_DECLINED;
}

ngx_int_t
xrootd_pmark_flowlabel_apply(ngx_connection_t *c, int fd, ngx_uint_t exp,
    ngx_uint_t act, ngx_log_t *log)
{
    (void) c; (void) fd; (void) exp; (void) act; (void) log;
    return NGX_DECLINED;
}

ngx_int_t
xrootd_pmark_flowlabel_apply_addr(int fd, const struct sockaddr *dst,
    socklen_t dstlen, ngx_uint_t exp, ngx_uint_t act, ngx_log_t *log)
{
    (void) fd; (void) dst; (void) dstlen; (void) exp; (void) act; (void) log;
    return NGX_DECLINED;
}

#endif
