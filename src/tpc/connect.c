/* File: connect.c — DNS resolution and TCP connect to TPC source server
 * WHAT: Resolves the remote XRootD origin host via getaddrinfo, validates each candidate address against SSRF policy rules (allow_local/allow_private), creates a blocking socket with configurable receive/send timeouts, then performs non-blocking connect followed by poll-based wait for connection completion. Also provides xrootd_tpc_check_src_policy as an SSRF preflight wrapper that resolves host+port without creating the socket — used before kXR_open destination file creation to validate source addresses early.
 *
 * WHY: Native TPC pull requires nginx to establish a TCP connection to the remote root:// origin server before it can send handshake frames and read the file. DNS resolution must iterate over all addrinfo candidates (IPv4/IPv6) because some may be unreachable; SSRF policy validation prevents connecting to localhost or private ranges when configured to reject them. Non-blocking connect with poll-based wait avoids blocking the nginx event loop while still respecting configurable timeout limits. The preflight check enables early source address validation before allocating destination file resources.
 *
 * HOW: getaddrinfo(src_host, port_str, hints SOCK_STREAM+AF_UNSPEC) → iterate addrinfo candidates → xrootd_net_target_check_addr with SSRF policy → socket(family,socktype,proto) → setsockopt SO_RCVTIMEO/SO_SNDTIMEO → fcntl O_NONBLOCK → connect() → if EINPROGRESS then poll POLLOUT with TPC_CONNECT_TIMEOUT_SEC → getsockopt SO_ERROR to verify zero → restore original flags. Returns connected fd or -1 on failure. Preflight: xrootd_net_target_check_dns resolves host+port without creating socket, returns 0/-1.
 * */

#include "tpc_internal.h"
#include "core/compat/net_target.h"
#include "observability/pmark/pmark.h"
#include "protocols/root/connection/netconnect.h"   /* shared outbound connect/I/O hardening */


#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* WHAT: DNS resolve + TCP connect to TPC origin — getaddrinfo → SSRF policy check per candidate → socket with SO_RCVTIMEO/SO_SNDTIMEO → non-blocking connect via poll. Returns connected fd or -1. */

int
tpc_connect(xrootd_tpc_pull_t *t)
{
    struct addrinfo  hints, *res, *rp;
    char             port_str[16];
    int              fd = -1;
    uint16_t         src_port;

    src_port = t->src_port ? t->src_port : 1094;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned) src_port);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(t->src_host, port_str, &hints, &res) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC DNS resolution failed for %s", t->src_host);
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        xrootd_net_target_policy_t  policy;
        char                        ssrf_err[128];

        ngx_memzero(&policy, sizeof(policy));
        policy.allow_local   = t->conf->tpc_allow_local;
        policy.allow_private = t->conf->tpc_allow_private;

        if (xrootd_net_target_check_addr(rp->ai_addr, &policy,
                                         ssrf_err, sizeof(ssrf_err))
            != NGX_OK)
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC source host %s: %s", t->src_host, ssrf_err);
            freeaddrinfo(res);
            return -1;
        }

        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }

        xrootd_apply_socket_io_timeouts(fd, TPC_IO_TIMEOUT_SEC);

        /*
         * SciTags (phase-34): stamp the IPv6 flow label on the OUTBOUND pull
         * socket before connecting (codes resolved on the event loop in
         * start_pull).  No-op on IPv4 / when not marked; fail-open.
         */
        if (t->pmark_exp != 0) {
            (void) xrootd_pmark_flowlabel_apply_addr(fd, rp->ai_addr,
                rp->ai_addrlen, t->pmark_exp, t->pmark_act, ngx_cycle->log);
        }

        if (xrootd_connect_fd_deadline(fd, rp->ai_addr, rp->ai_addrlen,
                                       TPC_CONNECT_TIMEOUT_SEC * 1000) == 0)
        {
            break;
        }

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC connect to %s failed", t->src_host);
        return -1;
    }

    return fd;
}

/*
 * SSRF preflight for kXR_open TPC destination path: validate the resolved
 * source addresses before creating the local destination file or returning an
 * open handle. Uses the same prohibited-address rules as tpc_connect() for
 * the first candidate addrinfo entry (matching that connect path).
 */
/* WHAT: SSRF preflight — resolve host+port via xrootd_net_target_check_dns without creating socket, validate against allow_local/allow_private policy. Used before kXR_open destination file creation. */
/*
 * xrootd_tpc_check_src_policy — SSRF preflight wrapper for native root:// TPC.
 *
 * Thin wrapper over xrootd_net_target_check_dns() that accepts the bare
 * host+port form used by the native TPC handshake, rather than a full URL.
 */
int
xrootd_tpc_check_src_policy(const char *src_host, uint16_t src_port,
    ngx_flag_t allow_local, ngx_flag_t allow_private,
    char *err_msg, size_t err_msg_sz)
{
    xrootd_net_target_t         target;
    xrootd_net_target_policy_t  policy;

    if (src_host == NULL || src_host[0] == '\0') {
        snprintf(err_msg, err_msg_sz, "TPC source host missing");
        return -1;
    }

    ngx_memzero(&target, sizeof(target));
    target.host.data = (u_char *) src_host;
    target.host.len  = ngx_strlen(src_host);
    target.port      = src_port ? src_port : 1094;
    target.has_port  = 1;

    ngx_memzero(&policy, sizeof(policy));
    policy.allow_local   = allow_local;
    policy.allow_private = allow_private;

    if (xrootd_net_target_check_dns(&target, &policy,
                                    err_msg, err_msg_sz) != NGX_OK)
    {
        return -1;
    }

    return 0;
}

