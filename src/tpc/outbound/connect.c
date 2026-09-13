/* File: connect.c — source-host resolution and TCP connect for a native TPC pull
 * WHAT: tpc_connect() resolves the remote root:// origin through the brix DNS
 * driver (brix_dns_resolve_sync: IP literal → per-worker cache → the event
 * loop's nginx resolver via the bridge → libc, all off the event loop),
 * re-checks every candidate address against the SSRF policy (I-DNS-3), and
 * dials the first that connects within BRIX_TPC_CONNECT_TIMEOUT_SEC with the I/O
 * timeouts and SciTags flow label applied.  brix_tpc_check_src_policy() is the
 * event-loop preflight the kXR_open destination gate runs: a verdict from an IP
 * literal or the cache, or "unknown" so the open can park on an async resolve.
 *
 * WHY: Native TPC pull requires nginx to establish a TCP connection to the remote
 * origin before it can send handshake frames and read the file.  The resolution
 * must iterate over every answered address (IPv4/IPv6) because some may be
 * unreachable; the per-address policy check prevents connecting to loopback or
 * private ranges when configured to reject them, and repeating it on the thread
 * closes the rebinding window between preflight and connect.  Nothing here may
 * block the worker: the preflight never resolves, the connect runs in the pool.
 *
 * HOW: preflight = brix_net_target_check_cached (0 permitted / -1 refused /
 * 1 no cached answer).  Connect = brix_dns_resolve_sync → for each address:
 * brix_net_target_check_addr → socket(family, SOCK_STREAM) → SO_RCVTIMEO/
 * SO_SNDTIMEO → flow label → brix_connect_fd_deadline.  Returns the connected
 * fd or -1 with t->err_msg set.
 * */

#include "tpc/engine/tpc_internal.h"
#include "core/compat/net_target.h"
#include "net/dns/dns.h"
#include "observability/pmark/pmark.h"
#include "protocols/root/connection/netconnect.h"   /* shared outbound connect/I/O hardening */

#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


/* Dial one candidate: socket → timeouts → flow label → deadline connect.
 * Returns the connected fd, or -1 with the socket closed. */
static int
tpc_connect_candidate(const brix_tpc_pull_t *t, struct sockaddr *sa,
    socklen_t salen)
{
    int  fd;

    fd = socket(sa->sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    brix_apply_socket_io_timeouts(fd, BRIX_TPC_IO_TIMEOUT_SEC);

    /*
     * SciTags (phase-34): stamp the IPv6 flow label on the OUTBOUND pull
     * socket before connecting (codes resolved on the event loop in
     * start_pull).  No-op on IPv4 / when not marked; fail-open.
     */
    if (t->pmark_exp != 0) {
        (void) brix_pmark_flowlabel_apply_addr(fd, sa, salen, t->pmark_exp,
                                               t->pmark_act, ngx_cycle->log);
    }

    if (brix_connect_fd_deadline(fd, sa, salen,
                                 BRIX_TPC_CONNECT_TIMEOUT_SEC * 1000) == 0)
    {
        return fd;
    }

    close(fd);
    return -1;
}


/* WHAT: resolve + policy-check + TCP connect to the TPC origin (thread-pool
 * task).  Returns the connected fd or -1 with t->err_msg set. */
int
tpc_connect(brix_tpc_pull_t *t)
{
    brix_dns_addr_t           addrs[BRIX_DNS_MAX_ADDRS];
    brix_net_target_policy_t  policy;
    char                      reason[BRIX_DNS_ERROR_LEN];
    ngx_uint_t                n, i;
    uint16_t                  src_port;

    src_port = t->src_port ? t->src_port : TPC_DEFAULT_PORT;

    ngx_memzero(&policy, sizeof(policy));
    policy.allow_local   = t->conf->common.tpc_allow_local;
    policy.allow_private = t->conf->common.tpc_allow_private;
    policy.dns           = t->conf->common.dns.policy;

    n = brix_dns_resolve_sync(policy.dns, t->src_host, src_port, BRIX_AF_AUTO,
                              SOCK_STREAM, addrs, BRIX_DNS_MAX_ADDRS, reason,
                              sizeof(reason));
    if (n == 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC DNS resolution failed for %s: %s", t->src_host, reason);
        return -1;
    }

    for (i = 0; i < n; i++) {
        struct sockaddr  *sa = (struct sockaddr *) &addrs[i].ss;
        char              ssrf_err[128];
        int               fd;

        /* I-DNS-3: the address actually dialled is the one checked. */
        if (brix_net_target_check_addr(sa, &policy, ssrf_err, sizeof(ssrf_err))
            != NGX_OK)
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC source host %s: %s", t->src_host, ssrf_err);
            return -1;
        }

        fd = tpc_connect_candidate(t, sa, addrs[i].len);
        if (fd >= 0) {
            return fd;
        }
    }

    snprintf(t->err_msg, sizeof(t->err_msg), "TPC connect to %s failed",
             t->src_host);
    return -1;
}


/*
 * brix_tpc_check_src_policy — event-loop SSRF preflight for native root:// TPC.
 *
 * Bare host+port form of brix_net_target_check_cached(): the verdict comes
 * from an IP literal or the per-worker DNS cache and nothing is resolved
 * here.  Returns 0 when every cached address is permitted, -1 with err_msg
 * when the host is missing, definitively unknown or resolves to a prohibited
 * range, and 1 when no answer is cached yet (the caller parks the open on an
 * async resolve — launch_dns.c).
 */
int
brix_tpc_check_src_policy(const ngx_stream_brix_srv_conf_t *conf,
    const char *src_host, uint16_t src_port, char *err_msg, size_t err_msg_sz)
{
    brix_net_target_t         target;
    brix_net_target_policy_t  policy;
    ngx_int_t                 rc;

    if (src_host == NULL || src_host[0] == '\0') {
        snprintf(err_msg, err_msg_sz, "TPC source host missing");
        return -1;
    }

    ngx_memzero(&target, sizeof(target));
    target.host.data = (u_char *) src_host;
    target.host.len  = ngx_strlen(src_host);
    target.port      = src_port ? src_port : TPC_DEFAULT_PORT;
    target.has_port  = 1;

    ngx_memzero(&policy, sizeof(policy));
    policy.allow_local   = conf->common.tpc_allow_local;
    policy.allow_private = conf->common.tpc_allow_private;
    policy.dns           = conf->common.dns.policy;

    rc = brix_net_target_check_cached(&target, &policy, err_msg, err_msg_sz);
    if (rc == NGX_OK) {
        return 0;
    }
    return rc == NGX_DECLINED ? 1 : -1;
}
