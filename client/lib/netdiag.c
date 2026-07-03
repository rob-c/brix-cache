/*
 * netdiag.c — networking diagnostics for `xrddiag bench` (§15.3).
 *
 * WHAT: A read-only block for an established connection: the connect-phase
 *       breakdown (TCP / TLS / login+auth), the address family that actually
 *       connected (happy-eyeballs), kernel TCP_INFO (RTT, retransmits), and the
 *       IPv6 flow label if the path is v6.
 * WHY:  Turns "the link is slow / which stack connected?" into concrete numbers,
 *       and ties into the IPv6 (phase-36) and SciTags (phase-34) work — visible
 *       from the client without tcpdump.
 * HOW:  Phase deltas come from diag.phase_ns (stamped in conn.c bringup). The
 *       family is read from getpeername on the live fd; TCP_INFO via getsockopt
 *       (graceful 0 where unavailable); the flow label via getsockname on v6.
 *
 * PII-free by construction: prints families, microseconds, counts and a flow
 * label only — never an IP address, path, or credential.
 */
#include "brix.h"

#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

static double
ms_between(uint64_t a, uint64_t b)
{
    return (a == 0 || b == 0 || b < a) ? 0.0 : (double) (b - a) / 1e6;
}

void
brix_netdiag_facts(const brix_conn *c, brix_netfacts *f)
{
    if (f == NULL) {
        return;
    }
    memset(f, 0, sizeof(*f));
    if (c == NULL || c->io.fd < 0) {
        return;
    }

    f->tcp_ms   = ms_between(c->diag.phase_ns[0], c->diag.phase_ns[1]);
    f->tls_ms   = ms_between(c->diag.phase_ns[1], c->diag.phase_ns[2]);
    f->auth_ms  = ms_between(c->diag.phase_ns[2], c->diag.phase_ns[3]);
    f->total_ms = ms_between(c->diag.phase_ns[0], c->diag.phase_ns[3]);

    /* Address family actually connected (happy-eyeballs winner) + IPv6 flow label. */
    {
        struct sockaddr_storage ss;
        socklen_t               sl = sizeof(ss);
        if (getpeername(c->io.fd, (struct sockaddr *) &ss, &sl) == 0) {
            f->family = ss.ss_family;
            if (ss.ss_family == AF_INET6) {
                struct sockaddr_in6 ln;
                socklen_t           ll = sizeof(ln);
                if (getsockname(c->io.fd, (struct sockaddr *) &ln, &ll) == 0) {
                    f->flow_label = ntohl(ln.sin6_flowinfo) & 0x000fffff;
                }
            }
        }
    }

    /* Kernel TCP_INFO: RTT + retransmits (Linux; graceful skip elsewhere). */
#ifdef TCP_INFO
    {
        struct tcp_info ti;
        socklen_t       tl = sizeof(ti);
        memset(&ti, 0, sizeof(ti));
        if (getsockopt(c->io.fd, IPPROTO_TCP, TCP_INFO, &ti, &tl) == 0) {
            f->have_tcpinfo = 1;
            f->rtt_us    = (uint32_t) ti.tcpi_rtt;
            f->rttvar_us = (uint32_t) ti.tcpi_rttvar;
            f->retrans   = (uint32_t) ti.tcpi_total_retrans;
        }
    }
#endif
}

void
brix_netdiag_report(const brix_conn *c, FILE *out)
{
    brix_netfacts f;

    if (c == NULL || c->io.fd < 0) {
        return;
    }
    brix_netdiag_facts(c, &f);

    fprintf(out, "Connect phases (ms):\n");
    fprintf(out, "  tcp        %.3f\n", f.tcp_ms);
    fprintf(out, "  tls        %.3f\n", f.tls_ms);
    fprintf(out, "  login+auth %.3f\n", f.auth_ms);
    fprintf(out, "  total      %.3f\n", f.total_ms);

    if (f.family != 0) {
        fprintf(out, "Connected via %s\n",
                f.family == AF_INET6 ? "IPv6" :
                f.family == AF_INET  ? "IPv4" : "?");
        if (f.family == AF_INET6) {
            fprintf(out, "Flow label   0x%05x%s\n", f.flow_label,
                    f.flow_label == 0 ? " (unset)" : "");
        }
    }
    if (f.have_tcpinfo) {
        fprintf(out, "TCP_INFO     rtt=%u us rttvar=%u us retrans=%u\n",
                f.rtt_us, f.rttvar_us, f.retrans);
    }
}
