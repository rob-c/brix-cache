/*
 * client/lib/platform/tcp_rtt.c - the connection's smoothed RTT, host-free
 *
 * WHAT: brix_plat_tcp_rtt — one getsockopt into the host's TCP info struct,
 *       normalised to microseconds.
 * WHY:  Every host knows the same three facts (smoothed RTT, its variation,
 *       the retransmit count) and spells all of them differently.  Keeping the
 *       body here and the spellings in <host>/host_net.h leaves one
 *       implementation to read and reason about, rather than a copy per host
 *       that has to be kept in step by eye.
 * HOW:  BRIX_PLAT_HOST_HEADER(host_net.h) resolves to this directory's
 *       <host>/host_net.h through the same computed include the rest of the
 *       PAL uses; that header names the struct, the socket option and the
 *       field-to-microseconds mapping.
 */

#include "platform/platform.h"
#include BRIX_PLAT_HOST_HEADER(host_net.h)

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

int
brix_plat_tcp_rtt(int fd, uint32_t *rtt_us, uint32_t *rttvar_us,
    uint32_t *retrans)
{
    BRIX_PLAT_TCP_INFO ti;
    socklen_t          len = sizeof(ti);

    memset(&ti, 0, sizeof(ti));
    if (getsockopt(fd, IPPROTO_TCP, BRIX_PLAT_TCP_INFO_OPT, &ti, &len) != 0) {
        return -1;
    }
    *rtt_us    = BRIX_PLAT_TCP_SRTT_US(ti);
    *rttvar_us = BRIX_PLAT_TCP_RTTVAR_US(ti);
    *retrans   = BRIX_PLAT_TCP_RETRANS(ti);
    return 0;
}
