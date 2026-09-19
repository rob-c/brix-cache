/*
 * client/lib/platform/linux/host_net.h - TCP round-trip facts, Linux spelling
 *
 * WHAT: The struct, socket option and field mapping the one portable
 *       brix_plat_tcp_rtt body (client/lib/platform/tcp_rtt.c) reads a
 *       connection's smoothed RTT through.
 *
 * WHY:  Linux and Darwin agree on what the kernel knows and disagree on every
 *       token used to ask for it — struct name, option name, field names, and
 *       the unit.  Naming those five facts here keeps the body itself host-free
 *       instead of leaving two near-identical copies in the host posix.c files.
 */
#ifndef BRIX_CLIENT_PLATFORM_LINUX_HOST_NET_H
#define BRIX_CLIENT_PLATFORM_LINUX_HOST_NET_H

#include <netinet/tcp.h>

#define BRIX_PLAT_TCP_INFO           struct tcp_info
#define BRIX_PLAT_TCP_INFO_OPT       TCP_INFO
/* tcpi_rtt and tcpi_rttvar are already microseconds here. */
#define BRIX_PLAT_TCP_SRTT_US(ti)    ((uint32_t) (ti).tcpi_rtt)
#define BRIX_PLAT_TCP_RTTVAR_US(ti)  ((uint32_t) (ti).tcpi_rttvar)
#define BRIX_PLAT_TCP_RETRANS(ti)    ((uint32_t) (ti).tcpi_total_retrans)

#endif /* BRIX_CLIENT_PLATFORM_LINUX_HOST_NET_H */
