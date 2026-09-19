/*
 * client/lib/platform/darwin/host_net.h - TCP round-trip facts, Darwin spelling
 *
 * WHAT: The struct, socket option and field mapping the one portable
 *       brix_plat_tcp_rtt body (client/lib/platform/tcp_rtt.c) reads a
 *       connection's smoothed RTT through.
 *
 * WHY:  Darwin has no TCP_INFO; TCP_CONNECTION_INFO carries the same facts,
 *       with the smoothed RTT and its variation in MILLISECONDS — so the scale
 *       is part of the host's answer, not something the caller may assume.
 */
#ifndef BRIX_CLIENT_PLATFORM_DARWIN_HOST_NET_H
#define BRIX_CLIENT_PLATFORM_DARWIN_HOST_NET_H

#include <netinet/tcp.h>

#define BRIX_PLAT_TCP_INFO           struct tcp_connection_info
#define BRIX_PLAT_TCP_INFO_OPT       TCP_CONNECTION_INFO
#define BRIX_PLAT_TCP_SRTT_US(ti)    ((uint32_t) (ti).tcpi_srtt * 1000u)
#define BRIX_PLAT_TCP_RTTVAR_US(ti)  ((uint32_t) (ti).tcpi_rttvar * 1000u)
#define BRIX_PLAT_TCP_RETRANS(ti)    ((uint32_t) (ti).tcpi_txretransmitpackets)

#endif /* BRIX_CLIENT_PLATFORM_DARWIN_HOST_NET_H */
