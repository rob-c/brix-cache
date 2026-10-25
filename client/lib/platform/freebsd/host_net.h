/* FreeBSD native TCP_INFO units and retransmit counters. */
#pragma once
#include <netinet/tcp.h>
#define BRIX_PLAT_TCP_INFO struct tcp_info
#define BRIX_PLAT_TCP_INFO_OPT TCP_INFO
#define BRIX_PLAT_TCP_SRTT_US(info) ((uint32_t) (info).tcpi_rtt)
#define BRIX_PLAT_TCP_RTTVAR_US(info) ((uint32_t) (info).tcpi_rttvar)
#define BRIX_PLAT_TCP_RETRANS(info) ((uint32_t) (info).tcpi_snd_rexmitpack)
