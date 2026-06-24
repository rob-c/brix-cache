#ifndef NGX_XROOTD_CONNECTION_NETOPT_H
#define NGX_XROOTD_CONNECTION_NETOPT_H

/*
 * netopt.h — shared OS-level dead-peer reaping socket options.
 *
 * WHAT: one header-only helper that applies SO_KEEPALIVE (with tight
 *   TCP_KEEPIDLE/INTVL/CNT probes) and TCP_USER_TIMEOUT to a socket fd.
 *
 * WHY: Phase 39 introduced this block inline in src/connection/handler.c for the
 *   root:// accept path.  Phase 50 needs the identical behaviour on the CMS
 *   client connect socket (src/cms/connect.c) and the CMS server accept socket
 *   (src/cms/server_handler.c) so a silently-dropped manager/data-node peer is
 *   reaped by the kernel even while no event-loop deadline is armed.  Factoring it
 *   here keeps one definition and lets handler.c, connect.c and server_handler.c
 *   (a separate stream module) all share it via static inline — no new .c, so the
 *   build graph (the `config` source list) is unchanged.
 *
 * HOW: header-only `static ngx_inline`, compiled into each translation unit.
 *   Every setsockopt failure is deliberately NON-FATAL — a missing/denied option
 *   must never abort a connection.  Each option is guarded by its feature macro so
 *   the helper compiles on platforms lacking the TCP_KEEP / USER_TIMEOUT opts.
 */

#include <ngx_core.h>
#include <ngx_event.h>
#include <netinet/in.h>
#include <netinet/tcp.h>   /* TCP_USER_TIMEOUT / TCP_KEEPIDLE / TCP_KEEPINTVL */

/*
 * Apply dead-peer reaping options to fd.
 *   keepalive        — enable SO_KEEPALIVE plus seconds-scale probes
 *                      (30 s idle / 10 s interval / 3 probes), matching the
 *                      Phase-39 root:// accept defaults.
 *   user_timeout_ms  — TCP_USER_TIMEOUT in ms; 0 leaves the kernel default.
 * Failures are swallowed (best-effort hardening, never a hard error).
 */
static ngx_inline void
xrootd_apply_tcp_deadpeer_opts(ngx_socket_t fd, ngx_flag_t keepalive,
    ngx_msec_t user_timeout_ms)
{
    if (keepalive) {
        int on = 1;
        (void) setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                          (const void *) &on, sizeof(on));
#if defined(TCP_KEEPIDLE)
        { int v = 30;
          (void) setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
                            (const void *) &v, sizeof(v)); }
#endif
#if defined(TCP_KEEPINTVL)
        { int v = 10;
          (void) setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
                            (const void *) &v, sizeof(v)); }
#endif
#if defined(TCP_KEEPCNT)
        { int v = 3;
          (void) setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
                            (const void *) &v, sizeof(v)); }
#endif
    }

#if defined(TCP_USER_TIMEOUT)
    if (user_timeout_ms > 0) {
        unsigned int ms = (unsigned int) user_timeout_ms;
        (void) setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
                          (const void *) &ms, sizeof(ms));
    }
#endif
}

/*
 * Select the TCP congestion-control algorithm on fd (e.g. "bbr", "cubic").
 *   algo — algorithm name; empty (len 0) leaves the kernel default untouched.
 * Per-socket and best-effort: a missing/unavailable algorithm (e.g. the bbr
 * module not loaded) fails the setsockopt silently and the connection proceeds
 * on the kernel default — never a hard error.  BBR is rate/RTT-model based and
 * does not collapse cwnd on the spurious "loss" signals that packet reordering
 * induces, so it improves throughput on reordering/lossy high-BDP links without
 * any client change (the sender's behaviour governs a download).
 */
static ngx_inline void
xrootd_apply_tcp_congestion(ngx_socket_t fd, ngx_str_t algo)
{
#if defined(TCP_CONGESTION)
    if (algo.len > 0 && algo.len < 64) {
        (void) setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION,
                          (const void *) algo.data, (socklen_t) algo.len);
    }
#else
    (void) fd;
    (void) algo;
#endif
}

#endif /* NGX_XROOTD_CONNECTION_NETOPT_H */
