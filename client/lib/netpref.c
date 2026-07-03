/*
 * netpref.c — process-wide address-family preference (IPv6→IPv4 auto-downgrade).
 *
 * WHAT: A tiny, lock-free state machine that records whether the current process
 *       (e.g. one FUSE mount session) should still attempt IPv6 or has fallen
 *       back to IPv4-only. brix_tcp_connect consults it for the getaddrinfo
 *       family hint and trips it when it sees IPv6 fail where IPv4 then works.
 * WHY:  On a dual-stack host with a broken IPv6 path, every fresh socket
 *       (pool slot, per-file conn, async stream, each reconnect) would otherwise
 *       pay a full connect timeout on the dead v6 address before falling back to
 *       v4 — repeatedly, for the life of the mount. Once we have positive proof
 *       the v6 path is black-holed AND v4 works, we demote the whole session to
 *       v4-only so the resolver stops returning v6 records entirely, and we say
 *       so exactly once. The downgrade is silent to the data path (transfers
 *       just keep working) but visible to the operator in the log.
 * HOW:  Three relaxed atomics (no ordering dependency between them): a sticky
 *       "demoted" flag, a one-shot "logged" guard, and a lazily-resolved
 *       "enabled" toggle (off via XRDC_NO_IPV6_FALLBACK for IPv6-only sites or
 *       debugging). State is global by design — the preference is a property of
 *       the host's network, not of any one connection — and accessed only through
 *       these functions, never as a bare extern.
 *
 * SAFETY: Demotion is never speculative. It happens only on the connect path's
 *       unambiguous evidence (v6 candidate failed, v4 candidate then succeeded),
 *       so an IPv6-only or healthy-IPv6 host never demotes: there is no working
 *       v4 to succeed after a v6 failure, and a healthy v6 never fails.
 *
 * Clean-room: depends on the C library and <stdatomic.h> only.
 */
#include "brix.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>   /* AF_UNSPEC, AF_INET */

/* 0 = still trying both families; 1 = demoted to IPv4-only for this process. */
static atomic_int g_demoted = 0;
/* One-shot guard so concurrent pool connections log the downgrade only once. */
static atomic_int g_logged = 0;
/* One-shot guard for the self-heal "reverting to dual-stack" message. */
static atomic_int g_revert_logged = 0;
/* Lazily resolved: -1 unknown, 0 disabled (opt-out), 1 enabled (default). */
static atomic_int g_enabled = -1;

/*
 * Resolve (once) whether auto-downgrade is enabled. Default ON; an operator pins
 * it OFF with XRDC_NO_IPV6_FALLBACK to keep retrying IPv6 forever — wanted on an
 * IPv6-only deployment that must never silently shed v6, or when debugging the
 * v6 path itself. The first caller wins the race; the value never changes after.
 */
static int
fallback_enabled(void)
{
    int e = atomic_load_explicit(&g_enabled, memory_order_relaxed);
    if (e >= 0) {
        return e;
    }
    e = (getenv("XRDC_NO_IPV6_FALLBACK") != NULL) ? 0 : 1;
    atomic_store_explicit(&g_enabled, e, memory_order_relaxed);
    return e;
}

int
brix_netpref_family(void)
{
    return atomic_load_explicit(&g_demoted, memory_order_relaxed)
           ? AF_INET : AF_UNSPEC;
}

int
brix_netpref_demoted(void)
{
    return atomic_load_explicit(&g_demoted, memory_order_relaxed);
}

void
brix_netpref_disable(void)
{
    atomic_store_explicit(&g_enabled, 0, memory_order_relaxed);
}

/*
 * Commit the sticky IPv4-only demotion and log the cause exactly once for the
 * life of the process — even if several pool/stream connections trip the
 * fallback at the same moment. `cause` is the situation-specific lead-in; the
 * shared tail names the consequence and the opt-out.
 */
static void
do_demote(const char *cause)
{
    atomic_store_explicit(&g_demoted, 1, memory_order_relaxed);
    if (atomic_exchange_explicit(&g_logged, 1, memory_order_relaxed) == 0) {
        fprintf(stderr,
                "xrootd: %s; downgrading this session to IPv4-only for all "
                "further connections (set XRDC_NO_IPV6_FALLBACK=1 to keep "
                "trying IPv6)\n",
                cause);
    }
}

void
brix_netpref_demote_ipv6(const char *host)
{
    if (!fallback_enabled()) {
        return;   /* opt-out: keep attempting IPv6 on every connection */
    }
    char cause[320];
    snprintf(cause, sizeof(cause), "IPv6 connect to %s failed but IPv4 succeeded",
             (host != NULL && host[0] != '\0') ? host : "the server");
    do_demote(cause);
}

void
brix_netpref_note_wire_error(int family)
{
    if (family != AF_INET6 || !fallback_enabled()) {
        return;   /* only an over-the-wire IPv6 failure is evidence of bad v6 */
    }
    if (atomic_load_explicit(&g_demoted, memory_order_relaxed)) {
        return;   /* already IPv4-only */
    }
    /* An established IPv6 connection failed mid-flight (reset / timeout / EOF):
     * pin the rest of the session to IPv4 so the reconnect skips v6 entirely and
     * pays no v6 connect timeout. Self-healing — see brix_netpref_undo_demote:
     * if IPv4 then turns out to be unavailable (an IPv6-only host), the connect
     * path reverts so the mount still comes back up. */
    do_demote("an IPv6 connection to the server failed over the wire");
}

void
brix_netpref_undo_demote(const char *why)
{
    if (!atomic_load_explicit(&g_demoted, memory_order_relaxed)) {
        return;
    }
    atomic_store_explicit(&g_demoted, 0, memory_order_relaxed);
    if (atomic_exchange_explicit(&g_revert_logged, 1, memory_order_relaxed) == 0) {
        fprintf(stderr,
                "xrootd: %s; reverting to dual-stack (IPv4+IPv6) connection "
                "attempts\n",
                (why != NULL && why[0] != '\0') ? why
                    : "the IPv4-only path did not work");
    }
}
