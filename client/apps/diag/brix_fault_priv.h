/*
 * brix_fault_priv.h — privileged ("root-ful") fault subsystem for
 * brix-fault-proxy.
 *
 * The base proxy (brix_fault_proxy.c) is deliberately root-FREE: every lever it
 * offers lives at or above the TCP byte stream it relays.  Some network faults,
 * however, live BELOW TCP and cannot be honestly emulated in userland — genuine
 * IP packet loss / reordering / duplication / single-bit corruption (which force
 * real retransmits or checksum drops), a next-hop MTU black hole, or an off-path
 * attacker forging an ICMP "fragmentation needed" or a mid-stream RST.  Those need
 * CAP_NET_ADMIN / CAP_NET_RAW.
 *
 * This module adds those levers as an OPT-IN, root-gated complement, driven by the
 * same control port via a `priv <verb> ...` command family.  It mutates HOST-GLOBAL
 * network state (a `tc netem` qdisc, an `nft` table, a NIC's MTU) and therefore
 * registers a teardown that MUST run on every exit path, restoring the host.
 *
 * SECURITY: arming requires BOTH euid 0 AND an explicit --privileged opt-in — root
 * alone does not arm it.  Every shell-out is execvp() with an explicit argv (never
 * a shell), and interface names / numeric operands are validated before use.
 */
#ifndef BRIX_FAULT_PRIV_H
#define BRIX_FAULT_PRIV_H

#include <stddef.h>
#include <sys/socket.h>

/* Arm the privileged subsystem.  `iface` (may be NULL) is the NIC that netem /
 * mtu levers act on; `listen_port` and the `target_ports[nports]` are used to
 * scope the nft cut rules to this proxy's own traffic.  On failure returns -1 and
 * points *err at a static human-readable reason (not root, --privileged missing,
 * bad iface). */
int  fp_priv_enable(const char *iface, int listen_port,
                    const int *target_ports, int nports, const char **err);

/* True once fp_priv_enable() has succeeded. */
int  fp_priv_enabled(void);

/* Dispatch a `priv <verb> [args]` control command (the caller has already
 * stripped the leading "priv " token, so `args` begins at the verb).  Writes a
 * reply line into reply/rsz.  Always returns 1 (the command was claimed). */
int  fp_priv_command(char *args, char *reply, size_t rsz);

/* Append the privileged usage block to `out`. */
void fp_priv_usage(void *out /* FILE * */);

/* Remove ALL installed host state: delete the netem qdisc, delete the nft table,
 * restore the NIC MTU.  Idempotent and async-signal-tolerant (uses only fork/
 * execvp + waitpid), so it is safe from an atexit handler or a SIGTERM handler. */
void fp_priv_teardown(void);

#endif /* BRIX_FAULT_PRIV_H */
