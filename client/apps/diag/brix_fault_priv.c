/*
 * brix_fault_priv.c — privileged ("root-ful") fault levers for brix-fault-proxy.
 *
 * See brix_fault_priv.h for the rationale.  This unit is the ONLY place the proxy
 * touches host-global network state, and it does so through three subsystems, each
 * fully owned so teardown is a single clean removal:
 *
 *   netem  — a `tc qdisc ... netem` on the configured NIC's egress.  Implemented
 *            in brix_fault_priv_netem.c (see brix_fault_priv_internal.h).  We keep a
 *            per-feature fragment table (delay, loss, corrupt, …) and re-emit the
 *            whole qdisc on every change (`tc qdisc replace`), so features compose
 *            and any one can be cleared independently.  This is REAL below-TCP
 *            impairment: loss/corrupt force genuine retransmits or checksum drops,
 *            reorder/duplicate deliver genuine out-of-order / doubled PACKETS —
 *            none of which the userland byte-stream levers can honestly produce.
 *   cut    — an `nft` table (inet brix_fault_proxy) whose input-hook rules match
 *            THIS proxy's own 4-tuples (listen port / target ports) and hand the
 *            kernel a verdict: `reject with tcp reset` (a correctly-sequenced RST,
 *            i.e. an on-path reset attack), `reject with icmpx ...` (a forged ICMP
 *            unreachable), or `drop` (a true silent black hole — the peer keeps
 *            retransmitting into the void, unlike the userland `hang` which still
 *            completes the TCP handshake and ACKs).
 *   mtu    — shrink the NIC MTU to wedge large transfers behind a next-hop MTU
 *            black hole / forced fragmentation, a below-TCP effect no relay can fake.
 *
 * NON-GOAL: forging spoofed-source ICMP "fragmentation needed" via a raw socket.
 * Hardened stacks (RFC 5927) validate the quoted sequence number, which an off-path
 * injector cannot know, so it is unreliable; `priv mtu` achieves the same wedged-
 * transfer outcome deterministically.
 *
 * NO SHELL: every external command is fork()+execvp() with an explicit argv; the
 * nft ruleset is piped to `nft -f -` over a pipe.  Interface names and numeric
 * operands are validated before use.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "brix_fault_priv.h"
#include "brix_fault_priv_internal.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* ----------------------------------------------------------------- state ---- */

/* Shared with the netem plane in brix_fault_priv_netem.c; declared in
 * brix_fault_priv_internal.h along with the NE_* slot indices. */
char                   g_iface[IFNAMSIZ];
char                   g_ne[NE_N][96];
int                    g_netem_on    = 0;   /* a netem qdisc is currently installed */

static int             g_on         = 0;
static int             g_listen_port;
static int             g_tports[8];
static int             g_ntports;
static int             g_mtu_saved  = -1;   /* original NIC MTU, for restore */
static int            g_nft_on      = 0;    /* nft table currently installed */
static pthread_mutex_t g_lock       = PTHREAD_MUTEX_INITIALIZER;

/* ---------------------------------------------------------------- nft cut ---- */

/* Map a cut mode to an nft verdict clause, or NULL if the mode is unknown. */
static const char *
cut_verdict(const char *mode)
{
    if (strcmp(mode, "rst") == 0)       return "reject with tcp reset";
    if (strcmp(mode, "drop") == 0)      return "drop";
    if (strcmp(mode, "icmp-admin") == 0) return "reject with icmpx type admin-prohibited";
    if (strcmp(mode, "icmp-host") == 0)  return "reject with icmpx type host-unreachable";
    if (strcmp(mode, "icmp-net") == 0)   return "reject with icmpx type no-route";
    if (strcmp(mode, "icmp-port") == 0)  return "reject with icmpx type port-unreachable";
    return NULL;
}

/* Install (or replace) the nft table cutting `dir` traffic with `mode`. dir:
 * 0 both / 1 up (proxy<->upstream) / 2 down (proxy<->client). Caller holds
 * g_lock. */
static int
cut_apply(const char *mode, int dir, char *reply, size_t rsz)
{
    const char *v = cut_verdict(mode);
    if (!v) {
        snprintf(reply, rsz, "err: unknown cut mode '%s'\n", mode);
        return -1;
    }

    /* Build a target-port set "{ p1, p2 }" for the upstream direction. */
    char pset[128] = "";
    int  po = snprintf(pset, sizeof(pset), "{ ");
    for (int i = 0; i < g_ntports; i++) {
        po += snprintf(pset + po, sizeof(pset) - po, "%s%d",
                       i ? ", " : "", g_tports[i]);
    }
    snprintf(pset + po, sizeof(pset) - po, " }");

    char rs[768];
    int  n = snprintf(rs, sizeof(rs),
        "add table inet brix_fault_proxy\n"
        "delete table inet brix_fault_proxy\n"
        "add table inet brix_fault_proxy\n"
        "add chain inet brix_fault_proxy in "
            "{ type filter hook input priority -150; policy accept; }\n");
    if (dir != 1) {   /* down: packets arriving from the client (dport=listen) */
        n += snprintf(rs + n, sizeof(rs) - n,
            "add rule inet brix_fault_proxy in tcp dport %d %s\n",
            g_listen_port, v);
    }
    if (dir != 2 && g_ntports > 0) {   /* up: replies from upstream (sport=target) */
        n += snprintf(rs + n, sizeof(rs) - n,
            "add rule inet brix_fault_proxy in tcp sport %s %s\n", pset, v);
    }

    char *argv[] = { "nft", "-f", "-", NULL };
    if (priv_run_stdin(argv, rs) != 0) {
        snprintf(reply, rsz, "err: nft failed (see proxy stderr)\n");
        return -1;
    }
    g_nft_on = 1;
    return 0;
}

/* Remove the nft cut table. Caller holds g_lock. */
static int
cut_clear(void)
{
    if (!g_nft_on) {
        return 0;
    }
    char *argv[] = { "nft", "delete", "table", "inet", "brix_fault_proxy", NULL };
    int rc = priv_run(argv);
    g_nft_on = 0;
    return rc == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------- mtu ----- */

static int
mtu_current(void)
{
    char path[64 + IFNAMSIZ];
    snprintf(path, sizeof(path), "/sys/class/net/%s/mtu", g_iface);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    int v = -1;
    if (fscanf(fp, "%d", &v) != 1) {
        v = -1;
    }
    fclose(fp);
    return v;
}

static int
mtu_set(int bytes)
{
    char bt[16];
    snprintf(bt, sizeof(bt), "%d", bytes);
    char *argv[] = { "ip", "link", "set", "dev", g_iface, "mtu", bt, NULL };
    return priv_run(argv) == 0 ? 0 : -1;
}

/* Handle `priv mtu <bytes>|restore`. Caller holds g_lock. */
static int
cmd_mtu(char *args, char *reply, size_t rsz)
{
    if (g_iface[0] == '\0') {
        snprintf(reply, rsz, "err: no --priv-iface configured for mtu\n");
        return -1;
    }
    char *tok = strtok(args, " ");
    if (!tok) {
        snprintf(reply, rsz, "err: mtu needs <bytes> or 'restore'\n");
        return -1;
    }
    if (strcmp(tok, "restore") == 0) {
        if (g_mtu_saved <= 0) {
            snprintf(reply, rsz, "ok (nothing to restore)\n");
            return 0;
        }
        int rc = mtu_set(g_mtu_saved);
        g_mtu_saved = -1;
        if (rc != 0) {
            snprintf(reply, rsz, "err: ip link set mtu failed\n");
        }
        return rc;
    }
    char *end;
    long  b = strtol(tok, &end, 10);
    if (end == tok || b < 68 || b > 65535) {   /* IPv4 minimum link MTU is 68 */
        snprintf(reply, rsz, "err: mtu out of range (68..65535)\n");
        return -1;
    }
    if (g_mtu_saved < 0) {
        g_mtu_saved = mtu_current();   /* remember the real MTU once */
    }
    if (mtu_set((int) b) != 0) {
        snprintf(reply, rsz, "err: ip link set mtu failed\n");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------- public API ---- */

int
fp_priv_enable(const char *iface, int listen_port,
               const int *target_ports, int nports, const char **err)
{
    if (geteuid() != 0) {
        *err = "privileged levers require root (euid 0)";
        return -1;
    }
    if (iface && iface[0] && !valid_iface(iface)) {
        *err = "invalid or nonexistent --priv-iface";
        return -1;
    }
    pthread_mutex_lock(&g_lock);
    memset(g_iface, 0, sizeof(g_iface));
    if (iface) {
        snprintf(g_iface, sizeof(g_iface), "%s", iface);
    }
    g_listen_port = listen_port;
    g_ntports = 0;
    for (int i = 0; i < nports && g_ntports < (int) (sizeof(g_tports) / sizeof(g_tports[0])); i++) {
        g_tports[g_ntports++] = target_ports[i];
    }
    g_on = 1;
    pthread_mutex_unlock(&g_lock);
    (void) err;
    return 0;
}

int
fp_priv_enabled(void)
{
    return g_on;
}

/* `priv cut <mode> [up|down]` — install the nft verdict for one direction. */
static void
priv_cut(char *rest, char *reply, size_t rsz)
{
    char *mode = strtok(rest, " ");
    char *dtok = strtok(NULL, " ");
    if (!mode) {
        snprintf(reply, rsz, "err: cut needs a mode\n");
        return;
    }
    int dir = 0;
    if (dtok && strcmp(dtok, "up") == 0)        { dir = 1; }
    else if (dtok && strcmp(dtok, "down") == 0) { dir = 2; }
    cut_apply(mode, dir, reply, rsz);
}

/* `priv clear` — put every privileged lever back the way we found it. */
static void
priv_clear_all(void)
{
    netem_clear();
    cut_clear();
    if (g_mtu_saved > 0) {
        mtu_set(g_mtu_saved);
        g_mtu_saved = -1;
    }
}

/* Route one privileged sub-verb. Caller holds g_lock. */
static void
priv_dispatch(const char *verb, char *rest, char *reply, size_t rsz)
{
    if (strcmp(verb, "netem") == 0) {
        netem_command(rest, reply, rsz);
    } else if (strcmp(verb, "cut") == 0) {
        priv_cut(rest, reply, rsz);
    } else if (strcmp(verb, "uncut") == 0) {
        if (cut_clear() != 0) {
            snprintf(reply, rsz, "err: nft delete failed\n");
        }
    } else if (strcmp(verb, "mtu") == 0) {
        cmd_mtu(rest, reply, rsz);
    } else if (strcmp(verb, "clear") == 0) {
        priv_clear_all();
    } else if (strcmp(verb, "status") == 0) {
        snprintf(reply, rsz, "priv on iface=%s nft=%s mtu_saved=%d\n",
                 g_iface[0] ? g_iface : "(none)", g_nft_on ? "yes" : "no",
                 g_mtu_saved);
    } else {
        snprintf(reply, rsz, "err: unknown priv sub-command '%s'\n", verb);
    }
}

int
fp_priv_command(char *args, char *reply, size_t rsz)
{
    snprintf(reply, rsz, "ok\n");
    if (!g_on) {
        snprintf(reply, rsz,
                 "err: privileged mode not enabled (need root + --privileged)\n");
        return 1;
    }

    char *verb = strtok(args, " ");
    char *rest = strtok(NULL, "");
    char  empty[1] = "";
    if (!verb) {
        snprintf(reply, rsz, "err: priv needs a sub-command\n");
        return 1;
    }
    if (!rest) {
        rest = empty;
    }

    pthread_mutex_lock(&g_lock);
    priv_dispatch(verb, rest, reply, rsz);
    pthread_mutex_unlock(&g_lock);
    return 1;
}

void
fp_priv_teardown(void)
{
    if (!g_on) {
        return;
    }
    netem_clear();              /* del qdisc (no-op without an interface) */
    cut_clear();                /* del nft table */
    if (g_mtu_saved > 0) {
        mtu_set(g_mtu_saved);   /* restore MTU */
        g_mtu_saved = -1;
    }
}

void
fp_priv_usage(void *out)
{
    fprintf((FILE *) out,
"\nPrivileged levers (root + --privileged; act BELOW TCP on --priv-iface):\n"
"      --privileged         arm the root-ful subsystem (refused unless euid 0)\n"
"      --priv-iface IFACE    NIC that netem/mtu levers act on (e.g. lo, eth0)\n"
"  priv netem delay <ms> [jit] [corr%%] [normal|pareto]  real link delay/jitter\n"
"  priv netem loss <pct> [corr%%]        real random IP packet loss (retransmits)\n"
"  priv netem loss-gemodel <p> [r] [1-h] [1-k]  bursty Gilbert-Elliott loss\n"
"  priv netem corrupt <pct>             real single-bit packet corruption\n"
"  priv netem duplicate <pct>           real packet duplication\n"
"  priv netem reorder <pct> [corr%%]     genuine out-of-order packet delivery\n"
"  priv netem rate <rate> | limit <pkts> | clear | show\n"
"  priv cut <rst|drop|icmp-admin|icmp-host|icmp-net|icmp-port> [up|down]\n"
"                                        kernel-crafted RST / ICMP / silent drop\n"
"  priv uncut                            remove the cut rules\n"
"  priv mtu <bytes> | restore            shrink the NIC MTU (PMTU black hole)\n"
"  priv clear | status\n"
"  All host state (qdisc, nft table, MTU) is auto-restored on exit.\n");
}
