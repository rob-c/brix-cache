/*
 * brix_fault_priv.c — privileged ("root-ful") fault levers for brix-fault-proxy.
 *
 * See brix_fault_priv.h for the rationale.  This unit is the ONLY place the proxy
 * touches host-global network state, and it does so through three subsystems, each
 * fully owned so teardown is a single clean removal:
 *
 *   netem  — a `tc qdisc ... netem` on the configured NIC's egress.  We keep a
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

/* netem feature slots, emitted in this order (delay must precede reorder for
 * `tc netem` to honour the hold-back). Each slot holds a validated, ready-to-
 * tokenize fragment such as "delay 100ms 20ms" or "loss gemodel 5% 90%". */
enum { NE_DELAY, NE_LOSS, NE_CORRUPT, NE_DUP, NE_REORDER, NE_RATE, NE_LIMIT, NE_N };

static int             g_on         = 0;
static char            g_iface[IFNAMSIZ];
static int             g_listen_port;
static int             g_tports[8];
static int             g_ntports;
static char            g_ne[NE_N][96];
static int             g_mtu_saved  = -1;   /* original NIC MTU, for restore */
static int            g_nft_on      = 0;    /* nft table currently installed */
static int            g_netem_on    = 0;    /* a netem qdisc is currently installed */
static pthread_mutex_t g_lock       = PTHREAD_MUTEX_INITIALIZER;

/* --------------------------------------------------------------- runners ---- */

/* fork+execvp `argv` with stdout silenced (stderr inherited for diagnostics).
 * Returns 0 on a clean exit(0), the child's non-zero exit code otherwise, or -1
 * if the process could not be created. */
static int
priv_run(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0) {
            dup2(nul, STDOUT_FILENO);
            close(nul);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
        /* retry */
    }
    if (WIFEXITED(st)) {
        return WEXITSTATUS(st);
    }
    return -1;
}

/* fork+execvp `argv`, piping `input` to the child's stdin (for `nft -f -`).
 * Same return convention as priv_run(). */
static int
priv_run_stdin(char *const argv[], const char *input)
{
    int pfd[2];
    if (pipe(pfd) != 0) {
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(pfd[0], STDIN_FILENO);
        close(pfd[0]);
        close(pfd[1]);
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0) {
            dup2(nul, STDOUT_FILENO);
            close(nul);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pfd[0]);
    size_t len = strlen(input), off = 0;
    while (off < len) {
        ssize_t w = write(pfd[1], input + off, len - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        off += (size_t) w;
    }
    close(pfd[1]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
        /* retry */
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* ------------------------------------------------------------ validation ---- */

/* An interface name that both matches a conservative charset and actually exists
 * under /sys/class/net (so a bad --priv-iface fails loudly, not silently). */
static int
valid_iface(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n >= IFNAMSIZ) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!isalnum((unsigned char) c) && c != '.' && c != '_' &&
            c != '-' && c != '@') {
            return 0;
        }
    }
    char path[64 + IFNAMSIZ];
    snprintf(path, sizeof(path), "/sys/class/net/%s", s);
    struct stat sb;
    return stat(path, &sb) == 0;
}

/* Format a 0..100 percentage token ("3", "0.1" -> "3%", "0.1%"). Returns 0 ok. */
static int
fmt_pct(const char *s, char *out, size_t osz)
{
    char  *end;
    double v = strtod(s, &end);
    if (end == s || v < 0.0 || v > 100.0) {
        return -1;
    }
    snprintf(out, osz, "%g%%", v);
    return 0;
}

/* Format a bounded non-negative integer token. max<=0 means "no upper bound". */
static int
fmt_uint(const char *s, char *out, size_t osz, long max)
{
    char *end;
    long  v = strtol(s, &end, 10);
    if (end == s || v < 0 || (max > 0 && v > max)) {
        return -1;
    }
    snprintf(out, osz, "%ld", v);
    return 0;
}

/* A `tc`-style rate token: digits then an optional bit/byte unit. */
static int
valid_rate(const char *s)
{
    const char *p = s;
    if (!isdigit((unsigned char) *p)) {
        return 0;
    }
    while (isdigit((unsigned char) *p)) {
        p++;
    }
    static const char *units[] = { "", "bit", "kbit", "mbit", "gbit", "tbit",
                                   "bps", "kbps", "mbps", "gbps", NULL };
    for (int i = 0; units[i]; i++) {
        if (strcmp(p, units[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------- netem apply -- */

/* Rebuild and install the whole netem qdisc from the current fragment table, or
 * delete it when every slot is empty. Caller holds g_lock. */
static int
netem_apply(void)
{
    if (g_iface[0] == '\0') {
        return -2;   /* no interface configured */
    }

    int empty = 1;
    for (int i = 0; i < NE_N; i++) {
        if (g_ne[i][0]) {
            empty = 0;
            break;
        }
    }
    if (empty) {
        if (!g_netem_on) {
            return 0;   /* nothing was ever installed */
        }
        char *argv[] = { "tc", "qdisc", "del", "dev", g_iface, "root", NULL };
        int rc = priv_run(argv);
        g_netem_on = 0;
        /* rc 2 == "no such qdisc" (already clean); treat as success. */
        return (rc == 0 || rc == 2) ? 0 : -1;
    }

    /* tc qdisc replace dev IFACE root netem <tokens...> */
    char  *argv[8 + NE_N * 8];
    int    ac = 0;
    argv[ac++] = "tc";
    argv[ac++] = "qdisc";
    argv[ac++] = "replace";
    argv[ac++] = "dev";
    argv[ac++] = g_iface;
    argv[ac++] = "root";
    argv[ac++] = "netem";

    static char frag[NE_N][96];   /* mutable copies; strtok writes into these */
    for (int i = 0; i < NE_N; i++) {
        if (!g_ne[i][0]) {
            continue;
        }
        memcpy(frag[i], g_ne[i], sizeof(frag[i]));
        for (char *t = strtok(frag[i], " "); t; t = strtok(NULL, " ")) {
            if (ac < (int) (sizeof(argv) / sizeof(argv[0])) - 1) {
                argv[ac++] = t;
            }
        }
    }
    argv[ac] = NULL;
    if (priv_run(argv) != 0) {
        return -1;
    }
    g_netem_on = 1;
    return 0;
}

/* Set the delay slot: "delay <ms>ms [<jit>ms [<corr>% [distribution <d>]]]". */
static int
netem_set_delay(char *args, char *reply, size_t rsz)
{
    char *ms   = strtok(args, " ");
    char *jit  = strtok(NULL, " ");
    char *corr = strtok(NULL, " ");
    char *dist = strtok(NULL, " ");
    if (!ms || strcmp(ms, "off") == 0) {
        g_ne[NE_DELAY][0] = '\0';
        goto done;
    }
    char mt[24], jt[24], ct[16];
    if (fmt_uint(ms, mt, sizeof(mt), 0) != 0) {
        snprintf(reply, rsz, "err: bad delay ms\n");
        return -1;
    }
    int n = snprintf(g_ne[NE_DELAY], sizeof(g_ne[NE_DELAY]), "delay %sms", mt);
    if (jit && fmt_uint(jit, jt, sizeof(jt), 0) == 0) {
        n += snprintf(g_ne[NE_DELAY] + n, sizeof(g_ne[NE_DELAY]) - n, " %sms", jt);
        if (corr && fmt_pct(corr, ct, sizeof(ct)) == 0) {
            n += snprintf(g_ne[NE_DELAY] + n, sizeof(g_ne[NE_DELAY]) - n, " %s", ct);
        }
    }
    if (dist && (!strcmp(dist, "normal") || !strcmp(dist, "pareto") ||
                 !strcmp(dist, "paretonormal") || !strcmp(dist, "uniform"))) {
        snprintf(g_ne[NE_DELAY] + n, sizeof(g_ne[NE_DELAY]) - n,
                 " distribution %s", dist);
    }
done:
    return netem_apply();
}

/* Set one single-percentage netem feature (corrupt/duplicate/reorder/loss). */
static int
netem_set_pct(int slot, const char *verb, char *args, char *reply, size_t rsz)
{
    char *p    = strtok(args, " ");
    char *corr = strtok(NULL, " ");
    if (!p || strcmp(p, "off") == 0) {
        g_ne[slot][0] = '\0';
        return netem_apply();
    }
    char pt[16], ct[16];
    if (fmt_pct(p, pt, sizeof(pt)) != 0) {
        snprintf(reply, rsz, "err: bad %s percentage\n", verb);
        return -1;
    }
    int n = snprintf(g_ne[slot], sizeof(g_ne[slot]), "%s %s", verb, pt);
    if (corr && fmt_pct(corr, ct, sizeof(ct)) == 0) {
        snprintf(g_ne[slot] + n, sizeof(g_ne[slot]) - n, " %s", ct);
    }
    return netem_apply();
}

/* Set bursty Gilbert-Elliott loss: "loss gemodel <p>% [<r>% [<1-h>% [<1-k>%]]]".
 * p = good->bad, r = bad->good, 1-h = loss-in-bad, 1-k = loss-in-good. */
static int
netem_set_gemodel(char *args, char *reply, size_t rsz)
{
    char *tok[4] = { 0 };
    int   nt = 0;
    for (char *t = strtok(args, " "); t && nt < 4; t = strtok(NULL, " ")) {
        tok[nt++] = t;
    }
    if (nt == 0 || strcmp(tok[0], "off") == 0) {
        g_ne[NE_LOSS][0] = '\0';
        return netem_apply();
    }
    char buf[96];
    int  n = snprintf(buf, sizeof(buf), "loss gemodel");
    for (int i = 0; i < nt; i++) {
        char pt[16];
        if (fmt_pct(tok[i], pt, sizeof(pt)) != 0) {
            snprintf(reply, rsz, "err: bad gemodel percentage\n");
            return -1;
        }
        n += snprintf(buf + n, sizeof(buf) - n, " %s", pt);
    }
    memcpy(g_ne[NE_LOSS], buf, sizeof(g_ne[NE_LOSS]));
    return netem_apply();
}

/* Dispatch `priv netem <sub> ...`. Caller holds g_lock. */
static int
cmd_netem(char *args, char *reply, size_t rsz)
{
    char *sub = strtok(args, " ");
    char *rest = strtok(NULL, "");   /* remainder after the sub-verb */
    char  empty[1] = "";
    if (!rest) {
        rest = empty;
    }
    if (!sub || strcmp(sub, "show") == 0) {
        char *w = reply;
        int   left = (int) rsz;
        int   k = snprintf(w, left, "netem[%s]:", g_iface[0] ? g_iface : "?");
        w += k; left -= k;
        for (int i = 0; i < NE_N && left > 1; i++) {
            if (g_ne[i][0]) {
                int m = snprintf(w, left, " %s", g_ne[i]);
                w += m; left -= m;
            }
        }
        snprintf(w, left > 0 ? left : 0, "\n");
        return 0;
    }
    if (strcmp(sub, "clear") == 0 || strcmp(sub, "off") == 0) {
        for (int i = 0; i < NE_N; i++) {
            g_ne[i][0] = '\0';
        }
        return netem_apply();
    }
    int rc;
    if (strcmp(sub, "delay") == 0) {
        rc = netem_set_delay(rest, reply, rsz);
    } else if (strcmp(sub, "loss") == 0) {
        rc = netem_set_pct(NE_LOSS, "loss random", rest, reply, rsz);
    } else if (strcmp(sub, "loss-gemodel") == 0) {
        rc = netem_set_gemodel(rest, reply, rsz);
    } else if (strcmp(sub, "corrupt") == 0) {
        rc = netem_set_pct(NE_CORRUPT, "corrupt", rest, reply, rsz);
    } else if (strcmp(sub, "duplicate") == 0) {
        rc = netem_set_pct(NE_DUP, "duplicate", rest, reply, rsz);
    } else if (strcmp(sub, "reorder") == 0) {
        rc = netem_set_pct(NE_REORDER, "reorder", rest, reply, rsz);
    } else if (strcmp(sub, "rate") == 0) {
        char *r = strtok(rest, " ");
        if (!r || strcmp(r, "off") == 0) {
            g_ne[NE_RATE][0] = '\0';
        } else if (!valid_rate(r)) {
            snprintf(reply, rsz, "err: bad rate (e.g. 1mbit)\n");
            return -1;
        } else {
            snprintf(g_ne[NE_RATE], sizeof(g_ne[NE_RATE]), "rate %s", r);
        }
        rc = netem_apply();
    } else if (strcmp(sub, "limit") == 0) {
        char *l = strtok(rest, " "), lt[24];
        if (!l || strcmp(l, "off") == 0) {
            g_ne[NE_LIMIT][0] = '\0';
        } else if (fmt_uint(l, lt, sizeof(lt), 0) != 0) {
            snprintf(reply, rsz, "err: bad limit\n");
            return -1;
        } else {
            snprintf(g_ne[NE_LIMIT], sizeof(g_ne[NE_LIMIT]), "limit %s", lt);
        }
        rc = netem_apply();
    } else {
        snprintf(reply, rsz, "err: unknown netem sub-command '%s'\n", sub);
        return -1;
    }
    if (rc == -2) {
        snprintf(reply, rsz, "err: no --priv-iface configured for netem\n");
    } else if (rc != 0 && strncmp(reply, "err:", 4) != 0) {
        /* A validation handler already left a specific "err: ..." message; only
         * the qdisc install itself falls through with reply still == "ok". */
        snprintf(reply, rsz, "err: tc failed (see proxy stderr)\n");
    } else if (rc == 0 && g_ne[NE_REORDER][0] && !g_ne[NE_DELAY][0]) {
        snprintf(reply, rsz, "ok (note: reorder needs a delay to take effect)\n");
    }
    return rc == 0 ? 0 : -1;
}

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
    if (strcmp(verb, "netem") == 0) {
        cmd_netem(rest, reply, rsz);
    } else if (strcmp(verb, "cut") == 0) {
        char *mode = strtok(rest, " ");
        char *dtok = strtok(NULL, " ");
        int   dir  = 0;
        if (dtok && strcmp(dtok, "up") == 0)   dir = 1;
        else if (dtok && strcmp(dtok, "down") == 0) dir = 2;
        if (!mode) {
            snprintf(reply, rsz, "err: cut needs a mode\n");
        } else {
            cut_apply(mode, dir, reply, rsz);
        }
    } else if (strcmp(verb, "uncut") == 0) {
        if (cut_clear() != 0) {
            snprintf(reply, rsz, "err: nft delete failed\n");
        }
    } else if (strcmp(verb, "mtu") == 0) {
        cmd_mtu(rest, reply, rsz);
    } else if (strcmp(verb, "clear") == 0) {
        for (int i = 0; i < NE_N; i++) {
            g_ne[i][0] = '\0';
        }
        netem_apply();
        cut_clear();
        if (g_mtu_saved > 0) {
            mtu_set(g_mtu_saved);
            g_mtu_saved = -1;
        }
    } else if (strcmp(verb, "status") == 0) {
        snprintf(reply, rsz, "priv on iface=%s nft=%s mtu_saved=%d\n",
                 g_iface[0] ? g_iface : "(none)", g_nft_on ? "yes" : "no",
                 g_mtu_saved);
    } else {
        snprintf(reply, rsz, "err: unknown priv sub-command '%s'\n", verb);
    }
    pthread_mutex_unlock(&g_lock);
    return 1;
}

void
fp_priv_teardown(void)
{
    if (!g_on) {
        return;
    }
    for (int i = 0; i < NE_N; i++) {
        g_ne[i][0] = '\0';
    }
    if (g_iface[0]) {
        netem_apply();          /* del qdisc */
    }
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
