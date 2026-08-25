/*
 * brix_fault_priv_netem.c — the `tc qdisc ... netem` plane of the privileged levers.
 *
 * WHAT: the per-feature netem fragment table (delay, loss, corrupt, duplicate,
 *       reorder, rate, limit), the qdisc (re)install, and the `priv netem <sub>`
 *       command surface.
 *
 * WHY:  split out of brix_fault_priv.c, which owns three independent host-global
 *       subsystems (netem / nft cut / MTU) and had grown past the 600-line cap
 *       (coding-standards §1). netem is the largest and the most self-contained
 *       of the three: it touches only the fragment table and the NIC's egress
 *       qdisc, so it lifts out whole.
 *
 * HOW:  the whole qdisc is re-emitted on every change (`tc qdisc replace`), so
 *       features compose and any one can be cleared independently. Every operand
 *       is validated before it reaches argv; there is no shell. State stays owned
 *       by brix_fault_priv.c and is reached through brix_fault_priv_internal.h —
 *       the caller holds g_lock for every entry point here.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "brix_fault_priv_internal.h"

#include <stdio.h>
#include <string.h>

/* Rebuild and install the whole netem qdisc from the current fragment table, or
 * delete it when every slot is empty. Caller holds g_lock. */
int
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
        return netem_apply();
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

/* `netem show` — the armed clauses, in qdisc order. */
static void
netem_show(char *reply, size_t rsz)
{
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
}

/* Drop every clause and reinstall the (now empty) qdisc. Also the teardown and
 * `priv clear` path — netem_apply() is a no-op when no interface is configured. */
int
netem_clear(void)
{
    for (int i = 0; i < NE_N; i++) {
        g_ne[i][0] = '\0';
    }
    return netem_apply();
}

/* `netem rate <rate>|off` — tbf-style egress ceiling. */
static int
netem_set_rate(char *rest, char *reply, size_t rsz)
{
    char *r = strtok(rest, " ");
    if (!r || strcmp(r, "off") == 0) {
        g_ne[NE_RATE][0] = '\0';
    } else if (!valid_rate(r)) {
        snprintf(reply, rsz, "err: bad rate (e.g. 1mbit)\n");
        return -1;
    } else {
        snprintf(g_ne[NE_RATE], sizeof(g_ne[NE_RATE]), "rate %s", r);
    }
    return netem_apply();
}

/* `netem limit <packets>|off` — the qdisc backlog bound. */
static int
netem_set_limit(char *rest, char *reply, size_t rsz)
{
    char *l = strtok(rest, " "), lt[24];
    if (!l || strcmp(l, "off") == 0) {
        g_ne[NE_LIMIT][0] = '\0';
    } else if (fmt_uint(l, lt, sizeof(lt), 0) != 0) {
        snprintf(reply, rsz, "err: bad limit\n");
        return -1;
    } else {
        snprintf(g_ne[NE_LIMIT], sizeof(g_ne[NE_LIMIT]), "limit %s", lt);
    }
    return netem_apply();
}

/* Route one arming sub-verb to its handler. NETEM_NO_SUB when `sub` names none. */
#define NETEM_NO_SUB (-3)

static int
netem_arm(const char *sub, char *rest, char *reply, size_t rsz)
{
    static const struct { const char *verb; int slot; const char *stanza; } pct[] = {
        { "loss",      NE_LOSS,    "loss random" },
        { "corrupt",   NE_CORRUPT, "corrupt" },
        { "duplicate", NE_DUP,     "duplicate" },
        { "reorder",   NE_REORDER, "reorder" },
    };
    static const struct { const char *verb; int (*fn)(char *, char *, size_t); } plain[] = {
        { "delay", netem_set_delay }, { "loss-gemodel", netem_set_gemodel },
        { "rate",  netem_set_rate },  { "limit",        netem_set_limit },
    };

    for (size_t k = 0; k < sizeof(pct) / sizeof(pct[0]); k++) {
        if (strcmp(sub, pct[k].verb) == 0) {
            return netem_set_pct(pct[k].slot, pct[k].stanza, rest, reply, rsz);
        }
    }
    for (size_t k = 0; k < sizeof(plain) / sizeof(plain[0]); k++) {
        if (strcmp(sub, plain[k].verb) == 0) {
            return plain[k].fn(rest, reply, rsz);
        }
    }
    return NETEM_NO_SUB;
}

/* Turn an arming result into the operator-facing reply. */
static void
netem_report(int rc, char *reply, size_t rsz)
{
    if (rc == -2) {
        snprintf(reply, rsz, "err: no --priv-iface configured for netem\n");
    } else if (rc != 0 && strncmp(reply, "err:", 4) != 0) {
        /* A validation handler already left a specific "err: ..." message; only
         * the qdisc install itself falls through with reply still == "ok". */
        snprintf(reply, rsz, "err: tc failed (see proxy stderr)\n");
    } else if (rc == 0 && g_ne[NE_REORDER][0] && !g_ne[NE_DELAY][0]) {
        snprintf(reply, rsz, "ok (note: reorder needs a delay to take effect)\n");
    }
}

int
netem_command(char *args, char *reply, size_t rsz)
{
    char *sub = strtok(args, " ");
    char *rest = strtok(NULL, "");   /* remainder after the sub-verb */
    char  empty[1] = "";
    if (!rest) {
        rest = empty;
    }
    if (!sub || strcmp(sub, "show") == 0) {
        netem_show(reply, rsz);
        return 0;
    }
    if (strcmp(sub, "clear") == 0 || strcmp(sub, "off") == 0) {
        return netem_clear();
    }
    int rc = netem_arm(sub, rest, reply, rsz);
    if (rc == NETEM_NO_SUB) {
        snprintf(reply, rsz, "err: unknown netem sub-command '%s'\n", sub);
        return -1;
    }
    netem_report(rc, reply, rsz);
    return rc == 0 ? 0 : -1;
}
