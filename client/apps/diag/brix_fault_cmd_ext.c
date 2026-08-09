/* brix_fault_cmd_ext.c — control commands for the extended (wide-config) levers.
 *
 * WHAT: The control-port verbs that write the g_ext_lock-guarded wide config —
 *       payload replace/inject, the outbound proxy leg, the header-stall gate
 *       and the chaos schedule — plus the flap / ramp background threads that
 *       replay ordinary commands on a timer.
 *
 * WHY:  Split out of brix_fault_cmd_lever.c on the 600-line file cap
 *       (coding-standards §1). These verbs are one concept distinct from the
 *       core levers: every one of them takes g_ext_lock and mutates the wide
 *       config struct, whereas the core levers are written lock-free.
 *
 * HOW:  Same behaviour as before the split — this is a pure move. The shared
 *       state and every prototype stayed in brix_fault_proxy_state.h, so the
 *       seam needed no new header. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "brix_fault_proxy_state.h"
#include "brix_fault_buf.h"
#include "brix_fault_toxic.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Store a `replace <find> <repl>` (or clear on "off") into the named direction. */
int
ext_set_replace(int d, char *findtok, char *repltok, char *reply, size_t rsz)
{
    if (!findtok || strcmp(findtok, "off") == 0) {
        pthread_mutex_lock(&g_ext_lock);
        if (d != 2) { g_up_mut.find_len = 0; }
        if (d != 1) { g_down_mut.find_len = 0; }
        pthread_mutex_unlock(&g_ext_lock);
        return 0;
    }
    unsigned char fb[128], rb[256];
    int fl = fp_ext_parse_payload(findtok, fb, sizeof(fb));
    int rl = repltok ? fp_ext_parse_payload(repltok, rb, sizeof(rb)) : 0;
    if (fl <= 0 || rl < 0) {
        snprintf(reply, rsz, "err: bad replace payload (use hex:.. or str:..)\n");
        return -1;
    }
    pthread_mutex_lock(&g_ext_lock);
    if (d != 2) {
        memcpy(g_up_mut.find, fb, (size_t) fl); g_up_mut.find_len = fl;
        memcpy(g_up_mut.repl, rb, (size_t) rl); g_up_mut.repl_len = rl;
    }
    if (d != 1) {
        memcpy(g_down_mut.find, fb, (size_t) fl); g_down_mut.find_len = fl;
        memcpy(g_down_mut.repl, rb, (size_t) rl); g_down_mut.repl_len = rl;
    }
    pthread_mutex_unlock(&g_ext_lock);
    return 0;
}

/* Store a one-shot `inject <payload>` for the named direction. */
int
ext_set_inject(int d, char *tok, char *reply, size_t rsz)
{
    unsigned char ib[512];
    int il = fp_ext_parse_payload(tok, ib, sizeof(ib));
    if (il <= 0) {
        snprintf(reply, rsz, "err: bad inject payload (use hex:.. or str:..)\n");
        return -1;
    }
    pthread_mutex_lock(&g_ext_lock);
    if (d != 2) { memcpy(g_up_mut.inject, ib, (size_t) il); g_up_mut.inject_len = il; }
    if (d != 1) { memcpy(g_down_mut.inject, ib, (size_t) il); g_down_mut.inject_len = il; }
    pthread_mutex_unlock(&g_ext_lock);
    return 0;
}

/* Configure the forged PROXY-protocol header: `proxy-header v1|v2 SRC [DST]`. */
int
ext_set_proxy(char *args, char *reply, size_t rsz)
{
    char *mode = strtok(args, " ");
    char *src  = strtok(NULL, " ");
    char *dst  = strtok(NULL, " ");
    if (!mode || strcmp(mode, "off") == 0) {
        g_proxy_mode = 0;
        return 0;
    }
    int m = (strcmp(mode, "v1") == 0) ? 1 : (strcmp(mode, "v2") == 0) ? 2 : 0;
    if (m == 0 || !src) {
        snprintf(reply, rsz, "err: proxy-header needs v1|v2 SRC [DST]\n");
        return -1;
    }
    pthread_mutex_lock(&g_ext_lock);
    snprintf(g_proxy_src, sizeof(g_proxy_src), "%s", src);
    snprintf(g_proxy_dst, sizeof(g_proxy_dst), "%s", dst ? dst : "");
    pthread_mutex_unlock(&g_ext_lock);
    g_proxy_mode = m;
    return 0;
}

/* `stall|unstall [dir]` — hold or release one direction's pump. */
static void
ext_set_stall(char *args, int on)
{
    int d = dir_of(args);
    if (d != 2) { g_stall_up = on; }
    if (d != 1) { g_stall_down = on; }
}

/* `chaos [<ms>|off]` — a background thread flipping levers at random. Every arm
 * bumps g_chaos_gen so the previously-detached thread retires itself. */
static void
ext_set_chaos(const char *args)
{
    if (strcmp(args, "off") == 0 || args[0] == '\0') {
        __atomic_add_fetch(&g_chaos_gen, 1, __ATOMIC_SEQ_CST);
        g_chaos_on = 0;
        return;
    }
    int ms = atoi(args);
    g_chaos_ms = ms > 10 ? ms : 100;
    unsigned gen = __atomic_add_fetch(&g_chaos_gen, 1, __ATOMIC_SEQ_CST);
    pthread_t th;
    if (pthread_create(&th, NULL, chaos_thread, (void *) (uintptr_t) gen) == 0) {
        pthread_detach(th);
        g_chaos_on = 1;
    }
}

/* Extended, still-root-free levers: socket-level stress (mss/rcvbuf/sndbuf),
 * backpressure (stall/unstall), connection lifetime, payload MITM (inject/
 * replace), PROXY-header forgery, and the chaos monkey. Returns 1 if handled. */
int
cmd_set_ext(const char *verb, char *args, char *reply, size_t rsz)
{
    if (strcmp(verb, "mss") == 0) {
        g_mss = atoi(args);
    } else if (strcmp(verb, "rcvbuf") == 0) {
        g_rcvbuf = atoi(args);
    } else if (strcmp(verb, "sndbuf") == 0) {
        g_sndbuf = atoi(args);
    } else if (strcmp(verb, "max-lifetime") == 0) {
        g_max_life_ms = atol(args);
    } else if (strcmp(verb, "stall") == 0) {
        ext_set_stall(args, 1);
    } else if (strcmp(verb, "unstall") == 0) {
        ext_set_stall(args, 0);
    } else if (strcmp(verb, "inject") == 0) {
        int d = dir_of(args);
        ext_set_inject(d, args, reply, rsz);
    } else if (strcmp(verb, "replace") == 0) {
        int d = dir_of(args);
        char *f = strtok(args, " ");
        char *r = strtok(NULL, " ");
        ext_set_replace(d, f, r, reply, rsz);
    } else if (strcmp(verb, "proxy-header") == 0) {
        ext_set_proxy(args, reply, rsz);
    } else if (strcmp(verb, "chaos") == 0) {
        ext_set_chaos(args);
    } else {
        return 0;
    }
    return 1;
}

/* Flap the listener in/out of service (a load balancer removing/adding the
 * backend): block for down_ms, unblock for up_ms, repeat until superseded. */
void *
flap_thread(void *arg)
{
    unsigned gen = (unsigned) (uintptr_t) arg;
    while (__atomic_load_n(&g_flap_gen, __ATOMIC_SEQ_CST) == gen) {
        apply_command((char[]){"unblock"}, NULL, 0);
        usleep((useconds_t) (g_flap_up_ms > 0 ? g_flap_up_ms : 500) * 1000);
        if (__atomic_load_n(&g_flap_gen, __ATOMIC_SEQ_CST) != gen) {
            break;
        }
        apply_command((char[]){"block"}, NULL, 0);
        usleep((useconds_t) (g_flap_down_ms > 0 ? g_flap_down_ms : 500) * 1000);
    }
    apply_command((char[]){"unblock"}, NULL, 0);   /* leave service restored */
    return NULL;
}

/* Sweep a numeric lever from start to end over ms (a degrading link / a server
 * warming up under load). Stops early if superseded (clear / new ramp epoch). */
void *
ramp_thread(void *arg)
{
    struct ramp_arg *r = arg;
    const int steps = 20;
    int per = r->ms / steps;
    if (per < 10) {
        per = 10;
    }
    for (int s = 0; s <= steps; s++) {
        if (__atomic_load_n(&g_ramp_gen, __ATOMIC_SEQ_CST) != r->gen) {
            break;
        }
        double v = r->start + (r->end - r->start) * s / steps;
        char   cmd[64];
        snprintf(cmd, sizeof(cmd), "%s %g", r->lever, v);
        apply_command(cmd, NULL, 0);
        usleep((useconds_t) per * 1000);
    }
    free(r);
    return NULL;
}
