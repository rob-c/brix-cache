/* brix_fault_cmd_lever.c — control commands for the core fault levers.
 *
 * WHAT: The control-port verbs that set, clear, or schedule the per-direction
 *       levers — lever/epoch/misc setters, payload mutation, and the background
 *       heal / chaos / flap / ramp threads they arm.
 *
 * WHY:  Split out of brix_fault_proxy.c, which was far over the 600-line cap
 *       (coding-standards §1). The program's shared lever state stayed where
 *       it was defined; see brix_fault_proxy_state.h for the seam.
 *
 * HOW:  Same behaviour as before the split — this is a pure move. Levers are
 *       read lock-free; wide config is snapshotted under g_ext_lock. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "brix_fault_proxy_state.h"
#include "brix_fault_buf.h"
#include "brix_fault_toxic.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Strip a trailing up|down|both direction token from `args`; return which lever
 * set(s) it names: 0 = both, 1 = up only, 2 = down only. */
int
dir_of(char *args)
{
    size_t L = strlen(args);
    while (L > 0 && isspace((unsigned char) args[L - 1])) {
        args[--L] = '\0';
    }
    char *sp = strrchr(args, ' ');
    char *tok = sp ? sp + 1 : args;
    int d = -1;
    if (strcmp(tok, "up") == 0)   d = 1;
    else if (strcmp(tok, "down") == 0) d = 2;
    else if (strcmp(tok, "both") == 0) d = 0;
    if (d < 0) {
        return 0;   /* no direction token -> both, leave args untouched */
    }
    if (sp) {
        *sp = '\0';   /* drop the token so numeric parse ignores it */
    } else {
        args[0] = '\0';
    }
    return d;
}

/* d: 0 both / 1 up / 2 down.  Set field `f` to value `v` on the named set(s). */
#define SET_DIR(d, f, v) do {                     \
    if ((d) != 2) g_up.f = (v);                   \
    if ((d) != 1) g_down.f = (v);                 \
} while (0)

void
reset_lever(volatile lever_t *L)
{
    L->latency_ms = 0; L->jitter_ms = 0; L->chunk_bytes = 0;
    L->drip_bytes = 0; L->drip_ms = 0;   L->rate_kbps = 0;
    L->lossy_ppm = 0;  L->reorder_ppm = 0; L->reorder_ms = 50;
    L->corrupt_ppm = 0; L->dup_ppm = 0;  L->truncate_at = 0;
    L->drop_ppm = 0;   L->repeat_ppm = 0; L->delayfirst_ms = 0;
    L->slow_close_ms = 0; L->burst_bytes = 0;
    L->lat_dist = 0;   L->lat_sigma_ms = 0;
}

/* d: 0 both / 1 up / 2 down.  Set field `f` to value `v` on the named set(s).
 * Local mirror of the SET_DIR macro for the fidelity setters below. */
#define FID_SET_DIR(d, f, v) do {                 \
    if ((d) != 2) g_up.f = (v);                   \
    if ((d) != 1) g_down.f = (v);                 \
} while (0)

/* Phase-B fidelity verbs, each validated so a malformed operand is refused with
 * an `err` reply and leaves the lever unchanged.  Handles toxicity/slow-close/
 * connect-delay/refuse/burst/latency-dist plus a validated `rate` (overriding
 * the unchecked cmd_set_lever rate branch — wired first in cmd_set_dispatch).
 * Returns 1 when `verb` was one of these, else 0. */
int
cmd_set_fidelity(const char *verb, char *args, char *reply, size_t rsz)
{
    if (strcmp(verb, "toxicity") == 0) {
        int d = dir_of(args);
        double pct = atof(args);
        if (pct < 0.0) { fp_reply(reply, rsz, "err: toxicity < 0\n"); return 1; }
        if (pct > 100.0) { pct = 100.0; }
        int ppm = (int) (pct * 10000.0 + 0.5);
        if (d != 2) { g_toxicity_up_ppm = ppm; }
        if (d != 1) { g_toxicity_down_ppm = ppm; }
    } else if (strcmp(verb, "slow-close") == 0) {
        int d = dir_of(args), ms = atoi(args);
        if (ms < 0) { fp_reply(reply, rsz, "err: slow-close < 0\n"); return 1; }
        FID_SET_DIR(d, slow_close_ms, ms);
    } else if (strcmp(verb, "connect-delay") == 0 ||
               strcmp(verb, "accept-delay") == 0) {
        int ms = atoi(args);
        if (ms < 0) { fp_reply(reply, rsz, "err: connect-delay < 0\n"); return 1; }
        g_connect_delay_ms = ms;
    } else if (strcmp(verb, "refuse") == 0) {
        double pct = atof(args);
        if (pct < 0.0) { fp_reply(reply, rsz, "err: refuse < 0\n"); return 1; }
        if (pct > 100.0) { pct = 100.0; }
        g_refuse_ppm = (int) (pct * 10000.0 + 0.5);
    } else if (strcmp(verb, "rate") == 0) {
        int d = dir_of(args), kbps = atoi(args);
        if (kbps < 0) { fp_reply(reply, rsz, "err: rate < 0\n"); return 1; }
        FID_SET_DIR(d, rate_kbps, kbps);
    } else if (strcmp(verb, "burst") == 0) {
        int d = dir_of(args), b = atoi(args);
        if (b < 0) { fp_reply(reply, rsz, "err: burst < 0\n"); return 1; }
        FID_SET_DIR(d, burst_bytes, b);
    } else if (strcmp(verb, "latency-dist") == 0) {
        int d = dir_of(args);
        char shape[16] = "";
        int mean = -1, sigma = 0;
        int nf = sscanf(args, "%15s %d %d", shape, &mean, &sigma);
        if (nf < 2 || mean < 0) {
            fp_reply(reply, rsz, "err: latency-dist <uniform|normal> <mean> [sigma]\n");
            return 1;
        }
        int dist;
        if (strcmp(shape, "uniform") == 0)      { dist = 0; }
        else if (strcmp(shape, "normal") == 0)  { dist = 1; }
        else { fp_reply(reply, rsz, "err: unknown distribution\n"); return 1; }
        FID_SET_DIR(d, jitter_ms, mean);
        FID_SET_DIR(d, lat_dist, dist);
        FID_SET_DIR(d, lat_sigma_ms, sigma);
    } else {
        return 0;
    }
    return 1;
}

void
clear_all(void)
{
    reset_lever(&g_up);
    reset_lever(&g_down);
    g_blocked = 0;
    g_hang = 0;
    g_one_shot = 0;
    g_fail_nth = 0;
    /* Extended levers. */
    g_stall_up = 0; g_stall_down = 0;
    /* Phase-B fidelity levers (toxicity resets to 100% = today's default). */
    g_toxicity_up_ppm = 1000000; g_toxicity_down_ppm = 1000000;
    g_connect_delay_ms = 0; g_refuse_ppm = 0;
    g_mss = 0; g_rcvbuf = 0; g_sndbuf = 0;
    g_max_life_ms = 0;
    g_proxy_mode = 0;
    __atomic_add_fetch(&g_chaos_gen, 1, __ATOMIC_SEQ_CST);   /* stop any chaos */
    g_chaos_on = 0;
    /* Phase-99 DPI/middlebox pathology levers. */
    g_idle_reap_ms = 0; g_idle_reap_rst = 0; g_eat_100 = 0;
    g_rst_after_bytes = 0; g_rst_after_ms = 0; g_rst_after_abortive = 0;
    g_drop_fin_up = 0; g_drop_fin_down = 0;
    g_classify_bytes = 0; g_classify_kbps = 0;
    g_syn_drop_ppm = 0; g_hello_reset_thresh = 0;
    g_udp_drop_ppm = 0; g_udp_hold_ms = 0; g_udp_reap_ms = 0;
    g_udp_reorder_ppm = 0; g_udp_reorder_ms = 0;
    /* Attack-mocking levers. */
    g_accept_pause_ms = 0; g_fanout = 0; g_global_rate_kbps = 0;
    g_mangle_up.active = 0; g_mangle_down.active = 0;
    __atomic_add_fetch(&g_flap_gen, 1, __ATOMIC_SEQ_CST);    /* stop flap */
    g_flap_on = 0;
    __atomic_add_fetch(&g_ramp_gen, 1, __ATOMIC_SEQ_CST);    /* stop ramps */
    pthread_mutex_lock(&g_ext_lock);
    g_up_mut.find_len = 0; g_up_mut.repl_len = 0; g_up_mut.inject_len = 0;
    g_down_mut.find_len = 0; g_down_mut.repl_len = 0; g_down_mut.inject_len = 0;
    g_proxy_src[0] = '\0'; g_proxy_dst[0] = '\0';
    g_trig_up.pat_len = 0; g_trig_up.fired = 0;
    g_trig_down.pat_len = 0; g_trig_down.fired = 0;
    /* Protocol-record surgery (TLS + HTTP smuggling). */
    fp_tls_cfg_init(&g_tls_up);   fp_tls_cfg_init(&g_tls_down);
    memset(&g_http_up, 0, sizeof(g_http_up));
    memset(&g_http_down, 0, sizeof(g_http_down));
    pthread_mutex_unlock(&g_ext_lock);
    fp_toxic_reset();               /* drop every named toxic */
}

void *
heal_thread(void *arg)
{
    long ms = (long) (intptr_t) arg;
    if (ms > 0) {
        usleep((useconds_t) ms * 1000);
    }
    clear_all();
    return NULL;
}

/* Directional traffic levers (latency/bandwidth/corruption). Each strips an
 * optional up/down/both token via dir_of() then sets the field on the selected
 * direction(s). `args` is mutated. Returns 1 if `verb` was a lever, else 0. */
int
cmd_set_lever(const char *verb, char *args)
{
    if (strcmp(verb, "latency") == 0) {
        int d = dir_of(args); SET_DIR(d, latency_ms, atoi(args));
    } else if (strcmp(verb, "jitter") == 0) {
        int d = dir_of(args); SET_DIR(d, jitter_ms, atoi(args));
    } else if (strcmp(verb, "chunk") == 0) {
        int d = dir_of(args); SET_DIR(d, chunk_bytes, atoi(args));
    } else if (strcmp(verb, "rate") == 0) {
        int d = dir_of(args); SET_DIR(d, rate_kbps, atoi(args));
    } else if (strcmp(verb, "drip") == 0) {
        int d = dir_of(args); int b = 0, m = 0;
        sscanf(args, "%d %d", &b, &m);
        SET_DIR(d, drip_bytes, b); SET_DIR(d, drip_ms, m);
    } else if (strcmp(verb, "lossy") == 0) {
        int d = dir_of(args);
        SET_DIR(d, lossy_ppm, (int) (strtod(args, NULL) * 10000.0 + 0.5));
    } else if (strcmp(verb, "corrupt") == 0) {
        int d = dir_of(args);
        SET_DIR(d, corrupt_ppm, (int) (strtod(args, NULL) * 10000.0 + 0.5));
    } else if (strcmp(verb, "dup") == 0) {
        int d = dir_of(args);
        SET_DIR(d, dup_ppm, (int) (strtod(args, NULL) * 10000.0 + 0.5));
    } else if (strcmp(verb, "reorder") == 0) {
        int d = dir_of(args); double p = 0; int m = -1;
        sscanf(args, "%lf %d", &p, &m);
        SET_DIR(d, reorder_ppm, (int) (p * 10000.0 + 0.5));
        if (m >= 0) { SET_DIR(d, reorder_ms, m); }
    } else if (strcmp(verb, "truncate-at") == 0) {
        int d = dir_of(args); SET_DIR(d, truncate_at, atol(args));
    } else if (strcmp(verb, "drop-bytes") == 0) {
        int d = dir_of(args);
        SET_DIR(d, drop_ppm, (int) (strtod(args, NULL) * 10000.0 + 0.5));
    } else if (strcmp(verb, "repeat-bytes") == 0) {
        int d = dir_of(args);
        SET_DIR(d, repeat_ppm, (int) (strtod(args, NULL) * 10000.0 + 0.5));
    } else if (strcmp(verb, "delay-first") == 0) {
        int d = dir_of(args); SET_DIR(d, delayfirst_ms, atoi(args));
    } else {
        return 0;
    }
    return 1;
}

/* Connection-lifecycle controls: bump the live epoch (drop/reset/half-close/
 * block) or toggle a persistent outage/hang state. Returns 1 if handled. */
int
cmd_set_epoch(const char *verb)
{
    if (strcmp(verb, "drop") == 0) {
        g_abortive = 0;
        __atomic_add_fetch(&g_drop_epoch, 1, __ATOMIC_SEQ_CST);
    } else if (strcmp(verb, "reset") == 0) {
        g_abortive = 1;
        __atomic_add_fetch(&g_drop_epoch, 1, __ATOMIC_SEQ_CST);
    } else if (strcmp(verb, "half-close") == 0) {
        __atomic_add_fetch(&g_halfclose_epoch, 1, __ATOMIC_SEQ_CST);
    } else if (strcmp(verb, "hang") == 0) {
        g_hang = 1;
    } else if (strcmp(verb, "unhang") == 0) {
        g_hang = 0;
    } else if (strcmp(verb, "block") == 0) {
        g_blocked = 1;
        __atomic_add_fetch(&g_drop_epoch, 1, __ATOMIC_SEQ_CST);
    } else if (strcmp(verb, "unblock") == 0) {
        g_blocked = 0;
    } else {
        return 0;
    }
    return 1;
}

/* One-off controls: fault counters, the deferred heal timer, reset-all.
 * Returns 1 if handled. */
int
cmd_set_misc(const char *verb, const char *args)
{
    if (strcmp(verb, "fail-nth") == 0) {
        g_fail_nth = atoi(args);
    } else if (strcmp(verb, "heal-after") == 0) {
        pthread_t h;
        if (pthread_create(&h, NULL, heal_thread,
                           (void *) (intptr_t) atol(args)) == 0) {
            pthread_detach(h);
        }
    } else if (strcmp(verb, "one-shot") == 0) {
        g_one_shot = 1;
    } else if (strcmp(verb, "abortive") == 0) {
        g_abortive = atoi(args) ? 1 : 0;
    } else if (strcmp(verb, "clear") == 0) {
        clear_all();
    } else {
        return 0;
    }
    return 1;
}

/* Autonomous "chaos monkey": every g_chaos_ms, fire a random lever within safe
 * bounds so a long soak sees an ever-shifting hostile network. Stops when its
 * generation is superseded (a new `chaos` / `chaos off` / `clear`). */
void *
chaos_thread(void *arg)
{
    unsigned gen  = (unsigned) (uintptr_t) arg;
    unsigned seed = g_seed ^ (gen * 2654435761u) ^ 0x9e3779b9u;
    while (__atomic_load_n(&g_chaos_gen, __ATOMIC_SEQ_CST) == gen) {
        int ms = g_chaos_ms > 0 ? g_chaos_ms : 500;
        usleep((useconds_t) ms * 1000);
        if (__atomic_load_n(&g_chaos_gen, __ATOMIC_SEQ_CST) != gen) {
            break;
        }
        char cmd[64];
        switch (rand_r(&seed) % 8) {
        case 0: snprintf(cmd, sizeof(cmd), "latency %u", rand_r(&seed) % 400); break;
        case 1: snprintf(cmd, sizeof(cmd), "jitter %u", rand_r(&seed) % 200); break;
        case 2: snprintf(cmd, sizeof(cmd), "corrupt %.3f",
                         (rand_r(&seed) % 50) / 100.0); break;
        case 3: snprintf(cmd, sizeof(cmd), "drop-bytes %.3f",
                         (rand_r(&seed) % 30) / 100.0); break;
        case 4: snprintf(cmd, sizeof(cmd), "chunk %u",
                         1u + rand_r(&seed) % 2048u); break;
        case 5: snprintf(cmd, sizeof(cmd), "rate %u",
                         8u + rand_r(&seed) % 4096u); break;
        case 6: snprintf(cmd, sizeof(cmd), "reorder %.2f 40",
                         (rand_r(&seed) % 2000) / 100.0); break;
        default: snprintf(cmd, sizeof(cmd), "%s",
                          (rand_r(&seed) % 4 == 0) ? "reset" : "clear"); break;
        }
        apply_command(cmd, NULL, 0);
    }
    return NULL;
}

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
