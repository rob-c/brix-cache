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
#include <stddef.h>   /* offsetof(): the fid_dir_ints descriptor table */
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

/* ---- Percent operand -> ppm ----
 *
 * WHAT: Converts a percentage operand to parts-per-million, returning 0 on
 *       success and -1 when the operand is negative.
 *
 * WHY:  `toxicity` and `refuse` both take a percentage and both store ppm; one
 *       converter keeps the clamp and the rounding identical between them, so a
 *       fix to either cannot drift.
 *
 * HOW:  1. atof the operand and refuse a negative.
 *       2. Clamp above 100% — over-saturating is an operator typo, not a fault.
 *       3. Scale to ppm with round-to-nearest.
 */
static int
fid_pct_to_ppm(const char *args, int *ppm)
{
    double  pct = atof(args);

    if (pct < 0.0) {
        return -1;
    }
    if (pct > 100.0) {
        pct = 100.0;
    }

    *ppm = (int) (pct * 10000.0 + 0.5);
    return 0;
}


/*
 * WHAT: One `set <verb> <n> [up|down|both]` lever — a non-negative int written
 *       to one `volatile int` field of lever_t on the named direction(s).
 * WHY:  These verbs differ only in name and target field, so express the family
 *       as data rather than an else-if ladder (coding-standards §8.6).
 * HOW:  `field` is an offsetof into lever_t, applied by cmd_set_dir_int.
 */
typedef struct {
    const char *verb;
    size_t      field;
} fid_dir_int_t;

static const fid_dir_int_t  fid_dir_ints[] = {
    { "slow-close", offsetof(lever_t, slow_close_ms) },
    { "rate",       offsetof(lever_t, rate_kbps)     },
    { "burst",      offsetof(lever_t, burst_bytes)   },
};


/* ---- Directional non-negative int levers ----
 *
 * WHAT: Handles the table above, returning 1 when `verb` was one of them (set
 *       or refused with an `err` reply) and 0 when it was not.
 *
 * WHY:  `rate` here deliberately shadows the unchecked cmd_set_lever branch —
 *       cmd_set_dispatch wires this first so a negative KB/s is refused rather
 *       than latched.
 *
 * HOW:  1. Match the verb against the table.
 *       2. Strip the direction token FIRST (dir_of rewrites `args`), then parse
 *          the remaining number, and refuse a negative without touching state.
 *       3. Write the value through the row's offsetof on the named side(s).
 */
static int
cmd_set_dir_int(const char *verb, char *args, char *reply, size_t rsz)
{
    size_t  n;
    int     d, v;

    for (n = 0; n < sizeof(fid_dir_ints) / sizeof(fid_dir_ints[0]); n++) {
        if (strcmp(verb, fid_dir_ints[n].verb) != 0) {
            continue;
        }

        d = dir_of(args);
        v = atoi(args);
        if (v < 0) {
            fp_reply(reply, rsz, "err: %s < 0\n", verb);
            return 1;
        }

        if (d != 2) {
            *(volatile int *) ((volatile char *) &g_up
                               + fid_dir_ints[n].field) = v;
        }
        if (d != 1) {
            *(volatile int *) ((volatile char *) &g_down
                               + fid_dir_ints[n].field) = v;
        }
        return 1;
    }

    return 0;
}


/* ---- set latency-dist <uniform|normal> <mean> [sigma] ----
 *
 * WHAT: Arms the jitter distribution on the named direction(s); always returns
 *       1 (the verb is consumed either way, malformed operands producing an
 *       `err` reply and no state change).
 *
 * WHY:  This is the only fidelity verb with a compound operand, so it owns its
 *       own parse rather than forcing the shared helpers to grow a shape field.
 *
 * HOW:  1. Strip the direction token, then sscanf shape + mean + optional sigma.
 *       2. Refuse a missing/negative mean and an unknown shape name before any
 *          write, so a rejected command leaves the previous distribution armed.
 *       3. Write mean, shape and sigma together — a partial arm would mean a
 *          normal distribution running with the previous sigma.
 */
static int
cmd_set_latency_dist(char *args, char *reply, size_t rsz)
{
    int   d = dir_of(args);
    char  shape[16] = "";
    int   mean = -1, sigma = 0, dist;
    int   nf = sscanf(args, "%15s %d %d", shape, &mean, &sigma);

    if (nf < 2 || mean < 0) {
        fp_reply(reply, rsz, "err: latency-dist <uniform|normal> <mean> [sigma]\n");
        return 1;
    }

    if (strcmp(shape, "uniform") == 0) {
        dist = 0;
    } else if (strcmp(shape, "normal") == 0) {
        dist = 1;
    } else {
        fp_reply(reply, rsz, "err: unknown distribution\n");
        return 1;
    }

    FID_SET_DIR(d, jitter_ms, mean);
    FID_SET_DIR(d, lat_dist, dist);
    FID_SET_DIR(d, lat_sigma_ms, sigma);
    return 1;
}


/* Phase-B fidelity verbs, each validated so a malformed operand is refused with
 * an `err` reply and leaves the lever unchanged.  Handles toxicity/slow-close/
 * connect-delay/refuse/burst/latency-dist plus a validated `rate` (overriding
 * the unchecked cmd_set_lever rate branch — wired first in cmd_set_dispatch).
 * Returns 1 when `verb` was one of these, else 0. */
int
cmd_set_fidelity(const char *verb, char *args, char *reply, size_t rsz)
{
    int  ppm;

    if (strcmp(verb, "toxicity") == 0) {
        int d = dir_of(args);
        if (fid_pct_to_ppm(args, &ppm) != 0) {
            fp_reply(reply, rsz, "err: toxicity < 0\n");
            return 1;
        }
        if (d != 2) { g_toxicity_up_ppm = ppm; }
        if (d != 1) { g_toxicity_down_ppm = ppm; }
        return 1;
    }

    if (strcmp(verb, "refuse") == 0) {
        if (fid_pct_to_ppm(args, &ppm) != 0) {
            fp_reply(reply, rsz, "err: refuse < 0\n");
            return 1;
        }
        g_refuse_ppm = ppm;
        return 1;
    }

    if (strcmp(verb, "connect-delay") == 0 ||
        strcmp(verb, "accept-delay") == 0) {
        int ms = atoi(args);
        if (ms < 0) {
            fp_reply(reply, rsz, "err: connect-delay < 0\n");
            return 1;
        }
        g_connect_delay_ms = ms;
        return 1;
    }

    if (cmd_set_dir_int(verb, args, reply, rsz)) {
        return 1;
    }

    if (strcmp(verb, "latency-dist") == 0) {
        return cmd_set_latency_dist(args, reply, rsz);
    }

    return 0;
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
