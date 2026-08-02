/*
 * brix_fault_proxy_control.c — brix-fault-proxy control plane.
 *
 * WHAT: the newline-command parser and the two threads that drive it — the
 *       control-port listener that applies live fault commands as traffic flows,
 *       and the optional --script timeline replayer.  Also the lever bookkeeping
 *       the commands mutate: the per-direction reset/clear helpers, the deferred
 *       heal timer, the direction-token stripper, and the status snapshot.
 *
 * WHY:  the control plane is the operator/test-facing surface; keeping it apart
 *       from the byte-shovelling data plane means the command grammar and its
 *       reply formatting live in one file with no relay-loop noise, and a change
 *       to the command set never risks the hot path.
 *
 * HOW:  each command is a verb plus args; cmd_set_lever/cmd_set_epoch/
 *       cmd_set_misc claim the verb they own (returning 1) so apply_command is a
 *       simple short-circuit chain.  Directional levers strip an optional
 *       up|down|both token via dir_of() then fan the value out with SET_DIR.
 *       Levers are volatile globals shared with the relay threads, so a mutation
 *       here is seen by the data plane on its next per-read snapshot.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "brix_fault_proxy_internal.h"

/* Strip a trailing up|down|both direction token from `args`; return which lever
 * set(s) it names: 0 = both, 1 = up only, 2 = down only.  Shared with the toxic
 * table (brix_fault_proxy_toxic.c), hence non-static. */
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
    L->drip_bytes = 0; L->drip_ms = 0;   L->rate_kbps = 0; L->burst_bytes = 0;
    L->lossy_ppm = 0;  L->reorder_ppm = 0; L->reorder_ms = 50;
    L->corrupt_ppm = 0; L->dup_ppm = 0;  L->truncate_at = 0;
    L->slow_close_ms = 0; L->lat_dist = 0; L->lat_sigma_ms = 0;
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
    g_toxicity_up_ppm   = 1000000;   /* back to 100% afflicted (default) */
    g_toxicity_down_ppm = 1000000;
    g_connect_delay_ms  = 0;
    g_refuse_ppm        = 0;
    fp_toxic_clear();
}

static void *
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
static int
cmd_set_lever(const char *verb, char *args)
{
    if (strcmp(verb, "latency") == 0) {
        int d = dir_of(args); SET_DIR(d, latency_ms, atoi(args));
    } else if (strcmp(verb, "jitter") == 0) {
        int d = dir_of(args); SET_DIR(d, jitter_ms, atoi(args));
    } else if (strcmp(verb, "chunk") == 0) {
        int d = dir_of(args); SET_DIR(d, chunk_bytes, atoi(args));
    } else if (strcmp(verb, "rate") == 0) {
        int d = dir_of(args); int v = atoi(args);
        if (v < 0) return 0;                 /* invalid -> unhandled -> err */
        SET_DIR(d, rate_kbps, v);
    } else if (strcmp(verb, "burst") == 0) {
        int d = dir_of(args); int v = atoi(args);
        if (v < 0) return 0;                 /* token-bucket depth, bytes */
        SET_DIR(d, burst_bytes, v);
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
    } else if (strcmp(verb, "slow-close") == 0) {
        int d = dir_of(args); int v = atoi(args);
        if (v < 0) return 0;                 /* invalid -> unhandled -> err */
        SET_DIR(d, slow_close_ms, v);
    } else if (strcmp(verb, "toxicity") == 0) {
        int d = dir_of(args); double p = strtod(args, NULL);
        if (p < 0) return 0;
        if (p > 100) p = 100;                /* clamp: 100% == every conn */
        int ppm = (int) (p * 10000.0 + 0.5);
        if (d != 2) g_toxicity_up_ppm = ppm;
        if (d != 1) g_toxicity_down_ppm = ppm;
    } else if (strcmp(verb, "latency-dist") == 0) {
        int d = dir_of(args);
        char mode[16] = ""; double mean = -1, sigma = -1;
        sscanf(args, "%15s %lf %lf", mode, &mean, &sigma);
        int dist = (strcmp(mode, "normal") == 0)  ? 1
                 : (strcmp(mode, "uniform") == 0) ? 0 : -1;
        if (dist < 0 || mean < 0) return 0;  /* bad mode/mean -> err */
        SET_DIR(d, lat_dist, dist);
        SET_DIR(d, jitter_ms, (int) mean);
        if (sigma >= 0) { SET_DIR(d, lat_sigma_ms, (int) sigma); }
    } else {
        return 0;
    }
    return 1;
}

/* Connection-lifecycle controls: bump the live epoch (drop/reset/half-close/
 * block) or toggle a persistent outage/hang state. Returns 1 if handled. */
static int
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
static int
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
    } else if (strcmp(verb, "connect-delay") == 0
               || strcmp(verb, "accept-delay") == 0) {
        int v = atoi(args);
        if (v < 0) return 0;
        g_connect_delay_ms = v;
    } else if (strcmp(verb, "refuse") == 0) {
        double p = strtod(args, NULL);
        if (p < 0) return 0;
        if (p > 100) p = 100;
        g_refuse_ppm = (int) (p * 10000.0 + 0.5);
    } else if (strcmp(verb, "clear") == 0) {
        clear_all();
    } else {
        return 0;
    }
    return 1;
}

/* Emit the full lever + counter snapshot into `reply` (no-op if NULL/empty). */
static void
cmd_status_report(char *reply, size_t rsz)
{
    if (!reply || !rsz) {
        return;
    }
    snprintf(reply, rsz,
"up[lat=%d jit=%d chunk=%d drip=%d/%dms rate=%d burst=%d lossy=%.4f%% reorder=%.4f%%/%dms "
"corrupt=%.4f%% dup=%.4f%% trunc=%ld sclose=%d dist=%d] "
"down[lat=%d jit=%d chunk=%d drip=%d/%dms rate=%d burst=%d lossy=%.4f%% reorder=%.4f%%/%dms "
"corrupt=%.4f%% dup=%.4f%% trunc=%ld sclose=%d dist=%d] "
"blocked=%d hang=%d abortive=%d one_shot=%d fail_nth=%d "
"refuse=%.4f%% cdelay=%d tox=%.4f/%.4f%% epoch=%u | "
"conns=%lu active=%lu up=%luB down=%luB severs=%lu corrupt=%lu dups=%lu refused=%lu\n",
        g_up.latency_ms, g_up.jitter_ms, g_up.chunk_bytes, g_up.drip_bytes,
        g_up.drip_ms, g_up.rate_kbps, g_up.burst_bytes, g_up.lossy_ppm / 10000.0,
        g_up.reorder_ppm / 10000.0, g_up.reorder_ms, g_up.corrupt_ppm / 10000.0,
        g_up.dup_ppm / 10000.0, g_up.truncate_at, g_up.slow_close_ms, g_up.lat_dist,
        g_down.latency_ms, g_down.jitter_ms, g_down.chunk_bytes, g_down.drip_bytes,
        g_down.drip_ms, g_down.rate_kbps, g_down.burst_bytes, g_down.lossy_ppm / 10000.0,
        g_down.reorder_ppm / 10000.0, g_down.reorder_ms, g_down.corrupt_ppm / 10000.0,
        g_down.dup_ppm / 10000.0, g_down.truncate_at, g_down.slow_close_ms, g_down.lat_dist,
        g_blocked, g_hang, g_abortive, g_one_shot, g_fail_nth,
        g_refuse_ppm / 10000.0, g_connect_delay_ms,
        g_toxicity_up_ppm / 10000.0, g_toxicity_down_ppm / 10000.0, g_drop_epoch,
        C.conns, C.active, C.up_bytes, C.down_bytes,
        C.severs, C.corrupt, C.dups, C.refused);
}

/* Emit the traffic/fault counters in Prometheus text-exposition format — a
 * scrape/monitoring oracle alongside the human `status` line (low-cardinality
 * labels only: direction). */
static void
cmd_metrics_report(char *reply, size_t rsz)
{
    if (!reply || !rsz) {
        return;
    }
    snprintf(reply, rsz,
"brix_fault_proxy_conns_total %lu\n"
"brix_fault_proxy_active_conns %lu\n"
"brix_fault_proxy_bytes_total{dir=\"up\"} %lu\n"
"brix_fault_proxy_bytes_total{dir=\"down\"} %lu\n"
"brix_fault_proxy_severs_total %lu\n"
"brix_fault_proxy_corrupt_bytes_total %lu\n"
"brix_fault_proxy_dups_total %lu\n"
"brix_fault_proxy_refused_total %lu\n",
        C.conns, C.active, C.up_bytes, C.down_bytes,
        C.severs, C.corrupt, C.dups, C.refused);
}

/* Parse and apply one control command.  `line` is mutated.  `reply` (may be NULL)
 * receives a human-readable response of up to `rsz` bytes. */
void
apply_command(char *line, char *reply, size_t rsz)
{
    /* JSON front-end (A2): a line beginning with '{' is a JSON request. When the
     * caller wants no reply (script replay) route through a scratch buffer so the
     * command's side effects still apply. */
    {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '{') {
            char scratch[512];
            brix_fp_json_request(line, reply ? reply : scratch,
                                 reply ? rsz : sizeof scratch);
            return;
        }
    }

    char verb[32] = "", args[224] = "";
    sscanf(line, "%31s %223[^\n]", verb, args);
    if (reply && rsz) {
        snprintf(reply, rsz, "ok\n");
    }

    if (cmd_set_lever(verb, args) || cmd_set_epoch(verb)
        || cmd_set_misc(verb, args)) {
        return;
    }
    if (strcmp(verb, "status") == 0) {
        cmd_status_report(reply, rsz);
    } else if (strcmp(verb, "metrics") == 0) {
        cmd_metrics_report(reply, rsz);
    } else if (strcmp(verb, "event-log") == 0) {
        /* reply pre-set to "ok\n"; only overwrite on a failed open. */
        if (fp_event_open(args) != 0 && reply && rsz) {
            snprintf(reply, rsz, "err: cannot open event log\n");
        }
    } else if (strcmp(verb, "toxic") == 0) {
        fp_toxic_cmd(args, reply, rsz);   /* add | remove | list [json] */
    } else if (strcmp(verb, "route") == 0) {
        fp_route_cmd(args, reply, rsz);   /* add | del | list [json] */
    } else if (verb[0] != '\0' && reply && rsz) {
        snprintf(reply, rsz, "err: unknown command\n");
    }
}

void *
control_thread(void *arg)
{
    int lfd = *(int *) arg;
    free(arg);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        /* A1 persistent session: one accepted connection carries many
         * newline-delimited commands until `quit`, EOF, or an over-long line.
         * Legacy fire-one-and-close clients that omit the terminator still work
         * via the trailing-partial flush below. */
        char   acc[1024];
        size_t used = 0;
        int    quit = 0;
        for (;;) {
            ssize_t n = read(cfd, acc + used, sizeof(acc) - 1 - used);
            if (n <= 0) {
                break;   /* EOF/error: flush any buffered partial after loop */
            }
            used += (size_t) n;
            acc[used] = '\0';
            char *start = acc, *nl;
            while ((nl = memchr(start, '\n',
                                (size_t) (acc + used - start))) != NULL) {
                *nl = '\0';
                char reply[1024];
                apply_command(start, reply, sizeof(reply));
                (void) write_all(cfd, reply, (ssize_t) strlen(reply));
                if (strcmp(start, "quit") == 0) { quit = 1; break; }
                start = nl + 1;
            }
            if (quit) {
                break;
            }
            size_t rem = (size_t) (acc + used - start);
            memmove(acc, start, rem);   /* keep the unconsumed tail */
            used = rem;
            if (used >= sizeof(acc) - 1) {   /* a single line overran the buffer */
                const char *e = "err: line too long\n";
                (void) write_all(cfd, e, (ssize_t) strlen(e));
                used = 0;   /* drop the oversized partial; resync on next newline */
            }
        }
        if (!quit && used > 0) {   /* legacy: bytes with no trailing newline */
            acc[used] = '\0';
            char reply[1024];
            apply_command(acc, reply, sizeof(reply));
            (void) write_all(cfd, reply, (ssize_t) strlen(reply));
        }
        close(cfd);
    }
    return NULL;
}

/* Replay a '<seconds> <command>' timeline file (relative to start). */
void *
script_thread(void *arg)
{
    FILE *fp = fopen((const char *) arg, "r");
    if (fp == NULL) {
        fprintf(stderr, "brix-fault-proxy: cannot open --script '%s'\n",
                (const char *) arg);
        return NULL;
    }
    char   line[256];
    double prev = 0.0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') {
            continue;
        }
        double t = 0.0;
        int    off = 0;
        if (sscanf(p, "%lf %n", &t, &off) < 1) {
            continue;
        }
        double dt = t - prev;
        if (dt > 0) {
            usleep((useconds_t) (dt * 1e6));
        }
        prev = t;
        apply_command(p + off, NULL, 0);
    }
    fclose(fp);
    return NULL;
}
