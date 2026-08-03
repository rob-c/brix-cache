/* brix_fault_report.c — command dispatch, status reporting and oracle jobs.
 *
 * WHAT: The top-level control-command dispatcher, the text and JSON status reports,
 *       the oracle-driven bisection/recovery jobs and their result slots, and the
 *       control-port and script driver threads.
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
#include "brix_fault_proxy_mods.h"
#include "brix_fault_priv.h"
#include "brix_fault_oracle.h"
#include "brix_fault_toxic.h"
#include "brix_fault_buf.h"
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --- Auto-bisection + assert-recovery oracle ------------------------------ */

struct bisect_arg { char lever[24]; long lo, hi; int timeout_ms; char cmd[256]; };
struct recov_arg  { char fault[256]; int hold_ms; char probe[256]; int timeout_ms; };

void
res_set(char *slot, const char *fmt, ...)
{
    va_list ap;
    pthread_mutex_lock(&g_res_lock);
    va_start(ap, fmt);
    vsnprintf(slot, 192, fmt, ap);
    va_end(ap);
    pthread_mutex_unlock(&g_res_lock);
}

/* Binary-search the smallest integer value of `lever` in [lo,hi] for which the
 * oracle command FAILS (non-zero exit = the bug reproduces), assuming severity
 * is monotonic in the lever.  Publishes progress + the boundary to g_bisect_result. */
void *
bisect_thread(void *arg)
{
    struct bisect_arg *b = arg;
    long lo = b->lo, hi = b->hi, found = b->hi + 1;
    int  probes = 0;
    while (lo <= hi) {
        long mid = lo + (hi - lo) / 2;
        char cmd[48];
        snprintf(cmd, sizeof(cmd), "%s %ld", b->lever, mid);
        apply_command(cmd, NULL, 0);
        int rc = fp_oracle_run(b->cmd, b->timeout_ms);
        probes++;
        res_set(g_bisect_result, "running: %s probe#%d val=%ld rc=%d",
                b->lever, probes, mid, rc);
        if (rc == -2) {
            res_set(g_bisect_result, "error: oracle disabled (--enable-exec)");
            break;
        }
        if (rc != 0) {              /* reproduced (fail or inconclusive) → go smaller */
            found = mid;
            hi = mid - 1;
        } else {                    /* survived → need a harsher value */
            lo = mid + 1;
        }
    }
    apply_command((char[]){"clear"}, NULL, 0);
    if (found <= b->hi) {
        res_set(g_bisect_result, "done: minimal %s=%ld reproduces (%d probes)",
                b->lever, found, probes);
    } else {
        res_set(g_bisect_result, "done: no %s in [%ld,%ld] reproduced (%d probes)",
                b->lever, b->lo, b->hi, probes);
    }
    g_oracle_busy = 0;
    free(b);
    return NULL;
}

/* Apply a fault for hold_ms, clear it, then poll a health probe until it passes
 * or times out — asserting the service recovers.  Publishes to g_recovery_result. */
void *
recovery_thread(void *arg)
{
    struct recov_arg *r = arg;
    char fcmd[256];
    snprintf(fcmd, sizeof(fcmd), "%s", r->fault);
    apply_command(fcmd, NULL, 0);
    res_set(g_recovery_result, "running: fault held %dms", r->hold_ms);
    usleep((useconds_t) r->hold_ms * 1000);
    apply_command((char[]){"clear"}, NULL, 0);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int elapsed = 0;
    for (;;) {
        int rc = fp_oracle_run(r->probe, 2000);
        if (rc == -2) {
            res_set(g_recovery_result, "error: oracle disabled (--enable-exec)");
            break;
        }
        elapsed = (int) now_ms_since(t0);
        if (rc == 0) {
            res_set(g_recovery_result, "done: recovered in %dms", elapsed);
            break;
        }
        if (elapsed >= r->timeout_ms) {
            res_set(g_recovery_result, "done: STUCK — no recovery in %dms", elapsed);
            break;
        }
        usleep(250 * 1000);
    }
    g_oracle_busy = 0;
    free(r);
    return NULL;
}

/* Report a result slot under g_res_lock. */
static void
oracle_result(const char *slot, char *reply, size_t rsz)
{
    pthread_mutex_lock(&g_res_lock);
    snprintf(reply, rsz, "%s\n", slot);
    pthread_mutex_unlock(&g_res_lock);
}

/* The two preconditions every probe-spawning oracle job shares. Returns 1 (with
 * `reply` filled) when `job` must not start. */
static int
oracle_refused(const char *job, char *reply, size_t rsz)
{
    if (!fp_oracle_enabled()) {
        snprintf(reply, rsz, "err: %s needs --enable-exec\n", job);
        return 1;
    }
    if (g_oracle_busy) {
        snprintf(reply, rsz, "err: an oracle job is already running\n");
        return 1;
    }
    return 0;
}

/* Hand `arg` to `fn` on a detached thread, taking the busy flag with it. On any
 * failure the flag is released and `arg` freed, so the slot never wedges. */
static void
oracle_spawn(void *(*fn)(void *), void *arg, const char *job,
             char *reply, size_t rsz, const char *okmsg)
{
    pthread_t th;
    g_oracle_busy = 1;
    if (pthread_create(&th, NULL, fn, arg) != 0) {
        g_oracle_busy = 0;
        free(arg);
        snprintf(reply, rsz, "err: cannot start %s thread\n", job);
        return;
    }
    pthread_detach(th);
    snprintf(reply, rsz, "%s", okmsg);
}

/* bisect <lever> <lo> <hi> <timeout_ms> <oracle-cmd> */
static void
oracle_bisect(char *args, char *reply, size_t rsz)
{
    struct bisect_arg *b = calloc(1, sizeof(*b));
    char *lever = strtok(args, " ");
    char *lo    = strtok(NULL, " ");
    char *hi    = strtok(NULL, " ");
    char *to    = strtok(NULL, " ");
    char *cmd   = strtok(NULL, "");

    if (!b || !lever || !lo || !hi || !to || !cmd) {
        free(b);
        snprintf(reply, rsz, "err: bisect <lever> <lo> <hi> <timeout_ms> <oracle-cmd>\n");
        return;
    }
    snprintf(b->lever, sizeof(b->lever), "%s", lever);
    b->lo = atol(lo); b->hi = atol(hi); b->timeout_ms = atoi(to);
    snprintf(b->cmd, sizeof(b->cmd), "%s", cmd);

    char ok[128];
    snprintf(ok, sizeof(ok), "ok (bisecting %s in [%ld,%ld]; poll bisect-result)\n",
             b->lever, b->lo, b->hi);
    oracle_spawn(bisect_thread, b, "bisect", reply, rsz, ok);
}

/* recovery <fault-cmd> | <hold_ms> | <probe-cmd> | <timeout_ms> */
static void
oracle_recovery(char *args, char *reply, size_t rsz)
{
    struct recov_arg *r = calloc(1, sizeof(*r));
    char *fault = strtok(args, "|");
    char *hold  = strtok(NULL, "|");
    char *probe = strtok(NULL, "|");
    char *to    = strtok(NULL, "|");

    if (!r || !fault || !hold || !probe || !to) {
        free(r);
        snprintf(reply, rsz,
                 "err: recovery <fault-cmd> | <hold_ms> | <probe-cmd> | <timeout_ms>\n");
        return;
    }
    snprintf(r->fault, sizeof(r->fault), "%s", fault);
    r->hold_ms = atoi(hold);
    snprintf(r->probe, sizeof(r->probe), "%s", probe);
    r->timeout_ms = atoi(to);

    oracle_spawn(recovery_thread, r, "recovery", reply, rsz,
                 "ok (recovery probe started; poll recovery-result)\n");
}

/* Oracle-driven control verbs (bisect / recovery / their results). Gated on
 * --enable-exec for anything that spawns a probe. Returns 1 if handled. */
int
cmd_set_oracle(const char *verb, char *args, char *reply, size_t rsz)
{
    if (strcmp(verb, "bisect-result") == 0) {
        oracle_result(g_bisect_result, reply, rsz);
        return 1;
    }
    if (strcmp(verb, "recovery-result") == 0) {
        oracle_result(g_recovery_result, reply, rsz);
        return 1;
    }
    if (strcmp(verb, "bisect") == 0) {
        if (!oracle_refused("bisect", reply, rsz)) {
            oracle_bisect(args, reply, rsz);
        }
        return 1;
    }
    if (strcmp(verb, "recovery") == 0) {
        if (!oracle_refused("recovery", reply, rsz)) {
            oracle_recovery(args, reply, rsz);
        }
        return 1;
    }
    return 0;
}

/* Protocol-surgery + record/replay dispatch (tls/http/record/replay). */
int
cmd_set_proto(const char *verb, char *args, char *reply, size_t rsz)
{
    if (strcmp(verb, "tls") == 0) {
        return cmd_set_tls(args, reply, rsz);
    }
    if (strcmp(verb, "http") == 0) {
        return cmd_set_http(args, reply, rsz);
    }
    return cmd_set_replay(verb, args, reply, rsz);
}

/* Emit the full lever + counter snapshot into `reply` (no-op if NULL/empty). */
void
cmd_status_report(char *reply, size_t rsz)
{
    if (!reply || !rsz) {
        return;
    }
    int k = snprintf(reply, rsz,
"up[lat=%d jit=%d chunk=%d drip=%d/%dms rate=%d lossy=%.4f%% reorder=%.4f%%/%dms "
"corrupt=%.4f%% dup=%.4f%% trunc=%ld] "
"down[lat=%d jit=%d chunk=%d drip=%d/%dms rate=%d lossy=%.4f%% reorder=%.4f%%/%dms "
"corrupt=%.4f%% dup=%.4f%% trunc=%ld] "
"blocked=%d hang=%d abortive=%d one_shot=%d fail_nth=%d epoch=%u | "
"conns=%lu active=%lu up=%luB down=%luB severs=%lu corrupt=%lu dups=%lu refused=%lu\n",
        g_up.latency_ms, g_up.jitter_ms, g_up.chunk_bytes, g_up.drip_bytes,
        g_up.drip_ms, g_up.rate_kbps, g_up.lossy_ppm / 10000.0,
        g_up.reorder_ppm / 10000.0, g_up.reorder_ms, g_up.corrupt_ppm / 10000.0,
        g_up.dup_ppm / 10000.0, g_up.truncate_at,
        g_down.latency_ms, g_down.jitter_ms, g_down.chunk_bytes, g_down.drip_bytes,
        g_down.drip_ms, g_down.rate_kbps, g_down.lossy_ppm / 10000.0,
        g_down.reorder_ppm / 10000.0, g_down.reorder_ms, g_down.corrupt_ppm / 10000.0,
        g_down.dup_ppm / 10000.0, g_down.truncate_at,
        g_blocked, g_hang, g_abortive, g_one_shot, g_fail_nth, g_drop_epoch,
        C.conns, C.active, C.up_bytes, C.down_bytes,
        C.severs, C.corrupt, C.dups, C.refused);
    if (k < 0 || (size_t) k >= rsz) {
        return;
    }
    int k2 = snprintf(reply + k, rsz - (size_t) k,
"ext up[drop=%.4f%% rep=%.4f%% dfirst=%d] down[drop=%.4f%% rep=%.4f%% dfirst=%d] "
"mss=%d rcvbuf=%d sndbuf=%d maxlife=%ldms stall=%d/%d proxy=%d chaos=%d | "
"dropped=%lu repeated=%lu injected=%luB replaced=%lu\n",
        g_up.drop_ppm / 10000.0, g_up.repeat_ppm / 10000.0, g_up.delayfirst_ms,
        g_down.drop_ppm / 10000.0, g_down.repeat_ppm / 10000.0, g_down.delayfirst_ms,
        g_mss, g_rcvbuf, g_sndbuf, g_max_life_ms, g_stall_up, g_stall_down,
        g_proxy_mode, g_chaos_on,
        C.dropped, C.repeated, C.injected, C.replaced);
    if (k2 < 0 || (size_t) (k + k2) >= rsz) {
        return;
    }
    int k3 = snprintf(reply + k + k2, rsz - (size_t) (k + k2),
"attack trig=%d/%d mangle=%d/%d accept-pause=%dms fanout=%d global-rate=%dkbps "
"flap=%d ramp=%u | triggered=%lu mangled=%lu fanout_conns=%lu\n",
        g_trig_up.pat_len > 0, g_trig_down.pat_len > 0,
        g_mangle_up.active, g_mangle_down.active,
        g_accept_pause_ms, g_fanout, g_global_rate_kbps,
        g_flap_on, __atomic_load_n(&g_ramp_gen, __ATOMIC_SEQ_CST),
        C.triggered, C.mangled, C.fanout_conns);
    size_t used = (size_t) (k + k2 + k3);
    if (k3 < 0 || used >= rsz) {
        return;
    }
    pthread_mutex_lock(&g_res_lock);
    snprintf(reply + used, rsz - used,
"proto tls=%d/%d http=%d/%d record=%d replay=%d/%s exec=%d | tls_rw=%lu http_rw=%lu "
"recorded=%luB replayed=%luB | bisect[%s] recovery[%s]\n",
        fp_tls_active(&g_tls_up), fp_tls_active(&g_tls_down),
        fp_http_active(&g_http_up), fp_http_active(&g_http_down),
        fp_replay_recording(), g_replay_active, g_replay_updir ? "up" : "down",
        fp_oracle_enabled(),
        C.tls_rewrites, C.http_rewrites, C.recorded, C.replayed,
        g_bisect_result, g_recovery_result);
    pthread_mutex_unlock(&g_res_lock);
}

/* Machine-readable snapshot (a subset, for test harnesses / dashboards). */
void
cmd_status_json(char *reply, size_t rsz)
{
    if (!reply || !rsz) {
        return;
    }
    snprintf(reply, rsz,
"{\"conns\":%lu,\"active\":%lu,\"up_bytes\":%lu,\"down_bytes\":%lu,"
"\"severs\":%lu,\"corrupt\":%lu,\"dups\":%lu,\"refused\":%lu,"
"\"dropped\":%lu,\"repeated\":%lu,\"injected\":%lu,\"replaced\":%lu,"
"\"triggered\":%lu,\"mangled\":%lu,\"fanout_conns\":%lu,"
"\"tls_rewrites\":%lu,\"http_rewrites\":%lu,\"recorded\":%lu,\"replayed\":%lu,"
"\"blocked\":%d,\"hang\":%d,\"epoch\":%u,\"chaos\":%d,\"flap\":%d,"
"\"fanout\":%d,\"global_rate_kbps\":%d,\"accept_pause_ms\":%d,"
"\"recording\":%d,\"replay\":%d,\"exec\":%d}\n",
        C.conns, C.active, C.up_bytes, C.down_bytes,
        C.severs, C.corrupt, C.dups, C.refused,
        C.dropped, C.repeated, C.injected, C.replaced,
        C.triggered, C.mangled, C.fanout_conns,
        C.tls_rewrites, C.http_rewrites, C.recorded, C.replayed,
        g_blocked, g_hang, g_drop_epoch, g_chaos_on, g_flap_on,
        g_fanout, g_global_rate_kbps, g_accept_pause_ms,
        fp_replay_recording(), g_replay_active, fp_oracle_enabled());
}

/* status [json] — the counters, either as a human report or as one JSON object. */
static void
cmd_status(const char *args, char *reply, size_t rsz)
{
    if (strcmp(args, "json") == 0) {
        cmd_status_json(reply, rsz);
    } else {
        cmd_status_report(reply, rsz);
    }
}

/* JSON control input ({"cmd":..,"args":..}) is reprojected onto the ONE verb
 * grammar and re-run, so no command is ever defined twice. */
static void
apply_json_command(const char *json, char *reply, size_t rsz)
{
    char verbline[2000];

    if (fp_json_to_verb(json, verbline, sizeof verbline) != 0) {
        fp_reply(reply, rsz, "err: bad json command\n");
        return;
    }
    apply_command(verbline, reply, rsz);
}

/* event-log <path> — point the structured event stream at a file. */
static void
cmd_event_log(const char *args, char *reply, size_t rsz)
{
    if (args[0] == '\0') {
        fp_reply(reply, rsz, "err: usage: event-log <path>\n");
    } else if (fp_event_open(args) != 0) {
        fp_reply(reply, rsz, "err: cannot open '%s'\n", args);
    } else {
        fp_reply(reply, rsz, "ok: event-log %s\n", args);
    }
}

/* The lever/attack/protocol/oracle families, each of which claims its own verbs.
 * Returns 1 once one of them has handled `verb`. */
static int
cmd_set_dispatch(const char *verb, char *args, char *reply, size_t rsz)
{
    return cmd_set_lever(verb, args) || cmd_set_epoch(verb)
        || cmd_set_misc(verb, args) || cmd_set_ext(verb, args, reply, rsz)
        || cmd_set_attack(verb, args, reply, rsz)
        || cmd_set_proto(verb, args, reply, rsz)
        || cmd_set_oracle(verb, args, reply, rsz);
}

/* Parse and apply one control command.  `line` is mutated.  `reply` (may be NULL)
 * receives a human-readable response of up to `rsz` bytes. */
void
apply_command(char *line, char *reply, size_t rsz)
{
    const char *j = line;
    while (*j == ' ' || *j == '\t') {
        j++;
    }
    if (*j == '{') {
        apply_json_command(j, reply, rsz);
        return;
    }

    char verb[32] = "", args[2000] = "";
    sscanf(line, "%31s %1999[^\n]", verb, args);
    fp_reply(reply, rsz, "ok\n");

    if (strcmp(verb, "priv") == 0) {
        fp_priv_command(args, reply, rsz);
    } else if (strcmp(verb, "event-log") == 0) {
        cmd_event_log(args, reply, rsz);
    } else if (strcmp(verb, "toxic") == 0) {
        fp_toxic_cmd(args, reply, rsz);
    } else if (strcmp(verb, "route") == 0) {
        fp_route_cmd(args, reply, rsz);
    } else if (cmd_set_dispatch(verb, args, reply, rsz)) {
        return;
    } else if (strcmp(verb, "status") == 0) {
        cmd_status(args, reply, rsz);
    } else if (verb[0] != '\0') {
        fp_reply(reply, rsz, "err: unknown command\n");
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
        char line[2048];
        ssize_t n = read(cfd, line, sizeof(line) - 1);
        if (n > 0) {
            line[n] = '\0';
            char reply[2048];
            apply_command(line, reply, sizeof(reply));
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
