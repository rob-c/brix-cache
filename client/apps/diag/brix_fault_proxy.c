/*
 * brix_fault_proxy.c — brix-fault-proxy: a root-free TCP fault-injection proxy.
 *
 * WHAT: Relays TCP from a local listen port to an upstream host:port and injects
 *       network faults on demand — latency, jitter, partial writes, slow-drip,
 *       bandwidth caps, packet-loss (resets), payload corruption, duplication,
 *       deterministic mid-transfer truncation, connection black-holes, and full
 *       outages — set at startup on the command line or live over a control port
 *       while traffic flows.  A "toxiproxy-lite" you can splice in front of any
 *       brix (or stock XRootD/HTTP) endpoint to prove a client survives a bad or
 *       actively hostile network, WITHOUT needing root: tc/netem needs
 *       CAP_NET_ADMIN; this is pure userspace sockets.
 *
 * DIRECTIONALITY: every byte-level lever is per-direction.  `up`   = client ->
 *       upstream (the request/upload path), `down` = upstream -> client (the
 *       response/download path).  A control command with no direction token
 *       applies to BOTH; append ` up`, ` down`, or ` both` to target one.
 *
 * FAULT LEVERS (each off/0 by default; set at startup via the matching --flag or
 *              live by writing the command to the control port):
 *   latency <ms> [dir]        delay every forwarded chunk (a high-RTT link)
 *   jitter <ms> [dir]         delay each chunk by a uniform-random 0..<ms> ms —
 *                             the application signature of IP reordering (see NOTE)
 *   chunk <bytes> [dir]       split each write into <=N-byte segments (egress
 *                             TCP_NODELAY) so the peer sees genuine partial reads
 *   drip <bytes> <ms> [dir]   forward <bytes>, sleep <ms>, repeat (slow stream)
 *   rate <KB/s> [dir]         pace the stream to a bandwidth ceiling (slow link)
 *   lossy <pct> [dir]         with prob <pct>%/chunk, sever the stream (loss=reset)
 *   reorder <pct> [ms] [dir]  with prob <pct>%/chunk, hold that chunk back <ms> ms
 *   corrupt <pct> [dir]       flip a random bit in <pct>% of forwarded BYTES — a
 *                             MITM tamper that a checksum-verifying peer must catch
 *   dup <pct> [dir]           with prob <pct>%/chunk, deliver that chunk twice
 *   truncate-at <bytes> [dir] sever each connection once <bytes> have flowed in
 *                             that direction (deterministic mid-transfer cut)
 *   fail-nth <n>              fail exactly the Nth accepted connection, pass others
 *   heal-after <ms>           auto-clear every lever after <ms> (a transient fault)
 *   one-shot                  self-heal (clear) the moment a sever/truncate fires
 *   drop                      graceful-FIN sever every live connection now
 *   reset                     abortive-RST sever every live connection now, and
 *                             make subsequent lossy/truncate severs use RST too
 *   abortive <0|1>            select RST (1) vs graceful FIN (0) for auto-severs
 *   half-close                FIN the client->upstream path on live conns while the
 *                             upstream->client path keeps flowing (tests half-open)
 *   hang                      accept new connections but never relay (a black hole)
 *   unhang                    resume relaying newly accepted connections
 *   block                     drop live conns AND refuse new ones (an outage window)
 *   unblock                   resume accepting
 *   clear                     reset every lever (levers=0, unblock, unhang)
 *   status                    report lever state and traffic/fault counters
 *
 * WHY:  A client's resilience (reconnect + file-handle resumption, per-PDU read
 *       deadlines, low-speed aborts, checksum-verify-and-retry) needs the exact
 *       conditions of "bad wifi from a laptop abroad" — or an outright tampering
 *       MITM — injected deterministically and without privilege.  The peer
 *       connects THROUGH this proxy; an operator (or a test) pulls the levers.
 *
 * HOW:  Thread-per-connection relay (so per-chunk latency is a simple usleep); a
 *       global drop-epoch counter that, when bumped, makes every live relay thread
 *       sever and exit; a control thread parsing newline commands; an optional
 *       timeline thread replaying a scripted scenario.  All randomness is per-thread
 *       rand_r() seeded from --seed for reproducibility.
 *
 * SECURITY: the control port is UNAUTHENTICATED — anyone who can reach it can pull
 *       the fault levers and reset live connections.  Both the listen and control
 *       sockets therefore bind to loopback by DEFAULT; widening the bind address
 *       (--bind) exposes the control plane and is refused unless you also pass
 *       --insecure-bind, which prints a warning.  Never expose the control port to
 *       an untrusted network.
 *
 * NOTE: packet LOSS is intentionally modelled as a connection sever, not byte
 *       drops: dropping bytes from an already-ACKed TCP stream corrupts it rather
 *       than emulating loss (which lives below TCP).  Likewise true out-of-order
 *       PACKET delivery cannot be emulated by re-ordering bytes — TCP reassembles
 *       in order below us — so `jitter`/`reorder` inject the variable latency that
 *       IP reordering actually imposes on a TCP application.  (True packet
 *       reordering needs `tc qdisc ... netem`, i.e. CAP_NET_ADMIN, which this
 *       avoids.)  `corrupt`, by contrast, IS a real in-band byte mutation: it is
 *       what an active on-path attacker (or a flaky NIC past the TCP checksum)
 *       does, and it is precisely what an application-layer checksum exists to
 *       catch.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <time.h>

#include "core/version.h"
#include "brix_fault_priv.h"
#include "brix_fault_ext.h"
#include "brix_fault_tls.h"
#include "brix_fault_http.h"
#include "brix_fault_replay.h"
#include "brix_fault_oracle.h"
#include "brix_fault_lever.h"
#include "brix_fault_toxic.h"
#include "brix_fault_route.h"
#include "brix_fault_proxy_mods.h"
#include "brix_fault_proxy_state.h"

/* ---- shared state: the single definition site ---------------------------- */
/* Declared in brix_fault_proxy_state.h; see that header for what each lever
 * means and how it is synchronised. */

volatile lever_t g_up;
volatile lever_t g_down;

fp_target g_targets[FP_MAX_TARGETS];
int       g_ntargets = 0;

struct sockaddr_storage g_bind_ss;
socklen_t               g_bind_len = 0;

volatile int      g_blocked  = 0;
volatile int      g_hang     = 0;
volatile int      g_abortive = 0;
volatile int      g_one_shot = 0;
volatile int      g_fail_nth = 0;
volatile unsigned g_drop_epoch      = 0;
volatile unsigned g_halfclose_epoch = 0;
unsigned          g_seed      = 0;
int               g_max_conns = 0;

volatile int      g_stall_up    = 0;
volatile int      g_stall_down  = 0;
volatile int      g_toxicity_up_ppm   = 1000000;  /* 100% = every conn afflicted (today's default) */
volatile int      g_toxicity_down_ppm = 1000000;
volatile int      g_connect_delay_ms  = 0;
volatile int      g_refuse_ppm        = 0;
volatile int      g_mss         = 0;
volatile int      g_rcvbuf      = 0;
volatile int      g_sndbuf      = 0;
volatile long     g_max_life_ms = 0;
volatile unsigned g_chaos_gen   = 0;
volatile int      g_chaos_ms    = 0;
volatile int      g_chaos_on    = 0;

volatile int      g_proxy_mode = 0;
char              g_proxy_src[128];
char              g_proxy_dst[128];

/* Phase-99 DPI/middlebox pathology levers. */
volatile int      g_idle_reap_ms      = 0;
volatile int      g_idle_reap_rst     = 0;
volatile int      g_eat_100           = 0;
volatile long     g_rst_after_bytes   = 0;
volatile long     g_rst_after_ms      = 0;
volatile int      g_rst_after_abortive = 0;
volatile int      g_drop_fin_up       = 0;
volatile int      g_drop_fin_down     = 0;
volatile long     g_classify_bytes    = 0;
volatile int      g_classify_kbps     = 0;
volatile int      g_syn_drop_ppm      = 0;
volatile int      g_hello_reset_thresh = 0;
volatile int      g_udp_drop_ppm      = 0;
volatile int      g_udp_hold_ms       = 0;
volatile int      g_udp_reap_ms       = 0;
volatile int      g_udp_reorder_ppm   = 0;
volatile int      g_udp_reorder_ms    = 0;

struct fp_mutbuf  g_up_mut, g_down_mut;
pthread_mutex_t   g_ext_lock = PTHREAD_MUTEX_INITIALIZER;

struct fp_trigger g_trig_up, g_trig_down;
struct fp_mangle  g_mangle_up, g_mangle_down;

volatile int      g_accept_pause_ms  = 0;
volatile int      g_fanout           = 0;
volatile int      g_global_rate_kbps = 0;
volatile unsigned g_flap_gen         = 0;
volatile int      g_flap_on          = 0;
volatile int      g_flap_up_ms       = 0;
volatile int      g_flap_down_ms     = 0;
volatile unsigned g_ramp_gen         = 0;

double            g_gr_tokens = 0.0;
struct timespec   g_gr_last;
int               g_gr_init = 0;
pthread_mutex_t   g_gr_lock = PTHREAD_MUTEX_INITIALIZER;

fp_tls_cfg  g_tls_up,  g_tls_down;
fp_http_cfg g_http_up, g_http_down;

volatile int      g_replay_active = 0;
volatile int      g_replay_updir  = 0;
fp_replay_store   g_replay_store;

char              g_bisect_result[192]   = "idle";
char              g_recovery_result[192] = "idle";
pthread_mutex_t   g_res_lock = PTHREAD_MUTEX_INITIALIZER;
volatile int      g_oracle_busy = 0;

struct timespec   g_t0;

fp_counters C;

__thread unsigned long t_conn_id = 0;
__thread int t_afflict_up = 1;
__thread int t_afflict_down = 1;
__thread int t_fwd_up = 0;   /* direction of the segment currently forwarding */

/* ---- Accept-path probability gate ----
 *
 * WHAT: Returns non-zero when a ppm lever fires for this connection, zero when
 *       the lever is off or the draw missed.
 *
 * WHY:  `refuse` and `syn-drop` draw the same way and must stay independent of
 *       each other and of the relay-path RNG; one gate keeps the ppm scale and
 *       the seeding rule in a single place.
 *
 * HOW:  1. An unarmed lever (ppm <= 0) never draws, so it costs nothing.
 *       2. Seed on first use from `g_seed` when the run is seeded, else from
 *          the caller's distinct constant — two levers seeded alike would fire
 *          on exactly the same connections.
 *       3. Draw in [0, 1e6) and compare against ppm.
 */
static int
fp_ppm_hit(int ppm, unsigned *seed, unsigned seed_init)
{
    if (ppm <= 0) {
        return 0;
    }

    if (*seed == 0) {
        *seed = g_seed ? g_seed : seed_init;
    }

    return (unsigned) (rand_r(seed) % 1000000) < (unsigned) ppm;
}


/* ---- Admission decision for one accepted client ----
 *
 * WHAT: Returns 1 when `client` should be relayed; returns 0 having already
 *       closed the fd and bumped the matching counter when a lever refused it.
 *
 * WHY:  Keeps every "refuse a new connection" rule in one place, so the accept
 *       loop cannot grow a path that admits a client the levers meant to drop.
 *       Ownership of the fd moves here on refusal — the caller never has to
 *       decide whether it was closed.
 *
 * HOW:  1. block: a hard outage refuses everything.
 *       2. refuse: probabilistically drop a fraction of NEW connections (a
 *          flaky listener).  Independent of block; does not sever live
 *          connections and does not bump the drop epoch.
 *       3. syn-drop: silently drop a fraction of accepted clients (no RST) so
 *          the connection looks like it never happened — connect-timeout under
 *          load.
 *       4. max-conns: refuse once the live-connection cap is reached.
 */
static int
fp_accept_admit(int client)
{
    static unsigned  refuse_seed = 0;
    static unsigned  syn_seed = 0;

    if (g_blocked) {
        brix_fp_event(CBUMP(refused, 1), NULL, "refuse", "block", NULL, 0);
        close(client);        /* outage: refuse */
        return 0;
    }

    if (fp_ppm_hit(g_refuse_ppm, &refuse_seed, 0x27d4eb2fu)) {
        brix_fp_event(CBUMP(refused, 1), NULL, "refuse", "refuse", NULL, 0);
        close(client);
        return 0;
    }

    if (fp_ppm_hit(g_syn_drop_ppm, &syn_seed, 0x9e3779b9u)) {
        CBUMP(syn_dropped, 1);
        close(client);
        return 0;
    }

    if (g_max_conns > 0
        && __atomic_load_n(&C.active, __ATOMIC_RELAXED) >= (unsigned long) g_max_conns) {
        brix_fp_event(CBUMP(refused, 1), NULL, "refuse", "max-conns", NULL, 0);
        close(client);        /* connection cap reached */
        return 0;
    }

    return 1;
}


/* ---- Hand an admitted client to a detached relay thread ----
 *
 * WHAT: Takes ownership of `client`: either a running relay thread owns it, or
 *       it has been closed and the live-connection gauge has been rolled back.
 *
 * WHY:  `active` is a GAUGE and is bumped before the thread exists (the thread
 *       cannot bump it for itself without racing the cap check), so a failed
 *       spawn must decrement it or the cap leaks toward permanent refusal.
 *       `conns` and the route's per-route count are cumulative TOTALS and are
 *       deliberately not rolled back — an accepted-then-dropped connection did
 *       happen.  Keeping that asymmetry in one function is what makes it
 *       auditable.
 *
 * HOW:  1. Disable Nagle so the injected timing is the proxy's, not the
 *          kernel's.
 *       2. Snapshot the drop epoch into the per-connection argument, so a later
 *          `sever` can tell this connection from one opened after it.
 *       3. On spawn failure, close and roll the counters back.
 */
static void
fp_spawn_relay(fp_route *route, int client)
{
    int         one = 1;
    relay_arg  *ra;
    pthread_t   t;

    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    ra = malloc(sizeof(*ra));
    if (ra == NULL) {
        close(client);
        return;
    }

    ra->client_fd = client;
    ra->epoch = __atomic_load_n(&g_drop_epoch, __ATOMIC_SEQ_CST);
    ra->conn_id = CBUMP(conns, 1);
    ra->route = route;
    CBUMP(active, 1);
    fp_route_inc_conns(route);

    if (pthread_create(&t, NULL, relay_thread, ra) != 0) {
        close(client);
        CDEC(active);
        free(ra);
        return;
    }

    pthread_detach(t);
}


/* Accept clients for `route` on `lfd`, spawning a detached relay thread per
 * connection (subject to the outage/connection-cap levers).  Returns when the
 * route is stopped (fp_route_alive(route) == 0) or on a non-EINTR accept error.
 * poll() with a short timeout makes the loop responsive to a `route del` without
 * blocking indefinitely in accept(). */
void
fp_accept_loop(fp_route *route, int lfd)
{
    fp_event_set_route(fp_route_name(route));   /* tag refuse events on this thread */
    while (fp_route_alive(route)) {
        /* accept-pause: delay servicing the accept queue so pending SYNs / the
         * accept backlog pile up (connect-timeout + backlog-overflow testing). */
        if (g_accept_pause_ms > 0) {
            usleep((useconds_t) g_accept_pause_ms * 1000);
        }
        struct pollfd lp = { lfd, POLLIN, 0 };
        int pr = poll(&lp, 1, 200);
        if (pr <= 0) {
            continue;   /* timeout (re-check alive) or EINTR */
        }
        int client = accept(lfd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (fp_accept_admit(client)) {
            fp_spawn_relay(route, client);
        }
    }
}

/* Print the startup banner (target chain + control endpoint). */
void
fp_print_banner(const fp_config *cfg)
{
    printf("brix-fault-proxy: %s:%d -> %s:%d", cfg->bind_str, cfg->listen_port,
           g_targets[0].host, g_targets[0].port);
    for (int i = 1; i < g_ntargets; i++) {
        printf(",%s:%d", g_targets[i].host, g_targets[i].port);
    }
    printf("  (control %s:%d)\n", cfg->bind_str, cfg->control_port);
    fflush(stdout);
}

/* On SIGINT/SIGTERM, restore any host network state the privileged subsystem
 * installed (qdisc / nft table / MTU) before exiting — otherwise a Ctrl-C would
 * leave the NIC impaired. fp_priv_teardown() uses only fork/execvp/waitpid. */
void
fp_on_signal(int sig)
{
    fp_priv_teardown();
    _exit(128 + sig);
}

/* Arm the privileged subsystem if requested, wiring in the teardown hooks. On a
 * hard failure (e.g. --privileged without root) prints the reason and returns
 * FP_USAGE; returns FP_CONTINUE otherwise. */
int
fp_arm_privileged(const fp_config *cfg)
{
    if (!cfg->privileged) {
        if (cfg->priv_iface != NULL) {
            fprintf(stderr, "brix-fault-proxy: --priv-iface requires "
                            "--privileged\n");
            return FP_USAGE;
        }
        return FP_CONTINUE;
    }
    int ports[FP_MAX_TARGETS];
    for (int i = 0; i < g_ntargets; i++) {
        ports[i] = g_targets[i].port;
    }
    const char *err = NULL;
    if (fp_priv_enable(cfg->priv_iface, cfg->listen_port, ports, g_ntargets,
                       &err) != 0) {
        fprintf(stderr, "brix-fault-proxy: --privileged: %s\n", err);
        return FP_USAGE;
    }
    atexit(fp_priv_teardown);
    signal(SIGINT, fp_on_signal);
    signal(SIGTERM, fp_on_signal);
    if (!cfg->quiet) {
        fprintf(stderr, "brix-fault-proxy: privileged levers ARMED (iface=%s) — "
                        "host network state will be restored on exit\n",
                cfg->priv_iface ? cfg->priv_iface : "(none)");
    }
    return FP_CONTINUE;
}

/* Launch the scripted-timeline thread (detached) if --script was given. */
static void
fp_spawn_script(const char *script_path)
{
    if (script_path == NULL) {
        return;
    }
    pthread_t st;
    if (pthread_create(&st, NULL, script_thread, (void *) script_path) == 0) {
        pthread_detach(st);
    }
}

/* Parse `--udp "<listen> <host:port>"` and launch the datagram relay thread
 * (detached).  Best-effort: a malformed spec warns and is ignored (TCP runs). */
static void
fp_spawn_udp(const char *spec)
{
    if (spec == NULL) {
        return;
    }
    fp_udp_cfg *uc = calloc(1, sizeof(*uc));
    char        uhost[256] = "";
    if (uc && sscanf(spec, "%d %255[^:]:%d",
                     &uc->listen_port, uhost, &uc->port) == 3) {
        snprintf(uc->host, sizeof(uc->host), "%s", uhost);
        pthread_t ut;
        if (pthread_create(&ut, NULL, fp_udp_thread, uc) == 0) {
            pthread_detach(ut);
            return;
        }
        free(uc);
        return;
    }
    free(uc);
    fprintf(stderr, "brix-fault-proxy: --udp needs \"<listen> <host:port>\"\n");
}

int
main(int argc, char **argv)
{
    fp_config cfg = { .bind_str = "127.0.0.1" };
    int       rc;

    /* `brix-fault-proxy ctl <host:port> "<cmd>"` is a control-port CLIENT, not a
     * proxy run — dispatch it before any listener/lever setup. */
    if (argc >= 2 && strcmp(argv[1], "ctl") == 0) {
        return fp_ctl_main(argc, argv);
    }

    reset_lever(&g_up);
    reset_lever(&g_down);
    fp_tls_cfg_init(&g_tls_up);        /* sentinels (-1); zero would read as active */
    fp_tls_cfg_init(&g_tls_down);
    clock_gettime(CLOCK_MONOTONIC, &g_t0);   /* replay-timestamp reference */

    if ((rc = fp_parse_args(argc, argv, &cfg)) != FP_CONTINUE) {
        return rc;
    }
    if (cfg.event_log != NULL && fp_event_open(cfg.event_log) != 0) {
        fprintf(stderr,
                "brix-fault-proxy: cannot open event-log '%s' (event log)\n",
                cfg.event_log);
        return FP_RUN;   /* unwritable log path is a runtime failure (exit 1) */
    }
    if ((rc = fp_setup_bind(cfg.bind_str, cfg.insecure, &g_bind_ss, &g_bind_len))
        != FP_CONTINUE) {
        return rc;
    }

    signal(SIGPIPE, SIG_IGN);

    if ((rc = fp_arm_privileged(&cfg)) != FP_CONTINUE) {
        return rc;
    }

    /* Route plane: the startup listener is the always-on "default" route; the
     * core provides binding + the accept/relay engine, so dynamic routes reuse
     * the one vetted bind address. */
    fp_route_ops ops = { fp_core_bind_listen, fp_accept_loop };
    fp_route_init(&ops);
    fp_route *def = fp_route_register_default(cfg.listen_port);
    for (int i = 0; i < g_ntargets; i++) {
        fp_route_add_target(def, g_targets[i].host, g_targets[i].port);
    }

    int lfd   = listen_sa(&g_bind_ss, g_bind_len, cfg.listen_port);
    int ctlfd = listen_sa(&g_bind_ss, g_bind_len, cfg.control_port);
    if (lfd < 0 || ctlfd < 0) {
        fprintf(stderr, "brix-fault-proxy: bind failed (listen=%d control=%d)\n",
                cfg.listen_port, cfg.control_port);
        return FP_RUN;
    }

    pthread_t ct;
    int *cfdp = malloc(sizeof(int));
    *cfdp = ctlfd;
    pthread_create(&ct, NULL, control_thread, cfdp);

    fp_spawn_script(cfg.script_path);
    fp_spawn_udp(cfg.udp_spec);

    if (!cfg.quiet) {
        fp_print_banner(&cfg);
    }

    fp_accept_loop(def, lfd);   /* main thread owns the default route's accept */
    return FP_OK;
}
