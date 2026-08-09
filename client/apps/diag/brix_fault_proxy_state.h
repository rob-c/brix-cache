/*
 * brix_fault_proxy_state.h — the brix-fault-proxy program's shared lever state.
 *
 * WHAT: The fault levers, connection-scoped switches, attack-mock config, and
 *       traffic counters that every TU of the brix-fault-proxy binary reads or
 *       writes, plus the prototypes of the functions those TUs hand to each
 *       other (relay data path, control-command parsers, CLI parsing).
 *
 * WHY:  brix_fault_proxy.c crossed the 600-line cap by a wide margin
 *       (coding-standards §1) and was split into per-stage TUs. The state it
 *       carried was already program-global — one process-wide set of levers is
 *       the whole point of a live-controllable fault proxy — so nothing new is
 *       introduced here: the same objects simply became visible to the TUs that
 *       were carved out of the same file. `brix_fault_proxy.c` remains their
 *       single definition site.
 *
 * HOW:  Include after the module headers (brix_fault_lever.h et al). Levers are
 *       `volatile` and read lock-free from relay threads; anything wider than a
 *       word (mutation buffers, triggers, TLS/HTTP config) is mutated under
 *       g_ext_lock and snapshotted into the hot path. Counters are bumped with
 *       the CBUMP macros (relaxed atomics), never assigned directly.
 */

#ifndef BRIX_FAULT_PROXY_STATE_H
#define BRIX_FAULT_PROXY_STATE_H

#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>

#include "brix_fault_ext.h"
#include "brix_fault_http.h"
#include "brix_fault_lever.h"
#include "brix_fault_replay.h"
#include "brix_fault_route.h"
#include "brix_fault_tls.h"

#define FP_OK    0   /* clean terminal action (--help / --version) or success */
#define FP_RUN   1   /* runtime failure (bind failed) */
#define FP_USAGE 2   /* command-line error */
#define FP_CONTINUE (-1) /* internal: argument parsing/setup ok, keep going */

#define FP_MAX_TARGETS 8

/* Mutation output buffer: 2x 64 KiB read + inject room. */
#define FP_SCRATCH 140000

/* One upstream in the round-robin target pool. */
typedef struct { char host[256]; int port; } fp_target;

/* Traffic / fault counters (test oracle). */
typedef struct {
    unsigned long conns, active, up_bytes, down_bytes;
    unsigned long severs, corrupt, dups, refused;
    unsigned long dropped, repeated, injected, replaced;
    unsigned long triggered, mangled, fanout_conns;
    unsigned long tls_rewrites, http_rewrites, recorded, replayed;
    unsigned long held;   /* segments stalled by the DPI header-size hold */
    /* Phase-99 DPI/middlebox pathology levers. */
    unsigned long reaped;        /* connections frozen/killed by idle-reap */
    unsigned long ate_100;       /* 100-continue interim responses swallowed */
    unsigned long fin_dropped;   /* EOFs not propagated (asymmetric teardown) */
    unsigned long throttled;     /* segments paced by classify-throttle slow-lane */
    unsigned long hello_reset;   /* oversized TLS ClientHellos reset */
    unsigned long classify_kills;/* connections killed by rst-after/max-bytes */
    unsigned long syn_dropped;   /* accepted clients silently dropped (syn-drop) */
    unsigned long udp_in, udp_out, udp_dropped, udp_reaped, udp_held;
} fp_counters;

/* Payload-mutation config per direction (guarded by g_ext_lock). */
struct fp_mutbuf {
    unsigned char find[128];   int find_len;
    unsigned char repl[256];   int repl_len;
    unsigned char inject[512]; int inject_len;   /* one-shot: consumed on next fwd */
};

/* Content trigger: when `pat` appears in a direction's stream, run `cmd` through
 * the control parser. `once` fires a single time. (guarded by g_ext_lock) */
struct fp_trigger {
    unsigned char pat[128]; int pat_len;
    char          cmd[256];
    int           once;
    volatile int  fired;
};

/* Numeric length-prefix lie: rewrite the big-endian uint32 at absolute stream
 * `offset` (op: 0=set 1=add 2=sub). */
struct fp_mangle {
    volatile long offset; volatile int op; volatile long val; volatile int active;
};

/* One linear lever sweep, handed to a ramp thread by the attack commands. */
struct ramp_arg { unsigned gen; char lever[24]; double start, end; int ms; };

/* One accepted client, handed to a relay thread. */
typedef struct {
    int       client_fd;
    unsigned  epoch;
    unsigned long conn_id;
    fp_route *route;         /* which route accepted this client (never NULL) */
} relay_arg;

/* Parsed command-line configuration for the proxy run. Lever options
 * (--latency, --block, …) are not carried here: they mutate the global
 * fault levers via apply_command() as they are parsed. */
typedef struct {
    int         listen_port;
    int         control_port;
    const char *bind_str;
    const char *script_path;
    const char *priv_iface;   /* --priv-iface: NIC for root-ful netem/mtu levers */
    const char *event_log;    /* --event-log: JSONL fault-event trail (NULL=off) */
    const char *udp_spec;     /* --udp "<listen> <host:port>": enable UDP relay */
    int         privileged;   /* --privileged: arm the root-gated subsystem */
    int         insecure;
    int         quiet;
} fp_config;

/* ---- shared state (defined in brix_fault_proxy.c) ------------------------ */

/* Per-direction fault levers (`lever_t`, shared with the named-toxic module). */
extern volatile lever_t g_up;    /* client   -> upstream (request / upload) */
extern volatile lever_t g_down;  /* upstream -> client   (response / download) */

/* Upstream target pool (round-robin with per-connection failover). */
extern fp_target g_targets[FP_MAX_TARGETS];
extern int       g_ntargets;

/* The one vetted (loopback-gated) bind template, captured after fp_setup_bind so
 * dynamic routes reuse it verbatim — only the port differs, never the address. */
extern struct sockaddr_storage g_bind_ss;
extern socklen_t               g_bind_len;

/* Global (connection-scoped) state. */
extern volatile int      g_blocked;
extern volatile int      g_hang;
extern volatile int      g_abortive;
extern volatile int      g_one_shot;
extern volatile int      g_fail_nth;
extern volatile unsigned g_drop_epoch;
extern volatile unsigned g_halfclose_epoch;
extern unsigned          g_seed;
extern int               g_max_conns;

/* Extended (still root-free) connection-level levers. */
extern volatile int      g_stall_up;
extern volatile int      g_stall_down;
/* Phase-B connection-scoped fidelity levers (root-free; reset by clear_all). */
extern volatile int      g_toxicity_up_ppm;   /* fraction of conns the up levers afflict, ppm (default 1e6=100%) */
extern volatile int      g_toxicity_down_ppm; /* same, down direction */
extern volatile int      g_connect_delay_ms;  /* usleep after accept, before dial */
extern volatile int      g_refuse_ppm;        /* probabilistic new-connection refusal, ppm */
extern volatile int      g_mss;
extern volatile int      g_rcvbuf;
extern volatile int      g_sndbuf;
extern volatile long     g_max_life_ms;
extern volatile unsigned g_chaos_gen;
extern volatile int      g_chaos_ms;
extern volatile int      g_chaos_on;

/* Phase-99 DPI/middlebox pathology levers (root-free; reset by clear_all). */
extern volatile int      g_idle_reap_ms;      /* freeze/kill a connection idle >= ms */
extern volatile int      g_idle_reap_rst;     /* 1=forged RST, 0=silent black-hole */
extern volatile int      g_eat_100;           /* swallow 100-continue on the down path */
extern volatile long     g_rst_after_bytes;   /* kill after this many bytes (both dirs) */
extern volatile long     g_rst_after_ms;      /* kill after this many ms (classify-and-kill) */
extern volatile int      g_rst_after_abortive;/* teardown for rst-after: 1=RST 0=FIN */
extern volatile int      g_drop_fin_up;       /* swallow the client->upstream EOF */
extern volatile int      g_drop_fin_down;     /* swallow the upstream->client EOF */
extern volatile long     g_classify_bytes;    /* slow-lane after this many bytes; 0=off */
extern volatile int      g_classify_kbps;     /* slow-lane rate ceiling */
extern volatile int      g_syn_drop_ppm;      /* silently drop accepted clients, ppm */
extern volatile int      g_hello_reset_thresh;/* reset a TLS ClientHello >= this many bytes */

/* Phase-99 Wave C — UDP relay levers (root-free; the "UDP vs TCP" class). */
extern volatile int      g_udp_drop_ppm;      /* drop datagrams, ppm */
extern volatile int      g_udp_hold_ms;       /* hold a flow's FIRST datagram by ms */
extern volatile int      g_udp_reap_ms;       /* reap a UDP flow idle >= ms; 0=off */
extern volatile int      g_udp_reorder_ppm;   /* per-datagram hold-back probability */
extern volatile int      g_udp_reorder_ms;    /* hold-back applied to a reordered dgram */

/* PROXY-protocol forgery (spoof a client source IP to the upstream). */
extern volatile int      g_proxy_mode;
extern char              g_proxy_src[128];
extern char              g_proxy_dst[128];

extern struct fp_mutbuf  g_up_mut, g_down_mut;
extern pthread_mutex_t   g_ext_lock;

extern struct fp_trigger g_trig_up, g_trig_down;
extern struct fp_mangle  g_mangle_up, g_mangle_down;

extern volatile int      g_accept_pause_ms;
extern volatile int      g_fanout;
extern volatile int      g_global_rate_kbps;
extern volatile unsigned g_flap_gen;
extern volatile int      g_flap_on;
extern volatile int      g_flap_up_ms;
extern volatile int      g_flap_down_ms;
extern volatile unsigned g_ramp_gen;

/* Shared (aggregate) token bucket for g_global_rate_kbps. */
extern double            g_gr_tokens;
extern struct timespec   g_gr_last;
extern int               g_gr_init;
extern pthread_mutex_t   g_gr_lock;

/* Per-direction TLS record-layer and HTTP-smuggling surgery config, mutated
 * under g_ext_lock and snapshotted into the relay hot path. */
extern fp_tls_cfg  g_tls_up,  g_tls_down;
extern fp_http_cfg g_http_up, g_http_down;

/* Replay playback: when active, accepted clients are fed a recorded byte
 * timeline instead of a live upstream. */
extern volatile int      g_replay_active;
extern volatile int      g_replay_updir;
extern fp_replay_store   g_replay_store;

/* Background oracle-driven jobs publish their outcome here. */
extern char              g_bisect_result[192];
extern char              g_recovery_result[192];
extern pthread_mutex_t   g_res_lock;
extern volatile int      g_oracle_busy;

/* Monotonic proxy-start reference for replay timestamps. */
extern struct timespec   g_t0;

extern fp_counters C;

#define CBUMP(f, n) __atomic_add_fetch(&C.f, (n), __ATOMIC_RELAXED)
#define CDEC(f)     __atomic_sub_fetch(&C.f, 1, __ATOMIC_RELAXED)
/* Add one byte-total to a per-connection and the global counter atomically. */
#define CBUMP2(conn_ctr, glob_ctr, n) do {        \
    *(conn_ctr) += (unsigned long) (n);           \
    __atomic_add_fetch((glob_ctr), (unsigned long) (n), __ATOMIC_RELAXED); \
} while (0)

/* Per-relay-thread connection id, so the deep fault path (fault_sever) can
 * attribute a JSONL event to its connection without threading an extra argument
 * through the hot relay signatures.  0 outside a relay thread. */
extern __thread unsigned long t_conn_id;

/* Per-connection toxicity gate: decided once at relay start from the per-direction
 * toxicity fraction.  When a direction is not afflicted its byte levers are
 * skipped (clean pass-through).  1 outside a relay thread (fully afflicted). */
extern __thread int t_afflict_up;
extern __thread int t_afflict_down;
extern __thread int t_fwd_up;

/* ---- cross-TU seams (definition sites named in each TU's banner) -------- */

void
usage(FILE *out);
int
dial(const char *host, int port);
int
write_all(int fd, const char *buf, ssize_t n);
void
sever(int cfd, int ufd, int abortive);
int
fault_sever(const char *reason);
ssize_t
fault_clamp_seg(ssize_t seg, int piece, long trunc, unsigned long conn_ctr);
void
fault_delays(ssize_t seg, unsigned *seed, const lever_t *L, unsigned long sent);
void
fault_corrupt(char *buf, ssize_t off, ssize_t seg, unsigned *seed, int cor);
void
global_rate_gate(ssize_t seg);
int
forward_segment(int to, char *buf, ssize_t off, ssize_t n, unsigned epoch,
                const lever_t *L, unsigned *seed, unsigned long *conn_ctr,
                unsigned long *glob_ctr, int piece, ssize_t *wrote);
int
forward_faulted(int to, char *buf, ssize_t n, unsigned epoch, volatile lever_t *L,
                unsigned *seed, unsigned long *conn_ctr, unsigned long *glob_ctr);
int
dial_route(fp_route *route);
int
relay_predial(int cfd, unsigned epoch, unsigned long conn_id);
int
ext_snapshot(int is_up, volatile lever_t *L, fp_ext_mut *mut,
             unsigned char *fbuf, unsigned char *rbuf, unsigned char *ibuf);
void
trig_check(int is_up, const char *buf, ssize_t nr);
void
mangle_apply(int is_up, char *buf, ssize_t nr, unsigned long base);
unsigned long long
now_ms_since(struct timespec t0);
size_t
apply_tls(int is_up, const char *in, ssize_t n, unsigned char *out);
size_t
apply_http(int is_up, const char *in, ssize_t n, unsigned char *out, int *applied);
int
relay_pump_dir(int i, struct pollfd *pfd, int cfd, int ufd,
               char *buf, size_t bufsz, unsigned char *scratch,
               unsigned char *scratch2, unsigned epoch,
               unsigned *seed, unsigned long *up_ctr, unsigned long *down_ctr,
               int *firstflag);
void
relay_pump(int cfd, int ufd, unsigned epoch, unsigned seed,
           unsigned long *up_ctr, unsigned long *down_ctr);
void
sa_to_hostport(const struct sockaddr *sa, socklen_t sl, char *out, size_t cap);
void
apply_conn_tuning(int cfd, int ufd);
void
send_proxy_header(int ufd, int cfd);
void
replay_to_client(int cfd, unsigned epoch);
void *
relay_thread(void *arg);
int
dir_of(char *args);
void
reset_lever(volatile lever_t *L);
void
clear_all(void);
void *
heal_thread(void *arg);
int
cmd_set_lever(const char *verb, char *args);
int
cmd_set_epoch(const char *verb);
int
cmd_set_misc(const char *verb, const char *args);
int
cmd_set_fidelity(const char *verb, char *args, char *reply, size_t rsz);
void
cmd_metrics_report(char *reply, size_t rsz);
void *
chaos_thread(void *arg);
int
ext_set_replace(int d, char *findtok, char *repltok, char *reply, size_t rsz);
int
ext_set_inject(int d, char *tok, char *reply, size_t rsz);
int
ext_set_proxy(char *args, char *reply, size_t rsz);
int
cmd_set_ext(const char *verb, char *args, char *reply, size_t rsz);
void *
flap_thread(void *arg);
void *
ramp_thread(void *arg);
int
cmd_preset(char *args, char *reply, size_t rsz);
int
cmd_trigger(int once, char *args, char *reply, size_t rsz);
int
cmd_mangle(char *args, char *reply, size_t rsz);
int
cmd_set_attack(const char *verb, char *args, char *reply, size_t rsz);
int
cmd_set_dpi(const char *verb, char *args, char *reply, size_t rsz);
int
cmd_set_udp(const char *verb, char *args, char *reply, size_t rsz);
/* UDP relay listener config (parsed from --udp); host/port name the upstream. */
typedef struct { int listen_port; char host[256]; int port; } fp_udp_cfg;
void *
fp_udp_thread(void *arg);   /* arg: fp_udp_cfg* (owned, freed on exit) */
int
cmd_set_tls(char *args, char *reply, size_t rsz);
int
cmd_set_http(char *args, char *reply, size_t rsz);
int
cmd_set_replay(const char *verb, char *args, char *reply, size_t rsz);
void
res_set(char *slot, const char *fmt, ...);
void *
bisect_thread(void *arg);
void *
recovery_thread(void *arg);
int
cmd_set_oracle(const char *verb, char *args, char *reply, size_t rsz);
int
cmd_set_proto(const char *verb, char *args, char *reply, size_t rsz);
void
cmd_status_report(char *reply, size_t rsz);
void
cmd_status_json(char *reply, size_t rsz);
void
apply_command(char *line, char *reply, size_t rsz);
void
apply_json_command(const char *json, char *reply, size_t rsz);
void *
control_thread(void *arg);
void *
script_thread(void *arg);
int
add_target(const char *spec);
int
sa_is_loopback(const struct sockaddr *sa);
int
listen_sa(const struct sockaddr_storage *tmpl, socklen_t slen, int port);
int
fp_apply_lever_opt(int opt, const char *optarg);
int
fp_apply_core_opt(int opt, fp_config *cfg);
int
fp_finalize_config(int argc, char **argv, fp_config *cfg);
int
fp_parse_args(int argc, char **argv, fp_config *cfg);
int
fp_setup_bind(const char *bind_str, int insecure,
    struct sockaddr_storage *bind_ss, socklen_t *bind_len);
int
fp_core_bind_listen(int port);
void
fp_accept_loop(fp_route *route, int lfd);
void
fp_print_banner(const fp_config *cfg);
void
fp_on_signal(int sig);
int
fp_arm_privileged(const fp_config *cfg);

#endif /* BRIX_FAULT_PROXY_STATE_H */
