/*
 * brix_fault_proxy_internal.h — shared contract for the brix-fault-proxy TUs.
 *
 * WHAT: the fault-lever state, traffic/fault counters, upstream-target pool and
 *       the cross-translation-unit prototypes shared by the three
 *       brix-fault-proxy sources — the CLI/lifecycle core (brix_fault_proxy.c),
 *       the data-plane fault engine (brix_fault_proxy_relay.c) and the
 *       control-plane command parser (brix_fault_proxy_control.c).
 *
 * WHY:  the proxy was one ~970-line file; splitting it by plane (config /
 *       relay / control) keeps each TU single-purpose, but the fault levers and
 *       counters are genuinely process-global mutable state touched by all
 *       three, so they live here behind extern declarations rather than being
 *       duplicated.
 *
 * HOW:  the globals are DEFINED exactly once in brix_fault_proxy.c and
 *       extern-declared here.  Every lever field is volatile because the control
 *       thread mutates it while relay threads read it; the counters use
 *       __atomic_* via the CBUMP macros for lock-free cross-thread accounting.
 */
#ifndef BRIX_FAULT_PROXY_INTERNAL_H
#define BRIX_FAULT_PROXY_INTERNAL_H

#include <pthread.h>    /* pthread_t (fp_route accept thread) */
#include <stddef.h>     /* size_t  */
#include <sys/types.h>  /* ssize_t */

#define FP_MAX_TARGETS 8

/* Per-direction fault levers.  0 = off (reorder_ms defaults to 50). */
typedef struct {
    volatile int latency_ms;
    volatile int jitter_ms;
    volatile int chunk_bytes;
    volatile int drip_bytes;
    volatile int drip_ms;
    volatile int rate_kbps;      /* bandwidth ceiling, KB/s (token-bucket paced) */
    volatile int burst_bytes;    /* token-bucket depth, bytes; 0 => 1 MTU (~1500) */
    volatile int lossy_ppm;      /* per-chunk sever probability, ppm (1% = 10000) */
    volatile int reorder_ppm;    /* per-chunk hold-back probability, ppm */
    volatile int reorder_ms;     /* hold-back delay applied to a reordered chunk */
    volatile int corrupt_ppm;    /* per-byte bit-flip probability, ppm */
    volatile int dup_ppm;        /* per-chunk duplicate-delivery probability, ppm */
    volatile long truncate_at;   /* sever after this many bytes this direction; 0=off */
    volatile int  slow_close_ms; /* delay the FIN/close by N ms (Toxiproxy slow_close) */
    volatile int  lat_dist;      /* jitter shape: 0 uniform (0..jitter_ms), 1 normal   */
    volatile int  lat_sigma_ms;  /* stddev when lat_dist==normal (0 => jitter_ms/4)     */
} lever_t;

extern volatile lever_t g_up;    /* client   -> upstream (request / upload) */
extern volatile lever_t g_down;  /* upstream -> client   (response / download) */

/* Upstream target pool (round-robin with per-connection failover). */
typedef struct { char host[256]; int port; } fp_target;
extern fp_target g_targets[FP_MAX_TARGETS];
extern int       g_ntargets;
extern unsigned  g_rr;

/* Global (connection-scoped) state. */
extern volatile int      g_blocked;         /* refuse new + sever live (outage) */
extern volatile int      g_hang;            /* accept new but never relay (black hole) */
extern volatile int      g_abortive;        /* 1 = auto-severs use RST, 0 = graceful FIN */
extern volatile int      g_one_shot;        /* clear all levers when a sever fires */
extern volatile int      g_fail_nth;        /* fail exactly the Nth accepted conn (0=off) */
extern volatile unsigned g_drop_epoch;      /* bump => live relays sever */
extern volatile unsigned g_halfclose_epoch; /* bump => live relays half-close */
extern unsigned          g_seed;            /* base RNG seed (per-thread derived) */
extern int               g_max_conns;       /* cap on concurrent relays (0=unlimited) */
extern volatile int      g_toxicity_up_ppm;   /* per-conn afflict prob, up dir; ppm (1e6=100%) */
extern volatile int      g_toxicity_down_ppm; /* per-conn afflict prob, down dir; ppm */
extern volatile int      g_connect_delay_ms;  /* delay before dialling upstream (0=off) */
extern volatile int      g_refuse_ppm;        /* prob of refusing a NEW conn; ppm (0=off) */

/* Traffic / fault counters (test oracle). */
typedef struct {
    unsigned long conns, active, up_bytes, down_bytes;
    unsigned long severs, corrupt, dups, refused;
} fp_counters;
extern fp_counters C;
#define CBUMP(f, n) __atomic_add_fetch(&C.f, (n), __ATOMIC_RELAXED)
#define CDEC(f)     __atomic_sub_fetch(&C.f, 1, __ATOMIC_RELAXED)
/* Add one byte-total to a per-connection and the global counter atomically. */
#define CBUMP2(conn_ctr, glob_ctr, n) do {        \
    *(conn_ctr) += (unsigned long) (n);           \
    __atomic_add_fetch((glob_ctr), (unsigned long) (n), __ATOMIC_RELAXED); \
} while (0)

/* A dynamic route (C2): its own listen socket + target pool + counters, so one
 * daemon can host many named proxies created and destroyed at runtime.  The
 * legacy --listen/--target path is registered as route "default".  Fault levers
 * and the toxic table remain process-global (shared by every route) in this
 * revision; only targets, counters and lifecycle are per-route. */
#define FP_MAX_ROUTES 16
typedef struct {
    char         name[32];
    int          listen_fd;
    int          listen_port;
    fp_target    targets[FP_MAX_TARGETS];
    int          ntargets;
    unsigned     rr;            /* per-route round-robin cursor */
    fp_counters  counters;      /* independent per-route counters (conns/bytes) */
    pthread_t    tid;           /* accept thread (unused for the default route) */
    volatile int stop;          /* set by `route del` to unwind the accept loop */
    int          is_default;    /* 1 => the legacy path; never deletable */
    int          active;        /* 0 => free / retired slot */
} fp_route;
extern fp_route g_routes[FP_MAX_ROUTES];
extern int      g_nroutes;      /* high-water slot count (never shrinks) */

/* Per-connection relay-thread argument (client fd + drop-epoch snapshot). */
typedef struct {
    int      client_fd;
    unsigned epoch;
    unsigned long conn_id;
    fp_route *route;    /* owning route: targets + counters (never NULL at runtime) */
} relay_arg;

/* Data plane (brix_fault_proxy_relay.c). */
int   write_all(int fd, const char *buf, ssize_t n);
void *relay_thread(void *arg);

/* Control plane (brix_fault_proxy_control.c). */
void  reset_lever(volatile lever_t *L);
void  clear_all(void);
void  apply_command(char *line, char *reply, size_t rsz);
void *control_thread(void *arg);
void *script_thread(void *arg);
int   dir_of(char *args);   /* strip trailing up|down|both: 0 both, 1 up, 2 down */

/* Named, stackable toxics (C1, brix_fault_proxy_toxic.c).  The flat g_up/g_down
 * levers remain the implicit default toxic; these layer named faults on top. */
#define FP_MAX_TOXICS 16
typedef struct {
    char    name[32];   /* operator handle used by remove/list                  */
    int     type;       /* fp_toxic_type — private to brix_fault_proxy_toxic.c  */
    int     dir;        /* dir_of convention: 0 both, 1 up, 2 down              */
    lever_t vals;       /* the single lever field this toxic contributes        */
    int     active;
} fp_toxic;
extern fp_toxic g_toxics[FP_MAX_TOXICS];
extern int      g_ntoxics;      /* count of live toxics; 0 => relay fast path   */

void  fp_toxic_cmd(char *args, char *reply, size_t rsz);  /* add | remove | list */
void  fp_toxic_clear(void);                               /* drop all (on clear) */
void  fp_toxic_compose(lever_t *eff, int dir_i);          /* fold toxics for dir  */

/* Dynamic routes (brix_fault_proxy_route.c). */
void  fp_route_cmd(char *args, char *reply, size_t rsz);  /* add | del | list [json] */
int   fp_route_register_default(int lfd, int port);       /* seed g_routes[0] */

/* Accept plane (brix_fault_proxy.c): serve one listen fd on behalf of `route`. */
int   fp_accept_serve(int lfd, fp_route *route);
int   fp_route_bind(int port);   /* bind a new listen port on the vetted address */

/* JSON front-end (brix_fault_proxy_json.c). */
int   brix_fp_json_request(const char *line, char *out, size_t osz); /* 1 = handled JSON */
void  brix_fp_json_status(char *out, size_t osz);

/* `ctl` client subcommand (brix_fault_proxy_ctl.c). */
int   fp_ctl_main(int argc, char **argv);

/* JSONL fault-event log (brix_fault_proxy_event.c). */
int   fp_event_open(const char *path);   /* 0 = ok, -1 = open failed (fail closed) */
int   fp_event_enabled(void);
void  brix_fp_event(unsigned long conn, const char *dir, const char *event,
                    const char *reason, const char *numkey, long numval);

#endif /* BRIX_FAULT_PROXY_INTERNAL_H */
