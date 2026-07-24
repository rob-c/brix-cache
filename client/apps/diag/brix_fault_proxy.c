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

#define FP_OK    0   /* clean terminal action (--help / --version) or success */
#define FP_RUN   1   /* runtime failure (bind failed) */
#define FP_USAGE 2   /* command-line error */
#define FP_CONTINUE (-1) /* internal: argument parsing/setup ok, keep going */

#define FP_MAX_TARGETS 8

/* Per-direction fault levers.  0 = off (reorder_ms defaults to 50). */
typedef struct {
    volatile int latency_ms;
    volatile int jitter_ms;
    volatile int chunk_bytes;
    volatile int drip_bytes;
    volatile int drip_ms;
    volatile int rate_kbps;      /* bandwidth ceiling, KB/s (paced) */
    volatile int lossy_ppm;      /* per-chunk sever probability, ppm (1% = 10000) */
    volatile int reorder_ppm;    /* per-chunk hold-back probability, ppm */
    volatile int reorder_ms;     /* hold-back delay applied to a reordered chunk */
    volatile int corrupt_ppm;    /* per-byte bit-flip probability, ppm */
    volatile int dup_ppm;        /* per-chunk duplicate-delivery probability, ppm */
    volatile int drop_ppm;       /* per-byte DELETE probability, ppm (framing desync) */
    volatile int repeat_ppm;     /* per-byte duplicate probability, ppm (length inflate) */
    volatile int delayfirst_ms;  /* delay ONLY the first forwarded chunk this direction */
    volatile long truncate_at;   /* sever after this many bytes this direction; 0=off */
} lever_t;

static volatile lever_t g_up;    /* client   -> upstream (request / upload) */
static volatile lever_t g_down;  /* upstream -> client   (response / download) */

/* Upstream target pool (round-robin with per-connection failover). */
static struct { char host[256]; int port; } g_targets[FP_MAX_TARGETS];
static int      g_ntargets = 0;
static unsigned g_rr       = 0;

/* Global (connection-scoped) state. */
static volatile int      g_blocked  = 0;   /* refuse new + sever live (outage) */
static volatile int      g_hang     = 0;   /* accept new but never relay (black hole) */
static volatile int      g_abortive = 0;   /* 1 = auto-severs use RST, 0 = graceful FIN */
static volatile int      g_one_shot = 0;   /* clear all levers when a sever fires */
static volatile int      g_fail_nth = 0;   /* fail exactly the Nth accepted conn (0=off) */
static volatile unsigned g_drop_epoch      = 0;  /* bump => live relays sever */
static volatile unsigned g_halfclose_epoch = 0;  /* bump => live relays half-close */
static unsigned          g_seed     = 0;   /* base RNG seed (per-thread derived) */
static int               g_max_conns = 0;  /* cap on concurrent relays (0=unlimited) */

/* Extended (still root-free) connection-level levers. */
static volatile int      g_stall_up   = 0; /* stop reading client   (backpressure) */
static volatile int      g_stall_down = 0; /* stop reading upstream (backpressure) */
static volatile int      g_mss        = 0; /* clamp TCP_MAXSEG on both ends (0=off) */
static volatile int      g_rcvbuf     = 0; /* SO_RCVBUF squeeze (tiny window) (0=off) */
static volatile int      g_sndbuf     = 0; /* SO_SNDBUF squeeze (0=off) */
static volatile long     g_max_life_ms = 0;/* sever every conn after this long (0=off) */
static volatile unsigned g_chaos_gen  = 0; /* bump => running chaos thread should stop */
static volatile int      g_chaos_ms   = 0; /* chaos tick interval, ms */
static volatile int      g_chaos_on   = 0; /* 1 while a chaos thread is running */

/* PROXY-protocol forgery (spoof a client source IP to the upstream). */
static volatile int      g_proxy_mode = 0; /* 0 off, 1 = v1 text, 2 = v2 binary */
static char              g_proxy_src[128]; /* forged "ip:port" */
static char              g_proxy_dst[128]; /* forged dst "ip:port" ("" = derive) */

/* Payload-mutation config per direction (guarded by g_ext_lock). */
static struct fp_mutbuf {
    unsigned char find[128];   int find_len;
    unsigned char repl[256];   int repl_len;
    unsigned char inject[512]; int inject_len;   /* one-shot: consumed on next fwd */
} g_up_mut, g_down_mut;
static pthread_mutex_t    g_ext_lock = PTHREAD_MUTEX_INITIALIZER;

/* --- Attack-mocking levers (topple-a-server toolkit) --- */

/* Content trigger: when `pat` appears in a direction's stream, run `cmd` through
 * the control parser. `once` fires a single time. (guarded by g_ext_lock) */
static struct fp_trigger {
    unsigned char pat[128]; int pat_len;
    char          cmd[256];
    int           once;
    volatile int  fired;
} g_trig_up, g_trig_down;

/* Numeric length-prefix lie: rewrite the big-endian uint32 at absolute stream
 * `offset` (op: 0=set 1=add 2=sub). */
static struct fp_mangle {
    volatile long offset; volatile int op; volatile long val; volatile int active;
} g_mangle_up, g_mangle_down;

static volatile int      g_accept_pause_ms = 0;  /* slow accept() → SYN/accept-queue pressure */
static volatile int      g_fanout          = 0;  /* extra upstream conns per client (pool drain) */
static volatile int      g_global_rate_kbps = 0; /* shared uplink ceiling across ALL relays */
static volatile unsigned g_flap_gen        = 0;  /* bump => flap thread stops */
static volatile int      g_flap_on         = 0;
static volatile int      g_flap_up_ms      = 0;
static volatile int      g_flap_down_ms    = 0;
static volatile unsigned g_ramp_gen        = 0;  /* bump => running ramps stop */

/* Shared (aggregate) token bucket for g_global_rate_kbps. */
static double            g_gr_tokens = 0.0;
static struct timespec   g_gr_last;
static int               g_gr_init  = 0;
static pthread_mutex_t   g_gr_lock  = PTHREAD_MUTEX_INITIALIZER;

/* --- Protocol-record surgery + session record/replay + oracle levers --- */

/* Per-direction TLS record-layer and HTTP-smuggling surgery config, mutated
 * under g_ext_lock and snapshotted into the relay hot path. */
static fp_tls_cfg  g_tls_up,  g_tls_down;
static fp_http_cfg g_http_up, g_http_down;

/* Replay playback: when active, accepted clients are fed a recorded byte
 * timeline instead of a live upstream.  The store is loaded (and only freed)
 * while inactive, so the playback path reads it lock-free. */
static volatile int      g_replay_active = 0;
static volatile int      g_replay_updir  = 0;   /* 0: replay 'down' recs to client */
static fp_replay_store   g_replay_store;

/* Background oracle-driven jobs (bisection / recovery) publish their outcome
 * here for `status` and the *-result commands. */
static char              g_bisect_result[192]   = "idle";
static char              g_recovery_result[192] = "idle";
static pthread_mutex_t   g_res_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int      g_oracle_busy = 0;     /* one job at a time */

/* Monotonic proxy-start reference for replay timestamps. */
static struct timespec   g_t0;

/* Traffic / fault counters (test oracle). */
static struct {
    unsigned long conns, active, up_bytes, down_bytes;
    unsigned long severs, corrupt, dups, refused;
    unsigned long dropped, repeated, injected, replaced;
    unsigned long triggered, mangled, fanout_conns;
    unsigned long tls_rewrites, http_rewrites, recorded, replayed;
} C;
#define CBUMP(f, n) __atomic_add_fetch(&C.f, (n), __ATOMIC_RELAXED)
#define CDEC(f)     __atomic_sub_fetch(&C.f, 1, __ATOMIC_RELAXED)
/* Add one byte-total to a per-connection and the global counter atomically. */
#define CBUMP2(conn_ctr, glob_ctr, n) do {        \
    *(conn_ctr) += (unsigned long) (n);           \
    __atomic_add_fetch((glob_ctr), (unsigned long) (n), __ATOMIC_RELAXED); \
} while (0)

static void reset_lever(volatile lever_t *L);
static void clear_all(void);
static void apply_command(char *line, char *reply, size_t rsz);

static void
usage(FILE *out)
{
    fprintf(out,
"usage: brix-fault-proxy --listen PORT --target HOST:PORT [--target ...] --control PORT [options]\n"
"       brix-fault-proxy LISTEN_PORT TARGET_HOST TARGET_PORT CONTROL_PORT   (positional)\n"
"\n"
"Relay TCP from a local listen port to an upstream, injecting network faults\n"
"on demand — from the command line at startup or live over the control port.\n"
"Byte-level levers are per-direction: 'up' = client->upstream, 'down' = the\n"
"reverse; a control command with no direction token applies to both.\n"
"\n"
"Endpoints:\n"
"  -l, --listen PORT        local port to accept client connections on\n"
"  -t, --target HOST:PORT   upstream to relay to (repeatable / comma-list for\n"
"                           round-robin + per-connection failover)\n"
"  -c, --control PORT       control port for live fault commands\n"
"  -b, --bind ADDR          address to bind listen+control to (default loopback;\n"
"                           IPv4 or IPv6 literal)\n"
"      --insecure-bind      permit a non-loopback --bind (exposes the control port)\n"
"      --max-conns N        cap concurrent relayed connections (0 = unlimited)\n"
"      --seed N             seed the fault RNG for reproducible runs\n"
"      --script FILE        replay a timeline of '<seconds> <command>' lines\n"
"  -q, --quiet              suppress the startup banner\n"
"\n"
"Initial fault levers (also settable live; append up|down to target one way):\n"
"      --latency MS         delay every forwarded chunk by MS milliseconds\n"
"      --jitter MS          delay every chunk by a random 0..MS ms\n"
"      --chunk BYTES        split forwarded writes into <=BYTES segments\n"
"      --drip 'BYTES MS'    forward BYTES, sleep MS, repeat (slow stream)\n"
"      --rate KBPS          pace the stream to KBPS kilobytes/second\n"
"      --lossy PCT          sever the stream with probability PCT%% per chunk\n"
"      --reorder 'PCT [MS]' hold back PCT%% of chunks by MS ms (default 50)\n"
"      --corrupt PCT        flip a bit in PCT%% of forwarded bytes (MITM tamper)\n"
"      --dup PCT            deliver PCT%% of chunks twice\n"
"      --truncate-at BYTES  sever each connection after BYTES have flowed\n"
"      --fail-nth N         fail exactly the Nth accepted connection\n"
"      --heal-after MS      auto-clear all levers after MS milliseconds\n"
"      --hang               start as a black hole (accept but never relay)\n"
"      --block              start blocked (refuse connections — an outage)\n"
"\n"
"Extended MITM / DoS levers (still root-free; also live over the control port):\n"
"      --drop-bytes PCT     delete PCT%% of forwarded bytes (framing desync)\n"
"      --repeat-bytes PCT   duplicate PCT%% of forwarded bytes (length inflate)\n"
"      --delay-first MS      delay only the first chunk of each direction\n"
"      --replace 'F R'      rewrite bytes F->R on the wire (hex:.. or str:..)\n"
"      --inject PAYLOAD     splice PAYLOAD into the next chunk (hex:.. / str:..)\n"
"      --mss BYTES          clamp TCP MSS (many tiny segments)\n"
"      --rcvbuf BYTES       squeeze SO_RCVBUF (tiny receive window)\n"
"      --sndbuf BYTES       squeeze SO_SNDBUF\n"
"      --stall up|down      stop reading a direction (TCP backpressure)\n"
"      --max-lifetime MS    guillotine every connection after MS ms\n"
"      --proxy-header 'v1 SRC [DST]'  prepend a forged PROXY-protocol header\n"
"      --chaos MS           autonomous random-fault monkey every MS ms\n"
"    attack-mocking levers (topple a target service):\n"
"      --preset NAME        apply a named realism/attack profile (NAME=list)\n"
"      --trigger 'D PAT CMD'  fire control CMD when PAT appears in dir D\n"
"      --trigger-once 'D PAT CMD'  same, but only the first match\n"
"      --mangle-len 'D OFF OP V'   forge a length field (set|add|sub V at OFF)\n"
"      --accept-pause MS    stall each accept() by MS (accept-queue pressure)\n"
"      --fanout N           open N extra upstream conns per client (amplify)\n"
"      --global-rate KBPS   shared bandwidth cap across ALL connections\n"
"      --flap 'UP DOWN'     cycle in/out of service (block DOWNms / serve UPms)\n"
"      --ramp 'LEVER A B MS'  sweep LEVER from A to B over MS ms\n"
"\n"
"  -h, --help               print this help and exit\n"
"  -V, --version            print version and exit\n"
"\n"
"control commands (write one per connection to the control port):\n"
"  latency <ms> | jitter <ms> | chunk <bytes> | drip <bytes> <ms> | rate <kbps>\n"
"  lossy <pct> | reorder <pct> [ms] | corrupt <pct> | dup <pct> | truncate-at <bytes>\n"
"  fail-nth <n> | heal-after <ms> | one-shot | abortive <0|1>\n"
"  drop | reset | half-close | hang | unhang | block | unblock | clear | status\n"
"  drop-bytes <pct> | repeat-bytes <pct> | delay-first <ms> | replace <f> <r>\n"
"  inject <payload> | mss <b> | rcvbuf <b> | sndbuf <b> | stall <dir> | unstall <dir>\n"
"  max-lifetime <ms> | proxy-header <v1|v2> <src> [dst] | chaos <ms>|off\n"
"  preset <name>|list | trigger[-once] <dir> <pat> <cmd>|off | mangle-len <dir> <off> <op> <v>\n"
"  accept-pause <ms> | fanout <n> | global-rate <kbps> | flap <up> <down>|off | ramp <lever> <a> <b> <ms>\n"
"    (append up|down|both to any byte-level lever to target one direction)\n"
"\n"
"Example:\n"
"  brix-fault-proxy --listen 11940 --target cache.example:1094 --control 11941\n"
"  printf 'corrupt 0.01 down\\n' | nc -q1 127.0.0.1 11941  # tamper the download\n"
"  printf 'truncate-at 5242880 down\\n' | nc -q1 127.0.0.1 11941  # cut at 5 MiB\n"
"\n"
"The control port is UNAUTHENTICATED and binds to loopback by default; do not\n"
"expose it to an untrusted network.  See man brix-fault-proxy(1).\n");
    fp_priv_usage(out);
}

/* Blocking connect to host:port (best-effort, first address that works). */
static int
dial(const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *ai;
    char            portstr[16];
    int             fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return -1;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Dial the next target in round-robin order, failing over to the rest. */
static int
dial_any(void)
{
    int n = g_ntargets;
    unsigned start = __atomic_fetch_add(&g_rr, 1, __ATOMIC_RELAXED);
    for (int i = 0; i < n; i++) {
        int idx = (int) ((start + (unsigned) i) % (unsigned) n);
        int fd = dial(g_targets[idx].host, g_targets[idx].port);
        if (fd >= 0) {
            return fd;
        }
    }
    return -1;
}

static int
write_all(int fd, const char *buf, ssize_t n)
{
    ssize_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, (size_t) (n - off));
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += w;
    }
    return 0;
}

/* Sever both ends of a relay; abortive (RST via SO_LINGER 0) when requested. */
static void
sever(int cfd, int ufd, int abortive)
{
    if (abortive) {
        struct linger lg = { 1, 0 };
        setsockopt(cfd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        if (ufd >= 0) {
            setsockopt(ufd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        }
    }
    close(cfd);
    if (ufd >= 0) {
        close(ufd);
    }
}

/* Count a severed stream and honour one-shot (clear all levers after firing).
 * Returns -1 so a caller can `return fault_sever();`. */
static int
fault_sever(void)
{
    CBUMP(severs, 1);
    if (g_one_shot) {
        clear_all();
    }
    return -1;
}

/* Clamp the outgoing segment to the chunk `piece` and, if truncation is armed,
 * to the exact remaining distance to the cut. Returns the clamped length, or -1
 * when the truncation point is already reached (caller must sever). */
static ssize_t
fault_clamp_seg(ssize_t seg, int piece, long trunc, unsigned long conn_ctr)
{
    if (seg > piece) {
        seg = piece;
    }
    /* Cap at the truncation boundary so the cut is exact rather than firing
     * only after the whole (possibly 64 KiB) read is delivered. */
    if (trunc > 0) {
        long remaining = trunc - (long) conn_ctr;
        if (remaining <= 0) {
            return -1;
        }
        if (seg > remaining) {
            seg = remaining;
        }
    }
    return seg;
}

/* Apply direction `L`'s pacing/jitter/reorder delays before a segment write. */
static void
fault_delays(ssize_t seg, unsigned *seed, const lever_t *L)
{
    if (L->jitter_ms > 0) {
        usleep((useconds_t) (rand_r(seed) % (unsigned) (L->jitter_ms + 1)) * 1000);
    }
    if (L->reorder_ppm > 0 && (int) (rand_r(seed) % 1000000u) < L->reorder_ppm) {
        usleep((useconds_t) L->reorder_ms * 1000);
    }
    if (L->rate_kbps > 0) {
        usleep((useconds_t) ((long long) seg * 1000000
                             / ((long long) L->rate_kbps * 1024)));
    }
}

/* Flip random bits in buf[off, off+seg) at the configured per-byte rate. */
static void
fault_corrupt(char *buf, ssize_t off, ssize_t seg, unsigned *seed, int cor)
{
    if (cor <= 0) {
        return;
    }
    for (ssize_t k = 0; k < seg; k++) {
        if ((int) (rand_r(seed) % 1000000u) < cor) {
            buf[off + k] ^= (char) (1u << (rand_r(seed) % 8u));
            CBUMP(corrupt, 1);
        }
    }
}

/* Aggregate token-bucket gate: pace this segment against a single uplink ceiling
 * shared across ALL relays (simulates a saturated shared link / upstream link).
 * Briefly holds g_gr_lock to update the shared tokens, then sleeps unlocked. */
static void
global_rate_gate(ssize_t seg)
{
    int kbps = g_global_rate_kbps;
    if (kbps <= 0) {
        return;
    }
    double rate = (double) kbps * 1024.0;   /* bytes / second */
    pthread_mutex_lock(&g_gr_lock);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (!g_gr_init) {
        g_gr_last = now;
        g_gr_tokens = 0.0;
        g_gr_init = 1;
    }
    double elapsed = (now.tv_sec - g_gr_last.tv_sec)
                   + (now.tv_nsec - g_gr_last.tv_nsec) / 1e9;
    g_gr_tokens += elapsed * rate;
    if (g_gr_tokens > rate) {
        g_gr_tokens = rate;   /* cap the burst at ~1s of credit */
    }
    g_gr_last = now;
    g_gr_tokens -= (double) seg;
    double deficit = g_gr_tokens < 0.0 ? -g_gr_tokens : 0.0;
    pthread_mutex_unlock(&g_gr_lock);
    if (deficit > 0.0) {
        usleep((useconds_t) (deficit / rate * 1e6));
    }
}

/* Deliver one segment starting at buf+off, applying `L`'s active faults. On
 * success writes the delivered length to *wrote and returns 0; returns -1 when
 * the stream should be severed (truncate cut, lossy drop, write error) or
 * silently dropped (block/epoch change). */
static int
forward_segment(int to, char *buf, ssize_t off, ssize_t n, unsigned epoch,
                const lever_t *L, unsigned *seed, unsigned long *conn_ctr,
                unsigned long *glob_ctr, int piece, ssize_t *wrote)
{
    ssize_t seg = fault_clamp_seg(n - off, piece, L->truncate_at, *conn_ctr);
    if (seg < 0) {
        return fault_sever();
    }

    fault_delays(seg, seed, L);

    if (L->lossy_ppm > 0 && (int) (rand_r(seed) % 1000000u) < L->lossy_ppm) {
        return fault_sever();   /* application-visible "loss" = sever the stream */
    }
    if (g_blocked || g_drop_epoch != epoch) {
        return -1;
    }

    fault_corrupt(buf, off, seg, seed, L->corrupt_ppm);
    global_rate_gate(seg);

    if (write_all(to, buf + off, seg) != 0) {
        return -1;
    }
    if (L->dup_ppm > 0 && (int) (rand_r(seed) % 1000000u) < L->dup_ppm) {
        (void) write_all(to, buf + off, seg);   /* duplicate delivery */
        CBUMP(dups, 1);
    }

    CBUMP2(conn_ctr, glob_ctr, seg);
    *wrote = seg;

    if (L->truncate_at > 0 && (long) *conn_ctr >= L->truncate_at) {
        return fault_sever();   /* deterministic mid-transfer cut */
    }
    return 0;
}

/*
 * Forward n bytes to `to`, applying direction `L`'s active fault levers.  Bytes
 * may be mutated in place (corruption).  Returns 0 on success, -1 if the
 * connection should be severed (write error, a lossy drop, or a truncate cut).
 * `seed` is this thread's private rand_r() state; `conn_ctr` the per-connection
 * per-direction running byte total (for truncate-at); `glob_ctr` the process-wide
 * traffic counter for this direction.
 */
static int
forward_faulted(int to, char *buf, ssize_t n, unsigned epoch, volatile lever_t *L,
                unsigned *seed, unsigned long *conn_ctr, unsigned long *glob_ctr)
{
    /* Snapshot the levers once so a mid-buffer control-plane change can't split
     * this read across two fault configurations (matches the original). */
    lever_t snap  = *L;
    int     piece = (snap.drip_bytes > 0) ? snap.drip_bytes
                  : (snap.chunk_bytes > 0 ? snap.chunk_bytes : (int) n);
    ssize_t off   = 0;

    if (piece <= 0) {
        piece = (int) n;   /* n >= 1 (read returned >0) */
    }
    if (snap.latency_ms > 0) {
        usleep((useconds_t) snap.latency_ms * 1000);
    }

    while (off < n) {
        ssize_t wrote = 0;
        if (forward_segment(to, buf, off, n, epoch, &snap, seed,
                            conn_ctr, glob_ctr, piece, &wrote) != 0) {
            return -1;
        }
        off += wrote;
        if (snap.drip_bytes > 0 && off < n) {
            usleep((useconds_t) snap.drip_ms * 1000);
        }
    }
    return 0;
}

typedef struct {
    int      client_fd;
    unsigned epoch;
    unsigned long conn_id;
} relay_arg;

/* Pre-dial dispositions that answer the client without ever reaching upstream:
 * the fail-nth sever and the hang/black-hole hold.  Returns 1 if the connection
 * was handled (closed + CDEC), 0 to proceed with dialling upstream. */
static int
relay_predial(int cfd, unsigned epoch, unsigned long conn_id)
{
    /* fail-nth: sever exactly the Nth accepted connection, then pass the rest. */
    if (g_fail_nth > 0 && conn_id == (unsigned long) g_fail_nth) {
        CBUMP(severs, 1);
        sever(cfd, -1, g_abortive);
        CDEC(active);
        return 1;
    }

    /* hang / black hole: accept but never relay — hold the client open. */
    if (g_hang) {
        struct pollfd hp = { cfd, POLLIN, 0 };
        while (g_hang && g_drop_epoch == epoch && !g_blocked) {
            if (poll(&hp, 1, 100) > 0 && (hp.revents & (POLLHUP | POLLERR))) {
                break;   /* client gave up */
            }
        }
        close(cfd);
        CDEC(active);
        return 1;
    }
    return 0;
}


#define FP_SCRATCH 140000   /* mutation output buffer: 2x 64 KiB read + inject room */

/* Snapshot the (locked) payload-mutation config for one direction into caller
 * storage, CONSUMING any pending one-shot inject.  Returns 1 if a mutation is
 * active (caller should run fp_ext_mutate), 0 to forward bytes untouched. */
static int
ext_snapshot(int is_up, volatile lever_t *L, fp_ext_mut *mut,
             unsigned char *fbuf, unsigned char *rbuf, unsigned char *ibuf)
{
    struct fp_mutbuf *M = is_up ? &g_up_mut : &g_down_mut;
    pthread_mutex_lock(&g_ext_lock);
    memcpy(fbuf, M->find, (size_t) M->find_len);
    memcpy(rbuf, M->repl, (size_t) M->repl_len);
    memcpy(ibuf, M->inject, (size_t) M->inject_len);
    mut->find = fbuf;   mut->find_len   = (size_t) M->find_len;
    mut->repl = rbuf;   mut->repl_len   = (size_t) M->repl_len;
    mut->inject = ibuf; mut->inject_len = (size_t) M->inject_len;
    M->inject_len = 0;               /* one-shot: consumed */
    pthread_mutex_unlock(&g_ext_lock);
    mut->drop_ppm   = L->drop_ppm;
    mut->repeat_ppm = L->repeat_ppm;
    return fp_ext_mut_active(mut);
}

/* Content trigger: if this direction's armed pattern appears in the just-read
 * buffer, run its stored control command (a targeted, protocol-state fault). */
static void
trig_check(int is_up, const char *buf, ssize_t nr)
{
    struct fp_trigger *T = is_up ? &g_trig_up : &g_trig_down;
    if (T->pat_len <= 0 || (T->once && T->fired)) {
        return;
    }
    char cmd[256];
    int  hit = 0;
    pthread_mutex_lock(&g_ext_lock);
    if (T->pat_len > 0 && !(T->once && T->fired) &&
        memmem(buf, (size_t) nr, T->pat, (size_t) T->pat_len) != NULL) {
        memcpy(cmd, T->cmd, sizeof(cmd));
        if (T->once) {
            T->fired = 1;
        }
        hit = 1;
    }
    pthread_mutex_unlock(&g_ext_lock);
    if (hit) {
        CBUMP(triggered, 1);
        apply_command(cmd, NULL, 0);
    }
}

/* Length-prefix lie: if the armed big-endian uint32 offset lies wholly within
 * this buffer, rewrite it (set/add/sub) — a framing attack on binary protocols. */
static void
mangle_apply(int is_up, char *buf, ssize_t nr, unsigned long base)
{
    struct fp_mangle *M = is_up ? &g_mangle_up : &g_mangle_down;
    if (!M->active) {
        return;
    }
    long off = M->offset;
    if (off < (long) base || off + 4 > (long) base + nr) {
        return;   /* the 4-byte field is not fully contained in this read */
    }
    unsigned char *p = (unsigned char *) buf + (off - (long) base);
    unsigned long  v = ((unsigned long) p[0] << 24) | ((unsigned long) p[1] << 16)
                     | ((unsigned long) p[2] << 8) | (unsigned long) p[3];
    long nv = (M->op == 0) ? M->val
            : (M->op == 1) ? (long) v + M->val
            :                (long) v - M->val;
    unsigned long u = (unsigned long) nv & 0xFFFFFFFFUL;
    p[0] = (unsigned char) (u >> 24); p[1] = (unsigned char) (u >> 16);
    p[2] = (unsigned char) (u >> 8);  p[3] = (unsigned char) u;
    CBUMP(mangled, 1);
}

/* Milliseconds elapsed since the monotonic reference `t0`. */
static unsigned long long
now_ms_since(struct timespec t0)
{
    struct timespec n;
    clock_gettime(CLOCK_MONOTONIC, &n);
    return (unsigned long long) ((n.tv_sec - t0.tv_sec) * 1000LL
                                 + (n.tv_nsec - t0.tv_nsec) / 1000000LL);
}

/* Snapshot this direction's (locked) TLS-surgery config and rewrite the record
 * stream in `in` into `out` (cap FP_SCRATCH).  Consumes a one-shot forged alert.
 * Returns the produced length. */
static size_t
apply_tls(int is_up, const char *in, ssize_t n, unsigned char *out)
{
    fp_tls_cfg  *TC = is_up ? &g_tls_up : &g_tls_down;
    fp_tls_cfg   snap;
    fp_tls_stats st = { 0, 0, 0, 0, 0, 0 };
    pthread_mutex_lock(&g_ext_lock);
    snap = *TC;
    if (TC->alert_level >= 0) {
        TC->alert_level = -1;              /* one-shot alert consumed */
    }
    pthread_mutex_unlock(&g_ext_lock);
    size_t on = fp_tls_rewrite((const unsigned char *) in, (size_t) n,
                               out, FP_SCRATCH, &snap, &st);
    CBUMP(tls_rewrites, 1);
    return on;
}

/* Snapshot this direction's (locked) HTTP-smuggling config and rewrite the
 * message in `in` into `out`.  *applied is 0 (forward original) when the buffer
 * held no header block.  Returns the produced length. */
static size_t
apply_http(int is_up, const char *in, ssize_t n, unsigned char *out, int *applied)
{
    fp_http_cfg  *HC = is_up ? &g_http_up : &g_http_down;
    fp_http_cfg   snap;
    fp_http_stats st = { 0, 0, 0, 0, 0 };
    pthread_mutex_lock(&g_ext_lock);
    snap = *HC;
    pthread_mutex_unlock(&g_ext_lock);
    size_t on = fp_http_rewrite((const unsigned char *) in, (size_t) n,
                                out, FP_SCRATCH, &snap, &st, applied);
    if (*applied) {
        CBUMP(http_rewrites, 1);
    }
    return on;
}

#define FP_PSWAP(a, b) do { unsigned char *fp_t_ = (a); (a) = (b); (b) = fp_t_; } while (0)

/* Relay one poll-ready direction through the fault engine.  Returns 0 to keep
 * looping, 1 on EOF/read error (caller closes both ends), 2 if a fault severed
 * the pair (already closed + CDEC, caller just returns). */
static int
relay_pump_dir(int i, struct pollfd *pfd, int cfd, int ufd,
               char *buf, size_t bufsz, unsigned char *scratch,
               unsigned char *scratch2, unsigned epoch,
               unsigned *seed, unsigned long *up_ctr, unsigned long *down_ctr,
               int *firstflag)
{
    if (!(pfd[i].revents & (POLLIN | POLLHUP | POLLERR))) {
        return 0;
    }
    int from = pfd[i].fd;
    int to   = pfd[i ^ 1].fd;
    ssize_t nr = read(from, buf, bufsz);
    if (nr <= 0) {
        return 1;
    }
    int is_up = (i == 0);
    volatile lever_t *L = is_up ? &g_up : &g_down;
    unsigned long *conn_ctr = is_up ? up_ctr : down_ctr;

    /* Stateful, content-addressed faults on the RAW bytes (before any mutation
     * changes their length/offset). */
    trig_check(is_up, buf, nr);
    mangle_apply(is_up, buf, nr, *conn_ctr);

    /* delay-first: hold back only the opening chunk of this direction. */
    if (L->delayfirst_ms > 0 && *firstflag) {
        usleep((useconds_t) L->delayfirst_ms * 1000);
    }
    *firstflag = 0;

    /* Transform chain: each length-changing stage ping-pongs between scratch A
     * and B so it never overwrites its own input — TLS record surgery, then HTTP
     * request smuggling, then byte-level MITM mutation. */
    const char    *cur = buf;
    ssize_t        curn = nr;
    unsigned char *dst = scratch, *alt = scratch2;

    if (fp_tls_active(is_up ? &g_tls_up : &g_tls_down)) {
        curn = (ssize_t) apply_tls(is_up, cur, curn, dst);
        cur  = (const char *) dst;
        FP_PSWAP(dst, alt);
    }
    if (fp_http_active(is_up ? &g_http_up : &g_http_down)) {
        int    applied = 0;
        size_t on = apply_http(is_up, cur, curn, dst, &applied);
        if (applied) {
            curn = (ssize_t) on;
            cur  = (const char *) dst;
            FP_PSWAP(dst, alt);
        }
    }

    fp_ext_mut    mut;
    unsigned char fbuf[128], rbuf[256], ibuf[512];
    if (ext_snapshot(is_up, L, &mut, fbuf, rbuf, ibuf)) {
        fp_ext_stats st = { 0, 0, 0, 0 };
        size_t on = fp_ext_mutate((const unsigned char *) cur, (size_t) curn,
                                  dst, FP_SCRATCH, &mut, seed, &st);
        curn = (ssize_t) on;
        cur  = (const char *) dst;
        FP_PSWAP(dst, alt);
        if (st.dropped)  { CBUMP(dropped,  st.dropped); }
        if (st.repeated) { CBUMP(repeated, st.repeated); }
        if (st.injected) { CBUMP(injected, st.injected); }
        if (st.replaced) { CBUMP(replaced, st.replaced); }
        if (curn == 0) {
            return 0;   /* every byte was dropped — nothing to forward */
        }
    }

    /* Session recording: capture exactly what we are about to forward. */
    if (fp_replay_recording()) {
        fp_replay_record(is_up, now_ms_since(g_t0),
                         (const unsigned char *) cur, (size_t) curn);
        CBUMP(recorded, (unsigned long) curn);
    }

    unsigned long *glob_ctr = is_up ? &C.up_bytes : &C.down_bytes;
    if (forward_faulted(to, (char *) cur, curn, epoch, L, seed,
                        conn_ctr, glob_ctr) != 0) {
        sever(cfd, ufd, g_abortive);
        CDEC(active);
        return 2;
    }
    return 0;
}


/* Bidirectional relay loop: shuttle bytes each way through the fault engine
 * until EOF, a control-plane sever, or a poll error.  Closes both ends + CDEC
 * before returning. */
static void
relay_pump(int cfd, int ufd, unsigned epoch, unsigned seed)
{
    struct pollfd pfd[2];
    pfd[0].fd = cfd;   /* client   -> upstream (up)   */
    pfd[1].fd = ufd;   /* upstream -> client   (down) */
    char buf[65536];
    /* Two ping-pong transform buffers (uninit; only written) so the TLS/HTTP/MITM
     * stages can chain without a stage overwriting its own input.  Plain stack
     * locals (not _Thread_local — avoids the TLS zero-init latency). */
    unsigned char scratch[FP_SCRATCH];
    unsigned char scratch2[FP_SCRATCH];
    unsigned long up_ctr = 0, down_ctr = 0;
    unsigned hc_epoch = g_halfclose_epoch;
    int      hc_done  = 0;
    int      first[2] = { 1, 1 };
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (;;) {
        if (g_blocked || g_drop_epoch != epoch) {
            sever(cfd, ufd, g_abortive);
            CDEC(active);
            return;
        }
        /* max-lifetime: guillotine a connection that has lived too long. */
        if (g_max_life_ms > 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long ms = (now.tv_sec - t0.tv_sec) * 1000
                    + (now.tv_nsec - t0.tv_nsec) / 1000000;
            if (ms >= g_max_life_ms) {
                CBUMP(severs, 1);
                sever(cfd, ufd, g_abortive);
                CDEC(active);
                return;
            }
        }
        /* half-close: FIN the up path, keep the down path flowing. */
        if (!hc_done && g_halfclose_epoch != hc_epoch) {
            shutdown(cfd, SHUT_RD);
            shutdown(ufd, SHUT_WR);
            hc_done = 1;
        }
        /* stall: stop reading a direction so the peer's send buffer fills
         * (real TCP backpressure) without ever severing. */
        pfd[0].events = (hc_done || g_stall_up)  ? 0 : POLLIN;
        pfd[1].events = g_stall_down ? 0 : POLLIN;
        int pr = poll(pfd, 2, 100);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pr == 0) {
            continue;   /* re-check fault flags */
        }
        for (int i = 0; i < 2; i++) {
            int r = relay_pump_dir(i, pfd, cfd, ufd, buf, sizeof(buf), scratch,
                                   scratch2, epoch, &seed, &up_ctr, &down_ctr,
                                   &first[i]);
            if (r == 2) {
                return;         /* severed + CDEC already done */
            }
            if (r == 1) {
                goto done;      /* EOF */
            }
        }
    }
done:
    close(cfd);
    close(ufd);
    CDEC(active);
}


/* Format a socket address as "ip:port" (v6 bracketed) for a PROXY header. */
static void
sa_to_hostport(const struct sockaddr *sa, socklen_t sl, char *out, size_t cap)
{
    char host[INET6_ADDRSTRLEN] = "", serv[16] = "";
    if (getnameinfo(sa, sl, host, sizeof(host), serv, sizeof(serv),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        out[0] = '\0';
        return;
    }
    if (sa->sa_family == AF_INET6) {
        snprintf(out, cap, "[%s]:%s", host, serv);
    } else {
        snprintf(out, cap, "%s:%s", host, serv);
    }
}

/* Apply the socket-level stress levers (small MSS / squeezed buffers) to a new
 * relay pair.  Best-effort: a kernel that clamps the value is fine. */
static void
apply_conn_tuning(int cfd, int ufd)
{
    if (g_mss > 0) {
        int m = g_mss;
        setsockopt(cfd, IPPROTO_TCP, TCP_MAXSEG, &m, sizeof(m));
        setsockopt(ufd, IPPROTO_TCP, TCP_MAXSEG, &m, sizeof(m));
    }
    if (g_rcvbuf > 0) {
        int b = g_rcvbuf;
        setsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &b, sizeof(b));
        setsockopt(ufd, SOL_SOCKET, SO_RCVBUF, &b, sizeof(b));
    }
    if (g_sndbuf > 0) {
        int b = g_sndbuf;
        setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &b, sizeof(b));
        setsockopt(ufd, SOL_SOCKET, SO_SNDBUF, &b, sizeof(b));
    }
}

/* Prepend a forged PROXY-protocol header to the upstream stream, spoofing the
 * client source the service will attribute the connection to. */
static void
send_proxy_header(int ufd, int cfd)
{
    int mode = g_proxy_mode;
    if (mode == 0) {
        return;
    }
    char src[128], dst[128];
    pthread_mutex_lock(&g_ext_lock);
    snprintf(src, sizeof(src), "%s", g_proxy_src);
    snprintf(dst, sizeof(dst), "%s", g_proxy_dst);
    pthread_mutex_unlock(&g_ext_lock);
    if (dst[0] == '\0') {
        struct sockaddr_storage ss;
        socklen_t               sl = sizeof(ss);
        if (getsockname(cfd, (struct sockaddr *) &ss, &sl) == 0) {
            sa_to_hostport((struct sockaddr *) &ss, sl, dst, sizeof(dst));
        }
    }
    unsigned char hdr[256];
    int n = (mode == 1) ? fp_ext_proxy_v1((char *) hdr, sizeof(hdr), src, dst)
                        : fp_ext_proxy_v2(hdr, sizeof(hdr), src, dst);
    if (n > 0) {
        (void) write_all(ufd, (char *) hdr, n);
        CBUMP(injected, (unsigned long) n);
    }
}

/* Replay mode: act as a synthetic peer, feeding the client the recorded byte
 * timeline (the g_replay_updir direction) with the original inter-segment
 * timing.  No live upstream is dialled.  The store is immutable while replay is
 * active, so it is read lock-free. */
static void
replay_to_client(int cfd, unsigned epoch)
{
    int                want = g_replay_updir ? 1 : 0;
    unsigned long long last = 0;
    int                started = 0;
    for (size_t k = 0; k < g_replay_store.n; k++) {
        fp_replay_rec *r = &g_replay_store.recs[k];
        if (r->is_up != want) {
            continue;
        }
        if (started) {
            long long d = (long long) r->ts_ms - (long long) last;
            if (d > 0 && d < 60000) {          /* honour original gaps, cap at 60s */
                usleep((useconds_t) d * 1000);
            }
        }
        last = r->ts_ms;
        started = 1;
        if (g_blocked || g_drop_epoch != epoch) {
            break;
        }
        if (r->len > 0 &&
            write_all(cfd, (const char *) r->bytes, (ssize_t) r->len) != 0) {
            break;
        }
        CBUMP(replayed, (unsigned long) r->len);
    }
}

static void *
relay_thread(void *arg)
{
    relay_arg *ra = (relay_arg *) arg;
    int        cfd = ra->client_fd;
    unsigned   epoch = ra->epoch;
    unsigned long conn_id = ra->conn_id;
    free(ra);

    unsigned seed = g_seed + (unsigned) conn_id * 2654435761u;

    if (relay_predial(cfd, epoch, conn_id)) {
        return NULL;
    }

    /* Replay: synthesise the response from a recorded session, no upstream. */
    if (g_replay_active) {
        replay_to_client(cfd, epoch);
        close(cfd);
        CDEC(active);
        return NULL;
    }

    int ufd = dial_any();
    if (ufd < 0) {
        close(cfd);
        CDEC(active);
        return NULL;
    }
    /* Egress NODELAY on BOTH ends so chunk/drip pieces are delivered as separate
     * segments (otherwise the kernel coalesces them and the peer never sees a
     * partial PDU).  The accept side already set NODELAY on cfd. */
    { int one = 1;
      setsockopt(ufd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }

    apply_conn_tuning(cfd, ufd);
    send_proxy_header(ufd, cfd);   /* forged PROXY header, before any client bytes */

    /* fanout: open (and hold) extra upstream connections per client connection to
     * drain the server's accept/worker pool — a connection-amplification attack. */
    int extra[16];
    int nextra = 0;
    int fo = g_fanout;
    if (fo > 0) {
        if (fo > 16) {
            fo = 16;
        }
        for (int k = 0; k < fo; k++) {
            int f = dial_any();
            if (f >= 0) {
                extra[nextra++] = f;
                CBUMP(fanout_conns, 1);
            }
        }
    }

    relay_pump(cfd, ufd, epoch, seed);

    for (int k = 0; k < nextra; k++) {
        close(extra[k]);
    }
    return NULL;
}

/* Strip a trailing up|down|both direction token from `args`; return which lever
 * set(s) it names: 0 = both, 1 = up only, 2 = down only. */
static int
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

static void
reset_lever(volatile lever_t *L)
{
    L->latency_ms = 0; L->jitter_ms = 0; L->chunk_bytes = 0;
    L->drip_bytes = 0; L->drip_ms = 0;   L->rate_kbps = 0;
    L->lossy_ppm = 0;  L->reorder_ppm = 0; L->reorder_ms = 50;
    L->corrupt_ppm = 0; L->dup_ppm = 0;  L->truncate_at = 0;
    L->drop_ppm = 0;   L->repeat_ppm = 0; L->delayfirst_ms = 0;
}

static void
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
    g_mss = 0; g_rcvbuf = 0; g_sndbuf = 0;
    g_max_life_ms = 0;
    g_proxy_mode = 0;
    __atomic_add_fetch(&g_chaos_gen, 1, __ATOMIC_SEQ_CST);   /* stop any chaos */
    g_chaos_on = 0;
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
static void *
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
static int
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
static int
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
static int
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

/* Extended, still-root-free levers: socket-level stress (mss/rcvbuf/sndbuf),
 * backpressure (stall/unstall), connection lifetime, payload MITM (inject/
 * replace), PROXY-header forgery, and the chaos monkey. Returns 1 if handled. */
static int
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
        int d = dir_of(args);
        if (d != 2) { g_stall_up = 1; }
        if (d != 1) { g_stall_down = 1; }
    } else if (strcmp(verb, "unstall") == 0) {
        int d = dir_of(args);
        if (d != 2) { g_stall_up = 0; }
        if (d != 1) { g_stall_down = 0; }
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
        if (strcmp(args, "off") == 0 || args[0] == '\0') {
            __atomic_add_fetch(&g_chaos_gen, 1, __ATOMIC_SEQ_CST);
            g_chaos_on = 0;
        } else {
            int ms = atoi(args);
            g_chaos_ms = ms > 10 ? ms : 100;
            unsigned gen = __atomic_add_fetch(&g_chaos_gen, 1, __ATOMIC_SEQ_CST);
            pthread_t th;
            if (pthread_create(&th, NULL, chaos_thread,
                               (void *) (uintptr_t) gen) == 0) {
                pthread_detach(th);
                g_chaos_on = 1;
            }
        }
    } else {
        return 0;
    }
    return 1;
}

/* Flap the listener in/out of service (a load balancer removing/adding the
 * backend): block for down_ms, unblock for up_ms, repeat until superseded. */
static void *
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

struct ramp_arg { unsigned gen; char lever[24]; double start, end; int ms; };

/* Sweep a numeric lever from start to end over ms (a degrading link / a server
 * warming up under load). Stops early if superseded (clear / new ramp epoch). */
static void *
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

/* Named real-world + attack profiles: each expands to a list of control commands
 * applied in order. NULL-terminated command arrays. */
static const struct { const char *name; const char *cmds[6]; } PRESETS[] = {
    /* realism */
    {"satellite",     {"latency 600 both", "jitter 40", "lossy 1", NULL}},
    {"hotel-wifi",    {"jitter 300", "reorder 20 60", "lossy 2", "rate 400", NULL}},
    {"3g-lossy",      {"latency 200", "jitter 120", "corrupt 0.1", "reorder 15 80", NULL}},
    {"transoceanic",  {"latency 150", "jitter 20", NULL}},
    {"congested",     {"rate 128", "drip 4096 40", NULL}},
    {"bufferbloat",   {"latency 50", "rate 256", "jitter 200", NULL}},
    /* attacks — designed to topple a server */
    {"slowloris",     {"drip 1 800 up", "delay-first 2000 up", NULL}},
    {"slowread",      {"drip 1 800 down", "rcvbuf 512", NULL}},
    {"rst-flood",     {"abortive 1", "lossy 100", NULL}},
    {"truncate-bomb", {"truncate-at 4096 down", NULL}},
    {"corrupt-storm", {"corrupt 5", NULL}},
    {"pool-exhaust",  {"fanout 8", "hang", NULL}},
    {"smuggle",       {"inject str:0\\r\\n\\r\\nGET /x HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n up", NULL}},
    {"black-hole",    {"hang", NULL}},
    {"lb-flap",       {"flap 500 500", NULL}},
};

/* Apply a named preset, or list them on `list`/empty. Returns 1 (handled). */
static int
cmd_preset(char *args, char *reply, size_t rsz)
{
    char *name = strtok(args, " ");
    size_t n = sizeof(PRESETS) / sizeof(PRESETS[0]);
    if (!name || strcmp(name, "list") == 0) {
        char *w = reply; int left = (int) rsz;
        int k = snprintf(w, left, "presets:");
        w += k; left -= k;
        for (size_t i = 0; i < n && left > 1; i++) {
            int m = snprintf(w, left, " %s", PRESETS[i].name);
            w += m; left -= m;
        }
        snprintf(w, left > 0 ? left : 0, "\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        if (strcmp(name, PRESETS[i].name) != 0) {
            continue;
        }
        for (int c = 0; PRESETS[i].cmds[c] != NULL; c++) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%s", PRESETS[i].cmds[c]);
            apply_command(buf, NULL, 0);
        }
        snprintf(reply, rsz, "ok (preset %s)\n", name);
        return 1;
    }
    snprintf(reply, rsz, "err: unknown preset (try 'preset list')\n");
    return 1;
}

/* Arm a content trigger: `trigger[-once] <dir> <payload> <command...>`. */
static int
cmd_trigger(int once, char *args, char *reply, size_t rsz)
{
    char *dirtok = strtok(args, " ");
    if (dirtok && strcmp(dirtok, "off") == 0) {
        pthread_mutex_lock(&g_ext_lock);
        g_trig_up.pat_len = 0; g_trig_up.fired = 0;
        g_trig_down.pat_len = 0; g_trig_down.fired = 0;
        pthread_mutex_unlock(&g_ext_lock);
        return 1;
    }
    char *pay = strtok(NULL, " ");
    char *cmd = strtok(NULL, "");
    int   d = 0;
    if (dirtok && strcmp(dirtok, "up") == 0)   d = 1;
    else if (dirtok && strcmp(dirtok, "down") == 0) d = 2;
    if (!dirtok || !pay || !cmd) {
        snprintf(reply, rsz, "err: trigger <up|down|both> <payload> <command>\n");
        return 1;
    }
    unsigned char pat[128];
    int pl = fp_ext_parse_payload(pay, pat, sizeof(pat));
    if (pl <= 0) {
        snprintf(reply, rsz, "err: bad trigger payload (hex:.. or str:..)\n");
        return 1;
    }
    pthread_mutex_lock(&g_ext_lock);
    struct fp_trigger *set[2] = { NULL, NULL };
    if (d != 2) { set[0] = &g_trig_up; }
    if (d != 1) { set[1] = &g_trig_down; }
    for (int j = 0; j < 2; j++) {
        if (!set[j]) {
            continue;
        }
        memcpy(set[j]->pat, pat, (size_t) pl);
        set[j]->pat_len = pl;
        snprintf(set[j]->cmd, sizeof(set[j]->cmd), "%s", cmd);
        set[j]->once = once;
        set[j]->fired = 0;
    }
    pthread_mutex_unlock(&g_ext_lock);
    return 1;
}

/* `mangle-len <up|down|both> <offset> <set|add|sub> <val>` (or `off`). */
static int
cmd_mangle(char *args, char *reply, size_t rsz)
{
    char *dirtok = strtok(args, " ");
    int   d = 0;
    if (dirtok && strcmp(dirtok, "up") == 0)   d = 1;
    else if (dirtok && strcmp(dirtok, "down") == 0) d = 2;
    if (dirtok && strcmp(dirtok, "off") == 0) {
        g_mangle_up.active = 0; g_mangle_down.active = 0;
        return 1;
    }
    char *offt = strtok(NULL, " ");
    char *opt  = strtok(NULL, " ");
    char *valt = strtok(NULL, " ");
    if (!dirtok || !offt || !opt || !valt) {
        snprintf(reply, rsz, "err: mangle-len <dir> <offset> <set|add|sub> <val>\n");
        return 1;
    }
    int op = (strcmp(opt, "set") == 0) ? 0 : (strcmp(opt, "add") == 0) ? 1
           : (strcmp(opt, "sub") == 0) ? 2 : -1;
    if (op < 0) {
        snprintf(reply, rsz, "err: mangle op must be set|add|sub\n");
        return 1;
    }
    struct fp_mangle *set[2] = { NULL, NULL };
    if (d != 2) { set[0] = &g_mangle_up; }
    if (d != 1) { set[1] = &g_mangle_down; }
    for (int j = 0; j < 2; j++) {
        if (!set[j]) {
            continue;
        }
        set[j]->offset = atol(offt);
        set[j]->op = op;
        set[j]->val = atol(valt);
        set[j]->active = 1;
    }
    return 1;
}

/* Attack-mocking control verbs (topple-a-server toolkit). Returns 1 if handled. */
static int
cmd_set_attack(const char *verb, char *args, char *reply, size_t rsz)
{
    if (strcmp(verb, "preset") == 0) {
        cmd_preset(args, reply, rsz);
    } else if (strcmp(verb, "trigger") == 0) {
        cmd_trigger(0, args, reply, rsz);
    } else if (strcmp(verb, "trigger-once") == 0) {
        cmd_trigger(1, args, reply, rsz);
    } else if (strcmp(verb, "mangle-len") == 0) {
        cmd_mangle(args, reply, rsz);
    } else if (strcmp(verb, "accept-pause") == 0) {
        g_accept_pause_ms = atoi(args);
    } else if (strcmp(verb, "fanout") == 0) {
        g_fanout = atoi(args);
    } else if (strcmp(verb, "global-rate") == 0) {
        g_global_rate_kbps = atoi(args);
        g_gr_init = 0;   /* re-prime the shared bucket */
    } else if (strcmp(verb, "flap") == 0) {
        if (strcmp(args, "off") == 0 || args[0] == '\0') {
            __atomic_add_fetch(&g_flap_gen, 1, __ATOMIC_SEQ_CST);
            g_flap_on = 0;
        } else {
            int up = 0, down = 0;
            sscanf(args, "%d %d", &up, &down);
            g_flap_up_ms = up; g_flap_down_ms = down;
            unsigned gen = __atomic_add_fetch(&g_flap_gen, 1, __ATOMIC_SEQ_CST);
            pthread_t th;
            if (pthread_create(&th, NULL, flap_thread,
                               (void *) (uintptr_t) gen) == 0) {
                pthread_detach(th);
                g_flap_on = 1;
            }
        }
    } else if (strcmp(verb, "ramp") == 0) {
        struct ramp_arg *r = calloc(1, sizeof(*r));
        if (r && sscanf(args, "%23s %lf %lf %d", r->lever, &r->start,
                        &r->end, &r->ms) == 4) {
            r->gen = __atomic_load_n(&g_ramp_gen, __ATOMIC_SEQ_CST);
            pthread_t th;
            if (pthread_create(&th, NULL, ramp_thread, r) == 0) {
                pthread_detach(th);
            } else {
                free(r);
            }
        } else {
            free(r);
            snprintf(reply, rsz, "err: ramp <lever> <start> <end> <ms>\n");
        }
    } else {
        return 0;
    }
    return 1;
}

/* --- TLS record surgery control (`tls <sub> ...`) ------------------------- */

/* Apply integer `v` to field `F` of the selected direction(s) TLS config.
 * d: 0 both / 1 up / 2 down. */
#define TLS_SET(d, F, v) do {                      \
    if ((d) != 2) g_tls_up.F   = (v);              \
    if ((d) != 1) g_tls_down.F = (v);              \
} while (0)

static int
cmd_set_tls(char *args, char *reply, size_t rsz)
{
    char *sub = strtok(args, " ");
    char *rest = strtok(NULL, "");
    char  rbuf[64] = "";
    if (rest) {
        snprintf(rbuf, sizeof(rbuf), "%s", rest);
    }
    int d = dir_of(rbuf);
    pthread_mutex_lock(&g_ext_lock);
    if (!sub || strcmp(sub, "off") == 0) {
        fp_tls_cfg_init(&g_tls_up);
        fp_tls_cfg_init(&g_tls_down);
    } else if (strcmp(sub, "fragment") == 0) {
        TLS_SET(d, frag_max, atoi(rbuf));
    } else if (strcmp(sub, "set-type") == 0) {
        TLS_SET(d, set_type, atoi(rbuf));
    } else if (strcmp(sub, "drop-type") == 0) {
        TLS_SET(d, drop_type, atoi(rbuf));
    } else if (strcmp(sub, "inflate") == 0) {
        TLS_SET(d, inflate_len, atoi(rbuf));
    } else if (strcmp(sub, "flip") == 0) {
        TLS_SET(d, flip_payload, 1);
    } else if (strcmp(sub, "set-version") == 0) {
        int maj = 3, min = 3;
        sscanf(rbuf, "%d %d", &maj, &min);
        TLS_SET(d, set_ver_major, maj);
        TLS_SET(d, set_ver_minor, min);
    } else if (strcmp(sub, "alert") == 0) {
        int lvl = 2, desc = 0;
        sscanf(rbuf, "%d %d", &lvl, &desc);
        TLS_SET(d, alert_level, lvl);
        TLS_SET(d, alert_desc, desc);
    } else {
        pthread_mutex_unlock(&g_ext_lock);
        snprintf(reply, rsz, "err: tls <fragment|set-type|drop-type|inflate|flip|"
                             "set-version|alert|off> ...\n");
        return 1;
    }
    pthread_mutex_unlock(&g_ext_lock);
    return 1;
}

/* --- HTTP smuggling control (`http <sub> ...`) ---------------------------- */
static int
cmd_set_http(char *args, char *reply, size_t rsz)
{
    char *sub = strtok(args, " ");
    char *rest = strtok(NULL, "");
    char  rbuf[512] = "";
    if (rest) {
        snprintf(rbuf, sizeof(rbuf), "%s", rest);
    }
    int d = dir_of(rbuf);
    fp_http_cfg *H[2] = { NULL, NULL };
    if (d != 2) { H[0] = &g_http_up; }
    if (d != 1) { H[1] = &g_http_down; }
    pthread_mutex_lock(&g_ext_lock);
    int ok = 1;
    if (!sub || strcmp(sub, "off") == 0) {
        memset(&g_http_up, 0, sizeof(g_http_up));
        memset(&g_http_down, 0, sizeof(g_http_down));
    } else if (strcmp(sub, "cl-te") == 0) {
        for (int j = 0; j < 2; j++) if (H[j]) { H[j]->add_cl = 1; H[j]->cl_val = atol(rbuf); H[j]->add_te = 1; }
    } else if (strcmp(sub, "te-cl") == 0) {
        for (int j = 0; j < 2; j++) if (H[j]) { H[j]->add_te = 1; H[j]->add_cl = 1; H[j]->cl_val = atol(rbuf); }
    } else if (strcmp(sub, "dup-cl") == 0) {
        for (int j = 0; j < 2; j++) if (H[j]) { H[j]->dup_cl = 1; H[j]->dup_cl_val = atol(rbuf); }
    } else if (strcmp(sub, "obfuscate-te") == 0) {
        int m = atoi(rbuf); if (m < 1 || m > 3) { m = 1; }
        for (int j = 0; j < 2; j++) if (H[j]) { H[j]->obfuscate_te = m; }
    } else if (strcmp(sub, "naked-lf") == 0) {
        for (int j = 0; j < 2; j++) if (H[j]) { H[j]->naked_lf = 1; }
    } else if (strcmp(sub, "inject-header") == 0) {
        char *nm = strtok(rbuf, " ");
        char *vl = strtok(NULL, "");
        if (nm && vl) {
            for (int j = 0; j < 2; j++) if (H[j]) {
                H[j]->inj_name_len = (int) snprintf((char *) H[j]->inj_name,
                    sizeof(H[j]->inj_name), "%s", nm);
                H[j]->inj_val_len = fp_ext_parse_payload(vl, H[j]->inj_val,
                    sizeof(H[j]->inj_val));
                if (H[j]->inj_val_len < 0) { H[j]->inj_val_len = 0; ok = 0; }
            }
        } else { ok = 0; }
    } else if (strcmp(sub, "append") == 0) {
        for (int j = 0; j < 2; j++) if (H[j]) {
            int n = fp_ext_parse_payload(rbuf, H[j]->append, sizeof(H[j]->append));
            H[j]->append_len = n > 0 ? n : 0;
            if (n <= 0) { ok = 0; }
        }
    } else {
        ok = -1;
    }
    pthread_mutex_unlock(&g_ext_lock);
    if (ok == -1) {
        snprintf(reply, rsz, "err: http <cl-te|te-cl|dup-cl|obfuscate-te|naked-lf|"
                             "inject-header|append|off> ...\n");
    } else if (ok == 0) {
        snprintf(reply, rsz, "err: bad http argument (payload hex:/str:)\n");
    }
    return 1;
}

/* --- Session record / replay control -------------------------------------- */
static int
cmd_set_replay(const char *verb, char *args, char *reply, size_t rsz)
{
    if (strcmp(verb, "record") == 0) {
        if (strcmp(args, "off") == 0 || args[0] == '\0') {
            fp_replay_record_stop();
            snprintf(reply, rsz, "ok (recording stopped)\n");
        } else if (fp_replay_record_start(args) == 0) {
            snprintf(reply, rsz, "ok (recording to %s)\n", args);
        } else {
            snprintf(reply, rsz, "err: cannot open record file\n");
        }
        return 1;
    }
    if (strcmp(verb, "replay") == 0) {
        char *sub = strtok(args, " ");
        if (!sub || strcmp(sub, "off") == 0) {
            g_replay_active = 0;
            snprintf(reply, rsz, "ok (replay off)\n");
            return 1;
        }
        if (strcmp(sub, "dir") == 0) {
            char *d = strtok(NULL, " ");
            g_replay_updir = (d && strcmp(d, "up") == 0) ? 1 : 0;
            return 1;
        }
        if (g_replay_active) {
            snprintf(reply, rsz, "err: replay already active (replay off first)\n");
            return 1;
        }
        fp_replay_free(&g_replay_store);
        if (fp_replay_load(sub, &g_replay_store) != 0) {
            snprintf(reply, rsz, "err: cannot load capture (missing / bad magic)\n");
            return 1;
        }
        g_replay_active = 1;
        snprintf(reply, rsz, "ok (replaying %zu records from %s)\n",
                 g_replay_store.n, sub);
        return 1;
    }
    return 0;
}

/* --- Auto-bisection + assert-recovery oracle ------------------------------ */

struct bisect_arg { char lever[24]; long lo, hi; int timeout_ms; char cmd[256]; };
struct recov_arg  { char fault[256]; int hold_ms; char probe[256]; int timeout_ms; };

static void
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
static void *
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
static void *
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

/* Oracle-driven control verbs (bisect / recovery / their results). Gated on
 * --enable-exec for anything that spawns a probe. Returns 1 if handled. */
static int
cmd_set_oracle(const char *verb, char *args, char *reply, size_t rsz)
{
    if (strcmp(verb, "bisect-result") == 0) {
        pthread_mutex_lock(&g_res_lock);
        snprintf(reply, rsz, "%s\n", g_bisect_result);
        pthread_mutex_unlock(&g_res_lock);
        return 1;
    }
    if (strcmp(verb, "recovery-result") == 0) {
        pthread_mutex_lock(&g_res_lock);
        snprintf(reply, rsz, "%s\n", g_recovery_result);
        pthread_mutex_unlock(&g_res_lock);
        return 1;
    }
    if (strcmp(verb, "bisect") == 0) {
        if (!fp_oracle_enabled()) {
            snprintf(reply, rsz, "err: bisect needs --enable-exec\n");
            return 1;
        }
        if (g_oracle_busy) {
            snprintf(reply, rsz, "err: an oracle job is already running\n");
            return 1;
        }
        struct bisect_arg *b = calloc(1, sizeof(*b));
        char *lever = strtok(args, " ");
        char *lo    = strtok(NULL, " ");
        char *hi    = strtok(NULL, " ");
        char *to    = strtok(NULL, " ");
        char *cmd   = strtok(NULL, "");
        if (!b || !lever || !lo || !hi || !to || !cmd) {
            free(b);
            snprintf(reply, rsz, "err: bisect <lever> <lo> <hi> <timeout_ms> <oracle-cmd>\n");
            return 1;
        }
        snprintf(b->lever, sizeof(b->lever), "%s", lever);
        b->lo = atol(lo); b->hi = atol(hi); b->timeout_ms = atoi(to);
        snprintf(b->cmd, sizeof(b->cmd), "%s", cmd);
        pthread_t th;
        g_oracle_busy = 1;
        if (pthread_create(&th, NULL, bisect_thread, b) != 0) {
            g_oracle_busy = 0; free(b);
            snprintf(reply, rsz, "err: cannot start bisect thread\n");
        } else {
            pthread_detach(th);
            snprintf(reply, rsz, "ok (bisecting %s in [%ld,%ld]; poll bisect-result)\n",
                     b->lever, b->lo, b->hi);
        }
        return 1;
    }
    if (strcmp(verb, "recovery") == 0) {
        if (!fp_oracle_enabled()) {
            snprintf(reply, rsz, "err: recovery needs --enable-exec\n");
            return 1;
        }
        if (g_oracle_busy) {
            snprintf(reply, rsz, "err: an oracle job is already running\n");
            return 1;
        }
        struct recov_arg *r = calloc(1, sizeof(*r));
        char *fault = strtok(args, "|");
        char *hold  = strtok(NULL, "|");
        char *probe = strtok(NULL, "|");
        char *to    = strtok(NULL, "|");
        if (!r || !fault || !hold || !probe || !to) {
            free(r);
            snprintf(reply, rsz, "err: recovery <fault-cmd> | <hold_ms> | <probe-cmd> | <timeout_ms>\n");
            return 1;
        }
        snprintf(r->fault, sizeof(r->fault), "%s", fault);
        r->hold_ms = atoi(hold);
        snprintf(r->probe, sizeof(r->probe), "%s", probe);
        r->timeout_ms = atoi(to);
        pthread_t th;
        g_oracle_busy = 1;
        if (pthread_create(&th, NULL, recovery_thread, r) != 0) {
            g_oracle_busy = 0; free(r);
            snprintf(reply, rsz, "err: cannot start recovery thread\n");
        } else {
            pthread_detach(th);
            snprintf(reply, rsz, "ok (recovery probe started; poll recovery-result)\n");
        }
        return 1;
    }
    return 0;
}

/* Protocol-surgery + record/replay dispatch (tls/http/record/replay). */
static int
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
static void
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
static void
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

/* Parse and apply one control command.  `line` is mutated.  `reply` (may be NULL)
 * receives a human-readable response of up to `rsz` bytes. */
static void
apply_command(char *line, char *reply, size_t rsz)
{
    char verb[32] = "", args[2000] = "";
    sscanf(line, "%31s %1999[^\n]", verb, args);
    if (reply && rsz) {
        snprintf(reply, rsz, "ok\n");
    }

    if (strcmp(verb, "priv") == 0) {
        fp_priv_command(args, reply, rsz);
        return;
    }
    if (cmd_set_lever(verb, args) || cmd_set_epoch(verb)
        || cmd_set_misc(verb, args) || cmd_set_ext(verb, args, reply, rsz)
        || cmd_set_attack(verb, args, reply, rsz)
        || cmd_set_proto(verb, args, reply, rsz)
        || cmd_set_oracle(verb, args, reply, rsz)) {
        return;
    }
    if (strcmp(verb, "status") == 0) {
        if (strcmp(args, "json") == 0) {
            cmd_status_json(reply, rsz);
        } else {
            cmd_status_report(reply, rsz);
        }
    } else if (verb[0] != '\0' && reply && rsz) {
        snprintf(reply, rsz, "err: unknown command\n");
    }
}

static void *
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
static void *
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

/* Add one "host:port" (or a comma-separated list) to the target pool. */
static int
add_target(const char *spec)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", spec);
    for (char *tok = strtok(tmp, ","); tok != NULL; tok = strtok(NULL, ",")) {
        if (g_ntargets >= FP_MAX_TARGETS) {
            fprintf(stderr, "brix-fault-proxy: too many --target (max %d)\n",
                    FP_MAX_TARGETS);
            return -1;
        }
        const char *colon = strrchr(tok, ':');
        if (colon == NULL || colon == tok || colon[1] == '\0') {
            fprintf(stderr, "brix-fault-proxy: invalid --target '%s' "
                            "(expected HOST:PORT)\n", tok);
            return -1;
        }
        size_t hlen = (size_t) (colon - tok);
        if (hlen >= sizeof(g_targets[0].host)) {
            return -1;
        }
        int p = atoi(colon + 1);
        if (p <= 0 || p > 65535) {
            fprintf(stderr, "brix-fault-proxy: invalid target port in '%s'\n", tok);
            return -1;
        }
        memcpy(g_targets[g_ntargets].host, tok, hlen);
        g_targets[g_ntargets].host[hlen] = '\0';
        g_targets[g_ntargets].port = p;
        g_ntargets++;
    }
    return 0;
}

static int
sa_is_loopback(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        uint32_t a = ntohl(((const struct sockaddr_in *) sa)->sin_addr.s_addr);
        return (a >> 24) == 127;
    }
    if (sa->sa_family == AF_INET6) {
        return IN6_IS_ADDR_LOOPBACK(
            &((const struct sockaddr_in6 *) sa)->sin6_addr) ? 1 : 0;
    }
    return 0;
}

/* Bind+listen on a copy of `tmpl` (family-agnostic) with `port` substituted. */
static int
listen_sa(const struct sockaddr_storage *tmpl, socklen_t slen, int port)
{
    struct sockaddr_storage ss = *tmpl;
    if (ss.ss_family == AF_INET) {
        ((struct sockaddr_in *) &ss)->sin_port = htons((uint16_t) port);
    } else {
        ((struct sockaddr_in6 *) &ss)->sin6_port = htons((uint16_t) port);
    }
    int fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (bind(fd, (struct sockaddr *) &ss, slen) != 0 || listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Parsed command-line configuration for the proxy run. Lever options
 * (--latency, --block, …) are not carried here: they mutate the global
 * fault levers via apply_command() as they are parsed. */
typedef struct {
    int         listen_port;
    int         control_port;
    const char *bind_str;
    const char *script_path;
    const char *priv_iface;   /* --priv-iface: NIC for root-ful netem/mtu levers */
    int         privileged;   /* --privileged: arm the root-gated subsystem */
    int         insecure;
    int         quiet;
} fp_config;

/* Route an initial-lever long option (--latency, --block, …) through the same
 * command parser as the live control port. Returns 1 if `opt` was a lever
 * option (handled), 0 otherwise so the core option switch can claim it. */
static int
fp_apply_lever_opt(int opt, const char *optarg)
{
    static const struct { int code; const char *name; } lever[] = {
        {1000, "latency"}, {1001, "jitter"},  {1002, "chunk"},   {1003, "drip"},
        {1004, "lossy"},   {1005, "reorder"}, {1007, "corrupt"}, {1008, "dup"},
        {1009, "rate"},    {1010, "truncate-at"}, {1011, "fail-nth"},
        {1012, "heal-after"},
        {1019, "mss"},       {1020, "rcvbuf"},      {1021, "sndbuf"},
        {1022, "max-lifetime"}, {1023, "drop-bytes"}, {1024, "repeat-bytes"},
        {1025, "delay-first"}, {1026, "inject"},    {1027, "replace"},
        {1028, "proxy-header"}, {1029, "chaos"},     {1030, "stall"},
        {1031, "preset"},      {1032, "trigger"},   {1033, "trigger-once"},
        {1034, "mangle-len"},  {1035, "accept-pause"}, {1036, "fanout"},
        {1037, "global-rate"}, {1038, "flap"},      {1039, "ramp"},
        {1041, "tls"},         {1042, "http"},      {1043, "record"},
        {1044, "replay"},
    };
    char   cmd[2048];
    size_t i;

    if (opt == 1006) { apply_command((char[]){"block"}, NULL, 0); return 1; }
    if (opt == 1013) { apply_command((char[]){"hang"},  NULL, 0); return 1; }

    for (i = 0; i < sizeof(lever) / sizeof(lever[0]); i++) {
        if (lever[i].code == opt) {
            snprintf(cmd, sizeof(cmd), "%s %s", lever[i].name, optarg);
            apply_command(cmd, NULL, 0);
            return 1;
        }
    }
    return 0;
}

/* Apply a single core (non-lever) option to `cfg`. Returns FP_CONTINUE to keep
 * parsing, or a terminal exit code (FP_OK for --help/--version, FP_USAGE on
 * an unknown option or a rejected --target). */
static int
fp_apply_core_opt(int opt, fp_config *cfg)
{
    switch (opt) {
    case 'l': cfg->listen_port = atoi(optarg); break;
    case 't':
        if (add_target(optarg) != 0) {
            return FP_USAGE;
        }
        break;
    case 'c': cfg->control_port = atoi(optarg); break;
    case 'b': cfg->bind_str = optarg; break;
    case 'I': cfg->insecure = 1; break;
    case 'q': cfg->quiet = 1; break;
    case 1014: g_seed = (unsigned) strtoul(optarg, NULL, 0); break;
    case 1015: g_max_conns = atoi(optarg); break;
    case 1016: cfg->script_path = optarg; break;
    case 1017: cfg->privileged = 1; break;
    case 1018: cfg->priv_iface = optarg; break;
    case 1040: fp_oracle_enable(); break;
    case 'h': usage(stdout); return FP_OK;
    case 'V':
        printf("brix-fault-proxy (BriX-Cache client) %s\n", brix_client_version());
        return FP_OK;
    default:
        usage(stderr);
        return FP_USAGE;
    }
    return FP_CONTINUE;
}

/* Fold any positional arguments into `cfg` and validate the required config.
 *
 * Positional back-compat: `brix-fault-proxy LISTEN HOST PORT CONTROL`.
 * Accepted only when no --listen/--target/--control were given, so the two
 * calling conventions never half-mix into a confusing partial config. */
static int
fp_finalize_config(int argc, char **argv, fp_config *cfg)
{
    int npos = argc - optind;

    if (cfg->listen_port == 0 && cfg->control_port == 0 && g_ntargets == 0
        && npos == 4) {
        cfg->listen_port = atoi(argv[optind]);
        char hp[512];
        snprintf(hp, sizeof(hp), "%s:%s", argv[optind + 1], argv[optind + 2]);
        if (add_target(hp) != 0) {
            return FP_USAGE;
        }
        cfg->control_port = atoi(argv[optind + 3]);
    } else if (npos != 0) {
        fprintf(stderr, "brix-fault-proxy: unexpected argument '%s'\n", argv[optind]);
        usage(stderr);
        return FP_USAGE;
    }

    if (cfg->listen_port <= 0 || cfg->control_port <= 0 || g_ntargets == 0) {
        fprintf(stderr, "brix-fault-proxy: --listen, --target and --control "
                        "are all required\n");
        usage(stderr);
        return FP_USAGE;
    }
    return FP_CONTINUE;
}

/* Parse argv into `cfg`, applying lever options as a side effect. Returns
 * FP_CONTINUE when the caller should proceed to run, otherwise a terminal
 * exit code. */
static int
fp_parse_args(int argc, char **argv, fp_config *cfg)
{
    static const struct option longopts[] = {
        {"listen",        required_argument, NULL, 'l'},
        {"target",        required_argument, NULL, 't'},
        {"control",       required_argument, NULL, 'c'},
        {"bind",          required_argument, NULL, 'b'},
        {"insecure-bind", no_argument,       NULL, 'I'},
        {"max-conns",     required_argument, NULL, 1015},
        {"seed",          required_argument, NULL, 1014},
        {"script",        required_argument, NULL, 1016},
        {"privileged",    no_argument,       NULL, 1017},
        {"priv-iface",    required_argument, NULL, 1018},
        {"quiet",         no_argument,       NULL, 'q'},
        {"latency",       required_argument, NULL, 1000},
        {"jitter",        required_argument, NULL, 1001},
        {"chunk",         required_argument, NULL, 1002},
        {"drip",          required_argument, NULL, 1003},
        {"lossy",         required_argument, NULL, 1004},
        {"reorder",       required_argument, NULL, 1005},
        {"block",         no_argument,       NULL, 1006},
        {"corrupt",       required_argument, NULL, 1007},
        {"dup",           required_argument, NULL, 1008},
        {"rate",          required_argument, NULL, 1009},
        {"truncate-at",   required_argument, NULL, 1010},
        {"fail-nth",      required_argument, NULL, 1011},
        {"heal-after",    required_argument, NULL, 1012},
        {"hang",          no_argument,       NULL, 1013},
        {"mss",           required_argument, NULL, 1019},
        {"rcvbuf",        required_argument, NULL, 1020},
        {"sndbuf",        required_argument, NULL, 1021},
        {"max-lifetime",  required_argument, NULL, 1022},
        {"drop-bytes",    required_argument, NULL, 1023},
        {"repeat-bytes",  required_argument, NULL, 1024},
        {"delay-first",   required_argument, NULL, 1025},
        {"inject",        required_argument, NULL, 1026},
        {"replace",       required_argument, NULL, 1027},
        {"proxy-header",  required_argument, NULL, 1028},
        {"chaos",         required_argument, NULL, 1029},
        {"stall",         required_argument, NULL, 1030},
        {"preset",        required_argument, NULL, 1031},
        {"trigger",       required_argument, NULL, 1032},
        {"trigger-once",  required_argument, NULL, 1033},
        {"mangle-len",    required_argument, NULL, 1034},
        {"accept-pause",  required_argument, NULL, 1035},
        {"fanout",        required_argument, NULL, 1036},
        {"global-rate",   required_argument, NULL, 1037},
        {"flap",          required_argument, NULL, 1038},
        {"ramp",          required_argument, NULL, 1039},
        {"enable-exec",   no_argument,       NULL, 1040},
        {"tls",           required_argument, NULL, 1041},
        {"http",          required_argument, NULL, 1042},
        {"record",        required_argument, NULL, 1043},
        {"replay",        required_argument, NULL, 1044},
        {"help",          no_argument,       NULL, 'h'},
        {"version",       no_argument,       NULL, 'V'},
        {0, 0, 0, 0},
    };
    int opt, rc;

    while ((opt = getopt_long(argc, argv, "l:t:c:b:qhV", longopts, NULL)) != -1) {
        if (fp_apply_lever_opt(opt, optarg)) {
            continue;
        }
        if ((rc = fp_apply_core_opt(opt, cfg)) != FP_CONTINUE) {
            return rc;
        }
    }
    return fp_finalize_config(argc, argv, cfg);
}

/* Resolve `bind_str` into `bind_ss`/`bind_len` and enforce the loopback gate.
 * The control port is unauthenticated, so a non-loopback bind must be a
 * deliberate, explicit act (--insecure-bind). Returns FP_CONTINUE or FP_USAGE. */
static int
fp_setup_bind(const char *bind_str, int insecure,
    struct sockaddr_storage *bind_ss, socklen_t *bind_len)
{
    struct addrinfo hints, *bres = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICHOST;
    if (getaddrinfo(bind_str, "0", &hints, &bres) != 0 || bres == NULL) {
        fprintf(stderr, "brix-fault-proxy: invalid --bind address '%s'\n", bind_str);
        return FP_USAGE;
    }
    *bind_len = bres->ai_addrlen;
    memcpy(bind_ss, bres->ai_addr, bres->ai_addrlen);
    freeaddrinfo(bres);

    /* Fail closed on a non-loopback bind unless the operator opts in. */
    if (!sa_is_loopback((struct sockaddr *) bind_ss) && !insecure) {
        fprintf(stderr, "brix-fault-proxy: refusing to bind the unauthenticated "
                        "control port to non-loopback '%s' without "
                        "--insecure-bind\n", bind_str);
        return FP_USAGE;
    }
    if (!sa_is_loopback((struct sockaddr *) bind_ss)) {
        fprintf(stderr, "brix-fault-proxy: WARNING binding control port to %s — "
                        "the control plane is UNAUTHENTICATED\n", bind_str);
    }
    return FP_CONTINUE;
}

/* Accept clients on `lfd` forever, spawning a detached relay thread per
 * connection (subject to the outage/connection-cap levers). Returns FP_OK when
 * the accept loop terminates on a non-EINTR error. */
static int
fp_accept_loop(int lfd)
{
    for (;;) {
        /* accept-pause: delay servicing the accept queue so pending SYNs / the
         * accept backlog pile up (connect-timeout + backlog-overflow testing). */
        if (g_accept_pause_ms > 0) {
            usleep((useconds_t) g_accept_pause_ms * 1000);
        }
        int client = accept(lfd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (g_blocked) {
            CBUMP(refused, 1);
            close(client);        /* outage: refuse */
            continue;
        }
        if (g_max_conns > 0
            && __atomic_load_n(&C.active, __ATOMIC_RELAXED) >= (unsigned long) g_max_conns) {
            CBUMP(refused, 1);
            close(client);        /* connection cap reached */
            continue;
        }
        int one = 1;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        relay_arg *ra = malloc(sizeof(*ra));
        ra->client_fd = client;
        ra->epoch = __atomic_load_n(&g_drop_epoch, __ATOMIC_SEQ_CST);
        ra->conn_id = CBUMP(conns, 1);
        CBUMP(active, 1);
        pthread_t t;
        if (pthread_create(&t, NULL, relay_thread, ra) != 0) {
            close(client);
            CDEC(active);
            free(ra);
            continue;
        }
        pthread_detach(t);
    }
    return FP_OK;
}

/* Print the startup banner (target chain + control endpoint). */
static void
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
static void
fp_on_signal(int sig)
{
    fp_priv_teardown();
    _exit(128 + sig);
}

/* Arm the privileged subsystem if requested, wiring in the teardown hooks. On a
 * hard failure (e.g. --privileged without root) prints the reason and returns
 * FP_USAGE; returns FP_CONTINUE otherwise. */
static int
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

int
main(int argc, char **argv)
{
    fp_config               cfg = { .bind_str = "127.0.0.1" };
    struct sockaddr_storage bind_ss;
    socklen_t               bind_len;
    int                     rc;

    reset_lever(&g_up);
    reset_lever(&g_down);
    fp_tls_cfg_init(&g_tls_up);        /* sentinels (-1); zero would read as active */
    fp_tls_cfg_init(&g_tls_down);
    clock_gettime(CLOCK_MONOTONIC, &g_t0);   /* replay-timestamp reference */

    if ((rc = fp_parse_args(argc, argv, &cfg)) != FP_CONTINUE) {
        return rc;
    }
    if ((rc = fp_setup_bind(cfg.bind_str, cfg.insecure, &bind_ss, &bind_len))
        != FP_CONTINUE) {
        return rc;
    }

    signal(SIGPIPE, SIG_IGN);

    if ((rc = fp_arm_privileged(&cfg)) != FP_CONTINUE) {
        return rc;
    }

    int lfd   = listen_sa(&bind_ss, bind_len, cfg.listen_port);
    int ctlfd = listen_sa(&bind_ss, bind_len, cfg.control_port);
    if (lfd < 0 || ctlfd < 0) {
        fprintf(stderr, "brix-fault-proxy: bind failed (listen=%d control=%d)\n",
                cfg.listen_port, cfg.control_port);
        return FP_RUN;
    }

    pthread_t ct;
    int *cfdp = malloc(sizeof(int));
    *cfdp = ctlfd;
    pthread_create(&ct, NULL, control_thread, cfdp);

    if (cfg.script_path != NULL) {
        pthread_t st;
        if (pthread_create(&st, NULL, script_thread, (void *) cfg.script_path) == 0) {
            pthread_detach(st);
        }
    }

    if (!cfg.quiet) {
        fp_print_banner(&cfg);
    }

    return fp_accept_loop(lfd);
}
