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
 *       This translation unit owns the CLI/lifecycle core: argument parsing,
 *       the loopback-bind security gate, the accept loop, the startup banner and
 *       main().  The byte-level fault engine and per-connection relay live in
 *       brix_fault_proxy_relay.c; the control-port command grammar lives in
 *       brix_fault_proxy_control.c; the state shared across all three (fault
 *       levers, counters, target pool) is defined here and declared in
 *       brix_fault_proxy_internal.h.
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
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/version.h"

#include "brix_fault_proxy_internal.h"

#define FP_OK    0   /* clean terminal action (--help / --version) or success */
#define FP_RUN   1   /* runtime failure (bind failed) */
#define FP_USAGE 2   /* command-line error */
#define FP_CONTINUE (-1) /* internal: argument parsing/setup ok, keep going */

/* --- Shared mutable state (declared extern in brix_fault_proxy_internal.h) --- */

volatile lever_t g_up;    /* client   -> upstream (request / upload) */
volatile lever_t g_down;  /* upstream -> client   (response / download) */

/* Upstream target pool (round-robin with per-connection failover). */
fp_target g_targets[FP_MAX_TARGETS];
int       g_ntargets = 0;
unsigned  g_rr       = 0;

/* Global (connection-scoped) state. */
volatile int      g_blocked  = 0;   /* refuse new + sever live (outage) */
volatile int      g_hang     = 0;   /* accept new but never relay (black hole) */
volatile int      g_abortive = 0;   /* 1 = auto-severs use RST, 0 = graceful FIN */
volatile int      g_one_shot = 0;   /* clear all levers when a sever fires */
volatile int      g_fail_nth = 0;   /* fail exactly the Nth accepted conn (0=off) */
volatile unsigned g_drop_epoch      = 0;  /* bump => live relays sever */
volatile unsigned g_halfclose_epoch = 0;  /* bump => live relays half-close */
unsigned          g_seed     = 0;   /* base RNG seed (per-thread derived) */
int               g_max_conns = 0;  /* cap on concurrent relays (0=unlimited) */
volatile int      g_toxicity_up_ppm   = 1000000;  /* 100%: afflict every conn by default */
volatile int      g_toxicity_down_ppm = 1000000;
volatile int      g_connect_delay_ms  = 0;
volatile int      g_refuse_ppm         = 0;

/* Traffic / fault counters (test oracle). */
fp_counters C;

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
"      --event-log FILE     append one JSON line per fault event (JSONL audit)\n"
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
"  -h, --help               print this help and exit\n"
"  -V, --version            print version and exit\n"
"\n"
"control commands (write one per connection to the control port):\n"
"  latency <ms> | jitter <ms> | chunk <bytes> | drip <bytes> <ms> | rate <kbps> | burst <bytes>\n"
"  lossy <pct> | reorder <pct> [ms] | corrupt <pct> | dup <pct> | truncate-at <bytes>\n"
"  fail-nth <n> | heal-after <ms> | one-shot | abortive <0|1>\n"
"  drop | reset | half-close | hang | unhang | block | unblock | clear | status\n"
"  toxicity <pct> | slow-close <ms> | connect-delay <ms> | refuse <pct> |\n"
"  latency-dist uniform|normal <mean_ms> [sigma_ms] | metrics | event-log <path>\n"
"  toxic add <name> <type> <params> [dir] | toxic remove <name> | toxic list [json]\n"
"  route add <name> <port> <host:port,...> | route del <name> | route list [json]\n"
"    (append up|down|both to any byte-level lever to target one direction)\n"
"\n"
"Example:\n"
"  brix-fault-proxy --listen 11940 --target cache.example:1094 --control 11941\n"
"  brix-fault-proxy ctl 127.0.0.1:11941 'corrupt 0.01 down'  # tamper the download\n"
"\n"
"The control port is UNAUTHENTICATED and binds to loopback by default; do not\n"
"expose it to an untrusted network.  See man brix-fault-proxy(1).\n");
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

/* The vetted bind template resolved at startup (fp_setup_bind); dynamic routes
 * reuse it via fp_route_bind so they can never widen the loopback/insecure gate. */
static struct sockaddr_storage g_bind_tmpl;
static socklen_t               g_bind_tmpl_len;

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
    };
    char   cmd[256];
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
    case 1017:
        if (fp_event_open(optarg) != 0) {
            fprintf(stderr, "brix-fault-proxy: cannot open event log '%s'\n", optarg);
            return FP_RUN;   /* fail closed at startup (exit 1) */
        }
        break;
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
        {"event-log",     required_argument, NULL, 1017},
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

/* Bind a fresh listen port on the daemon's already-vetted bind address (I4: a
 * route can never widen the gate — it inherits the startup bind template). */
int
fp_route_bind(int port)
{
    return listen_sa(&g_bind_tmpl, g_bind_tmpl_len, port);
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

int
main(int argc, char **argv)
{
    fp_config               cfg = { .bind_str = "127.0.0.1" };
    struct sockaddr_storage bind_ss;
    socklen_t               bind_len;
    int                     rc;

    /* `ctl` is a reserved first-arg client mode; it never collides with the
     * positional LISTEN HOST PORT CONTROL run form (dispatch before parsing). */
    if (argc >= 2 && strcmp(argv[1], "ctl") == 0) {
        return fp_ctl_main(argc, argv);
    }

    reset_lever(&g_up);
    reset_lever(&g_down);

    if ((rc = fp_parse_args(argc, argv, &cfg)) != FP_CONTINUE) {
        return rc;
    }
    if ((rc = fp_setup_bind(cfg.bind_str, cfg.insecure, &bind_ss, &bind_len))
        != FP_CONTINUE) {
        return rc;
    }
    /* Publish the vetted bind template so dynamic routes inherit the gate. */
    g_bind_tmpl     = bind_ss;
    g_bind_tmpl_len = bind_len;

    signal(SIGPIPE, SIG_IGN);

    int lfd   = listen_sa(&bind_ss, bind_len, cfg.listen_port);
    int ctlfd = listen_sa(&bind_ss, bind_len, cfg.control_port);
    if (lfd < 0 || ctlfd < 0) {
        fprintf(stderr, "brix-fault-proxy: bind failed (listen=%d control=%d)\n",
                cfg.listen_port, cfg.control_port);
        return FP_RUN;
    }
    /* Register the legacy path as route "default" (index 0) so `route list` and
     * per-route counters are uniform across the default and dynamic routes. */
    fp_route_register_default(lfd, cfg.listen_port);

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

    return fp_accept_serve(lfd, &g_routes[0]);
}
