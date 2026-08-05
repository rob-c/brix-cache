/* brix_fault_cli.c — usage text, argument parsing and listener setup.
 *
 * WHAT: Everything that runs before the first byte is relayed: --help text, target
 *       parsing, the loopback-gated bind vetting, listener creation, and the
 *       option parsers that translate flags into lever commands.
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
#include "brix_fault_priv.h"
#include "brix_fault_oracle.h"
#include "core/version.h"
#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void
usage(FILE *out)
{
    fprintf(out,
"usage: brix-fault-proxy --listen PORT --target HOST:PORT [--target ...] --control PORT [options]\n"
"       brix-fault-proxy LISTEN_PORT TARGET_HOST TARGET_PORT CONTROL_PORT   (positional)\n"
"       brix-fault-proxy ctl HOST:PORT \"<command>\" | -   (control-port client)\n"
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
"      --event-log FILE     append a JSONL trail of discrete fault events\n"
"                           (sever/refuse) for offline analysis\n"
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
"  event-log <path>   (redirect the JSONL fault-event trail live)\n"
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

/* Add one "host:port" (or a comma-separated list) to the target pool. */
int
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

int
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
int
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

/* Route an initial-lever long option (--latency, --block, …) through the same
 * command parser as the live control port. Returns 1 if `opt` was a lever
 * option (handled), 0 otherwise so the core option switch can claim it. */
int
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
        {1050, "idle-reap"},   {1051, "eat-100-continue"},
        {1052, "rst-after"},   {1053, "max-bytes"}, {1054, "drop-fin"},
        {1055, "classify-throttle"}, {1056, "hello-split-reset"},
        {1057, "syn-drop"},    {1058, "alg-rewrite"},
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
/* The options that only store a value — no validation, no output, no way to
 * fail. Kept apart from the ones that act so each half stays reviewable.
 * Returns 1 if `opt` was one of them. */
static int
fp_store_core_opt(int opt, fp_config *cfg)
{
    switch (opt) {
    case 'l': cfg->listen_port = atoi(optarg); break;
    case 'c': cfg->control_port = atoi(optarg); break;
    case 'b': cfg->bind_str = optarg; break;
    case 'I': cfg->insecure = 1; break;
    case 'q': cfg->quiet = 1; break;
    case 1014: g_seed = (unsigned) strtoul(optarg, NULL, 0); break;
    case 1015: g_max_conns = atoi(optarg); break;
    case 1016: cfg->script_path = optarg; break;
    case 1017: cfg->privileged = 1; break;
    case 1018: cfg->priv_iface = optarg; break;
    case 1045: cfg->event_log = optarg; break;
    case 1046: cfg->udp_spec = optarg; break;
    default: return 0;
    }
    return 1;
}

int
fp_apply_core_opt(int opt, fp_config *cfg)
{
    if (fp_store_core_opt(opt, cfg)) {
        return FP_CONTINUE;
    }
    switch (opt) {
    case 't':
        return add_target(optarg) == 0 ? FP_CONTINUE : FP_USAGE;
    case 1040:
        fp_oracle_enable();
        return FP_CONTINUE;
    case 'h':
        usage(stdout);
        return FP_OK;
    case 'V':
        printf("brix-fault-proxy (BriX-Cache client) %s\n", brix_client_version());
        return FP_OK;
    default:
        usage(stderr);
        return FP_USAGE;
    }
}

/* Fold any positional arguments into `cfg` and validate the required config.
 *
 * Positional back-compat: `brix-fault-proxy LISTEN HOST PORT CONTROL`.
 * Accepted only when no --listen/--target/--control were given, so the two
 * calling conventions never half-mix into a confusing partial config. */
int
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
int
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
        {"event-log",     required_argument, NULL, 1045},
        {"udp",           required_argument, NULL, 1046},
        {"idle-reap",     required_argument, NULL, 1050},
        {"eat-100-continue", required_argument, NULL, 1051},
        {"rst-after",     required_argument, NULL, 1052},
        {"max-bytes",     required_argument, NULL, 1053},
        {"drop-fin",      required_argument, NULL, 1054},
        {"classify-throttle", required_argument, NULL, 1055},
        {"hello-split-reset", required_argument, NULL, 1056},
        {"syn-drop",      required_argument, NULL, 1057},
        {"alg-rewrite",   required_argument, NULL, 1058},
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
int
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

/* Route mechanism: bind a listener on the one vetted (loopback-gated) bind
 * address at `port`.  A dynamic route reuses g_bind_ss verbatim — only the port
 * differs — so it can never widen the unauthenticated control plane's exposure. */
int
fp_core_bind_listen(int port)
{
    return listen_sa(&g_bind_ss, g_bind_len, port);
}
