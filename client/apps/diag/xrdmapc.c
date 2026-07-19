/*
 * xrdmapc.c — query a manager/redirector for the live cluster map of a path.
 *
 * WHAT: `xrdmapc [opts] root://host[:port][//path] [--verify]` — asks the
 *       endpoint (a cmsd/manager redirector, or a plain server) which data
 *       servers hold a path, prints them with read/write flag and free space,
 *       and (with --verify) probes each advertised holder to flag GHOST
 *       replicas (advertised but not actually serving) and UNREACHABLE nodes.
 * WHY:  Operational parity with this project's manager/cluster features and the
 *       "ghost replica" failure mode a plain transfer never surfaces (§15.4).
 *       A thin, libXrdCl-free front-end over the public libbrix — zero new wire.
 * HOW:  brix_locate(path) returns space-separated "S<r|w><host>:<port>" holder
 *       tokens (src/net/manager/registry.c / src/protocols/root/read/locate.c; IPv6 host bracketed).
 *       Parse them, brix_query(kXR_Qspace) for free/total, and for --verify open
 *       a fresh session to each holder and brix_stat(path): PASS=serves,
 *       GHOST=connects but NotFound, UNREACHABLE=connect fails.
 *
 * Clean-room: composes the public libbrix API only; the locate token grammar is
 * this project's own (registry.c). No XrdCl / xrdmapc source consulted.
 */
#include "brix.h"
#include "core/compat/crypto.h"
#include "core/compat/host_split.h"   /* shared host:port parse (libxrdproto) */
#include "core/version.h"
#include "core/progname.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_ghosts;

/* Parse one "S<flag><host>:<port>" locate token (host may be "[v6]"). 0 / -1. */
static int
parse_holder(const char *tok, char *host, size_t hsz, int *port, char *rw)
{
    const char *rest;

    if (tok[0] != 'S' || tok[1] == '\0') {
        return -1;
    }
    *rw = tok[1];                 /* 'r' read-capable, 'w' write-capable */
    rest = tok + 2;

    /* shared bracketed-IPv6-aware host:port split (libxrdproto). */
    return brix_split_host_port(rest, host, hsz, port, 1094);
}

/* Build a connectable URL for a parsed holder (numeric/host literal). */
static void
holder_url(const brix_opts *o, const char *host, int port, char *out, size_t outsz)
{
    int v6 = (strchr(host, ':') != NULL && host[0] != '[');
    snprintf(out, outsz, "%s://%s%s%s:%d/", o->want_tls ? "roots" : "root",
             v6 ? "[" : "", host, v6 ? "]" : "", port);
}

/* ---- Print best-effort endpoint free/total space line ----
 *
 * WHAT: Queries the connected endpoint for kXR_Qspace on `path` and, on a
 *       non-empty answer, prints the "Space:" line. Silent on any failure or
 *       empty result (best-effort, redirect-aware) — returns nothing.
 *
 * WHY:  Space reporting is advisory: a manager that cannot answer must not abort
 *       the cluster-map listing, so this is factored out with its own throwaway
 *       status and never propagates an error.
 *
 * HOW:  1. Clear a local status. 2. brix_query(kXR_Qspace). 3. If it succeeds
 *       and the answer buffer is non-empty, print "Space:   <answer>".
 */
static void
print_space(brix_conn *c, const char *path)
{
    char        space[1024];
    brix_status sst;

    brix_status_clear(&sst);
    if (brix_query(c, kXR_Qspace, path, space, sizeof(space), &sst) == 0
        && space[0] != '\0') {
        printf("Space:   %s\n", space);
    }
}

/* ---- Probe one advertised holder and classify it (--verify) ----
 *
 * WHAT: Opens a fresh session to <host:port> and stats `path`, printing one of
 *       PASS (serves, with byte size), GHOST (connects but does not serve), or
 *       UNREACHABLE (connect fails). Increments g_ghosts for GHOST/UNREACHABLE.
 *       Returns nothing.
 *
 * WHY:  The "ghost replica" failure mode (advertised holder that does not serve)
 *       is invisible to a plain transfer; --verify surfaces it by contacting
 *       each holder directly. Isolating the probe keeps the classification and
 *       its g_ghosts side effect in one small, reviewable place.
 *
 * HOW:  1. Build a connectable URL via holder_url(). 2. Parse+connect; on
 *       failure print UNREACHABLE and bump g_ghosts. 3. Otherwise brix_stat():
 *       success → PASS with size; failure → GHOST with the kXR name + bump
 *       g_ghosts. 4. Close the probe session.
 */
static void
probe_holder(const brix_opts *co, const char *path,
             const char *host, int port, char rw)
{
    char        hu[320];
    brix_url    hurl;
    brix_conn   hc;
    brix_status hst;

    holder_url(co, host, port, hu, sizeof(hu));
    brix_status_clear(&hst);
    if (brix_endpoint_parse(hu, &hurl, &hst) != 0
        || brix_connect(&hc, &hurl, co, &hst) != 0) {
        printf("  %s:%d  [%s]  UNREACHABLE (%s)\n", host, port,
               rw == 'w' ? "rw" : "ro", hst.msg);
        g_ghosts++;
        return;
    }

    {
        brix_statinfo si;
        brix_status   pst;
        brix_status_clear(&pst);
        if (brix_stat(&hc, path, &si, &pst) == 0) {
            printf("  %s:%d  [%s]  PASS (%lld bytes)\n", host, port,
                   rw == 'w' ? "rw" : "ro", (long long) si.size);
        } else {
            printf("  %s:%d  [%s]  GHOST (advertised, %s)\n", host,
                   port, rw == 'w' ? "rw" : "ro",
                   brix_kxr_name(pst.kxr));
            g_ghosts++;
        }
        brix_close(&hc);
    }
}

/* ---- Handle one locate token: parse, then list or probe ----
 *
 * WHAT: Parses a single "S<flag><host>:<port>" locate token and, if valid,
 *       prints the holder line (plain ro/rw) or, when `verify` is set, probes
 *       it via probe_holder(). Returns 1 if the token was a valid holder (to be
 *       counted), 0 if it was malformed and skipped.
 *
 * WHY:  Keeps the per-token decision (skip / list / verify) in one place so the
 *       holder loop stays a flat iteration and the counted-holder semantics
 *       (only well-formed tokens count) are expressed once.
 *
 * HOW:  1. parse_holder(); on failure return 0. 2. If not verifying, print the
 *       plain holder line and return 1. 3. Otherwise probe_holder() and return 1.
 */
static int
map_holder(const brix_opts *co, const char *path, const char *tok, int verify)
{
    char host[256];
    int  port = 0;
    char rw = '?';

    if (parse_holder(tok, host, sizeof(host), &port, &rw) != 0) {
        return 0;
    }
    if (!verify) {
        printf("  %s:%d  [%s]\n", host, port, rw == 'w' ? "rw" : "ro");
        return 1;
    }
    probe_holder(co, path, host, port, rw);
    return 1;
}

/* ---- Print the "Holders:" section from a locate answer ----
 *
 * WHAT: Tokenizes the locate answer, dispatches each token to map_holder(),
 *       prints "(none)" when no valid holder was found, and prints the "Total:"
 *       footer (with ", all serving" only when verifying and no ghosts). Returns
 *       nothing; ghost/unreachable counts accumulate in g_ghosts via probes.
 *
 * WHY:  Separates the listing/aggregation loop from connection setup so do_map
 *       reads as a short sequence and the token-counting stays adjacent to the
 *       footer that reports it.
 *
 * HOW:  1. Copy the answer (strtok_r mutates). 2. For each whitespace-delimited
 *       token, add map_holder()'s return to the holder count. 3. Print "(none)"
 *       if zero. 4. Print the "Total:" line, appending ", all serving" only when
 *       verifying with no ghosts.
 */
static void
map_holders(const brix_opts *co, const char *loc, const char *path, int verify)
{
    char  copy[8192];
    char *tok, *save;
    int   n = 0;

    snprintf(copy, sizeof(copy), "%s", loc);
    for (tok = strtok_r(copy, " \t\r\n", &save); tok != NULL;
         tok = strtok_r(NULL, " \t\r\n", &save)) {
        n += map_holder(co, path, tok, verify);
    }
    if (n == 0) {
        printf("  (none)\n");
    }
    printf("Total: %d holder(s)%s\n", n,
           verify ? (g_ghosts ? "" : ", all serving") : "");
}

/* ---- Query and print the cluster map for one endpoint/path ----
 *
 * WHAT: Connects to `url`, locates `path`, and prints the cluster map (header,
 *       best-effort space, holder list). Returns 50 on URL parse error, the
 *       brix_shellcode() of a connect/locate failure, 1 if any ghost/unreachable
 *       holder was seen (--verify), else 0.
 *
 * WHY:  Top-level orchestrator: a flat early-return sequence over the connect →
 *       locate → report steps, with the per-section detail delegated to helpers.
 *
 * HOW:  1. Parse the endpoint URL (error → 50). 2. Connect resiliently (error →
 *       shellcode). 3. Default an empty path to "/". 4. brix_locate() (error →
 *       close + shellcode). 5. Print header, print_space(), map_holders().
 *       6. Close and return 1 if g_ghosts else 0.
 */
static int
do_map(const char *url, const brix_opts *co, int verify)
{
    brix_url    u;
    brix_conn   c;
    brix_status st;
    char        loc[8192];
    const char *path;

    brix_status_clear(&st);
    if (brix_endpoint_parse(url, &u, &st) != 0) {
        fprintf(stderr, "xrdmapc: %s\n", st.msg);
        return 50;
    }
    if (brix_connect_resilient(&c, &u, co, &st) != 0) {
        fprintf(stderr, "xrdmapc: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return brix_shellcode(&st);
    }
    path = (u.path[0] != '\0') ? u.path : "/";

    if (brix_locate(&c, path, loc, sizeof(loc), &st) != 0) {
        fprintf(stderr, "xrdmapc: locate %s: %s\n", path, st.msg);
        brix_close(&c);
        return brix_shellcode(&st);
    }
    printf("Cluster map for %s:%d  path %s\n", u.host, u.port, path);

    print_space(&c, path);
    printf("Holders:\n");
    map_holders(co, loc, path, verify);

    brix_close(&c);
    return g_ghosts ? 1 : 0;
}

static void
usage_fp(FILE *out, const char *prog)
{
    prog = brix_prog_base(prog);   /* display the invoked name, not a path */
    fprintf(out,
        "usage: %s [opts] root[s]://host[:port][//path] [--verify]\n"
        "  lists the data servers holding <path> (default /), with r/w + space.\n"
        "  --verify        probe each holder; flag GHOST (advertised, not serving)\n"
        "  opts: --tls --notlsok --noverifyhost --auth <gsi|ztn|krb5|sss|unix>\n"
        "        --version  print version and exit\n",
        prog);
    brix_usage_footer(out, prog);
}

static void
usage(const char *prog)
{
    usage_fp(stderr, prog);
}

int
main(int argc, char **argv)
{
    brix_opts   co;
    const char *url = NULL;
    int         verify = 0, i;

    brix_opts_init(&co);
    brix_crypto_init();

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1] != '\0' && strcmp(a, "-") != 0) {
            if (strcmp(a, "--verify") == 0) {
                verify = 1;
            } else {
                int pr = brix_opts_parse_arg(&co, argc, argv, &i);
                if (pr == 2) { usage_fp(stdout, argv[0]); return 0; }  /* --help */
                if (pr)      { /* common conn flag, already handled */ }
                else if (strcmp(a, "-h") == 0) { usage(argv[0]); return 0; }  /* C1 */
                else { fprintf(stderr, "xrdmapc: unknown option '%s'\n", a); usage(argv[0]); return 50; }
            }
        } else if (url == NULL) {
            url = a;
        } else {
            fprintf(stderr, "xrdmapc: too many arguments\n");
            return 50;
        }
    }
    if (url == NULL) {
        usage(argv[0]);
        return 50;
    }
    return do_map(url, &co, verify);
}
