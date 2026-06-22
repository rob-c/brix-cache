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
 *       A thin, libXrdCl-free front-end over the public libxrdc — zero new wire.
 * HOW:  xrdc_locate(path) returns space-separated "S<r|w><host>:<port>" holder
 *       tokens (src/manager/registry.c / src/read/locate.c; IPv6 host bracketed).
 *       Parse them, xrdc_query(kXR_Qspace) for free/total, and for --verify open
 *       a fresh session to each holder and xrdc_stat(path): PASS=serves,
 *       GHOST=connects but NotFound, UNREACHABLE=connect fails.
 *
 * Clean-room: composes the public libxrdc API only; the locate token grammar is
 * this project's own (registry.c). No XrdCl / xrdmapc source consulted.
 */
#include "xrdc.h"
#include "compat/crypto.h"
#include "compat/host_split.h"   /* shared host:port parse (libxrdproto) */

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
    return xrootd_split_host_port(rest, host, hsz, port, 1094);
}

/* Build a connectable URL for a parsed holder (numeric/host literal). */
static void
holder_url(const xrdc_opts *o, const char *host, int port, char *out, size_t outsz)
{
    int v6 = (strchr(host, ':') != NULL && host[0] != '[');
    snprintf(out, outsz, "%s://%s%s%s:%d/", o->want_tls ? "roots" : "root",
             v6 ? "[" : "", host, v6 ? "]" : "", port);
}

static int
do_map(const char *url, const xrdc_opts *co, int verify)
{
    xrdc_url    u;
    xrdc_conn   c;
    xrdc_status st;
    char        loc[8192];
    char        space[1024];
    const char *path;
    char       *tok, *save;

    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(url, &u, &st) != 0) {
        fprintf(stderr, "xrdmapc: %s\n", st.msg);
        return 50;
    }
    if (xrdc_connect_resilient(&c, &u, co, &st) != 0) {
        fprintf(stderr, "xrdmapc: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return xrdc_shellcode(&st);
    }
    path = (u.path[0] != '\0') ? u.path : "/";

    if (xrdc_locate(&c, path, loc, sizeof(loc), &st) != 0) {
        fprintf(stderr, "xrdmapc: locate %s: %s\n", path, st.msg);
        xrdc_close(&c);
        return xrdc_shellcode(&st);
    }
    printf("Cluster map for %s:%d  path %s\n", u.host, u.port, path);

    /* Endpoint-level free/total space (best-effort; redirect-aware). */
    {
        xrdc_status sst;
        xrdc_status_clear(&sst);
        if (xrdc_query(&c, kXR_Qspace, path, space, sizeof(space), &sst) == 0
            && space[0] != '\0') {
            printf("Space:   %s\n", space);
        }
    }

    printf("Holders:\n");
    {
        char copy[8192];
        int  n = 0;
        snprintf(copy, sizeof(copy), "%s", loc);
        for (tok = strtok_r(copy, " \t\r\n", &save); tok != NULL;
             tok = strtok_r(NULL, " \t\r\n", &save)) {
            char host[256];
            int  port = 0;
            char rw = '?';
            if (parse_holder(tok, host, sizeof(host), &port, &rw) != 0) {
                continue;
            }
            n++;
            if (!verify) {
                printf("  %s:%d  [%s]\n", host, port,
                       rw == 'w' ? "rw" : "ro");
                continue;
            }
            /* --verify: probe the advertised holder. */
            {
                char        hu[320];
                xrdc_url    hurl;
                xrdc_conn   hc;
                xrdc_status hst;
                holder_url(co, host, port, hu, sizeof(hu));
                xrdc_status_clear(&hst);
                if (xrdc_endpoint_parse(hu, &hurl, &hst) != 0
                    || xrdc_connect(&hc, &hurl, co, &hst) != 0) {
                    printf("  %s:%d  [%s]  UNREACHABLE (%s)\n", host, port,
                           rw == 'w' ? "rw" : "ro", hst.msg);
                    g_ghosts++;
                } else {
                    xrdc_statinfo si;
                    xrdc_status   pst;
                    int           ok;
                    xrdc_status_clear(&pst);
                    ok = (xrdc_stat(&hc, path, &si, &pst) == 0);
                    if (ok) {
                        printf("  %s:%d  [%s]  PASS (%lld bytes)\n", host, port,
                               rw == 'w' ? "rw" : "ro", (long long) si.size);
                    } else {
                        printf("  %s:%d  [%s]  GHOST (advertised, %s)\n", host,
                               port, rw == 'w' ? "rw" : "ro",
                               xrdc_kxr_name(pst.kxr));
                        g_ghosts++;
                    }
                    xrdc_close(&hc);
                }
            }
        }
        if (n == 0) {
            printf("  (none)\n");
        }
        printf("Total: %d holder(s)%s\n", n,
               verify ? (g_ghosts ? "" : ", all serving") : "");
    }

    xrdc_close(&c);
    return g_ghosts ? 1 : 0;
}

static void
usage(void)
{
    fprintf(stderr,
        "usage: xrdmapc [opts] root[s]://host[:port][//path] [--verify]\n"
        "  lists the data servers holding <path> (default /), with r/w + space.\n"
        "  --verify        probe each holder; flag GHOST (advertised, not serving)\n"
        "  opts: --tls --notlsok --noverifyhost --auth <gsi|ztn|krb5|sss|unix>\n");
}

int
main(int argc, char **argv)
{
    xrdc_opts   co;
    const char *url = NULL;
    int         verify = 0, i;

    xrdc_opts_init(&co);
    xrootd_crypto_init();

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1] != '\0' && strcmp(a, "-") != 0) {
            if (strcmp(a, "--verify") == 0)            { verify = 1; }
            else if (xrdc_opts_parse_arg(&co, argc, argv, &i)) { /* common conn flag */ }
            else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(); return 0; }
            else { fprintf(stderr, "xrdmapc: unknown option '%s'\n", a); usage(); return 50; }
        } else if (url == NULL) {
            url = a;
        } else {
            fprintf(stderr, "xrdmapc: too many arguments\n");
            return 50;
        }
    }
    if (url == NULL) {
        usage();
        return 50;
    }
    return do_map(url, &co, verify);
}
