/*
 * mpxstats.c — aggregate + pretty-print an XRootD server's summary statistics.
 *
 * WHAT: `mpxstats-brix [host[:port]] [--metrics-port N]` pulls the server's Prometheus
 *       /metrics and prints a compact per-metric summary (series count + summed
 *       value), collapsing the label dimensions. With no host (or "-") it reads a
 *       metrics blob from stdin instead.
 * WHY:  The stock mpxstats relays the xrootd summary-stats stream; this is the
 *       parse-only, libXrdCl-free equivalent over the observability plane this
 *       project already exposes — handy for a one-screen server health glance.
 * HOW:  Reuse brix_http_get (the same cleartext pull `xrddiag status` uses) or
 *       read stdin; parse "name{labels} value" lines (skip # comments), fold by
 *       base metric name into a small table, print it sorted-as-seen.
 *
 * Clean-room: parse-only; no protocol core, no XrdCl.
 */
#include "brix.h"
#include "core/version.h"
#include "core/progname.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MPX_MAX_METRICS 512

typedef struct {
    char   name[160];
    double sum;
    long   series;
} mpx_metric;

static mpx_metric g_tab[MPX_MAX_METRICS];
static int        g_n;

/* Fold one "name{labels} value" sample into the table by base metric name. */
static void
ingest_line(const char *line)
{
    char        name[160];
    const char *p, *val;
    size_t      nl;
    int         i;
    double      v;

    if (line[0] == '#' || line[0] == '\0') {
        return;
    }
    /* base name = up to '{' or the first space */
    p = line;
    while (*p != '\0' && *p != '{' && !isspace((unsigned char) *p)) {
        p++;
    }
    nl = (size_t) (p - line);
    if (nl == 0 || nl >= sizeof(name)) {
        return;
    }
    memcpy(name, line, nl);
    name[nl] = '\0';

    /* value = the last whitespace-separated token on the line */
    val = strrchr(line, ' ');
    if (val == NULL) {
        return;
    }
    v = strtod(val + 1, NULL);

    for (i = 0; i < g_n; i++) {
        if (strcmp(g_tab[i].name, name) == 0) {
            g_tab[i].sum += v;
            g_tab[i].series++;
            return;
        }
    }
    if (g_n < MPX_MAX_METRICS) {
        snprintf(g_tab[g_n].name, sizeof(g_tab[g_n].name), "%s", name);
        g_tab[g_n].sum = v;
        g_tab[g_n].series = 1;
        g_n++;
    }
}

static void
ingest_buffer(char *buf)
{
    char *line, *save;
    for (line = strtok_r(buf, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        ingest_line(line);
    }
}

static void
report(const char *source)
{
    int  i;
    long total = 0;
    printf("mpxstats-brix: %s\n", source);
    printf("%-48s %8s %14s\n", "metric", "series", "sum");
    for (i = 0; i < g_n; i++) {
        printf("%-48s %8ld %14.0f\n", g_tab[i].name, g_tab[i].series, g_tab[i].sum);
        total += g_tab[i].series;
    }
    printf("(%d metric name(s), %ld series)\n", g_n, total);
}

/*
 * usage_fp — print mpxstats usage to the given stream.
 * WHY: --help goes to stdout (WS-2); -h keeps the legacy stderr path (C1).
 *      Both now include the footer. Returns rc so callers can write
 *      `return usage_fp(stderr, prog, 0)`.
 */
static int
usage_fp(FILE *out, const char *prog, int rc)
{
    prog = brix_prog_base(prog);   /* display the invoked name, not a path */
    fprintf(out,
        "usage: %s [host | -] [--metrics-port N]\n"
        "  no host (or '-') reads a /metrics blob from stdin\n",
        prog);
    brix_usage_footer(out, prog);
    return rc;
}

/* WHAT: Parse mpxstats command-line options.
 * WHY: Keep option policy separate from data-source execution.
 * HOW: Update host/port, print immediate help/version, and signal early exit. */
static int
mpx_parse_options(int argc, char **argv, const char **host, int *port,
    int *exit_now)
{
    int i;

    *exit_now = 0;
    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--version") == 0) {
            printf("%s (BriX-Cache client) %s\n", brix_prog_base(argv[0]),
                   brix_client_version());
            *exit_now = 1;
            return 0;
        }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            *exit_now = 1;
            return usage_fp(strcmp(arg, "-h") == 0 ? stderr : stdout,
                            argv[0], 0);
        }
        if (strcmp(arg, "--metrics-port") == 0 && i + 1 < argc) {
            *port = atoi(argv[++i]);
        } else if (*host == NULL) {
            *host = arg;
        }
    }
    return 0;
}


/* WHAT: Ingest a metrics document from standard input.
 * WHY: Support pipelines and saved metric snapshots without a server.
 * HOW: Read a bounded buffer, parse it, report it, and release storage. */
static int
mpx_read_stdin(void)
{
    size_t cap = 1u << 20;
    size_t len = 0;
    size_t n;
    char  *buf = malloc(cap);

    if (buf == NULL) {
        fprintf(stderr, "mpxstats-brix: out of memory\n");
        return 51;
    }
    while ((n = fread(buf + len, 1, cap - 1 - len, stdin)) > 0) {
        len += n;
        if (len >= cap - 1) {
            break;
        }
    }
    buf[len] = '\0';
    ingest_buffer(buf);
    free(buf);
    report("(stdin)");
    return 0;
}


/* WHAT: Fetch, ingest, and report a remote Prometheus document.
 * WHY: Isolate endpoint normalization and network failure cleanup.
 * HOW: Split an optional host port, issue the shared HTTP GET, then summarize. */
static int
mpx_read_remote(const char *host, int metrics_port)
{
    char        server[256];
    char        source[300];
    char       *colon;
    char       *body;
    brix_status status;
    int         http = 0;

    snprintf(server, sizeof(server), "%s", host);
    colon = strrchr(server, ':');
    if (colon != NULL && strchr(server, ':') == colon) {
        *colon = '\0';
        metrics_port = atoi(colon + 1);
    }
    body = malloc(1u << 20);
    if (body == NULL) {
        fprintf(stderr, "mpxstats-brix: out of memory\n");
        return 51;
    }
    brix_status_clear(&status);
    if (brix_http_get(server, metrics_port, "/metrics", 5000, &http, body,
                      1u << 20, NULL, &status) != 0)
    {
        fprintf(stderr, "mpxstats-brix: GET %s:%d/metrics: %s\n", server,
                metrics_port, status.msg);
        free(body);
        return 51;
    }
    ingest_buffer(body);
    free(body);
    snprintf(source, sizeof(source), "%s:%d (HTTP %d)", server, metrics_port,
             http);
    report(source);
    return g_n > 0 ? 0 : 51;
}


/* Real main; dispatched from xrddiag (multi-call, see xrddiag.c). */
int
brix_mpxstats_main(int argc, char **argv)
{
    const char *host = NULL;
    int         metrics_port = 9100;
    int         exit_now;
    int         rc;

    rc = mpx_parse_options(argc, argv, &host, &metrics_port, &exit_now);
    if (exit_now) {
        return rc;
    }

    if (host == NULL || strcmp(host, "-") == 0) {
        return mpx_read_stdin();
    }
    return mpx_read_remote(host, metrics_port);
}
