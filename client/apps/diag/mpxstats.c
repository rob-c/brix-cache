/*
 * mpxstats.c — aggregate + pretty-print an XRootD server's summary statistics.
 *
 * WHAT: `mpxstats [host[:port]] [--metrics-port N]` pulls the server's Prometheus
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
    printf("mpxstats: %s\n", source);
    printf("%-48s %8s %14s\n", "metric", "series", "sum");
    for (i = 0; i < g_n; i++) {
        printf("%-48s %8ld %14.0f\n", g_tab[i].name, g_tab[i].series, g_tab[i].sum);
        total += g_tab[i].series;
    }
    printf("(%d metric name(s), %ld series)\n", g_n, total);
}

/* Real main; dispatched from xrddiag (multi-call, see xrddiag.c). */
int
brix_mpxstats_main(int argc, char **argv)
{
    const char *host = NULL;
    int         metrics_port = 9100;
    int         i;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--metrics-port") == 0 && i + 1 < argc) {
            metrics_port = atoi(argv[++i]);
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            fprintf(stderr, "usage: mpxstats [host | -] [--metrics-port N]\n"
                            "  no host (or '-') reads a /metrics blob from stdin\n");
            return 0;
        } else if (host == NULL) {
            host = a;
        }
    }

    if (host == NULL || strcmp(host, "-") == 0) {
        /* stdin */
        char  *buf;
        size_t cap = 1u << 20, len = 0, r;
        buf = (char *) malloc(cap);
        if (buf == NULL) {
            fprintf(stderr, "mpxstats: out of memory\n");
            return 51;
        }
        while ((r = fread(buf + len, 1, cap - 1 - len, stdin)) > 0) {
            len += r;
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

    {
        /* strip a host:port → host + port override */
        char        h[256];
        char       *colon;
        char       *body;
        brix_status st;
        int         http = 0;
        snprintf(h, sizeof(h), "%s", host);
        colon = strrchr(h, ':');
        if (colon != NULL && strchr(h, ':') == colon) {   /* host:port (not v6) */
            *colon = '\0';
            metrics_port = atoi(colon + 1);
        }
        body = (char *) malloc(1u << 20);
        if (body == NULL) {
            fprintf(stderr, "mpxstats: out of memory\n");
            return 51;
        }
        brix_status_clear(&st);
        if (brix_http_get(h, metrics_port, "/metrics", 5000, &http, body,
                          1u << 20, NULL, &st) != 0) {
            fprintf(stderr, "mpxstats: GET %s:%d/metrics: %s\n", h, metrics_port,
                    st.msg);
            free(body);
            return 51;
        }
        ingest_buffer(body);
        free(body);
        {
            char src[300];
            snprintf(src, sizeof(src), "%s:%d (HTTP %d)", h, metrics_port, http);
            report(src);
        }
        return g_n > 0 ? 0 : 51;
    }
}
