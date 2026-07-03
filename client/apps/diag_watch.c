/*
 * diag_watch.c - extracted concern
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"


/* status — pull /metrics and summarise                                */

int
do_status(const diag_args *a)
{
    brix_url    u;
    brix_status st;
    char       *body;
    int         http = 0, lines = 0, shown = 0;
    char       *line, *save;

    brix_status_clear(&st);
    if (brix_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    body = malloc(1u << 20);
    if (body == NULL) {
        fprintf(stderr, "xrddiag: out of memory\n");
        return 51;
    }
    if (brix_http_get(u.host, a->metrics_port, "/metrics", 5000, &http, body,
                      1u << 20, NULL, &st) != 0) {
        fprintf(stderr, "xrddiag: GET %s:%d/metrics: %s\n",
                u.host, a->metrics_port, st.msg);
        free(body);
        return 51;
    }
    printf("Metrics from %s:%d (HTTP %d)\n", u.host, a->metrics_port, http);
    for (line = strtok_r(body, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        lines++;
        /* show the first handful of non-zero counters as a one-screen sample */
        if (shown < 20 && strstr(line, " 0") != line + (int) strlen(line) - 2) {
            printf("  %s\n", line);
            shown++;
        }
    }
    printf("  ... %d metric series total\n", lines);
    free(body);
    return lines > 0 ? 0 : 51;
}


/* main                                                                */

/* watch — continuous health / SLA probe loop                          */

/* One probe result for one endpoint. PII-free: timings + counts only; the only
 * label is the endpoint the user passed (host:port), never a resolved IP/path. */

/* Set only by the signal handler; the loop polls it and stops cleanly. */

void
watch_on_signal(int sig)
{
    (void) sig;
    g_watch_stop = 1;   /* async-signal-safe: a flag set is all we do */
}


/* Count whitespace/comma-separated tokens (≈ located replica hosts). We only ever
 * emit the COUNT, never the locate buffer, so no host/IP leaks. */
int
watch_count_tokens(const char *s)
{
    int n = 0, in = 0;
    for (; *s != '\0'; s++) {
        int delim = (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n' || *s == ',');
        if (!delim && !in) { in = 1; n++; }
        else if (delim)    { in = 0; }
    }
    return n;
}


/* Escape a Prometheus label value: backslash/quote/newline per the exposition
 * format; any other control byte (\r, \t, …) is dropped so the output is always a
 * single valid line (endpoint labels are host:port, so this is just defensive). */
void
watch_prom_label(const char *s, char *out, size_t osz)
{
    size_t j = 0;
    for (; *s != '\0' && j + 2 < osz; s++) {
        unsigned char ch = (unsigned char) *s;
        if (ch == '\\' || ch == '"') { out[j++] = '\\'; out[j++] = (char) ch; }
        else if (ch == '\n')         { out[j++] = '\\'; out[j++] = 'n'; }
        else if (ch < 0x20)          { continue; }   /* drop \r/\t/other controls */
        else                         { out[j++] = (char) ch; }
    }
    out[j] = '\0';
}


/* Probe one endpoint once: connect (timed), connect-phase split, a tiny read
 * (TTFB), and a locate (replica count). Never aborts the loop — a down endpoint
 * just yields up=0. Always returns 0. */
int
watch_probe_once(const diag_args *a, const char *url, watch_sample *out)
{
    brix_url      u;
    brix_conn     c;
    brix_status   st;
    brix_netfacts f;
    char          target[XRDC_PATH_MAX];
    brix_statinfo sti;
    uint64_t      t0;

    memset(out, 0, sizeof(*out));
    snprintf(out->endpoint, sizeof(out->endpoint), "%s", url);
    out->read_ms = out->locate_ms = -1.0;
    out->holders = -1;
    out->proto = "root";

    brix_status_clear(&st);
    if (brix_endpoint_parse(url, &u, &st) != 0) {
        /* PII-free contract: never let a raw URL's path/query reach a label. */
        snprintf(out->endpoint, sizeof(out->endpoint), "(unparseable)");
        return 0;   /* unparseable → down */
    }
    out->proto = (u.scheme == XRDC_SCHEME_ROOTS) ? "roots" : "root";
    /* Label on host:port only — never the path (PII-free metric/label contract). */
    snprintf(out->endpoint, sizeof(out->endpoint), "%s:%d", u.host, u.port);

    t0 = brix_mono_ns();
    if (brix_connect(&c, &u, &a->conn, &st) != 0) {
        out->connect_ms = (double) (brix_mono_ns() - t0) / 1e6;
        return 0;   /* down — reported, not an error */
    }
    out->up = 1;
    out->connect_ms = (double) (brix_mono_ns() - t0) / 1e6;
    if (a->probe_timeout_ms > 0) { c.io.timeout_ms = a->probe_timeout_ms; }

    brix_netdiag_facts(&c, &f);
    out->tcp_ms = f.tcp_ms;
    out->tls_ms = f.tls_ms;
    out->auth_ms = f.auth_ms;
    {
        const char *ver = NULL, *cipher = NULL;
        out->tls_active = (brix_tls_info(&c, &ver, &cipher) == 1);
    }

    /* tiny read (TTFB) against the biggest regular file under the namespace */
    brix_status_clear(&st);
    if (resolve_target(&c, &u, target, sizeof(target), &sti, &st) == 0) {
        brix_file   fh;
        brix_status rst;
        brix_status_clear(&rst);
        t0 = brix_mono_ns();
        if (brix_file_open_read(&c, target, &fh, &rst) == 0) {
            char    b[4096];
            ssize_t got = brix_file_read(&c, &fh, 0, b, sizeof(b), &rst);
            if (got >= 0) {
                out->read_ms = (double) (brix_mono_ns() - t0) / 1e6;
            }
            brix_file_close(&c, &fh, &rst);
        }
        {
            char        lb[8192];
            brix_status lst;
            uint64_t    l0 = brix_mono_ns();
            brix_status_clear(&lst);
            if (brix_locate(&c, target, lb, sizeof(lb), &lst) == 0) {
                out->locate_ms = (double) (brix_mono_ns() - l0) / 1e6;
                out->holders = watch_count_tokens(lb);
            }
        }
    }
    brix_close(&c);
    return 0;
}


void
watch_emit_human(const watch_sample *s, FILE *out)
{
    fprintf(out, "%-40s up=%d connect=%.1fms", s->endpoint, s->up, s->connect_ms);
    if (s->up) {
        if (s->read_ms >= 0)   { fprintf(out, " read=%.1fms", s->read_ms); }
        if (s->locate_ms >= 0) { fprintf(out, " locate=%.1fms holders=%d",
                                          s->locate_ms, s->holders); }
        fprintf(out, " tls=%d", s->tls_active);
    }
    fputc('\n', out);
}


void
watch_emit_json(const watch_sample *s, FILE *out)
{
    fputs("{\"endpoint\":", out);
    fjson_str(out, s->endpoint);
    fprintf(out, ",\"proto\":\"%s\",\"up\":%d,\"connect_ms\":%.3f,"
                 "\"tcp_ms\":%.3f,\"tls_ms\":%.3f,\"auth_ms\":%.3f,"
                 "\"read_ms\":%.3f,\"locate_ms\":%.3f,\"holders\":%d,\"tls\":%d}\n",
            s->proto, s->up, s->connect_ms, s->tcp_ms, s->tls_ms, s->auth_ms,
            s->read_ms, s->locate_ms, s->holders, s->tls_active);
}


/* One metric line for every sample, with HELP/TYPE printed once per metric. */
void
watch_emit_prom(const watch_sample *samples, int n, FILE *out)
{
    int  i;
    char ep[576], pr[64];

    fputs("# HELP brix_probe_up Endpoint reachable (1) or down (0).\n"
          "# TYPE brix_probe_up gauge\n", out);
    for (i = 0; i < n; i++) {
        watch_prom_label(samples[i].endpoint, ep, sizeof(ep));
        watch_prom_label(samples[i].proto, pr, sizeof(pr));
        fprintf(out, "brix_probe_up{endpoint=\"%s\",proto=\"%s\"} %d\n",
                ep, pr, samples[i].up);
    }
    fputs("# HELP brix_probe_connect_seconds Full connect (TCP+TLS+auth).\n"
          "# TYPE brix_probe_connect_seconds gauge\n", out);
    for (i = 0; i < n; i++) {
        watch_prom_label(samples[i].endpoint, ep, sizeof(ep));
        watch_prom_label(samples[i].proto, pr, sizeof(pr));
        fprintf(out, "brix_probe_connect_seconds{endpoint=\"%s\",proto=\"%s\"} %.6f\n",
                ep, pr, samples[i].connect_ms / 1000.0);
    }
    /* phase split + read/locate only for endpoints that came up */
    fputs("# HELP brix_probe_read_seconds Tiny-read time-to-first-byte.\n"
          "# TYPE brix_probe_read_seconds gauge\n", out);
    for (i = 0; i < n; i++) {
        if (!samples[i].up || samples[i].read_ms < 0) { continue; }
        watch_prom_label(samples[i].endpoint, ep, sizeof(ep));
        watch_prom_label(samples[i].proto, pr, sizeof(pr));
        fprintf(out, "brix_probe_read_seconds{endpoint=\"%s\",proto=\"%s\"} %.6f\n",
                ep, pr, samples[i].read_ms / 1000.0);
    }
    fputs("# HELP brix_probe_locate_holders Located replica count.\n"
          "# TYPE brix_probe_locate_holders gauge\n", out);
    for (i = 0; i < n; i++) {
        if (!samples[i].up || samples[i].holders < 0) { continue; }
        watch_prom_label(samples[i].endpoint, ep, sizeof(ep));
        watch_prom_label(samples[i].proto, pr, sizeof(pr));
        fprintf(out, "brix_probe_locate_holders{endpoint=\"%s\",proto=\"%s\"} %d\n",
                ep, pr, samples[i].holders);
    }
}


/* Write the Prometheus exposition to PATH atomically (tmp + rename) — the
 * node_exporter textfile-collector contract (never expose a half-written file). */
int
watch_write_prom_atomic(const char *path, const watch_sample *samples, int n,
                        brix_status *st)
{
    char  tmp[XRDC_PATH_MAX];
    FILE *f;
    int   fd;

    if ((size_t) snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path) >= sizeof(tmp)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "watch: prometheus path too long");
        return -1;
    }
    fd = mkstemp(tmp);
    if (fd < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "watch: mkstemp %s: %s",
                        path, strerror(errno));
        return -1;
    }
    f = fdopen(fd, "w");
    if (f == NULL) {
        close(fd);
        (void) unlink(tmp);
        brix_status_set(st, XRDC_ESOCK, errno, "watch: fdopen: %s", strerror(errno));
        return -1;
    }
    watch_emit_prom(samples, n, f);
    if (fclose(f) != 0 || rename(tmp, path) != 0) {
        (void) unlink(tmp);
        brix_status_set(st, XRDC_ESOCK, errno, "watch: write %s: %s",
                        path, strerror(errno));
        return -1;
    }
    return 0;
}


/* Interruptible sleep: ~200ms granularity so SIGINT stops promptly. */
void
watch_sleep(int seconds)
{
    int i;
    for (i = 0; i < seconds * 5 && !g_watch_stop; i++) {
        struct timespec ts = { 0, 200L * 1000L * 1000L };
        (void) nanosleep(&ts, NULL);
    }
}


int
do_watch(const diag_args *a)
{
    struct sigaction sa;
    watch_sample     samples[8];
    int              interval = a->interval_s > 0 ? a->interval_s : 10;
    int              cycle = 0, i;

    if (interval > 86400) { interval = 86400; }   /* bound watch_sleep's seconds*5 */

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = watch_on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    while (!g_watch_stop) {
        for (i = 0; i < a->nurls; i++) {
            watch_probe_once(a, a->urls[i], &samples[i]);
        }
        if (a->watch_prom) {
            if (a->prom_path != NULL) {
                brix_status wst;
                brix_status_clear(&wst);
                if (watch_write_prom_atomic(a->prom_path, samples, a->nurls, &wst) != 0) {
                    fprintf(stderr, "xrddiag: %s\n", wst.msg);
                }
            } else {
                watch_emit_prom(samples, a->nurls, stdout);
            }
        } else if (a->json) {
            for (i = 0; i < a->nurls; i++) { watch_emit_json(&samples[i], stdout); }
        } else {
            for (i = 0; i < a->nurls; i++) { watch_emit_human(&samples[i], stdout); }
        }
        fflush(stdout);

        cycle++;
        if (a->count > 0 && cycle >= a->count) { break; }
        if (g_watch_stop) { break; }
        watch_sleep(interval);
    }
    return 0;
}
