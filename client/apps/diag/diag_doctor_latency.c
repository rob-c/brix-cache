/*
 * diag_doctor_latency.c — mesh round-trip latency probe (phase-93 extension).
 *
 * WHAT: for every server the fan-out discovered, measure round-trip latency over
 *       the two XRootD control planes — the data-server plane (a kXR_stat "/"
 *       round-trip) and the CMS redirect plane (a kXR_locate "/" round-trip, the
 *       query the CMSD answers) — reporting min/avg/max ms per plane. Also the
 *       local-IPv6 capability probe used to skip IPv6-only nodes.
 * WHY:  --latency answers "how far is each node, and is the redirect plane as
 *       responsive as the data plane?" Each sample is a full request→reply, so
 *       the figure is bi-directional (out and back) by construction. Comparing
 *       the two planes surfaces an overloaded manager/CMSD vs a healthy DS.
 * HOW:  pure composition of the public libbrix API (stat/locate) timed with
 *       CLOCK_MONOTONIC — no new wire. PII-free: only cluster-member authorities
 *       and timing scalars, never a path, token, or credential. No goto.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* getaddrinfo AI_* / connect() when built standalone */
#endif
#include "diag_internal.h"


/* 1 when this host can route to the global IPv6 internet. A *connected* UDP
 * socket does a route lookup without emitting a packet; no route → ENETUNREACH.
 * Used to skip IPv6-only mesh nodes that would otherwise report a false DOWN. */
int
doctor_have_ipv6(void)
{
    struct sockaddr_in6 sa;
    int                 fd, rc, err;

    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0;                       /* no AF_INET6 at all */
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port   = htons(53);
    inet_pton(AF_INET6, "2001:4860:4860::8888", &sa.sin6_addr);   /* no packet sent */
    rc  = connect(fd, (struct sockaddr *) &sa, sizeof(sa));
    err = errno;
    close(fd);
    if (rc != 0 && (err == ENETUNREACH || err == EHOSTUNREACH
                    || err == EADDRNOTAVAIL)) {
        return 0;
    }
    return 1;
}


/* 1 when `host` resolves to IPv6 only (or is a v6 literal). Callers pair this
 * with !doctor_have_ipv6() to decide a node is unreachable-by-design here.
 * Unknown/failed lookups return 0 (don't skip — let the real connect speak). */
int
doctor_host_ipv6_only(const char *host)
{
    struct addrinfo  hints, *res, *ai;
    int              have4 = 0, have6 = 0;

    if (host == NULL || host[0] == '\0') {
        return 0;
    }
    if (strchr(host, ':') != NULL) {
        return 1;                       /* bare IPv6 literal */
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) {
        return 0;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET)  { have4 = 1; }
        if (ai->ai_family == AF_INET6) { have6 = 1; }
    }
    freeaddrinfo(res);
    return have6 && !have4;
}


static double
mono_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double) t.tv_sec * 1000.0 + (double) t.tv_nsec / 1e6;
}


/* Fold one timing sample into a min/sum/max accumulator triple. */
static void
lat_fold(double dt, double *sum, int *ok, double *min, double *max)
{
    *sum += dt;
    (*ok)++;
    if (dt < *min) { *min = dt; }
    if (dt > *max) { *max = dt; }
}


/* Data plane: `count` timed stat("/") round-trips. Failures are simply not
 * sampled — l->xr_ok records how many landed. */
static void
lat_sample_stat(brix_conn *c, int count, doctor_lat *l)
{
    int i;

    for (i = 0; i < count; i++) {
        brix_statinfo si;
        brix_status   ps;
        double        t0;

        brix_status_clear(&ps);
        t0 = mono_ms();
        if (brix_stat(c, "/", &si, &ps) == 0) {
            lat_fold(mono_ms() - t0, &l->xr_avg, &l->xr_ok,
                     &l->xr_min, &l->xr_max);
        }
    }
}


/* CMS plane: `count` timed locate("/") round-trips on the same connection. */
static void
lat_sample_locate(brix_conn *c, int count, doctor_lat *l)
{
    int i;

    for (i = 0; i < count; i++) {
        char        loc[4096];
        brix_status ps;
        double      t0;

        brix_status_clear(&ps);
        t0 = mono_ms();
        if (brix_locate(c, "/", loc, sizeof(loc), &ps) == 0) {
            lat_fold(mono_ms() - t0, &l->cms_avg, &l->cms_ok,
                     &l->cms_min, &l->cms_max);
        }
    }
}


/* Probe one reachable node: time `count` stat("/") round-trips (data plane) and
 * `count` locate("/") round-trips (cms plane) on one fresh connection. Skipped or
 * unconnected nodes are left untouched (probed stays 0). */
void
doctor_latency_probe(const diag_args *a, doctor_ep *e)
{
    char        url[320];
    brix_url    u;
    brix_conn   c;
    brix_status st;
    doctor_lat *l     = &e->lat;
    int         count = a->latency_count > 0 ? a->latency_count : 5;
    int         v6;

    if (e->skipped || !e->connected) {
        return;
    }
    l->probed  = 1;
    l->samples = count;

    v6 = (strchr(e->host, ':') != NULL && e->host[0] != '[');
    snprintf(url, sizeof(url), "root://%s%s%s:%d/",
             v6 ? "[" : "", e->host, v6 ? "]" : "", e->port);

    brix_status_clear(&st);
    if (brix_endpoint_parse(url, &u, &st) != 0
        || brix_connect(&c, &u, &a->conn, &st) != 0) {
        return;                         /* probed=1, *_ok=0 → renders "unreachable" */
    }
    c.io.timeout_ms = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;
    l->xr_min = l->cms_min = 1e30;

    lat_sample_stat(&c, count, l);
    lat_sample_locate(&c, count, l);
    if (l->xr_ok)  { l->xr_avg  /= l->xr_ok; }  else { l->xr_min = 0; }
    if (l->cms_ok) { l->cms_avg /= l->cms_ok; } else { l->cms_min = 0; }
    brix_close(&c);
}


/* One "min/avg/max" cell, or a word when the plane produced no sample. */
static void
lat_cell(int ok, double mn, double av, double mx, char *out, size_t osz,
         const char *empty)
{
    if (ok) {
        snprintf(out, osz, "%.2f/%.2f/%.2f", mn, av, mx);
    } else {
        snprintf(out, osz, "%s", empty);
    }
}


void
doctor_render_latency(const doctor_ep *eps, int n, FILE *out)
{
    int i, any = 0;

    for (i = 0; i < n; i++) {
        if (eps[i].lat.probed || eps[i].skipped) { any = 1; break; }
    }
    if (!any) {
        return;
    }
    fprintf(out, "\nMesh latency — bi-directional round-trip per node "
                 "(min/avg/max ms):\n");
    fprintf(out, "  %-42s  %-20s  %-20s\n", "node",
            "xrootd (data plane)", "cms (redirect plane)");
    for (i = 0; i < n; i++) {
        const doctor_lat *l = &eps[i].lat;
        char              node[64], xr[24], cms[24];

        snprintf(node, sizeof(node), "%.48s:%d", eps[i].host, eps[i].port);
        if (eps[i].skipped) {
            fprintf(out, "  %-42s  %s\n", node, "skipped — no local IPv6 route");
            continue;
        }
        if (!l->probed) {
            continue;
        }
        lat_cell(l->xr_ok,  l->xr_min,  l->xr_avg,  l->xr_max,  xr,  sizeof(xr),  "unreachable");
        lat_cell(l->cms_ok, l->cms_min, l->cms_avg, l->cms_max, cms, sizeof(cms), "n/a");
        fprintf(out, "  %-42s  %-20s  %-20s\n", node, xr, cms);
    }
    fprintf(out, "  legend: xrootd = kXR_stat round-trip (data-server plane); "
                 "cms = kXR_locate round-trip (CMSD-answered redirect plane).\n");
}


/* Append a ,"latency":{...} object to the endpoint's JSON (nothing if unprobed). */
void
doctor_emit_latency_json(const doctor_ep *e, FILE *out)
{
    const doctor_lat *l = &e->lat;

    if (!l->probed) {
        return;
    }
    fprintf(out, ",\"latency\":{\"samples\":%d,"
            "\"xrootd\":{\"ok\":%d,\"min_ms\":%.3f,\"avg_ms\":%.3f,\"max_ms\":%.3f},"
            "\"cms\":{\"ok\":%d,\"min_ms\":%.3f,\"avg_ms\":%.3f,\"max_ms\":%.3f}}",
            l->samples, l->xr_ok, l->xr_min, l->xr_avg, l->xr_max,
            l->cms_ok, l->cms_min, l->cms_avg, l->cms_max);
}
