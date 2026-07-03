/*
 * xrd_clockskew.c - extracted concern
 * Phase-38 split of xrd.c; behavior-identical.
 */
#include "xrd_internal.h"


/* Format an epoch as "YYYY-MM-DD HH:MM:SSZ" (UTC), or "?" when unset. */
void
xrd_fmt_epoch(long e, char *buf, size_t sz)
{
    time_t    t = (time_t) e;
    struct tm tmv;
    if (e == 0 || gmtime_r(&t, &tmv) == NULL) { snprintf(buf, sz, "?"); return; }
    strftime(buf, sz, "%Y-%m-%d %H:%M:%SZ", &tmv);
}


/* |x| for a double, avoiding a libm dependency. */
double
xrd_fabs(double x) { return x < 0.0 ? -x : x; }


/* Parse an HTTP IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT") to epoch, locale-free.
 * 0 / -1. */
int
xrd_parse_http_date(const char *s, time_t *out)
{
    static const char *MON = "JanFebMarAprMayJunJulAugSepOctNovDec";
    struct tm   tmv;
    char        mname[8];
    const char *m;
    int         d = 0, y = 0, hh = 0, mm = 0, ss = 0;

    memset(&tmv, 0, sizeof(tmv));
    if (sscanf(s, "%*3s, %d %3s %d %d:%d:%d", &d, mname, &y, &hh, &mm, &ss) != 6) {
        return -1;
    }
    m = strstr(MON, mname);
    if (m == NULL || (int) ((m - MON) % 3) != 0) { return -1; }
    tmv.tm_mday = d; tmv.tm_mon = (int) ((m - MON) / 3); tmv.tm_year = y - 1900;
    tmv.tm_hour = hh; tmv.tm_min = mm; tmv.tm_sec = ss;
    *out = timegm(&tmv);
    return (*out == (time_t) -1) ? -1 : 0;
}


/* Clock skew via an HTTP(S)/WebDAV endpoint's Date response header (read-only). */
int
xrd_clockskew_http(const char *endpoint, xrd_probe *p, char *err, size_t errsz)
{
    brix_weburl     w;
    brix_http_resp  resp;
    brix_status     st;
    struct timespec t0, t1;
    char            date[128];
    time_t          srv;
    double          rtt_s, local_mid;

    if (brix_weburl_parse(endpoint, &w) != 0) { snprintf(err, errsz, "bad URL"); return -1; }
    clock_gettime(CLOCK_REALTIME, &t0);
    brix_status_clear(&st);
    if (brix_http_req(w.host, w.port, w.tls, "HEAD", w.path[0] ? w.path : "/",
                      NULL, NULL, 0, 5000, 0 /*verify off for a clock probe*/,
                      NULL, &resp, &st) != 0) {
        snprintf(err, errsz, "%s", st.msg);
        return -1;
    }
    clock_gettime(CLOCK_REALTIME, &t1);
    if (!brix_http_header(&resp, "Date", date, sizeof(date))
        || xrd_parse_http_date(date, &srv) != 0) {
        snprintf(err, errsz, "no parseable Date header");
        brix_http_resp_free(&resp);
        return -1;
    }
    brix_http_resp_free(&resp);
    rtt_s     = (double) (t1.tv_sec - t0.tv_sec) + (double) (t1.tv_nsec - t0.tv_nsec) / 1e9;
    local_mid = (double) t0.tv_sec + (double) t0.tv_nsec / 1e9 + rtt_s / 2.0;
    p->clock_have   = 1;
    p->clock_method = "HTTP Date header (1s granularity)";
    p->server_epoch = (long) srv;
    p->offset_s     = (double) srv - local_mid;
    p->rtt_ms       = rtt_s * 1000.0;
    return 0;
}


/* Clock skew via root://: create a temp file (server stamps mtime with its wall
 * clock), stat it, compare to the local clock, then remove it. Needs write access. */
int
xrd_clockskew_root(const char *endpoint, const brix_opts *o, xrd_probe *p,
                   char *err, size_t errsz)
{
    brix_url      u;
    brix_conn     c;
    brix_status   st;
    brix_file     f;
    brix_statinfo si;
    char          tmp[128];
    time_t        t0, t1;

    brix_status_clear(&st);
    if (brix_endpoint_parse(endpoint, &u, &st) != 0) { snprintf(err, errsz, "%s", st.msg); return -1; }
    if (brix_connect(&c, &u, o, &st) != 0) { snprintf(err, errsz, "connect: %s", st.msg); return -1; }
    snprintf(tmp, sizeof(tmp), "/.xrd_clockskew_%ld", (long) getpid());
    t0 = time(NULL);
    if (brix_file_open_write(&c, tmp, 1 /*force*/, 0, &f, &st) != 0) {
        snprintf(err, errsz, "need an HTTP endpoint or write access (%s)", st.msg);
        brix_close(&c);
        return -1;
    }
    brix_file_close(&c, &f, &st);
    if (brix_stat(&c, tmp, &si, &st) != 0) {
        snprintf(err, errsz, "stat: %s", st.msg);
        { brix_status rs; brix_status_clear(&rs); brix_rm(&c, tmp, &rs); }
        brix_close(&c);
        return -1;
    }
    t1 = time(NULL);
    { brix_status rs; brix_status_clear(&rs); brix_rm(&c, tmp, &rs); }
    p->clock_have   = 1;
    p->clock_method = "root:// touch+stat (1s granularity)";
    p->server_epoch = (long) si.mtime;
    p->offset_s     = (double) si.mtime - ((double) t0 + (double) t1) / 2.0;
    p->rtt_ms       = (double) (t1 - t0) * 1000.0;
    brix_close(&c);
    return 0;
}


/* Measure client↔server clock skew: HTTP Date for web URLs, touch+stat for root://. */
int
xrd_measure_clock_skew(const char *endpoint, const brix_opts *o, xrd_probe *p,
                       char *err, size_t errsz)
{
    if (brix_is_web_url(endpoint)) {
        return xrd_clockskew_http(endpoint, p, err, errsz);
    }
    return xrd_clockskew_root(endpoint, o, p, err, errsz);
}


/* `xrd clockskew <endpoint>` — report client↔server clock offset and RTT. Warns past
 * 60 s (token exp/nbf + GSI validity start failing); exits nonzero past 5 min. */
int
xrd_clockskew(int argc, char **argv)
{
    const char *endpoint = (argc >= 3 && argv[2][0] != '-') ? argv[2] : NULL;
    brix_opts   o;
    xrd_probe   p;
    char        err[XRDC_MSG_MAX + 64] = "", sb[32];   /* room for a prefixed msg */
    double      ao;

    if (endpoint == NULL) { fprintf(stderr, "usage: xrd clockskew <endpoint>\n"); return 50; }
    memset(&o, 0, sizeof(o)); o.verify_host = 1;
    memset(&p, 0, sizeof(p));
    brix_crypto_init();
    if (xrd_measure_clock_skew(endpoint, &o, &p, err, sizeof(err)) != 0 || !p.clock_have) {
        fprintf(stderr, "xrd clockskew: %s\n", err[0] ? err : "unavailable");
        return 1;
    }
    ao = xrd_fabs(p.offset_s);
    xrd_fmt_epoch(p.server_epoch, sb, sizeof(sb));
    printf("server time:  %s  (%s)\n", sb, p.clock_method);
    printf("clock offset: %+.1f s  (server is %s the client)\n", p.offset_s,
           p.offset_s > 0.5 ? "ahead of" : (p.offset_s < -0.5 ? "behind" : "in sync with"));
    printf("round-trip:   %.1f ms\n", p.rtt_ms);
    if (ao > 60.0) {
        printf("WARNING: >60s skew — bearer-token exp/nbf and GSI/proxy validity "
               "checks may reject you\n");
    }
    return (ao > 300.0) ? 1 : 0;
}
