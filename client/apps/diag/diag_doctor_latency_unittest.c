/*
 * diag_doctor_latency_unittest.c — standalone unit test for the phase-93 mesh
 * round-trip latency probe: the render/JSON emitters, the IPv6-only classifier,
 * and the probe's unreachable path.
 *
 *   cc -std=c11 -Wall -Wextra -Werror -Ilib -I../src -I../shared \
 *      -DXRDPROTO_NO_NGX apps/diag/diag_doctor_latency_unittest.c -o /tmp/ut \
 *   && /tmp/ut          (run from client/)
 *
 * Exit 0 = all checks pass. Pure C — no server, no libbrix: the TU is #included
 * and its libbrix wire externs are satisfied by trivial stubs. brix_endpoint_parse
 * is stubbed to fail, so doctor_latency_probe exercises its unreachable branch
 * (probed=1, ok=0) deterministically; output is captured to a memstream.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* open_memstream, getaddrinfo */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_internal.h"

/* ---- libbrix wire externs referenced by doctor_latency_probe (never reach the
 *      network here — brix_endpoint_parse fails first). ---- */
void brix_status_clear(brix_status *st) { (void) st; }
int  brix_endpoint_parse(const char *e, brix_url *u, brix_status *s)
{ (void) e; (void) u; (void) s; return -1; }   /* force the unreachable path */
int  brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o, brix_status *s)
{ (void) c; (void) u; (void) o; (void) s; return -1; }
int  brix_stat(brix_conn *c, const char *p, brix_statinfo *si, brix_status *s)
{ (void) c; (void) p; (void) si; (void) s; return -1; }
int  brix_locate(brix_conn *c, const char *p, char *o, size_t n, brix_status *s)
{ (void) c; (void) p; (void) o; (void) n; (void) s; return -1; }
void brix_close(brix_conn *c) { (void) c; }

#include "diag_doctor_latency.c"

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static int has(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }

int
main(void)
{
    doctor_ep eps[3];
    char     *buf = NULL;
    size_t    sz = 0;
    FILE     *ms;
    diag_args a;

    memset(eps, 0, sizeof(eps));
    memset(&a, 0, sizeof(a));

    /* node 0: a healthy probed node with real timings. */
    snprintf(eps[0].host, sizeof(eps[0].host), "mgr.example.org");
    eps[0].port = 1094; eps[0].connected = 1;
    eps[0].lat = (doctor_lat){ .probed = 1, .samples = 5, .xr_ok = 5, .cms_ok = 5,
        .xr_min = 10.5, .xr_avg = 11.25, .xr_max = 12.0,
        .cms_min = 20.0, .cms_avg = 21.5, .cms_max = 24.0 };

    /* node 1: IPv6-only, skipped (no local v6). */
    snprintf(eps[1].host, sizeof(eps[1].host), "2001:db8::5");
    eps[1].port = 1095; eps[1].skipped = 1;

    /* node 2: probed but every sample failed (unreachable plane). */
    snprintf(eps[2].host, sizeof(eps[2].host), "ds2.example.org");
    eps[2].port = 1096; eps[2].connected = 1;
    eps[2].lat.probed = 1; eps[2].lat.samples = 5;   /* xr_ok = cms_ok = 0 */

    /* ---- doctor_render_latency ---- */
    ms = open_memstream(&buf, &sz);
    doctor_render_latency(eps, 3, ms);
    fclose(ms);
    CHECK(has(buf, "Mesh latency"));
    CHECK(has(buf, "bi-directional"));
    CHECK(has(buf, "xrootd (data plane)"));
    CHECK(has(buf, "cms (redirect plane)"));
    CHECK(has(buf, "mgr.example.org:1094"));
    CHECK(has(buf, "10.50/11.25/12.00"));               /* xr min/avg/max */
    CHECK(has(buf, "20.00/21.50/24.00"));               /* cms min/avg/max */
    CHECK(has(buf, "skipped — no local IPv6 route"));   /* node 1 */
    CHECK(has(buf, "unreachable"));                     /* node 2 xr plane */
    CHECK(has(buf, "kXR_stat") && has(buf, "kXR_locate"));  /* legend */
    free(buf); buf = NULL; sz = 0;

    /* render is a no-op when nothing was probed or skipped. */
    memset(eps, 0, sizeof(eps));
    ms = open_memstream(&buf, &sz);
    doctor_render_latency(eps, 3, ms);
    fclose(ms);
    CHECK(buf[0] == '\0');
    free(buf); buf = NULL; sz = 0;

    /* ---- doctor_emit_latency_json ---- */
    eps[0].lat = (doctor_lat){ .probed = 1, .samples = 3, .xr_ok = 3, .cms_ok = 2,
        .xr_min = 1.0, .xr_avg = 2.0, .xr_max = 3.0,
        .cms_min = 4.0, .cms_avg = 5.0, .cms_max = 6.0 };
    ms = open_memstream(&buf, &sz);
    doctor_emit_latency_json(&eps[0], ms);
    fclose(ms);
    CHECK(has(buf, "\"latency\":{"));
    CHECK(has(buf, "\"samples\":3"));
    CHECK(has(buf, "\"xrootd\":{\"ok\":3"));
    CHECK(has(buf, "\"cms\":{\"ok\":2"));
    CHECK(has(buf, "\"min_ms\":1.000"));
    free(buf); buf = NULL; sz = 0;

    /* unprobed endpoint emits no latency object. */
    ms = open_memstream(&buf, &sz);
    doctor_emit_latency_json(&eps[1], ms);   /* skipped, probed=0 */
    fclose(ms);
    CHECK(buf[0] == '\0');
    free(buf); buf = NULL; sz = 0;

    /* ---- doctor_host_ipv6_only ---- */
    CHECK(doctor_host_ipv6_only("2001:db8::1") == 1);   /* v6 literal, no DNS */
    CHECK(doctor_host_ipv6_only("127.0.0.1") == 0);     /* v4 literal → not v6-only */
    CHECK(doctor_host_ipv6_only(NULL) == 0);
    CHECK(doctor_host_ipv6_only("") == 0);

    /* ---- doctor_have_ipv6: smoke — returns a boolean, no crash ---- */
    { int v = doctor_have_ipv6(); CHECK(v == 0 || v == 1); }

    /* ---- doctor_latency_probe unreachable branch (endpoint_parse stubbed to fail):
     *      probed set, no successful samples, no crash. ---- */
    memset(&eps[2].lat, 0, sizeof(eps[2].lat));
    eps[2].connected = 1; eps[2].skipped = 0;
    a.latency_count = 4;
    doctor_latency_probe(&a, &eps[2]);
    CHECK(eps[2].lat.probed == 1);
    CHECK(eps[2].lat.samples == 4);
    CHECK(eps[2].lat.xr_ok == 0 && eps[2].lat.cms_ok == 0);

    /* a skipped node is never probed. */
    memset(&eps[1].lat, 0, sizeof(eps[1].lat));
    eps[1].skipped = 1;
    doctor_latency_probe(&a, &eps[1]);
    CHECK(eps[1].lat.probed == 0);

    if (g_fail) { printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    printf("OK all latency checks passed\n");
    return 0;
}
