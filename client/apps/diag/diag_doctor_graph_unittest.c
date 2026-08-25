/*
 * diag_doctor_graph_unittest.c — standalone unit test for the phase-93 mesh
 * topology diagram renderer (ASCII tree / Graphviz DOT / Mermaid).
 *
 *   cc -std=c11 -Wall -Wextra -Werror -Ilib -I../src -I../shared \
 *      -DXRDPROTO_NO_NGX apps/diag/diag_doctor_graph_unittest.c -o /tmp/ut \
 *   && /tmp/ut          (run from client/)
 *
 * Exit 0 = all checks pass. Pure C — no server, no connection, no libbrix: the
 * TU under test is #included and its two externs (doc_color, capacity_pct) are
 * satisfied by trivial stubs here. Output is captured to a memstream and the
 * shape asserted per format.
 */
#define _GNU_SOURCE   /* open_memstream */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_internal.h"

/* ---- extern stubs (the graph TU calls exactly these two). ---- */
const char *
doc_color(int s)
{
    return s == DOC_RED ? "RED" : s == DOC_YELLOW ? "YELLOW" : "GREEN";
}

int
doctor_cfg_capacity_pct(int64_t total, int64_t freeb)
{
    if (total <= 0 || freeb < 0) {
        return -1;
    }
    return (int) ((freeb * 100) / total);
}

#include "diag_doctor_graph.c"

/* ---- harness ---- */
static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* True when haystack contains needle. */
static int
has(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

/* Build a 3-node mesh: manager(GREEN) + server(GREEN) + down server. */
static int
build_mesh(doctor_ep *eps)
{
    memset(eps, 0, sizeof(doctor_ep) * 3);

    snprintf(eps[0].host, sizeof(eps[0].host), "mgr.example.org");
    eps[0].port = 1094;
    eps[0].connected = 1;
    eps[0].status = DOC_GREEN;
    eps[0].cfg.scraped = 1;
    snprintf(eps[0].cfg.role, sizeof(eps[0].cfg.role), "manager");
    snprintf(eps[0].cfg.version, sizeof(eps[0].cfg.version), "5.6.3");
    eps[0].cfg.space_total = 1000;
    eps[0].cfg.space_free  = 400;

    snprintf(eps[1].host, sizeof(eps[1].host), "ds1.example.org");
    eps[1].port = 1095;
    eps[1].connected = 1;
    eps[1].status = DOC_YELLOW;
    eps[1].cfg.scraped = 1;
    snprintf(eps[1].cfg.role, sizeof(eps[1].cfg.role), "server");
    snprintf(eps[1].cfg.version, sizeof(eps[1].cfg.version), "5.6.3");
    eps[1].cfg.space_total = 1000;
    eps[1].cfg.space_free  = 50;

    snprintf(eps[2].host, sizeof(eps[2].host), "ds2.example.org");
    eps[2].port = 1096;
    eps[2].connected = 0;    /* down: no scrape */
    eps[2].status = DOC_RED;

    return 3;
}

/* Render `format` to a heap string (caller frees). */
static char *
render(const doctor_ep *eps, int n, const char *format)
{
    char   *buf = NULL;
    size_t  sz = 0;
    FILE   *ms = open_memstream(&buf, &sz);
    doctor_render_map(eps, n, format, ms);
    fclose(ms);
    return buf;
}

/* Render `format` and check each expectation token in the NULL-terminated
 * list: a leading '!' means the token must be ABSENT from the rendering.
 * Frees the rendering; failures name the offending token. */
static void
render_expect(const doctor_ep *eps, int n, const char *format, ...)
{
    char       *s = render(eps, n, format);
    va_list     ap;
    const char *tok;

    va_start(ap, format);
    while ((tok = va_arg(ap, const char *)) != NULL) {
        int absent = tok[0] == '!';
        if (absent ? has(s, tok + 1) : !has(s, tok)) {
            printf("FAIL %s render: %s '%s'\n", format,
                   absent ? "unexpected" : "missing", tok + absent);
            g_fail++;
        }
    }
    va_end(ap);
    free(s);
}

int
main(void)
{
    doctor_ep eps[3];
    int       n = build_mesh(eps);
    char     *s;

    /* ---- format classifier ---- */
    CHECK(doctor_map_graph_only("dot") == 1);
    CHECK(doctor_map_graph_only("mermaid") == 1);
    CHECK(doctor_map_graph_only("mmd") == 1);
    CHECK(doctor_map_graph_only("ascii") == 0);
    CHECK(doctor_map_graph_only(NULL) == 0);
    CHECK(doctor_map_graph_only("tree") == 0);   /* unknown → ASCII */

    /* ---- ASCII tree ---- */
    render_expect(eps, n, "ascii",
                  "Mesh topology", "CMS locate", "3 nodes", "manager",
                  "mgr.example.org:1094", "v5.6.3",
                  "40% free",                     /* manager capacity */
                  "GREEN",
                  "YELLOW",                       /* ds1 */
                  "ds2.example.org:1096",
                  "DOWN",                         /* ds2 not connected */
                  "\\-",                          /* last-branch glyph */
                  "|-",                           /* mid-branch glyph */
                  "5% free",                      /* ds1 near-full (50/1000) */
                  /* down node ds2 was never scraped → no version/capacity
                   * token emitted */
                  "!ds2.example.org:1096  v",
                  NULL);

    /* ---- Graphviz DOT ---- */
    render_expect(eps, n, "dot",
                  "digraph mesh {", "rankdir=TB;", "n0 [label=",
                  "shape=box3d",                  /* root distinguished */
                  "n0 -> n1;", "n0 -> n2;",
                  "fillcolor=palegreen",          /* green node */
                  "fillcolor=khaki",              /* yellow node */
                  "fillcolor=gray",               /* down node */
                  "}",
                  NULL);

    /* ---- Mermaid ---- */
    render_expect(eps, n, "mermaid",
                  "graph TD",
                  "n0{{\"",                       /* root redirector → hexagon */
                  "n1[\"",                        /* data server → rectangle */
                  "n0 --> n1", "n0 --> n2",
                  "classDef green", "classDef down",
                  "class n0 green;", "class n1 yellow;", "class n2 down;",
                  "<br/>",                        /* mermaid line separator */
                  NULL);

    /* ---- single-node mesh (manager only) ---- */
    render_expect(eps, 1, "ascii",
                  "(1 node)",                     /* singular */
                  "!|-",                          /* no branches */
                  NULL);

    /* ---- IPv6-only skipped node: SKIP token, not DOWN; distinct fill/class ---- */
    eps[2].skipped = 1;                  /* ds2 becomes skipped (was down) */
    render_expect(eps, n, "ascii",
                  "SKIP(no IPv6)",
                  "!DOWN",                        /* skipped supersedes DOWN */
                  NULL);
    render_expect(eps, n, "dot",
                  "fillcolor=lightskyblue",       /* skipped node fill */
                  NULL);
    render_expect(eps, n, "mermaid",
                  "classDef skip", "class n2 skip;", NULL);
    eps[2].skipped = 0;

    /* ---- CMS locate-plane classification: redirector vs data server, ro/rw,
     *      pending — types even an unreachable (skipped) holder. ---- */
    eps[0].cms.reported = 1; eps[0].cms.role = DOC_CMS_MANAGER;
    eps[1].cms.reported = 1; eps[1].cms.role = DOC_CMS_SERVER; eps[1].cms.write = 1;
    eps[2].cms.reported = 1; eps[2].cms.role = DOC_CMS_SERVER; eps[2].cms.write = 0;
    eps[2].cms.pending  = 1; eps[2].skipped = 1;   /* skipped but still typed */
    render_expect(eps, n, "ascii",
                  "redirector",                   /* eps[0] typed from CMS */
                  "data server rw",               /* eps[1] read/write */
                  "data server ro pending",       /* eps[2] read-only, queued */
                  "SKIP(no IPv6)",                /* role AND skip both shown */
                  NULL);
    render_expect(eps, n, "dot",
                  "shape=box3d",                  /* redirector (root + M nodes) */
                  "shape=box,",                   /* data-server shape */
                  NULL);
    render_expect(eps, n, "mermaid",
                  "n0{{\"",                       /* redirector hexagon */
                  "n1[\"",                        /* data server rectangle */
                  NULL);
    memset(&eps[0].cms, 0, sizeof(eps[0].cms));
    memset(&eps[1].cms, 0, sizeof(eps[1].cms));
    memset(&eps[2].cms, 0, sizeof(eps[2].cms));
    eps[2].skipped = 0;

    /* ---- defensive: empty / NULL render nothing, no crash ---- */
    s = render(eps, 0, "ascii");
    CHECK(s[0] == '\0');
    free(s);

    if (g_fail) {
        printf("%d CHECK(s) FAILED\n", g_fail);
        return 1;
    }
    printf("OK all graph-renderer checks passed\n");
    return 0;
}
