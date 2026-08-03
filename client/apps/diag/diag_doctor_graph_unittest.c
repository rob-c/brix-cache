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
    s = render(eps, n, "ascii");
    CHECK(has(s, "Mesh topology"));
    CHECK(has(s, "CMS locate"));
    CHECK(has(s, "3 nodes"));
    CHECK(has(s, "manager"));
    CHECK(has(s, "mgr.example.org:1094"));
    CHECK(has(s, "v5.6.3"));
    CHECK(has(s, "40% free"));            /* manager capacity */
    CHECK(has(s, "GREEN"));
    CHECK(has(s, "YELLOW"));              /* ds1 */
    CHECK(has(s, "ds2.example.org:1096"));
    CHECK(has(s, "DOWN"));                /* ds2 not connected */
    CHECK(has(s, "\\-"));                 /* last-branch glyph */
    CHECK(has(s, "|-"));                  /* mid-branch glyph */
    CHECK(has(s, "5% free"));             /* ds1 near-full (50/1000) */
    /* down node ds2 was never scraped → no version/capacity token emitted */
    CHECK(!has(s, "ds2.example.org:1096  v"));
    free(s);

    /* ---- Graphviz DOT ---- */
    s = render(eps, n, "dot");
    CHECK(has(s, "digraph mesh {"));
    CHECK(has(s, "rankdir=TB;"));
    CHECK(has(s, "n0 [label="));
    CHECK(has(s, "shape=box3d"));         /* root distinguished */
    CHECK(has(s, "n0 -> n1;"));
    CHECK(has(s, "n0 -> n2;"));
    CHECK(has(s, "fillcolor=palegreen")); /* green node */
    CHECK(has(s, "fillcolor=khaki"));     /* yellow node */
    CHECK(has(s, "fillcolor=gray"));      /* down node */
    CHECK(has(s, "}"));
    free(s);

    /* ---- Mermaid ---- */
    s = render(eps, n, "mermaid");
    CHECK(has(s, "graph TD"));
    CHECK(has(s, "n0{{\""));              /* root redirector → hexagon */
    CHECK(has(s, "n1[\""));               /* data server → rectangle */
    CHECK(has(s, "n0 --> n1"));
    CHECK(has(s, "n0 --> n2"));
    CHECK(has(s, "classDef green"));
    CHECK(has(s, "classDef down"));
    CHECK(has(s, "class n0 green;"));
    CHECK(has(s, "class n1 yellow;"));
    CHECK(has(s, "class n2 down;"));
    CHECK(has(s, "<br/>"));               /* mermaid line separator */
    free(s);

    /* ---- single-node mesh (manager only) ---- */
    s = render(eps, 1, "ascii");
    CHECK(has(s, "(1 node)"));            /* singular */
    CHECK(!has(s, "|-"));                 /* no branches */
    free(s);

    /* ---- IPv6-only skipped node: SKIP token, not DOWN; distinct fill/class ---- */
    eps[2].skipped = 1;                  /* ds2 becomes skipped (was down) */
    s = render(eps, n, "ascii");
    CHECK(has(s, "SKIP(no IPv6)"));
    CHECK(!has(s, "DOWN"));              /* skipped supersedes DOWN */
    free(s);
    s = render(eps, n, "dot");
    CHECK(has(s, "fillcolor=lightskyblue"));   /* skipped node fill */
    free(s);
    s = render(eps, n, "mermaid");
    CHECK(has(s, "classDef skip"));
    CHECK(has(s, "class n2 skip;"));
    free(s);
    eps[2].skipped = 0;

    /* ---- CMS locate-plane classification: redirector vs data server, ro/rw,
     *      pending — types even an unreachable (skipped) holder. ---- */
    eps[0].cms.reported = 1; eps[0].cms.role = DOC_CMS_MANAGER;
    eps[1].cms.reported = 1; eps[1].cms.role = DOC_CMS_SERVER; eps[1].cms.write = 1;
    eps[2].cms.reported = 1; eps[2].cms.role = DOC_CMS_SERVER; eps[2].cms.write = 0;
    eps[2].cms.pending  = 1; eps[2].skipped = 1;   /* skipped but still typed */
    s = render(eps, n, "ascii");
    CHECK(has(s, "redirector"));           /* eps[0] typed from CMS */
    CHECK(has(s, "data server rw"));       /* eps[1] read/write */
    CHECK(has(s, "data server ro pending"));/* eps[2] read-only, queued */
    CHECK(has(s, "SKIP(no IPv6)"));        /* eps[2] role AND skip both shown */
    free(s);
    s = render(eps, n, "dot");
    CHECK(has(s, "shape=box3d"));          /* redirector shape (root + M nodes) */
    CHECK(has(s, "shape=box,"));           /* data-server shape */
    free(s);
    s = render(eps, n, "mermaid");
    CHECK(has(s, "n0{{\""));               /* redirector hexagon */
    CHECK(has(s, "n1[\""));                /* data server rectangle */
    free(s);
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
