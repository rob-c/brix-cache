/*
 * diag_doctor_graph.c — mesh topology diagram renderer (phase-93 extension).
 *
 * WHAT: draw the manager→data-server mesh that doctor_fanout discovered over the
 *       wire (a kXR_locate answer from the manager, i.e. the CMS subscription
 *       view) as an ASCII tree, a Graphviz DOT digraph, or a Mermaid graph.
 * WHY:  the fan-out already builds the topology as a doctor_ep[] (eps[0]=manager,
 *       eps[1..]=located data servers) with each node's scraped role/version/
 *       capacity/health; an operator asked to *see* the mesh, not just read a
 *       per-node table. DOT/Mermaid output is pipeable to `dot -Tpng` / a Mermaid
 *       renderer for a real picture.
 * HOW:  pure formatting over the already-scraped array — no new wire, no
 *       connection. The single edge class is manager→DS (the CMS star the locate
 *       answer expresses). PII-free beyond the cluster-member authorities that
 *       ARE the topology (no path, token, or credential). No goto; early-return.
 */
#include "diag_internal.h"


typedef enum { MAP_ASCII, MAP_DOT, MAP_MERMAID } doctor_map_fmt;

static doctor_map_fmt
doctor_map_format(const char *s)
{
    if (s != NULL && strcmp(s, "dot") == 0) {
        return MAP_DOT;
    }
    if (s != NULL && (strcmp(s, "mermaid") == 0 || strcmp(s, "mmd") == 0)) {
        return MAP_MERMAID;
    }
    return MAP_ASCII;   /* default + explicit "ascii"/"tree" */
}


/* 1 when `format` is a machine graph (dot/mermaid) that should be emitted alone
 * (pipeable, no health-report noise); 0 for the ASCII tree. Used by the fan-out
 * driver to decide whether to also print the per-node report. */
int
doctor_map_graph_only(const char *format)
{
    return doctor_map_format(format) != MAP_ASCII;
}


/* 1 when the node acts as a manager/redirector: the CMS locate answer is
 * authoritative, else a scraped "manager" role, else the connected-to root. */
static int
map_is_redirector(const doctor_ep *e, int is_root)
{
    if (e->cms.reported) {
        return e->cms.role == DOC_CMS_MANAGER;
    }
    if (e->cfg.scraped && strstr(e->cfg.role, "manager") != NULL) {
        return 1;
    }
    return is_root;
}


/* Resolve a node's role descriptor into `buf`. The CMS locate answer types the
 * node even when we could not connect (redirector vs data server); otherwise the
 * scraped Qconfig role, otherwise a generic default. Read/write access and a
 * pending (queued/staging) marker are appended for CMS-reported data servers —
 * this is the "what is it?" data the CMSD gives us for un-connectable hosts. */
static void
map_role(const doctor_ep *e, int is_root, char *buf, size_t bsz)
{
    const doctor_cmsloc *m = &e->cms;
    const char          *base;

    if (e->eos.kind == DOC_EOS_FST) {
        /* an EOS FST enumerated from the MGM — access from configstatus */
        snprintf(buf, bsz, "EOS FST%s", m->write ? " rw" : " ro");
        return;
    }
    if (m->reported) {
        base = (m->role == DOC_CMS_MANAGER) ? "redirector" : "data server";
    } else if (e->cfg.scraped && e->cfg.role[0]
               && strcmp(e->cfg.role, "none") != 0) {
        base = e->cfg.role;
    } else {
        base = is_root ? "manager" : "server";
    }
    snprintf(buf, bsz, "%s%s%s", base,
             (m->reported && m->role == DOC_CMS_SERVER)
                 ? (m->write ? " rw" : " ro") : "",
             (m->reported && m->pending) ? " pending" : "");
}


/* Health verdict (DOC_GREEN/YELLOW/RED) for colouring, EOS-FST-aware: an FST is
 * enumerated from the MGM and never probed inbound, so its health comes from the
 * MGM's booted/active flags rather than a connect result. */
static int
map_health(const doctor_ep *e)
{
    if (e->eos.kind == DOC_EOS_FST) {
        if (e->eos.booted && e->eos.active) { return DOC_GREEN; }
        if (e->eos.booted || e->eos.active) { return DOC_YELLOW; }
        return DOC_RED;
    }
    return e->status;
}


/* Up-to-five short PII-free descriptor tokens for one node:
 * role · host:port · {EOS banner | geotag | version} · "NN% free" · STATUS.
 * Returns the count filled. */
static int
map_fields(const doctor_ep *e, int is_root, char f[5][80])
{
    const doctor_cfg *g = &e->cfg;
    int               pct, k = 0;

    map_role(e, is_root, f[k++], 80);
    snprintf(f[k++], 80, "%.72s:%d", e->host, e->port);
    if (e->eos.kind == DOC_EOS_MGM) {
        snprintf(f[k++], 80, "EOS %.20s v%.12s", e->eos.instance,
                 e->eos.version[0] ? e->eos.version : "?");
    } else if (e->eos.kind == DOC_EOS_FST && e->eos.geotag[0]) {
        snprintf(f[k++], 80, "geo=%.39s", e->eos.geotag);
    } else if (g->scraped && g->version[0]) {
        snprintf(f[k++], 80, "v%s", g->version);
    }
    pct = doctor_cfg_capacity_pct(g->space_total, g->space_free);
    if (pct >= 0) {
        snprintf(f[k++], 80, "%d%% free", pct);
    }
    if (e->eos.kind == DOC_EOS_FST) {
        int h = map_health(e);
        snprintf(f[k++], 80, "%s",
                 h == DOC_RED ? "RED" : h == DOC_YELLOW ? "YELLOW" : "GREEN");
    } else {
        snprintf(f[k++], 80, "%s",
                 e->skipped   ? "SKIP(no IPv6)"
               : e->connected ? doc_color(e->status) : "DOWN");
    }
    return k;
}


/* Join a node's fields with `sep` into one line. */
static void
map_join(const doctor_ep *e, int is_root, const char *sep, char *out, size_t osz)
{
    char f[5][80];
    int  i, k = map_fields(e, is_root, f);
    size_t pos = 0;

    out[0] = '\0';
    for (i = 0; i < k; i++) {
        pos += snprintf(out + pos, (pos < osz) ? osz - pos : 0,
                        "%s%s", i ? sep : "", f[i]);
        if (pos >= osz) {
            break;
        }
    }
}


static void
map_render_ascii(const doctor_ep *eps, int n, FILE *out)
{
    char line[512];
    int  i;

    fprintf(out, "Mesh topology — discovered via CMS locate (%d node%s):\n\n",
            n, n == 1 ? "" : "s");
    map_join(&eps[0], 1, "  ", line, sizeof(line));
    fprintf(out, "  [%s]\n", line);
    for (i = 1; i < n; i++) {
        map_join(&eps[i], 0, "  ", line, sizeof(line));
        fprintf(out, "    %s [%s]\n", (i == n - 1) ? "\\-" : "|-", line);
    }
    fprintf(out, "\n  legend: root = the redirector we connected to; each branch "
                 "is a node it located over CMS — 'redirector' (subordinate "
                 "manager) or 'data server' (rw/ro = write/read access, 'pending' "
                 "= queued/staging). Role/access come from the locate answer, so "
                 "even an unreachable (SKIP) holder is still typed. 'EOS FST' "
                 "nodes come from the MGM's EOS command channel — the admin `fs "
                 "ls` inventory, or (when that is gated for this identity) the "
                 "distinct FSTs named by a sample of files' `fileinfo` replica "
                 "tables — with health from their booted/active flags, not an "
                 "inbound probe.\n");
}


/* Graphviz fill colour per health verdict. */
static const char *
map_fill(const doctor_ep *e)
{
    if (e->skipped) {
        return "lightskyblue";
    }
    if (e->eos.kind == DOC_EOS_FST) {
        int h = map_health(e);   /* MGM-reported, never inbound-probed */
        return h == DOC_RED ? "lightcoral"
             : h == DOC_YELLOW ? "khaki" : "palegreen";
    }
    if (!e->connected) {
        return "gray";
    }
    return e->status == DOC_RED ? "lightcoral"
         : e->status == DOC_YELLOW ? "khaki" : "palegreen";
}


static void
map_render_dot(const doctor_ep *eps, int n, FILE *out)
{
    char label[512];
    int  i;

    fprintf(out, "digraph mesh {\n");
    fprintf(out, "  rankdir=TB;\n");
    fprintf(out, "  node [style=filled, fontname=\"monospace\"];\n");
    for (i = 0; i < n; i++) {
        map_join(&eps[i], i == 0, "\\n", label, sizeof(label));
        fprintf(out, "  n%d [label=\"%s\", shape=%s, fillcolor=%s];\n",
                i, label, map_is_redirector(&eps[i], i == 0) ? "box3d" : "box",
                map_fill(&eps[i]));
    }
    for (i = 1; i < n; i++) {
        fprintf(out, "  n0 -> n%d;\n", i);
    }
    fprintf(out, "}\n");
}


static void
map_render_mermaid(const doctor_ep *eps, int n, FILE *out)
{
    char label[512];
    int  i;

    fprintf(out, "graph TD\n");
    for (i = 0; i < n; i++) {
        map_join(&eps[i], i == 0, "<br/>", label, sizeof(label));
        /* redirectors as a hexagon {{...}}, data servers as a rectangle [...] */
        if (map_is_redirector(&eps[i], i == 0)) {
            fprintf(out, "  n%d{{\"%s\"}}\n", i, label);
        } else {
            fprintf(out, "  n%d[\"%s\"]\n", i, label);
        }
    }
    for (i = 1; i < n; i++) {
        fprintf(out, "  n0 --> n%d\n", i);
    }
    /* colour classes by health verdict */
    fprintf(out, "  classDef red fill:#f8b,stroke:#900;\n");
    fprintf(out, "  classDef yellow fill:#ff8,stroke:#990;\n");
    fprintf(out, "  classDef green fill:#8f8,stroke:#090;\n");
    fprintf(out, "  classDef down fill:#ccc,stroke:#666;\n");
    fprintf(out, "  classDef skip fill:#bde,stroke:#369,stroke-dasharray:4;\n");
    for (i = 0; i < n; i++) {
        int         h = map_health(&eps[i]);
        const char *cls = eps[i].skipped ? "skip"
                        : eps[i].eos.kind == DOC_EOS_FST
                            ? (h == DOC_RED ? "red"
                             : h == DOC_YELLOW ? "yellow" : "green")
                        : !eps[i].connected ? "down"
                        : eps[i].status == DOC_RED ? "red"
                        : eps[i].status == DOC_YELLOW ? "yellow" : "green";
        fprintf(out, "  class n%d %s;\n", i, cls);
    }
}


/* Render the discovered mesh in the requested format. `format` is the
 * --map-format value (NULL/"ascii"/"tree" → ASCII, "dot", "mermaid"/"mmd"). */
void
doctor_render_map(const doctor_ep *eps, int n, const char *format, FILE *out)
{
    if (eps == NULL || n < 1) {
        return;
    }
    switch (doctor_map_format(format)) {
    case MAP_DOT:     map_render_dot(eps, n, out);     break;
    case MAP_MERMAID: map_render_mermaid(eps, n, out); break;
    case MAP_ASCII:
    default:          map_render_ascii(eps, n, out);   break;
    }
}
