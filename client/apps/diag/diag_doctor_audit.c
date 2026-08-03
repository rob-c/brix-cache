/*
 * diag_doctor_audit.c — remote config & performance advisor (phase-93).
 *
 * WHAT: scrape a remote endpoint's advertised configuration (kXR_Qconfig) and
 *       capacity (kXR_Qspace), classify the scraped *values* into actionable
 *       findings, promote the existing perf/shedding signals into machine-
 *       readable diagnosis records, and — for a manager — fan out to every
 *       located data server and diff the fleet for uniformity.
 * WHY:  the detect→advise spine (DX_RULES + dx_record + the renderers) already
 *       classifies error *codes*; config/perf faults are *values*, so this TU
 *       adds the value-predicate checks and the federation view without growing
 *       diag_doctor.c past the file-size guard.
 * HOW:  doctor_scrape_config fills doctor_ep.cfg over a live root:// connection;
 *       doctor_audit_rules / doctor_audit_perf record the §6.1–§6.3 findings;
 *       doctor_cross_cluster records the §5.3 fleet diffs onto eps[0];
 *       doctor_fanout discovers DSs from a manager's locate answer. PII-free
 *       (only advertised scalars, never a path); no goto; early-return.
 */
#include "diag_internal.h"
#include "core/compat/host_split.h"   /* brix_split_host_port(): DS token parse */
#include "posix/posix_map.h"          /* brix_parse_qspace(): Qspace byte totals */


/* ---- pure value predicates (unit-testable; no server, no connection) ---- */

/* Parse a "chksum" CSV value-line ("adler32,crc32c,…") into the two flags the
 * config-chksum rule needs. Either flag is 0 when its algorithm is absent. */
void
doctor_cfg_parse_chksum(const char *csv, int *have_adler32, int *have_crc32c)
{
    *have_adler32 = (csv != NULL && strstr(csv, "adler32") != NULL) ? 1 : 0;
    *have_crc32c  = (csv != NULL && strstr(csv, "crc32c")  != NULL) ? 1 : 0;
}


/* Free-space percentage (0..100), or -1 when capacity is unknown/unusable. */
int
doctor_cfg_capacity_pct(int64_t total, int64_t freeb)
{
    if (total <= 0 || freeb < 0) {
        return -1;
    }
    if (freeb > total) {
        freeb = total;
    }
    return (int) (freeb * 100 / total);
}


/* Effective capacity-low threshold: the --cap-threshold value, or 5% default. */
int
doctor_cfg_cap_threshold(const diag_args *a)
{
    return (a != NULL && a->cap_threshold_pct > 0) ? a->cap_threshold_pct : 5;
}


/* Count of scraped nodes (index >= 1) whose version differs from eps[0]. */
int
doctor_cfg_version_skew(const doctor_ep *eps, int n)
{
    int i, skew = 0;

    if (n < 2 || eps[0].cfg.version[0] == '\0') {
        return 0;
    }
    for (i = 1; i < n; i++) {
        if (!eps[i].cfg.scraped || eps[i].cfg.version[0] == '\0') {
            continue;
        }
        if (strcmp(eps[i].cfg.version, eps[0].cfg.version) != 0) {
            skew++;
        }
    }
    return skew;
}


/* Count of scraped nodes advertising role == "manager". */
int
doctor_cfg_manager_count(const doctor_ep *eps, int n)
{
    int i, m = 0;

    for (i = 0; i < n; i++) {
        if (eps[i].cfg.scraped && strcmp(eps[i].cfg.role, "manager") == 0) {
            m++;
        }
    }
    return m;
}


/* ---- wire scrape (kXR_Qconfig / kXR_Qspace) ---- */

/*
 * WHAT: fetch one Qconfig key's value-line, "" if unsupported/unanswered.
 * HOW:  strip at '=' or '\n' exactly as xrd_probe_caps does; a server that
 *       echoes the key name verbatim does NOT support it (→ "").
 */
static void
qc_val(brix_conn *c, const char *key, char *out, size_t osz)
{
    char        reply[256], *nl, *eq;
    const char *val;
    brix_status st;

    out[0] = '\0';
    brix_status_clear(&st);
    if (brix_query(c, kXR_Qconfig, key, reply, sizeof(reply), &st) != 0) {
        return;
    }
    if ((nl = strchr(reply, '\n')) != NULL) {
        *nl = '\0';
    }
    eq  = strchr(reply, '=');
    val = (eq != NULL) ? eq + 1 : reply;
    if (strcmp(val, key) == 0) {   /* echo == key ⇒ unsupported/absent */
        return;
    }
    snprintf(out, osz, "%s", val);
}


/* Fetch one integer-valued Qconfig key, or -1 when absent/unsupported. */
static int
qc_int(brix_conn *c, const char *key)
{
    char v[64];

    qc_val(c, key, v, sizeof(v));
    return v[0] != '\0' ? atoi(v) : -1;
}


/* Populate e->cfg from a live root:// connection. Best-effort + PII-free: an
 * unanswered/unsupported key leaves its field at the "absent" sentinel. */
void
doctor_scrape_config(brix_conn *c, doctor_ep *e)
{
    doctor_cfg        *g = &e->cfg;
    char               csv[256];
    unsigned long long tot = 0, freeb = 0;
    char               sp[512];
    brix_status        st;

    g->scraped = 1;
    g->bind_max = g->pio_max = g->readv_iov_max = g->readv_ior_max = -1;
    g->space_total = g->space_free = -1;

    qc_val(c, "version",  g->version,  sizeof(g->version));
    qc_val(c, "role",     g->role,     sizeof(g->role));
    qc_val(c, "sitename", g->sitename, sizeof(g->sitename));
    qc_val(c, "chksum",   csv,         sizeof(csv));
    doctor_cfg_parse_chksum(csv, &g->have_adler32, &g->have_crc32c);
    g->tpc    = qc_int(c, "tpc")    > 0 ? 1 : 0;
    g->tpcdlg = qc_int(c, "tpcdlg") > 0 ? 1 : 0;
    g->pgread = qc_int(c, "pgread") > 0 ? 1 : 0;
    g->bind_max      = qc_int(c, "bind_max");
    g->pio_max       = qc_int(c, "pio_max");
    g->readv_iov_max = qc_int(c, "readv_iov_max");
    g->readv_ior_max = qc_int(c, "readv_ior_max");

    /* capacity: kXR_Qspace is rpCheck'd server-side — pass an absolute path. */
    brix_status_clear(&st);
    if (brix_query(c, kXR_Qspace, "/", sp, sizeof(sp), &st) == 0 && sp[0] != '\0') {
        brix_parse_qspace(sp, &tot, &freeb);
        if (tot > 0) {
            g->space_total = (int64_t) tot;
            g->space_free  = (int64_t) freeb;
        }
    }
}


/* ---- computed single-endpoint rules (§6.1 config + §6.2 capacity) ---- */

void
doctor_audit_rules(const diag_args *a, doctor_ep *e)
{
    doctor_cfg *g = &e->cfg;
    int         pct;

    if (!g->scraped) {
        return;
    }
    if (!g->have_adler32 && !g->have_crc32c) {
        dx_record(e, &(dx_note){ "config-chksum", DX_WARN, 0,
            "no common checksum algorithm advertised (no adler32/crc32c)",
            "enable adler32 or crc32c so clients can verify data integrity" });
    }
    if (!g->tpc || !g->tpcdlg) {
        dx_record(e, &(dx_note){ "config-tpc", DX_WARN, 0,
            "third-party copy not fully advertised (tpc/tpcdlg)",
            "enable tpc (and tpcdlg delegation) if this endpoint takes part in TPC" });
    }
    if (g->sitename[0] == '\0') {
        dx_record(e, &(dx_note){ "config-sitename", DX_WARN, 0,
            "sitename is unset",
            "set a sitename for monitoring/attribution across the federation" });
    }
    if (g->bind_max >= 0 && g->bind_max < 4) {
        dx_record(e, &(dx_note){ "config-parallel", DX_WARN, 0,
            "server-side parallelism is capped low (bind_max < 4)",
            "raise bind_max / readv limits if clients need more parallel streams" });
    }
    pct = doctor_cfg_capacity_pct(g->space_total, g->space_free);
    if (pct >= 0 && pct < doctor_cfg_cap_threshold(a)) {
        dx_record(e, &(dx_note){ "capacity-low", DX_WARN, 0,
            "export filesystem is nearly full",
            "free space or add capacity before writes fail with kXR_NoSpace" });
    }
}


/* ---- §6.3 promotion: existing perf/shedding signals → dx_record findings ---- */

void
doctor_audit_perf(doctor_ep *e)
{
    if (e->nf.have_tcpinfo && e->nf.retrans > 0) {
        dx_record(e, &(dx_note){ "perf-retrans", DX_WARN, 0,
            "TCP retransmits observed on the path",
            "check the network path, MTU, and NIC offloads between client and server" });
    }
    if (e->have_xfer && e->xfer_bytes >= (4 << 20) && e->nf.have_tcpinfo
        && e->nf.rtt_us > 0 && e->nf.rtt_us < 5000 && e->mbps < 5.0) {
        dx_record(e, &(dx_note){ "perf-throughput", DX_WARN, 0,
            "low throughput at low RTT (possible window/stream limit)",
            "check window sizing / stream count / server load (cwnd/BDP)" });
    }
    if (e->shedding) {
        dx_record(e, &(dx_note){ "perf-shedding", DX_WARN, 0,
            "server is shedding load (kXR_wait / budget)",
            "reduce client concurrency or scale the server" });
    }
}


/* ---- §5.3 fleet-uniformity diffs (recorded onto eps[0]) ---- */

/* Capacity-balance: flag a DS whose free%% deviates > 25 points from the fleet
 * mean (DS nodes are index >= 1). Records one capacity-imbalance WARN. */
static void
doctor_cluster_balance(doctor_ep *eps, int n, FILE *out)
{
    int    i, cnt = 0, sum = 0, mean, pct, outliers = 0;

    for (i = 1; i < n; i++) {
        pct = doctor_cfg_capacity_pct(eps[i].cfg.space_total, eps[i].cfg.space_free);
        if (pct >= 0) { sum += pct; cnt++; }
    }
    if (cnt < 2) {
        return;
    }
    mean = sum / cnt;
    for (i = 1; i < n; i++) {
        pct = doctor_cfg_capacity_pct(eps[i].cfg.space_total, eps[i].cfg.space_free);
        if (pct >= 0 && (pct - mean > 25 || mean - pct > 25)) { outliers++; }
    }
    if (out != NULL) {
        fprintf(out, "  capacity balance: mean=%d%% free, %d outlier(s)\n",
                mean, outliers);
    }
    if (outliers > 0) {
        dx_record(&eps[0], &(dx_note){ "cap-imbalance", DX_WARN, 0,
            "data-server free space is unbalanced across the cluster",
            "rebalance data or check a stuck/degraded data server" });
    }
}


/* Cross-node fleet diff: version skew, manager-role count, capacity balance.
 * Records findings onto eps[0]; prints a human summary only when out != NULL. */
void
doctor_cross_cluster(doctor_ep *eps, int n, FILE *out)
{
    int skew, mgrs;

    if (n < 2) {
        return;
    }
    skew = doctor_cfg_version_skew(eps, n);
    mgrs = doctor_cfg_manager_count(eps, n);
    if (out != NULL) {
        fprintf(out, "Cluster analysis (%d node(s)):\n", n);
        fprintf(out, "  manager-role count=%d, version-skewed DS(s)=%d\n",
                mgrs, skew);
    }
    if (skew > 0) {
        dx_record(&eps[0], &(dx_note){ "config-version", DX_WARN, 0,
            "mixed server versions across the cluster",
            "align server versions to avoid protocol/parity gaps" });
    }
    if (mgrs != 1) {
        dx_record(&eps[0], &(dx_note){ "config-role", DX_FAIL, 0,
            "cluster does not advertise exactly one manager role",
            "correct the role directive so exactly one node is the manager" });
    }
    doctor_cluster_balance(eps, n, out);
}


/* ---- renderers (config block: text + JSON) ---- */

void
doctor_report_config(const doctor_ep *e)
{
    const doctor_cfg *g = &e->cfg;
    int               pct;

    if (!g->scraped) {
        return;
    }
    printf("  config: version=%s role=%s site=%s tpc=%d/%d chksum=%s%s%s pgread=%d\n",
           g->version[0]  ? g->version  : "?",
           g->role[0]     ? g->role     : "?",
           g->sitename[0] ? g->sitename : "(unset)",
           g->tpc, g->tpcdlg,
           g->have_adler32 ? "adler32" : "",
           (g->have_adler32 && g->have_crc32c) ? "," : "",
           g->have_crc32c ? "crc32c" : (g->have_adler32 ? "" : "(none)"),
           g->pgread);
    if (g->bind_max >= 0 || g->pio_max >= 0 || g->readv_iov_max >= 0) {
        printf("  config: bind_max=%d pio_max=%d readv_iov_max=%d\n",
               g->bind_max, g->pio_max, g->readv_iov_max);
    }
    if (g->space_total > 0) {
        pct = doctor_cfg_capacity_pct(g->space_total, g->space_free);
        printf("  capacity: %lld / %lld bytes free (%d%% free)\n",
               (long long) g->space_free, (long long) g->space_total, pct);
    }
}


void
doctor_emit_config_json(const doctor_ep *e, FILE *out)
{
    const doctor_cfg *g = &e->cfg;

    fprintf(out, ",\"config\":");
    if (!g->scraped) {
        fprintf(out, "null");
        return;
    }
    fprintf(out, "{\"version\":");
    fjson_str(out, g->version);
    fprintf(out, ",\"role\":");
    fjson_str(out, g->role);
    fprintf(out, ",\"sitename\":");
    fjson_str(out, g->sitename);
    fprintf(out, ",\"tpc\":%d,\"tpcdlg\":%d,\"have_adler32\":%s,"
            "\"have_crc32c\":%s,\"bind_max\":%d,\"pio_max\":%d,"
            "\"readv_iov_max\":%d,\"pgread\":%d,"
            "\"space_total\":%lld,\"space_free\":%lld}",
            g->tpc, g->tpcdlg, g->have_adler32 ? "true" : "false",
            g->have_crc32c ? "true" : "false", g->bind_max, g->pio_max,
            g->readv_iov_max, g->pgread,
            (long long) g->space_total, (long long) g->space_free);
}


/* ---- §5.3 manager fan-out (manager → N located data servers) ---- */

#define DOCTOR_FANOUT_CAP 33   /* [0]=manager + up to 32 data servers */

/* Classify one kXR_locate token "<type><access>host:port" into its CMS-plane
 * role/access and split out host/port. The type byte is the manager's own word
 * on what the node is: 'S'/'s' data server, 'M'/'m' subordinate manager
 * (redirector); lowercase means pending (queued/staging). The access byte is
 * 'r' (read-only) or 'w' (read/write). Returns 0 on a recognised location, -1
 * when the token is not one (unknown type byte or unparseable host). */
static int
doctor_locate_classify(const char *tok, doctor_cmsloc *cms,
                       char *host, size_t hsz, int *port)
{
    char t0;

    if (tok == NULL || tok[0] == '\0' || tok[1] == '\0') {
        return -1;
    }
    t0 = tok[0];
    if (t0 == 'S' || t0 == 's') {
        cms->role = DOC_CMS_SERVER;
    } else if (t0 == 'M' || t0 == 'm') {
        cms->role = DOC_CMS_MANAGER;
    } else {
        return -1;                              /* not a location entry */
    }
    cms->pending  = (t0 >= 'a' && t0 <= 'z');   /* lowercase => queued/staging */
    cms->write    = (tok[1] == 'w');
    cms->reported = 1;
    if (brix_split_host_port(tok + 2, host, hsz, port, 1094) != 0) {
        return -1;
    }
    return 0;
}

/* Turn one CMS locate token into endpoint slot `slot`. Returns 0 when the slot
 * was filled, -1 when the token names nothing we can classify.
 *
 * The classification comes from the locate token itself — data server vs
 * redirector, read-only vs read/write, online vs pending. That is the authority
 * for what the node IS even when we can never open an inbound connection to it,
 * so an IPv6-only holder on a v4-only host is recorded SKIPPED (not a red
 * connect failure) with its CMS verdict intact. */
static int
fanout_add_ds(const diag_args *a, char *tok, doctor_ep *slot, int lv6)
{
    doctor_cmsloc cms;
    char          host[256], dsurl[320];
    int           port, v6;

    memset(&cms, 0, sizeof(cms));
    if (doctor_locate_classify(tok, &cms, host, sizeof(host), &port) != 0) {
        return -1;
    }
    v6 = (strchr(host, ':') != NULL && host[0] != '[');
    if (!lv6 && (v6 || doctor_host_ipv6_only(host))) {
        slot->proto   = DXP_ROOT;
        snprintf(slot->host, sizeof(slot->host), "%s", host);
        slot->port    = port;
        slot->skipped = 1;
        slot->cms     = cms;
        return 0;
    }
    snprintf(dsurl, sizeof(dsurl), "root://%s%s%s:%d/",
             v6 ? "[" : "", host, v6 ? "]" : "", port);
    doctor_one(a, dsurl, slot);
    slot->cms = cms;   /* re-apply: doctor_one zeroes the endpoint */
    return 0;
}


/* Fill arr[1..] from a fresh locate on "/" against the manager. Returns the new
 * endpoint count (1 when the manager cannot be re-connected or locates nothing)
 * and sets *more when the fleet overflowed DOCTOR_FANOUT_CAP. */
static int
fanout_discover(const diag_args *a, doctor_ep *arr, int lv6, int *more)
{
    brix_url    u;
    brix_conn   c;
    brix_status st;
    char        loc[4096];
    char       *t, *save;
    int         n = 1;

    brix_status_clear(&st);
    if (brix_endpoint_parse(a->urls[0], &u, &st) != 0
        || brix_connect(&c, &u, &a->conn, &st) != 0) {
        return n;
    }
    c.io.timeout_ms = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;
    brix_status_clear(&st);
    if (brix_locate(&c, "/", loc, sizeof(loc), &st) == 0) {
        for (t = strtok_r(loc, " \t\r\n", &save); t != NULL;
             t = strtok_r(NULL, " \t\r\n", &save)) {
            if (n >= DOCTOR_FANOUT_CAP) {
                *more = 1;
                break;
            }
            if (fanout_add_ds(a, t, &arr[n], lv6) == 0) {
                n++;
            }
        }
    }
    brix_close(&c);
    return n;
}


/* Turn a manager URL (a->urls[0]) into eps[0]=manager + eps[1..) data servers.
 * Heap-allocates the endpoint array (caller frees). Returns 0 on success, -1 on
 * allocation failure; *truncated is set when the DS list exceeded the cap. */
int
doctor_fanout(const diag_args *a, doctor_ep **eps_out, int *n_out, int *truncated)
{
    doctor_ep  *arr;
    int         n = 1, more = 0;
    int         lv6 = doctor_have_ipv6();   /* skip IPv6-only DSs if local v6 is down */

    *truncated = 0;
    *eps_out   = NULL;
    *n_out     = 0;
    arr = calloc(DOCTOR_FANOUT_CAP, sizeof(*arr));
    if (arr == NULL) {
        return -1;
    }

    /* [0] = the manager itself — full battery + config scrape via dispatch. */
    doctor_dispatch(a, a->urls[0], &arr[0]);

    /* discover data servers from a fresh locate on "/". */
    n = fanout_discover(a, arr, lv6, &more);

    /* The node we connected to answered a locate with other hosts — it is, by
     * that act, acting as a manager/redirector. Record that on the CMS plane so
     * the map types the root correctly even when its Qconfig role is opaque
     * (e.g. EOS reports role=none). A lone node that located only itself stays
     * unclassified and renders as a standalone server. */
    if (n > 1) {
        arr[0].cms.role     = DOC_CMS_MANAGER;
        arr[0].cms.reported = 1;
    }

    /* EOS dialect: if urls[0] is an EOS MGM, speak its /proc command channel to
     * replace the locate-blind self-node with the real FST farm (or mark the MGM
     * admin-gated when enumeration is not permitted for this identity). Runs only
     * for --map and leaves a non-EOS mesh untouched. */
    if (doctor_eos_map(a, arr, DOCTOR_FANOUT_CAP, &n)) {
        more = 1;
    }

    *truncated = more;
    *eps_out   = arr;
    *n_out     = n;
    return 0;
}
