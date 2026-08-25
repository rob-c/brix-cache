/*
 * diag_doctor_audit_unittest.c — standalone unit test for the phase-93
 * config/performance advisor value-predicates and record-emitting rules.
 *
 *   cc -std=c11 -Wall -Wextra -Werror -Ilib -I../src -I../shared \
 *      -DXRDPROTO_NO_NGX apps/diag/diag_doctor_audit_unittest.c -o /tmp/ut \
 *   && /tmp/ut          (run from client/)
 *
 * Exit 0 = all checks pass. Pure C — no server, no connection, no libbrix: the
 * TU under test is #included and the ~dozen wire/render externs it references
 * are satisfied by trivial stubs here. dx_record is stubbed to a recorder so the
 * computed rules (audit_rules / cross_cluster) can be asserted by probe id.
 */
#define _GNU_SOURCE   /* strtok_r in doctor_fanout (matches the real build) */
#include "diag_doctor_ut_common.h"

/* ---- extern stubs (never reached by the pure predicates; audit/cross-cluster
 *      reach only dx_record, which we record into the endpoint). The common
 *      brix_status_clear / brix_query stubs come from the shared header. ---- */
void brix_parse_qspace(const char *t, unsigned long long *tot, unsigned long long *fr)
{ (void) t; *tot = 0; *fr = 0; }
/* Minimal host:port / [v6]:port splitter (real enough for doctor_locate_classify;
 * the shipped brix_split_host_port lives in libbrix, which this TU does not link). */
int
brix_split_host_port(const char *in, char *h, size_t hs, int *p, int d)
{
    const char *colon;
    size_t      hl;

    *p = d;
    if (in[0] == '[') {                     /* [v6]:port */
        const char *close = strchr(in, ']');
        if (close == NULL) { return -1; }
        hl = (size_t) (close - in - 1);
        if (hl == 0 || hl >= hs) { return -1; }
        memcpy(h, in + 1, hl);
        h[hl] = '\0';
        if (close[1] == ':') { *p = atoi(close + 2); }
        return 0;
    }
    colon = strrchr(in, ':');
    if (colon == in) { return -1; }         /* empty host */
    if (colon != NULL) {
        hl = (size_t) (colon - in);
        if (hl >= hs) { return -1; }
        memcpy(h, in, hl);
        h[hl] = '\0';
        *p = atoi(colon + 1);
    } else if (in[0] == '\0') {
        return -1;
    } else {
        snprintf(h, hs, "%s", in);
    }
    return 0;
}
int  brix_endpoint_parse(const char *e, brix_url *u, brix_status *s)
{ (void) e; (void) u; (void) s; return -1; }
int  brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o, brix_status *s)
{ (void) c; (void) u; (void) o; (void) s; return -1; }
int  brix_locate(brix_conn *c, const char *p, char *o, size_t n, brix_status *s)
{ (void) c; (void) p; (void) o; (void) n; (void) s; return -1; }
void brix_close(brix_conn *c) { (void) c; }
void fjson_str(FILE *o, const char *s) { (void) o; (void) s; }
void doctor_dispatch(const diag_args *a, const char *u, doctor_ep *e)
{ (void) a; (void) u; (void) e; }
void doctor_one(const diag_args *a, const char *u, doctor_ep *e)
{ (void) a; (void) u; (void) e; }
/* IPv6-skip helpers doctor_fanout consults (diag_doctor_latency.c). Stubbed to
 * "local IPv6 works" so the fan-out never takes its skip branch under test. */
int  doctor_have_ipv6(void) { return 1; }
int  doctor_host_ipv6_only(const char *h) { (void) h; return 0; }
/* EOS-dialect enrichment doctor_fanout calls at the tail (diag_doctor_eos.c);
 * stubbed to a no-op — the fan-out logic under test is protocol-agnostic. */
int  doctor_eos_map(const diag_args *a, doctor_ep *arr, int cap, int *n)
{ (void) a; (void) arr; (void) cap; (void) n; return 0; }

/* dx_record recorder: store each finding's probe id + verdict into e->dx[]. */
void
dx_record(doctor_ep *e, const dx_note *n)
{
    if (e->ndx >= DOC_MAXDX) {
        return;
    }
    snprintf(e->dx[e->ndx].probe, sizeof(e->dx[e->ndx].probe), "%s", n->probe);
    e->dx[e->ndx].verdict = n->verdict;
    e->ndx++;
}

#define DIAG_AUDIT_UNITTEST_HOST 1
#include "diag_doctor_audit.c"

/* ---- harness ---- */
static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* True when endpoint e recorded a finding with probe id `probe`. */
static int
recorded(const doctor_ep *e, const char *probe)
{
    int i;
    for (i = 0; i < e->ndx; i++) {
        if (strcmp(e->dx[i].probe, probe) == 0) {
            return 1;
        }
    }
    return 0;
}


static void
test_parse_chksum(void)
{
    int a, c;

    doctor_cfg_parse_chksum("adler32,crc32c", &a, &c);
    CHECK(a == 1 && c == 1);
    doctor_cfg_parse_chksum("adler32", &a, &c);
    CHECK(a == 1 && c == 0);
    doctor_cfg_parse_chksum("crc32c", &a, &c);
    CHECK(a == 0 && c == 1);
    doctor_cfg_parse_chksum("md5,sha256", &a, &c);
    CHECK(a == 0 && c == 0);
    doctor_cfg_parse_chksum("", &a, &c);
    CHECK(a == 0 && c == 0);
    doctor_cfg_parse_chksum(NULL, &a, &c);
    CHECK(a == 0 && c == 0);
}


static void
test_capacity_pct(void)
{
    CHECK(doctor_cfg_capacity_pct(0, 10) == -1);      /* unknown total    */
    CHECK(doctor_cfg_capacity_pct(-1, 10) == -1);     /* bad total        */
    CHECK(doctor_cfg_capacity_pct(100, -1) == -1);    /* unknown free     */
    CHECK(doctor_cfg_capacity_pct(100, 0) == 0);      /* full             */
    CHECK(doctor_cfg_capacity_pct(100, 5) == 5);
    CHECK(doctor_cfg_capacity_pct(100, 50) == 50);
    CHECK(doctor_cfg_capacity_pct(100, 100) == 100);
    CHECK(doctor_cfg_capacity_pct(100, 250) == 100);  /* clamp free>total */
}


static void
test_cap_threshold(void)
{
    diag_args a;
    memset(&a, 0, sizeof(a));

    CHECK(doctor_cfg_cap_threshold(NULL) == 5);       /* default          */
    a.cap_threshold_pct = 0;
    CHECK(doctor_cfg_cap_threshold(&a) == 5);         /* 0 => default     */
    a.cap_threshold_pct = 10;
    CHECK(doctor_cfg_cap_threshold(&a) == 10);
    a.cap_threshold_pct = -3;
    CHECK(doctor_cfg_cap_threshold(&a) == 5);         /* <=0 => default   */
}


static void
test_version_skew_and_managers(void)
{
    doctor_ep eps[4];
    memset(eps, 0, sizeof(eps));

    /* n < 2 => no skew regardless of contents. */
    snprintf(eps[0].cfg.version, sizeof(eps[0].cfg.version), "5.6.0");
    CHECK(doctor_cfg_version_skew(eps, 1) == 0);

    /* eps[0]=5.6.0 baseline; [1] same, [2] differs, [3] not scraped. */
    eps[1].cfg.scraped = 1; snprintf(eps[1].cfg.version, 48, "5.6.0");
    eps[2].cfg.scraped = 1; snprintf(eps[2].cfg.version, 48, "5.5.0");
    eps[3].cfg.scraped = 0; snprintf(eps[3].cfg.version, 48, "9.9.9");
    CHECK(doctor_cfg_version_skew(eps, 4) == 1);

    /* empty baseline version => cannot judge skew. */
    eps[0].cfg.version[0] = '\0';
    CHECK(doctor_cfg_version_skew(eps, 4) == 0);

    /* manager count: [0] manager, [1] server, [2] manager (scraped only). */
    snprintf(eps[0].cfg.role, sizeof(eps[0].cfg.role), "manager");
    eps[0].cfg.scraped = 1;
    snprintf(eps[1].cfg.role, 24, "server");
    snprintf(eps[2].cfg.role, 24, "manager");
    CHECK(doctor_cfg_manager_count(eps, 4) == 2);
}


/* audit_rules fires config-sitename/chksum/tpc/parallel/capacity on bad config. */
static void
test_audit_rules(void)
{
    diag_args a;
    doctor_ep e;
    memset(&a, 0, sizeof(a));
    memset(&e, 0, sizeof(e));

    /* not scraped => nothing recorded. */
    doctor_audit_rules(&a, &e);
    CHECK(e.ndx == 0);

    /* worst-case config: no chksum, no tpc, no sitename, low parallelism,
     * capacity 3% free with default 5% threshold. */
    e.cfg.scraped = 1;
    e.cfg.have_adler32 = e.cfg.have_crc32c = 0;
    e.cfg.tpc = e.cfg.tpcdlg = 0;
    e.cfg.sitename[0] = '\0';
    e.cfg.bind_max = 2;
    e.cfg.space_total = 100;
    e.cfg.space_free = 3;
    doctor_audit_rules(&a, &e);
    CHECK(recorded(&e, "config-chksum"));
    CHECK(recorded(&e, "config-tpc"));
    CHECK(recorded(&e, "config-sitename"));
    CHECK(recorded(&e, "config-parallel"));
    CHECK(recorded(&e, "capacity-low"));

    /* healthy config: nothing recorded. */
    memset(&e, 0, sizeof(e));
    e.cfg.scraped = 1;
    e.cfg.have_adler32 = e.cfg.have_crc32c = 1;
    e.cfg.tpc = e.cfg.tpcdlg = 1;
    snprintf(e.cfg.sitename, sizeof(e.cfg.sitename), "T2_UK_TEST");
    e.cfg.bind_max = 16;
    e.cfg.space_total = 100;
    e.cfg.space_free = 80;
    doctor_audit_rules(&a, &e);
    CHECK(e.ndx == 0);

    /* --cap-threshold 90 turns a healthy 80% free into a capacity-low WARN. */
    a.cap_threshold_pct = 90;
    doctor_audit_rules(&a, &e);
    CHECK(recorded(&e, "capacity-low"));
}


/* cross_cluster records version/role/imbalance onto eps[0] (out=NULL: no print). */
static void
test_cross_cluster(void)
{
    doctor_ep eps[4];
    memset(eps, 0, sizeof(eps));

    /* n<2 => nothing. */
    doctor_cross_cluster(eps, 1, NULL);
    CHECK(eps[0].ndx == 0);

    /* [0] manager 5.6.0; DS [1] 5.6.0 90% free, [2] 5.5.0 10% free, [3] 5.6.0.
     * => version skew (1) + exactly one manager + capacity outlier. */
    eps[0].cfg.scraped = 1;
    snprintf(eps[0].cfg.version, 48, "5.6.0");
    snprintf(eps[0].cfg.role, 24, "manager");
    eps[1].cfg.scraped = 1; snprintf(eps[1].cfg.version, 48, "5.6.0");
    eps[1].cfg.space_total = 100; eps[1].cfg.space_free = 90;
    eps[2].cfg.scraped = 1; snprintf(eps[2].cfg.version, 48, "5.5.0");
    eps[2].cfg.space_total = 100; eps[2].cfg.space_free = 10;
    eps[3].cfg.scraped = 1; snprintf(eps[3].cfg.version, 48, "5.6.0");
    eps[3].cfg.space_total = 100; eps[3].cfg.space_free = 88;
    doctor_cross_cluster(eps, 4, NULL);
    CHECK(recorded(&eps[0], "config-version"));    /* mixed versions */
    CHECK(recorded(&eps[0], "cap-imbalance")); /* 10% vs ~89% mean */
    CHECK(!recorded(&eps[0], "config-role"));       /* exactly one manager */

    /* zero managers => config-role FAIL. */
    memset(eps, 0, sizeof(eps));
    eps[0].cfg.scraped = 1; snprintf(eps[0].cfg.role, 24, "server");
    snprintf(eps[0].cfg.version, 48, "5.6.0");
    eps[1].cfg.scraped = 1; snprintf(eps[1].cfg.role, 24, "server");
    snprintf(eps[1].cfg.version, 48, "5.6.0");
    doctor_cross_cluster(eps, 2, NULL);
    CHECK(recorded(&eps[0], "config-role"));
}


/* doctor_locate_classify types a kXR_locate token by its type+access prefix. */
static void
test_locate_classify(void)
{
    doctor_cmsloc m;
    char          host[256];
    int           port;

    /* 'S''r' + bracketed IPv6 => online data server, read-only. */
    memset(&m, 0, sizeof(m));
    CHECK(doctor_locate_classify("Sr[2001:db8::1]:1094", &m,
                                 host, sizeof(host), &port) == 0);
    CHECK(m.role == DOC_CMS_SERVER && m.reported == 1);
    CHECK(m.write == 0 && m.pending == 0);
    CHECK(port == 1094 && strcmp(host, "2001:db8::1") == 0);

    /* 'M''w' => manager/redirector, read/write. */
    memset(&m, 0, sizeof(m));
    CHECK(doctor_locate_classify("Mwmgr.example.org:2094", &m,
                                 host, sizeof(host), &port) == 0);
    CHECK(m.role == DOC_CMS_MANAGER && m.write == 1 && m.pending == 0);
    CHECK(port == 2094 && strcmp(host, "mgr.example.org") == 0);

    /* lowercase 's' => pending (queued/staging) data server. */
    memset(&m, 0, sizeof(m));
    CHECK(doctor_locate_classify("srds.example.org:1095", &m,
                                 host, sizeof(host), &port) == 0);
    CHECK(m.role == DOC_CMS_SERVER && m.pending == 1);

    /* lowercase 'm' => pending manager. */
    memset(&m, 0, sizeof(m));
    CHECK(doctor_locate_classify("mrsub.example.org:1096", &m,
                                 host, sizeof(host), &port) == 0);
    CHECK(m.role == DOC_CMS_MANAGER && m.pending == 1);

    /* malformed: unknown type byte, too short, or empty host => -1. */
    memset(&m, 0, sizeof(m));
    CHECK(doctor_locate_classify("Xrhost:1094", &m, host, sizeof(host), &port) == -1);
    CHECK(doctor_locate_classify("S", &m, host, sizeof(host), &port) == -1);
    CHECK(doctor_locate_classify("", &m, host, sizeof(host), &port) == -1);
    CHECK(doctor_locate_classify(NULL, &m, host, sizeof(host), &port) == -1);
}


int
main(void)
{
    test_parse_chksum();
    test_capacity_pct();
    test_cap_threshold();
    test_version_skew_and_managers();
    test_audit_rules();
    test_cross_cluster();
    test_locate_classify();

    if (g_fail == 0) {
        printf("all checks passed\n");
        return 0;
    }
    printf("%d check(s) FAILED\n", g_fail);
    return 1;
}
