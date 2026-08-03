/*
 * diag_tpc_egress.c — TPC egress (SSRF-control) self-test.
 *
 * `xrddiag tpc-egress <your-gateway-url> --tpc-target host[:port]`
 *
 * Points at YOUR OWN root:// gateway and asks it to originate a third-party-copy
 * *pull* from the named source. In the TPC-pull model the destination server —
 * your gateway — is the party that dials the source host, so this is precisely
 * the surface an attacker abuses for SSRF: coerce the gateway into connecting to
 * an internal address it would never expose directly.
 *
 * The self-test issues only the destination *arm* (a cgiC2Dst kXR_open naming the
 * target as tpc.src) and, if the arm is accepted, a single bounded trigger. It
 * classifies the outcome:
 *
 *   REFUSED (policy)   the gateway's egress guard declined to originate  → SAFE
 *   conn-refused       egress permitted; the source port answered RST    → RISK
 *   filtered/timeout   egress permitted; the source stayed silent        → RISK
 *   reached (no lfn)   egress permitted; the source is up, lfn absent    → RISK
 *   reached (error)    egress permitted; the source answered an error    → RISK
 *   ACCEPTED           egress permitted; the pull ran to completion      → RISK
 *
 * Read-only against the source (a self-test lfn that will not exist) and strictly
 * PII-free in its report: verdict / kXR code / milliseconds / the operator-named
 * target only — never a resolved address, a path body, or a credential.
 *
 * Pure composition of the public libbrix client API — no new wire.
 */
#include <ctype.h>

#include "diag_internal.h"

/* Rendezvous-key minter, shared with the copy engine (lib/xfer/copy_remote.c). */
int gen_tpc_key(char *out, size_t outsz);

/* NULL/empty → "-" so the report never prints a bare gap. */
static const char *
tpce_dash(const char *s)
{
    return (s != NULL && s[0] != '\0') ? s : "-";
}

/* The self-test source path. Deliberately implausible so a *reachable* source
 * answers "no such file" fast instead of streaming real data back to us. */
#define TPCE_SELFTEST_LFN "/.brix-egress-selftest-nonexistent"

/* Default trigger budget when --probe-timeout is not given (ms). Short: a live
 * pull we do not want; we only need long enough to tell RST from a dropped SYN. */
#define TPCE_DEFAULT_BUDGET_MS 4000

/* A returned outbound-connect failure faster than this reflects an active
 * refusal (an RST came straight back); slower means the gateway sat through its
 * own connect timeout on a dropped SYN — i.e. the source is filtered. */
#define TPCE_FAST_FAIL_MS 1000.0


static double
tpce_mono_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double) t.tv_sec * 1000.0 + (double) t.tv_nsec / 1e6;
}


/* Case-insensitive substring test (needle assumed lowercase). */
static int
tpce_has(const char *hay, const char *needle)
{
    size_t nlen = strlen(needle);
    size_t i;

    if (hay == NULL) {
        return 0;
    }
    for (; *hay != '\0'; hay++) {
        for (i = 0; i < nlen; i++) {
            if (tolower((unsigned char) hay[i]) != needle[i]) {
                break;
            }
        }
        if (i == nlen) {
            return 1;
        }
    }
    return 0;
}


/*
 * A kXR_NotAuthorized from the arm is only an *egress* refusal when its text
 * names the source/egress policy — the gateway also returns NotAuthorized for
 * unrelated denials (read-only export, token scope), which must NOT read as a
 * working SSRF guard. Matches the address-range gate ("prohibited"/"private"/
 * "loopback") and the host-allowlist guard ("source host not permitted").
 */
static int
tpce_msg_is_egress_denial(const char *msg)
{
    return tpce_has(msg, "source")
        || tpce_has(msg, "egress")
        || tpce_has(msg, "not permitted")
        || tpce_has(msg, "not allowed")
        || tpce_has(msg, "prohibited")
        || tpce_has(msg, "private")
        || tpce_has(msg, "loopback")
        || tpce_has(msg, "ssrf");
}


/* Build the cgiC2Dst opaque that arms the destination to pull from `target`. */
static void
tpce_build_opaque(char *buf, size_t sz, const char *key, const char *target)
{
    snprintf(buf, sz,
             "tpc.key=%s&tpc.src=%s&tpc.lfn=%s&tpc.spr=root&tpc.tpr=root"
             "&tpc.dlgon=0&tpc.stage=copy",
             key, target, TPCE_SELFTEST_LFN);
}


/*
 * tpce_classify_trigger — map the trigger (sync) outcome to a verdict. Public so
 * the offline unit suite can prove every branch without a live gateway. `st` is
 * the status the trigger returned (rc==0 → st is success), `elapsed_ms` the
 * measured wall time, `budget_ms` the timeout we imposed.
 */
tpce_verdict
tpce_classify_trigger(const brix_status *st, double elapsed_ms,
                      double budget_ms, char *detail, size_t dsz)
{
    /* Success: the gateway connected to the source and completed the pull. */
    if (st->kxr == 0) {
        snprintf(detail, dsz, "pull completed — full egress + transfer");
        return TPCE_ACCEPTED;
    }
    /* Explicit reset — the source port answered, reachable but not serving. */
    if (st->sys_errno == ECONNREFUSED || tpce_has(st->msg, "refused")) {
        snprintf(detail, dsz, "source port answered RST (connection refused)");
        return TPCE_CONN_REFUSED;
    }
    /* Our bounded wait elapsed with no reply, or an explicit timeout: the pull
     * is still hanging server-side because the SYN was dropped. */
    if (st->sys_errno == ETIMEDOUT || tpce_has(st->msg, "timed out")
        || tpce_has(st->msg, "timeout") || elapsed_ms >= budget_ms * 0.9) {
        snprintf(detail, dsz, "source silent — SYN dropped (filtered)");
        return TPCE_FILTERED;
    }
    /* The gateway reported an outbound connect failure (its text carries no
     * errno): a fast reply is an active refusal, a slow one is the gateway's own
     * connect timeout expiring on a dropped SYN. */
    if (tpce_has(st->msg, "connect") && tpce_has(st->msg, "fail")) {
        if (elapsed_ms < TPCE_FAST_FAIL_MS) {
            snprintf(detail, dsz, "gateway's outbound connect failed fast "
                                  "(source refused the connection)");
            return TPCE_CONN_REFUSED;
        }
        snprintf(detail, dsz, "gateway's outbound connect timed out "
                              "(source filtered)");
        return TPCE_FILTERED;
    }
    /* The source is up and spoke XRootD back: the self-test lfn is absent. */
    if (st->kxr == kXR_NotFound || tpce_has(st->msg, "not found")
        || tpce_has(st->msg, "no such") || tpce_has(st->msg, "does not exist")) {
        snprintf(detail, dsz, "source reachable — self-test lfn absent (expected)");
        return TPCE_REACHED_NOENT;
    }
    snprintf(detail, dsz, "source reachable — answered with an error");
    return TPCE_REACHED_ERROR;
}


/*
 * Drive the destination through the two-sync TPC rendezvous and classify. The
 * server arms on the FIRST kXR_sync (returns OK immediately, sets tpc_armed) and
 * only originates the outbound pull on the SECOND — see brix_handle_sync /
 * brix_tpc_start_pull. So the arming sync is issued and discarded; the trigger
 * sync, run under the raised budget, is the one whose outcome names the egress
 * decision (its reply is deferred via kXR_waitresp until the pull settles).
 */
static void
tpce_trigger(brix_conn *c, brix_file *f, double budget_ms, tpce_result *r)
{
    brix_status st;
    double      t0;

    brix_status_clear(&st);
    (void) brix_file_sync(c, f, &st);     /* sync #1: arm (immediate OK) */

    brix_status_clear(&st);
    if (c->io.timeout_ms < (int) budget_ms) {
        c->io.timeout_ms = (int) budget_ms;
    }
    t0 = tpce_mono_ms();
    (void) brix_file_sync(c, f, &st);     /* sync #2: trigger the outbound pull */
    r->trig_ms  = tpce_mono_ms() - t0;
    r->trig_kxr = st.kxr;
    r->verdict  = tpce_classify_trigger(&st, r->trig_ms, budget_ms,
                                        r->detail, sizeof(r->detail));
}


/* Interpret the arm (destination open) result and drive the trigger when the
 * gateway agreed to originate. Returns with r->verdict + r->egress_permitted set. */
static void
tpce_after_arm(brix_conn *c, brix_file *f, int arm_rc, const brix_status *arm_st,
               double budget_ms, tpce_result *r)
{
    r->arm_kxr = arm_st->kxr;

    if (arm_rc == 0) {
        r->egress_permitted = 1;
        tpce_trigger(c, f, budget_ms, r);
        return;
    }
    if (arm_st->kxr == kXR_NotAuthorized && tpce_msg_is_egress_denial(arm_st->msg)) {
        r->verdict = TPCE_REFUSED_POLICY;
        snprintf(r->detail, sizeof(r->detail),
                 "gateway egress guard declined to originate");
        return;
    }
    r->verdict = TPCE_ARM_ERROR;
    snprintf(r->detail, sizeof(r->detail),
             "gateway refused the arm (kXR=%d) — not an egress-policy denial",
             arm_st->kxr);
}


/*
 * tpce_run — execute the self-test: connect to the gateway, arm a TPC-pull that
 * names `target` as the source, and classify. `out` is fully populated (verdict,
 * timings, kXR codes, PII-free detail) on every non-usage return.
 */
int
tpce_run(const diag_args *a, const char *gw_url, const char *target,
         tpce_result *out)
{
    brix_url    u;
    brix_conn   c;
    brix_file   f;
    brix_status st;
    char        opaque[1024];
    char        key[48];
    double      budget = a->probe_timeout_ms > 0
                             ? (double) a->probe_timeout_ms : TPCE_DEFAULT_BUDGET_MS;
    const char *dst_path;
    double      t0;
    int         arm_rc;

    memset(out, 0, sizeof(*out));
    brix_status_clear(&st);
    if (brix_url_parse(gw_url, &u, &st) != 0) {
        out->verdict = TPCE_ERR_CONNECT;
        snprintf(out->detail, sizeof(out->detail), "bad gateway url");
        return -1;
    }
    snprintf(out->gw_host, sizeof(out->gw_host), "%s", u.host);
    snprintf(out->target, sizeof(out->target), "%s", target);

    memset(&c, 0, sizeof(c));
    if (brix_connect(&c, &u, &a->conn, &st) != 0) {
        out->verdict = TPCE_ERR_CONNECT;
        out->arm_kxr = st.kxr;
        snprintf(out->detail, sizeof(out->detail),
                 "cannot reach/log in to the gateway (kXR=%d)", st.kxr);
        return -1;
    }

    if (gen_tpc_key(key, sizeof(key)) != 0) {
        brix_close(&c);
        out->verdict = TPCE_ERR_CONNECT;
        snprintf(out->detail, sizeof(out->detail), "cannot mint rendezvous key");
        return -1;
    }
    tpce_build_opaque(opaque, sizeof(opaque), key, target);
    dst_path = (u.path[0] != '\0' && strcmp(u.path, "/") != 0)
                   ? u.path : TPCE_SELFTEST_LFN;

    brix_status_clear(&st);
    memset(&f, 0, sizeof(f));
    t0 = tpce_mono_ms();
    arm_rc = brix_file_open_opaque(&c, dst_path, opaque, 1, 1, 0, &f, &st);
    out->arm_ms = tpce_mono_ms() - t0;

    tpce_after_arm(&c, &f, arm_rc, &st, budget, out);

    brix_close(&c);
    return 0;
}


/* ---- rendering ---- */

/* Short verdict label + the "is egress permitted?" summary word. */
static const char *
tpce_verdict_label(tpce_verdict v)
{
    switch (v) {
    case TPCE_ERR_CONNECT:     return "GATEWAY-UNREACHABLE";
    case TPCE_REFUSED_POLICY:  return "REFUSED (policy)";
    case TPCE_CONN_REFUSED:    return "PERMITTED (conn-refused)";
    case TPCE_FILTERED:        return "PERMITTED (filtered/timeout)";
    case TPCE_REACHED_NOENT:   return "PERMITTED (source reachable)";
    case TPCE_REACHED_ERROR:   return "PERMITTED (source reachable)";
    case TPCE_ACCEPTED:        return "PERMITTED (transfer completed)";
    case TPCE_ARM_ERROR:       return "INCONCLUSIVE (arm error)";
    }
    return "UNKNOWN";
}


void
tpce_report(const tpce_result *r)
{
    const char *band = r->verdict == TPCE_REFUSED_POLICY ? "[GREEN]"
                     : r->egress_permitted               ? "[RED]"
                     : "[YELLOW]";

    printf("%s tpc-egress self-test: %s\n", band, tpce_verdict_label(r->verdict));
    printf("  gateway=%s  target=%s\n", tpce_dash(r->gw_host),
           tpce_dash(r->target));
    printf("  %s\n", r->detail);
    if (r->arm_ms > 0) {
        printf("  arm: %.1f ms (kXR=%d)\n", r->arm_ms, r->arm_kxr);
    }
    if (r->egress_permitted) {
        printf("  trigger: %.1f ms (kXR=%d)\n", r->trig_ms, r->trig_kxr);
        printf("  RISK: this gateway will originate an outbound TPC pull to an\n"
               "        operator-named source — add a brix_tpc_source_guard\n"
               "        allowlist to constrain egress (SSRF control).\n");
    }
}


void
tpce_emit_json(const tpce_result *r, FILE *out)
{
    fprintf(out, "{\"tpc_egress\":{\"verdict\":");
    fjson_str(out, tpce_verdict_label(r->verdict));
    fprintf(out, ",\"egress_permitted\":%s",
            r->egress_permitted ? "true" : "false");
    fprintf(out, ",\"gateway\":");
    fjson_str(out, r->gw_host);
    fprintf(out, ",\"target\":");
    fjson_str(out, r->target);
    fprintf(out, ",\"detail\":");
    fjson_str(out, r->detail);
    fprintf(out, ",\"arm_kxr\":%d,\"trig_kxr\":%d"
            ",\"arm_ms\":%.1f,\"trig_ms\":%.1f}}\n",
            r->arm_kxr, r->trig_kxr, r->arm_ms, r->trig_ms);
}


/*
 * do_tpc_egress — subcommand entry. Exit codes: 0 = egress refused (the SSRF-safe
 * outcome the guard produces); 3 = egress permitted (a finding); 2 = gateway
 * unreachable / inconclusive; 50 = usage.
 */
int
do_tpc_egress(const diag_args *a)
{
    tpce_result r;

    if (a->url == NULL || a->tpc_target == NULL || a->tpc_target[0] == '\0') {
        fprintf(stderr, "usage: xrddiag tpc-egress <your-gateway-url> "
                        "--tpc-target host[:port] [--json] [--probe-timeout ms]\n");
        return 50;
    }

    tpce_run(a, a->url, a->tpc_target, &r);

    if (a->json) {
        tpce_emit_json(&r, stdout);
    } else {
        tpce_report(&r);
    }

    if (r.verdict == TPCE_REFUSED_POLICY) {
        return 0;
    }
    if (r.egress_permitted) {
        return 3;
    }
    return 2;
}
