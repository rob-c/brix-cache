/*
 * diag_doctor.c — remote-doctor orchestration + root:// endpoint probe (Phase-38 split).
 *
 * WHAT: the top-level remote-doctor engine — interrogate one endpoint (root://
 *       session facts, throughput, active diagnosis), the cross-endpoint
 *       transfer-path diff, the JSON/text renderers, the scheme dispatcher, and
 *       do_remote_doctor's report loop.
 * WHY:  split from the original monolith so each remote-doctor TU stays within
 *       the Phase-38 size budget; this file owns the "drive the probes and
 *       render the verdict" concern. The reusable probe primitives live in
 *       diag_doctor_probe.c (download/xfer/metrics/auth-suite/diagnose) and the
 *       per-protocol batteries in diag_doctor_proto.c (http/s3/cms) — both
 *       reached through the extern contract in diag_internal.h.
 * HOW:  doctor_one opens a root:// connection and calls the shared probes;
 *       doctor_dispatch routes by URL scheme to the protocol batteries; the
 *       renderers walk the accumulated doctor_ep[] array. No goto; PII-free.
 */
#include "diag_internal.h"


/*
 * WHAT: classify why the primary connection could not be set up.
 * WHY:  extracted from doctor_one's connect-failure path (complexity gate).
 * HOW:  map errno / status-message onto a fixed cause+remedy pair; the caller
 *       reports the classified cause, not st->msg (wire text may carry PII).
 */
static void
doctor_classify_conn_error(const brix_status *st, const char **cause,
                           const char **remedy)
{
    *cause  = "connection setup failed";
    *remedy = "check the network path and that the server is running";
    if (st->sys_errno == ECONNREFUSED) {
        *cause  = "no listener on host:port (service down or wrong port)";
        *remedy = "start the gateway / verify the port and any firewall";
    } else if (st->sys_errno == ETIMEDOUT || st->sys_errno == EHOSTUNREACH
               || st->sys_errno == ENETUNREACH) {
        *cause  = "host/network unreachable (routing or firewall drop)";
        *remedy = "check routing/firewall and that the host is up";
    } else if (st->msg[0] != '\0' && strstr(st->msg, "resolve") != NULL) {
        *cause  = "DNS resolution failed";
        *remedy = "check the hostname and DNS resolver";
    }
}


/*
 * WHAT: verdict-render half of a failed primary connect — auth rejection vs
 *       transport unreachability, plus the standalone auth-suite.
 * WHY:  extracted from doctor_one for the complexity gate.
 * HOW:  distinguish "server reachable but auth failed" from "couldn't reach
 *       it" by the client's error CODE: XRDC_EAUTH / kXR_NotAuthorized /
 *       kXR_AuthFailed mean auth was attempted and rejected; everything else
 *       is transport.
 */
static void
doctor_one_connect_fail(const diag_args *a, const brix_url *u,
                        const brix_status *st, const char *target,
                        doctor_ep *e)
{
    if (st->kxr == XRDC_EAUTH || st->kxr == kXR_NotAuthorized
        || st->kxr == kXR_AuthFailed) {
        doc_issue(e, DOC_RED, "authentication failed");
        dx_record(e, &(dx_note){ "auth", DX_FAIL, st->kxr,
                  "could not authenticate (credential rejected, or none usable for the server's auth)",
                  "check the credential's validity/scope and that it matches the server's auth mode" });
    } else {
        /* reachability: classify *why* the connection could not be set up. */
        const char *cause, *remedy;
        doctor_classify_conn_error(st, &cause, &remedy);
        /* use the classified cause, not st.msg — wire text may carry PII. */
        doc_issue(e, DOC_RED, "connect failed: %s", cause);
        dx_record(e, &(dx_note){ "reachability", DX_FAIL, st->kxr, cause, remedy });
    }
    /* the auth-suite is self-contained (its own force_anon session) — run it
     * even when our credential could not establish the primary connection. */
    if (a->auth_suite) {
        doctor_auth_suite(a, u, target, 0, e);
    }
}


/*
 * WHAT: session-fact collection over the freshly opened connection —
 *       transport timings, capabilities, TLS state, chosen auth.
 * WHY:  extracted from doctor_one for the complexity gate.
 * HOW:  read the facts off the live conn into *e and flag the
 *       no-silent-downgrade invariant (gotoTLS advertised but cleartext).
 */
static void
doctor_one_session_facts(brix_conn *c, doctor_ep *e)
{
    const char *ver = NULL, *cipher = NULL;

    /* network + transport facts */
    brix_netdiag_facts(c, &e->nf);
    e->caps = (unsigned) c->server_flags;
    e->gototls = (c->server_flags & kXR_gotoTLS) != 0;
    e->tls_active = brix_tls_info(c, &ver, &cipher);
    if (e->tls_active) {
        snprintf(e->tls_ver, sizeof(e->tls_ver), "%s", ver ? ver : "?");
        snprintf(e->tls_cipher, sizeof(e->tls_cipher), "%s", cipher ? cipher : "?");
    }
    snprintf(e->auth, sizeof(e->auth), "%s",
             c->diag.chosen_auth ? c->diag.chosen_auth : "anon");

    /* no-silent-downgrade: gotoTLS advertised but the session is cleartext */
    if (e->gototls && !e->tls_active) {
        doc_issue(e, DOC_RED, "gotoTLS advertised but session is cleartext");
    }
}


/*
 * WHAT: throughput probe over a resolved file.
 * WHY:  extracted from doctor_one for the complexity gate.
 * HOW:  resolve a readable target (skip cleanly if the export is empty),
 *       then time TTFB + MB/s with doctor_xfer. Returns 1 when a target was
 *       resolved (left in `target` for the later probes), else 0.
 */
static int
doctor_one_xfer_probe(brix_conn *c, const brix_url *u, char *target,
                      size_t tsz, doctor_ep *e)
{
    brix_statinfo sti;
    brix_status   rst;

    brix_status_clear(&rst);
    if (resolve_target(c, u, target, tsz, &sti, &rst) != 0) {
        return 0;
    }
    if (doctor_xfer(c, target, &e->ttfb_ms, &e->mbps, &e->xfer_bytes) == 0) {
        e->have_xfer = 1;
    }
    return 1;
}


/*
 * WHAT: post-session load/health signals — /metrics shedding, cwnd/BDP
 *       heuristic, TCP retransmits.
 * WHY:  extracted from doctor_one for the complexity gate.
 * HOW:  best-effort cleartext /metrics scrape (port 0 = skip), then escalate
 *       yellow issues from the facts already collected on *e.
 */
static void
doctor_one_load_signals(const diag_args *a, doctor_ep *e)
{
    /* server-side load signal (cleartext /metrics; best-effort, 0 = skip) */
    if (a->metrics_port > 0) {
        doctor_metrics(e->host, a->metrics_port, e);
    }
    if (e->shedding) {
        doc_issue(e, DOC_YELLOW, "server reports kXR_wait / budget shedding");
    }
    /* cwnd/BDP signal — only meaningful once enough bytes moved to time it. */
    if (e->have_xfer && e->xfer_bytes >= (4 << 20) && e->nf.have_tcpinfo
        && e->nf.rtt_us > 0 && e->nf.rtt_us < 5000 && e->mbps < 5.0) {
        doc_issue(e, DOC_YELLOW, "low throughput (%.1f MB/s) at low RTT — cwnd/BDP?",
                  e->mbps);
    }
    if (e->nf.have_tcpinfo && e->nf.retrans > 0) {
        doc_issue(e, DOC_YELLOW, "%u TCP retransmit(s)", e->nf.retrans);
    }
}


/* Interrogate ONE endpoint into *e. Bounded by the conn timeout (never hangs). */
void
doctor_one(const diag_args *a, const char *url, doctor_ep *e)
{
    brix_url      u;
    brix_conn     c;
    brix_status   st;
    char          target[XRDC_PATH_MAX];
    int           have_target = 0;

    target[0] = '\0';
    memset(e, 0, sizeof(*e));
    e->status = DOC_GREEN;
    brix_status_clear(&st);
    if (brix_endpoint_parse(url, &u, &st) != 0) {
        snprintf(e->host, sizeof(e->host), "%s", url);
        doc_issue(e, DOC_RED, "unparseable URL (bad scheme/host/port)");
        return;
    }
    snprintf(e->host, sizeof(e->host), "%s", u.host);
    e->port = u.port;

    if (brix_connect(&c, &u, &a->conn, &st) != 0) {
        doctor_one_connect_fail(a, &u, &st, target, e);
        return;
    }
    e->connected = 1;
    c.io.timeout_ms = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;

    doctor_one_session_facts(&c, e);

    /* phase-93 config audit: scrape advertised config + capacity while the
     * connection is live (best-effort, PII-free). --all-servers implies it. */
    if (a->config_audit || a->all_servers || a->map || a->deep_recon) {
        doctor_scrape_config(&c, e);
    }

    /* throughput probe over a resolved file (skip cleanly if the export is empty) */
    have_target = doctor_one_xfer_probe(&c, &u, target, sizeof(target), e);

    /* active differential diagnosis — exercise subsystems + classify (incl. locate). */
    doctor_diagnose(a, &c, &u,
                    &(dx_target){ .path = target, .have = have_target }, e);

    /* phase-93 deep-recon: read-only reconnaissance while the connection is
     * live (stats scrape + full config sweep + authorized-root listing). */
    if (a->deep_recon) {
        doctor_recon_probe(a, &c, e);
    }

    brix_close(&c);

    doctor_one_load_signals(a, e);

    /* phase-93: classify the scraped config/capacity values and promote the
     * perf/shedding signals into machine-readable diagnosis records. */
    if (a->config_audit || a->all_servers || a->map || a->deep_recon) {
        doctor_audit_rules(a, e);
        doctor_audit_perf(e);
    }
}


const char *
doc_color(int s)
{
    return s == DOC_RED ? "RED" : s == DOC_YELLOW ? "YELLOW" : "GREEN";
}


/*
 * WHAT: transfer-path diff of one adjacent endpoint pair.
 * WHY:  extracted from doctor_cross for the complexity gate.
 * HOW:  emit TLS-downgrade (critical), auth-fallback, and address-family
 *       asymmetry lines in the original order; returns the number of
 *       critical diffs found (0 or 1).
 */
static int
cross_diff_pair(const doctor_ep *p, const doctor_ep *q, FILE *out)
{
    int crit = 0;

    if (!p->connected || !q->connected) {
        return 0;
    }
    /* TLS-downgrade: a TLS hop followed by a cleartext one */
    if (p->tls_active && !q->tls_active) {
        fprintf(out, "  %s:%d -> %s:%d  TLS DOWNGRADE (encrypted then cleartext)\n",
                p->host, p->port, q->host, q->port);
        crit++;
    }
    /* auth-fallback: the chosen auth weakens across the hop */
    if (strcmp(p->auth, q->auth) != 0) {
        fprintf(out, "  %s:%d -> %s:%d  auth changed %s -> %s\n",
                p->host, p->port, q->host, q->port, p->auth, q->auth);
    }
    /* v4/v6 asymmetry */
    if (p->nf.family && q->nf.family && p->nf.family != q->nf.family) {
        fprintf(out, "  %s:%d -> %s:%d  address-family asymmetry (%s vs %s)\n",
                p->host, p->port, q->host, q->port,
                p->nf.family == 10 ? "IPv6" : "IPv4",
                q->nf.family == 10 ? "IPv6" : "IPv4");
    }
    return crit;
}


/* Cross-endpoint diff engine over the transfer path. Returns #critical diffs. */
int
doctor_cross(const doctor_ep *eps, int n, FILE *out)
{
    int i, crit = 0, connected = 0;
    if (n < 2) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (eps[i].connected) { connected++; }
    }
    if (connected < 2) {
        return 0;   /* fewer than two reachable hops — nothing to compare */
    }
    fprintf(out, "Path analysis (%d hops):\n", n);
    for (i = 1; i < n; i++) {
        crit += cross_diff_pair(&eps[i - 1], &eps[i], out);
    }
    return crit;
}


/* Human-readable diagnosis block for one endpoint: each probe's verdict, and for
 * problems the classified cause + remediation. */
void
doctor_print_diagnosis(const doctor_ep *e)
{
    int j;
    if (e->ndx == 0) {
        return;
    }
    printf("  diagnosis:\n");
    for (j = 0; j < e->ndx; j++) {
        const dx_finding *d = &e->dx[j];
        const char       *tag = d->verdict == DX_FAIL ? "FAIL"
                              : d->verdict == DX_WARN ? "WARN" : "ok";
        printf("    [%-4s] %-11s %s\n", tag, d->probe, d->cause);
        if (d->verdict != DX_OK && d->remedy[0] != '\0') {
            printf("           → %s\n", d->remedy);
        }
    }
}


/* Route one URL to its protocol battery by scheme. root:// (and any unrecognized
 * scheme, for back-compat) goes to the full libbrix battery; the rest to their
 * deep-dive batteries. */
void
doctor_dispatch(const diag_args *a, const char *url, doctor_ep *e)
{
    dx_url_t u;

    if (dx_url_parse(url, &u) != 0 || u.proto == DXP_ROOT) {
        doctor_one(a, url, e);
        return;
    }
    switch (u.proto) {
    case DXP_HTTP:
    case DXP_HTTPS:
    case DXP_DAVS:  doctor_http(a, &u, e); break;
    case DXP_S3:    doctor_s3(a, &u, e); break;
    case DXP_CMS:   doctor_cms(a, u.host, u.port, u.path, e); break;
    default:        doctor_one(a, url, e); break;
    }
}


/* One-line CMS-plane descriptor from the locate answer: "data server,
 * read-only" / "redirector" / "data server, read/write, pending". Empty when
 * nothing was reported (e.g. a lone directly-probed endpoint). */
static void
doctor_cms_phrase(const doctor_cmsloc *m, char *buf, size_t bsz)
{
    if (!m->reported) {
        buf[0] = '\0';
        return;
    }
    snprintf(buf, bsz, "%s%s%s",
             m->role == DOC_CMS_MANAGER ? "redirector" : "data server",
             m->role == DOC_CMS_SERVER
                 ? (m->write ? ", read/write" : ", read-only") : "",
             m->pending ? ", pending" : "");
}


/* The root/cms fact lines: connect phases, auth/TLS, the CMS verdict, the EOS
 * banner, and whatever optional transport/transfer facts were collected. Only
 * the libbrix-connected batteries populate these; HTTP reports a TLS line. */
static void
report_root_facts(const doctor_ep *e, const char *cms)
{
    printf("  connect: tcp %.1f / tls %.1f / login+auth %.1f ms  (%s)\n",
           e->nf.tcp_ms, e->nf.tls_ms, e->nf.auth_ms,
           e->nf.family == 10 ? "IPv6" : e->nf.family == 2 ? "IPv4" : "?");
    printf("  auth=%s  tls=%s%s%s  caps=0x%x\n", e->auth,
           e->tls_active ? e->tls_ver : "none",
           e->tls_active ? " " : "", e->tls_active ? e->tls_cipher : "",
           e->caps);
    if (cms[0]) {
        printf("  cms: %s (locate plane)\n", cms);
    }
    doctor_eos_report_mgm(e);   /* EOS MGM banner + FST-enumeration outcome */
    if (e->nf.have_tcpinfo) {
        printf("  tcp: rtt=%u us retrans=%u\n", e->nf.rtt_us, e->nf.retrans);
    }
    if (e->have_xfer) {
        printf("  xfer: ttfb %.1f ms, %.1f MB/s\n", e->ttfb_ms, e->mbps);
    }
    printf("  holders=%d  metrics=%s%s\n", e->holders,
           e->metrics_http == 200 ? "reachable" : "n/a",
           e->shedding ? " (SHEDDING)" : "");
}


/* Render one endpoint's text report block. WHAT: the [color] header, the
 * per-protocol fact lines, the issue list and the diagnosis block.
 * WHY: the per-endpoint renderer is the bulk of do_remote_doctor's text
 *      path; splitting it keeps the orchestrator under the complexity gate.
 * HOW: verbatim move of the loop body — root/cms print the full libbrix
 *      connect-phase + transport facts, the HTTP family only its TLS line. */
static void
remote_doctor_report_ep(const doctor_ep *e)
{
    int  j;
    char cms[48];

    if (doctor_eos_report_fst(e)) {
        return;   /* EOS FST enumerated from the MGM — never inbound-probed */
    }
    doctor_cms_phrase(&e->cms, cms, sizeof(cms));
    if (e->skipped) {
        /* Un-connectable holder: we cannot probe it, but the manager's locate
         * answer already told us what it is — surface that CMS-plane verdict. */
        printf("\n[SKIP] %s %s:%d — IPv6-only, no local IPv6 route%s%s "
               "(not probed)\n", dx_proto_name(e->proto), e->host, e->port,
               cms[0] ? "; CMS reports " : "", cms);
        return;
    }
    printf("\n[%s] %s %s:%d\n", doc_color(e->status), dx_proto_name(e->proto),
           e->host, e->port);
    if (!e->connected) {
        for (j = 0; j < e->nissues; j++) { printf("  - %s\n", e->issues[j]); }
        doctor_print_diagnosis(e);
        return;
    }
    /* root/cms use the libbrix connection → full connect-phase + transport facts;
     * the HTTP-family batteries report TLS facts inline + the diagnosis block. */
    if (e->proto == DXP_ROOT) {
        report_root_facts(e, cms);
    } else if (e->tls_active) {
        printf("  tls=%s %s\n", e->tls_ver, e->tls_cipher);
    }
    doctor_report_config(e);   /* phase-93 config/capacity block (no-op if unscraped) */
    doctor_report_recon(e);    /* phase-93 deep-recon block (no-op if unprobed) */
    for (j = 0; j < e->nissues; j++) { printf("  - %s\n", e->issues[j]); }
    doctor_print_diagnosis(e);
}

/* Print the client-side credential validity block. WHAT: token + X509 proxy
 * explanation to stdout, when either is present in the environment.
 * WHY: independent of the per-endpoint loop; the same creds reach every hop.
 * HOW: verbatim move — discover token, read $X509_USER_PROXY, explain both. */
static void
remote_doctor_report_creds(void)
{
    char       *tok = brix_token_discover();
    const char *proxy = getenv("X509_USER_PROXY");

    if (tok != NULL || (proxy != NULL && proxy[0] != '\0')) {
        printf("\nCredentials (in environment):\n");
        if (tok != NULL) { brix_token_explain(tok, stdout); free(tok); }
        if (proxy != NULL && proxy[0] != '\0') {
            brix_gsi_cert_explain(proxy, stdout);
        }
    }
}

/*
 * WHAT: the --all-servers manager fan-out path — probe the manager, then every
 *       data server it locates, and diff the fleet for uniformity.
 * WHY:  keeps do_remote_doctor's user-supplied-URL path unchanged (stack eps[8])
 *       while the fleet path uses a heap array sized for a large cluster.
 * HOW:  doctor_fanout builds eps[0]=manager + eps[1..)=DSs; doctor_cross_cluster
 *       records the version/role/balance findings onto eps[0] (so they escalate
 *       its status); then reuse the existing per-endpoint renderers.
 */
static int
fanout_worst(const doctor_ep *eps, int n)
{
    int i, worst = DOC_GREEN;

    for (i = 0; i < n; i++) {
        if (eps[i].status > worst) {
            worst = eps[i].status;
        }
    }
    return worst;
}


/* --latency: time a round-trip probe (xrootd stat + cms locate plane) against
 * every reachable node. Informational — it never changes the worst verdict.
 * Skipped under a graph-only map (dot/mermaid), whose output must stay clean. */
static void
fanout_probe_latency(const diag_args *a, doctor_ep *eps, int n)
{
    int i;

    if (!a->latency || (a->map && doctor_map_graph_only(a->map_format))) {
        return;
    }
    for (i = 0; i < n; i++) {
        doctor_latency_probe(a, &eps[i]);
    }
}


/* Release the fan-out array and project the fleet verdict onto an exit code. */
static int
fanout_done(doctor_ep *eps, int worst)
{
    free(eps);
    return (worst == DOC_RED) ? 1 : 0;
}


static int
do_remote_doctor_fanout(const diag_args *a)
{
    doctor_ep *eps = NULL;
    int        i, n = 0, trunc = 0, worst;

    if (doctor_fanout(a, &eps, &n, &trunc) != 0 || eps == NULL) {
        fprintf(stderr, "xrddiag: remote-doctor fan-out allocation failed\n");
        return 50;
    }
    /* record the cross-cluster findings onto eps[0]; print the human summary only
     * on the plain-text path (not for --json, nor when --map owns the output). */
    doctor_cross_cluster(eps, n, (a->json || a->map) ? NULL : stdout);
    worst = fanout_worst(eps, n);
    fanout_probe_latency(a, eps, n);
    /* --map: draw the discovered mesh. A machine graph (dot/mermaid) is emitted
     * ALONE so it pipes cleanly to `dot`/a Mermaid renderer; the ASCII tree is
     * drawn as a header above the usual per-node report. */
    if (a->map) {
        doctor_render_map(eps, n, a->map_format, stdout);
        if (doctor_map_graph_only(a->map_format)) {
            return fanout_done(eps, worst);
        }
        printf("\n");
    }
    if (a->json) {
        doctor_emit_json(eps, n, stdout);
        return fanout_done(eps, worst);
    }
    printf("remote-doctor: manager + %d data server(s)%s\n", n - 1,
           trunc ? " (data-server list truncated to cap)" : "");
    for (i = 0; i < n; i++) {
        remote_doctor_report_ep(&eps[i]);
    }
    if (a->latency) { doctor_render_latency(eps, n, stdout); }
    remote_doctor_report_creds();
    printf("\nResult: worst=%s\n", doc_color(worst));
    return fanout_done(eps, worst);
}

int
do_remote_doctor(const diag_args *a)
{
    doctor_ep eps[8];
    int       i, worst = DOC_GREEN, crit;

    if (a->nurls < 1) {
        fprintf(stderr, "xrddiag: remote-doctor needs at least one URL\n");
        return 50;
    }
    if (a->all_servers || a->map || a->latency) {
        return do_remote_doctor_fanout(a);
    }
    for (i = 0; i < a->nurls; i++) {
        doctor_dispatch(a, a->urls[i], &eps[i]);
        if (eps[i].status > worst) {
            worst = eps[i].status;
        }
    }

    if (a->json) {
        doctor_emit_json(eps, a->nurls, stdout);
        return (worst == DOC_RED) ? 1 : 0;
    }

    printf("remote-doctor: %d endpoint(s)\n", a->nurls);
    for (i = 0; i < a->nurls; i++) {
        remote_doctor_report_ep(&eps[i]);
    }

    remote_doctor_report_creds();

    printf("\n");
    crit = doctor_cross(eps, a->nurls, stdout);
    printf("Result: worst=%s, %d critical path issue(s)\n", doc_color(worst), crit);
    return (worst == DOC_RED || crit > 0) ? 1 : 0;
}
