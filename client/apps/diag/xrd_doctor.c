/*
 * xrd_doctor.c - extracted concern
 * Phase-38 split of xrd.c; behavior-identical.
 */
#include "xrd_internal.h"


/* Gather every endpoint fact doctor reports into *p: a normal (authenticated) connect
 * for liveness/TLS/auth/caps, plus a separate no-login insecure probe for the server
 * cert, plus a clock-skew measurement. Never fails hard — unreachable slices are left
 * zeroed (p->connected / p->cert.have / p->clock_have signal availability). */
void
xrd_doctor_probe(const char *endpoint, xrd_probe *p)
{
    brix_url    u;
    brix_opts   o;
    brix_conn   c;
    brix_status st;
    char        errbuf[XRDC_MSG_MAX + 64];   /* room for a prefixed status msg */

    memset(p, 0, sizeof(*p));
    memset(&o, 0, sizeof(o));
    o.verify_host = 1;
    brix_status_clear(&st);
    if (brix_endpoint_parse(endpoint, &u, &st) != 0) {
        snprintf(p->err, sizeof(p->err), "%s", st.msg);
        return;
    }
    snprintf(p->host, sizeof(p->host), "%s", u.host);
    p->port = u.port;

    /* (1) authenticated connect: liveness, role, negotiated TLS + auth, caps. */
    if (brix_connect(&c, &u, &o, &st) != 0) {
        snprintf(p->err, sizeof(p->err), "%s", st.msg);
    } else {
        const char *ver = NULL, *cipher = NULL;
        p->connected    = 1;
        p->server_flags = c.server_flags;
        snprintf(p->auth, sizeof(p->auth), "%s",
                 c.diag.chosen_auth ? c.diag.chosen_auth : "anonymous");
        snprintf(p->sec_list, sizeof(p->sec_list), "%s", c.sec_list);
        if (brix_tls_info(&c, &ver, &cipher)) {
            p->tls_active = 1;
            p->tls_ver = ver; p->tls_cipher = cipher;
        }
        xrd_probe_caps(&c, p);
        brix_close(&c);
    }

    /* (2) no-login insecure probe for the server certificate (roots:// / gotoTLS). */
    {
        brix_conn   cc;
        brix_opts   co;
        brix_status cs;
        memset(&co, 0, sizeof(co));
        co.insecure_tls = 1; co.verify_host = 0;
        brix_status_clear(&cs);
        if (brix_connect_no_login(&cc, &u, &co, &cs) == 0) {
            brix_tls_peer_cert_info(&cc, &p->cert);
            brix_close(&cc);
        }
    }

    /* (3) clock skew (HTTP Date for web URLs, touch+stat for root://). */
    (void) xrd_measure_clock_skew(endpoint, &o, p, errbuf, sizeof(errbuf));
}


/* Emit a JSON string literal for `s` (escaped, NULL → ""). */
void
xrd_json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; s != NULL && *s != '\0'; s++) {
        unsigned char ch = (unsigned char) *s;
        if (ch == '"' || ch == '\\') { fputc('\\', f); fputc((int) ch, f); }
        else if (ch == '\n') { fputs("\\n", f); }
        else if (ch == '\t') { fputs("\\t", f); }
        else if (ch == '\r') { fputs("\\r", f); }
        else if (ch < 0x20)  { fprintf(f, "\\u%04x", (unsigned) ch); }
        else { fputc((int) ch, f); }
    }
    fputc('"', f);
}


/*
 * WHAT: JSON emit — the connect/identity head of the doctor report (endpoint,
 *       port, connected, connect_error, role, server_flags, auth, sec_list).
 * WHY:  extracted from xrd_doctor_json (phase-72 H4) so each report section is
 *       one small renderer; the emitted bytes are frozen (CLI UX contract).
 * HOW:  writes directly to stdout in the exact original order/punctuation;
 *       connect_error appears only for a failed connect with a message.
 */
static void
doctor_json_head(const xrd_probe *p)
{
    printf("{\n");
    printf("  \"endpoint\": "); xrd_json_str(stdout, p->host);
    printf(",\n  \"port\": %d,\n", p->port);
    printf("  \"connected\": %s,\n", p->connected ? "true" : "false");
    if (!p->connected && p->err[0] != '\0') {
        printf("  \"connect_error\": "); xrd_json_str(stdout, p->err); printf(",\n");
    }
    printf("  \"role\": "); xrd_json_str(stdout, xrd_role_str(p->server_flags));
    printf(",\n  \"server_flags\": %u,\n", (unsigned) p->server_flags);
    printf("  \"auth\": "); xrd_json_str(stdout, p->connected ? p->auth : "");
    printf(",\n  \"sec_list\": "); xrd_json_str(stdout, p->sec_list); printf(",\n");
}


/*
 * WHAT: JSON emit — the "tls" object (active flag + version/cipher when live).
 * WHY:  one section per renderer keeps xrd_doctor_json a flat section list.
 * HOW:  version/cipher only appear when TLS negotiated, matching the original.
 */
static void
doctor_json_tls(const xrd_probe *p)
{
    printf("  \"tls\": { \"active\": %s", p->tls_active ? "true" : "false");
    if (p->tls_active) {
        printf(", \"version\": "); xrd_json_str(stdout, p->tls_ver);
        printf(", \"cipher\": ");  xrd_json_str(stdout, p->tls_cipher);
    }
    printf(" },\n");
}


/*
 * WHAT: JSON emit — the "cert" object (subject/issuer/SAN/validity/verdicts),
 *       or the literal `null` when no server certificate was captured.
 * WHY:  the cert block is the largest single section of the old branch ladder;
 *       isolating it removes most of xrd_doctor_json's complexity.
 * HOW:  formats the validity epochs locally (the buffers were only ever used
 *       for this section) and emits fields in the original fixed order.
 */
static void
doctor_json_cert(const xrd_probe *p)
{
    char nb[32], na[32];

    printf("  \"cert\": ");
    if (!p->cert.have) {
        printf("null,\n");
        return;
    }
    xrd_fmt_epoch(p->cert.not_before, nb, sizeof(nb));
    xrd_fmt_epoch(p->cert.not_after,  na, sizeof(na));
    printf("{\n    \"subject\": "); xrd_json_str(stdout, p->cert.subject);
    printf(",\n    \"issuer\": ");  xrd_json_str(stdout, p->cert.issuer);
    printf(",\n    \"sans\": ");    xrd_json_str(stdout, p->cert.sans);
    printf(",\n    \"not_before\": %ld", p->cert.not_before);
    printf(",\n    \"not_before_utc\": "); xrd_json_str(stdout, nb);
    printf(",\n    \"not_after\": %ld",  p->cert.not_after);
    printf(",\n    \"not_after_utc\": ");  xrd_json_str(stdout, na);
    printf(",\n    \"days_left\": %ld", p->cert.days_left);
    printf(",\n    \"expired\": %s",       p->cert.expired ? "true" : "false");
    printf(",\n    \"not_yet_valid\": %s", p->cert.not_yet_valid ? "true" : "false");
    printf(",\n    \"host_match\": %s",    p->cert.host_match ? "true" : "false");
    printf(",\n    \"self_signed\": %s\n  },\n", p->cert.self_signed ? "true" : "false");
}


/*
 * WHAT: JSON emit — the "clock" object (server epoch/offset/rtt/method), or
 *       `null` when skew could not be measured.
 * WHY:  section renderer extracted from xrd_doctor_json (phase-72 H4).
 * HOW:  single-line object, byte-identical to the original emission.
 */
static void
doctor_json_clock(const xrd_probe *p)
{
    printf("  \"clock\": ");
    if (!p->clock_have) {
        printf("null,\n");
        return;
    }
    printf("{ \"server_epoch\": %ld, \"offset_seconds\": %.1f, \"rtt_ms\": %.1f, \"method\": ",
           p->server_epoch, p->offset_s, p->rtt_ms);
    xrd_json_str(stdout, p->clock_method);
    printf(" },\n");
}


/*
 * WHAT: JSON emit — the "capabilities" object (kXR_Qconfig key/value pairs).
 * WHY:  section renderer extracted from xrd_doctor_json (phase-72 H4).
 * HOW:  comma-separates entries via the `i ?` idiom; the closing brace gets a
 *       newline+indent only when at least one cap was probed (as before).
 */
static void
doctor_json_caps(const xrd_probe *p)
{
    int i;

    printf("  \"capabilities\": {");
    for (i = 0; i < p->ncaps; i++) {
        printf("%s\n    ", i ? "," : "");
        xrd_json_str(stdout, p->caps[i].key);
        printf(": ");
        xrd_json_str(stdout, p->caps[i].val);
    }
    printf("%s},\n", p->ncaps ? "\n  " : "");
}


/*
 * WHAT: JSON emit — the "credentials" object (bearer token + GSI proxy
 *       presence, with paths when present).
 * WHY:  section renderer extracted from xrd_doctor_json (phase-72 H4).
 * HOW:  path fields are conditional on presence, exactly as before.
 */
static void
doctor_json_creds(const xrd_cred_facts *cf)
{
    printf("  \"credentials\": {\n");
    printf("    \"bearer_token\": %s", cf->token_present ? "true" : "false");
    if (cf->token_present) { printf(",\n    \"bearer_token_path\": "); xrd_json_str(stdout, cf->token_path); }
    printf(",\n    \"gsi_proxy\": %s", cf->proxy_present ? "true" : "false");
    if (cf->proxy_present) { printf(",\n    \"gsi_proxy_path\": "); xrd_json_str(stdout, cf->proxy_path); }
    printf("\n  },\n");
}


/*
 * WHAT: JSON emit — one functional-battery object inside the "tests" array
 *       (endpoint/protocol/reachability, pass counts, per-check results).
 * WHY:  splitting the per-battery body out of the array loop keeps both under
 *       the complexity gate while preserving the exact nesting/punctuation.
 * HOW:  `idx` drives the leading-comma idiom for the enclosing array; the
 *       "error" field appears only for an unreachable battery with a message.
 */
static void
doctor_json_battery(const xrd_battery *bt, int idx)
{
    int j;

    printf("%s\n    {\n", idx ? "," : "");
    printf("      \"endpoint\": "); xrd_json_str(stdout, bt->endpoint);
    printf(",\n      \"protocol\": "); xrd_json_str(stdout, bt->protocol);
    printf(",\n      \"reachable\": %s", bt->reachable ? "true" : "false");
    if (!bt->reachable && bt->err[0] != '\0') {
        printf(",\n      \"error\": "); xrd_json_str(stdout, bt->err);
    }
    printf(",\n      \"passed\": %d, \"failed\": %d, \"skipped\": %d",
           bt->npass, bt->nfail, bt->nskip);
    printf(",\n      \"checks\": [");
    for (j = 0; j < bt->n; j++) {
        printf("%s\n        { \"name\": ", j ? "," : "");
        xrd_json_str(stdout, bt->checks[j].name);
        printf(", \"status\": ");
        xrd_json_str(stdout, bt->checks[j].skipped ? "skip"
                             : (bt->checks[j].ok ? "pass" : "fail"));
        printf(", \"detail\": ");
        xrd_json_str(stdout, bt->checks[j].detail);
        printf(" }");
    }
    printf("%s]\n    }", bt->n ? "\n      " : "");
}


/*
 * WHAT: JSON emit — the "tests" array (one object per protocol battery).
 * WHY:  section renderer extracted from xrd_doctor_json (phase-72 H4).
 * HOW:  delegates each element to doctor_json_battery; the closing bracket
 *       gets newline+indent only when the array is non-empty (as before).
 */
static void
doctor_json_tests(const xrd_battery *bats, int nbats)
{
    int i;

    printf("  \"tests\": [");
    for (i = 0; i < nbats; i++) {
        doctor_json_battery(&bats[i], i);
    }
    printf("%s]\n", nbats ? "\n  " : "");
}


/* Dump the full endpoint report as a single JSON object on stdout. Renders the
 * fixed section sequence head/tls/cert/clock/caps/credentials/tests — the same
 * probe results the text report walks, in the same order. */
void
xrd_doctor_json(const xrd_probe *p, const xrd_cred_facts *cf,
                const xrd_battery *bats, int nbats)
{
    doctor_json_head(p);
    doctor_json_tls(p);
    doctor_json_cert(p);
    doctor_json_clock(p);
    doctor_json_caps(p);
    doctor_json_creds(cf);
    doctor_json_tests(bats, nbats);
    printf("}\n");
}



/*
 * WHAT: the full state of one `xrd doctor` run — parsed CLI options, discovered
 *       local credentials, functional-battery results, and the running fatal flag.
 * WHY:  the run was one 134-NLOC function (phase-72 H4); passing this struct
 *       lets each stage (parse / creds / batteries / render) be a small helper
 *       with explicit data flow instead of a dozen shared locals.
 * HOW:  filled top-down: doctor_parse_args → doctor_discover_creds →
 *       doctor_run_batteries; then either the JSON or text renderer walks the
 *       SAME results in the SAME fixed check order.
 */
typedef struct {
    const char  *endpoint;                 /* primary endpoint (or NULL) */
    const char  *also[XRD_DOCTOR_MAX_EP];  /* --also protocol faces */
    int          nalso;
    int          want_json;                /* --json */
    int          do_rw;                    /* --rw / --write */
    int          verify;                   /* 0 after --insecure */
    char        *tok;                      /* discovered bearer token (owned) */
    int          token_present;
    char         pxp[1024];                /* default GSI proxy path */
    int          proxy_present;
    xrd_battery  bats[XRD_DOCTOR_MAX_EP];  /* functional battery results */
    int          nbats;
    int          fatal;                    /* accumulates → exit code */
} xrd_doctor_run;


/*
 * WHAT: parse `xrd doctor` CLI flags into *d (endpoint, --also list, modes).
 * WHY:  stage 1 of the doctor pipeline, split from the old monolith (H4).
 * HOW:  same flag ladder as before: first non-flag arg is the endpoint,
 *       --also collects up to XRD_DOCTOR_MAX_EP-1 extra faces (excess URLs
 *       are consumed and dropped), unknown flags are ignored.
 */
static void
doctor_parse_args(int argc, char **argv, xrd_doctor_run *d)
{
    int i;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0)             { d->want_json = 1; }
        else if (strcmp(argv[i], "--rw") == 0
                 || strcmp(argv[i], "--write") == 0)    { d->do_rw = 1; }
        else if (strcmp(argv[i], "--insecure") == 0)    { d->verify = 0; }
        else if (strcmp(argv[i], "--also") == 0 && i + 1 < argc) {
            if (d->nalso < XRD_DOCTOR_MAX_EP - 1) { d->also[d->nalso++] = argv[++i]; }
            else { i++; }
        }
        else if (d->endpoint == NULL && argv[i][0] != '-') { d->endpoint = argv[i]; }
    }
}


/*
 * WHAT: discover local credentials (bearer token + default GSI proxy) into *d.
 * WHY:  stage 2 of the doctor pipeline; both renderers report these facts.
 * HOW:  token via the standard discovery chain (caller frees d->tok), proxy
 *       presence via an access(R_OK) probe of the conventional path.
 */
static void
doctor_discover_creds(xrd_doctor_run *d)
{
    d->tok           = brix_token_discover();
    d->token_present = (d->tok != NULL);
    brix_proxy_default_path(d->pxp, sizeof(d->pxp));
    d->proxy_present = (access(d->pxp, R_OK) == 0);
}


/*
 * WHAT: run the functional method battery on the primary endpoint + each
 *       --also face; any failed check marks the run fatal.
 * WHY:  stage 3 of the doctor pipeline; results feed both output modes.
 * HOW:  batteries run in CLI order (primary first) so the report order —
 *       text and JSON alike — matches the invocation.
 */
static void
doctor_run_batteries(xrd_doctor_run *d)
{
    int i;

    if (d->endpoint != NULL) {
        xrd_run_battery(d->endpoint, d->do_rw, d->verify, &d->bats[d->nbats++]);
    }
    for (i = 0; i < d->nalso; i++) {
        xrd_run_battery(d->also[i], d->do_rw, d->verify, &d->bats[d->nbats++]);
    }
    for (i = 0; i < d->nbats; i++) {
        if (d->bats[i].nfail > 0) { d->fatal = 1; }
    }
}


/*
 * WHAT: --json mode — probe the endpoint, emit the whole report as one JSON
 *       object, apply the fatal verdicts, and return the exit code.
 * WHY:  terminal stage of the JSON path, split from the old monolith (H4).
 * HOW:  same verdict rules as the text report: failed connect, expired /
 *       not-yet-valid cert, or >300 s clock skew are fatal.
 */
static int
doctor_emit_json(xrd_doctor_run *d)
{
    xrd_probe      p;
    xrd_cred_facts cf;

    memset(&p, 0, sizeof(p));
    if (d->endpoint != NULL) { xrd_doctor_probe(d->endpoint, &p); }
    cf.token_present = d->token_present;
    cf.token_path    = d->token_present ? "(discovered)" : "";
    cf.proxy_present = d->proxy_present;
    cf.proxy_path    = d->pxp;
    xrd_doctor_json(&p, &cf, d->bats, d->nbats);
    if (d->tok != NULL) { free(d->tok); }
    if (d->endpoint != NULL && !p.connected)               { d->fatal = 1; }
    if (p.cert.have && (p.cert.expired || p.cert.not_yet_valid)) { d->fatal = 1; }
    if (p.clock_have && (p.offset_s > 300.0 || p.offset_s < -300.0)) { d->fatal = 1; }
    return d->fatal ? 1 : 0;
}


/*
 * WHAT: text report — the "== credentials ==" section (token, proxy, hints).
 * WHY:  first text section, split from the old monolith (H4).
 * HOW:  explains + frees the discovered token; a cred-diagnose hit is fatal.
 */
static void
doctor_report_creds(xrd_doctor_run *d)
{
    printf("== credentials ==\n");
    if (d->tok != NULL) { brix_token_explain(d->tok, stdout); free(d->tok); }
    else { printf("  bearer token: none discovered (BEARER_TOKEN / *_FILE / XDG / /tmp)\n"); }
    if (d->proxy_present) { brix_gsi_cert_explain(d->pxp, stdout); }
    else                  { printf("  GSI proxy: none at %s\n", d->pxp); }
    if (brix_cred_diagnose(0, "  hint: ", stdout)) { d->fatal = 1; }
}


/*
 * WHAT: text report — the connect/auth/TLS lines of the endpoint section.
 * WHY:  per-check renderer; the JSON path reports the same probe fields.
 * HOW:  failed connect prints the error and marks the run fatal; success
 *       prints role/auth, the sec list when present, and the TLS posture.
 */
static void
doctor_report_conn(const xrd_probe *p, int *fatal)
{
    if (!p->connected) {
        printf("  connect:  FAILED (%s)\n", p->err[0] ? p->err : "?");
        *fatal = 1;
        return;
    }
    printf("  connect:  OK   role=%s  auth=%s\n",
           xrd_role_str(p->server_flags), p->auth);
    if (p->sec_list[0] != '\0') { printf("  sec:      %s\n", p->sec_list); }
    if (p->tls_active) {
        printf("  TLS:      active (%s %s)\n",
               p->tls_ver ? p->tls_ver : "?", p->tls_cipher ? p->tls_cipher : "?");
    } else {
        printf("  TLS:      cleartext\n");
    }
}


/*
 * WHAT: text report — the server host-certificate lines of the endpoint section.
 * WHY:  per-check renderer mirroring doctor_json_cert on the same probe data.
 * HOW:  expired / not-yet-valid certs are fatal; a valid cert reports days
 *       left + host match; no captured cert reports a cleartext session.
 */
static void
doctor_report_cert(const xrd_probe *p, int *fatal)
{
    char nb[32], na[32];

    if (!p->cert.have) {
        printf("  cert:     none (cleartext session)\n");
        return;
    }
    xrd_fmt_epoch(p->cert.not_before, nb, sizeof(nb));
    xrd_fmt_epoch(p->cert.not_after,  na, sizeof(na));
    printf("  cert:     %s\n", p->cert.subject);
    printf("            issuer %s\n", p->cert.issuer);
    if (p->cert.expired) {
        printf("            EXPIRED %ld day(s) ago (%s)\n", -p->cert.days_left, na);
        *fatal = 1;
    } else if (p->cert.not_yet_valid) {
        printf("            NOT YET VALID (from %s)\n", nb);
        *fatal = 1;
    } else {
        printf("            valid, %ld day(s) left (until %s)  host-match=%s\n",
               p->cert.days_left, na, p->cert.host_match ? "yes" : "no");
    }
}


/*
 * WHAT: text report — the clock-skew line of the endpoint section.
 * WHY:  per-check renderer mirroring doctor_json_clock on the same probe data.
 * HOW:  >300 s skew is fatal, >60 s warns (breaks token exp/nbf + GSI windows);
 *       an unmeasured clock explains what the measurement needs.
 */
static void
doctor_report_clock(const xrd_probe *p, int *fatal)
{
    if (!p->clock_have) {
        printf("  clock:    not measured (need an HTTP endpoint or write access)\n");
        return;
    }
    {
        double ao = xrd_fabs(p->offset_s);
        printf("  clock:    offset %+.1f s, rtt %.1f ms (%s)\n",
               p->offset_s, p->rtt_ms, p->clock_method);
        if (ao > 300.0) { *fatal = 1; }
        if (ao > 60.0) {
            printf("            WARNING: skew may break token exp/nbf + GSI validity\n");
        }
    }
}


/*
 * WHAT: text report — the kXR_Qconfig capability line of the endpoint section.
 * WHY:  per-check renderer mirroring doctor_json_caps on the same probe data.
 * HOW:  single "  caps:    " line of space-separated key=val pairs; omitted
 *       entirely when no capability key answered.
 */
static void
doctor_report_caps(const xrd_probe *p)
{
    int j;

    if (p->ncaps <= 0) { return; }
    printf("  caps:    ");
    for (j = 0; j < p->ncaps; j++) {
        printf(" %s=%s", p->caps[j].key, p->caps[j].val);
    }
    printf("\n");
}


/*
 * WHAT: text report — the "== endpoint host:port ==" section: probe the
 *       primary endpoint and render the connect/cert/clock/caps checks.
 * WHY:  stage of the text path split from the old monolith (H4); runs the
 *       per-check renderers in the same fixed order the JSON report uses.
 * HOW:  one probe, then doctor_report_conn/cert/clock/caps in sequence, each
 *       flagging d->fatal on its own verdict.
 */
static void
doctor_report_endpoint(xrd_doctor_run *d)
{
    xrd_probe p;

    xrd_doctor_probe(d->endpoint, &p);
    printf("== endpoint %s:%d ==\n", p.host, p.port);
    doctor_report_conn(&p, &d->fatal);
    doctor_report_cert(&p, &d->fatal);
    doctor_report_clock(&p, &d->fatal);
    doctor_report_caps(&p);
}


/*
 * WHAT: text report — one "== <proto> tests: <url> ==" functional-battery
 *       section per probed protocol face.
 * WHY:  final text stage split from the old monolith (H4); walks the same
 *       battery results doctor_json_tests renders.
 * HOW:  unreachable faces report the error and move on; otherwise each check
 *       prints a PASS/FAIL/SKIP row followed by the pass-count summary line.
 */
static void
doctor_report_batteries(const xrd_doctor_run *d)
{
    int i;

    for (i = 0; i < d->nbats; i++) {
        const xrd_battery *bt = &d->bats[i];
        int                j;
        printf("== %s tests: %s ==\n", bt->protocol, bt->endpoint);
        if (!bt->reachable) {
            printf("  unreachable (%s)\n", bt->err[0] ? bt->err : "?");
            continue;
        }
        for (j = 0; j < bt->n; j++) {
            const xrd_check *ck = &bt->checks[j];
            const char      *tag = ck->skipped ? "SKIP" : (ck->ok ? "PASS" : "FAIL");
            printf("  [%s] %-18s %s\n", tag, ck->name, ck->detail);
        }
        printf("  -> %d passed, %d failed, %d skipped%s\n",
               bt->npass, bt->nfail, bt->nskip,
               d->do_rw ? "" : "  (read-only; --rw for writes)");
    }
}


/* `xrd doctor [endpoint] [--rw] [--also URL]... [--insecure] [--json]` — one-stop
 * endpoint health: local credentials, and for each endpoint the connect/auth/TLS
 * posture, server host-cert validity, clock skew, the kXR_Qconfig capability matrix,
 * AND a functional method battery (read-only by default; --rw adds a full
 * write/read/verify/checksum/metadata cycle). --also adds protocol faces (root:// /
 * davs:// / s3://) so one run can cover every method on every protocol. --json emits
 * the whole report as one object. Exit nonzero on a fatal local cred problem, a failed
 * connect, an expired/skewed server, or any failed functional check. */
int
xrd_doctor(int argc, char **argv)
{
    xrd_doctor_run d;

    memset(&d, 0, sizeof(d));
    d.verify = 1;
    doctor_parse_args(argc, argv, &d);
    brix_crypto_init();   /* arm SHA-256/HMAC for token/proxy inspection */
    doctor_discover_creds(&d);

    /* Run the functional battery on the primary endpoint + each --also face. */
    doctor_run_batteries(&d);

    if (d.want_json) {
        return doctor_emit_json(&d);
    }

    /* human report */
    doctor_report_creds(&d);

    if (d.endpoint == NULL && d.nbats == 0) {
        printf("(pass an endpoint to also test connect + TLS + cert + clock + caps;\n"
               " add --rw for write tests and --also <url> for more protocols)\n");
        return d.fatal ? 1 : 0;
    }

    if (d.endpoint != NULL) {
        doctor_report_endpoint(&d);
    }

    /* functional method batteries (per protocol face) */
    doctor_report_batteries(&d);
    return d.fatal ? 1 : 0;
}


/* Probe the kXR_Qconfig capability keys on a live connection into p->caps. */
void
xrd_probe_caps(brix_conn *c, xrd_probe *p)
{
    int i;
    p->ncaps = 0;
    for (i = 0; XRD_CAP_KEYS[i] != NULL && p->ncaps < XRD_CAPS_MAX; i++) {
        char        reply[256], *nl, *eq;
        const char *val;
        brix_status st;
        brix_status_clear(&st);
        if (brix_query(c, kXR_Qconfig, XRD_CAP_KEYS[i], reply, sizeof(reply), &st) != 0) {
            continue;
        }
        if ((nl = strchr(reply, '\n')) != NULL) { *nl = '\0'; }
        eq  = strchr(reply, '=');               /* "key=val" → val; else whole reply */
        val = (eq != NULL) ? eq + 1 : reply;
        snprintf(p->caps[p->ncaps].key, sizeof(p->caps[p->ncaps].key), "%s",
                 XRD_CAP_KEYS[i]);
        snprintf(p->caps[p->ncaps].val, sizeof(p->caps[p->ncaps].val), "%s", val);
        p->ncaps++;
    }
}


/* `xrd certinfo <endpoint>` — connect (requesting TLS) and report the server's host
 * certificate: subject/issuer/SAN, validity window, days-until-expiry, host match.
 * Exit nonzero if the cert is expired or not yet valid. */
int
xrd_certinfo(int argc, char **argv)
{
    const char    *endpoint = (argc >= 3 && argv[2][0] != '-') ? argv[2] : NULL;
    brix_url       u;
    brix_opts      o;
    brix_conn      c;
    brix_status    st;
    brix_cert_info ci;
    char           nb[32], na[32];

    if (endpoint == NULL) { fprintf(stderr, "usage: xrd certinfo <endpoint>\n"); return 50; }
    memset(&o, 0, sizeof(o));
    /* Inspect, don't gate: skip chain + host verification so an expired/untrusted/
     * self-signed cert is still reportable. TLS happens per the scheme (roots://,
     * or a server that requires it); a cleartext root:// endpoint reports "no cert". */
    o.insecure_tls = 1; o.verify_host = 0;
    brix_crypto_init();
    brix_status_clear(&st);
    if (brix_endpoint_parse(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrd certinfo: %s\n", st.msg); return 50;
    }
    if (brix_connect_no_login(&c, &u, &o, &st) != 0) {
        fprintf(stderr, "xrd certinfo: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return brix_shellcode(&st);
    }
    if (brix_tls_peer_cert_info(&c, &ci) != 0 || !ci.have) {
        printf("%s:%d — no server certificate (session is cleartext)\n", u.host, u.port);
        brix_close(&c);
        return 0;
    }
    xrd_fmt_epoch(ci.not_before, nb, sizeof(nb));
    xrd_fmt_epoch(ci.not_after,  na, sizeof(na));
    printf("server certificate for %s:%d\n", u.host, u.port);
    printf("  subject:    %s\n", ci.subject);
    printf("  issuer:     %s\n", ci.issuer);
    if (ci.sans[0] != '\0') { printf("  SAN:        %s\n", ci.sans); }
    printf("  validity:   %s .. %s\n", nb, na);
    if (ci.expired) {
        printf("  status:     EXPIRED %ld day(s) ago\n", -ci.days_left);
    } else if (ci.not_yet_valid) {
        printf("  status:     NOT YET VALID\n");
    } else {
        printf("  status:     valid, %ld day(s) left\n", ci.days_left);
    }
    printf("  host match: %s%s\n", ci.host_match ? "yes" : "no",
           ci.self_signed ? "   (self-signed)" : "");
    brix_close(&c);
    return (ci.expired || ci.not_yet_valid) ? 1 : 0;
}
