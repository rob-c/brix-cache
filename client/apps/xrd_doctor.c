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
    xrdc_url    u;
    xrdc_opts   o;
    xrdc_conn   c;
    xrdc_status st;
    char        errbuf[XRDC_MSG_MAX + 64];   /* room for a prefixed status msg */

    memset(p, 0, sizeof(*p));
    memset(&o, 0, sizeof(o));
    o.verify_host = 1;
    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(endpoint, &u, &st) != 0) {
        snprintf(p->err, sizeof(p->err), "%s", st.msg);
        return;
    }
    snprintf(p->host, sizeof(p->host), "%s", u.host);
    p->port = u.port;

    /* (1) authenticated connect: liveness, role, negotiated TLS + auth, caps. */
    if (xrdc_connect(&c, &u, &o, &st) != 0) {
        snprintf(p->err, sizeof(p->err), "%s", st.msg);
    } else {
        const char *ver = NULL, *cipher = NULL;
        p->connected    = 1;
        p->server_flags = c.server_flags;
        snprintf(p->auth, sizeof(p->auth), "%s",
                 c.diag.chosen_auth ? c.diag.chosen_auth : "anonymous");
        snprintf(p->sec_list, sizeof(p->sec_list), "%s", c.sec_list);
        if (xrdc_tls_info(&c, &ver, &cipher)) {
            p->tls_active = 1;
            p->tls_ver = ver; p->tls_cipher = cipher;
        }
        xrd_probe_caps(&c, p);
        xrdc_close(&c);
    }

    /* (2) no-login insecure probe for the server certificate (roots:// / gotoTLS). */
    {
        xrdc_conn   cc;
        xrdc_opts   co;
        xrdc_status cs;
        memset(&co, 0, sizeof(co));
        co.insecure_tls = 1; co.verify_host = 0;
        xrdc_status_clear(&cs);
        if (xrdc_connect_no_login(&cc, &u, &co, &cs) == 0) {
            xrdc_tls_peer_cert_info(&cc, &p->cert);
            xrdc_close(&cc);
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


/* Dump the full endpoint report as a single JSON object on stdout. */
void
xrd_doctor_json(const xrd_probe *p, int token_present, const char *token_path,
                int proxy_present, const char *proxy_path,
                const xrd_battery *bats, int nbats)
{
    char nb[32], na[32];
    int  i, j;

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

    printf("  \"tls\": { \"active\": %s", p->tls_active ? "true" : "false");
    if (p->tls_active) {
        printf(", \"version\": "); xrd_json_str(stdout, p->tls_ver);
        printf(", \"cipher\": ");  xrd_json_str(stdout, p->tls_cipher);
    }
    printf(" },\n");

    printf("  \"cert\": ");
    if (!p->cert.have) {
        printf("null,\n");
    } else {
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

    printf("  \"clock\": ");
    if (!p->clock_have) {
        printf("null,\n");
    } else {
        printf("{ \"server_epoch\": %ld, \"offset_seconds\": %.1f, \"rtt_ms\": %.1f, \"method\": ",
               p->server_epoch, p->offset_s, p->rtt_ms);
        xrd_json_str(stdout, p->clock_method);
        printf(" },\n");
    }

    printf("  \"capabilities\": {");
    for (i = 0; i < p->ncaps; i++) {
        printf("%s\n    ", i ? "," : "");
        xrd_json_str(stdout, p->caps[i].key);
        printf(": ");
        xrd_json_str(stdout, p->caps[i].val);
    }
    printf("%s},\n", p->ncaps ? "\n  " : "");

    printf("  \"credentials\": {\n");
    printf("    \"bearer_token\": %s", token_present ? "true" : "false");
    if (token_present) { printf(",\n    \"bearer_token_path\": "); xrd_json_str(stdout, token_path); }
    printf(",\n    \"gsi_proxy\": %s", proxy_present ? "true" : "false");
    if (proxy_present) { printf(",\n    \"gsi_proxy_path\": "); xrd_json_str(stdout, proxy_path); }
    printf("\n  },\n");

    printf("  \"tests\": [");
    for (i = 0; i < nbats; i++) {
        const xrd_battery *bt = &bats[i];
        printf("%s\n    {\n", i ? "," : "");
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
    printf("%s]\n", nbats ? "\n  " : "");
    printf("}\n");
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
    const char *endpoint = NULL;
    const char *also[XRD_DOCTOR_MAX_EP];
    int         nalso = 0;
    int         want_json = 0, do_rw = 0, verify = 1, fatal = 0, i;
    char       *tok;
    char        pxp[1024];
    int         token_present, proxy_present;
    xrd_battery bats[XRD_DOCTOR_MAX_EP];
    int         nbats = 0;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0)             { want_json = 1; }
        else if (strcmp(argv[i], "--rw") == 0
                 || strcmp(argv[i], "--write") == 0)    { do_rw = 1; }
        else if (strcmp(argv[i], "--insecure") == 0)    { verify = 0; }
        else if (strcmp(argv[i], "--also") == 0 && i + 1 < argc) {
            if (nalso < XRD_DOCTOR_MAX_EP - 1) { also[nalso++] = argv[++i]; }
            else { i++; }
        }
        else if (endpoint == NULL && argv[i][0] != '-') { endpoint = argv[i]; }
    }
    xrootd_crypto_init();   /* arm SHA-256/HMAC for token/proxy inspection */

    tok           = xrdc_token_discover();
    token_present = (tok != NULL);
    xrdc_proxy_default_path(pxp, sizeof(pxp));
    proxy_present = (access(pxp, R_OK) == 0);

    /* Run the functional battery on the primary endpoint + each --also face. */
    if (endpoint != NULL) {
        xrd_run_battery(endpoint, do_rw, verify, &bats[nbats++]);
    }
    for (i = 0; i < nalso; i++) {
        xrd_run_battery(also[i], do_rw, verify, &bats[nbats++]);
    }
    for (i = 0; i < nbats; i++) {
        if (bats[i].nfail > 0) { fatal = 1; }
    }

    if (want_json) {
        xrd_probe p;
        memset(&p, 0, sizeof(p));
        if (endpoint != NULL) { xrd_doctor_probe(endpoint, &p); }
        xrd_doctor_json(&p, token_present, token_present ? "(discovered)" : "",
                        proxy_present, pxp, bats, nbats);
        if (tok != NULL) { free(tok); }
        if (endpoint != NULL && !p.connected)               { fatal = 1; }
        if (p.cert.have && (p.cert.expired || p.cert.not_yet_valid)) { fatal = 1; }
        if (p.clock_have && (p.offset_s > 300.0 || p.offset_s < -300.0)) { fatal = 1; }
        return fatal ? 1 : 0;
    }

    /* human report */
    printf("== credentials ==\n");
    if (tok != NULL) { xrdc_token_explain(tok, stdout); free(tok); }
    else { printf("  bearer token: none discovered (BEARER_TOKEN / *_FILE / XDG / /tmp)\n"); }
    if (proxy_present) { xrdc_gsi_cert_explain(pxp, stdout); }
    else               { printf("  GSI proxy: none at %s\n", pxp); }
    if (xrdc_cred_diagnose(0, "  hint: ", stdout)) { fatal = 1; }

    if (endpoint == NULL && nbats == 0) {
        printf("(pass an endpoint to also test connect + TLS + cert + clock + caps;\n"
               " add --rw for write tests and --also <url> for more protocols)\n");
        return fatal ? 1 : 0;
    }

    if (endpoint != NULL) {
        xrd_probe p;
        char      nb[32], na[32];
        int       j;
        xrd_doctor_probe(endpoint, &p);
        printf("== endpoint %s:%d ==\n", p.host, p.port);
        if (!p.connected) {
            printf("  connect:  FAILED (%s)\n", p.err[0] ? p.err : "?");
            fatal = 1;
        } else {
            printf("  connect:  OK   role=%s  auth=%s\n",
                   xrd_role_str(p.server_flags), p.auth);
            if (p.sec_list[0] != '\0') { printf("  sec:      %s\n", p.sec_list); }
            if (p.tls_active) {
                printf("  TLS:      active (%s %s)\n",
                       p.tls_ver ? p.tls_ver : "?", p.tls_cipher ? p.tls_cipher : "?");
            } else {
                printf("  TLS:      cleartext\n");
            }
        }
        if (p.cert.have) {
            xrd_fmt_epoch(p.cert.not_before, nb, sizeof(nb));
            xrd_fmt_epoch(p.cert.not_after,  na, sizeof(na));
            printf("  cert:     %s\n", p.cert.subject);
            printf("            issuer %s\n", p.cert.issuer);
            if (p.cert.expired) {
                printf("            EXPIRED %ld day(s) ago (%s)\n", -p.cert.days_left, na);
                fatal = 1;
            } else if (p.cert.not_yet_valid) {
                printf("            NOT YET VALID (from %s)\n", nb);
                fatal = 1;
            } else {
                printf("            valid, %ld day(s) left (until %s)  host-match=%s\n",
                       p.cert.days_left, na, p.cert.host_match ? "yes" : "no");
            }
        } else {
            printf("  cert:     none (cleartext session)\n");
        }
        if (p.clock_have) {
            double ao = xrd_fabs(p.offset_s);
            printf("  clock:    offset %+.1f s, rtt %.1f ms (%s)\n",
                   p.offset_s, p.rtt_ms, p.clock_method);
            if (ao > 300.0) { fatal = 1; }
            if (ao > 60.0) {
                printf("            WARNING: skew may break token exp/nbf + GSI validity\n");
            }
        } else {
            printf("  clock:    not measured (need an HTTP endpoint or write access)\n");
        }
        if (p.ncaps > 0) {
            printf("  caps:    ");
            for (j = 0; j < p.ncaps; j++) {
                printf(" %s=%s", p.caps[j].key, p.caps[j].val);
            }
            printf("\n");
        }
    }

    /* functional method batteries (per protocol face) */
    for (i = 0; i < nbats; i++) {
        const xrd_battery *bt = &bats[i];
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
               bt->npass, bt->nfail, bt->nskip, do_rw ? "" : "  (read-only; --rw for writes)");
    }
    return fatal ? 1 : 0;
}


/* Probe the kXR_Qconfig capability keys on a live connection into p->caps. */
void
xrd_probe_caps(xrdc_conn *c, xrd_probe *p)
{
    int i;
    p->ncaps = 0;
    for (i = 0; XRD_CAP_KEYS[i] != NULL && p->ncaps < XRD_CAPS_MAX; i++) {
        char        reply[256], *nl, *eq;
        const char *val;
        xrdc_status st;
        xrdc_status_clear(&st);
        if (xrdc_query(c, kXR_Qconfig, XRD_CAP_KEYS[i], reply, sizeof(reply), &st) != 0) {
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
    xrdc_url       u;
    xrdc_opts      o;
    xrdc_conn      c;
    xrdc_status    st;
    xrdc_cert_info ci;
    char           nb[32], na[32];

    if (endpoint == NULL) { fprintf(stderr, "usage: xrd certinfo <endpoint>\n"); return 50; }
    memset(&o, 0, sizeof(o));
    /* Inspect, don't gate: skip chain + host verification so an expired/untrusted/
     * self-signed cert is still reportable. TLS happens per the scheme (roots://,
     * or a server that requires it); a cleartext root:// endpoint reports "no cert". */
    o.insecure_tls = 1; o.verify_host = 0;
    xrootd_crypto_init();
    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrd certinfo: %s\n", st.msg); return 50;
    }
    if (xrdc_connect_no_login(&c, &u, &o, &st) != 0) {
        fprintf(stderr, "xrd certinfo: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return xrdc_shellcode(&st);
    }
    if (xrdc_tls_peer_cert_info(&c, &ci) != 0 || !ci.have) {
        printf("%s:%d — no server certificate (session is cleartext)\n", u.host, u.port);
        xrdc_close(&c);
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
    xrdc_close(&c);
    return (ci.expired || ci.not_yet_valid) ? 1 : 0;
}
