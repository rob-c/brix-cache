/*
 * xrd_doctor_json.c - xrd doctor JSON report renderer.
 * Phase-38 split of xrd_doctor.c; behavior-identical.
 */
#include "xrd_internal.h"


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
