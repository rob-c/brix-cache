/*
 * diag_doctor_json.c — the `xrddiag doctor --json` machine report.
 *
 * WHAT: renders the doctor_ep array as one JSON document: per-endpoint facts,
 *       issue list, classified diagnosis, CMS locate-plane verdict, plus the
 *       config/latency/EOS sub-objects each owned by its own translation unit.
 * WHY:  the emitter is pure formatting with no probing logic, and it was the
 *       single largest branch cluster in diag_doctor.c — hoisting it out keeps
 *       both files under the size and complexity gates.
 * HOW:  one emitter per JSON object, each writing its own leading comma so the
 *       orchestrator stays a flat loop (coding-standards §4/§8).
 */
#include "diag_internal.h"


/* `{"protocol":...,"host":...,"port":...,"status":...,"facts":{...},"issues":[`
 * — the endpoint header through to the (still open) issues array. */
static void
ep_emit_facts(const doctor_ep *e, int first, FILE *out)
{
    fprintf(out, "%s{\"protocol\":\"%s\",\"host\":", first ? "" : ",",
            dx_proto_name(e->proto));
    fjson_str(out, e->host);
    fprintf(out, ",\"port\":%d,\"status\":\"%s\","
            "\"connected\":%s,\"skipped\":%s,\"facts\":{\"family\":\"%s\","
            "\"tcp_ms\":%.3f,\"tls_ms\":%.3f,\"auth_ms\":%.3f,\"total_ms\":%.3f,"
            "\"rtt_us\":%u,\"retrans\":%u,\"tls\":\"%s\",\"auth\":\"%s\","
            "\"caps\":\"0x%x\",\"ttfb_ms\":%.3f,\"mbps\":%.1f,\"holders\":%d,"
            "\"metrics_http\":%d,\"shedding\":%s},\"issues\":[",
            e->port, doc_color(e->status),
            e->connected ? "true" : "false",
            e->skipped ? "true" : "false",
            e->nf.family == 10 ? "IPv6" : e->nf.family == 2 ? "IPv4" : "none",
            e->nf.tcp_ms, e->nf.tls_ms, e->nf.auth_ms, e->nf.total_ms,
            e->nf.rtt_us, e->nf.retrans,
            e->tls_active ? e->tls_ver : "none", e->auth, e->caps,
            e->ttfb_ms, e->mbps, e->holders, e->metrics_http,
            e->shedding ? "true" : "false");
}


/* Close the issues array with its members: `"a","b"],`-worth of content. */
static void
ep_emit_issues(const doctor_ep *e, FILE *out)
{
    int j;

    for (j = 0; j < e->nissues; j++) {
        if (j) {
            fputc(',', out);
        }
        fjson_str(out, e->issues[j]);
    }
    fprintf(out, "],\"diagnosis\":[");
}


/* The classified per-probe findings: verdict, kXR code, cause and remedy. */
static void
ep_emit_diagnosis(const doctor_ep *e, FILE *out)
{
    int j;

    for (j = 0; j < e->ndx; j++) {
        const dx_finding *d = &e->dx[j];

        fprintf(out, "%s{\"probe\":", j ? "," : "");
        fjson_str(out, d->probe);
        fprintf(out, ",\"verdict\":\"%s\",\"kxr\":%d,\"cause\":",
                dx_verdict_name(d->verdict), d->kxr);
        fjson_str(out, d->cause);
        fprintf(out, ",\"remedy\":");
        fjson_str(out, d->remedy);
        fputc('}', out);
    }
    fprintf(out, "]");
}


/* CMS locate-plane classification (mesh map) — role/access as the manager
 * reported it, present even for un-connectable (skipped) holders. */
static void
ep_emit_cms(const doctor_cmsloc *m, FILE *out)
{
    const char *role = m->role == DOC_CMS_MANAGER ? "manager"
                     : m->role == DOC_CMS_SERVER ? "server" : "none";
    const char *access = "none";

    if (m->reported && m->role == DOC_CMS_SERVER) {
        access = m->write ? "rw" : "ro";
    }
    fprintf(out, ",\"cms\":{\"reported\":%s,\"role\":\"%s\",\"access\":\"%s\","
            "\"pending\":%s}",
            m->reported ? "true" : "false", role, access,
            m->pending ? "true" : "false");
}


void
doctor_emit_json(const doctor_ep *eps, int n, FILE *out)
{
    int i;

    fprintf(out, "{\"remote_doctor\":{\"endpoints\":[");
    for (i = 0; i < n; i++) {
        const doctor_ep *e = &eps[i];

        ep_emit_facts(e, i == 0, out);
        ep_emit_issues(e, out);
        ep_emit_diagnosis(e, out);
        doctor_emit_config_json(e, out);   /* phase-93 "config" object (or null) */
        doctor_emit_latency_json(e, out);  /* phase-93 "latency" object (or nothing) */
        doctor_emit_recon_json(e, out);    /* phase-93 "recon" object (or nothing) */
        ep_emit_cms(&e->cms, out);
        doctor_eos_emit_json(e, out);      /* EOS MGM banner / enumerated FST */
        fprintf(out, "}");
    }
    fprintf(out, "],\"cross_endpoint_analysis\":{\"hops\":%d}}}\n", n > 1 ? n - 1 : 0);
}
