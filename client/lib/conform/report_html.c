/* Phase-118 standalone HTML report renderer. */
#include "conform/report_internal.h"

/* WHAT: Escape untrusted text for an HTML text node. WHY: Targets and remote
 * evidence must never become active report markup. HOW: Encode five metachars. */
static void
html_text(FILE *out, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)
        (value == NULL ? "" : value);

    while (*cursor != '\0') {
        if (*cursor == '&') fputs("&amp;", out);
        else if (*cursor == '<') fputs("&lt;", out);
        else if (*cursor == '>') fputs("&gt;", out);
        else if (*cursor == '"') fputs("&quot;", out);
        else if (*cursor == '\'') fputs("&#39;", out);
        else fputc(*cursor, out);
        cursor++;
    }
}

/* WHAT: Render the complete self-contained site report. WHY: Phase 118 promises
 * an attachable HTML artifact alongside Markdown. HOW: Use only static markup,
 * escaped text nodes and the same typed result vector as every other format. */
void
brix_conform_report_html(FILE *out, const brix_conform_report_meta *meta,
    const brix_conform_run_results *results)
{
    size_t index;

    fputs("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>BriX protocol-conformance report</title><style>"
        "body{font:14px system-ui,sans-serif;margin:2rem;color:#18202a}"
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd4dc;"
        "padding:.35rem;text-align:left;vertical-align:top}th{background:#eef2f5}"
        ".divergent{background:#ffe8e8}.inconclusive{background:#fff6d8}"
        "code{white-space:pre-wrap}</style></head><body>"
        "<h1>BriX protocol-conformance report</h1><dl><dt>Target</dt><dd>", out);
    html_text(out, meta->target);
    fputs("</dd><dt>Profile</dt><dd>", out); html_text(out, meta->profile);
    fputs("</dd><dt>Shape</dt><dd>", out); html_text(out, meta->shape);
    fputs("</dd><dt>Budget</dt><dd>", out); html_text(out, meta->budget);
    fputs("</dd><dt>Reference</dt><dd>", out); html_text(out, meta->reference);
    fputs("</dd><dt>Run key</dt><dd><code>", out); html_text(out, meta->run_key);
    fputs("</code></dd><dt>Timestamp</dt><dd>", out); html_text(out, meta->timestamp);
    fputs("</dd><dt>Tool version</dt><dd>", out); html_text(out, meta->tool_version);
    for (index = 0; index < meta->negative_verify_count; index++) {
        fputs("</dd><dt>Negative verification</dt><dd>", out);
        html_text(out, meta->negative_verify[index]);
        fputs(meta->negative_verify_passed ? " (passed)" : " (failed)", out);
    }
    fputs("</dd><dt>Usage</dt><dd>", out);
    fprintf(out, "%u/%u requests; %llu/%llu bytes; %us wall ceiling",
        meta->requests, meta->request_limit, meta->bytes, meta->byte_limit,
        meta->wall_seconds);
    fputs("</dd></dl><p>", out);
    fprintf(out, "%zu conformant · %zu divergent · %zu skipped · %zu inconclusive",
        results->conformant, results->divergent, results->skipped,
        results->inconclusive);
    fputs("</p><table><thead><tr><th>ID</th><th>Family</th><th>Verdict</th>"
        "<th>Ecosystem</th><th>Strict</th><th>Reference</th><th>Assertion</th>"
        "<th>Negative fixture</th><th>Evidence</th></tr></thead><tbody>", out);
    for (index = 0; index < results->count; index++) {
        const brix_conform_result *result = &results->results[index];
        const char *verdict = brix_conform_verdict_name(result->verdict);

        fputs("<tr class=\"", out); html_text(out, verdict); fputs("\"><td>", out);
        html_text(out, result->clause->id); fputs("</td><td>", out);
        html_text(out, result->clause->family); fputs("</td><td>", out);
        html_text(out, verdict); fputs("</td><td>", out);
        html_text(out, brix_conform_verdict_name(result->ecosystem_verdict));
        fputs("</td><td>", out);
        html_text(out, brix_conform_verdict_name(result->strict_verdict));
        fputs("</td><td>", out);
        html_text(out, brix_conform_reference_name(result->clause->reference));
        fputs("</td><td>", out); html_text(out, result->clause->text);
        fputs("</td><td>", out); html_text(out,
            result->clause->negative_fixture);
        fputs("</td><td>", out); html_text(out, result->reason);
        if (result->strict_reason[0] != '\0') {
            fputs("; ", out); html_text(out, result->strict_reason);
        }
        fputs("</td></tr>", out);
    }
    fputs("</tbody></table></body></html>\n", out);
}
