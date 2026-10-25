/*
 * Phase-118 Markdown site report renderer.
 *
 * WHAT: Renders run metadata and every clause as an attachable Markdown table.
 * WHY: Deployment reviews need a durable human-readable artifact.
 * HOW: Escape table separators/newlines and stream rows in registry order.
 */
#include "conform/report_internal.h"
#include "conform/report_fields.h"

#include <string.h>

/* ---- Emit Markdown table text safely ----
 *
 * WHAT: Escapes pipes and folds CR/LF to spaces.
 * WHY: Clause/evidence text must not change the report's table structure.
 * HOW: Walk bytes and prefix pipes with a backslash.
 */
static void
markdown_text(FILE *out, const char *value)
{
    const char *cursor = value == NULL ? "" : value;

    while (*cursor != '\0') {
        if (strchr("\\`*_{}[]<>#+-.!|", *cursor) != NULL) fputc('\\', out);
        if (*cursor == '\r' || *cursor == '\n') fputc(' ', out);
        else fputc(*cursor, out);
        cursor++;
    }
}

/* ---- Render the complete Markdown report ----
 *
 * WHAT: Writes header metadata, summary counts and one row per clause.
 * WHY: Every skip and oracle decision must survive outside terminal output.
 * HOW: Print fixed headings then escape each user/server-derived cell.
 */
void
brix_conform_report_markdown(FILE *out,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results)
{
    size_t index;

    fputs("# BriX protocol-conformance report\n\n- Target: ", out);
    markdown_text(out, meta->target);
    for (index = 0; index < meta->also_target_count; index++) {
        fputs("\n- Also: ", out);
        markdown_text(out, meta->also_targets[index]);
    }
    {
        const brix_conform_report_field fields[] = {
            { "\n- Profile: ", meta->profile },
            { "\n- Shape: ", meta->shape },
            { "\n- Budget: ", meta->budget },
            { "\n- Reference: ", meta->reference },
            { "\n- Run key: ", meta->run_key },
            { "\n- Timestamp: ", meta->timestamp },
            { "\n- Tool version: ", meta->tool_version },
        };

        brix_conform_report_fields(out, fields,
            sizeof(fields) / sizeof(fields[0]), markdown_text);
    }
    for (index = 0; index < meta->negative_verify_count; index++) {
        fputs("\n- Negative verification: ", out);
        markdown_text(out, meta->negative_verify[index]);
        fputs(meta->negative_verify_passed ? " (passed)" : " (failed)", out);
    }
    fprintf(out, "\n- Usage: %u/%u requests; %llu/%llu bytes; %us wall ceiling\n\n",
        meta->requests, meta->request_limit, meta->bytes, meta->byte_limit,
        meta->wall_seconds);
    fprintf(out, "Summary: **%zu conformant**, **%zu divergent**, **%zu skipped**, "
        "**%zu inconclusive**.\n\n"
        "| ID | Family | Verdict | Ecosystem | Strict | Reference | Assertion | Negative fixture | Reason/evidence |\n"
        "|---|---|---|---|---|---|---|---|---|\n",
        results->conformant, results->divergent, results->skipped,
        results->inconclusive);
    for (index = 0; index < results->count; index++) {
        const brix_conform_result *result = &results->results[index];

        fprintf(out, "| %s | %s | %s | %s | %s | %s | ", result->clause->id,
            result->clause->family, brix_conform_verdict_name(result->verdict),
            brix_conform_verdict_name(result->ecosystem_verdict),
            brix_conform_verdict_name(result->strict_verdict),
            brix_conform_reference_name(result->clause->reference));
        markdown_text(out, result->clause->text);
        fputs(" | ", out);
        markdown_text(out, result->clause->negative_fixture);
        fputs(" | ", out);
        markdown_text(out, result->reason);
        if (result->strict_reason[0] != '\0') {
            fputs(" strict=", out);
            markdown_text(out, result->strict_reason);
        }
        if (result->expected[0] != '\0') {
            fputs(" expected=", out);
            markdown_text(out, result->expected);
        }
        if (result->received[0] != '\0') {
            fputs(" received=", out);
            markdown_text(out, result->received);
        }
        fputs(" |\n", out);
    }
}
