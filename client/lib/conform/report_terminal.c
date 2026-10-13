/*
 * Phase-118 human-readable terminal report.
 *
 * WHAT: Prints family summaries and detailed non-conformant evidence.
 * WHY: Operators need live, skip-honest output independent of artifacts.
 * HOW: Group contiguous generated rows by family, count verdicts, then detail.
 */
#include "conform/report.h"

#include <string.h>

/* ---- Print one family summary ----
 *
 * WHAT: Emits one stable line with all four verdict counts.
 * WHY: Skips and inconclusive rows must be visible beside passes.
 * HOW: Format the supplied aggregate counts without terminal-only decoration.
 */
static void
terminal_family(FILE *out, const char *family, size_t ok, size_t divergent,
    size_t skipped, size_t inconclusive)
{
    fprintf(out, "%-5s %zu conformant · %zu divergent · %zu skipped · %zu inconclusive\n",
        family, ok, divergent, skipped, inconclusive);
}

/* ---- Print detailed evidence for one actionable result ----
 *
 * WHAT: Emits id, verdict, reason, expectation, observation and authority.
 * WHY: A non-green row must be independently understandable and reproducible.
 * HOW: Print only populated optional fields after the stable leading line.
 */
static void
terminal_detail(FILE *out, const brix_conform_result *result)
{
    fprintf(out, "  %s  %s", result->clause->id,
        brix_conform_verdict_name(result->verdict));
    if (result->reason[0] != '\0') fprintf(out, "  %s", result->reason);
    fputc('\n', out);
    if (result->ecosystem_verdict != result->strict_verdict)
        fprintf(out, "        ecosystem: %s  strict: %s (%s)\n",
            brix_conform_verdict_name(result->ecosystem_verdict),
            brix_conform_verdict_name(result->strict_verdict),
            result->strict_reason);
    if (result->expected[0] != '\0')
        fprintf(out, "        expected: %s\n", result->expected);
    if (result->received[0] != '\0')
        fprintf(out, "        received: %s\n", result->received);
    fprintf(out, "        ref: %s  oracle-mask: 0x%x  source: %s\n",
        brix_conform_reference_name(result->clause->reference),
        result->clause->oracles, result->clause->source);
    fprintf(out, "        negative-fixture: %s\n",
        result->clause->negative_fixture);
}

/* ---- Print actionable result details ----
 *
 * WHAT: Emits red/unknown rows, filtered to changes when a baseline is active.
 * WHY: Baseline mode should show transitions without hiding aggregate truth.
 * HOW: Walk once, skip unchanged rows, delegate stable detail formatting.
 */
static void
terminal_details(FILE *out, const brix_conform_run_results *results)
{
    size_t index;

    for (index = 0; index < results->count; index++) {
        const brix_conform_result *result = &results->results[index];

        if (results->baseline_applied && !result->changed) continue;
        if (result->verdict == BRIX_CONFORM_VERDICT_DIVERGENT
            || result->verdict == BRIX_CONFORM_VERDICT_INCONCLUSIVE)
            terminal_detail(out, result);
    }
}

/* ---- Render the complete terminal report ----
 *
 * WHAT: Prints metadata, every family aggregate and all actionable rows.
 * WHY: The terminal contract is the operator's immediate certification view.
 * HOW: Exploit registry family ordering for one pass, then detail red/unknown.
 */
void
brix_conform_report_terminal(FILE *out, const brix_conform_report_meta *meta,
    const brix_conform_run_results *results)
{
    size_t index = 0;

    if (out == NULL || meta == NULL || results == NULL) return;
    fprintf(out, "xrd conform target=%s profile=%s shape=%s budget=%s reference=%s\n",
        meta->target, meta->profile, meta->shape, meta->budget, meta->reference);
    fprintf(out, "xrd conform version=%s usage=requests:%u/%u bytes:%llu/%llu wall:%us\n",
        meta->tool_version, meta->requests, meta->request_limit, meta->bytes,
        meta->byte_limit, meta->wall_seconds);
    for (index = 0; index < meta->also_target_count; index++)
        fprintf(out, "xrd conform also=%s\n", meta->also_targets[index]);
    for (index = 0; index < meta->negative_verify_count; index++)
        fprintf(out, "xrd conform verify-negative=%s result=%s\n",
            meta->negative_verify[index],
            meta->negative_verify_passed ? "passed" : "failed");
    index = 0;
    while (index < results->count) {
        const char *family = results->results[index].clause->family;
        size_t ok = 0, divergent = 0, skipped = 0, inconclusive = 0;

        while (index < results->count
            && strcmp(results->results[index].clause->family, family) == 0) {
            switch (results->results[index].verdict) {
            case BRIX_CONFORM_VERDICT_CONFORMANT: ok++; break;
            case BRIX_CONFORM_VERDICT_DIVERGENT: divergent++; break;
            case BRIX_CONFORM_VERDICT_SKIPPED: skipped++; break;
            case BRIX_CONFORM_VERDICT_INCONCLUSIVE: inconclusive++; break;
            }
            index++;
        }
        terminal_family(out, family, ok, divergent, skipped, inconclusive);
    }
    terminal_details(out, results);
    fprintf(out, "TOTAL %zu conformant · %zu divergent · %zu skipped · %zu inconclusive\n",
        results->conformant, results->divergent, results->skipped,
        results->inconclusive);
    if (results->baseline_applied)
        fprintf(out, "BASELINE %zu clause verdict(s) changed\n", results->changed);
}
