/*
 * Phase-118 machine-readable JSON primitives and report bodies.
 *
 * WHAT: Emits canonical JSON, SARIF and ECS representations to open streams.
 * WHY: All machine formats must derive from the same typed result vector.
 * HOW: Escape untrusted strings byte-wise, then stream deterministic objects.
 */
#include "conform/report_internal.h"

#include <ctype.h>

/* ---- Emit one JSON string safely ----
 *
 * WHAT: Writes a quoted JSON string, escaping controls and metacharacters.
 * WHY: Targets, server evidence and clause text are untrusted report content.
 * HOW: Escape quote/slash controls and encode other controls as \u00XX.
 */
void
brix_conform_json_string(FILE *out, const char *value)
{
    const unsigned char *cursor = (const unsigned char *) (value == NULL ? "" : value);

    fputc('"', out);
    while (*cursor != '\0') {
        if (*cursor == '"' || *cursor == '\\') {
            fputc('\\', out);
            fputc(*cursor, out);
        } else if (*cursor == '\n') {
            fputs("\\n", out);
        } else if (*cursor == '\r') {
            fputs("\\r", out);
        } else if (*cursor == '\t') {
            fputs("\\t", out);
        } else if (iscntrl(*cursor)) {
            fprintf(out, "\\u%04x", (unsigned) *cursor);
        } else {
            fputc(*cursor, out);
        }
        cursor++;
    }
    fputc('"', out);
}

/* ---- Emit one result object shared by JSON consumers ----
 *
 * WHAT: Writes stable clause metadata, verdict and evidence as a JSON object.
 * WHY: The canonical and ECS formats must agree at field granularity.
 * HOW: Emit fixed keys in fixed order using the shared string escaper.
 */
static void
json_result(FILE *out, const brix_conform_result *result)
{
    fputs("{\"id\":", out); brix_conform_json_string(out, result->clause->id);
    fputs(",\"family\":", out); brix_conform_json_string(out, result->clause->family);
    fputs(",\"verdict\":", out); brix_conform_json_string(out,
        brix_conform_verdict_name(result->verdict));
    fputs(",\"ecosystem_verdict\":", out); brix_conform_json_string(out,
        brix_conform_verdict_name(result->ecosystem_verdict));
    fputs(",\"strict_verdict\":", out); brix_conform_json_string(out,
        brix_conform_verdict_name(result->strict_verdict));
    fputs(",\"strict_reason\":", out);
    brix_conform_json_string(out, result->strict_reason);
    fputs(",\"reason\":", out); brix_conform_json_string(out, result->reason);
    fputs(",\"reference\":", out); brix_conform_json_string(out,
        brix_conform_reference_name(result->clause->reference));
    fputs(",\"source\":", out); brix_conform_json_string(out, result->clause->source);
    fputs(",\"negative_fixture\":", out);
    brix_conform_json_string(out, result->clause->negative_fixture);
    fputs(",\"assertion\":", out); brix_conform_json_string(out, result->clause->text);
    fputs(",\"expected\":", out); brix_conform_json_string(out, result->expected);
    fputs(",\"received\":", out); brix_conform_json_string(out, result->received);
    fputs(",\"changed\":", out); fputs(result->changed ? "true" : "false", out);
    fputs(",\"baseline_verdict\":", out);
    brix_conform_json_string(out, result->baseline_verdict);
    fputc('}', out);
}

/* ---- Emit the baseline changed-only result set ----
 *
 * WHAT: Writes a deterministic JSON artifact containing only changed clauses.
 * WHY: Automation using --baseline asked for transitions, not full-ledger noise.
 * HOW: Reuse canonical result objects and filter on the comparison bit.
 */
void
brix_conform_report_diff_json(FILE *out,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results)
{
    size_t index;
    int first = 1;

    fputs("{\"schema\":\"brix.conform.diff.v1\",\"target\":", out);
    brix_conform_json_string(out, meta->target);
    fprintf(out, ",\"baseline_applied\":%s,\"changed\":%zu,\"results\":[",
        results->baseline_applied ? "true" : "false", results->changed);
    for (index = 0; index < results->count; index++) {
        if (!results->results[index].changed) continue;
        if (!first) fputc(',', out);
        first = 0;
        json_result(out, &results->results[index]);
    }
    fputs("]}\n", out);
}

/* ---- Emit the canonical complete JSON report ----
 *
 * WHAT: Writes metadata, aggregate counts and every clause result.
 * WHY: Baselines and automation require a lossless primary representation.
 * HOW: Stream a deterministic object and comma-delimited result array.
 */
void
brix_conform_report_json(FILE *out, const brix_conform_report_meta *meta,
    const brix_conform_run_results *results)
{
    size_t index;

    fputs("{\"schema\":\"brix.conform.v1\",\"target\":", out);
    brix_conform_json_string(out, meta->target);
    fputs(",\"targets\":[", out);
    brix_conform_json_string(out, meta->target);
    for (index = 0; index < meta->also_target_count; index++) {
        fputc(',', out);
        brix_conform_json_string(out, meta->also_targets[index]);
    }
    fputc(']', out);
    fputs(",\"profile\":", out); brix_conform_json_string(out, meta->profile);
    fputs(",\"shape\":", out); brix_conform_json_string(out, meta->shape);
    fputs(",\"budget\":", out); brix_conform_json_string(out, meta->budget);
    fputs(",\"reference\":", out); brix_conform_json_string(out, meta->reference);
    fputs(",\"run_key\":", out); brix_conform_json_string(out, meta->run_key);
    fputs(",\"timestamp\":", out); brix_conform_json_string(out, meta->timestamp);
    fputs(",\"tool_version\":", out);
    brix_conform_json_string(out, meta->tool_version);
    fputs(",\"negative_verification\":{\"requested\":[", out);
    for (index = 0; index < meta->negative_verify_count; index++) {
        if (index > 0) fputc(',', out);
        brix_conform_json_string(out, meta->negative_verify[index]);
    }
    fprintf(out, "],\"passed\":%s}",
        meta->negative_verify_passed ? "true" : "false");
    fprintf(out, ",\"usage\":{\"requests\":%u,\"bytes\":%llu},"
        "\"ceilings\":{\"requests\":%u,\"bytes\":%llu,\"wall_seconds\":%u}",
        meta->requests, meta->bytes, meta->request_limit, meta->byte_limit,
        meta->wall_seconds);
    fprintf(out, ",\"summary\":{\"conformant\":%zu,\"divergent\":%zu,"
        "\"skipped\":%zu,\"inconclusive\":%zu},\"results\":[",
        results->conformant, results->divergent, results->skipped,
        results->inconclusive);
    for (index = 0; index < results->count; index++) {
        if (index > 0) fputc(',', out);
        json_result(out, &results->results[index]);
    }
    fputs("]}\n", out);
}

/* ---- Emit SARIF findings for divergent and inconclusive clauses ----
 *
 * WHAT: Writes SARIF 2.1.0 results with stable rule ids and fingerprints.
 * WHY: CI code-scanning views need actionable non-green rows, not pass noise.
 * HOW: Filter result vector and render one result per actionable clause.
 */
void
brix_conform_report_sarif(FILE *out, const brix_conform_report_meta *meta,
    const brix_conform_run_results *results)
{
    size_t index;
    int first = 1;

    (void) meta;
    fputs("{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\","
        "\"runs\":[{\"tool\":{\"driver\":{\"name\":\"xrd conform\"}},\"results\":[", out);
    for (index = 0; index < results->count; index++) {
        const brix_conform_result *result = &results->results[index];

        if (result->verdict != BRIX_CONFORM_VERDICT_DIVERGENT
            && result->verdict != BRIX_CONFORM_VERDICT_INCONCLUSIVE) continue;
        if (!first) fputc(',', out);
        first = 0;
        fputs("{\"ruleId\":\"brix.conform.", out);
        fputs(result->clause->id, out);
        fputs("\",\"level\":\"", out);
        fputs(result->verdict == BRIX_CONFORM_VERDICT_DIVERGENT ? "error" : "warning", out);
        fputs("\",\"message\":{\"text\":", out);
        brix_conform_json_string(out, result->reason[0] ? result->reason : result->clause->text);
        fputs("},\"partialFingerprints\":{\"clause\":", out);
        brix_conform_json_string(out, result->clause->id);
        fputs("}}", out);
    }
    fputs("]}]}\n", out);
}

/* ---- Emit newline-delimited ECS-compatible events ----
 *
 * WHAT: Writes one event object per clause result.
 * WHY: Watch and batch results share ingestion with BriX operational logs.
 * HOW: Add ECS event fields, then embed the canonical result object.
 */
void
brix_conform_report_ecs(FILE *out, const brix_conform_report_meta *meta,
    const brix_conform_run_results *results)
{
    size_t index;

    for (index = 0; index < results->count; index++) {
        const brix_conform_result *result = &results->results[index];

        fputs("{\"@timestamp\":", out); brix_conform_json_string(out, meta->timestamp);
        fputs(",\"event.kind\":\"event\",\"event.category\":[\"configuration\"],"
            "\"event.type\":[\"info\"],\"event.outcome\":", out);
        brix_conform_json_string(out,
            result->verdict == BRIX_CONFORM_VERDICT_CONFORMANT ? "success" : "failure");
        fputs(",\"url.original\":", out); brix_conform_json_string(out, meta->target);
        fputs(",\"brix.conform\":", out); json_result(out, result);
        fputs("}\n", out);
    }
}
