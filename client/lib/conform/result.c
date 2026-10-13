/*
 * Phase-118 aggregate verdict accounting and process exit policy.
 *
 * WHAT: Counts result states and maps them onto the frozen CLI exit contract.
 * WHY: Renderers must not disagree with process success/failure semantics.
 * HOW: Recount the result vector, then apply divergence before inconclusive.
 */
#include "conform/run.h"

#include <stdio.h>

/* ---- Project observations through strict/ecosystem policy ---- */
void
brix_conform_apply_reference_mode(const brix_conform_run_config *config,
    brix_conform_run_results *results)
{
    size_t index;

    if (config == NULL || results == NULL) return;
    for (index = 0; index < results->count; index++) {
        brix_conform_result *result = &results->results[index];
        int de_facto = result->clause->reference == BRIX_CONFORM_REF_XROOTD
            || result->clause->reference == BRIX_CONFORM_REF_CLIENT;

        result->ecosystem_verdict = result->verdict;
        result->strict_verdict = result->verdict;
        result->strict_reason[0] = '\0';
        if (de_facto && result->verdict == BRIX_CONFORM_VERDICT_CONFORMANT) {
            result->strict_verdict = BRIX_CONFORM_VERDICT_DIVERGENT;
            snprintf(result->strict_reason, sizeof(result->strict_reason),
                "de-facto-answer-differs-from-nominal-spec");
        } else if (de_facto
            && result->verdict == BRIX_CONFORM_VERDICT_DIVERGENT) {
            result->strict_verdict = BRIX_CONFORM_VERDICT_INCONCLUSIVE;
            snprintf(result->strict_reason, sizeof(result->strict_reason),
                "de-facto-answer-failed-strict-answer-not-observed");
        }
        if (config->reference_mode == BRIX_CONFORM_REFERENCE_STRICT) {
            result->verdict = result->strict_verdict;
            if (result->strict_reason[0] != '\0')
                snprintf(result->reason, sizeof(result->reason), "%s",
                    result->strict_reason);
        } else if (config->reference_mode == BRIX_CONFORM_REFERENCE_BOTH
            && (result->strict_verdict == BRIX_CONFORM_VERDICT_DIVERGENT
                || (result->strict_verdict == BRIX_CONFORM_VERDICT_INCONCLUSIVE
                    && result->verdict == BRIX_CONFORM_VERDICT_CONFORMANT))) {
            result->verdict = result->strict_verdict;
        }
    }
}

/* ---- Recount every result verdict ----
 *
 * WHAT: Resets and fills aggregate counters from the result vector.
 * WHY: One derived source prevents counter drift after filtering/baseline work.
 * HOW: Walk once and increment the matching typed counter.
 */
void
brix_conform_run_results_count(brix_conform_run_results *results)
{
    size_t index;

    if (results == NULL) return;
    results->conformant = 0;
    results->divergent = 0;
    results->skipped = 0;
    results->inconclusive = 0;
    results->changed = 0;
    for (index = 0; index < results->count; index++) {
        if (results->results[index].changed) results->changed++;
        switch (results->results[index].verdict) {
        case BRIX_CONFORM_VERDICT_CONFORMANT: results->conformant++; break;
        case BRIX_CONFORM_VERDICT_DIVERGENT: results->divergent++; break;
        case BRIX_CONFORM_VERDICT_SKIPPED: results->skipped++; break;
        case BRIX_CONFORM_VERDICT_INCONCLUSIVE: results->inconclusive++; break;
        }
    }
}

/* ---- Map aggregate outcomes onto Phase-118 exit codes ----
 *
 * WHAT: Returns 0, 1 or 2 according to the configured failure policy.
 * WHY: Automation needs stable semantics independent of output rendering.
 * HOW: Divergence wins; then configured inconclusive failure; else success.
 */
int
brix_conform_run_exit_code(const brix_conform_run_config *config,
    const brix_conform_run_results *results)
{
    if (config == NULL || results == NULL) return 3;
    if (results->divergent > 0) return 1;
    if (results->inconclusive > 0
        && (config->fail_mode == BRIX_CONFORM_FAIL_INCONCLUSIVE
            || config->fail_mode == BRIX_CONFORM_FAIL_ANY)) return 2;
    return 0;
}
