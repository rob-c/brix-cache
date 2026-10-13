/* Explicit fixture gates for Phase-118 clauses not observable on one target. */
#include "xrd_conform_internal.h"

typedef struct {
    const char *id;
    const char *reason;
} conform_fixture_gate;

/* WHAT: Replace untouched selected rows with an actionable fixture contract.
 * WHY: `probe-not-executed` cannot distinguish planned topology evidence from
 *      an accidentally omitted probe and is therefore not an operator answer.
 * HOW: Preserve scope skips and every real observation; replace only the
 *      provisional reason installed by results_init(). */
void
xrd_conform_finalize_fixture_gates(xrd_conform_execution *execution)
{
    const conform_fixture_gate gates[] = {
        { "OPN-012", "fixture-required:anonymous-and-scoped-token-readonly" },
        { "OPN-020", "fixture-required:staged-out-nowait" },
        { "OPN-021", "fixture-required:independent-session-metadata-change" },
        { "OPN-033", "fixture-required:asserted-short-idle-endpoint" },
        { "MV-005", "fixture-required:two-export-rename" },
        { "RM-008", "fixture-required:concurrent-recursive-delete" },
        { "CAC-003", "fixture-required:partial-cache-block" },
        { "CAC-004", "fixture-required:serve-while-filling" },
        { "CAC-005", "fixture-required:over-capacity-cache" },
        { "CAC-009", "fixture-required:corrupted-cache-block" },
        { "CMS-001", "fixture-required:manager-and-holder-set" },
        { "CMS-002", "fixture-required:manager-empty-holder-set" },
        { "CMS-003", "fixture-required:manager-with-one-holder-down" },
        { "CMS-004", "fixture-required:manager-with-all-holders-down" },
        { "CMS-005", "fixture-required:redundant-manager-pair" },
        { "CMS-006", "fixture-required:manager-only-data-refusal" },
        { "CMS-007", "fixture-required:manager-map-and-locate" },
        { "TPC-001", "fixture-required:native-tpc-pair" },
        { "TPC-008", "fixture-required:tpc-claim-and-transfer" },
        { "XPR-003", "fixture-required:cross-plane-checksum" },
        { "XPR-004", "fixture-required:cross-plane-directory" },
        { "XPR-005", "fixture-required:cross-plane-denied-identity" },
        { "XPR-008", "fixture-required:cross-plane-traversal" },
        { "XPR-009", "fixture-required:cross-plane-mutation" },
        { "XPR-010", "fixture-required:cross-plane-case-pair" },
        { "XPR-011", "fixture-required:cross-plane-filename-encoding" },
        { "ADV-003", "fixture-required:server-rss-observer" },
        { "ADV-004", "fixture-required:server-fd-observer" },
    };
    size_t index;

    for (index = 0; index < sizeof(gates) / sizeof(gates[0]); index++) {
        brix_conform_result *row = xrd_conform_result_find(execution,
            gates[index].id);

        if (row != NULL && row->verdict == BRIX_CONFORM_VERDICT_INCONCLUSIVE
            && strcmp(row->reason, "probe-not-executed") == 0)
        {
            xrd_conform_result_set(execution, gates[index].id,
                BRIX_CONFORM_VERDICT_INCONCLUSIVE, gates[index].reason,
                NULL, NULL);
        }
    }
}
