/*
 * Phase-118 generated conformance-clause registry.
 *
 * WHAT: Exposes all 527 stable clause rows and exact-id lookup.
 * WHY: Reports and filters must enumerate the normative ledger without drift.
 * HOW: A checked-in generated include expands once into immutable row data;
 *      lookup uses a bounded linear scan because 527 startup-only rows are tiny.
 */
#include "conform/model.h"

#include <string.h>

#define BRIX_CONFORM_CLAUSE(cid, fam, ref, oracle, probe, negative, assertion, src) \
    { cid, fam, ref, oracle, probe, negative, assertion, src },
static const brix_conform_clause CLAUSES[] = {
#include "conform/ledger_rows.inc"
};
#undef BRIX_CONFORM_CLAUSE

/* ---- Return the immutable complete clause catalogue ----
 *
 * WHAT: Returns the registry and writes its element count when count is non-NULL.
 * WHY: Every consumer must enumerate the same complete stable row set.
 * HOW: Publish the static array and derive the count from its actual extent.
 */
const brix_conform_clause *
brix_conform_clauses(size_t *count)
{
    if (count != NULL) *count = sizeof(CLAUSES) / sizeof(CLAUSES[0]);
    return CLAUSES;
}

/* ---- Find a clause by its stable identifier ----
 *
 * WHAT: Returns the matching clause or NULL for an absent/NULL identifier.
 * WHY: --only, baselines and replay artifacts address clauses by stable id.
 * HOW: Reject NULL, then compare each bounded registry entry exactly.
 */
const brix_conform_clause *
brix_conform_clause_find(const char *id)
{
    size_t count;
    size_t index;

    if (id == NULL) return NULL;
    brix_conform_clauses(&count);
    for (index = 0; index < count; index++) {
        if (strcmp(CLAUSES[index].id, id) == 0) return &CLAUSES[index];
    }
    return NULL;
}
