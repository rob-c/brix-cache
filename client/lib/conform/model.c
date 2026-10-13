/*
 * Phase-118 conformance-model vocabulary renderers.
 *
 * WHAT: Maps typed result metadata to stable machine-readable names.
 * WHY: Terminal, JSON, SARIF and Markdown must never invent different labels.
 * HOW: Exhaustive switch statements return frozen lowercase spellings.
 */
#include "conform/model.h"

/* ---- Render a conformance verdict ----
 *
 * WHAT: Returns the stable lowercase verdict name; unknown values map to invalid.
 * WHY: Report consumers depend on one vocabulary across every rendering.
 * HOW: Map each enum member explicitly and fail closed for an invalid value.
 */
const char *
brix_conform_verdict_name(brix_conform_verdict verdict)
{
    switch (verdict) {
    case BRIX_CONFORM_VERDICT_CONFORMANT: return "conformant";
    case BRIX_CONFORM_VERDICT_DIVERGENT: return "divergent";
    case BRIX_CONFORM_VERDICT_SKIPPED: return "skipped";
    case BRIX_CONFORM_VERDICT_INCONCLUSIVE: return "inconclusive";
    }
    return "invalid";
}

/* ---- Render a clause reference authority ----
 *
 * WHAT: Returns the stable reference name; unknown values map to none.
 * WHY: A report must state which competing protocol authority it applied.
 * HOW: Map each enum member without allocating or consulting mutable state.
 */
const char *
brix_conform_reference_name(brix_conform_reference reference)
{
    switch (reference) {
    case BRIX_CONFORM_REF_SPEC: return "spec";
    case BRIX_CONFORM_REF_XROOTD: return "xrootd";
    case BRIX_CONFORM_REF_CLIENT: return "client";
    case BRIX_CONFORM_REF_CONS: return "cons";
    case BRIX_CONFORM_REF_NONE: return "none";
    }
    return "none";
}

/* ---- Render a safety probe class ----
 *
 * WHAT: Returns read, mutate or disrupt; unknown values map to invalid.
 * WHY: Safety decisions and skip ledgers need a stable public spelling.
 * HOW: Map every valid enum member explicitly.
 */
const char *
brix_conform_probe_class_name(brix_conform_probe_class probe_class)
{
    switch (probe_class) {
    case BRIX_CONFORM_PROBE_READ: return "read";
    case BRIX_CONFORM_PROBE_MUTATE: return "mutate";
    case BRIX_CONFORM_PROBE_DISRUPT: return "disrupt";
    }
    return "invalid";
}
