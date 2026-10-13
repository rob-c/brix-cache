/*
 * Phase-118 conformance clause and verdict model.
 *
 * WHAT: Defines immutable clause metadata and mutable per-run results.
 * WHY: The runner, renderers and tests must share one enumerable vocabulary.
 * HOW: Generated clause rows populate brix_conform_clause values; probes emit
 *      brix_conform_result values without changing the catalogue.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define BRIX_CONFORM_REASON_MAX 160
#define BRIX_CONFORM_EVIDENCE_MAX 320

typedef enum {
    BRIX_CONFORM_REF_NONE = 0,
    BRIX_CONFORM_REF_SPEC,
    BRIX_CONFORM_REF_XROOTD,
    BRIX_CONFORM_REF_CLIENT,
    BRIX_CONFORM_REF_CONS
} brix_conform_reference;

typedef enum {
    BRIX_CONFORM_ORACLE_NONE = 0,
    BRIX_CONFORM_ORACLE_O1 = 1U << 0,
    BRIX_CONFORM_ORACLE_O2 = 1U << 1,
    BRIX_CONFORM_ORACLE_O3 = 1U << 2,
    BRIX_CONFORM_ORACLE_O4 = 1U << 3
} brix_conform_oracle;

typedef enum {
    BRIX_CONFORM_PROBE_READ = 0,
    BRIX_CONFORM_PROBE_MUTATE,
    BRIX_CONFORM_PROBE_DISRUPT
} brix_conform_probe_class;

typedef enum {
    BRIX_CONFORM_VERDICT_CONFORMANT = 0,
    BRIX_CONFORM_VERDICT_DIVERGENT,
    BRIX_CONFORM_VERDICT_SKIPPED,
    BRIX_CONFORM_VERDICT_INCONCLUSIVE
} brix_conform_verdict;

typedef struct {
    const char                  *id;
    const char                  *family;
    brix_conform_reference       reference;
    unsigned                     oracles;
    brix_conform_probe_class     probe_class;
    const char                  *negative_fixture;
    const char                  *text;
    const char                  *source;
} brix_conform_clause;

typedef struct {
    const brix_conform_clause *clause;
    brix_conform_verdict       verdict;
    brix_conform_verdict       ecosystem_verdict;
    brix_conform_verdict       strict_verdict;
    char                       reason[BRIX_CONFORM_REASON_MAX];
    char                       strict_reason[BRIX_CONFORM_REASON_MAX];
    char                       expected[BRIX_CONFORM_EVIDENCE_MAX];
    char                       received[BRIX_CONFORM_EVIDENCE_MAX];
    char                       baseline_verdict[24];
    int                        changed;
} brix_conform_result;

const brix_conform_clause *brix_conform_clauses(size_t *count);
const brix_conform_clause *brix_conform_clause_find(const char *id);
const char *brix_conform_verdict_name(brix_conform_verdict verdict);
const char *brix_conform_reference_name(brix_conform_reference reference);
const char *brix_conform_probe_class_name(brix_conform_probe_class probe_class);
