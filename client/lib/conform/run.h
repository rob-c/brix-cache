/*
 * Phase-118 conformance-run configuration and aggregate result contract.
 *
 * Requires: conform/model.h and conform/conform.h before use.
 */
#pragma once

#include "conform/conform.h"
#include "conform/model.h"

#include <stddef.h>

typedef enum {
    BRIX_CONFORM_RUN_ACCEPT = 0,
    BRIX_CONFORM_RUN_FULL,
    BRIX_CONFORM_RUN_WATCH
} brix_conform_run_shape;

typedef enum {
    BRIX_CONFORM_REFERENCE_ECOSYSTEM = 0,
    BRIX_CONFORM_REFERENCE_STRICT,
    BRIX_CONFORM_REFERENCE_BOTH
} brix_conform_reference_mode;

typedef enum {
    BRIX_CONFORM_FAIL_DIVERGENT = 0,
    BRIX_CONFORM_FAIL_INCONCLUSIVE,
    BRIX_CONFORM_FAIL_ANY
} brix_conform_fail_mode;

typedef struct {
    brix_conform_run_shape       shape;
    brix_conform_budget          budget;
    brix_conform_reference_mode  reference_mode;
    brix_conform_fail_mode       fail_mode;
    const char                  *target;
    const char                  *profile;
    const char                  *scratch;
    const char                  *families;
    const char                  *exclude;
    const char                  *only;
    const char                  *out_dir;
    const char                  *baseline;
    const char                  *run_key;
    int                          allow_mutate;
    int                          allow_disrupt;
    const char                  *confirm_target;
    unsigned                     wall_seconds;
    unsigned                     request_limit;
    unsigned long long           byte_limit;
    unsigned                     watch_interval_seconds;
    unsigned                     watch_cycles;
} brix_conform_run_config;

typedef struct {
    brix_conform_result *results;
    size_t               count;
    size_t               conformant;
    size_t               divergent;
    size_t               skipped;
    size_t               inconclusive;
    size_t               changed;
    int                  baseline_applied;
} brix_conform_run_results;

int brix_conform_clause_selected(const brix_conform_clause *clause,
    const brix_conform_run_config *config, char *reason, size_t reason_size);
int brix_conform_scratch_path(const char *prefix, const char *leaf,
    char *out, size_t out_size);
int brix_conform_scratch_control_path(const char *prefix, const char *leaf,
    unsigned char control, char *out, size_t out_size);
void brix_conform_run_results_count(brix_conform_run_results *results);
void brix_conform_apply_reference_mode(const brix_conform_run_config *config,
    brix_conform_run_results *results);
int brix_conform_run_exit_code(const brix_conform_run_config *config,
    const brix_conform_run_results *results);
int brix_conform_apply_baseline(const char *path,
    brix_conform_run_results *results, char *error, size_t error_size);
