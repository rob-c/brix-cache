/*
 * opdsl.h — declarative operation pipeline for the BriX client (§7.16, the
 * XrdClOperations analog).
 *
 * WHAT: compose a sequence of client operations as data — each a step that runs
 *   against a brix_conn — and execute them as a pipeline that SHORT-CIRCUITS on
 *   the first failure into an optional "otherwise" handler (the Operation |
 *   Operation ... >> Handle / Then-Else model of XrdCl).
 * WHY:  callers currently hand-roll open→read→close ladders with ad-hoc error
 *   cleanup at every site. A declarative chain makes the success path linear and
 *   the failure path single-sourced, exactly as the upstream C++ DSL does, in
 *   plain C.
 * HOW:  brix_opd_new() builds an empty pipeline; brix_opd_step() appends a step
 *   (a function pointer + opaque arg); brix_opd_otherwise() sets the failure
 *   handler; brix_opd_run() executes steps in order until one returns non-zero,
 *   then runs the otherwise-handler (if any) and returns -1. All-success → 0.
 *   Pure control-flow: the steps themselves bind to the brix_file_open_read,
 *   brix_stat, brix_file_read (etc.) calls, so the engine has zero wire
 *   knowledge and is unit-testable with stubs.
 */
#ifndef BRIX_OPS_OPDSL_H
#define BRIX_OPS_OPDSL_H

#include "brix.h"

/* A single pipeline step: run `arg` against `c`, reporting through `st`.
 * Return 0 to continue the pipeline, non-zero to fail it. */
typedef int (*brix_opd_step_fn)(brix_conn *c, void *arg, brix_status *st);

/* Opaque pipeline handle. */
typedef struct brix_opd brix_opd_t;

/* Create an empty pipeline, or NULL on OOM. */
brix_opd_t *brix_opd_new(void);

/* Append a step (label is borrowed, for diagnostics). Returns the same pipeline
 * for chaining, or NULL if the pipeline/args are invalid (the pipeline is left
 * usable). */
brix_opd_t *brix_opd_step(brix_opd_t *p, const char *label,
                          brix_opd_step_fn fn, void *arg);

/* Set the failure handler run after the first failing step (the Else leg).
 * Optional; at most one. */
void brix_opd_otherwise(brix_opd_t *p, brix_opd_step_fn fn, void *arg);

/* Execute the pipeline against `c`. Runs steps in order; on the first step that
 * returns non-zero, runs the otherwise-handler (if set) and returns -1 with the
 * failing step's status in *st. All steps succeeding returns 0. The index of the
 * failing step (or the count on success) is stored through *ran when non-NULL. */
int brix_opd_run(brix_opd_t *p, brix_conn *c, brix_status *st, size_t *ran);

/* Number of steps appended so far. */
size_t brix_opd_len(const brix_opd_t *p);

/* Free the pipeline (does not touch the step args — the caller owns those). */
void brix_opd_free(brix_opd_t *p);

#endif /* BRIX_OPS_OPDSL_H */
