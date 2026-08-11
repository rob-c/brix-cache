/*
 * opdsl.c — declarative operation pipeline executor (§7.16). See opdsl.h.
 *
 * The pipeline is a small growable array of steps plus one optional failure
 * handler. Execution is a linear scan that stops at the first non-zero step and
 * runs the handler — the plain-C shape of the upstream Then/Else operation DSL.
 */
#include "ops/opdsl.h"

#include <stdlib.h>
#include <string.h>

#define BRIX_OPD_MAX 256          /* a pipeline is a handful of steps, not a loop */

typedef struct {
    const char       *label;
    brix_opd_step_fn  fn;
    void             *arg;
} brix_opd_entry_t;

struct brix_opd {
    brix_opd_entry_t *steps;
    size_t            n;
    size_t            cap;
    brix_opd_step_fn  otherwise_fn;
    void             *otherwise_arg;
};

brix_opd_t *
brix_opd_new(void)
{
    return calloc(1, sizeof(struct brix_opd));
}

brix_opd_t *
brix_opd_step(brix_opd_t *p, const char *label, brix_opd_step_fn fn, void *arg)
{
    if (p == NULL || fn == NULL || p->n >= BRIX_OPD_MAX) {
        return NULL;
    }
    if (p->n == p->cap) {
        size_t            ncap = p->cap ? p->cap * 2 : 8;
        brix_opd_entry_t *ns   = realloc(p->steps, ncap * sizeof(*ns));

        if (ns == NULL) {
            return NULL;
        }
        p->steps = ns;
        p->cap   = ncap;
    }
    p->steps[p->n].label = label;
    p->steps[p->n].fn    = fn;
    p->steps[p->n].arg   = arg;
    p->n++;
    return p;
}

void
brix_opd_otherwise(brix_opd_t *p, brix_opd_step_fn fn, void *arg)
{
    if (p != NULL) {
        p->otherwise_fn  = fn;
        p->otherwise_arg = arg;
    }
}

int
brix_opd_run(brix_opd_t *p, brix_conn *c, brix_status *st, size_t *ran)
{
    size_t i;

    if (p == NULL) {
        return -1;
    }
    for (i = 0; i < p->n; i++) {
        if (p->steps[i].fn(c, p->steps[i].arg, st) != 0) {
            if (ran != NULL) {
                *ran = i;               /* the index that failed */
            }
            if (p->otherwise_fn != NULL) {
                (void) p->otherwise_fn(c, p->otherwise_arg, st);
            }
            return -1;
        }
    }
    if (ran != NULL) {
        *ran = p->n;                    /* all ran */
    }
    return 0;
}

size_t
brix_opd_len(const brix_opd_t *p)
{
    return p != NULL ? p->n : 0;
}

void
brix_opd_free(brix_opd_t *p)
{
    if (p != NULL) {
        free(p->steps);
        free(p);
    }
}
