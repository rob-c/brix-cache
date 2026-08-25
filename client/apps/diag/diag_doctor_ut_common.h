/*
 * diag_doctor_ut_common.h — shared prologue for the standalone diag-doctor
 * unit tests (diag_doctor_audit_unittest.c, diag_doctor_recon_unittest.c, …).
 *
 * Each of those TUs #includes the C under test and satisfies its wire externs
 * with trivial stubs; the libc includes plus the two externs EVERY one of them
 * stubs identically (brix_status_clear, brix_query) live here. Each unit test
 * is compiled to its own binary, so defining the stubs in a header included
 * once per link is safe (and never reached by the pure predicates under test).
 */
#ifndef DIAG_DOCTOR_UT_COMMON_H
#define DIAG_DOCTOR_UT_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_internal.h"

void brix_status_clear(brix_status *st) { (void) st; }
int  brix_query(brix_conn *c, int it, const char *a, char *o, size_t n, brix_status *s)
{ (void) c; (void) it; (void) a; (void) o; (void) n; (void) s; return -1; }

#endif /* DIAG_DOCTOR_UT_COMMON_H */
