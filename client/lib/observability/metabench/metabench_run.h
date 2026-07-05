/*
 * metabench_run.h — threaded GSI runner for the metadata storm. Separate from the
 * pure metabench.{c,h} because it pulls libbrix (brix_connect / brix_mkdir / ...)
 * and pthreads; keeping it apart lets metabench.c unit-test standalone.
 */
#ifndef XRDC_METABENCH_RUN_H
#define XRDC_METABENCH_RUN_H

#include "brix.h"        /* brix_url, brix_opts, brix_status, brix_* ops */
#include "metabench.h"   /* metabench_plan / _phase / _result */

/* WHAT: spawn plan->workers threads, each with ONE persistent GSI conn, running
 * the manifest `phase` and timing every op. WHY: measure pblock, not repeated
 * handshakes. HOW: per-thread brix_connect → ops → brix_close; merge latencies.
 * Returns 0 iff failures==0 AND (p99_ceil_ms==0 || p99_ms<=ceil); else -1.
 * `out` is filled in all cases; `st` carries the first fatal error. */
int metabench_run(const brix_url *url, const brix_opts *opts,
                  const metabench_plan *plan, metabench_phase phase,
                  metabench_result *out, brix_status *st);

#endif /* XRDC_METABENCH_RUN_H */
