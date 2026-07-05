/*
 * diag_metabench.c — `xrddiag metabench <url>`: a concurrent metadata storm with
 * ops/sec + p50/p95/p99, proving the CLIENT performs (not just connects). The
 * metadata counterpart of diag_bench.c's download timing.
 *
 * Reuses client/lib/metabench so the workload is byte-for-byte identical to the
 * pblock reliability suite's other layers (one source of truth). Each worker
 * holds one persistent GSI/anon session (per a->conn) and creates → chmods →
 * stats → removes its own /w<id> subtree.
 *
 * Tunables (shared with the rest of xrddiag): -S/--streams = worker count,
 * --count = ops per worker. Exit non-zero on any op failure or a p99 breach so
 * it doubles as an operator health gate.
 */
#include "diag_internal.h"
#include "observability/metabench/metabench_run.h"

int
do_metabench(const diag_args *a)
{
    int         workers = a->streams > 0 ? a->streams : 8;
    int         ops     = a->count   > 0 ? a->count   : 125;
    int         ceil_ms = 50;
    brix_url    u;
    brix_status st;

    brix_status_clear(&st);
    if (a->url == NULL || brix_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag metabench: bad or missing url\n");
        return 50;
    }

    metabench_plan plan;
    metabench_plan_init(&plan, workers, ops, ceil_ms);

    printf("xrddiag metabench %s  (workers=%d, ops/worker=%d, p99<=%dms)\n",
           a->url, workers, ops, ceil_ms);

    metabench_result create_res;
    int rc = metabench_run(&u, &a->conn, &plan, MB_CREATE, &create_res, &st);
    metabench_result_print(&create_res, stdout);

    /* Best-effort cleanup so a repeated run starts from an empty namespace. */
    metabench_result remove_res;
    (void) metabench_run(&u, &a->conn, &plan, MB_REMOVE, &remove_res, &st);

    return rc == 0 ? 0 : 1;
}
