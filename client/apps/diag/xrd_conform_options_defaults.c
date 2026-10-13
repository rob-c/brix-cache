/* Phase-118 safe run-shape defaults. */
#include "xrd_conform_internal.h"

/* WHAT: Fill bounded defaults and reject an unknown run shape.
 * WHY: Zero initialization must never accidentally mean an unlimited run.
 * HOW: Match shape, assign ceilings, then common policy defaults. */
int
xrd_conform_run_defaults(const char *shape, xrd_conform_run *run)
{
    memset(run, 0, sizeof(*run));
    brix_opts_init(&run->opts);
    run->config.profile = "full";
    run->config.reference_mode = BRIX_CONFORM_REFERENCE_ECOSYSTEM;
    run->config.fail_mode = BRIX_CONFORM_FAIL_ANY;
    run->config.out_dir = "brix-conform-report";
    run->config.byte_limit = UINT64_C(268435456);
    if (strcmp(shape, "accept") == 0) {
        run->config.shape = BRIX_CONFORM_RUN_ACCEPT;
        run->config.budget = BRIX_CONFORM_BOUNDARY;
        run->config.wall_seconds = 120;
        run->config.request_limit = 2000;
        return 0;
    }
    if (strcmp(shape, "full") == 0) {
        run->config.shape = BRIX_CONFORM_RUN_FULL;
        run->config.budget = BRIX_CONFORM_PAIRWISE;
        run->config.wall_seconds = 3600;
        run->config.request_limit = 50000;
        return 0;
    }
    if (strcmp(shape, "watch") == 0) {
        run->config.shape = BRIX_CONFORM_RUN_WATCH;
        run->config.budget = BRIX_CONFORM_BOUNDARY;
        run->config.wall_seconds = 120;
        run->config.request_limit = 1000;
        run->config.watch_interval_seconds = 300;
        return 0;
    }
    return -1;
}
