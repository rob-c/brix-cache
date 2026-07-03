/*
 * test_stage_admit.c — the pure two-tier staging-backpressure decision behind
 * brix_wt_stage_admit(). The nginx-coupled glue (the statvfs sampler + conf
 * plumbing) is covered by the e2e; this isolates the watermark band logic.
 */
#include <assert.h>
#include <stdio.h>

#include "../../src/fs/cache/stage_admit.h"   /* enum + pure brix_wt_stage_decide */

int main(void) {
    /* below LOW → ALLOW */
    assert(brix_wt_stage_decide(100000, 800000, 900000) == BRIX_WT_ADMIT_ALLOW);
    assert(brix_wt_stage_decide(799999, 800000, 900000) == BRIX_WT_ADMIT_ALLOW);

    /* soft band [LOW, HIGH) → WAIT (LOW boundary inclusive) */
    assert(brix_wt_stage_decide(800000, 800000, 900000) == BRIX_WT_ADMIT_WAIT);
    assert(brix_wt_stage_decide(850000, 800000, 900000) == BRIX_WT_ADMIT_WAIT);
    assert(brix_wt_stage_decide(899999, 800000, 900000) == BRIX_WT_ADMIT_WAIT);

    /* at/above HIGH → REJECT */
    assert(brix_wt_stage_decide(900000, 800000, 900000) == BRIX_WT_ADMIT_REJECT);
    assert(brix_wt_stage_decide(999999, 800000, 900000) == BRIX_WT_ADMIT_REJECT);

    /* disabled (high == 0) → ALLOW regardless of occupancy */
    assert(brix_wt_stage_decide(999999, 0, 0) == BRIX_WT_ADMIT_ALLOW);

    printf("test_stage_admit: ALL PASS\n");
    return 0;
}
