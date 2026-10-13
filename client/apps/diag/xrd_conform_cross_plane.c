/* Phase-118 cross-plane size, content and existence grading. */
#include "xrd_conform_internal.h"

static void
grade_bytes(xrd_conform_execution *execution)
{
    uint64_t size = 0;
    const char *digest = NULL;
    int planes = 0;
    int size_ok = 1;
    int digest_ok = 1;

#define COMPARE_PLANE(have, plane_size, plane_digest) do { \
    if (have) { \
        if (planes == 0) { size = plane_size; digest = plane_digest; } \
        else { size_ok &= size == plane_size; \
               digest_ok &= strcmp(digest, plane_digest) == 0; } \
        planes++; \
    } \
} while (0)
    COMPARE_PLANE(execution->have_root, execution->root_size,
        execution->root_digest);
    COMPARE_PLANE(execution->have_http, execution->http_size,
        execution->http_digest);
    COMPARE_PLANE(execution->have_s3, execution->s3_size,
        execution->s3_digest);
    COMPARE_PLANE(execution->have_ftp, execution->ftp_size,
        execution->ftp_digest);
    COMPARE_PLANE(execution->have_oci, execution->oci_size,
        execution->oci_digest);
#undef COMPARE_PLANE
    if (planes < 2) return;
    xrd_conform_result_set(execution, "XPR-001",
        size_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                : BRIX_CONFORM_VERDICT_DIVERGENT,
        size_ok ? "cross-plane-size-agreement" : "cross-plane-size-mismatch",
        NULL, NULL);
    xrd_conform_result_set(execution, "XPR-002",
        digest_ok ? BRIX_CONFORM_VERDICT_CONFORMANT
                  : BRIX_CONFORM_VERDICT_DIVERGENT,
        digest_ok ? "cross-plane-sha256-agreement"
                  : "cross-plane-byte-mismatch", NULL, NULL);
}

static void
grade_existence(xrd_conform_execution *execution)
{
    const brix_conform_result *row = xrd_conform_result_find(execution,
        "XPR-007");
    int observations;
    int pass;

    if (row == NULL || row->verdict == BRIX_CONFORM_VERDICT_SKIPPED) return;
    observations = execution->http_missing_state != 0 ? 1 : 0;
    observations += execution->s3_missing_state != 0 ? 1 : 0;
    if (observations < 2) {
        xrd_conform_result_set(execution, "XPR-007",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "paired-plane-missing-observation-required", NULL, NULL);
        return;
    }
    pass = execution->http_missing_state == 1
        && execution->s3_missing_state == 1;
    xrd_conform_result_set(execution, "XPR-007",
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? "cross-plane-absence-agreement"
             : "cross-plane-existence-mismatch",
        "HTTP and S3 both report the generated object absent", NULL);
}

/* WHAT: Resolve cross-plane byte and absence rows after all targets run.
 * WHY: Plane agreement is a separate concern from execution/reporting.
 * HOW: Compare every available digest/size, then paired absence observations. */
void
xrd_conform_grade_cross_plane(xrd_conform_execution *execution)
{
    grade_bytes(execution);
    grade_existence(execution);
}
