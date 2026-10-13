/* Phase-118 explicit quota and capacity fixture probes. */
#include "xrd_conform_internal.h"

#define CONFORM_CAPACITY_WRITE (128U * 1024U)

/* ---- Spend one bounded request/byte allowance ---- */
static int
reserve_op(xrd_conform_execution *execution, size_t bytes,
    brix_status *status)
{
    char reason[64];

    if (xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) return 1;
    brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
    return 0;
}

/* ---- Exercise one operator-labelled refusal endpoint ----
 *
 * WHAT: Opens and writes a fixed scratch child, returning the first kXR error.
 * WHY: WRT-007 distinguishes policy quota from physical/staging capacity.
 * HOW: Connect independently, force-create below the authorised scratch root,
 *      record open/write/close refusal, then best-effort remove only that child.
 */
static int
probe_refusal(xrd_conform_execution *execution, const char *target,
    const char *leaf, const char *opaque, int *observed,
    brix_status *evidence)
{
    static const uint8_t payload[CONFORM_CAPACITY_WRITE] = { 0x5a };
    xrd_conform_scratch_object object;
    brix_opts opts = execution->run->opts;
    brix_url url;
    brix_conn connection;
    brix_file file;
    brix_status status;
    int opened = 0;
    int rc = -1;

    *observed = 0;
    brix_status_clear(&status);
    opts.capture = NULL;
    if (brix_conform_scratch_path(execution->run->config.scratch, leaf,
            object.path, sizeof(object.path)) != 0
        || brix_endpoint_parse(target, &url, &status) != 0
        || (url.scheme != XRDC_SCHEME_ROOT && url.scheme != XRDC_SCHEME_ROOTS)
        || brix_connect(&connection, &url, &opts, &status) != 0) {
        *evidence = status;
        return -1;
    }
    if (reserve_op(execution, 0, &status)
        && brix_file_open_opaque(&connection, object.path, opaque, 1, 1, 0,
            &file, &status) == 0) {
        opened = 1;
        if (reserve_op(execution, sizeof(payload), &status))
            rc = brix_file_write(&connection, &file, 0, payload,
                sizeof(payload), &status);
        if (rc == 0 && reserve_op(execution, 0, &status))
            rc = brix_file_close(&connection, &file, &status);
    }
    *observed = status.kxr;
    *evidence = status;
    if (opened && rc != 0) {
        brix_status cleanup;

        brix_status_clear(&cleanup);
        if (reserve_op(execution, 0, &cleanup))
            brix_file_close(&connection, &file, &cleanup);
    }
    {
        brix_status cleanup;

        brix_status_clear(&cleanup);
        if (reserve_op(execution, 0, &cleanup))
            brix_rm(&connection, object.path, &cleanup);
    }
    brix_close(&connection);
    return rc;
}

/* ---- Grade the paired WRT-007 fixture contract ---- */
void
xrd_conform_probe_write_capacity(xrd_conform_execution *execution)
{
    brix_status quota_status;
    brix_status capacity_status;
    char received[96];
    int quota_code;
    int capacity_code;
    int quota_rc;
    int capacity_rc;

    if (execution->run->quota_target == NULL
        || execution->run->capacity_target == NULL) {
        xrd_conform_result_set(execution, "WRT-007",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "fixture-missing:quota-capacity", NULL, NULL);
        return;
    }
    brix_status_clear(&quota_status);
    brix_status_clear(&capacity_status);
    quota_rc = probe_refusal(execution, execution->run->quota_target,
        "brix-conform-quota", NULL, &quota_code, &quota_status);
    capacity_rc = probe_refusal(execution, execution->run->capacity_target,
        "brix-conform-capacity", "oss.asize=1125899906842624",
        &capacity_code, &capacity_status);
    snprintf(received, sizeof(received), "quota=%d capacity=%d",
        quota_code, capacity_code);
    xrd_conform_result_set(execution, "WRT-007",
        quota_rc != 0 && capacity_rc != 0 && quota_code == kXR_overQuota
            && capacity_code == kXR_NoSpace
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_DIVERGENT,
        quota_rc != 0 && capacity_rc != 0 && quota_code == kXR_overQuota
            && capacity_code == kXR_NoSpace
            ? "quota-and-capacity-refused-with-distinct-codes"
            : "quota-capacity-code-mismatch",
        "quota=3021 capacity=3009", received);
}
