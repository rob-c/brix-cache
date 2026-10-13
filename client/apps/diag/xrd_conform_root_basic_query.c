/* Phase-118 ROOT locate and query probes. */
#include "xrd_conform_internal.h"
#include "posix/posix_map.h"

static int
locate_shape_valid(const char *reply)
{
    return reply != NULL && strchr("SsMm", reply[0]) != NULL
        && strchr("rwx?", reply[1]) != NULL && reply[2] != '\0';
}

static int
message_is_human_readable(const char *message)
{
    const unsigned char *cursor = (const unsigned char *) message;

    if (cursor == NULL || *cursor == '\0') return 0;
    while (*cursor != '\0') {
        if ((*cursor < 0x20 && *cursor != '\t') || *cursor == 0x7f) return 0;
        cursor++;
    }
    return 1;
}

static void
probe_locate(xrd_conform_execution *execution, brix_conn *connection,
    const char *path)
{
    char reply[2048];
    char missing[XRDC_PATH_MAX];
    char reason[64];
    brix_status status;
    brix_status repeated;
    int ok;
    int missing_rc;
    int repeated_rc;

    brix_status_clear(&status);
    if (!xrd_conform_basic_reserve(execution, reason)) return;
    ok = brix_locate(connection, path, reply, sizeof(reply), &status) == 0;
    xrd_conform_basic_grade(execution, "LOC-001", ok && reply[0] != '\0',
        "locate-returned-endpoint", &status);
    if (ok) xrd_conform_basic_grade(execution, "LOC-002",
        locate_shape_valid(reply), "locate-endpoint-shape-valid", &status);
    if (ok) xrd_conform_probe_locate_endpoint(execution, connection, reply,
        path);
    if ((size_t) snprintf(missing, sizeof(missing), "%s.__brix_missing__", path)
        >= sizeof(missing) || !xrd_conform_basic_reserve(execution, reason))
        return;
    brix_status_clear(&status);
    missing_rc = brix_locate(connection, missing, reply, sizeof(reply), &status);
    xrd_conform_basic_grade(execution, "LOC-008",
        missing_rc != 0 && status.kxr == kXR_NotFound,
        "missing-locate-returned-not-found", &status);
    xrd_conform_basic_grade(execution, "ERR-039", missing_rc != 0
        && message_is_human_readable(status.msg),
        "error-message-is-nonempty-and-readable", &status);
    if (!xrd_conform_basic_reserve(execution, reason)) return;
    brix_status_clear(&repeated);
    repeated_rc = brix_locate(connection, missing, reply, sizeof(reply),
        &repeated);
    xrd_conform_basic_grade(execution, "ERR-041",
        missing_rc != 0 && repeated_rc != 0
        && status.kxr == repeated.kxr && strcmp(status.msg, repeated.msg) == 0,
        "logical-error-is-deterministic", &repeated);
}

static int
strict_unsigned(const char *value)
{
    const unsigned char *cursor = (const unsigned char *) value;

    if (cursor == NULL || *cursor == '\0') return 0;
    while (*cursor != '\0' && *cursor != '\n') {
        if (*cursor < '0' || *cursor > '9') return 0;
        cursor++;
    }
    return *cursor == '\0' || cursor[1] == '\0';
}

static void
probe_query(xrd_conform_execution *execution, brix_conn *connection,
    const char *path)
{
    char reply[512];
    char digest[129];
    char crc64[129];
    char crc64nvme[129];
    char reason[64];
    brix_status status;
    unsigned long long total;
    unsigned long long free_bytes;
    int rc;

    if (!xrd_conform_basic_reserve(execution, reason)) return;
    brix_status_clear(&status);
    rc = brix_query(connection, kXR_Qconfig, "tpc", reply, sizeof(reply),
        &status);
    xrd_conform_basic_grade(execution, "QRY-002",
        rc == 0 && strict_unsigned(reply), "qconfig-tpc-is-numeric", &status);
    if (!xrd_conform_basic_reserve(execution, reason)) return;
    brix_status_clear(&status);
    rc = brix_query_cksum(connection, path, "sha256", digest, sizeof(digest),
        &status);
    if (rc == 0) {
        int checksum_ok = strcmp(digest, execution->root_digest) == 0;

        xrd_conform_observe_root_checksum(execution, digest, checksum_ok);
        xrd_conform_basic_grade(execution, "QRY-004", checksum_ok,
            "server-checksum-matches-adopted-bytes", &status);
    } else
        xrd_conform_result_set(execution, "QRY-004",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            status.kxr == kXR_Unsupported ? "sha256-not-advertised"
                                          : "checksum-query-failed",
            NULL, status.msg);
    if (!xrd_conform_basic_reserve(execution, reason)) return;
    brix_status_clear(&status);
    rc = brix_query_cksum(connection, path, "crc64", crc64, sizeof(crc64),
        &status);
    if (rc == 0 && xrd_conform_basic_reserve(execution, reason)) {
        brix_status_clear(&status);
        rc = brix_query_cksum(connection, path, "crc64nvme", crc64nvme,
            sizeof(crc64nvme), &status);
        if (rc == 0)
            xrd_conform_basic_grade(execution, "QRY-005",
                strcmp(crc64, crc64nvme) != 0,
                "crc64-polynomials-produce-distinct-digests", &status);
        else
            xrd_conform_result_set(execution, "QRY-005",
                BRIX_CONFORM_VERDICT_INCONCLUSIVE,
                "crc64nvme-not-available", NULL, status.msg);
    } else if (rc != 0) {
        xrd_conform_result_set(execution, "QRY-005",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE,
            "crc64-not-available", NULL, status.msg);
    }
    if (!xrd_conform_basic_reserve(execution, reason)) return;
    brix_status_clear(&status);
    rc = brix_query_cksum(connection, path, "brix-unknown", digest,
        sizeof(digest), &status);
    xrd_conform_basic_grade(execution, "QRY-006", rc != 0
        && (status.kxr == kXR_Unsupported || status.kxr == kXR_ArgInvalid),
        "unsupported-checksum-refused", &status);
    if (!xrd_conform_basic_reserve(execution, reason)) return;
    brix_status_clear(&status);
    rc = brix_query(connection, kXR_Qspace, path, reply, sizeof(reply),
        &status);
    if (rc != 0) {
        xrd_conform_result_set(execution, "QRY-008",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "qspace-query-failed", NULL,
            status.msg);
        return;
    }
    brix_parse_qspace(reply, &total, &free_bytes);
    xrd_conform_basic_grade(execution, "QRY-008",
        total > 0 && free_bytes <= total,
        "qspace-free-does-not-exceed-total", &status);
}

void
xrd_conform_probe_root_locate_query(xrd_conform_execution *execution,
    brix_conn *connection, const char *path)
{
    probe_locate(execution, connection, path);
    probe_query(execution, connection, path);
}
