/*
 * Native TPC capability and destination observations.
 * Owns bounded URL construction and byte verification shared by ordinary and
 * path-scoped delegated-copy probes; no transfer or cleanup authority lives here.
 */
#include "xrd_conform_tpc_helpers.h"
#include "core/compat/host_format.h"

#define TPC_PAYLOAD_SIZE 8192U

/* ---- Select an exact TPC row ----
 * WHAT: Return one only for an explicitly named supported TPC clause.
 * WHY: Fixture bypass must not apply to unrelated or broad selections.
 * HOW: 1. Validate execution. 2. Compare against the existing closed TPC list.
 */
int
xrd_conform_tpc_exact_selected(const xrd_conform_execution *execution)
{
    const char *only;

    if (execution == NULL || execution->run == NULL) return 0;
    only = execution->run->config.only;
    return only != NULL
        && (strcmp(only, "TPC-001") == 0 || strcmp(only, "TPC-002") == 0
            || strcmp(only, "TPC-003") == 0 || strcmp(only, "TPC-004") == 0
            || strcmp(only, "TPC-005") == 0 || strcmp(only, "TPC-006") == 0
            || strcmp(only, "TPC-007") == 0
            || strcmp(only, "TPC-008") == 0 || strcmp(only, "TPC-009") == 0);
}


/* ---- Format a native TPC endpoint ----
 * WHAT: Return zero for a bounded root URL, or -1 when it does not fit.
 * WHY: Native copies need the common IPv6-aware authority representation.
 * HOW: 1. Format host and port. 2. Append the selected scheme and path.
 */
int
xrd_conform_tpc_root_url(const brix_url *endpoint, const char *path, char *out,
    size_t out_size)
{
    char authority[XRDC_HOSTPORT_MAX];
    const char *scheme = endpoint->scheme == XRDC_SCHEME_ROOTS
        ? "roots" : "root";

    brix_format_host_port(endpoint->host, (uint16_t) endpoint->port,
        authority, sizeof(authority));
    return (size_t) snprintf(out, out_size, "%s://%s/%s", scheme,
        authority, path) < out_size ? 0 : -1;
}


/* ---- Verify a copied destination ----
 * WHAT: Return one only for exact size and byte equality after a clean close.
 * WHY: A successful transfer status alone does not prove destination integrity.
 * HOW: 1. Stat and open. 2. Read bounded bytes. 3. Close and compare.
 */
int
xrd_conform_tpc_destination_exact(brix_conn *connection, const char *path,
    const uint8_t *expected, size_t expected_length, brix_status *status)
{
    uint8_t received[TPC_PAYLOAD_SIZE];
    brix_statinfo info;
    brix_file file;
    ssize_t length;

    if (brix_stat(connection, path, &info, status) != 0
        || expected_length > sizeof(received)
        || info.size != (long long) expected_length
        || brix_file_open_read(connection, path, &file, status) != 0)
        return 0;
    length = brix_file_read(connection, &file, 0, received,
        sizeof(received), status);
    if (brix_file_close(connection, &file, status) != 0) return 0;
    return length == (ssize_t) expected_length
        && memcmp(received, expected, expected_length) == 0;
}


/* ---- Parse an unsigned TPC query reply ----
 * WHAT: Return one for a complete decimal value, otherwise zero.
 * WHY: Partial or negative capability values must not be accepted as evidence.
 * HOW: 1. Trim whitespace. 2. Parse with overflow checks. 3. Require the end.
 */
int
xrd_conform_tpc_unsigned(const char *value, unsigned long long *number)
{
    char *end = NULL;
    unsigned long long parsed;

    while (isspace((unsigned char) *value)) value++;
    if (!isdigit((unsigned char) *value)) return 0;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value) return 0;
    while (isspace((unsigned char) *end)) end++;
    if (*end != '\0') return 0;
    *number = parsed;
    return 1;
}


/* ---- Query native TPC support ----
 * WHAT: Return zero for a valid numeric capability, otherwise -1.
 * WHY: A malformed capability reply must not become a supported-feature claim.
 * HOW: 1. Use the native query helper. 2. Parse the bounded complete reply.
 */
int
xrd_conform_tpc_query(brix_conn *connection, unsigned long long *value,
    brix_status *status)
{
    char reply[128];

    if (brix_query(connection, kXR_Qconfig, "tpc", reply, sizeof(reply),
            status) != 0) return -1;
    return xrd_conform_tpc_unsigned(reply, value) ? 0 : -1;
}
