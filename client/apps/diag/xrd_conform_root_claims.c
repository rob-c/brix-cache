/* Phase-118 ROOT advertised-capability consistency probes. */
#include "xrd_conform_internal.h"

/* WHAT: Fetch and normalize one Qconfig value under the run ceilings.
 * WHY: Stock peers may answer either VALUE or KEY=VALUE with a final newline.
 * HOW: Reserve one exchange, strip line endings, then remove an exact key=. */
static int
query_value(xrd_conform_execution *execution, brix_conn *connection,
    const char *key, char *value, size_t value_size, brix_status *status)
{
    char reason[64];
    char *start;
    size_t key_length = strlen(key);
    size_t length;

    brix_status_clear(status);
    if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) return -2;
    if (brix_query(connection, kXR_Qconfig, key, value, value_size, status)
        != 0) return -1;
    length = strlen(value);
    while (length > 0
        && (value[length - 1] == '\n' || value[length - 1] == '\r'))
        value[--length] = '\0';
    start = value;
    if (length > key_length && memcmp(value, key, key_length) == 0
        && value[key_length] == '=') start += key_length + 1;
    if (start != value) memmove(value, start, strlen(start) + 1);
    return value[0] == '\0' || strcmp(value, key) == 0 ? -1 : 0;
}

/* WHAT: Parse a positive decimal Qconfig limit without truncation.
 * WHY: atoi silently accepts suffixes and wraps values used for allocation.
 * HOW: Require digits only, use strtoull, and constrain to readv's wire u32. */
static int
parse_readv_limit(const char *value, size_t *limit)
{
    const unsigned char *cursor = (const unsigned char *) value;
    char *end = NULL;
    unsigned long long parsed;

    if (*cursor == '\0') return 0;
    while (*cursor != '\0') {
        if (!isdigit(*cursor)) return 0;
        cursor++;
    }
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0
        || parsed >= UINT32_MAX || parsed >= SIZE_MAX) return 0;
    *limit = (size_t) parsed;
    return 1;
}

/* WHAT: Decide whether one advertised checksum name is safe to re-query.
 * WHY: A hostile Qconfig response must not inject CGI syntax into the path.
 * HOW: Accept a short identifier alphabet only. */
static int
algorithm_name_valid(const char *name)
{
    const unsigned char *cursor = (const unsigned char *) name;
    size_t length = 0;

    while (*cursor != '\0') {
        if (!isalnum(*cursor) && *cursor != '_' && *cursor != '-') return 0;
        cursor++;
        length++;
    }
    return length > 0 && length <= 31;
}

static int
digest_is_hex(const char *digest)
{
    const unsigned char *cursor = (const unsigned char *) digest;
    size_t length = 0;

    while (*cursor != '\0') {
        if (!isxdigit(*cursor)) return 0;
        cursor++;
        length++;
    }
    return length > 0 && (length & 1U) == 0;
}

/* WHAT: Prove each advertised checksum algorithm has a working Qcksum path.
 * WHY: A capability list that names an unusable algorithm misleads clients.
 * HOW: Parse bounded CSV tokens and issue one typed query for every token. */
static int
probe_checksum_claims(xrd_conform_execution *execution,
    brix_conn *connection, const char *path, char evidence[192])
{
    char value[512];
    char digest[256];
    char reason[64];
    char *cursor;
    brix_status status;
    unsigned count = 0;
    int rc;

    rc = query_value(execution, connection, "chksum", value, sizeof(value),
        &status);
    if (rc != 0 || strcmp(value, "0") == 0) {
        snprintf(evidence, 192, "chksum-unavailable: %.140s", status.msg);
        return 0;
    }
    cursor = value;
    while (*cursor != '\0') {
        char *comma = strchr(cursor, ',');

        if (comma != NULL) *comma = '\0';
        if (!algorithm_name_valid(cursor)) {
            snprintf(evidence, 192, "invalid-chksum-token: %.120s", cursor);
            return -1;
        }
        if (!xrd_conform_reserve(execution, 0, reason, sizeof(reason))) {
            snprintf(evidence, 192, "%s", reason);
            return 0;
        }
        brix_status_clear(&status);
        if (brix_query_cksum(connection, path, cursor, digest,
                sizeof(digest), &status) != 0 || !digest_is_hex(digest)) {
            snprintf(evidence, 192, "advertised-%.31s-failed: kxr=%d %.100s",
                cursor, status.kxr, status.msg);
            return -1;
        }
        count++;
        if (comma == NULL) break;
        cursor = comma + 1;
    }
    if (count == 0) return 0;
    snprintf(evidence, 192, "advertised-checksums-served=%u", count);
    return 1;
}

/* WHAT: Prove the advertised per-element readv cap at and above its boundary.
 * WHY: A small target cannot distinguish an honest cap from ordinary EOF.
 * HOW: On a large target, compare cap bytes then require cap+1 to error or
 * return no more than cap bytes, byte-exact against the adopted baseline. */
static int
probe_readv_claim(xrd_conform_execution *execution, brix_conn *connection,
    brix_file *file, const uint8_t *baseline, uint64_t size,
    char evidence[192])
{
    char value[64];
    char reason[64];
    brix_readv_seg segment;
    brix_status status;
    uint8_t *buffer;
    size_t limit;
    ssize_t got;
    int rc;

    rc = query_value(execution, connection, "readv_ior_max", value,
        sizeof(value), &status);
    if (rc != 0 || !parse_readv_limit(value, &limit)) {
        snprintf(evidence, 192, "readv_ior_max-unavailable-or-invalid");
        return rc == -2 ? 0 : -1;
    }
    if (size <= limit) {
        snprintf(evidence, 192, "target-too-small:size=%llu limit=%zu",
            (unsigned long long) size, limit);
        return 0;
    }
    buffer = malloc(limit + 1);
    if (buffer == NULL) {
        snprintf(evidence, 192, "allocation-failed:bytes=%zu", limit + 1);
        return 0;
    }
    memset(&segment, 0, sizeof(segment));
    segment.len = limit;
    segment.buf = buffer;
    if (!xrd_conform_reserve(execution, limit, reason, sizeof(reason))) {
        free(buffer);
        snprintf(evidence, 192, "%s", reason);
        return 0;
    }
    brix_status_clear(&status);
    got = brix_file_readv(connection, file, &segment, 1, &status);
    if (got != (ssize_t) limit || segment.got != limit
        || memcmp(buffer, baseline, limit) != 0) {
        free(buffer);
        snprintf(evidence, 192, "readv-limit-not-accepted:kxr=%d got=%zd",
            status.kxr, got);
        return -1;
    }
    memset(buffer, 0, limit + 1);
    segment.len = limit + 1;
    segment.got = 0;
    if (!xrd_conform_reserve(execution, limit + 1, reason, sizeof(reason))) {
        free(buffer);
        snprintf(evidence, 192, "%s", reason);
        return 0;
    }
    brix_status_clear(&status);
    got = brix_file_readv(connection, file, &segment, 1, &status);
    rc = got < 0 || (got == (ssize_t) segment.got && segment.got <= limit
        && memcmp(buffer, baseline, segment.got) == 0);
    free(buffer);
    if (!rc) {
        snprintf(evidence, 192, "readv-limit-exceeded:got=%zd limit=%zu",
            got, limit);
        return -1;
    }
    snprintf(evidence, 192, "readv-bound-observed=%zu", limit);
    return 1;
}

void
xrd_conform_probe_query_claims(xrd_conform_execution *execution,
    brix_conn *connection, brix_file *file, const char *path,
    const uint8_t *baseline, uint64_t size)
{
    char checksum_evidence[192];
    char readv_evidence[192];
    char received[384];
    int checksums = probe_checksum_claims(execution, connection, path,
        checksum_evidence);
    int readv = probe_readv_claim(execution, connection, file, baseline, size,
        readv_evidence);
    brix_conform_verdict verdict = checksums < 0 || readv < 0
        ? BRIX_CONFORM_VERDICT_DIVERGENT
        : checksums > 0 && readv > 0
            ? BRIX_CONFORM_VERDICT_CONFORMANT
            : BRIX_CONFORM_VERDICT_INCONCLUSIVE;

    if (checksums < 0)
        execution->query_checksum_claim_state = -1;
    else if (checksums > 0 && execution->query_checksum_claim_state == 0)
        execution->query_checksum_claim_state = 1;

    snprintf(received, sizeof(received), "%.180s; %.180s", checksum_evidence,
        readv_evidence);
    xrd_conform_result_set(execution, "QRY-003", verdict,
        verdict == BRIX_CONFORM_VERDICT_CONFORMANT
            ? "advertised-query-capabilities-observed"
            : verdict == BRIX_CONFORM_VERDICT_DIVERGENT
                ? "advertised-query-capability-diverged"
                : "claim-evidence-insufficient",
        "every advertised checksum served; readv limit enforced", received);
}
