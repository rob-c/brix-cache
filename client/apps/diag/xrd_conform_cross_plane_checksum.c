/* Phase-118 cross-plane server checksum evidence. */
#include "xrd_conform_internal.h"

#include <openssl/evp.h>

#include <ctype.h>

static int
row_active(xrd_conform_execution *execution)
{
    const brix_conform_result *row = xrd_conform_result_find(execution,
        "XPR-003");

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

/* WHAT: Normalize one exact SHA-256 hexadecimal value.
 * WHY: Protocols may vary hex case, but junk and truncated values are not proof.
 * HOW: Require exactly 64 hex digits and copy their lowercase representation. */
static int
normalize_sha256(const char *value, char out[65])
{
    size_t index;

    if (value == NULL || strlen(value) != 64) return -1;
    for (index = 0; index < 64; index++) {
        unsigned char byte = (unsigned char) value[index];

        if (!isxdigit(byte)) return -1;
        out[index] = (char) tolower(byte);
    }
    out[64] = '\0';
    return 0;
}

void
xrd_conform_observe_root_checksum(xrd_conform_execution *execution,
    const char *claimed, int valid)
{
    if (!row_active(execution)) return;
    execution->root_checksum_state = valid
        && normalize_sha256(claimed, execution->root_checksum) == 0 ? 1 : -1;
}

void
xrd_conform_observe_http_checksum(xrd_conform_execution *execution,
    const brix_http_resp *baseline, int valid)
{
    if (!row_active(execution)) return;
    execution->http_checksum_state = valid ? 1 : -1;
    if (valid)
        brix_s3_sha256_hex(baseline->body, baseline->body_len,
            execution->http_checksum);
}

/* WHAT: Validate an S3 ChecksumSHA256 header against adopted response bytes.
 * WHY: Base64 metadata is evidence only when canonical and byte-exact.
 * HOW: Decode the fixed SHA-256 shape, re-encode canonically, then compare raw. */
static int
s3_sha256_matches(const char *value, const brix_http_resp *baseline,
    char checksum[65])
{
    unsigned char decoded[33];
    unsigned char expected[32];
    unsigned char canonical[45];
    int decoded_length;
    size_t index;

    if (strlen(value) != 44 || value[43] != '=') return 0;
    decoded_length = EVP_DecodeBlock(decoded,
        (const unsigned char *) value, 44);
    if (decoded_length != 33) return 0;
    if (EVP_EncodeBlock(canonical, decoded, 32) != 44
        || strcmp((const char *) canonical, value) != 0) return 0;
    brix_s3_sha256_hex(baseline->body, baseline->body_len, checksum);
    for (index = 0; index < 32; index++) {
        unsigned high = (unsigned) (checksum[index * 2] <= '9'
            ? checksum[index * 2] - '0'
            : checksum[index * 2] - 'a' + 10);
        unsigned low = (unsigned) (checksum[index * 2 + 1] <= '9'
            ? checksum[index * 2 + 1] - '0'
            : checksum[index * 2 + 1] - 'a' + 10);

        expected[index] = (unsigned char) ((high << 4) | low);
    }
    return memcmp(decoded, expected, sizeof(expected)) == 0;
}

void
xrd_conform_probe_s3_checksum(xrd_conform_execution *execution,
    const brix_weburl *url, const brix_http_resp *baseline)
{
    brix_http_resp response;
    brix_status status;
    char value[128];
    int rc;
    int have_header;
    int valid;

    if (!url->is_s3 || !row_active(execution)) return;
    memset(&response, 0, sizeof(response));
    brix_status_clear(&status);
    rc = xrd_conform_http_request_fields(execution, url, "GET", NULL,
        "x-amz-checksum-mode: ENABLED\r\n", baseline->body_len, &response,
        &status);
    have_header = rc == 0 && brix_http_header(&response,
        "x-amz-checksum-sha256", value, sizeof(value));
    if (!have_header) {
        if (rc == 0) brix_http_resp_free(&response);
        return;
    }
    valid = response.status == 200 && response.framing_valid
        && response.body_len == baseline->body_len
        && (response.body_len == 0 || memcmp(response.body, baseline->body,
            response.body_len) == 0)
        && s3_sha256_matches(value, &response, execution->s3_checksum);
    execution->s3_checksum_state = valid ? 1 : -1;
    brix_http_resp_free(&response);
}

void
xrd_conform_finalize_checksums(xrd_conform_execution *execution)
{
    const char *checksum = NULL;
    int observations = 0;
    int valid = 1;

#define COMPARE_CHECKSUM(state, value) do { \
    if ((state) != 0) { \
        observations++; \
        if ((state) < 0) valid = 0; \
        else if (checksum == NULL) checksum = (value); \
        else if (strcmp(checksum, (value)) != 0) valid = 0; \
    } \
} while (0)
    COMPARE_CHECKSUM(execution->root_checksum_state,
        execution->root_checksum);
    COMPARE_CHECKSUM(execution->http_checksum_state,
        execution->http_checksum);
    COMPARE_CHECKSUM(execution->s3_checksum_state,
        execution->s3_checksum);
#undef COMPARE_CHECKSUM
    if (observations < 2) return;
    xrd_conform_result_set(execution, "XPR-003",
        valid ? BRIX_CONFORM_VERDICT_CONFORMANT
              : BRIX_CONFORM_VERDICT_DIVERGENT,
        valid ? "cross-plane-server-checksum-agreement"
              : "cross-plane-server-checksum-mismatch",
        "two or more validated server SHA-256 claims agree", NULL);
}
