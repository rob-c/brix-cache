/* Phase-118 scratch-confined kXR_fattr mutation probes. */
#include "xrd_conform_probe_helpers.h"
#include "protocols/root/protocol/frame_hdr.h"



/* WHAT: Prove that an export-level read-only policy rejects fattr mutation.
 * WHY: FAT-009 distinguishes EROFS policy from missing-object and auth errors.
 * HOW: Address only the fixed scratch-derived fixture, require fsReadOnly, and
 * remove an attribute if a writable endpoint unexpectedly accepted the set. */
void
xrd_conform_probe_fattr_readonly(xrd_conform_execution *execution,
    brix_conn *connection)
{
    static const char name[] = "phase118-readonly";
    xrd_conform_scratch_object object;
    brix_status status;
    int rc;
    int received_kxr;

    if (brix_conform_scratch_path(execution->run->config.scratch,
            "brix-conform-fattr-readonly", object.path,
            sizeof(object.path)) != 0) {
        xrd_conform_result_set(execution, "FAT-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "scratch-path-invalid",
            "kXR_fsReadOnly", NULL);
        return;
    }
    if (!xrd_conform_reserve_probe(execution, 1)) {
        xrd_conform_result_set(execution, "FAT-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "request-ceiling",
            "kXR_fsReadOnly", NULL);
        return;
    }
    brix_status_clear(&status);
    rc = brix_fattr_set(connection, object.path, name, "x", 1, 0, &status);
    received_kxr = status.kxr;
    if (rc == 0 && xrd_conform_reserve_probe(execution, 0))
        brix_fattr_del(connection, object.path, name, &status);
    xrd_conform_grade_status(execution, "FAT-009", rc != 0 && received_kxr == kXR_fsReadOnly,
        "readonly-fattr-set-refused", "readonly-fattr-wrong-answer", &status);
}

static int
contains_bytes(const uint8_t *haystack, size_t haystack_length,
    const char *needle)
{
    size_t needle_length = strlen(needle);
    size_t index;

    if (needle_length == 0 || needle_length > haystack_length) return 0;
    for (index = 0; index <= haystack_length - needle_length; index++)
        if (memcmp(haystack + index, needle, needle_length) == 0) return 1;
    return 0;
}

static int
raw_set(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, const char *const *names,
    size_t count, const uint8_t *value, size_t value_length,
    brix_status *status)
{
    ClientFattrRequest request;
    xrdw_fattr_req_t fields = { .subcode = kXR_fattrSet,
        .numattr = (uint8_t) count };
    uint8_t *payload;
    uint8_t *cursor;
    uint8_t *body = NULL;
    uint16_t wire_status = 0;
    uint32_t body_length = 0;
    brix_resp_out response = { &wire_status, &body, &body_length };
    size_t path_length = strlen(object->path) + 1;
    size_t payload_length = path_length;
    size_t index;
    int rc;

    for (index = 0; index < count; index++)
        payload_length += 2 + strlen(names[index]) + 1 + 4 + value_length;
    if (payload_length > UINT32_MAX || !xrd_conform_reserve_probe(execution, payload_length))
        return -1;
    payload = malloc(payload_length);
    if (payload == NULL) return -1;
    cursor = payload;
    memcpy(cursor, object->path, path_length);
    cursor += path_length;
    for (index = 0; index < count; index++) {
        size_t name_length = strlen(names[index]) + 1;

        xrdw_put_u16(cursor, 0);
        cursor += 2;
        memcpy(cursor, names[index], name_length);
        cursor += name_length;
    }
    for (index = 0; index < count; index++) {
        xrdw_put_u32(cursor, (uint32_t) value_length);
        cursor += 4;
        memcpy(cursor, value, value_length);
        cursor += value_length;
    }
    xrd_creq_begin(&request, sizeof(request), 0, kXR_fattr);
    xrdw_fattr_req_pack(&fields, ((ClientRequestHdr *) &request)->body);
    {
        brix_payload request_payload = {
            payload, (uint32_t) payload_length
        };
        rc = brix_roundtrip(connection, &request, &request_payload, &response,
            status);
    }
    free(payload);
    if (rc == 0)
        rc = wire_status == kXR_ok && body_length >= 2
            && body[0] == 0 && body[1] == count ? 0 : -1;
    free(body);
    return rc;
}

static void
probe_value_limit(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, uint8_t *large_value,
    brix_status *status)
{
    const char *name[] = { "phase118-max-value" };
    uint8_t *readback;
    size_t readback_length = 0;
    int maximum_ok;
    int over_refused;

    brix_status_clear(status);
    maximum_ok = raw_set(execution, connection, object, name, 1, large_value,
        kXR_faMaxVlen, status) == 0;
    readback = malloc(kXR_faMaxVlen);
    if (maximum_ok && readback != NULL
        && xrd_conform_reserve_probe(execution, kXR_faMaxVlen))
        maximum_ok = brix_fattr_get(connection, object->path, name[0],
                readback, kXR_faMaxVlen, &readback_length, status) == 0
            && readback_length == kXR_faMaxVlen
            && memcmp(readback, large_value, kXR_faMaxVlen) == 0;
    else maximum_ok = 0;
    free(readback);
    if (xrd_conform_reserve_probe(execution, 0))
        brix_fattr_del(connection, object->path, name[0], status);
    brix_status_clear(status);
    over_refused = raw_set(execution, connection, object, name, 1,
        large_value, kXR_faMaxVlen + 1U, status) != 0
        && status->kxr == kXR_ArgTooLong;
    xrd_conform_grade_status(execution, "FAT-004", maximum_ok && over_refused,
        "fattr-value-limit-enforced", "fattr-value-limit-mismatch", status);
}

static void
probe_name_limit(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, const char *max_name,
    const char *over_name, brix_status *status)
{
    const char *name[1] = { max_name };
    uint8_t readback[1];
    uint8_t listed[4096];
    size_t readback_length = 0;
    size_t listed_length = 0;
    int maximum_ok;
    int roundtrip = 0;
    int over_refused;

    brix_status_clear(status);
    maximum_ok = raw_set(execution, connection, object, name, 1,
        (const uint8_t *) "v", 1, status) == 0;
    if (maximum_ok && xrd_conform_reserve_probe(execution, 0))
        roundtrip = brix_fattr_get(connection, object->path, max_name,
                readback, sizeof(readback), &readback_length, status) == 0
            && readback_length == 1 && readback[0] == 'v'
            && brix_fattr_list(connection, object->path, (char *) listed,
                sizeof(listed), &listed_length, status) == 0
            && contains_bytes(listed, listed_length, max_name)
            && brix_fattr_del(connection, object->path, max_name, status) == 0
            && brix_fattr_get(connection, object->path, max_name, readback,
                sizeof(readback), &readback_length, status) != 0;
    name[0] = over_name;
    brix_status_clear(status);
    over_refused = raw_set(execution, connection, object, name, 1,
        (const uint8_t *) "v", 1, status) != 0
        && status->kxr == kXR_ArgInvalid;
    xrd_conform_grade_status(execution, "FAT-005", maximum_ok && roundtrip && over_refused,
        "fattr-name-limit-enforced", "fattr-name-limit-mismatch", status);
}

static void
probe_variable_limit(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    char storage[kXR_faMaxVars + 1U][24];
    const char *names[kXR_faMaxVars + 1U];
    size_t index;
    int maximum_ok;
    int over_refused;

    for (index = 0; index < kXR_faMaxVars + 1U; index++) {
        snprintf(storage[index], sizeof(storage[index]),
            "phase118-var-%02zu", index);
        names[index] = storage[index];
    }
    brix_status_clear(status);
    maximum_ok = raw_set(execution, connection, object, names,
        kXR_faMaxVars, (const uint8_t *) "v", 1, status) == 0;
    brix_status_clear(status);
    over_refused = raw_set(execution, connection, object, names,
        kXR_faMaxVars + 1U, (const uint8_t *) "v", 1, status) != 0
        && status->kxr == kXR_ArgInvalid;
    xrd_conform_grade_status(execution, "FAT-006", maximum_ok && over_refused,
        "fattr-variable-count-limit-enforced",
        "fattr-variable-count-limit-mismatch", status);
}

static void
probe_limits(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    uint8_t *large_value = malloc(kXR_faMaxVlen + 1U);
    char max_name[kXR_faMaxNlen + 1U];
    char over_name[kXR_faMaxNlen + 2U];
    size_t index;

    if (large_value == NULL) return;
    for (index = 0; index <= kXR_faMaxVlen; index++)
        large_value[index] = (uint8_t) index;
    memset(max_name, 'n', sizeof(max_name) - 1);
    max_name[sizeof(max_name) - 1] = '\0';
    memset(over_name, 'o', sizeof(over_name) - 1);
    over_name[sizeof(over_name) - 1] = '\0';

    probe_value_limit(execution, connection, object, large_value, status);
    probe_name_limit(execution, connection, object, max_name, over_name,
        status);
    probe_variable_limit(execution, connection, object, status);
    free(large_value);
}

static int
probe_basic_value(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, const char *name,
    const uint8_t *expected, size_t length, brix_status *status)
{
    uint8_t actual[256];
    size_t actual_length = 0;
    int set;

    set = xrd_conform_reserve_probe(execution, length)
        && brix_fattr_set(connection, object->path, name, expected, length, 0,
            status) == 0;
    return set && xrd_conform_reserve_probe(execution, 0)
        && brix_fattr_get(connection, object->path, name, actual,
            sizeof(actual), &actual_length, status) == 0
        && actual_length == length && memcmp(actual, expected, length) == 0;
}

static int
probe_name_listing(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, const char *first,
    const char *second, brix_status *status)
{
    uint8_t names[4096];
    size_t length = 0;

    if (!xrd_conform_reserve_probe(execution, 1)
        || brix_fattr_set(connection, object->path, second, "x", 1, 0,
            status) != 0 || !xrd_conform_reserve_probe(execution, 0)
        || brix_fattr_list(connection, object->path, (char *) names,
            sizeof(names), &length, status) != 0) return 0;
    return length <= sizeof(names) && contains_bytes(names, length, first)
        && contains_bytes(names, length, second);
}

static int
probe_name_delete(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, const char *name,
    brix_status *status)
{
    uint8_t actual[256];
    size_t length = 0;

    return xrd_conform_reserve_probe(execution, 0)
        && brix_fattr_del(connection, object->path, name, status) == 0
        && xrd_conform_reserve_probe(execution, 0)
        && brix_fattr_get(connection, object->path, name, actual,
            sizeof(actual), &length, status) != 0;
}

void
xrd_conform_probe_fattr_mutations(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object)
{
    static const char first_name[] = "phase118-a";
    static const char second_name[] = "phase118-b";
    uint8_t expected[256];
    brix_file file;
    brix_status status;
    size_t index;
    int got_first = 0;
    int listed = 0;
    int deleted = 0;

    for (index = 0; index < sizeof(expected); index++)
        expected[index] = (uint8_t) index;
    brix_status_clear(&status);
    if (!xrd_conform_reserve_probe(execution, 0)
        || brix_file_open_write(connection, object->path, 1, 0, &file,
            &status) != 0) return;
    if (xrd_conform_reserve_probe(execution, 0))
        brix_file_close(connection, &file, &status);
    probe_limits(execution, connection, object, &status);
    got_first = probe_basic_value(execution, connection, object, first_name,
        expected, sizeof(expected), &status);
    xrd_conform_grade_status(execution, "FAT-001", got_first, "fattr-set-get-byte-exact",
        "fattr-set-get-mismatch", &status);
    xrd_conform_grade_status(execution, "FAT-007", got_first, "fattr-value-8-bit-clean",
        "fattr-value-not-8-bit-clean", &status);

    listed = probe_name_listing(execution, connection, object, first_name,
        second_name, &status);
    xrd_conform_grade_status(execution, "FAT-002", listed, "fattr-list-contained-set-names",
        "fattr-list-missing-set-name", &status);

    deleted = probe_name_delete(execution, connection, object, first_name,
        &status);
    xrd_conform_grade_status(execution, "FAT-003", deleted, "fattr-delete-made-name-absent",
        "fattr-delete-did-not-remove-name", &status);
    if (xrd_conform_reserve_probe(execution, 0))
        brix_fattr_del(connection, object->path, second_name, &status);
    if (xrd_conform_reserve_probe(execution, 0))
        brix_rm(connection, object->path, &status);
}
