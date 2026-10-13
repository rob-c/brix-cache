/* Phase-118 scratch-confined kXR_fattr mutation probes. */
#include "xrd_conform_internal.h"
#include "protocols/root/protocol/frame_hdr.h"

static int
reserve_op(xrd_conform_execution *execution, size_t bytes)
{
    char reason[64];

    return xrd_conform_reserve(execution, bytes, reason, sizeof(reason));
}

static void
grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const char *failure, const brix_status *status)
{
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : failure, NULL, status == NULL ? NULL : status->msg);
}

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
    if (!reserve_op(execution, 1)) {
        xrd_conform_result_set(execution, "FAT-009",
            BRIX_CONFORM_VERDICT_INCONCLUSIVE, "request-ceiling",
            "kXR_fsReadOnly", NULL);
        return;
    }
    brix_status_clear(&status);
    rc = brix_fattr_set(connection, object.path, name, "x", 1, 0, &status);
    received_kxr = status.kxr;
    if (rc == 0 && reserve_op(execution, 0))
        brix_fattr_del(connection, object.path, name, &status);
    grade(execution, "FAT-009", rc != 0 && received_kxr == kXR_fsReadOnly,
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
    if (payload_length > UINT32_MAX || !reserve_op(execution, payload_length))
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
probe_limits(xrd_conform_execution *execution, brix_conn *connection,
    const xrd_conform_scratch_object *object, brix_status *status)
{
    uint8_t *large_value = malloc(kXR_faMaxVlen + 1U);
    char max_name[kXR_faMaxNlen + 1U];
    char over_name[kXR_faMaxNlen + 2U];
    char batch_storage[kXR_faMaxVars + 1U][24];
    const char *batch_names[kXR_faMaxVars + 1U];
    const char *one_name[1];
    size_t index;
    int max_value_ok = 0;
    int over_value_refused = 0;
    int max_name_ok = 0;
    int max_name_roundtrip = 0;
    int over_name_refused = 0;
    int max_vars_ok = 0;
    int over_vars_refused = 0;

    if (large_value == NULL) return;
    for (index = 0; index <= kXR_faMaxVlen; index++)
        large_value[index] = (uint8_t) index;
    memset(max_name, 'n', sizeof(max_name) - 1);
    max_name[sizeof(max_name) - 1] = '\0';
    memset(over_name, 'o', sizeof(over_name) - 1);
    over_name[sizeof(over_name) - 1] = '\0';

    one_name[0] = "phase118-max-value";
    brix_status_clear(status);
    max_value_ok = raw_set(execution, connection, object, one_name, 1,
        large_value, kXR_faMaxVlen, status) == 0;
    if (max_value_ok && reserve_op(execution, kXR_faMaxVlen)) {
        uint8_t *readback = malloc(kXR_faMaxVlen);
        size_t   readback_length = 0;

        max_value_ok = readback != NULL
            && brix_fattr_get(connection, object->path, one_name[0], readback,
                              kXR_faMaxVlen, &readback_length, status) == 0
            && readback_length == kXR_faMaxVlen
            && memcmp(readback, large_value, kXR_faMaxVlen) == 0;
        free(readback);
    }
    if (reserve_op(execution, 0))
        brix_fattr_del(connection, object->path, one_name[0], status);
    brix_status_clear(status);
    over_value_refused = raw_set(execution, connection, object, one_name, 1,
        large_value, kXR_faMaxVlen + 1U, status) != 0
        && status->kxr == kXR_ArgTooLong;
    grade(execution, "FAT-004", max_value_ok && over_value_refused,
        "fattr-value-limit-enforced", "fattr-value-limit-mismatch", status);

    one_name[0] = max_name;
    brix_status_clear(status);
    max_name_ok = raw_set(execution, connection, object, one_name, 1,
        (const uint8_t *) "v", 1, status) == 0;
    if (max_name_ok && reserve_op(execution, 0)) {
        uint8_t readback[1];
        uint8_t listed[4096];
        size_t  readback_length = 0;
        size_t  listed_length = 0;

        max_name_roundtrip = brix_fattr_get(connection, object->path,
            max_name, readback, sizeof(readback), &readback_length,
            status) == 0
            && readback_length == 1 && readback[0] == 'v'
            && brix_fattr_list(connection, object->path, (char *) listed,
                sizeof(listed), &listed_length, status) == 0
            && contains_bytes(listed, listed_length, max_name)
            && brix_fattr_del(connection, object->path, max_name,
                status) == 0
            && brix_fattr_get(connection, object->path, max_name, readback,
                sizeof(readback), &readback_length, status) != 0;
    }
    one_name[0] = over_name;
    brix_status_clear(status);
    over_name_refused = raw_set(execution, connection, object, one_name, 1,
        (const uint8_t *) "v", 1, status) != 0
        && status->kxr == kXR_ArgInvalid;
    grade(execution, "FAT-005",
        max_name_ok && max_name_roundtrip && over_name_refused,
        "fattr-name-limit-enforced", "fattr-name-limit-mismatch", status);

    for (index = 0; index < kXR_faMaxVars + 1U; index++) {
        snprintf(batch_storage[index], sizeof(batch_storage[index]),
            "phase118-var-%02zu", index);
        batch_names[index] = batch_storage[index];
    }
    brix_status_clear(status);
    max_vars_ok = raw_set(execution, connection, object, batch_names,
        kXR_faMaxVars, (const uint8_t *) "v", 1, status) == 0;
    brix_status_clear(status);
    over_vars_refused = raw_set(execution, connection, object, batch_names,
        kXR_faMaxVars + 1U, (const uint8_t *) "v", 1, status) != 0
        && status->kxr == kXR_ArgInvalid;
    grade(execution, "FAT-006", max_vars_ok && over_vars_refused,
        "fattr-variable-count-limit-enforced",
        "fattr-variable-count-limit-mismatch", status);
    free(large_value);
}

void
xrd_conform_probe_fattr_mutations(xrd_conform_execution *execution,
    brix_conn *connection, const xrd_conform_scratch_object *object)
{
    static const char first_name[] = "phase118-a";
    static const char second_name[] = "phase118-b";
    uint8_t expected[256];
    uint8_t actual[256];
    uint8_t names[4096];
    brix_file file;
    brix_status status;
    size_t actual_length = 0;
    size_t names_length = 0;
    size_t index;
    int set_first = 0;
    int got_first = 0;
    int listed = 0;
    int deleted = 0;

    for (index = 0; index < sizeof(expected); index++)
        expected[index] = (uint8_t) index;
    brix_status_clear(&status);
    if (!reserve_op(execution, 0)
        || brix_file_open_write(connection, object->path, 1, 0, &file,
            &status) != 0) return;
    if (reserve_op(execution, 0))
        brix_file_close(connection, &file, &status);
    probe_limits(execution, connection, object, &status);
    if (reserve_op(execution, sizeof(expected)))
        set_first = brix_fattr_set(connection, object->path, first_name,
            expected, sizeof(expected), 0, &status) == 0;
    if (set_first && reserve_op(execution, 0))
        got_first = brix_fattr_get(connection, object->path, first_name,
            actual, sizeof(actual), &actual_length, &status) == 0
            && actual_length == sizeof(expected)
            && memcmp(actual, expected, sizeof(expected)) == 0;
    grade(execution, "FAT-001", got_first, "fattr-set-get-byte-exact",
        "fattr-set-get-mismatch", &status);
    grade(execution, "FAT-007", got_first, "fattr-value-8-bit-clean",
        "fattr-value-not-8-bit-clean", &status);

    if (reserve_op(execution, 1))
        brix_fattr_set(connection, object->path, second_name, "x", 1, 0,
            &status);
    if (reserve_op(execution, 0)
        && brix_fattr_list(connection, object->path, (char *) names,
            sizeof(names), &names_length, &status) == 0)
        listed = names_length <= sizeof(names)
            && contains_bytes(names, names_length, first_name)
            && contains_bytes(names, names_length, second_name);
    grade(execution, "FAT-002", listed, "fattr-list-contained-set-names",
        "fattr-list-missing-set-name", &status);

    if (reserve_op(execution, 0))
        deleted = brix_fattr_del(connection, object->path, first_name,
            &status) == 0;
    if (deleted && reserve_op(execution, 0))
        deleted = brix_fattr_get(connection, object->path, first_name,
            actual, sizeof(actual), &actual_length, &status) != 0;
    grade(execution, "FAT-003", deleted, "fattr-delete-made-name-absent",
        "fattr-delete-did-not-remove-name", &status);
    if (reserve_op(execution, 0))
        brix_fattr_del(connection, object->path, second_name, &status);
    if (reserve_op(execution, 0))
        brix_rm(connection, object->path, &status);
}
