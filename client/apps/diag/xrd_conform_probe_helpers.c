/*
 * Common conformance scope, budget and verdict bookkeeping.
 * Protocol probes retain wire operations; this module owns only their shared
 * execution contract and copies evidence through the existing result helper.
 */
#include "xrd_conform_probe_helpers.h"
#include "protocols/root/protocol/frame_hdr.h"

/* WHAT: Read exactly one raw frame into caller-bounded body storage.
 * WHY: Flow and framing probes inspect raw replies without allocating from an
 * untrusted wire length, and must refuse a length beyond their own distinct cap.
 * HOW: Initialize outputs; read/unpack through shared framing helpers; enforce
 * the caller's cap before reading the body. No status or stream-ID filtering.
 */
int
xrd_conform_read_bounded_frame(brix_conn *connection, uint16_t *sid,
    uint16_t *wire_status, uint32_t *length, void *body, size_t capacity,
    brix_status *status)
{
    uint8_t header[XRD_RESPONSE_HDR_LEN];

    *sid = 0;
    *wire_status = 0;
    *length = 0;
    memset(body, 0, capacity);
    if (brix_read_full(&connection->io, header, sizeof(header), status) != 0) {
        return -1;
    }
    xrd_resp_hdr_unpack(header, sid, wire_status, length);
    if (*length > capacity) {
        brix_status_set(status, XRDC_EPROTO, 0,
            "conformance response body too large: %u", *length);
        return -1;
    }
    if (*length != 0 && brix_read_full(&connection->io, body, *length, status) != 0) {
        return -1;
    }
    return 0;
}

/* WHAT: Consume one bounded whitespace-delimited locate token.
 * WHY: Holder selection and access-bit checks must use identical boundaries.
 * HOW: Skip separators, retain the token extent, advance the caller's cursor.
 */
int
xrd_conform_next_locate_token(const char **cursor, const char **start,
    size_t *length)
{
    const char *next = *cursor;
    if (next == NULL) {
        return 0;
    }
    while (*next == ' ' || *next == '\t' || *next == '\n') {
        next++;
    }
    *start = next;
    while (*next != '\0' && *next != ' ' && *next != '\t' && *next != '\n') {
        next++;
    }
    *length = (size_t) (next - *start);
    *cursor = next;
    return *length != 0;
}

/* ---- Charge a probe whose caller owns refusal evidence ----
 * WHAT: Return one on reservation or zero when a run ceiling is exhausted.
 * WHY: Raw wire probes retain their own status/evidence handling on refusal.
 * HOW: 1. Delegate to the existing bounded request and byte counter.
 */
int
xrd_conform_reserve_probe(xrd_conform_execution *execution, size_t bytes)
{
    char reason[64];

    return xrd_conform_reserve(execution, bytes, reason, sizeof(reason));
}

/* ---- Charge one payload-free request ----
 * WHAT: Return the common reservation verdict for one zero-byte request.
 * WHY: Control probes must consume requests without inventing payload charges.
 * HOW: 1. Delegate to the common probe reservation with zero bytes.
 */
int
xrd_conform_reserve_request(xrd_conform_execution *execution)
{
    return xrd_conform_reserve_probe(execution, 0);
}

/* ---- Charge a payload-free operation with a typed refusal ----
 * WHAT: Return one on reservation, otherwise zero with the budget status.
 * WHY: Prepare and move probes need the same ceiling evidence as write probes.
 * HOW: 1. Delegate the zero-byte reservation and status to the common helper.
 */
int
xrd_conform_reserve_zero_status(xrd_conform_execution *execution,
    brix_status *status)
{
    return xrd_conform_reserve_status(execution, 0, status);
}

/* ---- Preserve selection and safety filtering ----
 * WHAT: Return one for an initialized row that has not been skipped.
 * WHY: Unselected or unsafe probes must never consume requests or mutate.
 * HOW: 1. Find the row. 2. Exclude absent and explicitly skipped rows.
 */
int
xrd_conform_row_active(xrd_conform_execution *execution, const char *id)
{
    const brix_conform_result *row = xrd_conform_result_find(execution, id);

    return row != NULL && row->verdict != BRIX_CONFORM_VERDICT_SKIPPED;
}

/* ---- Check a probe group's selection ----
 * WHAT: Return one if any supplied row remains active, otherwise zero.
 * WHY: Grouped exercises must not run when only unrelated clauses are selected.
 * HOW: 1. Iterate the immutable identifiers. 2. Delegate to the row predicate.
 */
int
xrd_conform_any_row_active(xrd_conform_execution *execution,
    const char *const *ids, size_t count)
{
    size_t index;

    for (index = 0; index < count; index++) {
        if (xrd_conform_row_active(execution, ids[index])) {
            return 1;
        }
    }
    return 0;
}

/* ---- Charge a bounded protocol operation ----
 * WHAT: Return one on reservation, zero with a usage status on budget refusal.
 * WHY: Every mutation and read probe must obey the common request/byte ceiling.
 * HOW: 1. Reserve through the shared counter. 2. Preserve its refusal reason.
 */
int
xrd_conform_reserve_status(xrd_conform_execution *execution, size_t bytes,
    brix_status *status)
{
    char reason[64];

    if (xrd_conform_reserve(execution, bytes, reason, sizeof(reason))) {
        return 1;
    }
    brix_status_set(status, XRDC_EUSAGE, 0, "%s", reason);
    return 0;
}

/* ---- Record a binary verdict with optional evidence ----
 * WHAT: Store a conformant or divergent result with the corresponding reason.
 * WHY: Probe families must use the same verdict algebra without losing evidence.
 * HOW: 1. Choose verdict and reason. 2. Delegate evidence copying to result_set.
 */
void
xrd_conform_grade_comparison(xrd_conform_execution *execution, const char *id,
    int pass, const char *success, const char *failure,
    const char *expected, const char *received)
{
    xrd_conform_result_set(execution, id,
        pass ? BRIX_CONFORM_VERDICT_CONFORMANT
             : BRIX_CONFORM_VERDICT_DIVERGENT,
        pass ? success : failure, expected, received);
}

/* WHAT: Grade a result with received evidence only. WHY: Preserve the common
 * helper contract. HOW: Delegate comparison with an absent expected value. */
void
xrd_conform_grade_received(xrd_conform_execution *execution, const char *id,
    int pass, const char *success, const char *failure, const char *received)
{
    xrd_conform_grade_comparison(execution, id, pass, success, failure, NULL, received);
}

/* ---- Record a verdict without received evidence ----
 * WHAT: Store a binary result with no protocol-specific evidence.
 * WHY: Login predicates do not always have a wire status to attach.
 * HOW: 1. Delegate grading with a null received value.
 */
void
xrd_conform_grade(xrd_conform_execution *execution, const char *id, int pass,
    const char *success, const char *failure)
{
    xrd_conform_grade_received(execution, id, pass, success, failure, NULL);
}

/* ---- Grade only a selected row ----
 * WHAT: Store a binary result only when the named clause is active.
 * WHY: A compound login exercise must not overwrite a pre-existing safety skip.
 * HOW: 1. Test selection. 2. Delegate binary grading.
 */
void
xrd_conform_grade_active(xrd_conform_execution *execution, const char *id,
    int pass, const char *success, const char *failure)
{
    if (xrd_conform_row_active(execution, id)) {
        xrd_conform_grade(execution, id, pass, success, failure);
    }
}

/* ---- Retain a native client status message ----
 * WHAT: Store a binary verdict and optional native status text.
 * WHY: Write-plane failures need their original diagnostic evidence.
 * HOW: 1. Select a nullable message. 2. Delegate grading.
 */
void
xrd_conform_grade_status(xrd_conform_execution *execution, const char *id,
    int pass, const char *success, const char *failure,
    const brix_status *status)
{
    xrd_conform_grade_received(execution, id, pass, success, failure,
        status == NULL ? NULL : status->msg);
}

/* ---- Retain the exact bounded wire-status evidence ----
 * WHAT: Store a verdict with the kXR status number and at most 150 message bytes.
 * WHY: A defined refusal must remain distinguishable from a generic server error.
 * HOW: 1. Format the established evidence representation. 2. Delegate grading.
 */
void
xrd_conform_grade_wire_status(xrd_conform_execution *execution, const char *id,
    int pass, const char *success, const char *failure,
    const brix_status *status)
{
    char received[192];

    snprintf(received, sizeof(received), "kxr=%d %.150s",
        status == NULL ? 0 : status->kxr,
        status == NULL ? "" : status->msg);
    xrd_conform_grade_received(execution, id, pass, success, failure, received);
}

/* ---- Compare a complete byte observation ----
 * WHAT: Return one only for an exact-length byte-identical observation.
 * WHY: Short or failed page reads must not be accepted as matching prefixes.
 * HOW: 1. Require exact length. 2. Compare only a nonempty complete buffer.
 */
int
xrd_conform_bytes_match(ssize_t got, size_t length, const uint8_t *actual,
    const uint8_t *expected)
{
    if (got != (ssize_t) length) {
        return 0;
    }
    return length == 0 || memcmp(actual, expected, length) == 0;
}

/* ---- Build a named scratch object through the capability helper ----
 * WHAT: Return the shared scratch-path builder's success or refusal.
 * WHY: Generated mutation names must not bypass the authorized scratch prefix.
 * HOW: 1. Pass the configured prefix, leaf and exact object capacity unchanged.
 */
int
xrd_conform_scratch_object_path(xrd_conform_execution *execution,
    const char *leaf, xrd_conform_scratch_object *object)
{
    return brix_conform_scratch_path(execution->run->config.scratch, leaf,
        object->path, sizeof(object->path));
}
