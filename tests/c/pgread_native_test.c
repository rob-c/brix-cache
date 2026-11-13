/* Real page decoder and bounded retry engine; transport boundaries are finite peers. */
#include "protocols/root/ops_internal.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>

typedef struct {
    brix_conn connection;
    const char *mode;
    unsigned sends, frames, body_reads;
    unsigned char wire[32];
    uint32_t wire_size;
} page_fixture_t;

void *__real_malloc(size_t);

/* WHAT: Refuse the page-frame allocation. WHY: A read must surface OOM cleanly.
 * HOW: Arm only at the response boundary, clear before any error formatting. */
void *__wrap_malloc(size_t size)
{
    if (getenv("BRIX_PGREAD_ALLOC") != NULL) {
        unsetenv("BRIX_PGREAD_ALLOC"); errno = ENOMEM; return NULL;
    }
    return __real_malloc(size);
}

/* WHAT: Observe requests at the transport seam. WHY: Retries must request one bad page.
 * HOW: Decode the canonical request body and require the pgRetry optional argument. */
int __wrap_brix_send(brix_conn *connection, void *header, const brix_payload *payload,
                      uint16_t *sid, brix_status *status)
{
    page_fixture_t *fixture = (page_fixture_t *)connection;
    ClientRequestHdr *request = header;
    assert(ntohs(request->requestid) == kXR_pgread);
    xrdw_pgread_req_t decoded;
    xrdw_pgread_req_unpack(request->body, &decoded);
    assert(decoded.offset == 3 && decoded.rlen == 16);
    if (fixture->sends > 0) {
        assert(payload != NULL && payload->len == 2);
        assert(((const unsigned char *)payload->data)[1] == kXR_pgRetry);
    }
    fixture->sends++; *sid = fixture->sends;
    if (!strcmp(fixture->mode, "send-error")) {
        brix_status_set(status, XRDC_ESOCK, EPIPE, "finite send failure"); return -1;
    }
    return 0;
}

/* WHAT: Provide one validated status header. WHY: The read engine handles sequencing.
 * HOW: Derive the frame from fixture-local mode and request/frame counters. */
int __wrap_read_status_frame(brix_conn *connection, uint16_t sid, uint8_t delta,
                              uint8_t *type, uint32_t *size, int64_t *offset,
                              brix_status *status)
{
    page_fixture_t *fixture = (page_fixture_t *)connection;
    assert(sid == fixture->sends && delta == kXR_pgread - kXR_1stRequest);
    fixture->frames++;
    if (!strcmp(fixture->mode, "frame-error")
        || (!strcmp(fixture->mode, "retry-transport") && fixture->sends > 1)) {
        brix_status_set(status, XRDC_ESOCK, ECONNRESET, "finite frame failure"); return -1;
    }
    *offset = !strcmp(fixture->mode, "offset") ? 4 : 3;
    *type = !strcmp(fixture->mode, "type") ? 255 : kXR_FinalResult;
    *size = fixture->wire_size;
    if (!strcmp(fixture->mode, "partial") && fixture->frames == 1) {
        *size = 0; *type = kXR_PartialResult;
    }
    if (!strcmp(fixture->mode, "empty")) { *size = 0; }
    if (!strcmp(fixture->mode, "malformed")) { *size = 1; }
    if (!strcmp(fixture->mode, "allocation")) { assert(setenv("BRIX_PGREAD_ALLOC", "1", 1) == 0); }
    return 0;
}

/* WHAT: Deliver encoded page bytes or a selected transport/corruption fault.
 * WHY: CRC checking and repair must execute in production code.
 * HOW: Copy a genuine encoder result, corrupting only its checksum when selected. */
int __wrap_brix_read_full(brix_io *io, void *out, size_t size, brix_status *status)
{
    page_fixture_t *fixture = (page_fixture_t *)((char *)io - offsetof(brix_conn, io));
    fixture->body_reads++;
    assert(size <= fixture->wire_size);
    if (!strcmp(fixture->mode, "body-error")) {
        brix_status_set(status, XRDC_ESOCK, ECONNRESET, "finite body failure"); return -1;
    }
    memcpy(out, fixture->wire, size);
    int first_bad = !strcmp(fixture->mode, "corrupt")
                    || !strcmp(fixture->mode, "retry-transport");
    if ((first_bad && fixture->sends == 1) || !strcmp(fixture->mode, "retry-fail")) {
        ((unsigned char *)out)[0] ^= 0x80;
    }
    return 0;
}

/* WHAT: Require invalid request bounds to fail before transport.
 * WHY: NULL optional payloads and overwide lengths cannot become malformed requests.
 * HOW: Exercise each public guard and inspect the unchanged send counter. */
static void invalid(page_fixture_t *fixture)
{
    brix_file file = {0}; brix_status status = {0}; unsigned char out[16];
    assert(brix_file_pgread_args(&fixture->connection, &file, 3, out, 16,
                                  NULL, 1, &status) == -1);
    assert(status.kxr == XRDC_EUSAGE);
    assert(brix_file_pgread_args(&fixture->connection, &file, 3, out,
                                  (size_t)INT32_MAX + 1, NULL, 0, &status) == -1);
    assert(status.kxr == XRDC_EUSAGE && fixture->sends == 0);
}

/* WHAT: Classify the expected terminal result. WHY: Retriable corruption is bounded.
 * HOW: Distinguish successful repair, strict integrity refusal and transport failure. */
static int expected_error(const char *mode, int strict)
{
    if (!strcmp(mode, "success") || !strcmp(mode, "partial")) { return 0; }
    if (!strcmp(mode, "empty")) { return strict ? XRDC_EPROTO : 0; }
    if (!strcmp(mode, "corrupt")) { return strict ? XRDC_EINTEGRITY : 0; }
    if (!strcmp(mode, "retry-fail")) { return XRDC_EINTEGRITY; }
    if (!strcmp(mode, "retry-transport")) { return strict ? XRDC_EINTEGRITY : XRDC_ESOCK; }
    if (strstr(mode, "-error")) { return XRDC_ESOCK; }
    return XRDC_EPROTO;
}

/* WHAT: Check one paged read's data, error and retry budget.
 * WHY: A final error must disarm the stall timer and leave no extra requests in flight.
 * HOW: Run strict optional-argument or ordinary profile reads and compare observations. */
static void read_case(page_fixture_t *fixture, int strict)
{
    brix_file file = {0}; brix_status status = {0}; unsigned char out[16] = {0};
    unsigned partials = 0;
    ssize_t result = strict
        ? brix_file_pgread_args(&fixture->connection, &file, 3, out, sizeof(out), NULL, 0, &status)
        : brix_file_pgread_profile(&fixture->connection, &file, 3, out, sizeof(out), &partials, &status);
    int expected = expected_error(fixture->mode, strict);
    if (expected != 0) {
        assert(result == -1 && status.kxr == expected && status.msg[0]);
    } else if (!strcmp(fixture->mode, "empty")) { assert(result == 0); }
    else { assert(result == 16 && !memcmp(out, "0123456789abcdef", 16)); }
    if (!strict && !strcmp(fixture->mode, "partial")) { assert(partials == 1); }
    assert(fixture->connection.io.stall_deadline_ns == 0);
}

/* WHAT: Require the exact finite request count. WHY: Bad pages cannot cause a loop.
 * HOW: Strict reads never retry; normal reads allow only the documented budget. */
static void request_count(const page_fixture_t *fixture, int strict)
{
    unsigned sends = 1;
    if (!strict && !strcmp(fixture->mode, "corrupt")) { sends = 2; }
    if (!strict && !strcmp(fixture->mode, "retry-transport")) { sends = 2; }
    if (!strict && !strcmp(fixture->mode, "retry-fail")) { sends = 3; }
    assert(fixture->sends == sends);
}

/* WHAT: Construct a real encoded page and execute an isolated read scenario.
 * WHY: Tests share the canonical wire encoder while checking externally known bytes.
 * HOW: Keep transport observations in the enclosing connection fixture. */
int main(int argc, char **argv)
{
    assert(argc == 3); page_fixture_t fixture = {0}; fixture.mode = argv[1];
    fixture.connection.io.stall_deadline_ms = 2000;
    fixture.wire_size = xrdp_pg_encode((const uint8_t *)"0123456789abcdef", 16, 3, fixture.wire);
    if (!strcmp(argv[1], "invalid")) { invalid(&fixture); }
    else {
        read_case(&fixture, atoi(argv[2]));
        request_count(&fixture, atoi(argv[2]));
    }
    return 0;
}
