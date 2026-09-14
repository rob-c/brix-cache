/* Actual copy pump and status classification, with memory-only write callbacks.
 * The fixture owns all bytes and replaces every reachable network operation. */
#include <assert.h>
#include "xfer/copy_internal.h"

volatile sig_atomic_t g_brix_copy_quit;

typedef struct {
    brix_conn primary;
    brix_streamset streams;
    brix_file file;
    size_t size;
    size_t accepted;
    unsigned primary_calls;
    unsigned secondary_calls;
    int refuse_secondary;
    int refuse_primary;
} upload_fixture_t;

/* WHAT: Own callback state. WHY: No socket or persistent fixture is needed.
 * HOW: 1. Return the process-private state reset by main before each case. */
static upload_fixture_t *
fixture(void)
{
    static upload_fixture_t state;
    return &state;
}

/* WHAT: Supply stable monotonic time. WHY: No real retry sleeps should occur.
 * HOW: 1. Return the same tick; error classification must stop denied writes. */
uint64_t
brix_mono_ns(void)
{
    return 1000000000ULL;
}

/* WHAT: Read cancellation. WHY: Match the pump's ordinary signal contract.
 * HOW: 1. Return whether the fixture-owned signal flag has been raised. */
int
brix_copy_quit_requested(void)
{
    return g_brix_copy_quit != 0;
}

/* WHAT: Refuse unexpected retries. WHY: Permission denial must fail immediately.
 * HOW: 1. Assert that this boundary is unreachable in all fixture cases. */
void
brix_backoff_sleep_fast(unsigned attempt)
{
    (void) attempt;
    assert(0 && "a denied write must not enter transport backoff");
}

/* WHAT: Refuse reconnects. WHY: Keep the test entirely outside the network.
 * HOW: 1. Fail immediately if the pump attempts a forbidden retry boundary. */
int
brix_reconnect(brix_conn *connection, const char *host, int port, brix_status *status)
{
    (void) connection; (void) host; (void) port; (void) status;
    assert(0 && "unexpected reconnect");
    return -1;
}

/* WHAT: Refuse reopens. WHY: Denial must not trigger an update-open operation.
 * HOW: 1. Fail immediately if retry classification reaches this boundary. */
int
brix_file_open_update(brix_conn *connection, const char *path, int posc,
    brix_file *file, brix_status *status)
{
    (void) connection; (void) path; (void) posc; (void) file; (void) status;
    assert(0 && "unexpected update-open");
    return -1;
}

/* WHAT: Refuse paged writes. WHY: This fixture covers plain upload selection.
 * HOW: 1. Fail if the plain sink reaches the separate CRC-framing operation. */
int
brix_file_pgwrite(brix_conn *connection, brix_file *file, int64_t offset,
    const void *buffer, size_t length, brix_status *status)
{
    (void) connection; (void) file; (void) offset;
    (void) buffer; (void) length; (void) status;
    assert(0 && "unexpected paged write");
    return -1;
}

/* WHAT: Classify a write connection. WHY: Check round-robin order, not a count.
 * HOW: 1. Record primary calls. 2. Match each secondary against its chunk slot. */
static int
is_secondary(brix_conn *connection, int64_t offset)
{
    upload_fixture_t *state = fixture();
    unsigned slot = (unsigned) (offset / XRDC_COPY_CHUNK) % 4;

    if (connection == &state->primary) {
        state->primary_calls++;
        return 0;
    }
    assert(slot > 0);
    assert(connection == &state->streams.sec[slot - 1]);
    state->secondary_calls++;
    return 1;
}

/* WHAT: Validate or deny one in-memory write. WHY: Preserve exact byte offsets.
 * HOW: 1. Classify the connection. 2. Inject denial before acceptance.
 *      3. Check every byte and advance the accepted extent exactly once. */
int
brix_file_write(brix_conn *connection, brix_file *file, int64_t offset,
    const void *buffer, size_t length, brix_status *status)
{
    upload_fixture_t *state = fixture();
    int secondary = is_secondary(connection, offset);
    const unsigned char *bytes = buffer;
    unsigned char expected = (unsigned char) (offset / XRDC_COPY_CHUNK + 1);

    assert(file == &state->file);
    assert(offset >= 0 && (size_t) offset == state->accepted);
    assert(length == XRDC_COPY_CHUNK);
    assert(length <= state->size - state->accepted);
    if ((secondary && state->refuse_secondary)
        || (!secondary && state->refuse_primary)) {
        brix_status_set(status, kXR_NotAuthorized, EACCES, "fixture write denied");
        return -1;
    }
    for (size_t index = 0; index < length; index++) {
        assert(bytes[index] == expected);
    }
    state->accepted += length;
    return 0;
}

/* WHAT: Supply bounded fixture bytes. WHY: Drive the real EOF-based upload pump.
 * HOW: 1. Check the canonical chunk capacity. 2. Fill one chunk or return EOF. */
static ssize_t
read_fixture(void *context, uint8_t *buffer, int64_t offset, size_t capacity,
    brix_status *status)
{
    upload_fixture_t *state = context;
    size_t length;

    (void) status;
    assert(capacity == XRDC_COPY_CHUNK);
    assert(offset >= 0 && (size_t) offset <= state->size);
    length = state->size - (size_t) offset;
    if (length > capacity) {
        length = capacity;
    }
    memset(buffer, (int) (offset / XRDC_COPY_CHUNK + 1), length);
    return (ssize_t) length;
}

/* WHAT: Run one pump scenario. WHY: Distinguish tiny transfers from real fanout.
 * HOW: 1. Configure owned streams and bytes. 2. Run the actual pump/sink.
 *      3. Require exact connection counts, accepted extent, and status. */
int
main(int argc, char **argv)
{
    upload_fixture_t *state = fixture();
    brix_status status = {0};
    brix_copy_opts options = {0};
    pump_remote_t sink = {0};
    int single;
    int result;

    assert(argc == 2);
    single = strcmp(argv[1], "single-chunk") == 0;
    state->refuse_secondary = strcmp(argv[1], "fallback") == 0;
    state->refuse_primary = strcmp(argv[1], "denied") == 0;
    assert(single || state->refuse_secondary || state->refuse_primary
           || strcmp(argv[1], "fanout") == 0);
    state->size = (single ? 1 : 5) * (size_t) XRDC_COPY_CHUNK;
    state->streams.n = 3;
    sink.c = &state->primary;
    sink.f = &state->file;
    sink.ss = &state->streams;
    sink.resilient = 1;
    sink.max_stall_ms = 1000;
    result = transfer_pump(read_fixture, state, pump_sink_remote, &sink, -1,
                           &options, (int64_t) state->size, &status);
    if (state->refuse_primary) {
        assert(result == -1 && status.kxr == kXR_NotAuthorized);
        assert(status.sys_errno == EACCES && state->accepted == 0);
        assert(state->primary_calls == 1 && state->secondary_calls == 0);
        assert(sink.sec_writes == 0);
        return 0;
    }
    assert(result == 0 && status.kxr == 0);
    assert(state->accepted == state->size);
    assert(state->secondary_calls == (single ? 0u : 3u));
    assert(state->primary_calls == (single ? 1u : state->refuse_secondary ? 5u : 2u));
    assert(sink.sec_writes == (single || state->refuse_secondary ? 0u : 3u));
    return 0;
}
