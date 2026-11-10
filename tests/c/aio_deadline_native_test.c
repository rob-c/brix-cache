/* Request expiry must retain live owners and bound readiness sleeps. */
#include "core/aio/aio_internal.h"
#include <assert.h>

typedef struct { unsigned timed_out, cancelled; } result_slot;
typedef struct {
    brix_loop loop;
    brix_aconn connection;
    uint64_t now;
    unsigned deletes;
} fixture;

/* WHAT: Recover the owned clock and loop. WHY: No external timing affects this test.
 * HOW: Decode the process-local fixture pointer. */
static fixture *state(void)
{
    void *pointer = NULL;
    assert(sscanf(getenv("BRIX_AIO_DEADLINE_FIXTURE"), "%p", &pointer) == 1);
    return pointer;
}

/* WHAT: Read finite monotonic time. WHY: Expiration boundaries must be exact.
 * HOW: Return the clock owned by this fixture. */
uint64_t __wrap_brix_mono_ns(void) { return state()->now; }

/* WHAT: Observe transport removal. WHY: Only an expired heartbeat kills the link.
 * HOW: Check connection ownership and count the removal. */
void __wrap_io_engine_del(brix_loop *loop, brix_aconn *connection)
{
    assert(loop == &state()->loop && connection == &state()->connection);
    state()->deletes++;
}

/* WHAT: Classify terminal callbacks. WHY: Expiry and cleanup each release once.
 * HOW: Check failure-body ownership and separate timeout from cancellation. */
static void completed(void *context, int rc, uint16_t code, uint8_t *body,
                      uint32_t length, const brix_status *status)
{
    result_slot *slot = context;
    assert(rc == -1 && body == NULL && length == 0 && code == (uint16_t) status->kxr);
    if (status->sys_errno == ETIMEDOUT) { slot->timed_out++; }
    else { slot->cancelled++; }
    assert(slot->timed_out + slot->cancelled == 1);
}

/* WHAT: Seed actual request ownership. WHY: Expiry must unlink from each container.
 * HOW: Allocate a real request and park or insert it by connection state. */
static void add_request(fixture *f, result_slot *slot, unsigned sid, uint64_t deadline, int ping)
{
    brix_areq *request = calloc(1, sizeof(*request)); assert(request);
    request->sid = (uint16_t) sid; request->deadline_ns = deadline;
    request->cb = completed; request->ctx = slot; request->is_ping = ping;
    if (f->connection.state == ACONN_RECONNECTING) {
        request->pend_next = f->connection.pending; f->connection.pending = request;
    } else { assert(reqmap_put(&f->connection.inflight, request) == 0); }
}

/* WHAT: Check deadline scheduling without expiry. WHY: Long deadlines must not wrap.
 * HOW: Seed a sole future request and require the expected bounded wait. */
static void check_wait(fixture *f, uint64_t delta, int expected)
{
    result_slot slot = {0};
    add_request(f, &slot, 1, f->now + delta, 0);
    assert(loop_process_timeouts(&f->loop) == expected);
    assert(slot.timed_out == 0 && slot.cancelled == 0);
    brix_status status; brix_status_set(&status, kXR_Cancelled, 0, "finite cleanup");
    aconn_drain_inflight(&f->connection, &status);
    assert(slot.cancelled == 1);
}

/* WHAT: Expire a mixed request set. WHY: One expired owner must not consume survivors.
 * HOW: Mix timeless, overdue, exact-deadline and future requests in each state. */
static void check_expiry(fixture *f, const char *mode)
{
    brix_aconn *ac = &f->connection; result_slot results[4] = {0};
    if (!strcmp(mode, "parked")) { ac->state = ACONN_RECONNECTING; }
    if (!strcmp(mode, "dead")) { ac->state = ACONN_DEAD; ac->dead = 1; }
    int ping = !strcmp(mode, "heartbeat");
    add_request(f, &results[0], 1, 0, 0);
    add_request(f, &results[1], 65, f->now - 1, ping);
    add_request(f, &results[2], 129, f->now, 0);
    add_request(f, &results[3], 193, f->now + 1000000, 0);
    int wait = loop_process_timeouts(&f->loop);
    assert(wait >= 1 && wait <= AIO_TICK_MS);
    unsigned expired = results[1].timed_out + results[2].timed_out;
    assert(expired == (!strcmp(mode, "dead") ? 0 : 2));
    assert(results[0].timed_out == 0 && results[3].timed_out == 0);
    assert(f->deletes == (unsigned) ping);
    if (ping) { assert(ac->state == ACONN_DEAD && results[3].cancelled == 1); }
    brix_status status; brix_status_set(&status, kXR_Cancelled, 0, "finite cleanup");
    aconn_drain_inflight(ac, &status); aconn_pending_fail_all(ac, &status);
    for (unsigned index = 0; index < 4; index++) {
        assert(results[index].timed_out + results[index].cancelled == 1);
    }
    assert(ac->inflight.count == 0 && ac->pending == NULL);
}

/* WHAT: Run a finite deadline scenario. WHY: No live network is needed for timer rules.
 * HOW: Exercise the canonical scanner and release all map storage afterward. */
int main(int argc, char **argv)
{
    assert(argc == 4); fixture f = {0}; char pointer[64]; f.now = 1000000000ULL;
    f.connection.loop = &f.loop; f.connection.state = ACONN_ALIVE;
    f.loop.aconns = &f.connection;
    snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_AIO_DEADLINE_FIXTURE", pointer, 1) == 0);
    if (!strcmp(argv[1], "wait")) { check_wait(&f, strtoull(argv[2], NULL, 10), atoi(argv[3])); }
    else { check_expiry(&f, argv[1]); }
    free(f.connection.inflight.slots);
    assert(unsetenv("BRIX_AIO_DEADLINE_FIXTURE") == 0);
    puts("deadline ownership verified"); return 0;
}
