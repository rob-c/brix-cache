/* Deterministic event-loop policy handoff at the heartbeat clock boundary. */
#include "core/aio/aio_internal.h"
#include <assert.h>
#include <stdio.h>

typedef struct {
    brix_loop loop;
    brix_aconn connection;
    const char *mode;
    uint64_t now;
    int writes, arms;
} fixture;

/* WHAT: Recover fixture state. WHY: Avoid a production hook or mutable global.
 * HOW: The process owns this pointer encoded in its private environment. */
static fixture *state(void)
{
    return (fixture *)(uintptr_t)strtoull(getenv("BRIX_AIO_FIXTURE"), NULL, 16);
}

/* WHAT: Interleave a policy update during the idle check. WHY: Expose mixed reads.
 * HOW: Change the real policy through its public setter before returning time. */
uint64_t __wrap_brix_mono_ns(void)
{
    fixture *f = state();
    if (!strcmp(f->mode, "disable-during-check")) {
        brix_aconn_set_resilience(&f->connection, -1, 0, -1);
    }
    return f->now;
}

/* WHAT: Observe a queued heartbeat. WHY: No live socket is needed for policy tests.
 * HOW: Validate its wire opcode and count the real request queue's send attempt. */
void __wrap_aconn_do_write(brix_aconn *connection)
{
    fixture *f = state(); assert(connection == &f->connection);
    assert(connection->wbuf.len == XRD_REQUEST_HDR_LEN);
    assert(xrd_get_u16_be(connection->wbuf.buf + 2) == kXR_ping); f->writes++;
}

/* WHAT: Observe poll interest. WHY: The real enqueue arms its owning loop.
 * HOW: Require the exact fixture pointers and permit registration. */
int __wrap_io_engine_arm(brix_loop *loop, brix_aconn *connection, int want)
{
    assert(loop == &state()->loop && connection == &state()->connection);
    assert(want & EPOLLIN); state()->arms++; return 0;
}

void *__real_calloc(size_t, size_t);
/* WHAT: Refuse heartbeat allocation. WHY: Resource pressure must leave no ping latch.
 * HOW: Fail only the request-sized allocation in the explicit fault case. */
void *__wrap_calloc(size_t count, size_t size)
{
    const char *pointer = getenv("BRIX_AIO_FIXTURE");
    if (pointer && size == sizeof(brix_areq) && !strcmp(state()->mode, "alloc-failure")) { return NULL; }
    return __real_calloc(count, size);
}

/* WHAT: Exercise one policy transition. WHY: Preserve timer and retry semantics.
 * HOW: Run the canonical heartbeat decision and inspect its real request map. */
int main(int argc, char **argv)
{
    assert(argc == 3); fixture f = {0}; char pointer[32];
    f.mode = argv[1]; f.now = 20000000000ULL; f.connection.loop = &f.loop;
    snprintf(pointer, sizeof(pointer), "%llx", (unsigned long long)(uintptr_t)&f);
    assert(setenv("BRIX_AIO_FIXTURE", pointer, 1) == 0);
    brix_aconn *ac = &f.connection; ac->state = ACONN_ALIVE; ac->next_sid = 1;
    brix_aconn_set_resilience(ac, 60000, 15000, 5);
    brix_aconn_set_resilience(ac, -1, -1, -1);
    assert(ac->max_stall_ms == 60000 && ac->keepalive_ms == 15000 && ac->def_retries == 5);
    if (!strcmp(f.mode, "disabled")) { brix_aconn_set_resilience(ac, -1, 0, -1); }
    if (!strcmp(f.mode, "recent") || !strcmp(f.mode, "disable-during-check")) { ac->last_activity_ns = f.now - 1; }
    if (!strcmp(f.mode, "reconnecting")) { ac->state = ACONN_RECONNECTING; }
    if (!strcmp(f.mode, "pending")) { ac->ping_inflight = 1; }
    aconn_maybe_ping(ac);
    int expected = atoi(argv[2]); assert(f.writes == expected);
    assert(ac->inflight.count == (unsigned)expected);
    if (expected) {
        brix_areq *request = reqmap_get(&ac->inflight, 1);
        assert(request && request->is_ping && request->retry_safe && request->retries_left == 5);
        assert(request->deadline_ns == f.now + 4000000000ULL);
        assert(ac->ping_inflight && f.arms == 1);
        reqmap_del(&ac->inflight, 1); free(request);
    }
    printf("writes=%d arms=%d keepalive=%d\n", f.writes, f.arms, ac->keepalive_ms);
    free(ac->inflight.slots); free(ac->wbuf.buf); unsetenv("BRIX_AIO_FIXTURE"); return 0;
}
