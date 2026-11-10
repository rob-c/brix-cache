/* Every parked request must retain an owner if replay drops the new socket. */
#include "core/aio/aio_internal.h"
#include <assert.h>
#include <sys/socket.h>

typedef struct { unsigned completions; brix_areq *request; } result_slot;
typedef struct {
    brix_loop loop;
    brix_aconn connection;
    brix_conn session;
    const char *mode;
    unsigned writes, arms, deletes;
} fixture;

/* WHAT: Recover the reconnect fixture.
 * WHY: The finite transport owns its event loop and connection.
 * HOW: Decode its process-local pointer. */
static fixture *state(void)
{
    void *pointer = NULL;
    assert(sscanf(getenv("BRIX_RECONNECT_FIXTURE"), "%p", &pointer) == 1);
    return pointer;
}

int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

/* Only the worker's completion handoff is supplied; queue ownership stays real. */
/* WHAT: Complete a failed reconnect handoff.
 * WHY: Queue ownership must be tested independently of external servers.
 * HOW: Publish failure status before the completion flag. */
static void *failed_worker(void *argument)
{
    brix_aconn *connection = argument;
    connection->rc_result = -1;
    brix_status_set(&connection->rc_st, XRDC_ESOCK, ECONNRESET, "finite reconnect failure");
    __atomic_store_n(&connection->rc_finished, 1, __ATOMIC_RELEASE);
    return NULL;
}

/* WHAT: Start or refuse a finite reconnect worker.
 * WHY: Worker creation failure must complete parked callers.
 * HOW: Check the real entry point, then refuse or start the handoff thread. */
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                         void *(*entry)(void *), void *argument)
{
    assert(entry == rc_worker_main && argument == &state()->connection);
    if (!strcmp(state()->mode, "worker-failure")) { return EAGAIN; }
    return __real_pthread_create(thread, attributes, failed_worker, argument);
}

/* WHAT: Verify one request completion.
 * WHY: Lost or duplicate callbacks violate caller ownership.
 * HOW: Count exactly once, validate failure payload and clear the owned request. */
static void completed(void *context, int rc, uint16_t kxr, uint8_t *body,
                       uint32_t length, const brix_status *status)
{
    result_slot *slot = context;
    assert(++slot->completions == 1);
    assert(rc == -1 && kxr == (uint16_t) status->kxr && body == NULL && length == 0);
    slot->request = NULL;
}

/* WHAT: Register or refuse finite poll interest.
 * WHY: Registration failure must release the pending queue.
 * HOW: Validate loop and flags, then record registration or return EIO. */
int __wrap_io_engine_arm(brix_loop *loop, brix_aconn *connection, int events)
{
    fixture *f = state(); assert(loop == &f->loop && connection == &f->connection);
    assert(events & EPOLLIN); f->arms++;
    if (!strcmp(f->mode, "arm-failure")) { errno = EIO; return -1; }
    connection->epoll_events = events;
    return 0;
}

/* WHAT: Observe removal of a dead connection.
 * WHY: The transport must unregister only its own loop entry.
 * HOW: Check ownership and count the removal. */
void __wrap_io_engine_del(brix_loop *loop, brix_aconn *connection)
{
    assert(loop == &state()->loop && connection == &state()->connection);
    state()->deletes++;
}

/* WHAT: Accept or drop replayed bytes.
 * WHY: A second transport failure must retain every queued request.
 * HOW: Invoke real transport-error handling or consume the buffered bytes. */
void __wrap_aconn_do_write(brix_aconn *connection)
{
    fixture *f = state(); assert(connection == &f->connection); f->writes++;
    if (strcmp(f->mode, "success") != 0) {
        brix_status error;
        brix_status_set(&error, XRDC_ESOCK, ECONNRESET, "replay socket dropped");
        aconn_on_transport_error(connection, &error);
    } else {
        connection->wbuf.start = connection->wbuf.len;
    }
}

/* WHAT: Finish a real worker handoff. WHY: A replay drop must park unissued
 * requests without sending them again. HOW: Check ownership, join, then poll. */
static void settle_worker(fixture *f, unsigned count)
{
    if (strcmp(f->mode, "repark") != 0 && strcmp(f->mode, "unsafe") != 0) { return; }
    brix_aconn *ac = &f->connection;
    assert(ac->state == ACONN_RECONNECTING && f->writes == 1);
    unsigned pending = 0;
    for (brix_areq *p = ac->pending; p != NULL; p = p->pend_next) { pending++; }
    assert(pending == count - (!strcmp(f->mode, "unsafe") ? 1 : 0));
    assert(ac->rc_thread_live && pthread_join(ac->rc_thread, NULL) == 0);
    ac->rc_thread_live = 0;
    aconn_poll_reconnect(ac);
}

/* WHAT: Run a bounded reconnect replay scenario.
 * WHY: Every parked caller must reach one terminal callback.
 * HOW: Seed requests, execute replay and handoff, then check counts and release resources. */
int main(int argc, char **argv)
{
    assert(argc == 3); unsigned count = (unsigned) atoi(argv[2]);
    assert(count > 0 && count <= 5);
    fixture f = {0}; f.mode = argv[1]; result_slot results[5] = {0};
    char pointer[64]; snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_RECONNECT_FIXTURE", pointer, 1) == 0);
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    brix_aconn *ac = &f.connection; ac->loop = &f.loop; ac->conn = &f.session;
    f.session.io.fd = pair[0]; ac->state = ACONN_RECONNECTING; ac->dead = 1;
    ac->next_sid = 1;
    if (!strcmp(f.mode, "worker-failure") || !strcmp(f.mode, "repark")
        || !strcmp(f.mode, "unsafe")) { ac->max_stall_ms = 1000; }
    for (unsigned index = 0; index < count; index++) {
        brix_areq *request = calloc(1, sizeof(*request)); assert(request != NULL);
        request->cb = completed; request->ctx = &results[index];
        request->retry_safe = strcmp(f.mode, "unsafe") != 0; request->retries_left = 2;
        request->pend_next = ac->pending; ac->pending = request;
        results[index].request = request;
    }
    aconn_reconnect_succeeded(ac);
    settle_worker(&f, count);
    if (!strcmp(f.mode, "success")) {
        assert(ac->state == ACONN_ALIVE && ac->inflight.count == count);
        assert(ac->pending == NULL && f.writes == count);
        brix_status done; brix_status_set(&done, kXR_Cancelled, 0, "finite cleanup");
        aconn_drain_inflight(ac, &done);
    } else {
        assert(ac->state == ACONN_DEAD && ac->inflight.count == 0);
        assert(ac->pending == NULL);
    }
    unsigned total = 0;
    for (unsigned index = 0; index < count; index++) {
        total += results[index].completions;
        if (results[index].request != NULL) { areq_free(results[index].request); }
    }
    printf("completed=%u expected=%u writes=%u\n", total, count, f.writes);
    free(ac->inflight.slots); free(ac->wbuf.buf);
    assert(close(pair[0]) == 0 && close(pair[1]) == 0);
    assert(unsetenv("BRIX_RECONNECT_FIXTURE") == 0);
    return total == count ? 0 : 2;
}
