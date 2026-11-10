/* Async loop creation, attachment and submission under bounded resource failures. */
#include "core/aio/aio_internal.h"
#include <assert.h>
#include <sys/socket.h>

typedef struct {
    const char *fault;
    unsigned callbacks, teardown;
    int callback_error;
} fixture;

/* WHAT: Recover fixture state. WHY: Faults belong to one test process.
 * HOW: Decode its explicit environment pointer. */
static fixture *state(void)
{
    const char *value = getenv("BRIX_AIO_LIFECYCLE_FIXTURE");
    void *pointer = NULL;
    if (value != NULL) { assert(sscanf(value, "%p", &pointer) == 1); }
    return pointer;
}

/* WHAT: Select a fault. WHY: Setup must finish before testing a later failure.
 * HOW: Compare the current fixture's scoped fault label. */
static int fault(const char *name)
{
    fixture *f = state(); return f != NULL && f->fault != NULL && !strcmp(f->fault, name);
}

void *__real_calloc(size_t, size_t);
void *__real_malloc(size_t);
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __real_io_engine_setup(brix_loop *, brix_status *);
void __real_io_engine_teardown(brix_loop *);
int __real_io_engine_arm(brix_loop *, brix_aconn *, int);

/* WHAT: Refuse selected allocations. WHY: Each public owner must unwind safely.
 * HOW: Match both the active operation and allocation size. */
void *__wrap_calloc(size_t count, size_t size)
{
    if ((fault("loop-alloc") && size == sizeof(brix_loop))
        || (fault("attach-alloc") && size == sizeof(brix_aconn))
        || (fault("command-alloc") && size == sizeof(cmd))
        || (fault("request-alloc") && size == sizeof(brix_areq))) { return NULL; }
    return __real_calloc(count, size);
}

/* WHAT: Refuse submission payload storage. WHY: A rejected submit owns no callback.
 * HOW: Fail only the distinctive finite payload allocation. */
void *__wrap_malloc(size_t size)
{
    if (fault("payload-alloc") && size == 37) { return NULL; }
    return __real_malloc(size);
}

/* WHAT: Refuse a worker thread. WHY: pthread errors are returned, not stored in errno.
 * HOW: Leave an unrelated errno while returning the requested resource error. */
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                         void *(*entry)(void *), void *argument)
{
    if (fault("thread")) { errno = EACCES; return EAGAIN; }
    return __real_pthread_create(thread, attributes, entry, argument);
}

/* WHAT: Refuse readiness setup. WHY: Partial loop creation must run its teardown.
 * HOW: Set a typed failure before allocating descriptors. */
int __wrap_io_engine_setup(brix_loop *loop, brix_status *status)
{
    if (fault("engine")) {
        brix_status_set(status, XRDC_ESOCK, EMFILE, "finite engine refusal"); return -1;
    }
    return __real_io_engine_setup(loop, status);
}

/* WHAT: Observe loop teardown. WHY: Failures must unwind exactly once.
 * HOW: Count the real teardown, preserving all resource handling. */
void __wrap_io_engine_teardown(brix_loop *loop)
{
    if (state() != NULL) { state()->teardown++; }
    __real_io_engine_teardown(loop);
}

/* WHAT: Refuse connection registration. WHY: Attach must surface loop-side failure.
 * HOW: Leave the owned socket open and report ENOSPC. */
int __wrap_io_engine_arm(brix_loop *loop, brix_aconn *connection, int events)
{
    if (fault("arm")) { errno = ENOSPC; return -1; }
    return __real_io_engine_arm(loop, connection, events);
}

/* WHAT: Count terminal failure callbacks. WHY: A submit must finish exactly once.
 * HOW: Require no borrowed body and retain the returned error class. */
static void completed(void *context, int rc, uint16_t code, uint8_t *body,
                      uint32_t length, const brix_status *status)
{
    fixture *f = context; assert(rc == -1 && code == (uint16_t) status->kxr);
    assert(body == NULL && length == 0 && ++f->callbacks == 1);
    f->callback_error = status->kxr;
}

/* WHAT: Check public creation errors. WHY: Both status and cleanup are caller contracts.
 * HOW: Inject the chosen creation failure and inspect its precise diagnostic. */
static void check_create(fixture *f, const char *mode)
{
    f->fault = mode; brix_status status = {0};
    assert(brix_loop_create(&status) == NULL);
    if (!strcmp(mode, "loop-alloc")) {
        assert(status.kxr == XRDC_EPROTO && f->teardown == 0); return;
    }
    assert(status.kxr == XRDC_ESOCK && f->teardown == 1);
    assert(status.sys_errno == (!strcmp(mode, "thread") ? EAGAIN : EMFILE));
}

/* WHAT: Check refused attachments. WHY: Signing and invalid resources fail closed.
 * HOW: Use a real running loop and owned socket, then assert zero attached owners. */
static void check_attach(fixture *f, const char *mode)
{
    brix_status status = {0}; brix_loop *loop = brix_loop_create(&status); assert(loop);
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    brix_conn session = {0}; session.io.fd = pair[0];
    if (!strcmp(mode, "signing")) { session.signing_active = 1; }
    if (!strcmp(mode, "bad-fd")) { session.io.fd = -1; }
    f->fault = mode;
    brix_loop *argument_loop = !strcmp(mode, "null-loop") ? NULL : loop;
    brix_conn *argument_session = !strcmp(mode, "null-session") ? NULL : &session;
    assert(brix_aconn_attach(argument_loop, argument_session, &status) == NULL);
    assert(loop->aconns == NULL && fcntl(pair[0], F_GETFD) >= 0);
    assert(status.kxr != 0);
    f->fault = NULL; brix_loop_destroy(loop);
    assert(f->teardown == 1 && close(pair[0]) == 0 && close(pair[1]) == 0);
}

/* WHAT: Validate a consumed submit. WHY: Parked requests retain a private payload copy.
 * HOW: Inspect the live request before cancellation and require one callback. */
static void finish_submission(fixture *f, brix_aconn *connection, const char *mode)
{
    if (!strcmp(mode, "park")) {
        brix_areq *request = connection->pending; assert(request && !request->pend_next);
        assert(request->plen == 37 && request->payload[0] == 0xa5);
        assert(request->retry_safe && request->retries_left == 2 && f->callbacks == 0);
        brix_status status; brix_status_set(&status, kXR_Cancelled, 0, "finite cleanup");
        aconn_pending_fail_all(connection, &status);
    }
    assert(f->callbacks == 1 && connection->pending == NULL);
}

/* WHAT: Check command ownership. WHY: Rejections and parked requests differ in ownership.
 * HOW: Queue through the public API, drain the real command queue, then cancel safely. */
static void check_submit(fixture *f, const char *mode)
{
    brix_loop loop = {0}; pthread_mutex_init(&loop.cq_lock, NULL);
    int pair[2]; assert(pipe(pair) == 0); loop.evfd_w = pair[1];
    brix_aconn connection = {0}; connection.loop = &loop;
    connection.state = !strcmp(mode, "dead") ? ACONN_DEAD : ACONN_RECONNECTING;
    connection.def_retries = 7;
    uint8_t header[24] = {0}, payload[37]; memset(payload, 0xa5, sizeof(payload));
    header[3] = kXR_query & 0xff; brix_status status = {0};
    f->fault = !strcmp(mode, "request-alloc") ? NULL : mode;
    brix_aio_opts options = {1234, 2, 1, NULL, 0};
    int rc = brix_aio_submit_ex(&connection, header, payload, sizeof(payload),
                              &options, completed, f, &status);
    if (!strcmp(mode, "command-alloc") || !strcmp(mode, "payload-alloc")) {
        assert(rc == -1 && status.kxr == XRDC_EPROTO && loop.cq_head == NULL);
        assert(f->callbacks == 0);
    } else {
        assert(rc == 0 && loop.cq_head && loop.cq_tail == loop.cq_head);
        memset(payload, 0, sizeof(payload)); f->fault = mode; loop_drain_commands(&loop);
        assert(loop.cq_head == NULL && loop.cq_tail == NULL);
        finish_submission(f, &connection, mode);
    }
    f->fault = NULL;
    assert(close(pair[0]) == 0 && close(pair[1]) == 0);
    assert(pthread_mutex_destroy(&loop.cq_lock) == 0);
}

/* WHAT: Exercise null-argument refusals. WHY: Invalid calls must not enqueue or callback.
 * HOW: Vary one missing required input at a time and inspect typed failures. */
static void check_null_submit(fixture *f, const char *mode)
{
    brix_aconn connection = {0}; uint8_t header[24] = {0}; brix_status status = {0};
    brix_aconn *ac = !strcmp(mode, "null-connection") ? NULL : &connection;
    const void *hdr = !strcmp(mode, "null-header") ? NULL : header;
    brix_aio_cb callback = !strcmp(mode, "null-callback") ? NULL : completed;
    assert(brix_aio_submit(ac, hdr, NULL, 0, callback, f, 100, &status) == -1);
    assert(status.kxr == XRDC_EUSAGE && f->callbacks == 0);
    brix_loop_destroy(NULL); brix_aconn_close(NULL); brix_aconn_set_resilience(NULL, 0, 0, 0);
}

/* WHAT: Shut down an attached loop. WHY: The session socket remains caller-owned.
 * HOW: Exercise explicit close, shutdown-owned close and STOP allocation refusal. */
static void check_shutdown(fixture *f, const char *mode)
{
    brix_status status = {0}; brix_loop *loop = brix_loop_create(&status); assert(loop);
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    brix_conn session = {0}; session.io.fd = pair[0];
    brix_aconn *ac = brix_aconn_attach(loop, &session, &status); assert(ac);
    brix_aconn_set_resilience(ac, 0, 0, 0);
    if (!strcmp(mode, "explicit")) { brix_aconn_close(ac); assert(loop->aconns == NULL); }
    if (!strcmp(mode, "stop-alloc")) { f->fault = "command-alloc"; }
    brix_loop_destroy(loop); f->fault = NULL;
    assert(f->teardown == 1 && fcntl(pair[0], F_GETFD) >= 0);
    assert(close(pair[0]) == 0 && close(pair[1]) == 0);
}

/* WHAT: Run one lifecycle contract. WHY: Fault state must be isolated per process.
 * HOW: Dispatch the selected family and release the fixture pointer after cleanup. */
int main(int argc, char **argv)
{
    assert(argc == 3); fixture f = {0}; char pointer[64];
    snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_AIO_LIFECYCLE_FIXTURE", pointer, 1) == 0);
    if (!strcmp(argv[1], "create")) { check_create(&f, argv[2]); }
    else if (!strcmp(argv[1], "attach")) { check_attach(&f, argv[2]); }
    else if (!strcmp(argv[1], "submit")) { check_submit(&f, argv[2]); }
    else if (!strcmp(argv[1], "shutdown")) { check_shutdown(&f, argv[2]); }
    else { assert(!strcmp(argv[1], "null")); check_null_submit(&f, argv[2]); }
    assert(unsetenv("BRIX_AIO_LIFECYCLE_FIXTURE") == 0);
    puts("lifecycle ownership verified"); return 0;
}
