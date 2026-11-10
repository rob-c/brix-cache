/* Async manager ownership: eager/lazy streams, partial construction and fallback. */
#include "core/aio/aio_internal.h"
#include <assert.h>
#include <sys/socket.h>

typedef struct {
    const char *mode;
    brix_loop loop;
    unsigned allocations, connects, opened, closed, attached, detached, destroyed;
    unsigned fail_allocation, fail_connect, fail_attach, calls;
    int with_options;
} fixture;

/* WHAT: Recover scoped failure state. WHY: Tests need no mutable production globals.
 * HOW: Decode the pointer installed by this isolated process. */
static fixture *state(void)
{
    void *pointer = NULL; const char *text = getenv("BRIX_AIO_MANAGER_FIXTURE");
    if (text) { assert(sscanf(text, "%p", &pointer) == 1); }
    return pointer;
}

void *__real_calloc(size_t, size_t);
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

/* WHAT: Refuse one manager allocation. WHY: Every partial owner must unwind.
 * HOW: Count only allocations while the manager contract is active. */
void *__wrap_calloc(size_t count, size_t size)
{
    fixture *f = state();
    if (f && ++f->allocations == f->fail_allocation) { return NULL; }
    return __real_calloc(count, size);
}

/* WHAT: Refuse parallel connect workers. WHY: Creation failure must fall back inline.
 * HOW: Return the real pthread error convention for this one selected case. */
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                         void *(*entry)(void *), void *argument)
{
    if (!strcmp(state()->mode, "thread-failure")) { return EAGAIN; }
    return __real_pthread_create(thread, attributes, entry, argument);
}

/* WHAT: Supply a finite loop owner. WHY: This family isolates manager construction.
 * HOW: Return the fixture loop or a precise resource failure. */
brix_loop *__wrap_brix_loop_create(brix_status *status)
{
    if (!strcmp(state()->mode, "loop-failure")) {
        brix_status_set(status, XRDC_ESOCK, EMFILE, "finite loop refusal"); return NULL;
    }
    return &state()->loop;
}

/* WHAT: Observe loop shutdown. WHY: Connections must detach before destroying their loop.
 * HOW: Check all attached owners have been released exactly once. */
void __wrap_brix_loop_destroy(brix_loop *loop)
{
    fixture *f = state(); assert(loop == &f->loop && f->attached == f->detached);
    assert(++f->destroyed == 1);
}

/* WHAT: Create a finite session. WHY: Manager cleanup must close actual descriptors.
 * HOW: Validate retained endpoint/options, then own one end of a socketpair. */
int __wrap_brix_connect(brix_conn *connection, const brix_url *url,
                        const brix_opts *options, brix_status *status)
{
    fixture *f = state(); unsigned call = __atomic_add_fetch(&f->connects, 1, __ATOMIC_RELAXED);
    assert(!strcmp(url->host, "manager.invalid") && url->port == 1094);
    assert((options != NULL) == f->with_options);
    if (call == f->fail_connect) {
        brix_status_set(status, kXR_NotAuthorized, EACCES, "finite session refusal"); return -1;
    }
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    memset(connection, 0, sizeof(*connection)); connection->io.fd = pair[0];
    assert(close(pair[1]) == 0); __atomic_add_fetch(&f->opened, 1, __ATOMIC_RELAXED);
    return 0;
}

/* WHAT: Close an owned session. WHY: Partial and successful managers share the same duty.
 * HOW: Require a live descriptor and invalidate it after the real close. */
void __wrap_brix_close(brix_conn *connection)
{
    assert(connection->io.fd >= 0 && close(connection->io.fd) == 0);
    connection->io.fd = -1; state()->closed++;
}

/* WHAT: Attach a session or refuse registration. WHY: Unattached later sessions still need cleanup.
 * HOW: Create a separate owner using the unwrapped allocator. */
brix_aconn *__wrap_brix_aconn_attach(brix_loop *loop, brix_conn *connection, brix_status *status)
{
    fixture *f = state(); assert(loop == &f->loop && fcntl(connection->io.fd, F_GETFD) >= 0);
    if (++f->calls == f->fail_attach) {
        brix_status_set(status, XRDC_ESOCK, ENOSPC, "finite attach refusal"); return NULL;
    }
    brix_aconn *ac = __real_calloc(1, sizeof(*ac)); assert(ac);
    ac->conn = connection; ac->loop = loop; f->attached++; return ac;
}

/* WHAT: Detach without closing the borrowed session. WHY: The manager owns session closure.
 * HOW: Check the descriptor remains valid, then release just the attachment. */
void __wrap_brix_aconn_close(brix_aconn *ac)
{
    assert(ac->loop == &state()->loop && fcntl(ac->conn->io.fd, F_GETFD) >= 0);
    state()->detached++; free(ac);
}

/* WHAT: Inspect forwarded resilience policy. WHY: Lazy streams must inherit the same limits.
 * HOW: Require exact configured values on every attachment. */
void __wrap_brix_aconn_set_resilience(brix_aconn *ac, int stall, int keepalive, int retries)
{
    assert(ac->loop == &state()->loop && stall == 4000 && keepalive == 1234 && retries == 3);
}

/* WHAT: Inspect metadata dispatch. WHY: Manager calls preserve payload and retry policy.
 * HOW: Verify the selected live stream and produce a finite owned response. */
int __wrap_brix_aio_call_ex(brix_aconn *ac, const void *header, const void *payload,
                           uint32_t length, const brix_aio_opts *options, uint16_t *status,
                           uint8_t **body, uint32_t *body_length, brix_status *error)
{
    assert(ac && ac->loop == &state()->loop && fcntl(ac->conn->io.fd, F_GETFD) >= 0);
    assert(xrd_get_u16_be((const uint8_t *) header + 2) == kXR_query);
    assert(length == 7 && !memcmp(payload, "payload", 7));
    assert(options->deadline_ms == 0 && options->max_retries == 3 && options->retry_safe == 1);
    *status = kXR_ok; *body = malloc(3); assert(*body); memcpy(*body, "yes", 3);
    *body_length = 3; memset(error, 0, sizeof(*error)); return 0;
}

/* WHAT: Exercise round-robin and lazy recovery. WHY: One failed lazy slot must not deny all work.
 * HOW: Pick every slot, verify fallback, then retry and dispatch a real manager call. */
static void check_picks(fixture *f, brix_mgr *manager, int count)
{
    brix_aconn *first = brix_mgr_pick(manager); assert(first);
    brix_aconn *second = brix_mgr_pick(manager); assert(second);
    if (f->fail_connect || f->fail_attach || count == 1) { assert(second == first); }
    else { assert(second != first); }
    for (int i = 0; i < count * 3; i++) { assert(brix_mgr_pick(manager)); }
    uint8_t header[24] = {0}, *body = NULL; uint16_t status = 0; uint32_t length = 0;
    xrd_put_u16_be(header + 2, kXR_query); brix_status error = {0};
    assert(brix_mgr_call(manager, header, "payload", 7, 1, &status, &body, &length, &error) == 0);
    assert(status == kXR_ok && length == 3 && !memcmp(body, "yes", 3)); free(body);
}

/* WHAT: Configure one construction scenario. WHY: Fault indices identify distinct owned resources.
 * HOW: Select bounded allocation/connect/attach failure points before entering production code. */
static void configure(fixture *f, const char *mode, int *count, int *eager)
{
    f->mode = mode; *count = 3; *eager = 3;
    if (!strncmp(mode, "alloc-", 6)) { f->fail_allocation = (unsigned) atoi(mode + 6); }
    if (!strcmp(mode, "connect-failure") || !strcmp(mode, "lazy-connect")) { f->fail_connect = 2; }
    if (!strcmp(mode, "attach-failure") || !strcmp(mode, "lazy-attach")) { f->fail_attach = 2; }
    if (!strncmp(mode, "lazy", 4)) { *eager = 1; }
    if (!strcmp(mode, "defaults")) { *count = 0; *eager = 0; }
    if (!strcmp(mode, "clamp-eager")) { *eager = 99; }
}

/* WHAT: Assert manager ownership end to end. WHY: Every successful descriptor must be closed once.
 * HOW: Build, optionally pick/call, destroy and compare independent acquisition counters. */
int main(int argc, char **argv)
{
    assert(argc == 3); fixture f = {0}; int count, eager; configure(&f, argv[1], &count, &eager);
    f.with_options = atoi(argv[2]); char pointer[64]; snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_AIO_MANAGER_FIXTURE", pointer, 1) == 0);
    brix_url url = {0}; strcpy(url.host, "manager.invalid"); url.port = 1094;
    brix_opts options = {0}; brix_status status = {0};
    brix_mgr *manager = brix_mgr_create(&url, f.with_options ? &options : NULL,
                                      count, eager, 4000, 1234, 3, &status);
    int rejected = f.fail_allocation > 0 && f.fail_allocation < 5;
    rejected |= !strcmp(f.mode, "loop-failure") || !strcmp(f.mode, "connect-failure")
             || !strcmp(f.mode, "attach-failure");
    if (rejected) { assert(manager == NULL && status.kxr != 0); }
    else { assert(manager); check_picks(&f, manager, count > 0 ? count : 1); }
    brix_mgr_destroy(manager); brix_mgr_destroy(NULL);
    assert(f.closed == f.opened && f.detached == f.attached);
    assert(unsetenv("BRIX_AIO_MANAGER_FIXTURE") == 0);
    puts("manager ownership verified"); return 0;
}
