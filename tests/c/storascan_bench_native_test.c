/* Real benchmark orchestration with bounded transport failures and resource
 * observers. Worker threads, argument parsing, and result aggregation stay real. */
#include "brix.h"
#include "brix_net.h"
#include "brix_ops.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *fault;
    int64_t size;
    atomic_int connects, connect_ok, closes, opens, open_ok, file_closes;
    atomic_int creates, created, joined, reads, callocs;
    atomic_uint_fast64_t clock;
    atomic_int armed;
} bench_observer;

/* WHAT: Recover caller state. WHY: No fixture globals. HOW: Process-local key. */
static bench_observer *observer(void)
{
    const char *value = getenv("BRIX_BENCH_OBSERVER");
    return value ? (bench_observer *)(uintptr_t) strtoull(value, NULL, 16) : NULL;
}

/* WHAT: Select an injected fault. WHY: Keep each process finite. HOW: Exact tag. */
static int fault(const char *name)
{
    bench_observer *s = observer();
    return s != NULL && strcmp(s->fault, name) == 0;
}

/* WHAT: Supply a connection. WHY: Bound network behavior. HOW: Validate URL. */
int __wrap_brix_connect(brix_conn *c, const brix_url *u,
                       const brix_opts *opts, brix_status *st)
{
    bench_observer *s = observer();
    int index = atomic_fetch_add(&s->connects, 1);
    (void) opts;
    assert(strcmp(u->host, "fixture.invalid") == 0 && u->port == 1094);
    if (fault("connect") || (index > 0 && fault("worker-connect"))) {
        brix_status_set(st, XRDC_ESOCK, ECONNREFUSED, "fixture connect");
        return -1;
    }
    memset(c, 0, sizeof(*c));
    atomic_fetch_add(&s->connect_ok, 1);
    return 0;
}

void __wrap_brix_close(brix_conn *c)
{
    (void) c;
    atomic_fetch_add(&observer()->closes, 1);
    atomic_store(&observer()->armed, 1);
}

int __wrap_brix_stat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *st)
{
    (void) c;
    assert(strcmp(path, "/data") == 0);
    if (fault("stat")) {
        brix_status_set(st, kXR_NotAuthorized, EACCES, "fixture stat denied");
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->size = observer()->size;
    return 0;
}

int __wrap_brix_file_open_read(brix_conn *c, const char *path, brix_file *f, brix_status *st)
{
    (void) c;
    assert(strcmp(path, "/data") == 0);
    atomic_fetch_add(&observer()->opens, 1);
    if (fault("open")) {
        brix_status_set(st, kXR_NotAuthorized, EACCES, "fixture open denied");
        return -1;
    }
    atomic_fetch_add(&observer()->open_ok, 1);
    memset(f, 0, sizeof(*f));
    return 0;
}

int __wrap_brix_file_close(brix_conn *c, brix_file *f, brix_status *st)
{
    (void) c; (void) f; (void) st;
    atomic_fetch_add(&observer()->file_closes, 1);
    return 0;
}

ssize_t __wrap_brix_file_read(brix_conn *c, brix_file *f, int64_t offset,
                             void *buffer, size_t size, brix_status *st)
{
    bench_observer *s = observer();
    size_t available;
    (void) c; (void) f;
    atomic_fetch_add(&s->reads, 1);
    assert(offset >= 0 && offset <= s->size && size > 0);
    if (s->size > (int64_t) size) { assert(offset <= s->size - (int64_t) size); }
    if (fault("read")) {
        brix_status_set(st, kXR_IOError, EIO, "fixture read failure");
        return -1;
    }
    available = (size_t) (s->size - offset);
    if (available > size) { available = size; }
    memset(buffer, 'x', available);
    return (ssize_t) available;
}

/* WHAT: Advance bounded time. WHY: Duration cases finish immediately. HOW: 50ms. */
uint64_t __wrap_brix_mono_ns(void)
{
    return atomic_fetch_add(&observer()->clock, 50000000ULL);
}

int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __real_pthread_join(pthread_t, void **);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg)
{
    int rc, index = atomic_fetch_add(&observer()->creates, 1);
    if (fault("thread") || (index == 0 && fault("one-thread"))) { return EAGAIN; }
    rc = __real_pthread_create(thread, attr, start, arg);
    if (rc == 0) { atomic_fetch_add(&observer()->created, 1); }
    return rc;
}

int __wrap_pthread_join(pthread_t thread, void **result)
{
    int rc = __real_pthread_join(thread, result);
    assert(rc == 0);
    atomic_fetch_add(&observer()->joined, 1);
    return rc;
}

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
char *__real_strdup(const char *);
void *__wrap_malloc(size_t size)
{
    bench_observer *s = observer();
    if (s != NULL && atomic_load(&s->armed)) {
        if (fault("latency-allocation") && size > 1024 * 1024) { return NULL; }
        if (fault("buffer-allocation") && size == 8) { return NULL; }
        if (fault("merge-allocation") && size == 32) { return NULL; }
    }
    return __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size)
{
    bench_observer *s = observer();
    if (s != NULL && atomic_load(&s->armed)) {
        int index = atomic_fetch_add(&s->callocs, 1);
        if (fault("workers-allocation") && index == 0) { return NULL; }
        if (fault("threads-allocation") && index == 1) { return NULL; }
    }
    return __real_calloc(count, size);
}

char *__wrap_strdup(const char *value)
{
    return fault("list-allocation") ? NULL : __real_strdup(value);
}

int storascan_main(int, char **);
/* WHAT: Exercise one CLI invocation. WHY: Assert cleanup on every failure.
 * HOW: Main owns observers until all real worker threads have joined. */
int main(int argc, char **argv)
{
    bench_observer state = {0};
    char pointer[32];
    int rc;
    assert(argc >= 4);
    state.fault = argv[1]; state.size = atoll(argv[2]);
    snprintf(pointer, sizeof(pointer), "%llx", (unsigned long long) (uintptr_t) &state);
    assert(setenv("BRIX_BENCH_OBSERVER", pointer, 1) == 0);
    rc = storascan_main(argc - 3, argv + 3);
    assert(state.connect_ok == state.closes);
    assert(state.open_ok == state.file_closes);
    assert(state.created == state.joined);
    fprintf(stderr, "OBS connects=%d opens=%d reads=%d threads=%d\n",
        (int) state.connects, (int) state.opens, (int) state.reads, (int) state.joined);
    assert(unsetenv("BRIX_BENCH_OBSERVER") == 0);
    return rc;
}
