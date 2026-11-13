/* Reconnect deadlines, retry cadence and the worker-to-loop publication contract. */
#include "core/aio/aio_internal.h"
#include <assert.h>

typedef struct {
    brix_loop loop;
    brix_aconn connection;
    brix_conn session;
    uint64_t now, deadline, connect_ns;
    unsigned attempts, sleeps, success_after;
} fixture;

/* WHAT: Recover the owned fixture. WHY: Clock and transport seams share state.
 * HOW: Decode the pointer installed only for this process. */
static fixture *state(void)
{
    void *pointer = NULL;
    assert(sscanf(getenv("BRIX_AIO_WORKER_FIXTURE"), "%p", &pointer) == 1);
    return pointer;
}

/* WHAT: Supply monotonic time. WHY: Deadline tests must not sleep in real time.
 * HOW: Return a clock advanced only by the finite transport and backoff seams. */
uint64_t __wrap_brix_mono_ns(void) { return state()->now; }

/* WHAT: Reconnect the expected peer. WHY: Retries must retain endpoint identity.
 * HOW: Validate the session, charge elapsed time and succeed on the chosen attempt. */
int __wrap_brix_reconnect(brix_conn *session, const char *host, int port, brix_status *st)
{
    fixture *f = state();
    assert(session == &f->session && !strcmp(host, "reconnect.invalid") && port == 12001);
    assert(f->now < f->deadline && ++f->attempts <= 20);
    f->now += f->connect_ns;
    if (f->success_after != 0 && f->attempts >= f->success_after) { return 0; }
    brix_status_set(st, XRDC_ESOCK, ECONNREFUSED, "finite refusal %u", f->attempts);
    return -1;
}

/* WHAT: Check backoff bounds. WHY: Jitter must never sleep past the deadline.
 * HOW: Validate the public cadence envelope and advance the owned clock. */
int __wrap_nanosleep(const struct timespec *delay, struct timespec *remaining)
{
    fixture *f = state();
    assert(remaining == NULL && delay->tv_sec >= 0 && delay->tv_nsec >= 0);
    assert(delay->tv_nsec < 1000000000L && f->now < f->deadline);
    uint64_t duration = (uint64_t) delay->tv_sec * 1000000000ULL + delay->tv_nsec;
    uint64_t budget = f->deadline - f->now;
    unsigned base = f->attempts == 1 ? 200 : (f->attempts == 2 ? 400 : 800);
    if (f->attempts >= 4) { base = 1000; }
    uint64_t minimum = (uint64_t) base * 1000000ULL;
    assert(duration > 0 && duration <= budget && duration < minimum + 100000000ULL);
    assert(duration >= minimum || duration == budget);
    f->sleeps++; f->now += duration;
    return 0;
}

/* WHAT: Exercise a bounded worker. WHY: The loop must observe one final handoff.
 * HOW: Run the actual worker in a thread, join, inspect status and its sole wakeup. */
int main(int argc, char **argv)
{
    assert(argc == 4); fixture f = {0}; char pointer[64];
    f.success_after = (unsigned) atoi(argv[1]);
    f.now = 1000000000ULL;
    f.deadline = f.now + strtoull(argv[2], NULL, 10) * 1000000ULL;
    f.connect_ns = strtoull(argv[3], NULL, 10) * 1000000ULL;
    f.connection.loop = &f.loop; f.connection.conn = &f.session;
    f.connection.reconnect_deadline_ns = f.deadline;
    snprintf(f.session.host, sizeof(f.session.host), "reconnect.invalid"); f.session.port = 12001;
    snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_AIO_WORKER_FIXTURE", pointer, 1) == 0);
    int wakeup[2]; assert(pipe(wakeup) == 0); f.loop.evfd_w = wakeup[1];
    pthread_t worker; assert(pthread_create(&worker, NULL, rc_worker_main, &f.connection) == 0);
    assert(pthread_join(worker, NULL) == 0);
    assert(__atomic_load_n(&f.connection.rc_finished, __ATOMIC_ACQUIRE) == 1);
    assert(close(wakeup[1]) == 0);
    uint64_t signal = 0; assert(read(wakeup[0], &signal, sizeof(signal)) == sizeof(signal));
    assert(signal == 1 && read(wakeup[0], &signal, sizeof(signal)) == 0);
    assert(close(wakeup[0]) == 0);
    if (f.success_after != 0 && f.attempts >= f.success_after) {
        assert(f.connection.rc_result == 0 && f.attempts == f.success_after);
        assert(f.sleeps == f.attempts - 1);
    } else {
        assert(f.connection.rc_result == -1 && f.now >= f.deadline);
        assert(f.connection.rc_st.kxr == XRDC_ESOCK);
        assert(f.connection.rc_st.sys_errno == (f.attempts ? ECONNREFUSED : 0));
    }
    printf("attempts=%u sleeps=%u result=%d\n", f.attempts, f.sleeps, f.connection.rc_result);
    assert(unsetenv("BRIX_AIO_WORKER_FIXTURE") == 0);
    return 0;
}
