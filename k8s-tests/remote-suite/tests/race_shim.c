/*
 * race_shim.c — LD_PRELOAD worker-thread syscall slower for the evil-actor v2 test.
 *
 * WHAT: Interposes the blocking file-I/O syscalls that the nginx-xrootd thread
 *   pool runs on its WORKER threads (pread/pwrite/preadv/pwritev/read/write) and
 *   adds a tunable usleep — but ONLY on a worker thread, never on the event-loop
 *   (main) thread. This deterministically widens the window in which a worker is
 *   mid-syscall on a connection's scratch/payload buffer while the event loop
 *   races ahead (a client disconnect freeing those buffers, a peer connection's
 *   close+unlink+recreate of a shared handle, a pipelined op reusing the scratch).
 *
 * WHY: Worker-vs-event-loop / cross-connection use-after-free and data-race
 *   windows are normally microseconds wide and fire ~1-in-10000. Holding the
 *   worker inside its syscall makes a latent UAF fire on essentially every
 *   iteration, so ASan catches it at the access and TSan catches the missing
 *   happens-before — turning a probabilistic race into a reproducible finding.
 *
 * HOW: A constructor captures the main (event-loop) thread id at load time, which
 *   is inherited verbatim across nginx's fork-without-exec into every worker
 *   process, so pthread_self()==main identifies the event loop in any worker. The
 *   thread-pool threads are created later (init_process) and are therefore "not
 *   main" => the delay applies only to them. Each wrapper chains to the real fn
 *   via dlsym(RTLD_NEXT) (which under a sanitizer build reaches the sanitizer's
 *   own interceptor, then libc). The delay is applied BEFORE the syscall by
 *   default (widens the half-built-task window) or AFTER if XRD_RACE_AFTER=1.
 *
 * ENV: XRD_RACE_DELAY_US (default 0 = inert), XRD_RACE_AFTER (0/1).
 *
 * BUILD: cc -shared -fPIC -O0 -g -o librace.so race_shim.c -ldl -lpthread
 *   (for an ASan/TSan nginx, build a matching variant with the same -fsanitize=).
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/uio.h>

static pthread_t  g_main;
static long       g_delay_us = 0;
static int        g_after = 0;
static int        g_inited = 0;

__attribute__((constructor))
static void race_init(void)
{
    const char *d = getenv("XRD_RACE_DELAY_US");
    const char *a = getenv("XRD_RACE_AFTER");
    g_main = pthread_self();
    g_delay_us = d ? atol(d) : 0;
    g_after = a ? atoi(a) : 0;
    g_inited = 1;
}

/* True on a thread-pool worker (not the event-loop/main thread) when a delay is
 * configured. */
static inline int race_on_worker(void)
{
    return g_inited && g_delay_us > 0 && !pthread_equal(pthread_self(), g_main);
}

/* The one place we sleep. Use nanosleep directly so an intercepted usleep can't
 * recurse, and so worker signal-masking (workers block all signals) is fine. */
static inline void race_delay(void)
{
    struct timespec ts;
    long us = g_delay_us;
    ts.tv_sec  = us / 1000000L;
    ts.tv_nsec = (us % 1000000L) * 1000L;
    nanosleep(&ts, NULL);
}

typedef ssize_t (*pread_fn)(int, void *, size_t, off_t);
typedef ssize_t (*pwrite_fn)(int, const void *, size_t, off_t);
typedef ssize_t (*preadv_fn)(int, const struct iovec *, int, off_t);
typedef ssize_t (*pwritev_fn)(int, const struct iovec *, int, off_t);
typedef ssize_t (*rw_fn)(int, void *, size_t);
typedef ssize_t (*cw_fn)(int, const void *, size_t);

ssize_t pread(int fd, void *buf, size_t n, off_t off)
{
    static pread_fn real;
    if (!real) { real = (pread_fn) dlsym(RTLD_NEXT, "pread"); }
    int w = race_on_worker();
    if (w && !g_after) { race_delay(); }
    ssize_t r = real(fd, buf, n, off);
    if (w && g_after) { race_delay(); }
    return r;
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off)
{
    static pwrite_fn real;
    if (!real) { real = (pwrite_fn) dlsym(RTLD_NEXT, "pwrite"); }
    int w = race_on_worker();
    if (w && !g_after) { race_delay(); }
    ssize_t r = real(fd, buf, n, off);
    if (w && g_after) { race_delay(); }
    return r;
}

ssize_t preadv(int fd, const struct iovec *iov, int cnt, off_t off)
{
    static preadv_fn real;
    if (!real) { real = (preadv_fn) dlsym(RTLD_NEXT, "preadv"); }
    int w = race_on_worker();
    if (w && !g_after) { race_delay(); }
    ssize_t r = real(fd, iov, cnt, off);
    if (w && g_after) { race_delay(); }
    return r;
}

ssize_t pwritev(int fd, const struct iovec *iov, int cnt, off_t off)
{
    static pwritev_fn real;
    if (!real) { real = (pwritev_fn) dlsym(RTLD_NEXT, "pwritev"); }
    int w = race_on_worker();
    if (w && !g_after) { race_delay(); }
    ssize_t r = real(fd, iov, cnt, off);
    if (w && g_after) { race_delay(); }
    return r;
}

/* read()/write() — only the cache-fill / write-through-flush workers use these on
 * a non-main thread; the event loop's own read()/write() are on g_main and so are
 * never delayed. */
ssize_t read(int fd, void *buf, size_t n)
{
    static rw_fn real;
    if (!real) { real = (rw_fn) dlsym(RTLD_NEXT, "read"); }
    if (race_on_worker() && !g_after) { race_delay(); }
    return real(fd, buf, n);
}

ssize_t write(int fd, const void *buf, size_t n)
{
    static cw_fn real;
    if (!real) { real = (cw_fn) dlsym(RTLD_NEXT, "write"); }
    if (race_on_worker() && !g_after) { race_delay(); }
    return real(fd, buf, n);
}
