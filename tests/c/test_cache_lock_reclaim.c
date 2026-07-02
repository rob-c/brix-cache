/*
 * test_cache_lock_reclaim.c — regression: a cache-fill lock left by a DEAD owner
 * must be reclaimed, not stall the entry forever ("stuck after many reboots").
 *
 * THE BUG
 *   The per-file cache fill lock is an O_CREAT|O_EXCL lock FILE (src/fs/cache/lock.c)
 *   with the owner's pid written in. It is unlinked at every normal fill exit —
 *   but a worker SIGKILLed/crashed mid-fill (e.g. at reload's
 *   worker_shutdown_timeout) leaves it orphaned. Nothing reclaims it:
 *   xrootd_cache_try_lock never reads the pid back, cache_reap.c skips *.lock,
 *   and the eviction-sentinel stale-reclaim is a different lock. The orphaned
 *   .lock file survives reboots on disk, so EVERY later request for that entry
 *   polls to cache_lock_timeout (default 300s) and fails kXR_FileLocked —
 *   permanently, while pinning a thread-pool thread for the whole timeout.
 *   Across many restart cycles these accumulate.
 *
 * THE FIX
 *   xrootd_cache_wait_or_lock() reclaims a provably-stale lock (owner pid dead,
 *   or torn content older than the timeout) and retries. A benign reclaim race
 *   at worst causes one duplicate origin fetch, which is safe: fills write a
 *   verified .part and atomically rename it into place.
 *
 * TESTS
 *   1. dead-owner lock  -> reclaimed, caller acquires (owned=1)   [the bug]
 *   2. live-owner lock  -> NOT reclaimed, honoured to timeout      [no over-reclaim]
 *   3. no lock present  -> acquired immediately (owned=1)          [sanity]
 */
#include "fs/cache/cache_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

/* --- stubs for the module/nginx externals lock.o references --- */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
                   const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;   /* never called (t->c==NULL) */
}

int
xrootd_cache_file_ready(const char *path)
{
    (void) path;
    return 0;                       /* cache file never "already present" here */
}

void
xrootd_cache_set_error(xrootd_cache_fill_t *t, int xrd, int sys, const char *msg)
{
    (void) sys; (void) msg;
    if (t) { t->result = -1; t->xrd_error = xrd; }
}

void
xrootd_cache_set_syserror(xrootd_cache_fill_t *t, int xrd, const char *msg)
{
    (void) msg;
    if (t) { t->result = -1; t->xrd_error = xrd; t->sys_errno = errno; }
}

/* A pid that is guaranteed dead: fork a child that exits immediately, reap it. */
static pid_t
dead_pid(void)
{
    pid_t p = fork();
    if (p == 0) { _exit(0); }
    int st;
    waitpid(p, &st, 0);
    /* tiny window before the slot could be reused; adequate for a unit test */
    return p;
}

static void
write_lock(const char *path, long pid)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) { perror("open lock"); exit(2); }
    char b[64];
    int n = snprintf(b, sizeof(b), "pid=%ld\n", pid);
    (void)! write(fd, b, n);
    close(fd);
}

static int failures;

static void
check(int cond, const char *name)
{
    printf("  %-45s %s\n", name, cond ? "PASS" : "FAIL");
    if (!cond) failures++;
}

int
main(void)
{
    char dir[] = "/tmp/clkrcl.XXXXXX";
    if (mkdtemp(dir) == NULL) { perror("mkdtemp"); return 2; }

    ngx_stream_xrootd_srv_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    conf.cache_lock_timeout = 2;                 /* keep the RED timeout short */

    xrootd_cache_fill_t t;

    /* ---- Test 1: dead-owner lock must be reclaimed ---- */
    memset(&t, 0, sizeof(t));
    t.conf = &conf;
    snprintf(t.cache_path, sizeof(t.cache_path), "%s/obj", dir);
    snprintf(t.lock_path,  sizeof(t.lock_path),  "%s/obj.lock", dir);
    write_lock(t.lock_path, (long) dead_pid());

    int owned = 0;
    time_t s = time(NULL);
    int rc = xrootd_cache_wait_or_lock(&t, &owned);
    time_t took = time(NULL) - s;

    check(rc == 0 && owned == 1,
          "dead-owner lock reclaimed (owned=1)");
    check(took < conf.cache_lock_timeout,
          "reclaim was immediate (did not poll to timeout)");
    unlink(t.lock_path);

    /* ---- Test 2: live-owner lock must be honoured (no over-reclaim) ---- */
    memset(&t, 0, sizeof(t));
    t.conf = &conf;
    snprintf(t.cache_path, sizeof(t.cache_path), "%s/obj2", dir);
    snprintf(t.lock_path,  sizeof(t.lock_path),  "%s/obj2.lock", dir);
    write_lock(t.lock_path, (long) getpid());     /* this process is alive */

    owned = 0;
    rc = xrootd_cache_wait_or_lock(&t, &owned);
    check(rc == -1 && owned == 0,
          "live-owner lock honoured (timed out, not reclaimed)");
    unlink(t.lock_path);

    /* ---- Test 3: no lock present -> acquire immediately ---- */
    memset(&t, 0, sizeof(t));
    t.conf = &conf;
    snprintf(t.cache_path, sizeof(t.cache_path), "%s/obj3", dir);
    snprintf(t.lock_path,  sizeof(t.lock_path),  "%s/obj3.lock", dir);
    owned = 0;
    rc = xrootd_cache_wait_or_lock(&t, &owned);
    check(rc == 0 && owned == 1, "free path acquired immediately (owned=1)");
    unlink(t.lock_path);

    rmdir(dir);
    if (failures) {
        printf("\n%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall cache-lock reclaim checks passed\n");
    return 0;
}
