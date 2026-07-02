#include "cache_internal.h"


#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


/* xrootd_cache_lock_is_stale — is the lock file at `lock_path` orphaned?
 *
 * WHY: the fill lock is an O_EXCL lock FILE, not an fcntl/flock the kernel
 * releases on death. A worker SIGKILLed/crashed mid-fill (e.g. at reload's
 * worker_shutdown_timeout) leaves it behind, and nothing else reclaims it
 * (cache_reap skips *.lock; the eviction-sentinel reclaim is a different lock).
 * The orphan survives reboots on disk, so without this check every later
 * request for the entry polls to cache_lock_timeout and fails kXR_FileLocked
 * forever, pinning a thread-pool thread for the whole timeout each time.
 *
 * HOW: the lock file records "pid=N". If that process is gone (kill(N,0)==ESRCH)
 * the lock is definitively stale — after a reboot every pre-reboot pid is dead,
 * so the very first request reclaims it. A live owner (kill==0) is a legitimate
 * in-progress fill and is never reclaimed, however long it runs. Torn/legacy
 * content with no parseable pid falls back to age: older than the fill timeout
 * cannot belong to any still-waiting owner, so it is stale. EPERM (pid owned by
 * another user) is treated as alive — conservative, never over-reclaims.
 */
static int
xrootd_cache_lock_is_stale(const char *lock_path, time_t timeout)
{
    int          fd;
    ssize_t      n;
    char         buf[64];
    long         pid = 0;
    struct stat  st;

    fd = open(lock_path, O_RDONLY | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) {
        return 0;                       /* vanished/unreadable — let caller retry */
    }
    n = read(fd, buf, sizeof(buf) - 1);
    if (fstat(fd, &st) != 0) {
        close(fd);
        return 0;
    }
    close(fd);

    if (n > 0) {
        buf[n] = '\0';
        if (sscanf(buf, "pid=%ld", &pid) == 1 && pid > 0) {
            if (kill((pid_t) pid, 0) == 0) {
                return 0;               /* owner alive — legitimate fill */
            }
            return (errno == ESRCH);    /* dead → stale; EPERM → assume alive */
        }
    }

    /* No parseable owner (torn write / legacy lock): reclaim only once it is
     * older than a full fill timeout, which no waiting owner can still hold. */
    return (time(NULL) - st.st_mtime) > timeout;
}

/* xrootd_cache_try_lock — attempt exclusive lock on cache fill path
 * WHAT: Creates a lock file (O_CREAT|O_EXCL) at t->lock_path to claim ownership of cache fill. Writes PID into the file for identification. Returns 1 if locked, 0 if another process holds it (EEXIST), -1 on any other error (including write failure or unlink cleanup). This is an atomic filesystem lock — no fcntl(2). */

/* WHY: Atomic filesystem locking via O_CREAT|O_EXCL avoids the complexity of
 * fcntl(2) advisory locks which require fd ownership and don't work across process
 * boundaries. A lock file created with O_EXCL guarantees mutual exclusion at the
 * kernel level — only one process can succeed in creating the file simultaneously.
 * This approach is simpler, portable, and works correctly even when nginx workers
 * are running under different UID/GID combinations (e.g., during privilege drops). */

/* HOW: Three-step atomic acquisition. Step 1: open() with O_CREAT|O_EXCL — if another
 * process already created the lock file, EEXIST is returned (another worker filling
 * this cache entry). Step 2: write PID into lock file via snprintf+write — identifies
 * the locking process for debugging. If write fails, close(fd) and unlink(lock_path)
 * to clean up orphaned lock. Step 3: close(fd) without unlinking — the lock persists
 * until the cache fill completes and cleanup removes it. Returns 1 (success), 0
 * (EEXIST = someone else owns this), or -1 (any other error). */

static int
xrootd_cache_try_lock(xrootd_cache_fill_t *t)
{
    int  fd, n;
    char body[64];

    fd = open(t->lock_path, O_CREAT | O_EXCL | O_WRONLY | O_NOCTTY | O_CLOEXEC, 0600);
    if (fd < 0) {
        return (errno == EEXIST) ? 0 : -1;
    }

    n = snprintf(body, sizeof(body), "pid=%ld\n", (long) getpid());
    if (n > 0) {
        ssize_t wr;

        wr = write(fd, body, (size_t) n);
        if (wr < 0) {
            int err;

            err = errno;
            close(fd);
            unlink(t->lock_path);
            errno = err;
            return -1;
        }
    }
    close(fd);

    return 1;
}

/* xrootd_cache_wait_or_lock — poll until cache file exists or claim fill ownership
 * WHAT: Two-phase polling loop that either waits for the cache file to appear (another process already filling it) or claims ownership via lock. Phase 1: checks file_ready() — if file exists, returns 0 without locking. Phase 2: tries atomic lock — if locked, sets *owned=1 and fills. Polls at XROOTD_CACHE_LOCK_POLL_USEC intervals until cache_lock_timeout expires (returns kXR_FileLocked). */

/* WHY: Two-phase polling prevents race conditions between concurrent workers attempting
 * to fill the same cache entry simultaneously. Without this loop, two workers might both
 * try to open() the origin file and perform duplicate fills — wasting bandwidth and
 * creating inconsistent cache state. The timeout ensures we don't hang indefinitely if
 * a stale lock exists from a crashed process (the lock file cleanup in try_lock handles
 * write failures, but orphaned locks can persist after SIGKILL). */

/* HOW: Infinite loop with three checks per iteration. Check 1: file_ready() — the cache
 * file already appeared (another worker completed fill first), return immediately without
 * locking. Check 2: try_lock() — attempt O_CREAT|O_EXCL atomic lock; if success (*owned=1,
 * caller will perform the origin fetch). Check 3: timeout comparison — time(NULL) - start >=
 * conf->cache_lock_timeout (returns kXR_FileLocked with error message). Between checks:
 * usleep(XROOTD_CACHE_LOCK_POLL_USEC) provides backoff to reduce contention. Every failure
 * path sets cache error via xrootd_cache_set_syserror() or xrootd_cache_set_error(). */

int
xrootd_cache_wait_or_lock(xrootd_cache_fill_t *t, int *owned)
{
    time_t start;

    *owned = 0;
    start = time(NULL);

    for (;;) {
        int ready;

        ready = xrootd_cache_file_ready(t->cache_path);
        if (ready == 1) {
            return 0;
        }
        if (ready < 0) {
            xrootd_cache_set_syserror(t, kXR_IOError,
                                      "cache path is not usable");
            return -1;
        }

        ready = xrootd_cache_try_lock(t);
        if (ready == 1) {
            *owned = 1;
            return 0;
        }
        if (ready < 0) {
            xrootd_cache_set_syserror(t, kXR_IOError,
                                      "cache lock create failed");
            return -1;
        }

        /* EEXIST: another worker claims the fill. If that owner is dead, its
         * O_EXCL lock is orphaned and would strand this entry forever — reclaim
         * it and retry immediately. A benign reclaim race at worst causes one
         * duplicate origin fetch, which is safe: fills write a verified .part
         * and atomically rename it into place (fetch.c). */
        if (xrootd_cache_lock_is_stale(t->lock_path,
                                       t->conf->cache_lock_timeout))
        {
            if (unlink(t->lock_path) == 0 && t->c != NULL) {
                ngx_log_error(NGX_LOG_WARN, t->c->log, 0,
                    "xrootd: reclaimed stale cache-fill lock \"%s\" "
                    "(owner process gone)", t->lock_path);
            }
            continue;                   /* retry try_lock without sleeping */
        }

        if (time(NULL) - start >= t->conf->cache_lock_timeout) {
            xrootd_cache_set_error(t, kXR_FileLocked, 0,
                                   "timed out waiting for cache fill lock");
            return -1;
        }

        usleep(XROOTD_CACHE_LOCK_POLL_USEC);
    }
}

