/*
 * brix_fault_proxy_event.c — optional JSONL fault-event log (D2).
 *
 * WHAT: when `--event-log FILE` (or the live `event-log <path>` verb) is set,
 *       append one JSON object per discrete fault event — sever (with a reason),
 *       truncate cut, batched per-read corruption, duplicate delivery, and
 *       connection refusal — so a run leaves a machine-readable audit trail.
 *
 * WHY:  the human `status` line and Prometheus `metrics` are point-in-time
 *       aggregates; they cannot tell you *which* connection was cut *when* or
 *       *why*.  A JSONL stream gives per-event provenance for offline analysis
 *       without turning the proxy into a payload capture (an explicit non-goal:
 *       NO relayed bytes are ever written to the log).
 *
 * HOW:  a single append-only fd guarded by one mutex (events are discrete and
 *       off the per-byte hot path, so a global lock is cheap and correct).  When
 *       no log is configured the fd is -1 and brix_fp_event() returns on the
 *       first branch — zero cost.  Each line is built with bounded snprintf and
 *       written under the lock so concurrent relay threads never interleave.
 */
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "brix_fault_proxy_mods.h"

static int             g_event_fd = -1;
static pthread_mutex_t g_event_mu = PTHREAD_MUTEX_INITIALIZER;

/* Per-thread "route" tag.  A route accept thread names its route once; every
 * other thread leaves it empty and events read "default". */
static __thread char   t_event_route[64] = "";

/* Set (or clear, with NULL/"") the route tag for events emitted on this thread. */
void
fp_event_set_route(const char *name)
{
    if (name == NULL || name[0] == '\0') {
        t_event_route[0] = '\0';
        return;
    }
    size_t i = 0;
    while (name[i] != '\0' && i + 1 < sizeof t_event_route) {
        t_event_route[i] = name[i];
        i++;
    }
    t_event_route[i] = '\0';
}

/* Open (or replace) the event-log sink.  Returns 0 on success, -1 if the path
 * cannot be opened for append — the caller fails closed (startup exit / err:). */
int
fp_event_open(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&g_event_mu);
    if (g_event_fd >= 0) {
        close(g_event_fd);
    }
    g_event_fd = fd;
    pthread_mutex_unlock(&g_event_mu);
    return 0;
}

/* 1 when a log is configured — lets hot callers skip building event strings. */
int
fp_event_enabled(void)
{
    return g_event_fd >= 0;
}

/* Append one formatted field to the event line, advancing `*n`.  Returns 0 on
 * success and -1 once the line is full — an event that would not fit whole is
 * dropped rather than written truncated (a half-object is not valid JSONL). */
static int __attribute__((format(printf, 4, 5)))
ev_append(char *line, size_t cap, int *n, const char *fmt, ...)
{
    if (*n < 0 || (size_t) *n >= cap) {
        return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(line + *n, cap - (size_t) *n, fmt, ap);
    va_end(ap);
    if (m < 0 || (size_t) (*n + m) >= cap) {
        return -1;
    }
    *n += m;
    return 0;
}

/* Append one JSONL event.  `dir`/`reason`/`numkey` are optional (NULL omits the
 * field); `numval` is emitted only when `numkey` is non-NULL.  No payload bytes
 * are ever included — only structural metadata. */
void
brix_fp_event(unsigned long conn, const char *dir, const char *event,
              const char *reason, const char *numkey, long numval)
{
    if (g_event_fd < 0) {
        return;                     /* zero-cost when --event-log is unset */
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    double t = (double) tv.tv_sec + (double) tv.tv_usec / 1e6;

    const char *route = t_event_route[0] != '\0' ? t_event_route : "default";
    char line[320];
    int  n = 0;

    if (ev_append(line, sizeof line, &n, "{\"t\":%.2f,\"route\":\"%s\",\"conn\":%lu",
                  t, route, conn) != 0) {
        return;
    }
    if (dir != NULL &&
        ev_append(line, sizeof line, &n, ",\"dir\":\"%s\"", dir) != 0) {
        return;
    }
    if (ev_append(line, sizeof line, &n, ",\"event\":\"%s\"", event) != 0) {
        return;
    }
    if (reason != NULL &&
        ev_append(line, sizeof line, &n, ",\"reason\":\"%s\"", reason) != 0) {
        return;
    }
    if (numkey != NULL &&
        ev_append(line, sizeof line, &n, ",\"%s\":%ld", numkey, numval) != 0) {
        return;
    }
    if (n >= (int) sizeof line - 2) {
        return;                     /* no room for the closing "}\n" */
    }
    line[n++] = '}';
    line[n++] = '\n';

    pthread_mutex_lock(&g_event_mu);
    ssize_t wr = write(g_event_fd, line, (size_t) n);
    (void) wr;   /* best-effort: a full log must not disrupt the relay */
    pthread_mutex_unlock(&g_event_mu);
}
