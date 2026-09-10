/*
 * stage_events.c — 2.0 F2: the StageEvents notification file
 * (brix_frm_stagemsg), BriX's counterpart of xrootd's oss.stagemsg /
 * XRDOFSEVENTS hand-off to an external stager or tape monitor.
 *
 * WHAT: One append-only text line per stage transition — the durable engine
 *       (queued / started / done / failed / deadletter / replayed / dropped),
 *       the kXR_prepare registry (queued / staging / online / failed /
 *       cancelled / deleted / expired) and the MSS adapter (recall-begin /
 *       recall-online / recall-failed / migrate-done / migrate-failed) — so a
 *       site hook can tail ONE file instead of parsing error.log or the
 *       journal directory. Line grammar (space separated, LF terminated):
 *
 *         <utc-iso8601> <source> <event> <reqid|-> <key|-> [name=value ...]
 *
 *       The key and every value are %-escaped with ngx_escape_uri (space,
 *       '%', '#', '?', '"', controls, non-ASCII), so a line always splits on
 *       spaces and a name=value pair on its first '='.
 *
 * WHY:  Stock xrootd sites drive tape bookkeeping from the stager's event
 *       stream. The in-band kXR_wait / HTTP 202 park informs the CLIENT and
 *       the transfer ledger books BYTES; neither is a per-request transition
 *       feed an operator can hook without reading engine internals.
 *
 * HOW:  brix_stage_engine_conf_apply() opens the file once per worker
 *       (O_APPEND|O_CLOEXEC, created 0600). Every emit is ONE write(2) of a
 *       whole line, so lines from several workers interleave but never tear.
 *       The feed is best-effort by design: a failed open or write is logged
 *       once per worker, the feed goes quiet, and the next emit re-opens
 *       lazily — an operator who repairs the directory needs no reload, and a
 *       broken feed never fails a stage. No credential reaches the file:
 *       callers pass keys, principals and numbers, never a brix_stage_cred_t.
 */

#include "stage_events.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define STAGE_EVENTS_LINE_MAX  8192

/* Per-worker feed state (file-scope, like the engine's stage_journal_dir). */
static struct {
    char        path[1024];
    int         fd;
    unsigned    reported;        /* the one-per-outage ERR line was logged */
    ngx_log_t  *log;
} stage_events = { "", -1, 0, NULL };


static void
stage_events_fail(const char *what)
{
    if (stage_events.reported || stage_events.log == NULL) {
        return;
    }
    stage_events.reported = 1;
    ngx_log_error(NGX_LOG_ERR, stage_events.log, errno,
        "brix: brix_frm_stagemsg \"%s\": %s failed; stage notifications are "
        "off in this worker until the file is writable again (staging "
        "itself is unaffected)", stage_events.path, what);
}

/* 1 = an fd is ready, 0 = the feed is off or its file is still unopenable. */
static int
stage_events_reopen(void)
{
    if (stage_events.fd >= 0) {
        return 1;
    }
    if (stage_events.path[0] == '\0') {
        return 0;
    }
    stage_events.fd = open(stage_events.path,
                           O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (stage_events.fd < 0) {
        stage_events_fail("open");
        return 0;
    }
    return 1;
}

ngx_int_t
brix_stage_events_open(const char *path, ngx_log_t *log)
{
    brix_stage_events_close();
    stage_events.log      = log;
    stage_events.reported = 0;
    if (path == NULL || path[0] == '\0') {
        return NGX_OK;
    }
    if (strlen(path) >= sizeof(stage_events.path)) {
        errno = ENAMETOOLONG;
        (void) snprintf(stage_events.path, sizeof(stage_events.path), "%s",
                        path);
        stage_events_fail("open");
        stage_events.path[0] = '\0';
        return NGX_ERROR;
    }
    (void) snprintf(stage_events.path, sizeof(stage_events.path), "%s", path);
    return stage_events_reopen() ? NGX_OK : NGX_ERROR;
}

void
brix_stage_events_close(void)
{
    if (stage_events.fd >= 0) {
        (void) close(stage_events.fd);
    }
    stage_events.fd      = -1;
    stage_events.path[0] = '\0';
}

int
brix_stage_events_enabled(void)
{
    return stage_events.path[0] != '\0';
}

/* Append `src` %-escaped ("-" when empty). Returns the new length, or 0 when
 * the field would not fit — the caller then drops the rest of the line. */
static size_t
stage_events_put(u_char *line, size_t len, const char *src)
{
    size_t  n, esc;

    if (src == NULL || src[0] == '\0') {
        src = "-";
    }
    n   = strlen(src);
    esc = ngx_escape_uri(NULL, (u_char *) src, n, NGX_ESCAPE_URI);
    if (len + n + 2 * esc + 2 > STAGE_EVENTS_LINE_MAX) {  /* + ' ' + '\n' */
        return 0;
    }
    (void) ngx_escape_uri(line + len, (u_char *) src, n, NGX_ESCAPE_URI);
    return len + n + 2 * esc;
}

static size_t
stage_events_put_pair(u_char *line, size_t len, const char *name,
    const char *value)
{
    size_t  n = strlen(name);

    if (len + n + 3 > STAGE_EVENTS_LINE_MAX) {
        return 0;
    }
    line[len++] = ' ';
    memcpy(line + len, name, n);
    len += n;
    line[len++] = '=';
    return stage_events_put(line, len, value);
}

void
brix_stage_events_emit(const char *source, const char *event,
    const char *reqid, const char *key, ...)
{
    u_char      line[STAGE_EVENTS_LINE_MAX];
    size_t      len, next;
    time_t      now;
    ngx_tm_t    tm;
    va_list     ap;
    const char *name, *value;

    if (!brix_stage_events_enabled() || !stage_events_reopen()) {
        return;
    }
    now = time(NULL);
    ngx_gmtime(now, &tm);
    len = (size_t) snprintf((char *) line, sizeof(line),
                            "%04d-%02d-%02dT%02d:%02d:%02dZ %s %s ",
                            tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday,
                            tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec,
                            source, event);
    len = stage_events_put(line, len, reqid);
    if (len == 0) {
        return;
    }
    line[len++] = ' ';
    len = stage_events_put(line, len, key);
    if (len == 0) {
        return;
    }

    va_start(ap, key);
    for (name = va_arg(ap, const char *); name != NULL;
         name = va_arg(ap, const char *))
    {
        value = va_arg(ap, const char *);
        next  = stage_events_put_pair(line, len, name, value);
        if (next == 0) {
            break;                       /* keep what fits; the line stays whole */
        }
        len = next;
    }
    va_end(ap);

    line[len++] = '\n';
    if (write(stage_events.fd, line, len) == (ssize_t) len) {
        stage_events.reported = 0;       /* a later outage is news again */
        return;
    }
    stage_events_fail("write");
    (void) close(stage_events.fd);
    stage_events.fd = -1;
}
