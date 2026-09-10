/* stage_events.h — 2.0 F2: the StageEvents notification feed
 * (brix_frm_stagemsg). See stage_events.c for the line grammar and the
 * best-effort contract. Internal to the stage engine, the prepare registry
 * and the frm MSS driver; nothing else emits. */

#ifndef BRIX_FS_XFER_STAGE_EVENTS_H
#define BRIX_FS_XFER_STAGE_EVENTS_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>

/* Open (create 0600, append) the feed for this worker; "" / NULL disables it.
 * A failed open is logged ONCE and retried lazily by the next emit. */
ngx_int_t brix_stage_events_open(const char *path, ngx_log_t *log);
void      brix_stage_events_close(void);
int       brix_stage_events_enabled(void);

/* Append one line: `<utc> <source> <event> <reqid|-> <key|-> [name=value ...]`.
 * The trailing arguments are (name, value) C-string pairs ended by NULL; key
 * and every value are %-escaped so the line always splits on spaces. Never
 * pass a credential. A no-op while the feed is disabled or broken. */
void brix_stage_events_emit(const char *source, const char *event,
    const char *reqid, const char *key, ...);

/* Format a number for an emit pair in a caller-owned buffer. */
static inline const char *
brix_stage_events_num(char *buf, size_t size, long long v)
{
    (void) snprintf(buf, size, "%lld", v);
    return buf;
}

#endif /* BRIX_FS_XFER_STAGE_EVENTS_H */
