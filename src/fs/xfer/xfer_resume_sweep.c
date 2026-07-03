/*
 * xfer_resume_sweep.c — TTL housekeeping for abandoned upload-resume partials.
 *
 * WHAT: A worker-0 periodic timer that removes stale resume partials
 *       (`*.xrdresume.part`, see brix_make_resume_path) from the configured
 *       upload stage dir once they are older than a TTL.
 *
 * WHY:  A client that starts a resumable upload and never returns leaves its
 *       identity-keyed `.part` behind forever; over time these abandoned partials
 *       fill the stage device. The resume design is "keep the partial so the
 *       client can resume" — this bounds that with a time limit so unclaimed
 *       partials are eventually reclaimed (the spec §7b "sweep only expired /
 *       non-resumable" rule). A still-fresh partial (age < TTL) is preserved, so
 *       an in-progress / recently-interrupted upload is never disturbed.
 *
 * HOW:  Only the configured stage dir is swept — it is a flat directory of
 *       server-named hash files, so an O(entries) readdir is cheap and safe (the
 *       adjacent-to-destination naming used when no stage dir is configured is
 *       scattered across the namespace and intentionally not swept). Worker 0
 *       only (like the FRM reaper) so deletes are not N-way contended; unlinkat()
 *       on the dir fd avoids any path-traversal surface. TTL is
 *       $BRIX_UPLOAD_RESUME_TTL seconds (default 1 day; 0 disables). No goto.
 */

#include "xfer.h"

#include <ngx_event.h>

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define XFER_RESUME_SUFFIX        ".xrdresume.part"
#define XFER_RESUME_SUFFIX_LEN    (sizeof(XFER_RESUME_SUFFIX) - 1)
#define XFER_RESUME_TTL_DEFAULT   86400        /* 1 day                          */
#define XFER_RESUME_SWEEP_DELAY   5000         /* ms after worker start: 1st pass */
#define XFER_RESUME_SWEEP_PERIOD  3600000      /* ms between passes (1 hour)      */
#define XFER_RESUME_SCAN_CAP      8192         /* bound a single pass             */

static ngx_event_t  xfer_sweep_ev;
static char         xfer_sweep_dir[PATH_MAX];
static time_t       xfer_sweep_ttl;            /* seconds; 0 = disabled          */
static ngx_log_t   *xfer_sweep_log;

/* Resolve the TTL once: $BRIX_UPLOAD_RESUME_TTL (seconds), else the default. */
static time_t
xfer_resume_ttl(void)
{
    const char *env = getenv("BRIX_UPLOAD_RESUME_TTL");
    char       *end;
    long        v;

    if (env == NULL || env[0] == '\0') {
        return XFER_RESUME_TTL_DEFAULT;
    }
    v = strtol(env, &end, 10);
    if (*end != '\0' || v < 0) {
        return XFER_RESUME_TTL_DEFAULT;
    }
    return (time_t) v;                          /* 0 → caller disables the sweep */
}

/* One sweep pass: unlink resume partials older than the TTL. */
static void
xfer_resume_sweep_run(void)
{
    DIR           *dir;
    int            dfd;
    struct dirent *ent;
    time_t         now = time(NULL);
    ngx_uint_t     scanned = 0, removed = 0;

    dir = opendir(xfer_sweep_dir);
    if (dir == NULL) {
        return;                                /* dir gone / not yet created */
    }
    dfd = dirfd(dir);

    while (scanned < XFER_RESUME_SCAN_CAP && (ent = readdir(dir)) != NULL) {
        size_t      len = ngx_strlen(ent->d_name);
        struct stat sb;

        if (len <= XFER_RESUME_SUFFIX_LEN
            || ngx_memcmp(ent->d_name + len - XFER_RESUME_SUFFIX_LEN,
                          XFER_RESUME_SUFFIX, XFER_RESUME_SUFFIX_LEN) != 0)
        {
            continue;                          /* not a resume partial */
        }
        scanned++;

        if (dfd < 0
            || fstatat(dfd, ent->d_name, &sb, AT_SYMLINK_NOFOLLOW) != 0
            || !S_ISREG(sb.st_mode))
        {
            continue;
        }
        if (now - sb.st_mtime < xfer_sweep_ttl) {
            continue;                          /* still fresh — may be resumed */
        }
        if (unlinkat(dfd, ent->d_name, 0) == 0) {
            removed++;
        }
    }
    closedir(dir);

    if (removed > 0) {
        ngx_log_error(NGX_LOG_NOTICE, xfer_sweep_log, 0,
                      "xfer: swept %ui abandoned resume partial(s) (> %T s) "
                      "from \"%s\"", removed, xfer_sweep_ttl, xfer_sweep_dir);
    }
}

static void
xfer_resume_sweep_handler(ngx_event_t *ev)
{
    xfer_resume_sweep_run();
    if (!ngx_exiting) {
        ngx_add_timer(ev, XFER_RESUME_SWEEP_PERIOD);
    }
}

void
brix_xfer_resume_sweep_register(ngx_cycle_t *cycle, const char *stage_dir)
{
    if (stage_dir == NULL || stage_dir[0] == '\0') {
        return;                                /* no stage dir → adjacent naming */
    }
    if (ngx_worker != 0) {
        return;                                /* one sweeper, like the reaper */
    }

    xfer_sweep_ttl = xfer_resume_ttl();
    if (xfer_sweep_ttl == 0) {
        return;                                /* explicitly disabled */
    }

    ngx_cpystrn((u_char *) xfer_sweep_dir, (u_char *) stage_dir,
                sizeof(xfer_sweep_dir));
    xfer_sweep_log = cycle->log;

    ngx_memzero(&xfer_sweep_ev, sizeof(xfer_sweep_ev));
    xfer_sweep_ev.handler = xfer_resume_sweep_handler;
    xfer_sweep_ev.log     = cycle->log;
    xfer_sweep_ev.data    = &xfer_sweep_ev;
    ngx_add_timer(&xfer_sweep_ev, XFER_RESUME_SWEEP_DELAY);
}
