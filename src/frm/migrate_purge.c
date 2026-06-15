/*
 * migrate_purge.c — Category-2 migrate/purge scaffolding (Phase 35 / Phase 4 F6).
 *
 * WHAT: A worker-0 timer that evaluates the configured disk watermarks
 *   (xrootd_frm_purge_watermark high low → purge_hi_ppm/purge_lo_ppm) against the
 *   live occupancy of the export and LOGS the decision, plus a migrate hook that
 *   records intent. It bumps the xrootd_frm_migrate_total / xrootd_frm_purge_total
 *   scaffolding counters.
 *
 * WHY: Category-2 (disk→tape copy-out and watermark-driven purge) is an EXPLICIT
 *   non-goal of B2 — the real policy belongs to the MSS backend (CTA / dCache /
 *   HPSS). nginx-xrootd ships only the directives, the metrics, and this stub so a
 *   deployment can wire its own engine and observe the hooks; the purge engine
 *   itself deliberately does NOT delete anything.
 *
 * HOW: Mirrors reaper.c — a single worker-0 ngx_event timer rearmed every
 *   purge_interval_ms, gated on purge_hi_ppm > 0. Occupancy is read with statvfs
 *   on the FRM queue's directory. No file is ever removed here.
 */

#include "frm_internal.h"

#include <sys/statvfs.h>
#include <string.h>


static ngx_event_t   frm_purge_ev;
static ngx_log_t    *frm_purge_log;
static ngx_uint_t    frm_purge_hi_ppm;
static ngx_uint_t    frm_purge_lo_ppm;
static ngx_msec_t    frm_purge_interval;
static char          frm_purge_dir[NGX_XROOTD_FRM_PATH_MAX];


/* Occupancy of the filesystem holding `dir`, in parts-per-million (used/total).
 * Returns -1 if statvfs fails. */
static long
frm_fs_occupancy_ppm(const char *dir)
{
    struct statvfs vfs;
    double         total, used;

    if (dir[0] == '\0' || statvfs(dir, &vfs) != 0) {
        return -1;
    }
    total = (double) vfs.f_blocks * (double) vfs.f_frsize;
    if (total <= 0) {
        return -1;
    }
    used = total - (double) vfs.f_bavail * (double) vfs.f_frsize;
    return (long) ((used / total) * 1000000.0);
}

static void
frm_purge_handler(ngx_event_t *ev)
{
    long occ = frm_fs_occupancy_ppm(frm_purge_dir);

    /*
     * SCAFFOLD ONLY: report the watermark decision; never delete. A real engine
     * would, when occ >= hi, copy-out + purge cold files down to lo. That policy
     * is delegated to the MSS backend (Category-2 is an explicit B2 non-goal).
     */
    if (occ >= 0 && (ngx_uint_t) occ >= frm_purge_hi_ppm) {
        ngx_log_error(NGX_LOG_NOTICE, frm_purge_log, 0,
                      "frm: purge watermark HIGH reached (occupancy=%l ppm >= "
                      "hi=%ui ppm, lo=%ui ppm) — engine is a stub, nothing purged",
                      occ, frm_purge_hi_ppm, frm_purge_lo_ppm);
        XROOTD_FRM_METRIC_INC(purge_total);
    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, frm_purge_log, 0,
                       "frm: purge watermark ok (occupancy=%l ppm < hi=%ui ppm)",
                       occ, frm_purge_hi_ppm);
    }

    if (!ngx_exiting) {
        ngx_add_timer(ev, frm_purge_interval);
    }
}

/*
 * Record a migrate-out intent for `lfn` (Category-2 disk→tape copy-out). SCAFFOLD:
 * when xrootd_frm_migrate_copycmd is configured a real deployment would run it via
 * the stage-agent; here we only count the intent. Safe to call from anywhere.
 */
void
frm_migrate_note(const char *lfn)
{
    (void) lfn;
    XROOTD_FRM_METRIC_INC(migrate_total);
}

/*
 * Arm the worker-0 purge-watermark timer. No-op unless purge_hi_ppm > 0 and this
 * is worker 0 (mirrors the reaper's single-worker election). Called from
 * init_process after the queue is opened.
 */
void
frm_migrate_purge_register(ngx_cycle_t *cycle, xrootd_frm_conf_t *frm)
{
    frm_queue_t *q;

    if (frm == NULL || !frm->enable || frm->purge_hi_ppm == 0) {
        return;
    }
    if (ngx_worker != 0) {
        return;                         /* worker-0 only */
    }

    frm_purge_log      = cycle->log;
    frm_purge_hi_ppm   = frm->purge_hi_ppm;
    frm_purge_lo_ppm   = frm->purge_lo_ppm;
    frm_purge_interval = frm->purge_interval_ms ? frm->purge_interval_ms
                                                : 300000;

    /* Watch the filesystem holding the queue file (a stand-in for the export
     * root; a real engine would watch the data root / cache root). */
    q = frm_singleton_queue();
    frm_purge_dir[0] = '\0';
    if (q != NULL && q->path.data != NULL) {
        char       *slash;
        size_t      n = q->path.len < sizeof(frm_purge_dir) - 1
                        ? q->path.len : sizeof(frm_purge_dir) - 1;
        ngx_memcpy(frm_purge_dir, q->path.data, n);
        frm_purge_dir[n] = '\0';
        slash = strrchr(frm_purge_dir, '/');
        if (slash != NULL && slash != frm_purge_dir) {
            *slash = '\0';
        }
    }

    ngx_memzero(&frm_purge_ev, sizeof(frm_purge_ev));
    frm_purge_ev.handler = frm_purge_handler;
    frm_purge_ev.log     = cycle->log;
    frm_purge_ev.data    = &frm_purge_ev;
    ngx_add_timer(&frm_purge_ev, frm_purge_interval);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "frm: purge-watermark monitor armed (hi=%ui lo=%ui ppm, "
                  "interval=%Mms) — SCAFFOLD, no files are purged",
                  frm_purge_hi_ppm, frm_purge_lo_ppm, frm_purge_interval);
}
