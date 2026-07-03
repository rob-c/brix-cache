#ifndef BRIX_SD_FRM_H
#define BRIX_SD_FRM_H

/*
 * sd_frm.h - the nearline (tape/MSS) backend FS driver (phase-64 SP5, P4/P6).
 *
 * WHAT: A capability-typed SD driver whose objects are NEARLINE: an object is
 *       either ONLINE (present in the MSS disk buffer, directly readable) or
 *       OFFLINE (on tape, minutes-to-hours away). It advertises CAP_NEARLINE and
 *       implements the `recall` slot; the composing registry therefore REQUIRES a
 *       cache tier in front of it (G8, the recall target). A read of an offline
 *       object is a RECALL into the online buffer - exactly the cache miss-fill,
 *       but sourced from tape.
 *
 * WHY:  P6 makes tape "just another backend tier": instead of a parallel FRM
 *       subsystem that drivers call, tape residency becomes an SD driver behind
 *       the same seam (stat/open/pread/recall/staged_*). A node composes
 *       cache(frm-backend) and serves tape transparently - no special FRM code
 *       path above the seam. (This SP5 increment lands the driver + an in-tree
 *       stub MSS adapter and a SYNCHRONOUS recall; the async park/wake of a slow
 *       recall via the stage_engine waiter, and the dissolution of the legacy
 *       src/frm/ subsystem, are the remaining P6 migration.)
 *
 * HOW:  Tape access is abstracted behind a pluggable MSS adapter
 *       (brix_mss_adapter_t): residency (online/offline/absent), recall
 *       begin/poll (tape -> online buffer), and migrate (online -> tape). The
 *       `tape://` store-URL selects the adapter; "stub" is the built-in
 *       local-directory simulation used for tests. recall ensures the object is
 *       online (driving the adapter), then sd_cache fills from the online buffer
 *       through this driver's open/pread; staged_* writes the online buffer then
 *       migrates to tape. See docs/refactor/phase-64-fully-tiered-composable-
 *       storage.md (section 9, 13b, 26, Appendix I).
 */

#include "fs/backend/sd.h"

/* Residency of an object on the MSS (Appendix I). */
#define BRIX_RESIDENCY_ONLINE    0   /* in the MSS disk buffer, readable now    */
#define BRIX_RESIDENCY_NEARLINE  1   /* recallable (a stage is in flight/queued) */
#define BRIX_RESIDENCY_OFFLINE   2   /* on tape; a recall will fault it in       */
#define BRIX_RESIDENCY_ABSENT   (-1) /* unknown to the MSS                       */

/*
 * The pluggable MSS adapter - how the frm driver talks to the tape system. One
 * vtable; the tape:// store-URL selects it (exec | hpss | cta | stub). All calls
 * are blocking and run on the cache-fill / scheduler path (off the event loop).
 */
typedef struct {
    const char *name;                                   /* "stub" | "exec" | ... */
    /* Is `key` online, nearline, or offline/absent? Fills size/mtime when known. */
    int  (*residency)(void *mss, const char *key, off_t *size_out,
                      time_t *mtime_out);
    /* Begin a recall of `key` into the MSS online buffer; 0 started / -1 error. */
    int  (*recall_begin)(void *mss, const char *key);
    /* Poll a recall: 1 online (ready), 0 in-flight, -1 error. */
    int  (*recall_poll)(void *mss, const char *key);
    /* Migrate `key` from the online buffer to tape (after a staged write). */
    int  (*migrate)(void *mss, const char *key);
    /* Drop the online copy of `key` (free buffer space). */
    int  (*purge)(void *mss, const char *key);
    /* Open the online-buffer file of an ONLINE `key` for reading; fd or -1. */
    int  (*open_online)(void *mss, const char *key);
    /* Create+open the online-buffer file of `key` for a staged write; fd or -1. */
    int  (*create_online)(void *mss, const char *key, mode_t mode);
    void (*destroy)(void *mss);
} brix_mss_adapter_t;

/* Build a nearline backend instance. `adapter` selects the MSS adapter by name
 * (NULL/"" or "stub" => the built-in local-directory stub); `location` is the
 * adapter's MSS base (for the stub, the local tape directory). Returns a
 * malloc-owned instance, or NULL (errno set). Destroy with brix_sd_frm_destroy. */
brix_sd_instance_t *brix_sd_frm_create(const char *adapter,
    const char *location, ngx_log_t *log);

/* Free an instance built by brix_sd_frm_create. NULL-safe. */
void brix_sd_frm_destroy(brix_sd_instance_t *inst);

#endif /* BRIX_SD_FRM_H */
