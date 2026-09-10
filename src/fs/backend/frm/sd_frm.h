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
 * vtable; the tape:// store-URL selects it (stub | exec/hpss/cta stagecmd |
 * lib/libhpss/libcta dlopen). All calls are blocking and run on the cache-fill /
 * scheduler path (off the event loop).
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
    /* Migrate `key` from the online buffer to tape (after a staged write).
     * 0 shipped / -1 error (errno) / BRIX_MSS_MIGRATE_DEFERRED = the object
     * is a dataset completion marker under the archiver (2.0 F3): nothing
     * moved yet, the driver must drive seal(key) -- through the durable
     * stage engine when it has one -- to compose and ship the archive. */
    int  (*migrate)(void *mss, const char *key);
    /* 2.0 F3: seal the dataset whose completion marker is `key` (compose
     * every online member into the archive object, ship it, write the
     * index sidecar, migrate the marker). 0 ok -- also when the dataset
     * is already sealed, so a journal replay is idempotent -- / -1 error:
     * EINVAL not a marker, ENOENT the marker's online copy is gone, else
     * the tape tier's errno (transient, retried by the engine). Only the
     * archiver decorator implements it; a NULL slot => ENOTSUP. */
    int  (*seal)(void *mss, const char *key);
    /* Drop the online copy of `key` (free buffer space). */
    int  (*purge)(void *mss, const char *key);
    /* Phase-115 W3.2: does the MSS hold a DURABLE copy of `key`, regardless of
     * the online buffer? 1 yes / 0 no / -1 cannot tell (errno set). The purge
     * engine releases an online copy only on 1; a NULL slot means the adapter
     * cannot answer and the engine falls back to the staged-write invariant
     * (ONLINE ⇒ migrated) documented on sd_frm_evict. */
    int  (*on_tape)(void *mss, const char *key);
    /* Atomic two-name exchange of the ONLINE-BUFFER copies (phase-107 C6):
     * renameat2(RENAME_EXCHANGE) on <base>/.online/<a|b>. Both names must be
     * online (ENOENT otherwise — recall first); the driver migrates both keys
     * afterwards so tape truth catches up. A NULL slot means this MSS cannot
     * swap — the driver reports ENOTSUP, never a two-rename emulation. */
    int  (*exchange)(void *mss, const char *a, const char *b);
    /* §3.7 MSS namespace enumeration (the stock `rsscmd dread` analog): call
     * cb(ud, name, is_dir) for each entry of MSS directory `key` until done
     * (a nonzero cb return stops early). 0 ok / -1 error (errno set). A NULL
     * slot means this MSS cannot enumerate — the driver reports ENOTSUP,
     * exactly the pre-slot behaviour. */
    int  (*list)(void *mss, const char *key,
                 int (*cb)(void *ud, const char *name, int is_dir), void *ud);
    /* §3.7 MSS-side directory creation (the stock `rsscmd rcreate` analog):
     * create directory `key` (and its parents) on the MSS. 0 ok / -1 error
     * (errno set). NULL slot ⇒ the MSS namespace cannot be extended — the
     * driver reports ENOTSUP, the pre-slot behaviour. */
    int  (*mkpath)(void *mss, const char *key, mode_t mode);
    /* Open the online-buffer file of an ONLINE `key` for reading; fd or -1. */
    int  (*open_online)(void *mss, const char *key);
    /* Create+open the online-buffer file of `key` for a staged write; fd or -1. */
    int  (*create_online)(void *mss, const char *key, mode_t mode);
    /* Phase-107 C3: make the LOCAL directory entry of `key`'s just-published
     * artifact durable (fsync its parent directory). 0 ok / -1 error (errno
     * set). NULL slot ⇒ the adapter keeps nothing local worth flushing. */
    int  (*sync_publish)(void *mss, const char *key);
    void (*destroy)(void *mss);
} brix_mss_adapter_t;

/* migrate() answer: the publish is deferred to seal() (2.0 F3). */
#define BRIX_MSS_MIGRATE_DEFERRED  1

/* Build a nearline backend instance. `adapter` selects the MSS adapter by name
 * (NULL/"" or "stub" => the built-in local-directory stub); `location` is the
 * adapter's MSS base (for the stub, the local tape directory). Returns a
 * malloc-owned instance, or NULL (errno set). Destroy with brix_sd_frm_destroy. */
brix_sd_instance_t *brix_sd_frm_create(const char *adapter,
    const char *location, ngx_log_t *log);

/* Store-URL query options — "tape://<adapter>/<base>?arc=<depth>" (phase-115
 * W3.1). arc_depth 0 = per-file tape objects (the default); 1..8 = the dataset
 * archiver (sd_frm_arc.h) wraps the selected adapter and seals every dataset
 * (= the first `arc_depth` path components) into one archive object. */
typedef struct {
    unsigned arc_depth;
} brix_sd_frm_opts_t;

/* Parse the query string `q` (after the '?'; "" or NULL = defaults) into
 * *opts. 0 ok / -1 with errno EINVAL: unknown key, or arc outside 1..8. Pure
 * grammar — the config parsers call it so `nginx -t` rejects a bad query. */
int brix_sd_frm_parse_query(const char *q, brix_sd_frm_opts_t *opts);

/* brix_sd_frm_create with options (NULL opts = defaults). */
brix_sd_instance_t *brix_sd_frm_create_opts(const char *adapter,
    const char *location, const brix_sd_frm_opts_t *opts, ngx_log_t *log);

/* Free an instance built by brix_sd_frm_create. NULL-safe. */
void brix_sd_frm_destroy(brix_sd_instance_t *inst);

/* Is `inst` an frm-driver instance? NULL-safe. */
int brix_sd_frm_instance_is(const brix_sd_instance_t *inst);

/* 2.0 F3: the export root this tape tier serves. A deferred archive seal
 * queued through the stage engine carries it so a restart reconcile can
 * rebuild the export's composed stack and find the tier again. Set once by
 * the backend registry right after create; "" = unanchored (a seal
 * queued from such a tier is dropped on replay, never re-driven blind). */
void brix_sd_frm_set_export_root(brix_sd_instance_t *inst, const char *root);

/* 2.0 F3: drive the adapter's seal(key) for the dataset completion marker
 * `key` and feed `frm seal-done` / `frm seal-failed errno=` to the
 * StageEvents file. NGX_OK / NGX_ERROR with the adapter's errno (ENOTSUP:
 * this tier has no archiver, EINVAL: not a marker, ENOENT: marker gone).
 * Called by the stage engine for kind archive, on its mover thread. */
ngx_int_t brix_sd_frm_seal(brix_sd_instance_t *inst, const char *key);

/* 2.0 F1: the exec MSS adapter's configured program and per-invocation
 * deadline (brix_frm_stagecmd / brix_frm_copy_timeout). Set by the config
 * merge in the master (NULL/0 = fall back to the BRIX_FRM_*STAGECMD
 * environment contract, no deadline); applies to every exec-family adapter
 * built afterwards. */
void brix_sd_frm_set_exec_defaults(const char *stagecmd,
    ngx_msec_t copy_timeout_ms);

/*
 * Phase-115 W3.2 — the tape-buffer purge engine (sd_frm_purge.c).
 *
 * The online buffer behind a tape:// tier fills with recalled and freshly
 * migrated copies; nothing above the seam knows which of them are safe to
 * drop. brix_sd_frm_purge() releases LRU online copies until BOTH arms are
 * satisfied: the filesystem occupancy of the buffer's mount is back under
 * `lo_ppm` (arm 1, armed when the tick observed occupancy > `hi_ppm`) and
 * the bytes the buffer OWNS are back under `max_bytes` (arm 2, armed when
 * `max_bytes` > 0). A copy is released only when the adapter's on_tape probe
 * confirms a durable copy (or the adapter cannot answer and the staged-write
 * invariant ONLINE => migrated holds), it is older than `min_age_s`, and the
 * `is_pinned` callback does not claim it (a live stage request). Symlinks are
 * never followed, nothing outside the online root is ever touched.
 *
 * 2.0 F4 — per-group rules (brix_frm_purge_policy) and the policy program
 * (brix_frm_purge_polprog, sd_frm_purge_policy.c): `rule_of` maps a key to
 * one of `rules`; each rule is an owned-bytes arm of its own (hi/lo) with
 * an optional longer hold, and a `polprog` rule releases only the copies
 * the program approved this pass. The export-wide arms above still reach
 * into every group.
 */
typedef struct {
    const char  *name;          /* the brix_oss_space group, or "*"         */
    uint64_t     hi_bytes;      /* the group's own arm: trigger             */
    uint64_t     lo_bytes;      /*   ... and target                          */
    time_t       hold_s;        /* keep copies touched more recently         */
    int          polprog;       /* releases need the program's approval      */
} brix_sd_frm_purge_rule_t;

typedef struct {
    ngx_uint_t   hi_ppm;        /* arm 1 trigger; 0 or >= 1000000 disables it  */
    ngx_uint_t   lo_ppm;        /* arm 1 target                                */
    off_t        max_bytes;     /* arm 2 (owned-bytes cap); <= 0 disables it   */
    time_t       min_age_s;     /* never release a copy touched more recently  */
    uint64_t     fs_total;      /* statvfs of the online root's mount (arm 1)  */
    uint64_t     fs_used;
    int        (*is_pinned)(void *ud, const char *key);  /* may be NULL */
    void        *ud;
    /* 2.0 F4: NULL/0 = no per-group rules; rule_of answers an index into
     * rules or -1; polprog NULL = no program; the deadline bounds one run. */
    const brix_sd_frm_purge_rule_t *rules;
    size_t       nrules;
    int        (*rule_of)(void *ud, const char *key);
    const char  *polprog;
    ngx_msec_t   polprog_timeout_ms;
} brix_sd_frm_purge_policy_t;

typedef struct {
    ngx_uint_t   evicted;       /* online copies released                      */
    ngx_uint_t   young;         /* skipped: touched within min_age_s           */
    ngx_uint_t   pinned;        /* skipped: is_pinned() claimed the key        */
    ngx_uint_t   unmigrated;    /* skipped: on_tape != 1 (no durable copy)     */
    ngx_uint_t   symlinks;      /* seen and refused (never followed)           */
    ngx_uint_t   failed;        /* adapter purge returned nonzero              */
    uint64_t     bytes;         /* bytes released                              */
    uint64_t     owned_before;  /* regular-file bytes under the online root    */
    uint64_t     owned_after;
    ngx_uint_t   held;          /* 2.0 F4: skipped, inside the rule's hold     */
    ngx_uint_t   unapproved;    /* 2.0 F4: skipped, the program did not pick it*/
} brix_sd_frm_purge_report_t;

/* "<location>/.online" for a frm instance into buf; NGX_ERROR when `inst` is
 * not an frm-driver instance or the path does not fit. */
ngx_int_t brix_sd_frm_online_root(const brix_sd_instance_t *inst, char *buf,
    size_t cap);

/* One purge pass. NGX_OK = pass ran (see *rep, possibly nothing to do),
 * NGX_DECLINED = another pass holds the online root's purge lock,
 * NGX_ERROR = the online root is unusable (errno set, logged). */
ngx_int_t brix_sd_frm_purge(brix_sd_instance_t *inst,
    const brix_sd_frm_purge_policy_t *pol, brix_sd_frm_purge_report_t *rep,
    ngx_log_t *log);

#endif /* BRIX_SD_FRM_H */
