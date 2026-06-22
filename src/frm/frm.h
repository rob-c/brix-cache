#ifndef NGX_XROOTD_FRM_H
#define NGX_XROOTD_FRM_H

/*
 * frm.h — public API for the FRM durable stage-request queue (src/frm/).
 *
 * WHAT: The durable, crash-safe queue of tape stage-in requests + its directive
 *   config struct. This is the only header that src/query/prepare.c, the HTTP
 *   Tape REST endpoint, and the residency code include. The queue is
 *   file-backed (the source of truth) with an SHM hot index (a rebuildable
 *   cache); see frm_format.h for the on-disk layout and src/frm/README.md for
 *   the truth-vs-cache invariant and lock order.
 *
 * WHY: A tape recall takes minutes to hours, so the request must outlive both
 *   the client connection (the old bug homed it on ctx->prepare_paths, freed at
 *   disconnect) and a worker/master restart. Every mutating op commits to the
 *   file under an fcntl lock, then patches the SHM index.
 */

/* Lightweight nginx-core types only (NOT the module umbrella) so this header is
 * safe to include from src/types/config.h without an include cycle. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "frm_format.h"

/* Host-qualified reqid: "<seq>.<pid>@<host>" — sized to FRM_REQID_LEN. */
#define XROOTD_FRM_REQID_LEN  FRM_REQID_LEN

/* Max absolute export path the FRM/Tape-REST code handles (also in
 * frm_internal.h; exposed here for the HTTP Tape REST face). */
#ifndef NGX_XROOTD_FRM_PATH_MAX
#define NGX_XROOTD_FRM_PATH_MAX  4096
#endif

/* Opaque per-process queue handle (definition in frm_internal.h). */
typedef struct frm_queue_s frm_queue_t;

/*
 * Per-server FRM configuration (one xrootd_frm_conf_t frm; embedded in
 * ngx_stream_xrootd_srv_conf_t, after prepare_command). `queue` is resolved at
 * postconfiguration and is NULL when disabled.
 */
typedef struct {
    ngx_flag_t    enable;            /* xrootd_frm                            */
    ngx_str_t     queue_path;        /* xrootd_frm_queue_path                 */
    ngx_uint_t    max_inflight;      /* xrootd_frm_max_inflight               */
    ngx_uint_t    max_per_source;    /* xrootd_frm_max_per_source (Phase 4 F4) */
    ngx_str_t     stagecmd;          /* xrootd_frm_stagecmd (← prepare_command)*/
    ngx_str_t     copycmd;           /* xrootd_frm_copycmd      (Phase 1)     */
    ngx_uint_t    copymax;           /* xrootd_frm_copymax      (Phase 1)     */
    ngx_msec_t    stage_ttl;         /* xrootd_frm_stage_ttl                  */
    ngx_msec_t    xfrhold_ms;        /* xrootd_frm_xfrhold      (Phase 1)     */
    ngx_uint_t    stage_wait;        /* xrootd_frm_stage_wait   (Phase 1)     */
    ngx_flag_t    async_recall;      /* xrootd_frm_async_recall (Phase 3)     */
    ngx_msec_t    fail_backoff_ms;   /* xrootd_frm_fail_backoff (Phase 1)     */
    ngx_uint_t    fail_retries;      /* xrootd_frm_fail_retries (Phase 1)     */
    ngx_str_t     residency_cmd;     /* xrootd_frm_residency_cmd(Phase 1/4)   */
    ngx_msec_t    copy_timeout;      /* xrootd_frm_copy_timeout (Phase 1)     */
    /* Category-2 (Phase 4) — directives accepted, engine is a stub */
    ngx_str_t     migrate_copycmd;   /* xrootd_frm_migrate_copycmd            */
    ngx_uint_t    purge_hi_ppm;      /* xrootd_frm_purge_watermark high       */
    ngx_uint_t    purge_lo_ppm;      /* xrootd_frm_purge_watermark low        */
    ngx_msec_t    purge_interval_ms; /* xrootd_frm_purge_interval             */
    /* resolved at postconfig (process-local; NULL when !enable) */
    frm_queue_t  *queue;
} xrootd_frm_conf_t;

/*
 * Caller-supplied view of a new request for frm_request_add(). Only `lfn` is
 * required; everything else may be zero/NULL.
 */
typedef struct {
    const char  *lfn;            /* logical path (required, NUL-terminated)   */
    const char  *requester_dn;   /* GSI DN / token sub (may be NULL)          */
    const char  *user;
    const char  *notify;
    const char  *selector;
    const char  *cs_value;
    frm_cstype_t cs_type;
    uint32_t     options;        /* FRM_OPT_*                                 */
    int8_t       priority;       /* -1..2                                     */
    uint8_t      queue;          /* stgQ/migQ/getQ/putQ                       */
    int64_t      tod_expire;     /* 0 = never                                 */
} frm_req_view_t;

/* ---- directive helpers (src/frm/directives.c) ------------------------------*/
void  xrootd_frm_conf_init(xrootd_frm_conf_t *frm);
char *xrootd_frm_conf_merge(ngx_conf_t *cf, xrootd_frm_conf_t *conf,
                            xrootd_frm_conf_t *prev,
                            const ngx_str_t *prepare_command);
/* custom setter referenced from the stream module command table (TAKE2 ratios) */
char *xrootd_frm_set_purge_watermark(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);

/* ---- queue lifecycle (config + master init, src/frm/queue.c) ---------------*/
/*
 * Resolve (creating on first call) the process-local queue handle for a queue
 * file path. Called from postconfiguration in the master, before fork, so the
 * file fd is inherited by every worker. Returns NULL on error.
 */
frm_queue_t *frm_queue_get(ngx_conf_t *cf, const ngx_str_t *path,
                           ngx_uint_t max_inflight, ngx_uint_t max_per_source);

/* Configure the SHM hot-index zone for `path` (postconfiguration). */
ngx_int_t    frm_index_configure(ngx_conf_t *cf, const ngx_str_t *path,
                                 ngx_uint_t slots);

/* The process-local queue handle resolved at init_process. Valid in any face
 * running in the worker (stream open path, HTTP Tape REST). NULL when FRM is off
 * or before init. (Also declared internally; exposed for the HTTP face.) */
frm_queue_t *frm_singleton_queue(void);

/*
 * Open this process's file descriptors onto the queue file (the queue data fd +
 * the .lock sidecar). Called per-worker from init_process. The master's
 * reconciliation runs separately in the SHM zone-init callback (before fork);
 * workers open their own fds so POSIX locks serialise correctly across them.
 */
ngx_int_t    frm_queue_init(frm_queue_t *q, ngx_log_t *log);

/* ---- reqid (src/frm/reqid.c) -----------------------------------------------*/
/* Durable, globally-unique "<hdr.seq++>.<pid>@<host>" under the file lock. */
ngx_int_t    frm_reqid_generate(frm_queue_t *q, char *buf, size_t buf_sz,
                                ngx_log_t *log);

/* ---- mutating ops (fcntl lkExcl → fsync → patch SHM) -----------------------*/
/*
 * Admit a request. Writes reqid_out (>= XROOTD_FRM_REQID_LEN bytes). Returns
 * NGX_OK; NGX_DECLINED if a live (QUEUED/STAGING) request already exists for the
 * same lfn (dedup — reqid_out is filled with the existing reqid); NGX_ABORT if
 * the queue is at max_inflight; NGX_ERROR on I/O failure.
 */
ngx_int_t    frm_request_add(frm_queue_t *q, const frm_req_view_t *req,
                             char *reqid_out, size_t reqid_out_sz,
                             ngx_log_t *log);

/* Fetch a full record by reqid. NGX_OK / NGX_DECLINED (no such reqid). */
ngx_int_t    frm_request_get(frm_queue_t *q, const char *reqid,
                             frm_record_t *out, ngx_log_t *log);

/* Transition status (+ optional errno-style fail_code). NGX_DECLINED if gone. */
ngx_int_t    frm_request_set_status(frm_queue_t *q, const char *reqid,
                             frm_status_t status, int32_t fail_code,
                             ngx_log_t *log);

/* Remove a request (cancel). NGX_OK / NGX_DECLINED (already gone — idempotent).*/
ngx_int_t    frm_request_delete(frm_queue_t *q, const char *reqid,
                             ngx_log_t *log);

/* Authorization guard for a CLIENT-initiated cancel/evict of reqid. NGX_OK if
 * caller_dn (NULL/"" = anonymous) may act on it; NGX_DECLINED if the request is
 * owned by a different non-empty principal DN. Fail-open: anon caller, absent
 * record, or owner-less record all pass. Internal deletions bypass this. */
ngx_int_t    frm_request_owner_check(frm_queue_t *q, const char *reqid,
                             const char *caller_dn, ngx_log_t *log);

/*
 * Find the newest live (QUEUED/STAGING/ONLINE) request for a logical path.
 * NGX_OK fills out; NGX_DECLINED if none. Used by QPrep / the open path.
 */
ngx_int_t    frm_request_find_by_path(frm_queue_t *q, const char *lfn,
                             frm_record_t *out, ngx_log_t *log);

/*
 * Iterate active records. *cursor starts at 0; updated each call. status<0 = any
 * status; queue==0xff = any queue; dn_filter!=NULL restricts to that requester.
 * Returns NGX_OK (out filled, advance), NGX_DONE (iteration complete).
 */
ngx_int_t    frm_request_list(frm_queue_t *q, ngx_uint_t *cursor,
                             int status, int queue, const char *dn_filter,
                             frm_record_t *out, ngx_log_t *log);

/* ---- maintenance (worker-0 reaper timer, src/frm/reaper.c) -----------------*/
ngx_int_t    frm_reap_expired(frm_queue_t *q, time_t now, ngx_log_t *log);
void         frm_reaper_register(ngx_cycle_t *cycle);

/* ---- Phase 4 F6: Category-2 migrate/purge scaffolding (migrate_purge.c) -----
 * Engine is a stub (Category-2 is delegated to the MSS backend); these only arm
 * a worker-0 watermark monitor + count intents. */
void         frm_migrate_purge_register(ngx_cycle_t *cycle,
                                        xrootd_frm_conf_t *frm);
void         frm_migrate_note(const char *lfn);

/* ===========================================================================
 * Phase 1 — residency + transfer worker (the synchronous tape gateway)
 * ======================================================================== */

/* ---- residency (residency_xattr.c / residency_probe.c) --------------------*/
typedef enum {
    FRM_RES_UNKNOWN  = 0,   /* not determinable                              */
    FRM_RES_ONLINE,         /* resident on disk                             */
    FRM_RES_NEARLINE,       /* on the backend, not on disk (stageable)       */
    FRM_RES_OFFLINE,        /* on the backend but not retrievable now        */
    FRM_RES_LOST            /* file is gone                                  */
} frm_residency_state_t;

typedef struct {
    frm_residency_state_t  state;
    int                    backend_exists;   /* a tape/backend copy exists    */
} frm_residency_t;

/*
 * phase-46 W2b: process-global "FRM was configured on this process" flag, set
 * once at postconfiguration (master, pre-fork) when any frm-enabled server block
 * exists.  When unset, no object can carry a residency marker, so
 * frm_residency_probe() short-circuits to ONLINE and skips its stat+getxattr —
 * eliminating that per-request cost on plain (no-tape) S3/WebDAV exports, the
 * same way the native stat/open paths already gate on conf->frm.enable.
 */
void frm_mark_configured(void);
int  frm_is_configured(void);

/*
 * Probe a file's residency by its absolute export path. xattr-based: a present
 * file whose user.frm.residency xattr is "nearline"/"offline" is non-resident;
 * absent xattr or "online" means resident (so existing exports need no
 * migration). A missing file → FRM_RES_LOST. Never reads request input.
 */
ngx_int_t frm_residency_probe(ngx_log_t *log, const char *full_path,
                              frm_residency_t *out);

/* Set the residency xattr (the stage worker flips nearline → online). */
ngx_int_t frm_residency_set(ngx_log_t *log, const char *full_path,
                            frm_residency_state_t state);

/* ---- transfer worker / scheduler (stage_exec/worker/scheduler.c) ----------*/
/*
 * Atomically claim a QUEUED request → STAGING so exactly one worker stages it.
 * NGX_OK = claimed by the caller; NGX_DECLINED = already staging or gone.
 */
ngx_int_t frm_request_claim(frm_queue_t *q, const char *reqid, ngx_log_t *log);

/* Arm the per-worker stage scheduler timer (registered from init_process).
 * thread_pool is the server's ngx_thread_pool_t* (passed as void* to keep this
 * header free of the threads headers). */
void      frm_stage_scheduler_register(ngx_cycle_t *cycle,
                                       xrootd_frm_conf_t *frm,
                                       void *thread_pool,
                                       ngx_flag_t manager_mode,
                                       uint16_t self_port);

/* Nudge the scheduler to drain QUEUED requests ASAP (from the open path). */
void      frm_stage_kick(void);

/* ===========================================================================
 * Phase 2 — HTTP WLCG Tape REST façade (thin wrappers over the store; defined
 * here, after frm_residency_t, so frm_file_locality can name it). These give the
 * davs:// Tape REST endpoint (src/webdav/tape_rest.c) its verbs without it
 * touching the durable file directly.
 * ======================================================================== */

/* Synchronous locality probe for archiveinfo/fileinfo: stat + residency, NO
 * queue write. full_path is the absolute export path. NGX_OK fills out;
 * NGX_DECLINED if the file is gone (caller reports exists=false). */
ngx_int_t    frm_file_locality(const char *full_path, frm_residency_t *out,
                             ngx_log_t *log);

/* The file record of a stage request id. Phase 0/1 is one lfn per reqid, so this
 * returns that single record (frm_request_get). NGX_OK / NGX_DECLINED. */
ngx_int_t    frm_request_list_files(frm_queue_t *q, const char *reqid,
                             frm_record_t *out, ngx_log_t *log);

/* List all active requests (any status/queue), optionally filtered by requester
 * DN. Iterates the SHM index; *cursor starts at 0. NGX_OK (advance) / NGX_DONE. */
ngx_int_t    frm_request_list_active(frm_queue_t *q, ngx_uint_t *cursor,
                             const char *dn_filter, frm_record_t *out,
                             ngx_log_t *log);

/* Cancel a stage request by id → status CANCELLED (kept for status queries; use
 * frm_request_delete to remove). Idempotent: NGX_OK / NGX_DECLINED (gone). */
ngx_int_t    frm_request_cancel(frm_queue_t *q, const char *reqid,
                             ngx_log_t *log);

/* Release a disk pin (Tape REST release/unpin): the staged copy no longer needs
 * to stay resident. Thin: confirms the path exists and records the intent
 * (xrootd_frm_evict_total); the actual disk purge is delegated to the MSS
 * (Category-2, Phase 4). NGX_OK if the path exists, NGX_DECLINED otherwise. */
ngx_int_t    frm_pin_release(const char *full_path, ngx_log_t *log);

#endif /* NGX_XROOTD_FRM_H */
