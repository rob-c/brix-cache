/*
 * stage_request_registry.h — the durable tape/prepare REQUEST registry.
 *
 * WHAT: The reqid-keyed durable request store that backs kXR_prepare
 *       (src/query/prepare.c) and the WebDAV Tape REST API
 *       (src/webdav/tape_rest.c): admit a stage request, look it up, check its
 *       owner, list active requests + their files, cancel/delete, release a pin.
 *       This is the FRM-dissolution (§13b, phase-64 P6) re-home of the FRM queue
 *       (former src/frm/queue.c + reqfile.c + reqid.c + index.c) as a peer of the
 *       stage_engine: the request METADATA (owner/cs_type/lfn/status) the engine's
 *       transfer record does not carry, keyed by the same reqid the mover uses.
 *
 * WHY:  The recall/stage TRANSFER is the stage_engine's job (submit -> mover ->
 *       journal, driven by the sd_frm backend's recall). But the client-facing
 *       request SEMANTICS — a stable reqid the client echoes to cancel, the
 *       requesting identity for owner-checked cancel, custodial-vs-staging class,
 *       the list/status views the Tape REST API returns — are a request registry,
 *       not a transfer queue. Splitting them lets src/frm/ dissolve while the wire
 *       contract (reqid format, owner auth, list/cancel/pin) is preserved exactly.
 *
 * HOW:  A single durable file (crash-safe append + compaction, inherited from the
 *       FRM reqfile format) under the stage journal dir. reqid keeps the historic
 *       "<seq>.<pid>@<host>" form (BRIX_STAGE_REQID_LEN) so clients that echo a
 *       reqid keep working across the dissolution. All ops are worker-safe (a shm
 *       or file lock over the durable store); list uses an opaque cursor.
 *
 * See docs/superpowers/plans/2026-07-01-frm-dissolution.md (Task 4).
 */
#ifndef BRIX_STAGE_REQUEST_REGISTRY_H
#define BRIX_STAGE_REQUEST_REGISTRY_H

#include <ngx_core.h>

/* reqid wire format preserved verbatim from the FRM queue ("<seq>.<pid>@<host>").
 * Clients echo this back to cancel, so the length + shape MUST NOT change. */
#define BRIX_STAGE_REQID_LEN   64
#define BRIX_STAGE_LFN_LEN     4096
#define BRIX_STAGE_DN_LEN      512
#define BRIX_STAGE_USER_LEN    64

/* Per-file checksum type for recall integrity verification (F5): the stage worker
 * verifies the recalled file against the request's checksum and fails the recall on
 * mismatch. Values match the former frm_cstype_t (WLCG checksumType names). */
typedef enum {
    BRIX_STAGE_CS_NONE    = 0,
    BRIX_STAGE_CS_SHA1    = 1,
    BRIX_STAGE_CS_SHA2    = 2,
    BRIX_STAGE_CS_SHA3    = 3,
    BRIX_STAGE_CS_ADLER32 = 4,
    BRIX_STAGE_CS_MD5     = 5,
    BRIX_STAGE_CS_CRC32   = 6
} brix_stage_cstype_t;

/* Request lifecycle status (reported by kXR_prepare status + Tape REST). */
typedef enum {
    BRIX_STAGE_REQ_QUEUED = 0,   /* admitted, recall not yet started            */
    BRIX_STAGE_REQ_ACTIVE,       /* recall in flight (mover running)            */
    BRIX_STAGE_REQ_DONE,         /* online, ready                               */
    BRIX_STAGE_REQ_FAILED,       /* recall failed (retryable/terminal per errno)*/
    BRIX_STAGE_REQ_CANCELLED     /* client/owner cancelled                      */
} brix_stage_req_status_t;

typedef struct brix_stage_registry_s brix_stage_registry_t;

/* One request record as returned to the callers (a stable read view; the durable
 * on-disk layout is private to the .c). */
typedef struct {
    char                      reqid[BRIX_STAGE_REQID_LEN];
    char                      lfn[BRIX_STAGE_LFN_LEN];       /* logical path     */
    char                      requester_dn[BRIX_STAGE_DN_LEN];
    brix_stage_cstype_t     cs_type;
    brix_stage_req_status_t status;
    int64_t                   tod_added;
    int64_t                   tod_expire;    /* 0 = never (reaper)                 */
} brix_stage_request_t;

/* Caller-supplied view of a NEW request for brix_stage_request_add(). Only `lfn`
 * is required; the rest default. Mirrors the former frm_req_view_t. */
typedef struct {
    const char            *lfn;             /* required — logical (client) path    */
    const char            *requester_dn;    /* GSI DN / token sub, NULL = anon     */
    const char            *user;            /* mapped user, NULL = none            */
    brix_stage_cstype_t   cs_type;        /* checksum alg, default NONE           */
    const char            *cs_value;        /* checksum value string, NULL = none  */
    int64_t                 tod_expire;     /* 0 = never                           */
} brix_stage_request_view_t;

/* Process-wide singleton (one durable store per server), or NULL if uninitialised.
 * Configured once at postconfiguration (Task 5) with the journal dir. */
brix_stage_registry_t *brix_stage_registry_singleton(void);

/* Initialise the durable registry under `journal_dir` (idempotent; recovers +
 * compacts an existing store). Returns NGX_OK / NGX_ERROR. */
ngx_int_t brix_stage_registry_init(const char *journal_dir, ngx_log_t *log);

/* Mint a reqid for a new request. Writes `reqid_out` (>= BRIX_STAGE_REQID_LEN).
 * NGX_OK, or NGX_ERROR (store full / I/O). */
ngx_int_t brix_stage_request_reqid_generate(brix_stage_registry_t *reg,
    char *reqid_out, size_t reqid_out_sz, ngx_log_t *log);

/* Admit a request; writes the minted reqid into `reqid_out`. NGX_OK / NGX_ERROR /
 * NGX_DECLINED (store full). Idempotent per (lfn, requester_dn) is NOT assumed —
 * the caller may pre-check with find_by_path. */
ngx_int_t brix_stage_request_add(brix_stage_registry_t *reg,
    const brix_stage_request_view_t *view, char *reqid_out,
    size_t reqid_out_sz, ngx_log_t *log);

/* Fetch a request by reqid into `out`. NGX_OK / NGX_DECLINED (unknown) / NGX_ERROR. */
ngx_int_t brix_stage_request_get(brix_stage_registry_t *reg,
    const char *reqid, brix_stage_request_t *out, ngx_log_t *log);

/* Find an active request for `lfn`, writing its reqid into `reqid_out`.
 * NGX_OK / NGX_DECLINED (none) / NGX_ERROR. (kXR_prepare idempotency.) */
ngx_int_t brix_stage_request_find_by_path(brix_stage_registry_t *reg,
    const char *lfn, char *reqid_out, size_t reqid_out_sz, ngx_log_t *log);

/* Owner check: NGX_OK iff `requester_dn` owns `reqid` (an anonymous session can
 * never cancel a durable reqid it did not create). NGX_DECLINED otherwise. */
ngx_int_t brix_stage_request_owner_check(brix_stage_registry_t *reg,
    const char *reqid, const char *requester_dn, ngx_log_t *log);

/* Set a request's status (mover progress; wired from the engine on completion). */
ngx_int_t brix_stage_request_set_status(brix_stage_registry_t *reg,
    const char *reqid, brix_stage_req_status_t status, ngx_log_t *log);

/* Cancel (mark CANCELLED + abort any in-flight recall) or hard-delete a request.
 * Both idempotent (an unknown reqid is NGX_OK). */
ngx_int_t brix_stage_request_cancel(brix_stage_registry_t *reg,
    const char *reqid, ngx_log_t *log);
ngx_int_t brix_stage_request_delete(brix_stage_registry_t *reg,
    const char *reqid, ngx_log_t *log);

/* Enumerate ACTIVE (non-terminal) requests. *cursor is opaque; start at 0, repeat
 * until NGX_DONE. Each call fills `out`. NGX_OK (one) / NGX_DONE (end) / NGX_ERROR. */
ngx_int_t brix_stage_request_list_active(brix_stage_registry_t *reg,
    ngx_uint_t *cursor, brix_stage_request_t *out, ngx_log_t *log);

/* Enumerate the file(s) of one request (Tape REST GET .../<reqid>). A single-LFN
 * request yields one entry. *cursor opaque. NGX_OK / NGX_DONE / NGX_ERROR. */
ngx_int_t brix_stage_request_list_files(brix_stage_registry_t *reg,
    const char *reqid, ngx_uint_t *cursor, brix_stage_request_t *out,
    ngx_log_t *log);

/* Release a custodial pin on `abs_path` (Tape REST DELETE .../release). NGX_OK /
 * NGX_DECLINED (not pinned) / NGX_ERROR. */
ngx_int_t brix_stage_request_pin_release(brix_stage_registry_t *reg,
    const char *abs_path, ngx_log_t *log);

/* Reap expired requests (tod_expire < now); the per-worker sweep hook (Task 5).
 * Returns the count reaped. */
ngx_uint_t brix_stage_request_reap_expired(brix_stage_registry_t *reg,
    time_t now, ngx_log_t *log);

#endif /* BRIX_STAGE_REQUEST_REGISTRY_H */
