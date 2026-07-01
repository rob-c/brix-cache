/*
 * stage.c — the FRM transfer worker via a long-lived stage agent.
 *
 * WHAT: A per-worker scheduler drains QUEUED requests, claims each
 *   (QUEUED → STAGING, so exactly one claim stages a record), and hands it to a
 *   dedicated STAGE-AGENT process over a socketpair. The agent runs the operator
 *   copycmd (fork+exec+reap) and writes back the exit code; the worker reads the
 *   reply on the event loop and commits ONLINE/FAILED.
 *
 * WHY: We must NOT fork the copycmd from the nginx worker. nginx's SIGCHLD
 *   handler (ngx_process_get_status → ngx_unlock_mutexes) walks every shared
 *   memory zone treating it as an ngx_slab_pool_t and force-unlocks sp->mutex;
 *   several nginx-xrootd zones overwrite that header, so reaping ANY worker child
 *   SIGSEGVs the master. The agent is double-forked (reparented to init) so nginx
 *   never reaps it, and the agent — not nginx — reaps the copycmd children. This
 *   also keeps all blocking work (fork/waitpid) off the event loop without a
 *   thread pool.
 *
 * HOW: the crash-safe fork/reparent/reap/socketpair mechanics now live in the
 *   shared transfer-agent harness (src/fs/xfer/xfer_mover_agent.c), which every
 *   external-process transfer uses. This file supplies only the FRM payload:
 *   the request/reply frame layout and the agent-side process callback
 *   (frm_agent_xfer_process → oracle/copycmd/verify) plus the worker-side
 *   completion callback (frm_agent_xfer_on_reply → frm_stage_commit). The
 *   single-recall guarantee is the claim on top of the queue's under-lock lfn
 *   dedup.
 */

#include "frm_internal.h"
#include "waiter.h"
#include "../compat/checksum.h"
#include "../manager/registry.h"
#include "../compat/staged_file.h"   /* xrootd_commit_staged (scratch->storage move) */
#include "../fs/xfer/xfer.h"     /* the shared crash-safe out-of-process agent harness */
#include "../fs/xfer/xfer_reconcile.h"  /* the shared journal-recovery scan */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>   /* setenv (export $FRM_LFN to the copycmd) */
#include <sys/wait.h>
#include <unistd.h>

/* ---- FRM copycmd materialize-to-scratch (folded from the former fs/vfs_scratch;
 * the copycmd writes a LOCAL POSIX path, committed onto storage afterwards). The
 * FRM producer always targets the default POSIX backend, so the capability gate
 * reduces to the force-scratch flag. ------------------------------------------ */
static ngx_int_t
frm_scratch_path(const char *stage_dir, const char *key, char *out, size_t outsz)
{
    int n;

    if (stage_dir == NULL || stage_dir[0] == '\0' || key == NULL || key[0] == '\0') {
        errno = EINVAL;
        return NGX_ERROR;
    }
    n = snprintf(out, outsz, "%s/%s.scratch", stage_dir, key);
    if (n < 0 || (size_t) n >= outsz) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* The local path the copycmd writes into: `logical` in place, or a
 * <stage_dir>/<key>.scratch copy when force-staging. *materialized reports which. */
static ngx_int_t
frm_produce_target(const char *logical, const char *stage_dir, const char *key,
    unsigned force, char *out, size_t outsz, ngx_uint_t *materialized)
{
    if (logical == NULL || out == NULL || materialized == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (!force) {
        int n = snprintf(out, outsz, "%s", logical);

        if (n < 0 || (size_t) n >= outsz) {
            errno = ENAMETOOLONG;
            return NGX_ERROR;
        }
        *materialized = 0;
        return NGX_OK;
    }
    if (frm_scratch_path(stage_dir, key, out, outsz) != NGX_OK) {
        return NGX_ERROR;
    }
    *materialized = 1;
    return NGX_OK;
}

/* Publish a produced scratch onto storage (same-FS rename or cross-device copy).
 * No-op when !materialized (the copycmd wrote the export object in place). */
static ngx_int_t
frm_produce_commit(const char *logical, const char *stage_dir, const char *key,
    ngx_uint_t materialized, ngx_log_t *log)
{
    char scratch[PATH_MAX];

    if (!materialized) {
        return NGX_OK;
    }
    if (logical == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (frm_scratch_path(stage_dir, key, scratch, sizeof(scratch)) != NGX_OK) {
        return NGX_ERROR;
    }
    return xrootd_commit_staged(NGX_INVALID_FILE, scratch, logical, log);
}


#define FRM_COPYCMD_MAX   1024
#define FRM_SCHED_PERIOD  500     /* ms between drains while work is pending  */
#define FRM_SCHED_KICK    1       /* ms — drain ASAP after an enqueue         */
#define FRM_SCHED_IDLE    30000   /* ms — slow safety tick when queue is empty*/

/* Agent reply exit-code sentinels (≤0; a positive code is the copycmd's exit). */
#define FRM_RC_OK            0     /* staged (or already online per oracle)     */
#define FRM_RC_FORK         -1     /* could not fork/exec the command           */
#define FRM_RC_VERIFY       -2     /* F5: checksum mismatch on the staged file  */
#define FRM_RC_OFFLINE      -3     /* F3: residency oracle says offline/lost    */

/* fixed-size IPC frames (framing by size; the worker/agent read with
 * frm_read_full, so frames larger than PIPE_BUF are fine). */
typedef struct {
    char    reqid[FRM_REQID_LEN];
    char    path[FRM_LFN_LEN];                /* WHERE the copycmd writes (export
                                              * in place, or a scratch temp)     */
    char    lfn[FRM_LFN_LEN];                 /* the logical name being recalled,
                                              * exported to the copycmd as
                                              * $FRM_LFN — so a recall script
                                              * knows WHAT to fetch even when the
                                              * destination is a scratch path    */
    char    copycmd[FRM_COPYCMD_MAX];
    char    residency_cmd[FRM_COPYCMD_MAX];  /* F3 oracle (empty = none)        */
    char    cs_value[FRM_CSVAL_LEN];         /* F5 expected checksum (hex/str)  */
    uint8_t cs_type;                         /* F5 frm_cstype_t (0 = none)      */
} frm_agent_req_t;

typedef struct {
    char reqid[FRM_REQID_LEN];
    int  exit_code;                          /* FRM_RC_* or the copycmd exit    */
} frm_agent_rep_t;


/* per-worker scheduler + agent state (process-local) */
static ngx_event_t        frm_sched_ev;
static ngx_log_t         *frm_sched_log;
static ngx_str_t          frm_sched_cmd;     /* copycmd (→stagecmd fallback)   */
static ngx_str_t          frm_sched_residency_cmd; /* F3 oracle (may be empty)  */
static ngx_uint_t         frm_sched_copymax;
static ngx_uint_t         frm_sched_ready;
static ngx_flag_t         frm_sched_manager; /* F1: register staged path on done*/
static uint16_t           frm_sched_self_port;/* F1: advertised listen port      */
/* Materialize-to-scratch (prototype): copycmd writes to a LOCAL POSIX scratch
 * mount, then the worker commits scratch -> storage via the VFS<->VFS move. On a
 * POSIX backend this is inert (copycmd writes the export path in place). Until a
 * non-POSIX FRM backend exists, both are opt-in via env so the seam can be
 * exercised: XROOTD_FRM_STAGE_DIR (scratch mount) + XROOTD_FRM_FORCE_SCRATCH=1. */
static ngx_str_t          frm_sched_stage_dir;
static ngx_flag_t         frm_sched_force_scratch;
/* The crash-safe out-of-process agent: the fork/reap/socketpair mechanics now
 * live in the shared harness (src/fs/xfer/xfer_mover_agent.c); this file supplies
 * only the FRM payload (frame contents + the process/on_reply callbacks). */
static xrootd_xfer_agent_t frm_agent;


/* ===================== agent process (post-double-fork) ==================== */

/* Run `cmd path` (no shell) and return its exit status, or FRM_RC_FORK. */
static int
frm_agent_run(const char *cmd, const char *path)
{
    pid_t pid = fork();
    int   st;

    if (pid < 0) {
        return FRM_RC_FORK;
    }
    if (pid == 0) {
        char *argv[3];
        int   f;
        for (f = 3; f < 1024; f++) { (void) close(f); }
        argv[0] = (char *) cmd;
        argv[1] = (char *) path;
        argv[2] = NULL;
        execv(cmd, argv);
        _exit(127);
    }
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
    return WIFEXITED(st) ? WEXITSTATUS(st) : FRM_RC_FORK;
}

/* F5: verify the staged file's checksum against the requested cs_type/cs_value.
 * Returns 1 on match (or when verification is not applicable/possible to assess
 * as a request — unsupported algo is skipped, not failed), 0 on a real mismatch
 * or unreadable file. Runs in the agent (off the event loop). */
static int
frm_agent_verify_cksum(const char *path, uint8_t cs_type, const char *expected)
{
    static const char *names[] = {
        NULL,        /* FRM_CS_NONE    */
        "sha1",      /* FRM_CS_SHA1    */
        "sha256",    /* FRM_CS_SHA2    */
        NULL,        /* FRM_CS_SHA3 (unsupported here) */
        "adler32",   /* FRM_CS_ADLER32 */
        "md5",       /* FRM_CS_MD5     */
        "crc32",     /* FRM_CS_CRC32   */
    };
    const char            *name;
    xrootd_checksum_alg_t   alg;
    char                    norm[32];
    char                    got[160];
    int                     fd;
    ngx_int_t               rc;

    if (cs_type >= sizeof(names) / sizeof(names[0])
        || names[cs_type] == NULL || expected[0] == '\0')
    {
        return 1;                            /* nothing to verify → accept */
    }
    name = names[cs_type];
    if (xrootd_checksum_parse(name, ngx_strlen(name), &alg, norm, sizeof(norm))
        != NGX_OK)
    {
        return 1;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;                            /* staged file unreadable → fail */
    }
    rc = xrootd_checksum_hex_fd(alg, fd, path, ngx_cycle->log, got, sizeof(got));
    (void) close(fd);
    if (rc != NGX_OK) {
        return 0;
    }
    return (ngx_strcasecmp((u_char *) got, (u_char *) expected) == 0) ? 1 : 0;
}

/*
 * Process one stage request: F3 residency oracle (skip copy if already online,
 * fail if offline) → copycmd → F5 checksum verify. Returns FRM_RC_OK / a copycmd
 * exit code / an FRM_RC_* sentinel. No goto: a small linear pipeline.
 */
static int
frm_agent_process(const frm_agent_req_t *req)
{
    int rc;

    /* Export the logical name so the oracle + copycmd know WHAT to recall even
     * when req->path is a scratch destination (the agent is single-threaded, so
     * a per-request setenv is safe; the forked child inherits it). */
    (void) setenv("FRM_LFN", req->lfn, 1);

    if (req->residency_cmd[0] != '\0') {
        /* The oracle answers "is the OBJECT already resident?" — ask about the
         * logical object (req->lfn), not req->path, which under materialize-to-
         * scratch is an empty scratch temp we are about to recall INTO. */
        int orc = frm_agent_run(req->residency_cmd, req->lfn);
        if (orc == 0) {
            return FRM_RC_OK;                /* oracle: already resident */
        }
        if (orc == 2) {
            return FRM_RC_OFFLINE;           /* oracle: offline/lost */
        }
        /* any other code (incl. 1 = nearline) → proceed to stage */
    }

    rc = frm_agent_run(req->copycmd, req->path);
    if (rc != 0) {
        return (rc > 0) ? rc : FRM_RC_FORK;
    }

    if (req->cs_type != (uint8_t) FRM_CS_NONE
        && !frm_agent_verify_cksum(req->path, req->cs_type, req->cs_value))
    {
        return FRM_RC_VERIFY;
    }
    return FRM_RC_OK;
}

/* Agent-side callback (xfer harness owns the socket framing + loop): build one
 * reply from one request. Terminates the wire-sourced strings on a local copy,
 * then runs the FRM oracle/copycmd/verify pipeline. */
static void
frm_agent_xfer_process(const void *reqv, void *repv, void *data)
{
    frm_agent_req_t  req = *(const frm_agent_req_t *) reqv;   /* local, mutable */
    frm_agent_rep_t *rep = repv;

    (void) data;
    req.reqid[FRM_REQID_LEN - 1]           = '\0';
    req.path[FRM_LFN_LEN - 1]              = '\0';
    req.lfn[FRM_LFN_LEN - 1]               = '\0';
    req.copycmd[FRM_COPYCMD_MAX - 1]       = '\0';
    req.residency_cmd[FRM_COPYCMD_MAX - 1] = '\0';
    req.cs_value[FRM_CSVAL_LEN - 1]        = '\0';

    ngx_memcpy(rep->reqid, req.reqid, sizeof(rep->reqid));
    rep->exit_code = frm_agent_process(&req);
}


/* ===================== worker side: completion handling ==================== */

/* Bucket a completed recall's wall-clock latency (seconds) into the FRM
 * histogram. Mirrors unified.c's non-cumulative-bucket scheme; the exporter
 * cumulates into Prometheus le-buckets at scrape time. */
static void
frm_metric_observe_latency(time_t secs)
{
    static const time_t bounds[XROOTD_FRM_LATENCY_BUCKETS - 1] =
        { 1, 10, 30, 60, 300, 1800, 3600 };
    ngx_xrootd_metrics_t *m = xrootd_metrics_shared();
    ngx_uint_t            i;

    if (m == NULL) {
        return;
    }
    if (secs < 0) {
        secs = 0;
    }
    for (i = 0; i < XROOTD_FRM_LATENCY_BUCKETS - 1; i++) {
        if (secs <= bounds[i]) {
            break;
        }
    }
    ngx_atomic_fetch_add(&m->frm.stage_latency_bucket[i], 1);
    ngx_atomic_fetch_add(&m->frm.stage_latency_count, 1);
    ngx_atomic_fetch_add(&m->frm.stage_latency_sum_sec, (ngx_atomic_int_t) secs);
}

/*
 * Commit a finished recall. `rec` is the record as fetched at reply time (its
 * tod_status is the claim time, so now-tod_status is the recall latency). On
 * success flips residency ONLINE + status ONLINE; on failure marks FAILED and
 * forces residency OFFLINE so opens stop spinning. Metrics: the in_flight gauge
 * is decremented inside frm_request_set_status' terminal transition.
 */
static void
frm_stage_commit(const frm_record_t *rec, int code)
{
    frm_queue_t *q = frm_singleton_queue();
    const char  *reqid     = rec->reqid;
    const char  *full_path = rec->lfn;

    if (q == NULL) {
        return;
    }
    if (code == 0) {
        /* Publish the scratch copy onto storage (no-op on a POSIX backend, where
         * the copycmd wrote the export object in place) BEFORE flipping residency
         * — the bytes must be on storage before any open is allowed to resolve. */
        ngx_uint_t materialized = frm_sched_force_scratch ? 1 : 0;
        const char *sdir = frm_sched_stage_dir.len
                           ? (const char *) frm_sched_stage_dir.data : NULL;
        if (frm_produce_commit(full_path, sdir, reqid,
                               materialized, frm_sched_log) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, frm_sched_log, ngx_errno,
                          "frm: scratch commit \"%s\" failed", full_path);
            code = FRM_RC_FORK;              /* fall through to the failure path */
        }
    }
    if (code == 0) {
        (void) frm_residency_set(frm_sched_log, full_path, FRM_RES_ONLINE);
        (void) frm_request_set_status(q, reqid, FRM_ST_ONLINE, 0, frm_sched_log);
        XROOTD_FRM_METRIC_INC(stage_success_total);
        frm_metric_observe_latency(time(NULL) - (time_t) rec->tod_status);
        ngx_log_error(NGX_LOG_INFO, frm_sched_log, 0,
                      "frm: staged \"%s\" (reqid=%s)", full_path, reqid);

        /* F1 (cmsd Have): in manager mode, advertise that this server now holds
         * the path so a post-stage redirect resolves here (mirrors the cache-fill
         * self-register, but addressed by the configured listen port since the
         * agent reply has no client connection). */
        if (frm_sched_manager && q->host[0] != '\0') {
            xrootd_srv_register(q->host, frm_sched_self_port, full_path, 0, 0);
            XROOTD_FRM_METRIC_INC(cmsd_have_total);
        }
    } else {
        ngx_uint_t reason = (code == FRM_RC_VERIFY)  ? XROOTD_FRM_FAIL_VERIFY
                          : (code == FRM_RC_OFFLINE) ? XROOTD_FRM_FAIL_OTHER
                          :                            XROOTD_FRM_FAIL_COPYCMD;
        (void) frm_request_set_status(q, reqid, FRM_ST_FAILED, code,
                                      frm_sched_log);
        (void) frm_residency_set(frm_sched_log, full_path, FRM_RES_OFFLINE);
        XROOTD_FRM_METRIC_INC(stage_fail_total[reason]);
        ngx_log_error(NGX_LOG_ERR, frm_sched_log, 0,
                      "frm: stage FAILED rc=%d (%s) \"%s\" (reqid=%s) → offline",
                      code,
                      (code == FRM_RC_VERIFY)  ? "checksum mismatch"
                    : (code == FRM_RC_OFFLINE) ? "residency oracle: offline"
                    :                            "copycmd",
                      full_path, reqid);
    }

    /* Unified transfer ledger: one audit line for this recall, sharing the
     * schema and sink with STAGE uploads (and, later, WT/TPC). A tape recall
     * brings data IN to our storage; the principal is the recall requester. No
     * byte count is tracked for a recall, so bytes=0. */
    {
        const char *principal = (rec->requester_dn[0] != '\0') ? rec->requester_dn
                              : (rec->user[0] != '\0')          ? rec->user
                              :                                    NULL;
        xrootd_xfer_finish(XROOTD_XFER_TAPE, "in", full_path, principal, 0,
                           (code == 0) ? XROOTD_XFER_OK : XROOTD_XFER_AGENT_FAIL,
                           (code == 0) ? 0 : code, frm_sched_log);
    }

    /* Phase 3: wake any clients parked on this recall (kXR_attn asynresp). Marks
     * cross-worker waiters ready for their owner's poll; delivers this worker's
     * own inline. No-op when async recall is off (no waiters were ever added). */
    frm_waiter_deliver(reqid, code);
}

/* Worker-side callback (xfer harness owns the recv loop, EOF/respawn, re-arm):
 * one agent reply arrived → resolve the request and commit residency/status.
 * Agent death recovery, the connection leak fix, and the read-event re-arm now
 * live once in src/fs/xfer/xfer_mover_agent.c. In-flight STAGING records on a
 * dead agent are still recovered by frm_reconcile on the next master start. */
static void
frm_agent_xfer_on_reply(const void *repv, void *data)
{
    const frm_agent_rep_t *rep = repv;
    frm_queue_t           *q   = frm_singleton_queue();
    frm_record_t           rec;
    char                   reqid[FRM_REQID_LEN];

    (void) data;
    ngx_cpystrn((u_char *) reqid, (u_char *) rep->reqid, sizeof(reqid));
    if (q != NULL && frm_request_get(q, reqid, &rec, frm_sched_log) == NGX_OK) {
        frm_stage_commit(&rec, rep->exit_code);
    }
}

/* Worker-side callback: a reply batch drained → a stage slot freed, drain more. */
static void
frm_agent_xfer_after_drain(void *data)
{
    (void) data;
    frm_stage_kick();
}

/* The FRM payload binding for the shared agent harness. */
static const xrootd_xfer_agent_ops_t frm_agent_ops = {
    .req_size    = sizeof(frm_agent_req_t),
    .rep_size    = sizeof(frm_agent_rep_t),
    .process     = frm_agent_xfer_process,
    .on_reply    = frm_agent_xfer_on_reply,
    .after_drain = frm_agent_xfer_after_drain,
    .data        = NULL,
    .name        = "frm stage",
};


/* ===================== worker side: the drain ============================== */

/* Hand a claimed record to the agent. Returns NGX_OK sent / NGX_AGAIN busy. */
static ngx_int_t
frm_stage_dispatch(const frm_record_t *rec)
{
    frm_agent_req_t req;

    if (frm_agent.fd < 0) {
        return NGX_ERROR;
    }
    ngx_memzero(&req, sizeof(req));
    ngx_cpystrn((u_char *) req.reqid, (u_char *) rec->reqid, sizeof(req.reqid));

    /* The copycmd writes to a LOCAL POSIX path: the export object in place on a
     * POSIX backend, or a <stage_dir>/<reqid>.scratch copy when staging is in
     * effect (committed onto storage in frm_stage_commit).  storage=NULL ⇒ the
     * default POSIX backend; the key is the reqid so the commit recomputes it. */
    {
        ngx_uint_t materialized;
        const char *sdir = frm_sched_stage_dir.len
                           ? (const char *) frm_sched_stage_dir.data : NULL;
        if (frm_produce_target((const char *) rec->lfn,
                sdir, (const char *) rec->reqid, frm_sched_force_scratch,
                (char *) req.path, sizeof(req.path), &materialized) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, frm_sched_log, ngx_errno,
                          "frm: scratch target for \"%s\" failed", rec->lfn);
            return NGX_ERROR;
        }
    }
    /* The logical name the copycmd should fetch (exported as $FRM_LFN), distinct
     * from req.path when that is a scratch destination. */
    ngx_cpystrn((u_char *) req.lfn, (u_char *) rec->lfn, sizeof(req.lfn));
    ngx_cpystrn((u_char *) req.copycmd, frm_sched_cmd.data,
                ngx_min(frm_sched_cmd.len + 1, sizeof(req.copycmd)));
    /* F3: the residency oracle (empty when unconfigured). */
    if (frm_sched_residency_cmd.len > 0) {
        ngx_cpystrn((u_char *) req.residency_cmd, frm_sched_residency_cmd.data,
                    ngx_min(frm_sched_residency_cmd.len + 1,
                            sizeof(req.residency_cmd)));
    }
    /* F5: the requested integrity check for the agent to verify post-copy. */
    req.cs_type = rec->cs_type;
    ngx_cpystrn((u_char *) req.cs_value, (u_char *) rec->cs_value,
                sizeof(req.cs_value));

    /* Framing + partial-write handling now live in the shared harness. */
    return xrootd_xfer_agent_dispatch(&frm_agent, &req);
}

static void
frm_stage_drain(void)
{
    frm_queue_t *q = frm_singleton_queue();
    frm_record_t rec;
    ngx_uint_t   cursor, staging = 0;

    if (!frm_sched_ready || q == NULL || q->fd < 0 || frm_sched_cmd.len == 0) {
        return;
    }

    /* In-flight tape recalls (the shared journal scan; the QUEUED claim loop
     * below stays bespoke — it carries a copymax budget + early-break). */
    staging = xrootd_xfer_journal_foreach(q, FRM_ST_STAGING, FRM_XFER_TAPE,
                                          NULL, NULL, frm_sched_log);

    cursor = 0;
    while (staging < frm_sched_copymax
           && frm_request_list(q, &cursor, FRM_ST_QUEUED, 0xff, NULL,
                               &rec, frm_sched_log) == NGX_OK)
    {
        ngx_int_t rc;
        if (rec.xfer_kind != FRM_XFER_TAPE) {
            continue;                        /* a non-tape journal record     */
        }
        if (frm_request_claim(q, rec.reqid, frm_sched_log) != NGX_OK) {
            continue;                        /* another worker took it */
        }
        rc = frm_stage_dispatch(&rec);
        if (rc == NGX_OK) {
            staging++;
        } else {
            /* un-claim so it is retried (agent busy) or fail it (broken pipe) */
            (void) frm_request_set_status(q, rec.reqid,
                       (rc == NGX_AGAIN) ? FRM_ST_QUEUED : FRM_ST_FAILED,
                       (rc == NGX_AGAIN) ? 0 : -1, frm_sched_log);
            if (rc == NGX_AGAIN) {
                break;                       /* stop; retry next tick */
            }
            XROOTD_FRM_METRIC_INC(stage_fail_total[XROOTD_FRM_FAIL_DISPATCH]);
        }
    }
}

static void
frm_sched_handler(ngx_event_t *ev)
{
    frm_index_table_t *idx = frm_index_table();
    ngx_msec_t         delay;

    /*
     * Idle fast-path.  The SHM hot index mirrors the queue, so idx->count == 0
     * means there are no QUEUED/STAGING records — and since a parked waiter
     * always implies an in-flight recall (hence a record), no waiters either.
     * When that holds we skip BOTH the per-tick fcntl whole-file lock + file
     * scan (frm_stage_drain) AND the SHM waiter-table scan (frm_waiter_poll_
     * local), turning an idle tick into a single lock-free counter read, and we
     * back the timer off to a slow safety cadence.  frm_stage_kick() — called on
     * every enqueue and on every freed stage slot — pulls the timer back to
     * FRM_SCHED_KICK the instant there is work, so the slow idle cadence costs no
     * staging latency.  If the index zone is absent (idx == NULL) the count is
     * untrustworthy, so fall through to the authoritative full drain.
     */
    if (idx != NULL && idx->count == 0) {
        delay = FRM_SCHED_IDLE;
    } else {
        frm_stage_drain();
        frm_waiter_poll_local();      /* deliver cross-worker completions (P3) */
        delay = FRM_SCHED_PERIOD;
    }

    if (!ngx_exiting) {
        ngx_add_timer(ev, delay);
    }
}


/* ===================== setup ============================================== */

void
frm_stage_scheduler_register(ngx_cycle_t *cycle, xrootd_frm_conf_t *frm,
                             void *thread_pool, ngx_flag_t manager_mode,
                             uint16_t self_port)
{
    frm_queue_t *q = frm_singleton_queue();

    (void) thread_pool;                      /* agent model: no thread pool */
    if (q == NULL || frm == NULL) {
        return;
    }
    frm_sched_cmd     = (frm->copycmd.len > 0) ? frm->copycmd : frm->stagecmd;
    frm_sched_residency_cmd = frm->residency_cmd;        /* F3 oracle           */
    frm_sched_copymax = frm->copymax ? frm->copymax : 4;
    frm_sched_manager = manager_mode;                    /* F1                  */
    frm_sched_self_port = self_port;                     /* F1                  */
    frm_sched_log     = cycle->log;

    {
        /* Materialize-to-scratch wiring (xrootd_frm_stage_dir/_force_scratch). */
        frm_sched_stage_dir     = frm->stage_dir;
        frm_sched_force_scratch = (frm->force_scratch == 1) ? 1 : 0;
        if (frm_sched_force_scratch && frm_sched_stage_dir.len == 0) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                "frm: xrootd_frm_force_scratch set but xrootd_frm_stage_dir empty "
                "— staging-to-scratch disabled");
            frm_sched_force_scratch = 0;
        }
    }

    if (frm_sched_cmd.len == 0) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "frm: no copycmd/stagecmd — staging disabled");
        return;
    }

    if (xrootd_xfer_agent_attach(&frm_agent, &frm_agent_ops, cycle->log)
        != NGX_OK)
    {
        return;
    }

    ngx_memzero(&frm_sched_ev, sizeof(frm_sched_ev));
    frm_sched_ev.handler = frm_sched_handler;
    frm_sched_ev.log     = cycle->log;
    frm_sched_ev.data    = &frm_sched_ev;
    frm_sched_ready      = 1;
    ngx_add_timer(&frm_sched_ev, FRM_SCHED_PERIOD);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "frm: stage agent started (copymax=%ui)", frm_sched_copymax);
}

void
frm_stage_kick(void)
{
    if (frm_sched_ready) {
        ngx_add_timer(&frm_sched_ev, FRM_SCHED_KICK);
    }
}
