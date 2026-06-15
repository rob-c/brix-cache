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
 * HOW: setup blocks SIGCHLD, fork→fork(agent)→intermediate _exit (agent → init),
 *   reaps the intermediate while SIGCHLD is blocked (nginx never sees it). The
 *   worker side of the socketpair is registered as an nginx read event; replies
 *   drive completion. The single-recall guarantee is the claim on top of the
 *   queue's under-lock lfn dedup.
 */

#include "frm_internal.h"
#include "waiter.h"
#include "../compat/checksum.h"
#include "../manager/registry.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>


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
    char    path[FRM_LFN_LEN];
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
static int                frm_agent_fd = -1; /* worker side of the socketpair  */
static ngx_connection_t  *frm_agent_conn;    /* nginx connection for replies   */

/* agent lifecycle (death recovery): defined below, forward-declared here. */
static ngx_int_t          frm_agent_attach(ngx_log_t *log);
static void               frm_agent_teardown(void);
static void               frm_agent_respawn(void);


/* ===================== agent process (post-double-fork) ==================== */

static ssize_t
frm_read_full(int fd, void *buf, size_t len)
{
    u_char *p = buf;
    size_t  got = 0;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n == 0) { return 0; }            /* EOF */
        if (n < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        got += (size_t) n;
    }
    return (ssize_t) len;
}

static ssize_t
frm_write_full(int fd, const void *buf, size_t len)
{
    const u_char *p = buf;
    size_t        put = 0;
    while (put < len) {
        ssize_t n = write(fd, p + put, len - put);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        put += (size_t) n;
    }
    return (ssize_t) len;
}

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

    if (req->residency_cmd[0] != '\0') {
        int orc = frm_agent_run(req->residency_cmd, req->path);
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

/* The agent: read a request, run the oracle/copycmd/verify pipeline, reply. */
static void
frm_agent_main(int fd)
{
    frm_agent_req_t req;
    frm_agent_rep_t rep;

    signal(SIGCHLD, SIG_DFL);                /* our own waitpid must work */

    for ( ;; ) {
        if (frm_read_full(fd, &req, sizeof(req)) <= 0) {
            _exit(0);                        /* nginx closed → shut down */
        }
        req.reqid[FRM_REQID_LEN - 1]         = '\0';
        req.path[FRM_LFN_LEN - 1]            = '\0';
        req.copycmd[FRM_COPYCMD_MAX - 1]     = '\0';
        req.residency_cmd[FRM_COPYCMD_MAX-1] = '\0';
        req.cs_value[FRM_CSVAL_LEN - 1]      = '\0';

        ngx_memcpy(rep.reqid, req.reqid, sizeof(rep.reqid));
        rep.exit_code = frm_agent_process(&req);
        if (frm_write_full(fd, &rep, sizeof(rep)) < 0) {
            _exit(0);
        }
    }
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

    /* Phase 3: wake any clients parked on this recall (kXR_attn asynresp). Marks
     * cross-worker waiters ready for their owner's poll; delivers this worker's
     * own inline. No-op when async recall is off (no waiters were ever added). */
    frm_waiter_deliver(reqid, code);
}

/*
 * Release the worker side of the agent socketpair.  ngx_close_connection frees
 * the ngx_connection_t back to the pool, removes its read event AND closes the
 * fd, so we must NOT close frm_agent_fd ourselves (double close).  Idempotent.
 */
static void
frm_agent_teardown(void)
{
    if (frm_agent_conn != NULL) {
        ngx_close_connection(frm_agent_conn);   /* frees conn + closes the fd */
        frm_agent_conn = NULL;
    }
    frm_agent_fd = -1;                           /* dispatch now fails closed */
}

/*
 * Recover from a dead stage agent: tear the old socketpair/connection down (the
 * leak fix — the death paths in frm_agent_on_reply previously just returned,
 * orphaning the connection and the fd) and spawn a fresh agent so future recalls
 * keep flowing.  If respawn fails, frm_agent_fd stays -1, so frm_stage_dispatch
 * fails closed (records go FAILED gracefully) — no leak, no write to a dead fd,
 * no spin.  In-flight STAGING records dispatched to the dead agent are recovered
 * by frm_reconcile on the next master start (mid-run re-queue is unsafe in the
 * per-worker multi-agent model — it would re-queue other workers' live stages).
 */
static void
frm_agent_respawn(void)
{
    frm_agent_teardown();
    if (frm_agent_attach(frm_sched_log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, frm_sched_log, 0,
                      "frm: stage agent respawn failed — staging paused until "
                      "the next reload");
    } else {
        ngx_log_error(NGX_LOG_NOTICE, frm_sched_log, 0,
                      "frm: stage agent respawned after exit");
    }
}

/* nginx read-event handler: drain all pending agent replies. */
static void
frm_agent_on_reply(ngx_event_t *rev)
{
    ngx_connection_t *c = rev->data;
    frm_agent_rep_t   rep;
    frm_record_t      rec;
    frm_queue_t      *q = frm_singleton_queue();

    for ( ;; ) {
        ssize_t n = recv(c->fd, &rep, sizeof(rep), 0);
        if (n == 0) {
            /* Agent exited (EOF): close+free this connection (was leaked) and
             * respawn so staging recovers.  Returns immediately — `c`/`rev` are
             * freed by the teardown inside respawn, so must not be touched. */
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "frm: stage agent exited");
            frm_agent_respawn();
            return;
        }
        if (n < 0) {
            if (ngx_errno == NGX_EAGAIN) { break; }
            if (ngx_errno == NGX_EINTR)  { continue; }
            ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno, "frm: agent recv");
            frm_agent_respawn();
            return;
        }
        if (n != (ssize_t) sizeof(rep)) {
            /* partial frame: read the remainder (small, rarely happens) */
            if (frm_read_full(c->fd, (u_char *) &rep + n,
                              sizeof(rep) - (size_t) n) <= 0)
            {
                frm_agent_respawn();
                return;
            }
        }
        rep.reqid[FRM_REQID_LEN - 1] = '\0';

        /* resolve the request's lfn (full path) to commit residency */
        if (q != NULL
            && frm_request_get(q, rep.reqid, &rec, c->log) == NGX_OK)
        {
            frm_stage_commit(&rec, rep.exit_code);
        }
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "frm: agent read-event re-arm");
    }
    frm_stage_kick();                        /* a slot freed → drain more */
}


/* ===================== worker side: the drain ============================== */

/* Hand a claimed record to the agent. Returns NGX_OK sent / NGX_AGAIN busy. */
static ngx_int_t
frm_stage_dispatch(const frm_record_t *rec)
{
    frm_agent_req_t req;
    ssize_t         n;

    if (frm_agent_fd < 0) {
        return NGX_ERROR;
    }
    ngx_memzero(&req, sizeof(req));
    ngx_cpystrn((u_char *) req.reqid, (u_char *) rec->reqid, sizeof(req.reqid));
    ngx_cpystrn((u_char *) req.path, (u_char *) rec->lfn, sizeof(req.path));
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

    n = write(frm_agent_fd, &req, sizeof(req));
    if (n == (ssize_t) sizeof(req)) {
        return NGX_OK;
    }
    if (n < 0 && (ngx_errno == NGX_EAGAIN || ngx_errno == NGX_EINTR)) {
        return NGX_AGAIN;                    /* agent backed up — retry later */
    }
    /* a partial/failed write: finish it blocking (small, rare) */
    if (n >= 0 && frm_write_full(frm_agent_fd, (u_char *) &req + n,
                                 sizeof(req) - (size_t) n) == (ssize_t)
                                 (sizeof(req) - (size_t) n))
    {
        return NGX_OK;
    }
    return NGX_ERROR;
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

    cursor = 0;
    while (frm_request_list(q, &cursor, FRM_ST_STAGING, 0xff, NULL,
                            &rec, frm_sched_log) == NGX_OK)
    {
        staging++;
    }

    cursor = 0;
    while (staging < frm_sched_copymax
           && frm_request_list(q, &cursor, FRM_ST_QUEUED, 0xff, NULL,
                               &rec, frm_sched_log) == NGX_OK)
    {
        ngx_int_t rc;
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

/* Double-fork the agent (reparented to init so nginx never reaps it), reaping
 * the intermediate child while SIGCHLD is blocked. Returns the worker-side fd. */
static int
frm_agent_spawn(ngx_log_t *log)
{
    int      sv[2];
    sigset_t block, prev;
    pid_t    inter;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "frm: socketpair failed");
        return -1;
    }

    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &prev);

    inter = fork();
    if (inter < 0) {
        sigprocmask(SIG_SETMASK, &prev, NULL);
        close(sv[0]); close(sv[1]);
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "frm: agent fork failed");
        return -1;
    }
    if (inter == 0) {
        pid_t agent = fork();
        if (agent == 0) {
            close(sv[0]);
            frm_agent_main(sv[1]);           /* never returns */
            _exit(0);
        }
        _exit(0);                            /* intermediate → agent re-parents */
    }

    /* parent: reap the intermediate ourselves (nginx never sees it). */
    close(sv[1]);
    while (waitpid(inter, NULL, 0) < 0 && errno == EINTR) { }
    sigprocmask(SIG_SETMASK, &prev, NULL);

    (void) fcntl(sv[0], F_SETFL, O_NONBLOCK);
    return sv[0];
}

/*
 * Spawn a stage agent and register the worker side of its socketpair as an nginx
 * read event.  Shared by startup (frm_stage_scheduler_register) and respawn
 * after agent death.  On any failure tears down and leaves frm_agent_fd = -1
 * (dispatch fails closed), returning NGX_ERROR.
 */
static ngx_int_t
frm_agent_attach(ngx_log_t *log)
{
    frm_agent_fd = frm_agent_spawn(log);
    if (frm_agent_fd < 0) {
        return NGX_ERROR;
    }

    /* register the worker side of the socketpair as an nginx read event */
    frm_agent_conn = ngx_get_connection(frm_agent_fd, log);
    if (frm_agent_conn == NULL) {
        close(frm_agent_fd);
        frm_agent_fd = -1;
        return NGX_ERROR;
    }
    frm_agent_conn->read->handler  = frm_agent_on_reply;
    frm_agent_conn->read->log       = log;
    frm_agent_conn->recv            = ngx_recv;
    if (ngx_handle_read_event(frm_agent_conn->read, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "frm: cannot arm agent read event");
        frm_agent_teardown();               /* close+free; fd back to -1 */
        return NGX_ERROR;
    }
    return NGX_OK;
}

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

    if (frm_sched_cmd.len == 0) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "frm: no copycmd/stagecmd — staging disabled");
        return;
    }

    if (frm_agent_attach(cycle->log) != NGX_OK) {
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
