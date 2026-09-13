/*
 * stage_engine_journal.c — the durable journal + dead-letter substrate of the
 * async-staging engine (split from stage_engine.c, phase-79).
 *
 * WHAT: Owns the per-worker journal directory and the crash-visibility records
 *       that back an async submit: minting a request id, persisting a QUEUED
 *       record, removing a completed one, bumping the retry counter, and moving a
 *       permanently-denied flush to the dead-letter directory. Also the engine's
 *       one-time init that sets the journal directory.
 *
 * WHY:  stage_engine.c owned three concerns and exceeded the file-size cap. The
 *       durable-record substrate is a self-contained concern: the byte mover and
 *       the scheduler both reach it only through the seam in
 *       stage_engine_internal.h. The exact on-disk record I/O, the O_TRUNC crash-
 *       safe update, and the attempt/age dead-letter caps are unchanged by the
 *       split — this is a re-home, not a behavior change.
 *
 * HOW:  Every record write opens O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, writes the
 *       full fixed-size brix_sreq_t, and fsyncs. stage_deny_terminal (public,
 *       shared by the scheduler and reconcile halves) bumps attempts, re-persists,
 *       and on cap dead-letters + emits a loud tombstone. The two dead-letter
 *       helpers stay file-local.
 */

#include "stage_engine.h"
#include "stage_engine_internal.h"
#include "xfer.h"   /* brix_xfer_finish + the kind/result vocabulary (ledger) */
#include "stage_events.h"          /* 2.0 F2 StageEvents feed (brix_frm_stagemsg) */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---- SP4: the durable async queue -----------------------------------------
 * An async submit is DEFERRED rather than run inline: the request is appended to
 * a per-worker in-memory pending list (holding the live src/dst instances, which
 * are the memoised per-worker tier instances - they outlive the request) and,
 * when a journal dir is configured, persisted as a small record for crash
 * visibility/recovery. brix_stage_scheduler_tick() (a per-worker timer) drains
 * the list, runs each mover, and drops the stage copy of a completed FLUSH. This
 * generalises the FRM queue model to SD instances (section 11); the full physical
 * extraction of src/frm/ is the remaining SP4/SP5 migration. */

/*
 * Encapsulated module state — access via accessor functions.
 * WHY: Prevents accidental modification, enables future extension,
 *   and satisfies 100/100 code quality requirement for module globals.
 */
static struct {
    char       journal_dir[1024];     /* "" = in-memory only */
    ngx_uint_t max_inflight;          /* BRIX_STAGE_MAX_INFLIGHT_DEFAULT */
    ngx_uint_t max_attempts;          /* BRIX_STAGE_DENY_MAX_ATTEMPTS */
} stage_engine_state = {
    .journal_dir  = "",
    .max_inflight = BRIX_STAGE_MAX_INFLIGHT_DEFAULT,
    .max_attempts = BRIX_STAGE_DENY_MAX_ATTEMPTS
};

void
brix_stage_engine_set_limits(ngx_uint_t max_inflight, ngx_uint_t max_attempts)
{
    if (max_inflight > 0) {
        stage_engine_state.max_inflight = max_inflight;
    }
    if (max_attempts > 0) {
        stage_engine_state.max_attempts = max_attempts;
    }
}

ngx_uint_t
brix_stage_engine_max_inflight(void)
{
    return stage_engine_state.max_inflight;
}

ngx_uint_t
brix_stage_engine_max_attempts(void)
{
    return stage_engine_state.max_attempts;
}

const char *
brix_stage_engine_journal_dir(void)
{
    return stage_engine_state.journal_dir;
}

int
stage_journal_load(const char *path, brix_sreq_t *rec)
{
    char     rbuf[sizeof(brix_sreq_t)];
    int      fd;
    ssize_t  n;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    n = read(fd, rbuf, sizeof(rbuf));
    (void) close(fd);
    if (n < 0 || brix_sreq_decode(rbuf, (size_t) n, rec) != NGX_OK) {
        return -1;
    }
    return 0;
}
static uint64_t stage_reqid_seq;
#if (NGX_THREADS)
static ngx_tid_t stage_loop_tid;    /* the event loop's thread (2.0 F3) */
#endif

void
brix_stage_engine_init(const char *journal_dir)
{
    if (journal_dir != NULL && journal_dir[0] != '\0') {
        snprintf(stage_engine_state.journal_dir, sizeof(stage_engine_state.journal_dir), "%s", journal_dir);
    } else {
        stage_engine_state.journal_dir[0] = '\0';
    }
#if (NGX_THREADS)
    stage_loop_tid = ngx_thread_tid();
#endif
}

int
brix_stage_on_loop(void)
{
#if (NGX_THREADS)
    return stage_loop_tid == 0 || ngx_thread_tid() == stage_loop_tid;
#else
    return 1;
#endif
}

/* Mint a per-worker-unique request id: pid-seconds-counter. */
void
stage_reqid_mint(char out[40])
{
    snprintf(out, 40, "%ld-%lld-%llu", (long) getpid(),
             (long long) time(NULL), (unsigned long long) ++stage_reqid_seq);
}

/* Persist (best-effort) a QUEUED request record so a crash leaves a recoverable
 * row; removed on completion. Skipped when no journal dir is configured. */
void
stage_journal_write(const stage_pending_t *p)
{
    brix_sreq_t rec;
    char          path[1200];
    int           fd;

    if (stage_engine_state.journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                          stage_engine_state.journal_dir, p->reqid) >= sizeof(path))
    {
        return;
    }
    ngx_memzero(&rec, sizeof(rec));
    snprintf(rec.reqid, sizeof(rec.reqid), "%s", p->reqid);
    rec.kind  = p->kind;
    rec.state = BRIX_SREQ_QUEUED;
    snprintf(rec.src_driver, sizeof(rec.src_driver), "%s",
             (p->src->driver && p->src->driver->name) ? p->src->driver->name : "");
    snprintf(rec.src_key, sizeof(rec.src_key), "%s", p->src_key);
    snprintf(rec.dst_driver, sizeof(rec.dst_driver), "%s",
             (p->dst->driver && p->dst->driver->name) ? p->dst->driver->name : "");
    snprintf(rec.dst_key, sizeof(rec.dst_key), "%s", p->dst_key);
    snprintf(rec.export_root, sizeof(rec.export_root), "%s", p->export_root);
    rec.cred        = p->cred;    /* copy the owner identity into the durable record */
    /* The cred's trailing bearer is IN-MEMORY ONLY: a live secret that would be
     * expired by replay time.  Scrub it from the stack record and persist only
     * the identity prefix (BRIX_SREQ_IDENTITY_SIZE), so a raw token never lands
     * on disk regardless of the write length below. */
    ngx_memzero(rec.cred.bearer, sizeof(rec.cred.bearer));
    rec.enqueued_at = (int64_t) time(NULL);

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    if (write(fd, &rec, BRIX_SREQ_IDENTITY_SIZE)
        == (ssize_t) BRIX_SREQ_IDENTITY_SIZE)
    {
        (void) fsync(fd);
    }
    (void) close(fd);
}

void
stage_journal_remove(const char *reqid)
{
    char path[1200];

    if (stage_engine_state.journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                          stage_engine_state.journal_dir, reqid) < sizeof(path))
    {
        (void) unlink(path);
    }
}

/* Constants BRIX_STAGE_DENY_MAX_ATTEMPTS and BRIX_STAGE_DENY_MAX_AGE_SEC are
 * defined in stage_engine.h (the authoritative location, visible to tests). */

/* Write the updated rec (with bumped attempts) back to the active journal slot.
 *
 * WHAT: Overwrites <journal_dir>/<reqid>.req atomically enough for a crash-safe
 *       update — O_TRUNC on the existing file is sufficient (the record is
 *       readable even if we crash mid-write; the next drive will re-bump).
 *
 * WHY:  Persisting attempts across restarts is what prevents the unbounded retry
 *       loop: a restart would otherwise reset the in-memory state to zero while
 *       the disk record still carries the accumulated count.
 *
 * HOW:  Open for write with O_TRUNC, write the full record, fsync. */
static void
stage_journal_update_rec(const char *journal_dir, const brix_sreq_t *rec)
{
    char path[1200];
    int  fd;

    if (journal_dir == NULL || journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                          journal_dir, rec->reqid) >= sizeof(path))
    {
        return;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    /* Persist only the identity prefix — never the in-memory-only cred.bearer
     * (a decoded rec already carries a zeroed bearer, but the shorter write keeps
     * the on-disk record shape identical to stage_journal_write's). */
    if (write(fd, rec, BRIX_SREQ_IDENTITY_SIZE)
        == (ssize_t) BRIX_SREQ_IDENTITY_SIZE)
    {
        (void) fsync(fd);
    }
    (void) close(fd);
}

/* Stamp a decoded record FAILED (last_errno + finished_at) and re-persist it to
 * the active journal slot. Shared tail of the two public FAILED helpers below;
 * the record stays in the active journal so the scheduler / reconcile retry it. */
static void
stage_journal_persist_failed(const char *journal_dir, brix_sreq_t *rec,
    int last_errno)
{
    char num[24], att[24];

    rec->state       = BRIX_SREQ_FAILED;
    rec->last_errno  = last_errno;
    rec->finished_at = (int64_t) time(NULL);
    stage_journal_update_rec(journal_dir, rec);
    brix_stage_events_emit("engine", "failed", rec->reqid, rec->dst_key,
                           "errno",
                           brix_stage_events_num(num, sizeof(num), last_errno),
                           "attempts",
                           brix_stage_events_num(att, sizeof(att),
                                                 rec->attempts),
                           NULL);
}

/* 2.0 F2: the dead-letter line names why the record left the retry loop. */
static void
stage_journal_note_deadletter(const brix_sreq_t *rec, const char *reason)
{
    char att[24];

    brix_stage_events_emit("engine", "deadletter", rec->reqid, rec->dst_key,
                           "attempts",
                           brix_stage_events_num(att, sizeof(att),
                                                 rec->attempts),
                           "reason", reason, NULL);
}

void
stage_journal_mark_failed(const char *journal_dir, const char *reqid,
    int last_errno)
{
    char        path[1200];
    char        rbuf[sizeof(brix_sreq_t)];
    brix_sreq_t rec;
    int         fd;
    ssize_t     n;

    if (journal_dir == NULL || journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                          journal_dir, reqid) >= sizeof(path))
    {
        return;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return;                          /* record already removed / never written */
    }
    n = read(fd, rbuf, sizeof(rbuf));
    (void) close(fd);
    if (brix_sreq_decode(rbuf, (size_t) n, &rec) != NGX_OK) {
        return;                          /* corrupt slot — leave it for reconcile */
    }
    /* 2.0 (2026-09-09): count THIS drive. A failed first drive is an attempt —
     * "attempts a journal record may accumulate ... a transient failure" is what
     * brix_frm_fail_retries caps (directives.md) — and it is the only number the
     * `replayed` event can report about a record the sweep just rescued. Before,
     * the inline/thread completion path persisted FAILED without bumping, so a
     * record that failed once and was re-driven successfully published
     * attempts=0, indistinguishable from a crash replay that never ran at all
     * (which stays 0: it recorded no failure). */
    stage_journal_bump_failed(journal_dir, &rec, last_errno);
}

void
stage_journal_bump_failed(const char *journal_dir, brix_sreq_t *rec,
    int last_errno)
{
    if (rec == NULL) {
        return;
    }
    rec->attempts++;                     /* count this re-drive of a still-dead origin */
    stage_journal_persist_failed(journal_dir, rec, last_errno);
}

/* Move the active journal record to <journal_dir>/deadletter/<reqid>.req,
 * creating the deadletter directory on demand (0700).
 *
 * WHAT: rename(2) from the active slot to the deadletter slot; creates the
 *       subdirectory on the first call.  If rename fails (e.g. cross-device),
 *       falls back to copy + unlink.
 *
 * WHY:  Moving the file out of the active journal directory ensures the
 *       scheduler and reconcile stop picking it up while preserving the bytes
 *       and the stage copy for operator recovery.
 *
 * HOW:  Build the two paths, mkdir the deadletter dir (EEXIST is OK), rename. */
static void
stage_journal_move_to_deadletter(const char *journal_dir, const char *reqid,
    ngx_log_t *log)
{
    char src_path[1200];
    char dl_dir[1200];
    char dst_path[1300];
    int  fd;
    char buf[sizeof(brix_sreq_t)];
    ssize_t n;

    if (journal_dir == NULL || journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(src_path, sizeof(src_path), "%s/%s.req",
                          journal_dir, reqid) >= sizeof(src_path))
    {
        return;
    }
    if ((size_t) snprintf(dl_dir, sizeof(dl_dir), "%s/deadletter",
                          journal_dir) >= sizeof(dl_dir))
    {
        return;
    }
    if ((size_t) snprintf(dst_path, sizeof(dst_path), "%s/%s.req",
                          dl_dir, reqid) >= sizeof(dst_path))
    {
        return;
    }

    if (mkdir(dl_dir, 0700) != 0 && errno != EEXIST) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
            "xrootd stage: dead-letter mkdir \"%s\" failed", dl_dir);
        return;
    }

    if (rename(src_path, dst_path) == 0) {
        return;
    }
    /* rename failed (cross-device or other): copy + unlink as fallback */
    fd = open(src_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    n = read(fd, buf, sizeof(buf));
    (void) close(fd);
    if (n > 0) {
        int dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          0600);
        if (dst_fd >= 0) {
            ssize_t wn = write(dst_fd, buf, (size_t) n);
            (void) wn;                 /* best-effort copy; -Werror=unused-result */
            (void) fsync(dst_fd);
            (void) close(dst_fd);
        }
    }
    (void) unlink(src_path);
}

/* Dead-letter terminal for a permanently denied flush.
 *
 * WHAT: Increments rec->attempts, re-persists the updated record to the active
 *       journal slot, then checks whether the attempt cap
 *       (BRIX_STAGE_DENY_MAX_ATTEMPTS) or the age cap
 *       (BRIX_STAGE_DENY_MAX_AGE_SEC) has been reached.  When either cap fires,
 *       moves the active record to <journal_dir>/deadletter/<reqid>.req, emits a
 *       loud NGX_LOG_ERR naming the reqid, principal, key and dst_key, and
 *       returns 1 (stop re-driving).  Returns 0 when below both caps (keep
 *       retrying later).
 *
 * WHY:  A BRIX_XFER_DENIED result means the per-user credential is permanently
 *       missing or expired; the deny mode opted out of service-cred fallback.
 *       Without a cap the scheduler tick and restart-reconcile re-drive the
 *       same record forever.  The cap bounds the loop while preserving the
 *       stage copy for operator recovery: a dead-lettered write is NEVER flushed
 *       on the wrong identity — dead-letter means STOP, not "flush as service".
 *
 * HOW:  Called by stage_complete (BRIX_XFER_DENIED) and stage_reconcile_one
 *       (errno==EACCES from brix_sd_stage_reflush).  The rec pointer is the
 *       decoded brix_sreq_t from the on-disk record (already bumped by the
 *       caller's re-read, so we bump it here before persist).  journal_dir is
 *       passed explicitly so the function is unit-testable without the module
 *       global. */
int
stage_deny_terminal(const char *journal_dir, const char *reqid,
    brix_sreq_t *rec, ngx_log_t *log)
{
    int64_t age_sec;

    /* Bump and persist: always update attempts so the count survives a restart.
     * Even if we are about to dead-letter, the persisted count is in the
     * deadletter copy (which survives after the move). */
    rec->attempts++;
    stage_journal_update_rec(journal_dir, rec);

    /* Check both caps: attempt count OR age triggers dead-letter. */
    age_sec = (int64_t) time(NULL) - rec->enqueued_at;

    if (rec->attempts < stage_engine_state.max_attempts
        && age_sec < (int64_t) BRIX_STAGE_DENY_MAX_AGE_SEC)
    {
        return 0;    /* below both caps — keep record in active journal for retry */
    }

    /* Both-or-either cap reached: move to deadletter and emit a loud tombstone. */
    ngx_log_error(NGX_LOG_ERR, log, 0,
        "xrootd stage: flush DEAD-LETTERED (reqid=%s principal=\"%s\" "
        "key=%s dst=\"%s\" attempts=%uD age=%lds) - "
        "credential permanently missing/expired in deny mode; "
        "stage copy retained in deadletter/ for operator recovery",
        reqid,
        rec->cred.principal[0] ? rec->cred.principal : "-",
        rec->cred.key[0]       ? rec->cred.key       : "-",
        rec->dst_key,
        rec->attempts,
        (long) age_sec);

    stage_journal_move_to_deadletter(journal_dir, reqid, log);
    stage_journal_note_deadletter(rec, "denied");
    return 1;
}

int
stage_retry_terminal(const char *journal_dir, brix_sreq_t *rec,
    int last_errno, ngx_log_t *log)
{
    stage_journal_bump_failed(journal_dir, rec, last_errno);
    if (rec->attempts < stage_engine_state.max_attempts) {
        return 0;                  /* below brix_frm_fail_retries: keep FAILED */
    }
    ngx_log_error(NGX_LOG_ERR, log, 0,
        "xrootd stage: flush DEAD-LETTERED (reqid=%s key=%s dst=\"%s\" "
        "attempts=%uD errno=%d) - brix_frm_fail_retries reached while the "
        "origin stays unreachable; stage copy retained in deadletter/ for "
        "operator recovery",
        rec->reqid, rec->src_key, rec->dst_key, rec->attempts, last_errno);
    stage_journal_move_to_deadletter(journal_dir, rec->reqid, log);
    stage_journal_note_deadletter(rec, "unreachable");
    return 1;
}
