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

char            stage_journal_dir[1024];     /* "" = in-memory only */
static uint64_t stage_reqid_seq;

void
brix_stage_engine_init(const char *journal_dir)
{
    if (journal_dir != NULL && journal_dir[0] != '\0') {
        snprintf(stage_journal_dir, sizeof(stage_journal_dir), "%s", journal_dir);
    } else {
        stage_journal_dir[0] = '\0';
    }
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

    if (stage_journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                          stage_journal_dir, p->reqid) >= sizeof(path))
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
    rec.enqueued_at = (int64_t) time(NULL);

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    if (write(fd, &rec, sizeof(rec)) == (ssize_t) sizeof(rec)) {
        (void) fsync(fd);
    }
    (void) close(fd);
}

void
stage_journal_remove(const char *reqid)
{
    char path[1200];

    if (stage_journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                          stage_journal_dir, reqid) < sizeof(path))
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
    if (write(fd, rec, sizeof(*rec)) == (ssize_t) sizeof(*rec)) {
        (void) fsync(fd);
    }
    (void) close(fd);
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

    if (rec->attempts < BRIX_STAGE_DENY_MAX_ATTEMPTS
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
    return 1;
}
