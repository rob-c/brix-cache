/*
 * stage_engine.c - the one async-staging engine (phase-64 section 11). See header.
 *
 * SP1 lands the seam: the generic promote-loop mover (open src for read,
 * staged_open dst, pread -> staged_write -> staged_commit) plus the inline submit
 * front door and the unified audit line. The durable queue + waiter + restart
 * reconcile are extracted from src/frm/ in SP4 (section 13b) and attach behind
 * brix_stage_submit() without touching a caller; until then async degrades to an
 * honest inline move and the scheduler/reconcile hooks are no-ops.
 */
#include "stage_engine.h"
#include "xfer.h"   /* brix_xfer_finish + the kind/result vocabulary (ledger) */
#include "core/aio/aio.h"                /* brix_task_bind (mover thread-offload) */
#include "fs/vfs/vfs_backend_registry.h"      /* brix_vfs_backend_resolve (reconcile) */
#include "fs/backend/cache/sd_cache.h"    /* cache instance_is / source_instance    */
#include "fs/backend/stage/sd_stage.h"    /* stage instance_is / reflush            */
#include "fs/backend/ucred.h"            /* brix_sd_ucred_resolve (cred re-check)  */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Move granule: one 1 MiB driver-mediated pread/staged_write per turn (the same
 * window the legacy sd_stage promote and the xfer pump use). */
#define STAGE_ENGINE_CHUNK (1u << 20)

/* ---- SP4: the durable async queue -----------------------------------------
 * An async submit is DEFERRED rather than run inline: the request is appended to
 * a per-worker in-memory pending list (holding the live src/dst instances, which
 * are the memoised per-worker tier instances - they outlive the request) and,
 * when a journal dir is configured, persisted as a small record for crash
 * visibility/recovery. brix_stage_scheduler_tick() (a per-worker timer) drains
 * the list, runs each mover, and drops the stage copy of a completed FLUSH. This
 * generalises the FRM queue model to SD instances (section 11); the full physical
 * extraction of src/frm/ is the remaining SP4/SP5 migration. */

typedef struct stage_pending_s {
    char                     reqid[40];
    brix_stage_kind_t      kind;
    brix_sd_instance_t    *src;
    char                     src_key[1024];
    brix_sd_instance_t    *dst;
    char                     dst_key[1024];
    char                     export_root[1024]; /* anchor for restart reconcile     */
    brix_stage_cred_t        cred;              /* owner identity for async flush   */
    struct stage_pending_s  *next;
} stage_pending_t;

static stage_pending_t *stage_pending_head;          /* per-worker FIFO tail-append */
static stage_pending_t *stage_pending_tail;
static char             stage_journal_dir[1024];     /* "" = in-memory only */
static uint64_t         stage_reqid_seq;

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
static void
stage_reqid_mint(char out[40])
{
    snprintf(out, 40, "%ld-%lld-%llu", (long) getpid(),
             (long long) time(NULL), (unsigned long long) ++stage_reqid_seq);
}

/* Persist (best-effort) a QUEUED request record so a crash leaves a recoverable
 * row; removed on completion. Skipped when no journal dir is configured. */
static void
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

static void
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

/* ---- kind -> ledger vocabulary -------------------------------------------- */

/* Map an async-staging kind onto the existing unified-ledger transfer kind, so
 * one audit schema covers recall/flush/upload/multipart (section 19). */
static brix_xfer_kind_t
stage_kind_to_xfer(brix_stage_kind_t kind)
{
    switch (kind) {
    case BRIX_STAGE_RECALL:    return BRIX_XFER_TAPE;   /* tape -> cache store  */
    case BRIX_STAGE_FLUSH:     return BRIX_XFER_WT;     /* stage -> backend     */
    case BRIX_STAGE_UPLOAD:    return BRIX_XFER_STAGE;  /* body -> stage store  */
    case BRIX_STAGE_MULTIPART: return BRIX_XFER_STAGE;  /* part -> stage store  */
    }
    return BRIX_XFER_STAGE;
}

/* "in" = bytes land in our storage; "out" = bytes leave to the backend. */
static const char *
stage_kind_dir(brix_stage_kind_t kind)
{
    return (kind == BRIX_STAGE_FLUSH) ? "out" : "in";
}

const char *
brix_stage_kind_str(brix_stage_kind_t kind)
{
    switch (kind) {
    case BRIX_STAGE_RECALL:    return "recall";
    case BRIX_STAGE_FLUSH:     return "flush";
    case BRIX_STAGE_UPLOAD:    return "upload";
    case BRIX_STAGE_MULTIPART: return "multipart";
    }
    return "stage";
}

/* ---- the generic promote-loop mover --------------------------------------- */

/* The two endpoints of one move: a source instance+key read through the source
 * driver and a destination instance+key written through the staged sink. Bundled
 * into one file-local descriptor so the mover helpers thread a single argument
 * instead of four positional ones (source/dest confusion is a data-flow hazard). */
typedef struct {
    brix_sd_instance_t *src;
    const char           *src_key;
    brix_sd_instance_t *dst;
    const char           *dst_key;
} stage_move_ep_t;

/* Validate that both endpoints expose the driver ops the mover needs.
 *
 * WHAT: Returns BRIX_XFER_OK when the source can open+pread and the destination
 *       provides the full staged-write quartet (open/write/commit/abort);
 *       otherwise sets *err_out=ENOSYS and returns the endpoint-specific
 *       terminal code (SRC_ERR for a source gap, DST_ERR for a dest gap).
 *
 * WHY:  A capability-typed driver may omit ops; the mover must fail loudly and
 *       early rather than NULL-deref a missing function pointer mid-copy.
 *
 * HOW:  Two guard checks, each setting *err_out on the failing side. */
static brix_xfer_result_t
stage_move_caps_check(const stage_move_ep_t *ep, int *err_out)
{
    if (ep->src->driver->open == NULL || ep->src->driver->pread == NULL) {
        *err_out = ENOSYS;
        return BRIX_XFER_SRC_ERR;
    }
    if (ep->dst->driver->staged_open == NULL
        || ep->dst->driver->staged_write == NULL
        || ep->dst->driver->staged_commit == NULL
        || ep->dst->driver->staged_abort == NULL)
    {
        *err_out = ENOSYS;
        return BRIX_XFER_DST_ERR;
    }
    return BRIX_XFER_OK;
}

/* Resolve the source object's permission bits for a mode-preserving flush.
 *
 * WHAT: Returns the low 9 permission bits of the source, fstat-refreshed when
 *       the driver supports it, falling back to 0600 when the driver reports no
 *       mode.
 *
 * WHY:  open() may not populate snap (the posix driver fstats lazily); an
 *       accurate mode lets a flush preserve the source's permission bits. A
 *       zero mode means unknown provenance → a PRIVATE tier artifact (0600),
 *       not world-readable, consistent with the 0600/0700 physical-cache
 *       convention.
 *
 * HOW:  Copy snap, refresh via fstat if available, mask to 0777, default 0600. */
static mode_t
stage_move_source_mode(brix_sd_instance_t *src, brix_sd_obj_t *so)
{
    brix_sd_stat_t snap = so->snap;
    mode_t         mode;

    if (src->driver->fstat != NULL) {
        (void) src->driver->fstat(so, &snap);
    }
    mode = (mode_t) (snap.mode & 0777);
    if (mode == 0) {
        mode = 0600;
    }
    return mode;
}

/* Stream the whole source object into the open staged destination handle.
 *
 * WHAT: Runs the 1 MiB-granule pread -> staged_write copy loop until EOF. On
 *       success returns BRIX_XFER_OK with *bytes_out set to the total copied;
 *       on a read or write error sets *err_out=errno and returns the
 *       endpoint-specific terminal code. Neither `so` nor `ds` is closed here —
 *       the caller owns handle teardown.
 *
 * WHY:  Isolating the loop keeps the branch-heavy error handling out of the
 *       orchestration function so each has a single job.
 *
 * HOW:  Loop pread (retry on EINTR), staged_write at the running offset; break
 *       on EOF; on error early-return with the appropriate terminal code. */
static brix_xfer_result_t
stage_move_copy_loop(const stage_move_ep_t *ep, brix_sd_obj_t *so,
    brix_sd_staged_t *ds, off_t *bytes_out, int *err_out)
{
    u_char *buf;
    off_t   off = 0;
    int     oerr;

    buf = malloc(STAGE_ENGINE_CHUNK);
    if (buf == NULL) {
        *err_out = ENOMEM;
        return BRIX_XFER_DST_ERR;
    }

    for ( ;; ) {
        ssize_t r = ep->src->driver->pread(so, buf, STAGE_ENGINE_CHUNK, off);

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            oerr = errno ? errno : EIO;
            ngx_log_error(NGX_LOG_ERR, ep->src->log, oerr,
                "stage move: source read failed at off=%O (%s key=\"%s\")",
                off, ep->src->driver->name, ep->src_key);
            free(buf);
            *err_out = oerr;
            return BRIX_XFER_SRC_ERR;
        }
        if (r == 0) {
            break;                      /* EOF - the whole object is moved */
        }
        if (ep->dst->driver->staged_write(ds, buf, (size_t) r, off) < 0) {
            oerr = errno ? errno : EIO;
            ngx_log_error(NGX_LOG_ERR, ep->dst->log, oerr,
                "stage move: dest write failed at off=%O (%s key=\"%s\")",
                off, ep->dst->driver->name, ep->dst_key);
            free(buf);
            *err_out = oerr;
            return BRIX_XFER_DST_ERR;
        }
        off += r;
    }

    free(buf);
    *bytes_out = off;
    return BRIX_XFER_OK;
}

/* Copy the whole object `src_key` on `src` into `dst_key` on `dst` by reading
 * through the source driver and writing through the destination's staged sink,
 * then committing it atomically. Both endpoints are SD instances, so this same
 * loop moves bytes between ANY two tiers (posix stage -> remote backend, tape
 * buffer -> posix cache, ...). On success *bytes_out carries the moved size and
 * the staged handle is consumed by commit; on failure the staged temp is aborted
 * and *err_out carries errno.  `cred` is the per-user credential for the dst
 * staged_open (NULL = service credential / driver default). Returns an
 * brix_xfer_result_t terminal code. */
static brix_xfer_result_t
stage_engine_move(const stage_move_ep_t *ep, const brix_sd_cred_t *cred,
    off_t *bytes_out, int *err_out)
{
    brix_sd_obj_t     *so;
    brix_sd_staged_t  *ds;
    brix_xfer_result_t res;
    int                 oerr = 0;
    mode_t              mode;

    res = stage_move_caps_check(ep, err_out);
    if (res != BRIX_XFER_OK) {
        return res;
    }

    so = ep->src->driver->open(ep->src, ep->src_key, BRIX_SD_O_READ, 0, &oerr);
    if (so == NULL) {
        *err_out = oerr ? oerr : EIO;
        ngx_log_error(NGX_LOG_ERR, ep->src->log, *err_out,
            "stage move: source open failed (%s key=\"%s\")",
            ep->src->driver->name, ep->src_key);
        return BRIX_XFER_SRC_ERR;
    }

    mode = stage_move_source_mode(ep->src, so);

    /* Use the cred-aware staged_open for the destination so the backend driver
     * presents the per-user x509 proxy when flushing to a remote origin.  The
     * source (stage store) is always local so no cred is needed there. */
    ds = brix_sd_staged_open_maybe_cred(ep->dst, ep->dst_key, mode, cred, &oerr);
    if (ds == NULL) {
        ep->src->driver->close(so);
        *err_out = oerr ? oerr : EIO;
        ngx_log_error(NGX_LOG_ERR, ep->dst->log, *err_out,
            "stage move: dest staged_open failed (%s key=\"%s\")",
            ep->dst->driver->name, ep->dst_key);
        return BRIX_XFER_DST_ERR;
    }

    res = stage_move_copy_loop(ep, so, ds, bytes_out, err_out);
    ep->src->driver->close(so);
    if (res != BRIX_XFER_OK) {
        ep->dst->driver->staged_abort(ds);     /* copy failed - drop the temp */
        return res;
    }

    if (ep->dst->driver->staged_commit(ds, 0) != NGX_OK) {
        oerr = errno ? errno : EIO;
        ngx_log_error(NGX_LOG_ERR, ep->dst->log, oerr,
            "stage move: dest commit failed (%s key=\"%s\")",
            ep->dst->driver->name, ep->dst_key);
        ep->dst->driver->staged_abort(ds);     /* commit failed - drop the temp */
        *err_out = oerr;
        return BRIX_XFER_COMMIT_ERR;
    }

    return BRIX_XFER_OK;
}

/*
 * Move the object inline, applying optional per-user credential re-resolution
 * before touching the origin, and booking one unified audit line.
 *
 * WHAT: Re-resolves the per-user x509 proxy (if cred != NULL && cred->key[0])
 *       via brix_sd_ucred_resolve before calling the byte mover.  On success
 *       the resolved path is threaded into brix_sd_cred_t and passed to
 *       stage_engine_move so the destination driver presents the user's identity.
 *       On failure with cred->deny set, returns BRIX_XFER_DENIED without moving
 *       data (hard EACCES, audit line emitted).  On failure without deny, warns
 *       and falls back to the service credential.
 *
 * WHY:  A detached async flush (possibly after a restart) must authenticate to
 *       the origin as the ORIGINAL user — not the service account — for per-user
 *       quota / audit / ACL enforcement on the backend.  Deny mode makes the
 *       missing-credential case loud rather than silently promoting.
 *
 * HOW:  1. If cred is NULL or key[0]=='\0': move with service credential (NULL).
 *       2. Call brix_sd_ucred_resolve(dir, key, &ru): on OK build brix_sd_cred_t
 *          (x509_proxy=ru.path, principal=cred->principal) and move with it.
 *       3. On failure + deny=1: log ERR, book DENIED audit line, EACCES, return.
 *       4. On failure + deny=0: log WARN, move with service cred (credp=NULL).
 *       5. Pass the principal through to the audit line (was hard-coded NULL).
 */
static brix_xfer_result_t
stage_engine_run(brix_stage_kind_t kind, brix_sd_instance_t *src,
    const char *src_key, brix_sd_instance_t *dst, const char *dst_key,
    const brix_stage_cred_t *cred)
{
    brix_xfer_result_t   res;
    off_t                 bytes = 0;
    int                   oerr = 0;
    ngx_log_t            *log = (dst->log != NULL) ? dst->log : src->log;
    brix_sd_cred_t        sdcred;
    const brix_sd_cred_t *credp = NULL;
    const char           *principal = NULL;

    if (cred != NULL && cred->principal[0] != '\0') {
        principal = cred->principal;
    }

    if (cred != NULL && cred->key[0] != '\0') {
        brix_sd_ucred_t ru;

        ngx_memzero(&ru, sizeof(ru));
        if (brix_sd_ucred_resolve(cred->dir, cred->key, &ru) == NGX_OK) {
            ngx_memzero(&sdcred, sizeof(sdcred));
            sdcred.x509_proxy = ru.path;
            sdcred.principal  = cred->principal;
            credp = &sdcred;
        } else if (cred->deny) {
            /* Hard deny: missing or expired per-user credential; refuse to flush
             * under the service identity — the caller opted into strict mode. */
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "xrootd stage: %s of \"%s\" DENIED - per-user credential "
                "key=%s principal=\"%s\" %s (fallback=deny)",
                brix_stage_kind_str(kind), dst_key, cred->key,
                cred->principal[0] ? cred->principal : "-",
                ru.expired ? "EXPIRED" : "missing");
            brix_xfer_finish(stage_kind_to_xfer(kind), stage_kind_dir(kind),
                dst_key, principal, 0, BRIX_XFER_DENIED, EACCES, log);
            errno = EACCES;
            return BRIX_XFER_DENIED;
        } else {
            /* Soft fallback: warn and continue under the service credential. */
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "xrootd stage: per-user credential key=%s %s - flushing "
                "\"%s\" with the service credential (fallback=allow)",
                cred->key, ru.expired ? "EXPIRED" : "missing", dst_key);
        }
    }

    {
        stage_move_ep_t ep = { src, src_key, dst, dst_key };

        res = stage_engine_move(&ep, credp, &bytes, &oerr);
    }

    /* One unified audit line per terminal transfer (transport-agnostic). */
    brix_xfer_finish(stage_kind_to_xfer(kind), stage_kind_dir(kind), dst_key,
        principal, (size_t) bytes, res, (res == BRIX_XFER_OK) ? 0 : oerr, log);

    if (res != BRIX_XFER_OK && oerr != 0) {
        errno = oerr;
    }
    return res;
}

/* ---- the public front doors ----------------------------------------------- */

const char *
brix_stage_submit(brix_stage_kind_t kind, brix_sd_instance_t *src,
    const char *src_key, brix_sd_instance_t *dst, const char *dst_key,
    const brix_stage_opts_t *opts)
{
    static const char ran_inline[] = "";
    static char       last_reqid[40];   /* event-loop single-threaded: stable enough */
    stage_pending_t  *p;

    if (src == NULL || src_key == NULL || dst == NULL || dst_key == NULL
        || src->driver == NULL || dst->driver == NULL)
    {
        return NULL;
    }

    /* Synchronous (the default): move now and return "" = done inline. */
    if (opts == NULL || !opts->async) {
        (void) stage_engine_run(kind, src, src_key, dst, dst_key,
                                (opts != NULL) ? opts->cred : NULL);
        return ran_inline;
    }

    /* Asynchronous: defer to the scheduler (durable). The src/dst instances are
     * the memoised per-worker tier instances, so holding them is safe. */
    p = calloc(1, sizeof(*p));
    if (p == NULL) {
        (void) stage_engine_run(kind, src, src_key, dst, dst_key, opts->cred);
        return ran_inline;
    }
    stage_reqid_mint(p->reqid);
    p->kind = kind;
    p->src  = src;
    p->dst  = dst;
    snprintf(p->src_key, sizeof(p->src_key), "%s", src_key);
    snprintf(p->dst_key, sizeof(p->dst_key), "%s", dst_key);
    if (opts->export_root != NULL) {
        snprintf(p->export_root, sizeof(p->export_root), "%s", opts->export_root);
    }
    if (opts->cred != NULL) {
        p->cred = *opts->cred;    /* copy the owner identity into the pending item */
    }

    if (stage_pending_tail != NULL) {
        stage_pending_tail->next = p;
    } else {
        stage_pending_head = p;
    }
    stage_pending_tail = p;

    stage_journal_write(p);
    snprintf(last_reqid, sizeof(last_reqid), "%s", p->reqid);
    return last_reqid;          /* non-empty = deferred; the caller may park on it */
}

/* ---- brix_sreq_decode ---------------------------------------------------
 *
 * WHAT: NGX_OK with *out filled from a full-size OR legacy (pre-cred) record
 *       buffer; NGX_ERROR for any other size (corrupt).
 *
 * WHY:  brix_sreq_t grew an appended cred; journals written before the upgrade
 *       must replay (with a zeroed cred -> service-credential flush, matching
 *       their pre-feature semantics).
 *
 * HOW:  legacy size == offsetof(brix_sreq_t, cred) because the cred is the
 *       final member; memzero then copy exactly n bytes. */
ngx_int_t
brix_sreq_decode(const void *buf, size_t n, brix_sreq_t *out)
{
    if (n != sizeof(brix_sreq_t) && n != offsetof(brix_sreq_t, cred)) {
        return NGX_ERROR;
    }
    ngx_memzero(out, sizeof(*out));
    ngx_memcpy(out, buf, n);
    return NGX_OK;
}

/* ---- brix_stage_run_inline_cred + brix_stage_run_inline -------------------
 *
 * WHAT: brix_stage_run_inline_cred runs the mover inline with an explicit
 *       per-user credential threaded into stage_engine_run.  brix_stage_run_inline
 *       is the zero-cred (service-credential) wrapper that existing callers use.
 *
 * WHY:  Separate entry points let callers that hold a resolved credential avoid a
 *       second lookup, while keeping the common no-cred path at its original name.
 *
 * HOW:  Both validate arguments then delegate to stage_engine_run. */
ngx_int_t
brix_stage_run_inline_cred(brix_stage_kind_t kind, brix_sd_instance_t *src,
    const char *src_key, brix_sd_instance_t *dst, const char *dst_key,
    const brix_stage_cred_t *cred)
{
    if (src == NULL || src_key == NULL || dst == NULL || dst_key == NULL
        || src->driver == NULL || dst->driver == NULL)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }
    return (stage_engine_run(kind, src, src_key, dst, dst_key, cred)
            == BRIX_XFER_OK) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
brix_stage_run_inline(brix_stage_kind_t kind, brix_sd_instance_t *src,
    const char *src_key, brix_sd_instance_t *dst, const char *dst_key)
{
    return brix_stage_run_inline_cred(kind, src, src_key, dst, dst_key, NULL);
}

/* Max transfers a single tick STARTS, so a backlog never monopolises the worker.
 * The next tick continues the queue. */
#define STAGE_TICK_BUDGET 32

/* Terminal post-processing for a completed mover (inline or thread): on success a
 * FLUSH drops the now-redundant stage copy (the migrate semantic, §9.5) and the
 * journal record is removed; on a permanent deny (BRIX_XFER_DENIED) the attempt
 * counter is bumped and, when the cap is reached, the record is moved to the
 * deadletter/ subdirectory (stage copy kept for operator recovery); on any other
 * failure the record is KEPT (transient — the reconcile retries on restart or a
 * later tick re-drives it). Shared by both the scheduler and thread paths.
 *
 * WHAT: Distinguishes three outcomes: OK (remove journal + drop stage copy),
 *       DENIED (call stage_deny_terminal to enforce the dead-letter cap), and
 *       all other errors (WARN + keep for retry).
 *
 * WHY:  A BRIX_XFER_DENIED result is not transient: the per-user credential is
 *       permanently missing/expired in deny mode.  Treating it like a transient
 *       error leaves the record looping forever.  The dead-letter cap bounds
 *       that loop while preserving the data for operator recovery.
 *
 * HOW:  On DENIED, re-reads the on-disk record to get the current attempts
 *       count (surviving across restarts), then delegates to stage_deny_terminal
 *       which bumps, persists, and conditionally moves to deadletter/. */
static void
stage_complete(brix_stage_kind_t kind, brix_sd_instance_t *src,
    const char *src_key, const char *dst_key, const char *reqid,
    brix_xfer_result_t res, ngx_log_t *log)
{
    if (res == BRIX_XFER_OK) {
        if (kind == BRIX_STAGE_FLUSH && src->driver->unlink != NULL) {
            (void) src->driver->unlink(src, src_key, 0);
        }
        stage_journal_remove(reqid);
        return;
    }

    if (res == BRIX_XFER_DENIED && stage_journal_dir[0] != '\0') {
        /* Permanent deny: re-read the on-disk record to get the current
         * attempts count (may have been bumped by a prior drive after a
         * restart), then apply the dead-letter cap. */
        char        path[1200];
        char        rbuf[sizeof(brix_sreq_t)];
        brix_sreq_t rec;
        int         fd;
        ssize_t     n;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                              stage_journal_dir, reqid) < sizeof(path))
        {
            fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                n = read(fd, rbuf, sizeof(rbuf));
                (void) close(fd);
                if (brix_sreq_decode(rbuf, (size_t) n, &rec) == NGX_OK) {
                    (void) stage_deny_terminal(stage_journal_dir, reqid, &rec,
                                               log);
                    return;
                }
            }
        }
        /* Journal record unreadable: fall through to the WARN+keep path so
         * the transient I/O error does not silently swallow the failure. */
    }

    ngx_log_error(NGX_LOG_WARN, log, 0,
        "xrootd stage: deferred %s of \"%s\" failed (reqid %s) - record kept",
        brix_stage_kind_str(kind), dst_key, reqid);
}

#if (NGX_THREADS)

/* In-flight offloaded movers (per-worker), bounded so a burst never floods the
 * thread pool nor unbounds memory. The tick stops starting new ones at the cap and
 * resumes next tick as they drain. */
static ngx_uint_t stage_inflight;
#define STAGE_MAX_INFLIGHT 8

/* The off-loop mover task (lives on its own small pool, freed in the done event).
 * `cred` carries the owner identity so the flush thread can re-resolve the per-user
 * proxy at flush time via stage_engine_run's cred logic. */
typedef struct {
    ngx_pool_t           *pool;
    brix_stage_kind_t   kind;
    brix_sd_instance_t *src;
    brix_sd_instance_t *dst;
    brix_xfer_result_t  res;
    ngx_log_t            *log;
    char                  reqid[40];
    char                  src_key[1024];
    char                  dst_key[1024];
    brix_stage_cred_t     cred;          /* owner identity for per-user cred check */
} stage_flush_task_t;

static void
stage_flush_thread(void *data, ngx_log_t *log)
{
    stage_flush_task_t      *t    = data;
    const brix_stage_cred_t *credp = (t->cred.key[0] != '\0') ? &t->cred : NULL;

    (void) log;
    t->res = stage_engine_run(t->kind, t->src, t->src_key, t->dst, t->dst_key,
                              credp);
}

static void
stage_flush_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    stage_flush_task_t *t = task->ctx;
    ngx_pool_t         *pool = t->pool;

    if (stage_inflight > 0) {
        stage_inflight--;
    }
    stage_complete(t->kind, t->src, t->src_key, t->dst_key, t->reqid, t->res,
                   t->log);
    ngx_destroy_pool(pool);              /* frees the task + ctx */
}

/* Post `p`'s mover to `pool`. NGX_OK = posted (caller drops the pending item; the
 * journal record persists until the thread completes); NGX_DECLINED = setup failed
 * (caller runs it inline). */
static ngx_int_t
stage_flush_offload(const stage_pending_t *p, ngx_thread_pool_t *pool)
{
    ngx_log_t          *log = (p->dst->log != NULL) ? p->dst->log : p->src->log;
    ngx_pool_t         *tp;
    ngx_thread_task_t  *task;
    stage_flush_task_t *t;

    if (log == NULL) {
        log = ngx_cycle->log;
    }
    tp = ngx_create_pool(4096, log);
    if (tp == NULL) {
        return NGX_DECLINED;
    }
    task = ngx_thread_task_alloc(tp, sizeof(stage_flush_task_t));
    if (task == NULL) {
        ngx_destroy_pool(tp);
        return NGX_DECLINED;
    }
    t = task->ctx;
    t->pool = tp;
    t->kind = p->kind;
    t->src  = p->src;
    t->dst  = p->dst;
    t->res  = BRIX_XFER_DST_ERR;
    t->log  = log;
    t->cred = p->cred;    /* copy owner identity for cred re-resolution in thread */
    snprintf(t->reqid, sizeof(t->reqid), "%s", p->reqid);
    snprintf(t->src_key, sizeof(t->src_key), "%s", p->src_key);
    snprintf(t->dst_key, sizeof(t->dst_key), "%s", p->dst_key);

    brix_task_bind(task, stage_flush_thread, stage_flush_done);
    task->event.log = log;
    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        ngx_destroy_pool(tp);
        return NGX_DECLINED;
    }
    stage_inflight++;
    return NGX_OK;
}

/* The export's async thread pool (the common "default" pool). NULL = serve inline. */
static ngx_thread_pool_t *
stage_thread_pool(void)
{
    static ngx_str_t name = ngx_string("default");

    return (ngx_cycle != NULL)
         ? ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name) : NULL;
}

#endif /* NGX_THREADS */

void
brix_stage_scheduler_tick(void)
{
    int budget = STAGE_TICK_BUDGET;
#if (NGX_THREADS)
    ngx_thread_pool_t *pool = stage_thread_pool();
#endif

    while (stage_pending_head != NULL && budget-- > 0) {
        stage_pending_t     *p = stage_pending_head;
        brix_xfer_result_t res;
        ngx_log_t           *log = (p->dst->log != NULL) ? p->dst->log
                                                         : p->src->log;

#if (NGX_THREADS)
        /* Run the mover OFF the event loop so a flush to a REMOTE backend (or from a
         * remote stage store) never blocks/fails on the un-pumped loop. Bounded
         * in-flight; the durable journal record is what survives a crash mid-flush
         * (recovered by reconcile), so the on-disk record is dropped only in the
         * completion. */
        if (pool != NULL) {
            if (stage_inflight >= STAGE_MAX_INFLIGHT) {
                break;                      /* let in-flight drain; resume next tick */
            }
            if (stage_flush_offload(p, pool) == NGX_OK) {
                stage_pending_head = p->next;
                if (stage_pending_head == NULL) {
                    stage_pending_tail = NULL;
                }
                free(p);
                continue;
            }
            /* offload setup failed - fall through to the inline path */
        }
#endif

        stage_pending_head = p->next;
        if (stage_pending_head == NULL) {
            stage_pending_tail = NULL;
        }
        {
            const brix_stage_cred_t *credp =
                (p->cred.key[0] != '\0') ? &p->cred : NULL;
            res = stage_engine_run(p->kind, p->src, p->src_key, p->dst,
                                   p->dst_key, credp);
        }
        stage_complete(p->kind, p->src, p->src_key, p->dst_key, p->reqid, res,
                       log);
        free(p);
    }
}

/* Re-flush ONE persisted record. Only a staged-write FLUSH is replayable: its
 * bytes are durable on the stage store and the export anchor lets us rebuild both
 * tiers. An UPLOAD/MULTIPART (client body -> stage) cannot be replayed - the body
 * is gone after a crash, so the client retries; such records are dropped, never
 * silently re-driven wrong. Returns 1 replayed / 0 kept (retry) / -1 dropped. */
/* Re-flush ONE persisted record.
 *
 * WHAT: Reads the journal record (up to sizeof brix_sreq_t bytes), decodes it
 *       with size-tolerance via brix_sreq_decode, then re-drives a FLUSH through
 *       the export's stage decorator with the persisted owner credential.
 *
 * WHY:  Only a staged-write FLUSH is replayable: its bytes are durable on the
 *       stage store and the export anchor lets us rebuild both tiers.  An
 *       UPLOAD/MULTIPART (client body -> stage) cannot be replayed — the body is
 *       gone after a crash, so the client retries; such records are dropped.
 *       The size-tolerant decode allows journals written before the cred field
 *       was appended to be replayed with a zeroed cred (= service-credential flush,
 *       preserving pre-feature semantics).
 *
 * HOW:  Read into a max-size buffer, call brix_sreq_decode; on decode failure
 *       drop the record.  Pass the cred (NULL when key[0]=='\0') to reflush.
 *       Returns 1 replayed / 0 kept (retry) / -1 dropped. */
static int
stage_reconcile_one(const char *path, ngx_log_t *log)
{
    char                rbuf[sizeof(brix_sreq_t)];
    brix_sreq_t         rec;
    brix_sd_instance_t *inst;
    const brix_stage_cred_t *credp;
    int                  fd;
    ssize_t              n;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    n = read(fd, rbuf, sizeof(rbuf));
    (void) close(fd);

    if (brix_sreq_decode(rbuf, (size_t) n, &rec) != NGX_OK) {
        (void) unlink(path);                 /* corrupt/short/oversized record - drop */
        return -1;
    }
    if (rec.kind != BRIX_STAGE_FLUSH || rec.export_root[0] == '\0') {
        (void) unlink(path);                 /* not a recoverable staged write */
        return -1;
    }

    credp = (rec.cred.key[0] != '\0') ? &rec.cred : NULL;

    /* Rebuild the export's composed stack and unwrap to its stage decorator.
     * On success the stage copy is already dropped by reflush. On a permanent
     * deny (EACCES from reflush + deny cred), apply the dead-letter cap so the
     * reconcile does not re-drive the same record forever. On any other failure,
     * keep the record for a later transient retry. */
    inst = brix_vfs_backend_resolve(rec.export_root, log);
    if (brix_sd_cache_instance_is(inst)) {
        inst = brix_sd_cache_source_instance(inst);
    }
    if (brix_sd_stage_instance_is(inst)) {
        ngx_int_t rc;
        int       saved_errno;

        errno = 0;
        rc    = brix_sd_stage_reflush(inst, rec.dst_key, credp);
        saved_errno = errno;

        if (rc == NGX_OK) {
            (void) unlink(path);             /* re-flushed + stage copy dropped */
            return 1;
        }

        /* Distinguish a permanent deny (EACCES, deny cred) from a transient
         * error so dead-letter logic applies only to the former. */
        if (saved_errno == EACCES && rec.cred.deny) {
            /* stage_deny_terminal bumps attempts, persists, moves to deadletter
             * when the cap is reached.  The `path` is the active record; we use
             * stage_journal_dir + reqid (not path) so the helper can rebuild the
             * active and deadletter paths itself from the canonical dir. */
            if (stage_deny_terminal(stage_journal_dir, rec.reqid, &rec, log)) {
                return -1;   /* dead-lettered = dropped from active journal */
            }
            /* Below the cap: keep for retry (same as transient). */
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "xrootd stage: reconcile denied flush \"%s\" (export \"%s\" "
                "attempts=%uD) - record kept (below dead-letter cap)",
                rec.dst_key, rec.export_root, rec.attempts);
            return 0;
        }
    }

    /* Backend unreachable / no stage tier now: keep the record for a later retry. */
    ngx_log_error(NGX_LOG_WARN, log, 0,
        "xrootd stage: reconcile could not re-flush \"%s\" (export \"%s\") - "
        "record kept for retry", rec.dst_key, rec.export_root);
    return 0;
}

/* Snapshot the *.req journal record names from `dir` into `names`.
 *
 * WHAT: Opens `dir`, collects up to `cap` names ending in ".req" (each shorter
 *       than the per-slot width) into `names`, and returns the count. Returns 0
 *       when the directory cannot be opened.
 *
 * WHY:  The driving loop unlinks records as it replays/drops them, so the name
 *       set must be snapshotted before driving rather than iterated live.
 *
 * HOW:  readdir loop with a suffix + length filter, copying each accepted name
 *       (with its NUL) into the caller's fixed-width array. */
static ngx_uint_t
stage_reconcile_snapshot(const char *dir, char names[][256], ngx_uint_t cap)
{
    DIR           *d;
    struct dirent *de;
    ngx_uint_t     ncount = 0;

    d = opendir(dir);
    if (d == NULL) {
        return 0;
    }
    while ((de = readdir(d)) != NULL && ncount < cap) {
        size_t nlen = strlen(de->d_name);

        if (nlen > 4 && nlen < 256
            && strcmp(de->d_name + nlen - 4, ".req") == 0)
        {
            memcpy(names[ncount], de->d_name, nlen + 1);
            ncount++;
        }
    }
    closedir(d);
    return ncount;
}

void
brix_stage_reconcile(brix_stage_queue_t *queue)
{
    char       names[1024][256];
    ngx_uint_t ncount, i, replayed = 0, kept = 0, dropped = 0;
    ngx_log_t *log;

    (void) queue;
    if (stage_journal_dir[0] == '\0') {
        return;                              /* no durable journal configured */
    }
    /* Reconcile REPORTS every replay/keep/drop decision through ngx_log_error,
     * whose macro dereferences the log unconditionally — a NULL log here is a
     * crash, not a quiet run. Without a cycle (pre-init or a bare harness)
     * DEFER: return with the journal untouched so a properly-initialised boot
     * replays it. The in-tree caller (worker-0 init_process) always has one. */
    if (ngx_cycle == NULL) {
        return;
    }
    log = ngx_cycle->log;

    /* Snapshot the *.req names first (we unlink while driving). */
    ncount = stage_reconcile_snapshot(stage_journal_dir, names, 1024);

    for (i = 0; i < ncount; i++) {
        char path[1300];
        int  r;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s",
                              stage_journal_dir, names[i]) >= sizeof(path))
        {
            continue;
        }
        r = stage_reconcile_one(path, log);
        if (r > 0)      { replayed++; }
        else if (r < 0) { dropped++;  }
        else            { kept++;     }
    }

    if (replayed > 0 || kept > 0 || dropped > 0) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "xrootd stage: restart reconcile - %ui staged flush(es) replayed, "
            "%ui kept for retry, %ui dropped", replayed, kept, dropped);
    }
}
