/*
 * stage_engine_reconcile.c — restart replay of the durable staging journal
 * (split from stage_engine.c, phase-79).
 *
 * WHAT: On worker start, re-drives every persisted staged-flush record so no
 *       write-back transfer is lost across a crash: snapshot the *.req names,
 *       decode each (size-tolerantly), and re-flush the recoverable ones through
 *       the export's rebuilt stage decorator with the persisted owner credential.
 *
 * WHY:  stage_engine.c owned three concerns and exceeded the file-size cap.
 *       Restart reconcile is a self-contained concern reached only through the
 *       journal seam (stage_journal_dir) and the public dead-letter helper. The
 *       replayable-vs-droppable classification (only a FLUSH with a durable stage
 *       copy replays; an UPLOAD/MULTIPART body is gone so its record is dropped)
 *       and the deny dead-letter cap are unchanged by the split — this is a
 *       re-home, not a behavior change.
 *
 * HOW:  brix_stage_reconcile snapshots the journal names first (records are
 *       unlinked while driving), then calls stage_reconcile_one per name, which
 *       reads + decodes the record, rebuilds the export stack via
 *       brix_vfs_backend_resolve, unwraps to the stage decorator, and calls
 *       brix_sd_stage_reflush; a permanent deny goes through stage_deny_terminal.
 */

#include "stage_engine.h"
#include "stage_engine_internal.h"
#include "fs/vfs/vfs_backend_registry.h"  /* brix_vfs_backend_resolve (reconcile) */
#include "fs/backend/cache/sd_cache.h"    /* cache instance_is / source_instance */
#include "fs/backend/stage/sd_stage.h"    /* stage instance_is / reflush         */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

        /* Transient re-drive failure (the origin is still unreachable): bump
         * attempts and re-persist the record FAILED. The higher attempt count is
         * the durable evidence that the restart replay re-drove this transfer —
         * against a recovered origin the reflush above would instead have
         * completed and unlinked the record. Kept in the active journal so a
         * later tick / restart retries it. */
        stage_journal_bump_failed(stage_journal_dir, &rec, saved_errno);
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd stage: reconcile re-flush of \"%s\" (export \"%s\") failed "
            "(errno %d attempts=%uD) - record kept FAILED for retry",
            rec.dst_key, rec.export_root, saved_errno, rec.attempts);
        return 0;
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
