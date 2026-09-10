/*
 * sd_frm_staged.c — the nearline driver's staged-write family + C3 barrier.
 *
 * WHAT: staged_open/write/commit/abort (online buffer -> tape migrate on
 *       commit), the phase-107 C3 sync_publish barrier and the C6 atomic
 *       exchange, split out of sd_frm.c when the driver TU hit the 600-line
 *       cap (coding-standards §1).
 *
 * WHY:  the staged family is one coherent lifecycle (create_online, pwrite,
 *       migrate|purge) with its own handle state; it shares only sd_frm_state
 *       and the MSS vtable with the rest of the driver.
 *
 * HOW:  state + prototypes live in sd_frm_internal.h; the vtable rows stay in
 *       sd_frm.c. The C3 barrier delegates to the MSS adapter's sync_publish
 *       verb (NULL verb = nothing local to flush -> NGX_OK).
 */
#include "sd_frm.h"
#include "sd_frm_mss.h"
#include "sd_frm_internal.h"
#include "fs/backend/posix/sd_posix_internal.h"  /* sd_posix_reserve (C5) */
#include "fs/xfer/stage_events.h"                /* 2.0 F2 StageEvents feed */
#include "fs/xfer/stage_engine.h"                /* 2.0 F3 deferred seal    */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- 2.0 F3: publish, and the archiver's deferred seal ------------------ */

ngx_int_t
brix_sd_frm_seal(brix_sd_instance_t *inst, const char *key)
{
    sd_frm_state *st;
    char          num[24];

    if (!brix_sd_frm_instance_is(inst) || key == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    st = SD_FRM_ST(inst);
    if (st->mss->seal == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (st->mss->seal(st->mss_ctx, key) != 0) {
        brix_stage_events_emit("frm", "seal-failed", NULL, key, "errno",
                               brix_stage_events_num(num, sizeof(num), errno),
                               NULL);
        return NGX_ERROR;
    }
    brix_stage_events_emit("frm", "seal-done", NULL, key, NULL);
    return NGX_OK;
}

/* migrate() answered BRIX_MSS_MIGRATE_DEFERRED: `key` is a dataset completion
 * marker and sealing it (compose + ship the archive) is minutes of tape work
 * that must not run on the client's close. Hand it to the durable stage
 * engine (kind archive: journaled, retried on the brix_frm_fail_backoff
 * sweep, replayed after a restart, dead-lettered at brix_frm_fail_retries)
 * when this is the event loop and a journal is configured. Without a
 * journal, or from the engine's own mover thread (a FLUSH whose destination
 * is this tier -- the submit FIFO is the loop's), seal inline right here. */
static ngx_int_t
frm_seal_defer(sd_frm_state *fst, brix_sd_instance_t *inst, const char *key)
{
    brix_stage_opts_t opts;

    if (brix_stage_engine_journal_dir()[0] == '\0' || !brix_stage_on_loop()) {
        return brix_sd_frm_seal(inst, key);
    }
    ngx_memzero(&opts, sizeof(opts));
    opts.async       = 1;
    opts.export_root = fst->export_root;
    if (brix_stage_submit(BRIX_STAGE_ARCHIVE, inst, key, inst, key, &opts)
        == NULL)
    {
        return brix_sd_frm_seal(inst, key);  /* refused the handle: inline */
    }
    return NGX_OK;                           /* queued (or ran inline) */
}

/* Publish `key` from the online buffer to tape: the adapter's migrate ships
 * it now (0), fails (-1, errno; the frm migrate-failed event carries it), or
 * -- a dataset completion marker under the archiver -- defers the seal. */
static ngx_int_t
frm_publish(brix_sd_instance_t *inst, const char *key)
{
    sd_frm_state *fst = SD_FRM_ST(inst);
    int           rc;

    rc = fst->mss->migrate(fst->mss_ctx, key);
    if (rc < 0) {
        char num[24];

        brix_stage_events_emit("frm", "migrate-failed", NULL, key, "errno",
                               brix_stage_events_num(num, sizeof(num), errno),
                               NULL);
        return NGX_ERROR;
    }
    if (rc == BRIX_MSS_MIGRATE_DEFERRED) {
        return frm_seal_defer(fst, inst, key);
    }
    brix_stage_events_emit("frm", "migrate-done", NULL, key, NULL);
    return NGX_OK;
}

/* ---- migrate via the staged-write path (online buffer -> tape on commit) ---- */

brix_sd_staged_t *
sd_frm_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, off_t declared_size, int *err_out)
{
    sd_frm_state        *st = SD_FRM_ST(inst);
    sd_frm_staged_state *ss;
    brix_sd_staged_t  *h;
    int                  fd;

    fd = st->mss->create_online(st->mss_ctx, final_path, mode);
    if (fd < 0) {
        if (err_out) { *err_out = errno ? errno : EIO; }
        return NULL;
    }

    /* Phase-107 C5: the ONLINE BUFFER is the disk-resident half this driver
     * owns — preallocate the declared final size there so a buffer that cannot
     * hold the object refuses the OPEN (ENOSPC/EDQUOT), not the migrate after
     * hours of streaming. Tape-side reservation stays the MSS tier's own
     * scheduling concern. Anything short of "no space" is advisory. */
    if (declared_size > 0) {
        brix_sd_obj_t shell;

        ngx_memzero(&shell, sizeof(shell));
        shell.fd = fd;
        if (sd_posix_reserve(&shell, declared_size) != NGX_OK
            && (errno == ENOSPC || errno == EDQUOT))
        {
            int err = errno;

            (void) close(fd);
            (void) st->mss->purge(st->mss_ctx, final_path);
            if (err_out) { *err_out = err; }
            errno = err;
            return NULL;
        }
    }

    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        (void) close(fd);
        free(ss);
        free(h);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    ss->fst = st;
    ss->fd  = fd;
    ngx_cpystrn((u_char *) ss->key, (u_char *) final_path, sizeof(ss->key));
    h->inst  = inst;
    h->state = ss;
    return h;
}

ssize_t
sd_frm_staged_write(brix_sd_staged_t *st, const void *buf, size_t len, off_t off)
{
    sd_frm_staged_state *ss = st->state;

    return pwrite(ss->fd, buf, len, off);
}

/*
 * WHAT: Evaluate a typed publish precondition (phase-107 C6) for a staged
 *       commit, BEFORE the migrate, so a refusal leaves the tape copy
 *       untouched (the caller's staged_abort then purges the buffer temp).
 * WHY:  The online buffer under `key` at commit time is this handle's OWN —
 *       staged_open created it — so the adapter's residency probe answers
 *       ONLINE for every staged create.  Judged by residency, ABSENT (a
 *       kXR_new open, an If-None-Match PUT) refused EVERY create with EEXIST:
 *       no root:// or HTTP create could ever commit to a tape export
 *       (phase-115 W3.1).
 * HOW:  ABSENT asks the durable copy (`on_tape`, phase-115 W3.2).  An
 *       adapter without the verb cannot see past the buffer, so the open-time
 *       existence check stands alone — every kind is ADVISORY here anyway
 *       (pre->atomic stays 0, the W7 checklist's verdict for frm; §3.5
 *       forbids claiming atomicity the MSS never gave).  MATCH_* keep the
 *       residency stat: with the buffer shadowing the target they compare
 *       against what is online, a limitation recorded with the phase.
 */
static ngx_int_t
frm_commit_precond(const sd_frm_staged_state *ss, const brix_sd_precond_t *pre)
{
    const brix_mss_adapter_t *mss = ss->fst->mss;
    off_t                     tsz = 0;
    time_t                    tmt = 0;
    int                       res;

    if (pre == NULL || pre->kind == BRIX_SD_PRECOND_NONE) {
        return NGX_OK;
    }
    if (pre->kind == BRIX_SD_PRECOND_ABSENT) {
        if (mss->on_tape != NULL
            && mss->on_tape(ss->fst->mss_ctx, ss->key) == 1)
        {
            errno = EEXIST;
            return NGX_ERROR;
        }
        return NGX_OK;
    }
    res = mss->residency(ss->fst->mss_ctx, ss->key, &tsz, &tmt);
    if (res == BRIX_RESIDENCY_ABSENT) {
        errno = ECANCELED;           /* MATCH_* against a missing target */
        return NGX_ERROR;
    }
    if (brix_sd_precond_eval_stat(pre, tsz, tmt) != 0) {
        return NGX_ERROR;            /* errno = ECANCELED / ENOTSUP */
    }
    return NGX_OK;
}

ngx_int_t
sd_frm_staged_commit(brix_sd_staged_t *st, brix_sd_precond_t *pre)
{
    sd_frm_staged_state *ss = st->state;

    if (frm_commit_precond(ss, pre) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ss->fd >= 0) {
        (void) close(ss->fd);
        ss->fd = -1;
    }
    /* Publish: migrate the online-buffer object to tape (a dataset completion
     * marker queues its archive seal instead -- 2.0 F3, frm_publish). */
    if (frm_publish(st->inst, ss->key) != NGX_OK) {
        /* Ownership contract: only a SUCCESSFUL commit consumes the handle. A
         * failed migrate must leave st+ss valid — every caller aborts a failed
         * commit (stage_engine, cstb_pump_and_commit, cache fetch), and abort
         * frees them. Freeing here made that mandatory abort a use-after-free,
         * a double free, and a second purge of the online buffer. */
        return NGX_ERROR;
    }
    free(ss);
    free(st);
    return NGX_OK;
}

void
sd_frm_staged_abort(brix_sd_staged_t *st)
{
    sd_frm_staged_state *ss = st->state;

    if (ss->fd >= 0) {
        (void) close(ss->fd);
        ss->fd = -1;
    }
    (void) ss->fst->mss->purge(ss->fst->mss_ctx, ss->key);
    free(ss);
    free(st);
}


/* Atomic two-name exchange (phase-107 C6): swap the ONLINE-BUFFER copies via
 * the adapter's exchange verb, then MIGRATE both keys so tape truth catches
 * up — an un-migrated swap would serve OLD content after a purge + recall.
 * Both names must be online (the verb answers ENOENT otherwise; the caller
 * recalls first); an adapter without the verb (stub) refuses ENOTSUP, never
 * a two-rename emulation (§3.5). Failure discipline mirrors the C3 barrier:
 * a first-migrate failure un-exchanges (nothing shipped, state fully
 * restored); a second-migrate failure cannot be unwound — `a` already
 * shipped — so it logs at crit and FAILS rather than claim tape consistency
 * the MSS does not have (the vfs_rename.c durable-publish doctrine). */
ngx_int_t
sd_frm_exchange(brix_sd_instance_t *inst, const char *a, const char *b)
{
    sd_frm_state *st = SD_FRM_ST(inst);
    int           err;

    if (st->mss->exchange == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (st->mss->exchange(st->mss_ctx, a, b) != 0) {
        return NGX_ERROR;                    /* errno from the verb */
    }
    if (frm_publish(inst, a) != NGX_OK) {
        err = errno ? errno : EIO;
        (void) st->mss->exchange(st->mss_ctx, a, b);
        errno = err;
        return NGX_ERROR;
    }
    if (frm_publish(inst, b) != NGX_OK) {
        err = errno ? errno : EIO;
        ngx_log_error(NGX_LOG_CRIT, st->log, err,
                      "brix: frm exchange: tape catch-up migrate failed for "
                      "\"%s\" after \"%s\" shipped", b, a);
        errno = err;
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* Durable-publish barrier (phase-107 C3): the frm publish lands in the LOCAL
 * POSIX online buffer before migrate ships it to the MSS — flush that entry's
 * parent directory through the adapter's sync_publish verb so the published
 * name survives a crash of this host. Tape-side durability is the MSS's own
 * contract; an adapter without the verb has nothing local to flush. */
ngx_int_t
sd_frm_sync_publish(brix_sd_instance_t *inst, const char *path)
{
    sd_frm_state *st = SD_FRM_ST(inst);

    if (st->mss->sync_publish == NULL) {
        return NGX_OK;
    }
    return (st->mss->sync_publish(st->mss_ctx, path) == 0) ? NGX_OK : NGX_ERROR;
}
