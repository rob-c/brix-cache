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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

ngx_int_t
sd_frm_staged_commit(brix_sd_staged_t *st, brix_sd_precond_t *pre)
{
    sd_frm_staged_state *ss = st->state;
    int                  rc;

    /* Typed publish precondition (phase-107 C6): the MSS adapter's residency
     * probe is this driver's only view of the tape-side target, so every kind
     * is ADVISORY here — check-then-migrate, pre->atomic stays 0 (the W7
     * checklist's verdict for frm; §3.5 forbids claiming atomicity the MSS
     * never gave).  Evaluated BEFORE the migrate so a refused precondition
     * leaves the tape copy untouched (the caller's staged_abort then purges
     * the online-buffer temp). */
    if (pre != NULL && pre->kind != BRIX_SD_PRECOND_NONE) {
        off_t  tsz = 0;
        time_t tmt = 0;
        int    res = ss->fst->mss->residency(ss->fst->mss_ctx, ss->key,
                                             &tsz, &tmt);

        if (pre->kind == BRIX_SD_PRECOND_ABSENT) {
            if (res != BRIX_RESIDENCY_ABSENT) {
                errno = EEXIST;
                return NGX_ERROR;
            }
        } else if (res == BRIX_RESIDENCY_ABSENT) {
            errno = ECANCELED;       /* MATCH_* against a missing target */
            return NGX_ERROR;
        } else if (brix_sd_precond_eval_stat(pre, tsz, tmt) != 0) {
            return NGX_ERROR;        /* errno = ECANCELED / ENOTSUP */
        }
    }

    if (ss->fd >= 0) {
        (void) close(ss->fd);
        ss->fd = -1;
    }
    /* Publish: migrate the online-buffer object to tape. */
    rc = ss->fst->mss->migrate(ss->fst->mss_ctx, ss->key);
    if (rc != 0) {
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
    if (st->mss->migrate(st->mss_ctx, a) != 0) {
        err = errno ? errno : EIO;
        (void) st->mss->exchange(st->mss_ctx, a, b);
        errno = err;
        return NGX_ERROR;
    }
    if (st->mss->migrate(st->mss_ctx, b) != 0) {
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
