/*
 * sd_stage_write.c - the staged-upload (HTTP PUT) path of the write-stage
 * decorator (section 12.2), plus the shared per-user cred capture helpers.
 * Split from sd_stage.c (phase-79); the write-BACK object moved to
 * sd_stage_wb.c (600-line ratchet). See sd_stage.h for the decorator contract
 * and sd_stage_internal.h for the shared seam.
 *
 * WHAT: The staged-upload path the decorator interposes on: a staged slot lands
 *       on the stage store and is FLUSHed to the backend on commit through the
 *       one staging engine (brix_stage_run_inline_cred / brix_stage_submit
 *       FLUSH). A posix stage store is byte-equivalent to phase-63's local-temp
 *       promote. Also owns the cred helpers (record/present/wipe) both write
 *       paths use to capture the owner identity at open time.
 * WHY:  Each file owns one concept: the OTHER interposed write path (the
 *       write-back byte-I/O object) lives in sd_stage_wb.c, and the decorator
 *       core (forwarders + dispatch + driver table + lifecycle) in sd_stage.c.
 * HOW:  The driver table in sd_stage.c routes staged ops to the methods below.
 *       The captured cred records the owner identity at open time so a deferred
 *       or async flush authenticates as the original user.
 */
#include "sd_stage.h"
#include "sd_stage_internal.h"
#include "fs/xfer/stage_engine.h"   /* brix_stage_run_inline / _submit (FLUSH) */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>          /* OPENSSL_cleanse (bearer scrub) */

/* Staged-write object state: an upload lands on the stage store and is flushed
 * to the backend on commit.  `cred` records the owner identity so a deferred or
 * async flush can authenticate as the original user rather than the service account. */
typedef struct {
    sd_stage_inst_state  *is;          /* back-ref: source / store / policy     */
    char                  key[PATH_MAX];   /* export-relative final key         */
    brix_sd_staged_t   *inner;       /* the stage store's staged handle       */
    brix_stage_cred_t    cred;        /* per-user identity (zeroed = service)  */
} sd_stage_staged_state;

/* Record the caller's per-user identity into a durable stage cred slot.
 *
 * WHAT: Copies key/principal/cred_dir/fallback_deny (and a live WLCG bearer, if
 *       present) from an optional brix_sd_cred_t into `dst` (a brix_stage_cred_t
 *       embedded in the durable write-back or staged state). A NULL or empty-key
 *       cred leaves `dst` untouched (zeroed = service-credential path).
 *
 * WHY:  Both the write-back open and the staged open must capture the owner
 *       identity NOW, while the request context is live, so a deferred or async
 *       flush can authenticate to the backend as the original user rather than
 *       the service account. Sharing one copier keeps the two capture sites
 *       byte-identical and keeps each caller's branch count in check.
 *
 * HOW:  1. Return immediately unless cred is non-NULL with a key OR a bearer.
 *       2. ngx_cpystrn key; principal/dir default to "" when their source
 *          pointer is NULL. 3. Narrow fallback_deny into dst->deny. 4. Copy a
 *          live bearer when present — the in-memory-only slot the SYNC flush uses
 *          to re-present a token that has no on-disk cred file to re-resolve. */
void
sd_stage_record_cred(brix_stage_cred_t *dst, const brix_sd_cred_t *cred)
{
    int have_key;
    int have_bearer;

    if (cred == NULL) {
        return;
    }
    have_key    = (cred->key    != NULL && cred->key[0]    != '\0');
    have_bearer = (cred->bearer != NULL && cred->bearer[0] != '\0');
    /* A passthrough WLCG bearer (brix_vfs_deleg_bearer) carries NO store key —
     * the token IS the credential.  Record it on either kind of identity so the
     * flush can re-present it; only a truly empty cred falls back to service. */
    if (!have_key && !have_bearer) {
        return;
    }
    if (have_key) {
        ngx_cpystrn((u_char *) dst->key, (u_char *) cred->key, sizeof(dst->key));
    }
    ngx_cpystrn((u_char *) dst->principal,
                (u_char *) (cred->principal ? cred->principal : ""),
                sizeof(dst->principal));
    ngx_cpystrn((u_char *) dst->dir,
                (u_char *) (cred->cred_dir ? cred->cred_dir : ""),
                sizeof(dst->dir));
    dst->deny = (uint8_t) cred->fallback_deny;
    if (have_bearer) {
        ngx_cpystrn((u_char *) dst->bearer, (u_char *) cred->bearer,
                    sizeof(dst->bearer));
    }
}

/* A recorded per-user identity is present when EITHER a store key (x509 proxy /
 * s3 / ceph, re-resolved at flush time) OR a live bearer (token write-back,
 * carried in memory) is set.  The flush gates on this rather than on key alone
 * so a keyless passthrough bearer is not silently demoted to the service cred. */
int
sd_stage_cred_present(const brix_stage_cred_t *c)
{
    return c->key[0] != '\0' || c->bearer[0] != '\0';
}

/* Cleanse the in-memory bearer once the SYNC flush that borrowed it has
 * returned.  The stage state is freed right after, but free() does not scrub;
 * OPENSSL_cleanse (used the same way by brix_sd_ucred_wipe) prevents the token
 * from lingering in a reused heap block.  Non-secret identity fields are left
 * intact.  NULL-safe. */
void
sd_stage_cred_wipe(brix_stage_cred_t *c)
{
    if (c != NULL) {
        OPENSSL_cleanse(c->bearer, sizeof(c->bearer));
    }
}

/* ---- the staged-upload path (the only interposed HTTP-PUT path) ------------ */

/* Common staged_open body shared by sd_stage_staged_open and
 * sd_stage_staged_open_cred.
 *
 * WHAT: Opens a staged upload slot on the STORE (local — always plain) and
 *       records the optional per-user cred in ss->cred for the commit-time flush.
 *
 * WHY:  The store is service-owned so its staged_open is always plain; the
 *       credential is only needed at flush time (store→source) and must be
 *       captured now while the request context is still live.
 *
 * HOW:  Allocate ss + h, wire them, copy cred when key is non-empty. */
static brix_sd_staged_t *
sd_stage_staged_open_inner(brix_sd_instance_t *inst, sd_stage_inst_state *is,
    const char *final_path, mode_t mode, off_t declared_size,
    const brix_sd_cred_t *cred, int *err_out)
{
    sd_stage_staged_state *ss;
    brix_sd_staged_t    *h;
    brix_sd_staged_t    *inner;
    int                    err = 0;

    if (is->store->driver->staged_open == NULL) {
        if (err_out != NULL) { *err_out = ENOSYS; }
        return NULL;
    }
    inner = is->store->driver->staged_open(is->store, final_path, mode,
                                           declared_size, &err);
    if (inner == NULL) {
        if (err_out != NULL) { *err_out = err ? err : EIO; }
        return NULL;
    }
    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        if (is->store->driver->staged_abort != NULL) {
            is->store->driver->staged_abort(inner);
        }
        free(ss);
        free(h);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    ss->is    = is;
    ss->inner = inner;
    ngx_cpystrn((u_char *) ss->key, (u_char *) final_path, sizeof(ss->key));

    /* Record the owner identity for the flush; zeroed cred = service account. */
    sd_stage_record_cred(&ss->cred, cred);

    h->inst  = inst;
    h->state = ss;
    return h;
}

brix_sd_staged_t *
sd_stage_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, off_t declared_size, int *err_out)
{
    sd_stage_inst_state *is = inst->state;
    return sd_stage_staged_open_inner(inst, is, final_path, mode, declared_size,
                                      NULL, err_out);
}

/* Credential-scoped staged_open: records the owner identity so the commit-time
 * flush can authenticate as the original user.
 *
 * WHAT: Delegates to sd_stage_staged_open_inner with the caller's cred.
 *
 * WHY:  Without this slot a caller using brix_sd_staged_open_maybe_cred against
 *       the stage decorator would lose the credential — the plain staged_open
 *       slot receives no cred parameter.
 *
 * HOW:  sd_stage_staged_open_inner copies key/principal/cred_dir/deny into
 *       ss->cred; sd_stage_staged_commit then passes &ss->cred to the flush. */
brix_sd_staged_t *
sd_stage_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, off_t declared_size, const brix_sd_cred_t *cred, int *err_out)
{
    sd_stage_inst_state *is = inst->state;
    return sd_stage_staged_open_inner(inst, is, final_path, mode, declared_size,
                                      cred, err_out);
}

ssize_t
sd_stage_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    sd_stage_staged_state *ss = st->state;
    brix_sd_staged_t    *inner = ss->inner;

    return inner->inst->driver->staged_write
         ? inner->inst->driver->staged_write(inner, buf, len, off) : -1;
}

/* Publish the buffered object on the stage store, then FLUSH it to the backend
 * through the one staging engine. On a successful flush the stage buffer copy is
 * dropped; on a failed flush it is KEPT (durability preserved for retry, section
 * 16). Consumes the handle. */
ngx_int_t
sd_stage_staged_commit(brix_sd_staged_t *st, brix_sd_precond_t *pre)
{
    sd_stage_staged_state *ss = st->state;
    sd_stage_inst_state   *is = ss->is;
    brix_sd_instance_t  *store = is->store;
    brix_sd_instance_t  *source = is->source;
    ngx_int_t              rc;

    /* 1. publish the buffered object on the stage store. */
    if (store->driver->staged_commit(ss->inner, pre) != NGX_OK) {
        /* Ownership contract (brix_vfs_staged_commit): a failed commit leaves
         * the whole handle valid — the inner store's commit did not free
         * ss->inner, so DON'T abort/free here. The caller invokes staged_abort
         * (sd_stage_staged_abort), which aborts ss->inner and frees ss+st
         * exactly once. Doing it here too would double-free. errno is already
         * set by the inner commit. */
        return NGX_ERROR;
    }
    /* ss->inner is consumed (freed) by the commit above — drop the dangling
     * pointer so a later sd_stage_staged_abort (which the caller MUST run if a
     * write-back step below fails) does not abort an already-released handle. */
    ss->inner = NULL;

    /* 2a. ASYNC write-back (SP4): the object is durable on the stage store now, so
     * the commit succeeds immediately; the scheduler flushes it to the backend and
     * drops the stage copy on completion. The export anchor rides on the durable
     * record so a restart-reconcile can rebuild both tiers and re-flush (§11.3).
     * The owner cred is embedded in the opts so the scheduler can authenticate as
     * the original user when it drains the queue (non-NULL only when a key was
     * recorded at staged_open time). */
    if (is->policy.flush_mode == BRIX_WT_MODE_ASYNC) {
        brix_stage_opts_t o;

        ngx_memzero(&o, sizeof(o));
        o.async       = 1;
        o.export_root = (is->root_canon[0] != '\0') ? is->root_canon : NULL;
        o.cred        = sd_stage_cred_present(&ss->cred) ? &ss->cred : NULL;
        /* phase74-fp: argument order verified against brix_stage_submit(kind,
         * src, src_key, dst, dst_key, opts) — a FLUSH moves bytes FROM the
         * stage `store` TO the backend instance (locally named `source`), so
         * store is the src and source the dst; the name swap is deliberate. */
        (void) brix_stage_submit(BRIX_STAGE_FLUSH, store, ss->key, source,  /* NOLINT(readability-suspicious-call-argument) */
                                   ss->key, &o);
        sd_stage_cred_wipe(&ss->cred);       /* async never journals the token */
        free(ss);
        free(st);
        return NGX_OK;
    }

    /* 2b. SYNC write-back: flush inline and reflect the result, threading the
     * owner cred so the backend driver uses the per-user proxy rather than the
     * service credential. */
    /* phase74-fp: same verified src/dst order as the async submit above —
     * FLUSH reads from the stage store and writes to the backend `source`. */
    rc = brix_stage_run_inline_cred(BRIX_STAGE_FLUSH, store, ss->key, source,  /* NOLINT(readability-suspicious-call-argument) */
                                     ss->key,
                                     sd_stage_cred_present(&ss->cred) ? &ss->cred : NULL);

    /* 3. on success drop the stage buffer copy; on failure keep it for retry. */
    if (rc != NGX_OK) {
        /* Ownership contract again: the handle is only consumed on SUCCESS. A
         * failed inline flush must leave st+ss valid so the caller's
         * staged_abort releases them exactly once (it now skips the consumed
         * ss->inner). Freeing here made the mandatory abort a use-after-free
         * plus a double-free of both allocations. */
        return rc;
    }
    if (store->driver->unlink != NULL) {
        (void) store->driver->unlink(store, ss->key, 0);
    }

    sd_stage_cred_wipe(&ss->cred);           /* scrub the token after the flush */
    free(ss);
    free(st);
    return NGX_OK;
}

void
sd_stage_staged_abort(brix_sd_staged_t *st)
{
    sd_stage_staged_state *ss = st->state;
    sd_stage_inst_state   *is = ss->is;

    /* ss->inner is NULL once the inner commit consumed it (a write-back failure
     * after step 1 still lands here) — only an unpublished handle is aborted. */
    if (ss->inner != NULL && is->store->driver->staged_abort != NULL) {
        is->store->driver->staged_abort(ss->inner);
    }
    sd_stage_cred_wipe(&ss->cred);           /* scrub any recorded token on abort */
    free(ss);
    free(st);
}

/* ---- namespace relays displaced from sd_stage.c (600-line cap) ------------ */

/* Path-based truncate forwards straight to the source (no staging): resizing the
 * origin object by name is what lets kXR_truncate over a staged remote backend
 * avoid a RECALL + colliding write-open. Mirrors sd_stage_setattr. */
ngx_int_t
sd_stage_truncate_path(brix_sd_instance_t *inst, const char *path, off_t len)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);

    if (s->driver->truncate_path == NULL
        && s->driver->truncate_path_cred == NULL)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return brix_sd_truncate_path_maybe_cred(s, path, len, NULL);
}

ngx_int_t
sd_stage_truncate_path_cred(brix_sd_instance_t *inst, const char *path,
    off_t len, const brix_sd_cred_t *cred)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);

    if (s->driver->truncate_path == NULL
        && s->driver->truncate_path_cred == NULL)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return brix_sd_truncate_path_maybe_cred(s, path, len, cred);
}

/* Atomic exchange relay (phase-107 C6): the stage tier keeps no per-path state
 * to swap here — a dirty write-back object is keyed by handle, not name — so
 * the swap is the SOURCE's alone. brix_sd_exchange_maybe_cred refuses ENOTSUP
 * when the source has no primitive (never a two-rename emulation, §3.5). */
ngx_int_t
sd_stage_exchange(brix_sd_instance_t *inst, const char *a, const char *b)
{
    return brix_sd_exchange_maybe_cred(SD_STAGE_SRC(inst), a, b, NULL);
}

ngx_int_t
sd_stage_exchange_cred(brix_sd_instance_t *inst, const char *a, const char *b,
    const brix_sd_cred_t *cred)
{
    return brix_sd_exchange_maybe_cred(SD_STAGE_SRC(inst), a, b, cred);
}
