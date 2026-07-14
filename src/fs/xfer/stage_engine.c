/*
 * stage_engine.c - the generic byte mover at the heart of the one async-staging
 * engine (phase-64 section 11). See stage_engine.h.
 *
 * This translation unit owns the kind->ledger vocabulary and the generic
 * promote-loop mover: open src for read, staged_open dst, pread -> staged_write
 * -> staged_commit, with optional per-user credential re-resolution and one
 * unified audit line per terminal transfer. It also carries the inline run
 * front doors (brix_stage_run_inline[_cred]) and the size-tolerant journal-record
 * decode.
 *
 * The durable journal + dead-letter substrate lives in stage_engine_journal.c;
 * the async front door + per-worker scheduler in stage_engine_scheduler.c; and
 * the restart reconcile in stage_engine_reconcile.c (phase-79 file-size split).
 * The three halves reach the mover (stage_engine_run) and each other only
 * through stage_engine_internal.h.
 */
#include "stage_engine.h"
#include "stage_engine_internal.h"
#include "xfer.h"   /* brix_xfer_finish + the kind/result vocabulary (ledger) */
#include "fs/backend/ucred.h"            /* brix_sd_ucred_resolve (cred re-check)  */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Move granule: one 1 MiB driver-mediated pread/staged_write per turn (the same
 * window the legacy sd_stage promote and the xfer pump use). */
#define STAGE_ENGINE_CHUNK (1u << 20)

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
brix_xfer_result_t
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
