/*
 * sd_xroot_nearline.c — the nearline (tape/MSS) pair of the root:// origin
 * driver: residency (is this path online?) and recall (bring it online).
 *
 * WHY THIS FILE EXISTS
 *   An xrootd origin fronting an HSM is the ONE nearline source we can drive
 *   entirely over the wire, because the protocol already spells both halves:
 *   kXR_stat's ASCII flag word carries kXR_offline for a path whose data is not
 *   currently on disk, and kXR_prepare with kXR_stage IS the stage verb, right
 *   down to returning a request id. Until this file existed the driver had
 *   neither slot, so a tape-backed root:// origin reported ONLINE for every path
 *   (brix_vfs_residency's answer for a driver with no residency model) and every
 *   first read of a migrated file blocked a worker for however long the origin's
 *   MSS took — minutes to hours — instead of parking the open and answering
 *   "staging, retry later" (HTTP 202 + Retry-After, S3 InvalidObjectState,
 *   root:// kXR_offline).
 *
 * OPT-IN, AND WHY IT MUST BE
 *   Neither slot is reachable unless the instance advertises
 *   BRIX_SD_CAP_NEARLINE, which brix_sd_xroot_create_origin sets only from
 *   cfg->nearline — the `nearline` param on the tier's store line. That is not
 *   timidity: CAP_NEARLINE is a CONTRACT, not a hint. tier_build refuses to
 *   compose a nearline backend without a cache tier in front (the recall target,
 *   §9.4), so auto-advertising it would have turned every existing plain root://
 *   origin config into a startup failure. An origin that is not tape-backed also
 *   never sets kXR_offline, so the operator declaring `nearline` on a disk origin
 *   gets correct-but-pointless behaviour rather than a wrong answer.
 *
 * SHAPE
 *   Both slots open a fresh per-op origin session (anonymous/service, or the
 *   caller's credential for the recall_cred twin), issue one request, and tear
 *   it down — the same per-op session shape every path-based op in sd_xroot_ns.c
 *   uses, and for the same reason: these are rare, out-of-band metadata calls, not
 *   a data path worth pooling a connection for.
 */

#include "sd_xroot_internal.h"
#include "protocols/root/protocol/flags.h"   /* kXR_offline (ASCII-stat flag) */

#include <errno.h>
#include <stdlib.h>

/* sd_xroot_residency — vtable residency slot: classify `key` WITHOUT staging it.
 *
 * WHAT: NGX_OK with *out set to BRIX_SD_RES_ONLINE or BRIX_SD_RES_NEARLINE, or
 *       NGX_ERROR with errno set (ENOENT for a path the origin does not have).
 * WHY:  The protocol planes advertise tape state from this seam — the HTTP Tape
 *       REST API, S3 x-amz-storage-class, root:// stat's own kXR_offline bit —
 *       and they must be able to say "on tape" without triggering a recall, so
 *       this is a pure read.
 * HOW:  One kXR_stat by NAME; kXR_offline in the reply's flag word means the
 *       data is not on disk. The base protocol distinguishes only present-and-
 *       online from present-and-offline, so we never report OFFLINE or LOST: a
 *       path the origin cannot describe at all is an error (ENOENT), not a
 *       residency class, and inventing LOST from a missing path would tell the
 *       tape REST API a file was destroyed when the origin merely 404'd. */
static ngx_int_t
sd_xroot_residency_as(brix_sd_instance_t *inst, const char *key,
    brix_sd_residency_t *out, const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state       *is = inst->state;
    brix_cache_origin_conn_t   oc;
    brix_cache_fill_t         *t;
    brix_cache_stat_out_t      so;
    int                        rc, e = 0;

    if (out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) {
        errno = e;
        return NGX_ERROR;
    }
    rc = brix_cache_origin_stat(t, &oc, key, &so);
    e  = errno;
    brix_cache_origin_close(&oc);
    free(t);
    if (rc != 0) {
        errno = e;
        return NGX_ERROR;
    }
    *out = (so.flags & kXR_offline) ? BRIX_SD_RES_NEARLINE
                                    : BRIX_SD_RES_ONLINE;
    return NGX_OK;
}

ngx_int_t
sd_xroot_residency(brix_sd_instance_t *inst, const char *key,
    brix_sd_residency_t *out)
{
    return sd_xroot_residency_as(inst, key, out, NULL);
}

/* sd_xroot_recall — vtable recall slot: bring `key` online, without blocking.
 *
 * WHAT: NGX_OK (already online — the caller does a normal cache-fill),
 *       NGX_AGAIN (staging in flight; reqid_out carries the origin's request id,
 *       "" if it returned none — the cache tier parks the open on it), or
 *       NGX_ERROR with errno set.
 * WHY:  This is the verb sd_cache drives on every nearline miss. Returning
 *       NGX_AGAIN instead of stalling is the whole point: the open fails soft
 *       with EAGAIN and the protocol plane answers "staging, retry later"
 *       (SP5 §9.2) rather than holding a worker for the length of a tape mount.
 * HOW:  Residency first — an already-online path needs no prepare at all, and
 *       asking anyway would queue pointless MSS work on every cache miss of a
 *       resident file. Only a NEARLINE answer sends kXR_prepare(kXR_stage), and
 *       that is always NGX_AGAIN: prepare is asynchronous by definition, so a
 *       successful send means "queued", never "done". A prepare that FAILS is
 *       still NGX_AGAIN with an empty reqid rather than NGX_ERROR — the object
 *       is genuinely offline, the read cannot be served now either way, and
 *       EAGAIN ("retry later") describes that far better to a client than a hard
 *       error on an advisory hint. Both steps use their own short-lived session
 *       (see the file header). */
static ngx_int_t
sd_xroot_recall_common(brix_sd_instance_t *inst, const char *key,
    char reqid_out[40], const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state       *is = inst->state;
    brix_cache_origin_conn_t   oc;
    brix_cache_fill_t         *t;
    brix_sd_residency_t        res;
    int                        e = 0;

    if (reqid_out != NULL) {
        reqid_out[0] = '\0';
    }
    if (sd_xroot_residency_as(inst, key, &res, cred) != NGX_OK) {
        return NGX_ERROR;                  /* errno already set (ENOENT/EIO/…) */
    }
    if (res == BRIX_SD_RES_ONLINE) {
        return NGX_OK;                     /* resident — a normal fill follows */
    }
    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) {
        errno = e;
        return NGX_ERROR;
    }
    (void) brix_cache_origin_prepare_stage(t, &oc, key, reqid_out);
    brix_cache_origin_close(&oc);
    free(t);
    return NGX_AGAIN;                      /* queued — park the open on reqid */
}

ngx_int_t
sd_xroot_recall(brix_sd_instance_t *inst, const char *key, char reqid_out[40])
{
    return sd_xroot_recall_common(inst, key, reqid_out, NULL);
}

/* recall_cred (phase-107 C2) — the SAME two-step (kXR_stat probe, then
 * kXR_prepare(kXR_stage)) with BOTH origin sessions opened under the caller's
 * credential (sd_xroot_session with a non-NULL cred — the ns_cred wrapper
 * pattern), so a deny-mode prestage never reaches the origin as the service
 * identity and the origin's own MSS fair-share sees the real requester. Both
 * sessions are torn down before return — nothing outlives the call, so the
 * borrowed cred is never retained (the sd.h copy rule binds only a driver
 * whose recall keeps running after it returns). */
ngx_int_t
sd_xroot_recall_cred(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, char reqid_out[40])
{
    return sd_xroot_recall_common(inst, key, reqid_out, cred);
}

/* sd_xroot_evict — vtable evict slot (phase-107 C2): forward the release
 * upstream as kXR_prepare(optionX=kXR_evict), the wire's own "drop your online
 * copy" verb — the origin's MSS keeps the durable copy, exactly the shape our
 * OWN prepare plane now implements on the receiving side. Gated on the SAME
 * operator declaration as recall/residency (CAP_NEARLINE from cfg->nearline):
 * evict is top-dispatched with no capability walk, and on a plain disk origin
 * the origin's copy is the ONLY copy — forwarding a release there would be a
 * delete wearing a different verb, so it answers ENOTSUP instead (the sd.h
 * contract) and the caller keeps its advisory no-op. Bytes released are
 * unknowable over the wire (the reply carries none): *bytes_out stays 0.
 * Same per-op session shape as the other slots in this file. */
static ngx_int_t
sd_xroot_evict_common(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out, const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state       *is = inst->state;
    brix_cache_origin_conn_t   oc;
    brix_cache_fill_t         *t;
    int                        rc, e = 0;

    if (bytes_out != NULL) {
        *bytes_out = 0;
    }
    if ((brix_sd_caps(inst) & BRIX_SD_CAP_NEARLINE) == 0) {
        errno = ENOTSUP;                   /* disk origin: its copy is the only
                                            * copy — never release it */
        return NGX_ERROR;
    }
    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) {
        errno = e;
        return NGX_ERROR;
    }
    rc = brix_cache_origin_prepare_evict(t, &oc, path);
    e  = errno;
    brix_cache_origin_close(&oc);
    free(t);
    if (rc != 0) {
        errno = e;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
sd_xroot_evict(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out)
{
    return sd_xroot_evict_common(inst, path, bytes_out, NULL);
}

/* evict_cred — the SAME forwarded release with the origin session opened under
 * the caller's credential (the recall_cred rationale: a deny-mode release never
 * reaches the origin as the service identity). The session is torn down before
 * return, so the borrowed cred is never retained. */
ngx_int_t
sd_xroot_evict_cred(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out, const brix_sd_cred_t *cred)
{
    return sd_xroot_evict_common(inst, path, bytes_out, cred);
}
