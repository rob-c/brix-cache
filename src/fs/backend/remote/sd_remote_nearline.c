/*
 * sd_remote_nearline.c — the nearline (archive) pair of the remote-origin
 * (s3://) driver: residency (are this object's bytes readable now?) and recall
 * (start bringing them back).
 *
 * WHY THIS FILE EXISTS
 *   An S3 bucket with a GLACIER or DEEP_ARCHIVE lifecycle is the cheapest cold
 *   store WLCG sites actually deploy, and until this file existed the driver had
 *   neither nearline slot: brix_vfs_residency reported ONLINE for every key (its
 *   answer for a driver with no residency model), so the first read of an
 *   archived object came back as an opaque 403 InvalidObjectState from the
 *   origin — a hard error, with nothing above able to say "it is on tape, ask
 *   again later", and no way at all to START the restore.
 *
 * THE WIRE
 *   S3 splits the two halves exactly as this driver's slots do:
 *     HEAD          → x-amz-storage-class / x-amz-restore / x-amz-archive-status
 *     POST ?restore → RestoreObject
 *   The HEAD is a pure read: it never touches the archive tier and never starts
 *   a restore, which is precisely what the residency contract requires.
 *
 * OPT-IN, AND WHY IT MUST BE
 *   Neither slot is reachable unless the instance advertises
 *   BRIX_SD_CAP_NEARLINE, which brix_sd_remote_create sets only from
 *   cfg->nearline. CAP_NEARLINE is a CONTRACT, not a hint: tier_build refuses to
 *   compose a nearline backend without a cache tier in front (the recall target,
 *   §9.4), so inferring it from a storage class seen on one object would turn
 *   every working s3:// export into a startup failure the first time somebody
 *   archived a single key.
 *
 * IDENTITY
 *   residency has no _cred twin: it signs as the export's service credential,
 *   because a residency probe is the gateway's own housekeeping, driven by the
 *   cache tier on a miss. recall carries one (phase-107 C2): a CLIENT-initiated
 *   prestage (kXR_prepare) is the user's request, so the RestoreObject — an
 *   operation the bucket owner may well have IAM-scoped per user, and one that
 *   is BILLED — signs with the requester's keys when the VFS cred gate resolves
 *   them, and the internal residency probe inside recall_cred signs the same
 *   way so a deny-mode request never reaches the origin under the service
 *   credential at all (the stat_cred rationale). The cache tier's own
 *   recall-at-fill keeps calling the plain slot and stays export-charged.
 */

#include "sd_remote_internal.h"
#include "fs/backend/s3/sd_s3.h"

#include <errno.h>
#include <string.h>

/* A storage class is one token; an x-amz-restore value is a fixed-shape pair
 * ("ongoing-request=\"false\", expiry-date=\"...\""). 128 fits both with room,
 * and anything longer is not a value this build can classify. */
#define SD_REMOTE_ARCH_MAX  128

/* The storage classes whose objects are NOT directly readable. Everything else
 * S3 offers — STANDARD, the IA tiers, INTELLIGENT_TIERING, GLACIER_IR — serves a
 * GET immediately, which is why this is a list of the archival ones rather than
 * a list of the online ones: see sd_remote_is_archived on why that direction is
 * the safe one. */
static const char *sd_remote_archived_class[] = {
    "GLACIER", "DEEP_ARCHIVE",
};

/*
 * WHAT: 1 iff the object's bytes are in an archive tier and so cannot be read
 *       without a restore.
 * WHY:  Two independent things put an object in that state, and missing either
 *       one would make the driver claim an unreadable object is online: an
 *       explicit archival storage class, and INTELLIGENT_TIERING's automatic
 *       demotion, which keeps the storage class as INTELLIGENT_TIERING and
 *       reports the demotion in x-amz-archive-status instead.
 * HOW:  An exact match against the archival class list, or any non-empty
 *       archive status (its two values, ARCHIVE_ACCESS and DEEP_ARCHIVE_ACCESS,
 *       both mean archived; the header is absent otherwise).
 *
 *       An UNRECOGNISED storage class is treated as online. That is the opposite
 *       of the http driver's locality mapping, which errors on an unknown token,
 *       and the asymmetry is deliberate: the Tape REST API's localities are a
 *       closed vocabulary, so an unknown one means we are not talking to that
 *       API at all, whereas AWS adds storage classes routinely and every one it
 *       has ever added outside this list serves reads directly. Guessing
 *       "archived" for a new class would park every open on a restore that was
 *       never needed; guessing "online" degrades to exactly the behaviour this
 *       driver had before the slot existed.
 */
static int
sd_remote_is_archived(const char *sclass, const char *astatus)
{
    size_t i;

    if (astatus[0] != '\0') {
        return 1;
    }
    for (i = 0; i < sizeof(sd_remote_archived_class)
                    / sizeof(sd_remote_archived_class[0]); i++) {
        if (strcmp(sclass, sd_remote_archived_class[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * WHAT: Classify an archived object from its x-amz-restore header.
 * WHY:  An archived object has three states, not two, and the header is the only
 *       thing that separates them: no restore has been asked for (the header is
 *       absent), one is running, or one has completed and a temporary copy is
 *       readable RIGHT NOW. The last is genuinely ONLINE — reporting it as
 *       NEARLINE would make the cache re-request a restore for bytes it could
 *       already have fetched, and pay for the archive retrieval twice.
 * HOW:  `ongoing-request="false"` is the completed spelling; anything else with
 *       the header present is in flight. Both in-flight and never-requested are
 *       NEARLINE — from the caller's side they differ only in whether recall's
 *       RestoreObject starts the job or joins it, which recall does not need to
 *       know in advance.
 */
static brix_sd_residency_t
sd_remote_restore_state(const char *restore)
{
    if (strstr(restore, "ongoing-request=\"false\"") != NULL) {
        return BRIX_SD_RES_ONLINE;
    }
    return BRIX_SD_RES_NEARLINE;
}

/* sd_remote_residency — vtable residency slot: classify `key` WITHOUT restoring.
 *
 * WHAT: NGX_OK with *out set to ONLINE or NEARLINE, or NGX_ERROR with errno set
 *       (ENOENT for a key the bucket does not hold).
 * WHY:  Every protocol plane advertises tape state from this seam, and all of
 *       them must be able to say "archived" without paying for a retrieval.
 * HOW:  One signed HEAD, three headers, the two classifiers above. OFFLINE and
 *       LOST are never reported: S3 has no notion of "temporarily unretrievable"
 *       (an archived object is always restorable) and none of "destroyed" (a key
 *       that is gone is simply absent, which is ENOENT — inventing LOST from a
 *       404 would tell every plane above that a file had been DESTROYED because
 *       the bucket merely does not have it).
 */
static ngx_int_t
sd_remote_residency_impl(brix_sd_instance_t *inst, const char *key,
    brix_sd_residency_t *out, const char *ak, const char *sk,
    const char *region, const char *session)
{
    const brix_sd_remote_cfg_t *cfg;
    sd_s3_open_params           p;
    sd_s3_file                 *s3;
    char                        objpath[768];
    char                        errbuf[256];
    char                        sclass[SD_REMOTE_ARCH_MAX];
    char                        restore[SD_REMOTE_ARCH_MAX];
    char                        astatus[SD_REMOTE_ARCH_MAX];
    const sd_s3_meta_buf        b_class   = { sclass,  sizeof(sclass)  };
    const sd_s3_meta_buf        b_restore = { restore, sizeof(restore) };
    const sd_s3_meta_buf        b_status  = { astatus, sizeof(astatus) };
    const sd_s3_archive_buf_t   want = { &b_class, &b_restore, &b_status };
    int                         rc;

    if (inst == NULL || inst->state == NULL || key == NULL || out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    cfg = inst->state;
    sd_remote_s3_key(cfg, key, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);

    s3 = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        return NGX_ERROR;
    }
    rc = sd_s3_archive_state(s3, &want, errbuf, sizeof(errbuf));
    sd_s3_close(s3);
    if (rc != 0) {
        return NGX_ERROR;              /* errno mapped from the HTTP status */
    }
    if (!sd_remote_is_archived(sclass, astatus)) {
        *out = BRIX_SD_RES_ONLINE;
        return NGX_OK;
    }
    *out = sd_remote_restore_state(restore);
    return NGX_OK;
}

ngx_int_t
sd_remote_residency(brix_sd_instance_t *inst, const char *key,
    brix_sd_residency_t *out)
{
    return sd_remote_residency_impl(inst, key, out, NULL, NULL, NULL, NULL);
}

/* sd_remote_recall — vtable recall slot: bring `key` online, without blocking.
 *
 * WHAT: NGX_OK (already readable — a normal cache fill follows), NGX_AGAIN (a
 *       restore is under way; reqid_out is left empty), or NGX_ERROR with errno.
 * WHY:  This is the verb sd_cache drives on every nearline miss. Returning
 *       NGX_AGAIN instead of stalling is the whole point: the open fails soft
 *       with EAGAIN and the plane above answers "staging, retry later" rather
 *       than holding a worker for the hours a DEEP_ARCHIVE retrieval takes.
 * HOW:  Residency first — a RestoreObject against an object that is already
 *       readable is a paid no-op on every cache miss of a hot key. Only a
 *       NEARLINE answer posts the restore, and that is ALWAYS NGX_AGAIN: the
 *       verb is asynchronous by definition, so acceptance means "queued", never
 *       "done". A restore that FAILS is still NGX_AGAIN — the object is
 *       genuinely not readable either way, and "retry later" describes that to a
 *       client far better than a hard error on an advisory hint does.
 *
 *       reqid_out stays empty: RestoreObject issues no request id at all, and
 *       the slot contract says an empty id means "queued, poll the state" —
 *       which is exactly what a caller must do with S3.
 */
static ngx_int_t
sd_remote_recall_impl(brix_sd_instance_t *inst, const char *key,
    char reqid_out[40], const char *ak, const char *sk, const char *region,
    const char *session)
{
    const brix_sd_remote_cfg_t *cfg;
    sd_s3_open_params           p;
    brix_sd_residency_t         res;
    char                        objpath[768];
    char                        errbuf[256];

    if (reqid_out != NULL) {
        reqid_out[0] = '\0';
    }
    if (sd_remote_residency_impl(inst, key, &res, ak, sk, region, session)
        != NGX_OK)
    {
        return NGX_ERROR;              /* errno already set (ENOENT/EACCES/…) */
    }
    if (res == BRIX_SD_RES_ONLINE) {
        return NGX_OK;                 /* readable — a normal fill follows */
    }
    cfg = inst->state;
    sd_remote_s3_key(cfg, key, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);
    (void) sd_s3_restore(&p, cfg->restore_days, errbuf, sizeof(errbuf));
    return NGX_AGAIN;                  /* queued — the caller polls residency */
}

ngx_int_t
sd_remote_recall(brix_sd_instance_t *inst, const char *key, char reqid_out[40])
{
    return sd_remote_recall_impl(inst, key, reqid_out,
                                 NULL, NULL, NULL, NULL);
}

/* recall_cred (phase-107 C2) — the SAME probe-then-restore, signed with the
 * requesting user's keys (sd_remote_cred_gate: 1 = override, 0 = static
 * fallback, -1 = deny — the stat_cred shape). Both the HEAD and the
 * RestoreObject POST complete before return: S3's restore is asynchronous at
 * the SERVICE (the caller polls residency), but the REQUEST itself is one
 * synchronous signed round trip, so the borrowed cred is consumed inside the
 * call and never retained — the sd.h copy rule binds only a driver that keeps
 * issuing requests after it returns (the opendir asymmetry this driver
 * documented). */
ngx_int_t
sd_remote_recall_cred(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, char reqid_out[40])
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_recall_impl(inst, key, reqid_out,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return sd_remote_recall_impl(inst, key, reqid_out,
                                 NULL, NULL, NULL, NULL);
}
