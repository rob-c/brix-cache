/*
 * sd_frm_recall.c — the frm driver's recall family: the bounded synchronous
 * recall every open and cache fill goes through, and the recall / recall_cred
 * vtable verbs kXR_prepare and the cache tier drive.
 *
 * WHAT: frm_ensure_online() asks the bound MSS adapter for residency, starts a
 *       recall for an OFFLINE object and polls once; sd_frm_recall{,_cred}()
 *       wrap it for the driver vtable and book the one unified kind=tape
 *       ledger line for a genuine recall.
 *
 * WHY:  Moved out of sd_frm.c when 2.0 F2 pushed it past the 600-line cap
 *       (coding-standards §1), the same split the staged-write family took.
 *       F2 adds the StageEvents feed lines (brix_frm_stagemsg): recall-begin /
 *       recall-online / recall-failed, keyed by the MSS key — never a
 *       credential.
 *
 * HOW:  Same contract as before the move: 0 = online, -1 with errno ENOENT
 *       (absent), EAGAIN (an async MSS is still staging — HTTP 202 / kXR_wait
 *       park, §9.2; a retry re-polls and the eventual residency hit emits no
 *       line of its own) or EIO. `*recalled` says whether THIS call started
 *       a tape->cache recall so the ledger books real recalls only.
 */

#include "sd_frm.h"
#include "sd_frm_mss.h"
#include "sd_frm_internal.h"
#include "fs/xfer/xfer.h"          /* brix_xfer_finish — kind=tape ledger line */
#include "fs/xfer/stage_events.h"  /* 2.0 F2 StageEvents feed */

#include <errno.h>

/* Terminal outcome of a recall this call started: one feed line + errno. */
static int
frm_recall_fail(const char *key, int e)
{
    char num[24];

    brix_stage_events_emit("frm", "recall-failed", NULL, key,
                           "errno", brix_stage_events_num(num, sizeof(num), e),
                           NULL);
    errno = e;
    return -1;
}

int
frm_ensure_online(sd_frm_state *st, const char *key, int *recalled)
{
    off_t  sz = 0;
    time_t mt = 0;
    int    res = st->mss->residency(st->mss_ctx, key, &sz, &mt);
    int    p;

    if (recalled != NULL) { *recalled = 0; }
    if (res == BRIX_RESIDENCY_ONLINE) {
        return 0;
    }
    if (res == BRIX_RESIDENCY_ABSENT) {
        errno = ENOENT;
        return -1;
    }
    if (recalled != NULL) { *recalled = 1; }
    brix_stage_events_emit("frm", "recall-begin", NULL, key, NULL);
    errno = 0;
    if (st->mss->recall_begin(st->mss_ctx, key) != 0) {
        /* W3.1: a member missing from its sealed archive is NotFound, else EIO. */
        return frm_recall_fail(key, (errno == ENOENT) ? ENOENT : EIO);
    }
    /* One poll: a synchronous adapter is online now; an async MSS is still
     * staging → EAGAIN (HTTP 202 / root kXR_wait park, §9.2); a retry re-polls. */
    p = st->mss->recall_poll(st->mss_ctx, key);
    if (p == 1) {
        brix_stage_events_emit("frm", "recall-online", NULL, key, NULL);
        return 0;
    }
    if (p < 0) {
        return frm_recall_fail(key, EIO);
    }
    errno = EAGAIN;
    return -1;
}

static ngx_int_t
sd_frm_recall_common(brix_sd_instance_t *inst, const char *key,
    char reqid_out[40], const char *principal)
{
    sd_frm_state *st  = SD_FRM_ST(inst);
    ngx_log_t    *log = (ngx_cycle != NULL) ? ngx_cycle->log : NULL;
    int           recalled = 0;

    if (reqid_out != NULL) {
        reqid_out[0] = '\0';         /* synchronous recall: no parking handle */
    }
    if (frm_ensure_online(st, key, &recalled) == 0) {
        /* The cache-fill path (sd_cache) drives every nearline miss through this
         * verb, so a genuine tape->cache recall books its one unified ledger
         * line here (kind=tape, dir=in) — the sync counterpart to the async
         * stage_engine RECALL emit (finding #12). Byte count = the now-online
         * object size. An already-online object (recalled==0) is a plain fill. */
        if (recalled) {
            off_t  sz = 0;
            time_t mt = 0;

            (void) st->mss->residency(st->mss_ctx, key, &sz, &mt);
            brix_xfer_finish(BRIX_XFER_TAPE, "in", key, principal,
                (size_t) (sz > 0 ? sz : 0), BRIX_XFER_OK, 0, log);
        }
        return NGX_OK;               /* online now - the cache tier does a normal fill */
    }
    {
        int e = errno;

        /* Terminal recall failure books a kind=tape/error line; EAGAIN (async
         * still in flight) is non-terminal and must not be recorded. */
        if (recalled && e != EAGAIN) {
            brix_xfer_finish(BRIX_XFER_TAPE, "in", key, principal, 0,
                BRIX_XFER_SRC_ERR, e, log);
        }
        return (e == EAGAIN) ? NGX_AGAIN : NGX_ERROR;
    }
}

ngx_int_t
sd_frm_recall(brix_sd_instance_t *inst, const char *key, char reqid_out[40])
{
    return sd_frm_recall_common(inst, key, reqid_out, NULL);
}

/* recall_cred (phase-107 C2) — SAME recall, attributed. The MSS adapter has no
 * per-user execution leg (every verb runs as the service — the reason evict has
 * no twin), but the tape LEDGER does: this twin books the kind=tape line under
 * the requesting principal instead of anonymously, so a per-user kXR_prepare
 * on an frm export is auditable to who asked for the tape mount. The recall is
 * SYNCHRONOUS (no parking handle), so borrowing the cred for the call's
 * duration retains nothing — the copy rule in sd.h binds only a driver whose
 * recall outlives the call. */
ngx_int_t
sd_frm_recall_cred(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, char reqid_out[40])
{
    return sd_frm_recall_common(inst, key, reqid_out,
                                cred != NULL ? cred->principal : NULL);
}
