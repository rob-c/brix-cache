/*
 * aio_mfile.c - connection-surviving async file handle (open/pread/pwrite/sync/close).
 * Phase-38 split of aio_mgr.c; behavior-identical.
 */
#include "aio.h"
#include "brix.h"
#include "protocols/root/protocol/protocol.h"
#include "core/compat/codec_core.h"   /* phase-42 W4 inline read decompression */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

/* mfile */
struct brix_mfile {
    brix_aconn     *ac;
    char            path[XRDC_PATH_MAX];
    char            opaque[256];
    int             have_opaque;
    int             writable;
    int             posc;
    uint8_t         fhandle[XRD_FHANDLE_LEN];
    int             have_handle;
    int             max_stall_ms;
    int             max_retries;
    pthread_mutex_t lock;
    uint64_t        gen;        /* bumped on each (re)open */
    /* phase-42 W4: inline read-compression codec learned from the open reply
     * cptype[0] (0 = plaintext).  Re-learned on every (re)open in mfile_do_open,
     * so reopen-at-offset after a fault transparently re-negotiates; a server
     * that declines simply yields 0 and reads stay plaintext. */
    uint8_t         read_codec;
    /* phase-42 W5: inline write-compression codec (write opens only); each
     * brix_mfile_pwrite compresses its payload as a self-contained frame the
     * server decompresses on ingest.  Re-learned on every (re)open. */
    uint8_t         write_codec;
};

static uint64_t
now_ns(void)
{
    return brix_mono_ns();
}

/* Compute the kXR_open options word for a (re)open with the given force tri-state.
 *
 * WHAT: Returns the wire options bitmask — kXR_open_read for a read handle, or
 *       kXR_open_updt|kXR_mkpath plus (force==1) kXR_delete / (force==0) kXR_new /
 *       (force==2) nothing, plus kXR_posc when POSC is set — for a write handle.
 * WHY:  The force tri-state (truncate vs create-excl vs update-in-place) is exactly
 *       what makes reopen NON-destructive: reopen passes force==2 so recovery never
 *       re-truncates or re-creates. Isolating it keeps mfile_do_open flat.
 * HOW:  1) read handle → kXR_open_read, done.
 *       2) write handle → base updt|mkpath; OR in delete/new per force (force==2
 *          adds neither = update in place); OR in posc when requested. */
static uint16_t
mfile_open_options(const brix_mfile *mf, int force)
{
    uint16_t options;

    if (!mf->writable) {
        return kXR_open_read;
    }
    options = kXR_open_updt | kXR_mkpath;
    if (force == 1) {
        options |= kXR_delete;       /* truncate/overwrite */
    } else if (force == 0) {
        options |= kXR_new;          /* create-excl */
    }                                /* force == 2: update in place */
    if (mf->posc) {
        options |= kXR_posc;
    }
    return options;
}

/* Learn the inline-compression codec from a kXR_open reply body.
 *
 * WHAT: Resets mf->read_codec/write_codec to 0, then (write handle → write_codec,
 *       read handle → read_codec) adopts the server's codec id when the reply
 *       confirms it. Returns 0 on success (including "no codec"), or -1 with *st
 *       set when the server negotiated a codec this build cannot decode.
 * WHY:  phase-42 W4/W5. Per the dual-check contract (codec_core.h) cptype is a
 *       legacy field a non-cooperating server may reuse; trusting it alone would
 *       inflate plaintext and corrupt data, so it is adopted ONLY alongside the
 *       cpsize magic. Failing an un-decodable codec avoids asymmetric-build
 *       corruption (copying compressed bytes through as plaintext). Re-learned on
 *       every (re)open, so a fault mid-transfer transparently re-negotiates.
 * HOW:  1) clear both codecs (stock servers leave cpsize 0 → stays plaintext).
 *       2) ServerOpenBody is fhandle[4] cpsize[4] cptype[4]; a body under 12 bytes
 *          carries no codec fields → return 0.
 *       3) parse big-endian cpsize and cptype[0]; unless cpsize == the magic and
 *          the id is in [1, BRIX_CODEC_MAX) → return 0 (plaintext).
 *       4) if this build cannot decode the id → status + return -1.
 *       5) store it in the write- or read-side codec per mf->writable, return 0. */
static int
mfile_learn_codec(brix_mfile *mf, const uint8_t *body, uint32_t blen,
                  brix_status *st)
{
    mf->read_codec = 0;
    mf->write_codec = 0;
    if (blen < 12) {
        return 0;
    }
    uint32_t cpsize = ((uint32_t) body[4] << 24) | ((uint32_t) body[5] << 16)
                    | ((uint32_t) body[6] << 8)  |  (uint32_t) body[7];
    uint8_t  cid    = body[8];   /* cptype[0] */
    if (cpsize != BRIX_INLINE_CMP_MAGIC || cid < 1 || cid >= BRIX_CODEC_MAX) {
        return 0;
    }
    /* Server confirmed codec `cid`; if this build cannot handle it, fail the open
     * rather than silently copying compressed bytes as plaintext. */
    if (!brix_codec_available(cid)) {
        brix_status_set(st, XRDC_EUNSUPPORTED, 0,
            "server negotiated inline-compression codec %u that this "
            "client build cannot decode", (unsigned) cid);
        return -1;
    }
    if (mf->writable) {
        mf->write_codec = cid;
    } else {
        mf->read_codec = cid;
    }
    return 0;
}

/* Build + send a kXR_open with the given force tri-state (see brix_file_open_opaque).
 * On success copies the fresh handle into mf->fhandle. Caller holds no lock. */
static int
mfile_do_open(brix_mfile *mf, int force, brix_status *st)
{
    ClientOpenRequest req;
    uint16_t          options = mfile_open_options(mf, force);
    uint16_t          kxr = 0;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;
    char             *payload;
    size_t            need;
    int               plen;

    need = strlen(mf->path) + 1 + (mf->have_opaque ? strlen(mf->opaque) + 1 : 0);
    payload = (char *) malloc(need);
    if (payload == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory (open payload)");
        return -1;
    }
    plen = mf->have_opaque
         ? snprintf(payload, need, "%s?%s", mf->path, mf->opaque)
         : snprintf(payload, need, "%s", mf->path);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_open);
    {
        xrdw_open_req_t b = { .mode = (uint16_t) (mf->writable ? 0644 : 0),
                              .options = options, .optiont = 0 };
        xrdw_open_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    brix_aio_opts o = { mf->max_stall_ms, mf->max_retries, 1 /*open is idempotent*/ };
    int rc = brix_aio_call_ex(mf->ac, &req, payload, (uint32_t) plen, &o,
                              &kxr, &body, &blen, st);
    free(payload);
    if (rc != 0) {
        return -1;
    }
    if (blen < XRD_FHANDLE_LEN) {
        brix_status_set(st, XRDC_EPROTO, 0, "open reply too short (%u bytes)", blen);
        free(body);
        return -1;
    }
    memcpy(mf->fhandle, body, XRD_FHANDLE_LEN);

    /* phase-42 W4/W5: learn the inline-compression codec from the open reply.
     * Re-learned on every (re)open, so a fault mid-transfer re-negotiates. */
    rc = mfile_learn_codec(mf, body, blen, st);
    free(body);
    return rc;
}

brix_mfile *
brix_mfile_open(brix_aconn *ac, const char *path, int writable, int force,
                int posc, const char *opaque, int max_stall_ms, int max_retries,
                brix_status *st)
{
    brix_mfile *mf = (brix_mfile *) calloc(1, sizeof(*mf));
    if (mf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory (mfile)");
        return NULL;
    }
    mf->ac = ac;
    snprintf(mf->path, sizeof(mf->path), "%s", path);
    if (opaque != NULL && opaque[0] != '\0') {
        snprintf(mf->opaque, sizeof(mf->opaque), "%s", opaque);
        mf->have_opaque = 1;
    }
    mf->writable     = writable;
    mf->posc         = posc;
    mf->max_stall_ms = max_stall_ms;
    mf->max_retries  = max_retries;
    pthread_mutex_init(&mf->lock, NULL);

    if (mfile_do_open(mf, force, st) != 0) {
        pthread_mutex_destroy(&mf->lock);
        free(mf);
        return NULL;
    }
    mf->have_handle = 1;
    mf->gen = 1;
    return mf;
}

/* A failure that a reopen + retry might fix: a transient transport fault, or a
 * stale handle after the session was re-established. */
static int
mfile_should_reopen(const brix_status *st)
{
    return brix_status_retryable(st) || st->kxr == kXR_FileNotOpen;
}

/* Reopen the file NON-destructively if no one else already did (generation match).
 * Returns 0 if the file is open (by us or a racing caller), -1 on failure. */
static int
mfile_reopen(brix_mfile *mf, uint64_t expected_gen, brix_status *st)
{
    pthread_mutex_lock(&mf->lock);
    if (mf->gen != expected_gen && mf->have_handle) {
        pthread_mutex_unlock(&mf->lock);
        return 0;   /* someone else reopened while we waited */
    }
    mf->have_handle = 0;
    int rc = mfile_do_open(mf, mf->writable ? 2 /*update, no truncate*/ : -1, st);
    if (rc == 0) {
        mf->have_handle = 1;
        mf->gen++;
    }
    pthread_mutex_unlock(&mf->lock);
    return rc;
}

/* Snapshot the current handle + generation (+ optional read/write codecs) under
 * the lock.  rcodec/wcodec may be NULL for callers that don't need them. */
static int
mfile_snapshot(brix_mfile *mf, uint8_t fh[XRD_FHANDLE_LEN], uint64_t *gen,
               uint8_t *rcodec, uint8_t *wcodec)
{
    pthread_mutex_lock(&mf->lock);
    int ok = mf->have_handle;
    if (ok) {
        memcpy(fh, mf->fhandle, XRD_FHANDLE_LEN);
    }
    if (rcodec != NULL) {
        *rcodec = mf->read_codec;
    }
    if (wcodec != NULL) {
        *wcodec = mf->write_codec;
    }
    *gen = mf->gen;
    pthread_mutex_unlock(&mf->lock);
    return ok;
}

ssize_t
brix_mfile_pread(brix_mfile *mf, int64_t off, void *buf, size_t len,
                 brix_status *st)
{
    /* Retry transport faults until the max_stall patience window elapses, with
     * exponential backoff between attempts — NOT a fixed small count. Under
     * sustained loss (a flapping firewall) a fixed count is exhausted in a tight
     * spin long before the patience window, surfacing a spurious EIO; bounding by
     * the deadline rides the loss out as long as progress is possible. */
    uint64_t deadline = now_ns() + (uint64_t) mf->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;

    for (;;) {
        uint8_t  fh[XRD_FHANDLE_LEN];
        uint64_t gen;
        uint8_t  codec = 0;
        if (!mfile_snapshot(mf, fh, &gen, &codec, NULL)) {
            if (mfile_reopen(mf, gen, st) != 0) {
                if (now_ns() >= deadline) {
                    return -1;
                }
                brix_backoff_sleep_fast(attempt++);
            }
            continue;
        }

        ClientReadRequest req;
        memset(&req, 0, sizeof(req));
        req.requestid = htons(kXR_read);
        {
            xrdw_read_req_t b = { .offset = off, .rlen = (int32_t) len };
            memcpy(b.fhandle, fh, XRD_FHANDLE_LEN);
            xrdw_read_req_pack(&b, ((ClientRequestHdr *) &req)->body);
        }

        uint16_t kxr = 0;
        uint8_t *body = NULL;
        uint32_t blen = 0;
        brix_aio_opts o = { mf->max_stall_ms, 0, 0 /*we own reopen/retry*/ };
        if (brix_aio_call_ex(mf->ac, &req, NULL, 0, &o, &kxr, &body, &blen, st) == 0) {
            /* phase-42 W4: a compressed handle returns one self-contained codec
             * frame per request (aio_call_ex has already accumulated all
             * oksofar frames into `body`); inflate it into the caller's buffer.
             * A corrupt frame is not a transport fault — do not reopen/retry. */
            if (codec != 0) {
                ssize_t pl = brix_inflate_frame(codec, body, blen, buf, len, st);
                free(body);
                return pl;
            }
            size_t n = (blen < len) ? blen : len;
            if (n > 0) {
                memcpy(buf, body, n);
            }
            free(body);
            return (ssize_t) n;
        }
        if (!mfile_should_reopen(st) || now_ns() >= deadline) {
            return -1;
        }
        brix_backoff_sleep_fast(attempt++);          /* don't tight-spin under loss */
        (void) mfile_reopen(mf, gen, st);       /* refresh handle, then retry */
    }
}

int
brix_mfile_pwrite(brix_mfile *mf, int64_t off, const void *buf, size_t len,
                  brix_status *st)
{
    /* Deadline-bounded retry with backoff (see brix_mfile_pread). */
    uint64_t deadline = now_ns() + (uint64_t) mf->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;

    for (;;) {
        uint8_t  fh[XRD_FHANDLE_LEN];
        uint64_t gen;
        uint8_t  wcodec = 0;
        if (!mfile_snapshot(mf, fh, &gen, NULL, &wcodec)) {
            if (mfile_reopen(mf, gen, st) != 0) {
                if (now_ns() >= deadline) {
                    return -1;
                }
                brix_backoff_sleep_fast(attempt++);
            }
            continue;
        }

        /* phase-42 W5: a compression-negotiated write handle compresses each
         * payload as a self-contained frame; the server decompresses on ingest.
         * The request offset stays the PLAINTEXT offset. */
        const void *payload = buf;
        size_t      plen    = len;
        uint8_t    *frame   = NULL;
        if (wcodec != 0 && len > 0) {
            size_t flen = 0;
            frame = brix_deflate_frame(wcodec, buf, len, &flen, st);
            if (frame == NULL) {
                return -1;   /* compress failure is not a transport fault */
            }
            payload = frame;
            plen    = flen;
        }

        ClientWriteRequest req;
        memset(&req, 0, sizeof(req));
        req.requestid = htons(kXR_write);
        {
            xrdw_write_req_t b = { .offset = off, .pathid = 0 };
            memcpy(b.fhandle, fh, XRD_FHANDLE_LEN);
            xrdw_write_req_pack(&b, ((ClientRequestHdr *) &req)->body);
        }

        uint16_t kxr = 0;
        brix_aio_opts o = { mf->max_stall_ms, 0, 0 };
        int rc = brix_aio_call_ex(mf->ac, &req, payload, (uint32_t) plen, &o,
                                  &kxr, NULL, NULL, st);
        free(frame);
        if (rc == 0) {
            return 0;
        }
        if (!mfile_should_reopen(st) || now_ns() >= deadline) {
            return -1;
        }
        brix_backoff_sleep_fast(attempt++);
        (void) mfile_reopen(mf, gen, st);
    }
}

int
brix_mfile_sync(brix_mfile *mf, brix_status *st)
{
    uint8_t  fh[XRD_FHANDLE_LEN] = { 0 };
    uint64_t gen;
    if (!mfile_snapshot(mf, fh, &gen, NULL, NULL)) {
        if (mfile_reopen(mf, gen, st) != 0) {
            return -1;
        }
        (void) mfile_snapshot(mf, fh, &gen, NULL, NULL);
    }
    ClientSyncRequest req;
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_sync);
    {
        xrdw_sync_req_t b;
        memcpy(b.fhandle, fh, XRD_FHANDLE_LEN);
        xrdw_sync_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    uint16_t kxr = 0;
    /* A sync after a reopen is meaningless (fresh handle), but re-issuing is
     * harmless; do not loop — a failed sync is reported, not retried forever. */
    return brix_aio_call(mf->ac, &req, NULL, 0, &kxr, NULL, NULL,
                         mf->max_stall_ms, st);
}

int
brix_mfile_close(brix_mfile *mf, brix_status *st)
{
    int rc = 0;
    if (mf->have_handle) {
        ClientCloseRequest req;
        memset(&req, 0, sizeof(req));
        req.requestid = htons(kXR_close);
        {
            xrdw_close_req_t b;
            memcpy(b.fhandle, mf->fhandle, XRD_FHANDLE_LEN);
            xrdw_close_req_pack(&b, ((ClientRequestHdr *) &req)->body);
        }
        uint16_t kxr = 0;
        /* Best-effort: if the conn is down the server reaps the handle on
         * disconnect anyway, so a close failure is not fatal. */
        rc = brix_aio_call(mf->ac, &req, NULL, 0, &kxr, NULL, NULL, 5000, st);
    }
    pthread_mutex_destroy(&mf->lock);
    free(mf);
    return rc;
}
