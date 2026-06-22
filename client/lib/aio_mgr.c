/*
 * aio_mgr.c — connection manager + transparent file-handle resumption (M3).
 *
 * WHAT: Two layers on top of the async loop (aio.c):
 *        - xrdc_mgr: the loop plus a small pool of attached connections. Metadata
 *          requests round-robin across them; idempotent ones survive a reconnect
 *          transparently (retry_safe at the transport layer, M2).
 *        - xrdc_mfile: an open file that survives a connection drop. Because an
 *          XRootD file handle is valid only on the session that opened it, a
 *          reconnect invalidates it; so on a transport failure or a stale-handle
 *          error this layer REOPENS the file (fresh handle, NON-destructively — no
 *          re-truncate, no create-excl) and RE-ISSUES the read/write at the same
 *          absolute offset. Re-issuing the identical offset is idempotent, so a
 *          mid-transfer cat/dd survives a server restart with no data loss and no
 *          EIO reaching the caller.
 * WHY:   M2 makes the transport reconnect; M3 makes *open files* recover, which is
 *        what "survives a server bounce mid-transfer" actually requires.
 * HOW:   mfile is a blocking façade over the async loop: each pread/pwrite is one
 *        xrdc_aio_call, and the (many) FUSE worker threads calling concurrently
 *        pipeline over the shared connection. A per-file mutex + generation counter
 *        serialises reopen so concurrent callers reopen at most once and then reuse
 *        the fresh handle.
 *
 * Clean-room: the existing wire structs (ClientOpen/Read/Write/Close/SyncRequest)
 * + the async loop. No XrdCl.
 */
#include "aio.h"
#include "xrdc.h"
#include "protocol/protocol.h"
#include "compat/codec_core.h"   /* phase-42 W4 inline read decompression */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <endian.h>

/* ------------------------------------------------------------------- mgr ----- */

struct xrdc_mgr {
    xrdc_loop   *loop;
    int          n;
    xrdc_conn   *conns;    /* array[n], owned */
    xrdc_aconn **acs;      /* array[n] */
    int          rr;       /* round-robin cursor */
    int          max_stall_ms;
    int          max_retries;
};

xrdc_mgr *
xrdc_mgr_create(const xrdc_url *u, const xrdc_opts *o, int nconns,
                int max_stall_ms, int keepalive_ms, int max_retries,
                xrdc_status *st)
{
    if (nconns < 1) {
        nconns = 1;
    }
    xrdc_mgr *m = (xrdc_mgr *) calloc(1, sizeof(*m));
    if (m == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (mgr)");
        return NULL;
    }
    m->conns = (xrdc_conn *) calloc((size_t) nconns, sizeof(*m->conns));
    m->acs   = (xrdc_aconn **) calloc((size_t) nconns, sizeof(*m->acs));
    if (m->conns == NULL || m->acs == NULL) {
        free(m->conns);
        free(m->acs);
        free(m);
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (mgr arrays)");
        return NULL;
    }
    m->max_stall_ms = max_stall_ms;
    m->max_retries  = max_retries;

    m->loop = xrdc_loop_create(st);
    if (m->loop == NULL) {
        free(m->conns);
        free(m->acs);
        free(m);
        return NULL;
    }

    for (int i = 0; i < nconns; i++) {
        if (xrdc_connect(&m->conns[i], u, o, st) != 0) {
            /* tear down what we built */
            for (int j = 0; j < i; j++) {
                xrdc_aconn_close(m->acs[j]);
            }
            xrdc_loop_destroy(m->loop);
            for (int j = 0; j < i; j++) {
                xrdc_close(&m->conns[j]);
            }
            free(m->conns);
            free(m->acs);
            free(m);
            return NULL;
        }
        m->acs[i] = xrdc_aconn_attach(m->loop, &m->conns[i], st);
        if (m->acs[i] == NULL) {
            xrdc_close(&m->conns[i]);
            for (int j = 0; j < i; j++) {
                xrdc_aconn_close(m->acs[j]);
            }
            xrdc_loop_destroy(m->loop);
            for (int j = 0; j < i; j++) {
                xrdc_close(&m->conns[j]);
            }
            free(m->conns);
            free(m->acs);
            free(m);
            return NULL;
        }
        xrdc_aconn_set_resilience(m->acs[i], max_stall_ms, keepalive_ms, max_retries);
        m->n = i + 1;
    }
    return m;
}

void
xrdc_mgr_destroy(xrdc_mgr *m)
{
    if (m == NULL) {
        return;
    }
    for (int i = 0; i < m->n; i++) {
        xrdc_aconn_close(m->acs[i]);
    }
    xrdc_loop_destroy(m->loop);
    for (int i = 0; i < m->n; i++) {
        xrdc_close(&m->conns[i]);
    }
    free(m->conns);
    free(m->acs);
    free(m);
}

xrdc_aconn *
xrdc_mgr_pick(xrdc_mgr *m)
{
    int i = __atomic_fetch_add(&m->rr, 1, __ATOMIC_RELAXED);
    if (i < 0) {
        i = -i;
    }
    return m->acs[i % m->n];
}

int
xrdc_mgr_call(xrdc_mgr *m, const void *hdr24, const void *payload,
              uint32_t plen, int retry_safe, uint16_t *kxr,
              uint8_t **body, uint32_t *blen, xrdc_status *st)
{
    xrdc_aconn   *ac = xrdc_mgr_pick(m);
    xrdc_aio_opts o  = { 0 /*adaptive*/, m->max_retries, retry_safe };
    return xrdc_aio_call_ex(ac, hdr24, payload, plen, &o, kxr, body, blen, st);
}

/* ----------------------------------------------------------------- mfile ----- */

struct xrdc_mfile {
    xrdc_aconn     *ac;
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
     * xrdc_mfile_pwrite compresses its payload as a self-contained frame the
     * server decompresses on ingest.  Re-learned on every (re)open. */
    uint8_t         write_codec;
};

static uint64_t
now_ns(void)
{
    return xrdc_mono_ns();
}

/* Build + send a kXR_open with the given force tri-state (see xrdc_file_open_opaque).
 * On success copies the fresh handle into mf->fhandle. Caller holds no lock. */
static int
mfile_do_open(xrdc_mfile *mf, int force, xrdc_status *st)
{
    ClientOpenRequest req;
    uint16_t          options;
    uint16_t          kxr = 0;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;
    char             *payload;
    size_t            need;
    int               plen;

    if (mf->writable) {
        options = kXR_open_updt | kXR_mkpath;
        if (force == 1) {
            options |= kXR_delete;       /* truncate/overwrite */
        } else if (force == 0) {
            options |= kXR_new;          /* create-excl */
        }                                /* force == 2: update in place */
        if (mf->posc) {
            options |= kXR_posc;
        }
    } else {
        options = kXR_open_read;
    }

    need = strlen(mf->path) + 1 + (mf->have_opaque ? strlen(mf->opaque) + 1 : 0);
    payload = (char *) malloc(need);
    if (payload == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (open payload)");
        return -1;
    }
    plen = mf->have_opaque
         ? snprintf(payload, need, "%s?%s", mf->path, mf->opaque)
         : snprintf(payload, need, "%s", mf->path);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_open);
    req.mode      = mf->writable ? htons(0644) : 0;
    req.options   = htons(options);

    xrdc_aio_opts o = { mf->max_stall_ms, mf->max_retries, 1 /*open is idempotent*/ };
    int rc = xrdc_aio_call_ex(mf->ac, &req, payload, (uint32_t) plen, &o,
                              &kxr, &body, &blen, st);
    free(payload);
    if (rc != 0) {
        return -1;
    }
    if (blen < XRD_FHANDLE_LEN) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "open reply too short (%u bytes)", blen);
        free(body);
        return -1;
    }
    memcpy(mf->fhandle, body, XRD_FHANDLE_LEN);

    /* phase-42 W4/W5: learn the inline-compression codec from the open reply
     * (ServerOpenBody = fhandle[4] cpsize[4] cptype[4]).  Per the dual-check
     * contract (codec_core.h) adopt cptype[0] ONLY when cpsize == the big-endian
     * XROOTD_INLINE_CMP_MAGIC: cptype is a legacy field a non-cooperating server
     * may reuse, and trusting it alone would inflate plaintext and corrupt data.
     * Read opens inflate responses (W4); write opens compress payloads (W5).
     * Stock servers leave cpsize 0 → plaintext.  Re-learned on every (re)open, so
     * a fault mid-transfer transparently re-negotiates. */
    mf->read_codec = 0;
    mf->write_codec = 0;
    if (blen >= 12) {
        uint32_t cpsize = ((uint32_t) body[4] << 24) | ((uint32_t) body[5] << 16)
                        | ((uint32_t) body[6] << 8)  |  (uint32_t) body[7];
        uint8_t  cid    = body[8];   /* cptype[0] */
        if (cpsize == XROOTD_INLINE_CMP_MAGIC && cid >= 1 && cid < XROOTD_CODEC_MAX) {
            /* Server confirmed codec `cid`; if this build cannot handle it, fail
             * the open rather than silently copying compressed bytes as plaintext
             * (asymmetric-build corruption). */
            if (!xrootd_codec_available(cid)) {
                xrdc_status_set(st, XRDC_EUNSUPPORTED, 0,
                    "server negotiated inline-compression codec %u that this "
                    "client build cannot decode", (unsigned) cid);
                free(body);
                return -1;
            }
            if (mf->writable) {
                mf->write_codec = cid;
            } else {
                mf->read_codec = cid;
            }
        }
    }

    free(body);
    return 0;
}

xrdc_mfile *
xrdc_mfile_open(xrdc_aconn *ac, const char *path, int writable, int force,
                int posc, const char *opaque, int max_stall_ms, int max_retries,
                xrdc_status *st)
{
    xrdc_mfile *mf = (xrdc_mfile *) calloc(1, sizeof(*mf));
    if (mf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (mfile)");
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
mfile_should_reopen(const xrdc_status *st)
{
    return xrdc_status_retryable(st) || st->kxr == kXR_FileNotOpen;
}

/* Reopen the file NON-destructively if no one else already did (generation match).
 * Returns 0 if the file is open (by us or a racing caller), -1 on failure. */
static int
mfile_reopen(xrdc_mfile *mf, uint64_t expected_gen, xrdc_status *st)
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
mfile_snapshot(xrdc_mfile *mf, uint8_t fh[XRD_FHANDLE_LEN], uint64_t *gen,
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
xrdc_mfile_pread(xrdc_mfile *mf, int64_t off, void *buf, size_t len,
                 xrdc_status *st)
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
                xrdc_backoff_sleep_fast(attempt++);
            }
            continue;
        }

        ClientReadRequest req;
        memset(&req, 0, sizeof(req));
        req.requestid = htons(kXR_read);
        memcpy(req.fhandle, fh, XRD_FHANDLE_LEN);
        uint64_t off_be = htobe64((uint64_t) off);
        memcpy(&req.offset, &off_be, 8);
        req.rlen = (kXR_int32) htonl((uint32_t) len);

        uint16_t kxr = 0;
        uint8_t *body = NULL;
        uint32_t blen = 0;
        xrdc_aio_opts o = { mf->max_stall_ms, 0, 0 /*we own reopen/retry*/ };
        if (xrdc_aio_call_ex(mf->ac, &req, NULL, 0, &o, &kxr, &body, &blen, st) == 0) {
            /* phase-42 W4: a compressed handle returns one self-contained codec
             * frame per request (aio_call_ex has already accumulated all
             * oksofar frames into `body`); inflate it into the caller's buffer.
             * A corrupt frame is not a transport fault — do not reopen/retry. */
            if (codec != 0) {
                ssize_t pl = xrdc_inflate_frame(codec, body, blen, buf, len, st);
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
        xrdc_backoff_sleep_fast(attempt++);          /* don't tight-spin under loss */
        (void) mfile_reopen(mf, gen, st);       /* refresh handle, then retry */
    }
}

int
xrdc_mfile_pwrite(xrdc_mfile *mf, int64_t off, const void *buf, size_t len,
                  xrdc_status *st)
{
    /* Deadline-bounded retry with backoff (see xrdc_mfile_pread). */
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
                xrdc_backoff_sleep_fast(attempt++);
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
            frame = xrdc_deflate_frame(wcodec, buf, len, &flen, st);
            if (frame == NULL) {
                return -1;   /* compress failure is not a transport fault */
            }
            payload = frame;
            plen    = flen;
        }

        ClientWriteRequest req;
        memset(&req, 0, sizeof(req));
        req.requestid = htons(kXR_write);
        memcpy(req.fhandle, fh, XRD_FHANDLE_LEN);
        uint64_t off_be = htobe64((uint64_t) off);
        memcpy(&req.offset, &off_be, 8);

        uint16_t kxr = 0;
        xrdc_aio_opts o = { mf->max_stall_ms, 0, 0 };
        int rc = xrdc_aio_call_ex(mf->ac, &req, payload, (uint32_t) plen, &o,
                                  &kxr, NULL, NULL, st);
        free(frame);
        if (rc == 0) {
            return 0;
        }
        if (!mfile_should_reopen(st) || now_ns() >= deadline) {
            return -1;
        }
        xrdc_backoff_sleep_fast(attempt++);
        (void) mfile_reopen(mf, gen, st);
    }
}

int
xrdc_mfile_sync(xrdc_mfile *mf, xrdc_status *st)
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
    memcpy(req.fhandle, fh, XRD_FHANDLE_LEN);
    uint16_t kxr = 0;
    /* A sync after a reopen is meaningless (fresh handle), but re-issuing is
     * harmless; do not loop — a failed sync is reported, not retried forever. */
    return xrdc_aio_call(mf->ac, &req, NULL, 0, &kxr, NULL, NULL,
                         mf->max_stall_ms, st);
}

int
xrdc_mfile_close(xrdc_mfile *mf, xrdc_status *st)
{
    int rc = 0;
    if (mf->have_handle) {
        ClientCloseRequest req;
        memset(&req, 0, sizeof(req));
        req.requestid = htons(kXR_close);
        memcpy(req.fhandle, mf->fhandle, XRD_FHANDLE_LEN);
        uint16_t kxr = 0;
        /* Best-effort: if the conn is down the server reaps the handle on
         * disconnect anyway, so a close failure is not fatal. */
        rc = xrdc_aio_call(mf->ac, &req, NULL, 0, &kxr, NULL, NULL, 5000, st);
    }
    pthread_mutex_destroy(&mf->lock);
    free(mf);
    return rc;
}
