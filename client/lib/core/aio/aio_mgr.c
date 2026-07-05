/*
 * aio_mgr.c — connection manager + transparent file-handle resumption (M3).
 *
 * WHAT: Two layers on top of the async loop (aio.c):
 *        - brix_mgr: the loop plus a small pool of attached connections. Metadata
 *          requests round-robin across them; idempotent ones survive a reconnect
 *          transparently (retry_safe at the transport layer, M2).
 *        - brix_mfile: an open file that survives a connection drop. Because an
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
 *        brix_aio_call, and the (many) FUSE worker threads calling concurrently
 *        pipeline over the shared connection. A per-file mutex + generation counter
 *        serialises reopen so concurrent callers reopen at most once and then reuse
 *        the fresh handle.
 *
 * Clean-room: the existing wire structs (ClientOpen/Read/Write/Close/SyncRequest)
 * + the async loop. No XrdCl.
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
#include <endian.h>

/* mgr */
struct brix_mgr {
    brix_loop   *loop;
    int          n;        /* total stream slots */
    brix_conn   *conns;    /* array[n], owned */
    brix_aconn **acs;      /* array[n]; acs[i]==NULL ⇒ slot i not yet connected */
    int          rr;       /* round-robin cursor */
    int          max_stall_ms;
    int          keepalive_ms;
    int          max_retries;
    /* Retained so lazily-opened streams (eager < n) can connect on first use. */
    brix_url        url;
    brix_opts       opts;
    int             have_opts;   /* opts captured (vs caller passed NULL) */
    pthread_mutex_t lazy_lock;   /* serialises first-use connect of a lazy slot */
};

/* One parallel-connect job: a worker thread runs brix_connect on its own slot so
 * the eager streams' connect+TLS+login+auth round-trips overlap (mount-time wall
 * collapses from eager×RTT to ~1×RTT). Threads are joined before mgr_create
 * returns, so they never cross a later fuse daemonize fork. */
typedef struct {
    const brix_url  *u;
    const brix_opts *o;
    brix_conn       *conn;   /* slot to fill */
    brix_status      st;     /* per-thread status (no shared writes) */
    int              rc;     /* 0 ok, -1 fail */
} mgr_connect_job;

static void *
mgr_connect_worker(void *arg)
{
    mgr_connect_job *j = (mgr_connect_job *) arg;
    j->rc = brix_connect(j->conn, j->u, j->o, &j->st);
    return NULL;
}

/* Run `count` connect jobs concurrently and wait for all to finish. A thread that
 * fails to spawn runs its job inline (degrades to serial for that one), so the
 * caller always sees every job's rc/st populated on return. */
static void
mgr_connect_parallel(mgr_connect_job *jobs, int count)
{
    pthread_t *tids = (pthread_t *) calloc((size_t) count, sizeof(*tids));
    int        i;

    for (i = 0; i < count; i++) {
        if (tids == NULL
            || pthread_create(&tids[i], NULL, mgr_connect_worker, &jobs[i]) != 0) {
            if (tids != NULL) { tids[i] = (pthread_t) 0; }
            mgr_connect_worker(&jobs[i]);   /* inline fallback */
        }
    }
    if (tids != NULL) {
        for (i = 0; i < count; i++) {
            if (tids[i] != (pthread_t) 0) { pthread_join(tids[i], NULL); }
        }
        free(tids);
    }
}

/* Tear down a partially-built manager (used on any create-time failure). */
static void
mgr_free(brix_mgr *m)
{
    int i;
    for (i = 0; i < m->n; i++) {
        if (m->acs[i] != NULL) { brix_aconn_close(m->acs[i]); }
    }
    if (m->loop != NULL) { brix_loop_destroy(m->loop); }
    for (i = 0; i < m->n; i++) {
        if (m->acs[i] != NULL) { brix_close(&m->conns[i]); }
    }
    pthread_mutex_destroy(&m->lazy_lock);
    free(m->conns);
    free(m->acs);
    free(m);
}

brix_mgr *
brix_mgr_create(const brix_url *u, const brix_opts *o, int nconns, int eager,
                int max_stall_ms, int keepalive_ms, int max_retries,
                brix_status *st)
{
    mgr_connect_job *jobs;
    int              i;

    if (nconns < 1) {
        nconns = 1;
    }
    /* At least one stream connects up front so a bad endpoint / auth fails the
     * mount immediately; the remainder may be eager or lazy per the caller. */
    if (eager < 1)      { eager = 1; }
    if (eager > nconns) { eager = nconns; }

    brix_mgr *m = (brix_mgr *) calloc(1, sizeof(*m));
    if (m == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory (mgr)");
        return NULL;
    }
    m->conns = (brix_conn *) calloc((size_t) nconns, sizeof(*m->conns));
    m->acs   = (brix_aconn **) calloc((size_t) nconns, sizeof(*m->acs));
    if (m->conns == NULL || m->acs == NULL) {
        free(m->conns);
        free(m->acs);
        free(m);
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory (mgr arrays)");
        return NULL;
    }
    m->n            = nconns;
    m->max_stall_ms = max_stall_ms;
    m->keepalive_ms = keepalive_ms;
    m->max_retries  = max_retries;
    m->url          = *u;
    if (o != NULL) { m->opts = *o; m->have_opts = 1; }
    pthread_mutex_init(&m->lazy_lock, NULL);

    m->loop = brix_loop_create(st);
    if (m->loop == NULL) {
        mgr_free(m);
        return NULL;
    }

    /* Connect the eager streams concurrently, then attach them to the loop
     * serially (attach touches the shared loop and is not the slow part). */
    jobs = (mgr_connect_job *) calloc((size_t) eager, sizeof(*jobs));
    if (jobs == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory (mgr jobs)");
        mgr_free(m);
        return NULL;
    }
    for (i = 0; i < eager; i++) {
        jobs[i].u = &m->url; jobs[i].o = m->have_opts ? &m->opts : NULL;
        jobs[i].conn = &m->conns[i]; jobs[i].rc = -1;
    }
    mgr_connect_parallel(jobs, eager);

    for (i = 0; i < eager; i++) {
        if (jobs[i].rc != 0) {
            *st = jobs[i].st;                 /* surface the first real failure */
            for (int k = 0; k < eager; k++) { /* close any that DID connect */
                if (k != i && jobs[k].rc == 0) { brix_close(&m->conns[k]); }
            }
            free(jobs);
            mgr_free(m);                       /* acs all NULL ⇒ frees loop+arrays */
            return NULL;
        }
    }
    free(jobs);

    for (i = 0; i < eager; i++) {
        m->acs[i] = brix_aconn_attach(m->loop, &m->conns[i], st);
        if (m->acs[i] == NULL) {
            brix_close(&m->conns[i]);          /* this one attached failed */
            for (int k = i + 1; k < eager; k++) { brix_close(&m->conns[k]); }
            mgr_free(m);
            return NULL;
        }
        brix_aconn_set_resilience(m->acs[i], max_stall_ms, keepalive_ms,
                                  max_retries);
    }
    return m;
}

void
brix_mgr_destroy(brix_mgr *m)
{
    if (m == NULL) {
        return;
    }
    mgr_free(m);
}

/* Bring a lazily-deferred slot up on first use: connect + attach + arm
 * resilience under lazy_lock (double-checked so concurrent pickers connect it
 * at most once). On failure the slot stays NULL and the caller falls back to an
 * already-live stream — eager ≥ 1 guarantees one exists. */
static brix_aconn *
mgr_ensure_slot(brix_mgr *m, int i)
{
    brix_aconn *ac = __atomic_load_n(&m->acs[i], __ATOMIC_ACQUIRE);
    brix_status st;

    if (ac != NULL) {
        return ac;
    }
    pthread_mutex_lock(&m->lazy_lock);
    ac = m->acs[i];                            /* re-check under the lock */
    if (ac == NULL) {
        if (brix_connect(&m->conns[i], &m->url,
                         m->have_opts ? &m->opts : NULL, &st) == 0) {
            ac = brix_aconn_attach(m->loop, &m->conns[i], &st);
            if (ac != NULL) {
                brix_aconn_set_resilience(ac, m->max_stall_ms, m->keepalive_ms,
                                          m->max_retries);
                __atomic_store_n(&m->acs[i], ac, __ATOMIC_RELEASE);
            } else {
                brix_close(&m->conns[i]);
            }
        }
    }
    pthread_mutex_unlock(&m->lazy_lock);
    return ac;
}

brix_aconn *
brix_mgr_pick(brix_mgr *m)
{
    int         i = __atomic_fetch_add(&m->rr, 1, __ATOMIC_RELAXED);
    brix_aconn *ac;
    int         k;

    if (i < 0) {
        i = -i;
    }
    i %= m->n;

    ac = mgr_ensure_slot(m, i);
    if (ac != NULL) {
        return ac;
    }
    /* Lazy connect of slot i failed (server hiccup): fall back to any live
     * stream rather than returning NULL — at least the eager slot(s) are up. */
    for (k = 0; k < m->n; k++) {
        ac = __atomic_load_n(&m->acs[k], __ATOMIC_ACQUIRE);
        if (ac != NULL) {
            return ac;
        }
    }
    return NULL;
}

int
brix_mgr_call(brix_mgr *m, const void *hdr24, const void *payload,
              uint32_t plen, int retry_safe, uint16_t *kxr,
              uint8_t **body, uint32_t *blen, brix_status *st)
{
    brix_aconn   *ac = brix_mgr_pick(m);
    brix_aio_opts o  = { 0 /*adaptive*/, m->max_retries, retry_safe };
    return brix_aio_call_ex(ac, hdr24, payload, plen, &o, kxr, body, blen, st);
}

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

/* Build + send a kXR_open with the given force tri-state (see brix_file_open_opaque).
 * On success copies the fresh handle into mf->fhandle. Caller holds no lock. */
static int
mfile_do_open(brix_mfile *mf, int force, brix_status *st)
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

    /* phase-42 W4/W5: learn the inline-compression codec from the open reply
     * (ServerOpenBody = fhandle[4] cpsize[4] cptype[4]).  Per the dual-check
     * contract (codec_core.h) adopt cptype[0] ONLY when cpsize == the big-endian
     * BRIX_INLINE_CMP_MAGIC: cptype is a legacy field a non-cooperating server
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
        if (cpsize == BRIX_INLINE_CMP_MAGIC && cid >= 1 && cid < BRIX_CODEC_MAX) {
            /* Server confirmed codec `cid`; if this build cannot handle it, fail
             * the open rather than silently copying compressed bytes as plaintext
             * (asymmetric-build corruption). */
            if (!brix_codec_available(cid)) {
                brix_status_set(st, XRDC_EUNSUPPORTED, 0,
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
