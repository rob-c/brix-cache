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

/* Allocate the manager shell and bring the async loop up.
 *
 * WHAT: calloc the brix_mgr plus its per-slot conns[nconns]/acs[nconns] arrays,
 *       copy the retained url/opts + resilience knobs, init lazy_lock, and create
 *       the shared loop. Returns the ready (but streamless) manager, or NULL with
 *       *st populated on any allocation/loop-create failure.
 * WHY:  brix_mgr_create's own complexity comes from the eager connect/attach
 *       phases; pulling the fixed setup out keeps that orchestration flat and
 *       keeps every early-return cleanup local to the resource it owns.
 * HOW:  1) calloc the shell (out-of-memory → status, return NULL).
 *       2) calloc conns + acs; on either failure free both + shell, return NULL.
 *       3) copy scalar fields + url; copy opts only when the caller passed some.
 *       4) init lazy_lock, then create the loop; loop failure → mgr_free (acs all
 *          NULL ⇒ it frees loop+arrays) and return NULL. */
static brix_mgr *
mgr_alloc_and_init(const brix_url *u, const brix_opts *o, int nconns,
                   int max_stall_ms, int keepalive_ms, int max_retries,
                   brix_status *st)
{
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
    return m;
}

/* Connect the first `eager` streams concurrently and require all to succeed.
 *
 * WHAT: Runs `eager` parallel connect jobs against slots 0..eager-1; returns 0
 *       with every conns[i] connected, or -1 with *st set to the first failure
 *       and any slot that DID connect already closed. The acs[] entries stay NULL
 *       (attach happens later).
 * WHY:  Overlapping the connect+TLS+login+auth round-trips collapses mount-time
 *       wall from eager×RTT to ~1×RTT; failing the whole mount if any eager stream
 *       cannot connect gives a bad endpoint/auth an immediate, clean failure.
 * HOW:  1) calloc the job array (OOM → status, return -1).
 *       2) point each job at the retained url/opts and its slot, prime rc=-1.
 *       3) mgr_connect_parallel spawns+joins the workers.
 *       4) scan results; on the first rc!=0 copy its status, close the OTHER
 *          successfully-connected conns (this one isn't open), free jobs, -1.
 *       5) all connected → free jobs, return 0. Caller closes conns via mgr_free
 *          only after acs are populated, so failed-phase conns are closed here. */
static int
mgr_connect_eager(brix_mgr *m, int eager, brix_status *st)
{
    mgr_connect_job *jobs = (mgr_connect_job *) calloc((size_t) eager,
                                                       sizeof(*jobs));
    int i;

    if (jobs == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory (mgr jobs)");
        return -1;
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
            return -1;
        }
    }
    free(jobs);
    return 0;
}

/* Attach the eager (already-connected) streams to the loop and arm resilience.
 *
 * WHAT: For slots 0..eager-1, attach conns[i] to the loop into acs[i] and set its
 *       stall/keepalive/retry policy. Returns 0 on full success, or -1 with the
 *       just-failed conn and every still-unattached higher conn closed (their acs
 *       stay NULL, so a following mgr_free frees the rest).
 * WHY:  Attach touches the shared loop and is cheap, so it runs serially after the
 *       parallel connect; keeping it separate keeps brix_mgr_create flat.
 * HOW:  1) walk i in [0, eager): brix_aconn_attach conns[i] → acs[i].
 *       2) on NULL, close conns[i] (its attach failed) and every conns[i+1..]
 *          (never attached, so mgr_free won't reach them) and return -1.
 *       3) otherwise arm resilience and continue; return 0 when all attached. */
static int
mgr_attach_eager(brix_mgr *m, int eager, brix_status *st)
{
    int i;
    for (i = 0; i < eager; i++) {
        m->acs[i] = brix_aconn_attach(m->loop, &m->conns[i], st);
        if (m->acs[i] == NULL) {
            brix_close(&m->conns[i]);          /* this one attached failed */
            for (int k = i + 1; k < eager; k++) { brix_close(&m->conns[k]); }
            return -1;
        }
        brix_aconn_set_resilience(m->acs[i], m->max_stall_ms, m->keepalive_ms,
                                  m->max_retries);
    }
    return 0;
}

brix_mgr *
brix_mgr_create(const brix_url *u, const brix_opts *o, int nconns, int eager,
                int max_stall_ms, int keepalive_ms, int max_retries,
                brix_status *st)
{
    brix_mgr *m;

    if (nconns < 1) {
        nconns = 1;
    }
    /* At least one stream connects up front so a bad endpoint / auth fails the
     * mount immediately; the remainder may be eager or lazy per the caller. */
    if (eager < 1)      { eager = 1; }
    if (eager > nconns) { eager = nconns; }

    m = mgr_alloc_and_init(u, o, nconns, max_stall_ms, keepalive_ms, max_retries,
                           st);
    if (m == NULL) {
        return NULL;
    }

    /* Connect the eager streams concurrently, then attach them to the loop
     * serially (attach touches the shared loop and is not the slow part). */
    if (mgr_connect_eager(m, eager, st) != 0) {
        mgr_free(m);                       /* acs all NULL ⇒ frees loop+arrays */
        return NULL;
    }
    if (mgr_attach_eager(m, eager, st) != 0) {
        mgr_free(m);
        return NULL;
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

