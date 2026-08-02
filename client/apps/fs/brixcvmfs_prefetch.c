/*
 * brixcvmfs_prefetch.c — CVMFS-brix predictive subtree prefetch (Phase-38 split).
 *
 * WHAT: the opt-in F4 readahead worker — the first readdir of a directory
 *       queues it, a background thread walks the catalog subtree and pre-pulls
 *       every referenced CAS object into the shared cache (G2 .cvmfs-bundle
 *       batching when armed), so later opens are cache hits.
 * WHY:  split from brixcvmfs.c to keep each TU within the file-size budget; the
 *       worker owns its own failover/scratch/CAS-store state and is a pure
 *       best-effort accelerator — its errors are always swallowed and can never
 *       fail a foreground FUSE op.
 * HOW:  the FUSE thread enqueues (pf_enqueue); the detached worker (pf_main)
 *       borrows a libcurl handle from the shared pool per fetch (exclusive
 *       checkout, so it never races the foreground loop) and is bounded by a
 *       byte budget. Single-writer packed caches share the mount's store.
 */
#include "cvmfs/walk/walk.h"
#include "cvmfs/bundle/bundle.h"
#include "brixcvmfs_split.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- predictive prefetch (phase-85 F4) ---------------------------------- *
 * Opt-in subtree readahead: the first readdir of a directory queues it for a
 * background worker that walks the catalog subtree (cvmfs_walk_subtree) and
 * pre-pulls every referenced CAS object into the shared cache, so subsequent
 * opens are cache hits. The worker owns its OWN failover state, scratch and
 * CAS-store handle (puts are O_EXCL+rename atomic, so sharing the cache
 * DIRECTORY with the foreground is safe); its libcurl handle is borrowed from
 * the shared g_curl_pool per fetch (exclusive checkout, so it never races the
 * FUSE loop's handle). Bounded by a byte budget;
 * prefetch errors are always swallowed — they can never fail a foreground op. */

#define BRIX_PF_QCAP     32
#define BRIX_PF_SEENCAP  512

typedef struct {
    int             enabled;
    int             depth;                 /* nested-catalog descent budget */
    long            budget;                /* bytes; <= 0 = unbounded */
    long            spent;
    int             capped;                /* budget hit: audit once, drain queue */
    char            tmp_dir[512];
    char            cache_dir[512];
    int             cache_dirfd;           /* dup'd overlay dirfd, or -1 */
    long            quota;
    pthread_t       tid;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    struct { char path[1024]; cvmfs_hash_t root; } q[BRIX_PF_QCAP];
    int             qh, qn;
    uint64_t        seen[BRIX_PF_SEENCAP]; /* FNV-1a of queued dir paths */
    int             nseen;
    cvmfs_failover_t fo;                   /* worker-owned failover state */
    cvmfs_failover_t fo0;                  /* pristine snapshot (blacklist reset) */
    /* -o bundle (phase-87 G2): walk items batch up and one .cvmfs-bundle POST
     * pre-stores the cache-resident members before the per-item pulls below
     * (which then resolve as verified cache hits). Worker-thread only. */
    int             bundle;
    int             nbatch;
    struct { cvmfs_hash_t hash; char suffix; } batch[CVMFS_BUNDLE_MAX_ITEMS];
    char            want[CVMFS_BUNDLE_MAX_WANT];
    unsigned char  *resp;                  /* lazily malloc'd reply buffer */
} brix_prefetch_t;

/* Reply buffer bound: full frame overhead for MAX_ITEMS plus the data budget. */
#define BRIX_PF_RESPCAP                                                     \
    (CVMFS_BUNDLE_HDR_LEN                                                   \
     + CVMFS_BUNDLE_MAX_ITEMS * (12u + CVMFS_BUNDLE_MAX_PATH)               \
     + CVMFS_BUNDLE_MAX_TOTAL)

static brix_prefetch_t g_pf = { .cache_dirfd = -1 };

static uint64_t pf_fnv1a(const char *s) {
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++) { h ^= (unsigned char) *s; h *= 1099511628211ull; }
    return h;
}

typedef struct {
    cvmfs_fetch_ctx_t *fx;
    unsigned char     *out;
} pf_walk_ud_t;
/* Flush the batched walk items: one .cvmfs-bundle POST for the not-yet-cached
 * members, ingest the reply (per-member CAS verify — fetch_bundle.c), then
 * pull EVERY batched object through cvmfs_fetch_object as usual. Bundle-stored
 * members resolve as verified cache hits; misses, rejects and any bundle
 * failure at all fall back to the ordinary single fetches — the bundle is an
 * RTT optimization, never a second trust or error path. */
/* Build the want-list for the current batch: every member not already in the
 * cache, as "data/<object-path>" lines in g_pf.want. Returns the list length. */
static size_t pf_bundle_want(cvmfs_fetch_ctx_t *fx) {
    size_t wn = 0;

    for (int i = 0; i < g_pf.nbatch; i++) {
        char key[160], obj[160];
        int  need;
        if (cvmfs_hash_to_hex(&g_pf.batch[i].hash, g_pf.batch[i].suffix,
                              key, sizeof(key)) < 0
            || brix_cas_has(fx->cache, key)
            || cvmfs_hash_to_object_path(&g_pf.batch[i].hash,
                                         g_pf.batch[i].suffix,
                                         obj, sizeof(obj)) < 0)
            continue;
        need = snprintf(g_pf.want + wn, sizeof(g_pf.want) - wn, "data/%s\n", obj);
        if (need < 0 || wn + (size_t) need >= sizeof(g_pf.want)) break;
        wn += (size_t) need;
    }

    return wn;
}

static void pf_bundle_flush(pf_walk_ud_t *p) {
    cvmfs_fetch_ctx_t *fx = p->fx;
    size_t wn = pf_bundle_want(fx);
    int    i;

    if (wn > 0) {
        if (g_pf.resp == NULL) g_pf.resp = malloc(BRIX_PF_RESPCAP);
        cvmfs_fo_route_t route;
        if (g_pf.resp != NULL
            && cvmfs_failover_select(fx->fo, mono_now(), &route) == 0) {
            const char *proxy = route.proxy >= 0
                              ? fx->fo->proxies[route.proxy].url : NULL;
            size_t rn = 0;
            if (bundle_http_post(proxy, fx->fo->hosts[route.host].url,
                                 g_pf.want, wn,
                                 g_pf.resp, BRIX_PF_RESPCAP, &rn) == 0) {
                unsigned stored = 0, fb = 0;
                (void) cvmfs_bundle_ingest(fx, g_pf.resp, rn, &stored, &fb);
            }
        }
    }

    for (i = 0; i < g_pf.nbatch; i++) {
        size_t n = 0;
        if (g_pf.budget > 0 && g_pf.spent >= g_pf.budget)
            break;             /* pf_visit fires the one prefetchcap audit line */
        if (cvmfs_fetch_object(fx, &g_pf.batch[i].hash, g_pf.batch[i].suffix,
                               p->out, BRIX_PF_OBJCAP, &n, mono_now()) == 0)
            g_pf.spent += (long) n;
        else
            g_pf.fo = g_pf.fo0;                /* same reset as the unbatched path */
    }
    g_pf.nbatch = 0;
}

static int pf_visit(const cvmfs_walk_item_t *it, void *ud) {
    pf_walk_ud_t *p = ud;
    if (it->kind == CVMFS_WALK_CATALOG) return 0;   /* the walk itself cached it */
    if (g_pf.budget > 0 && g_pf.spent >= g_pf.budget) {
        if (!g_pf.capped) {
            g_pf.capped = 1;
            fprintf(stderr, "brixcvmfs: audit signal=prefetchcap repo=%s "
                    "budget=%ld spent=%ld (prefetch stopped, foreground unaffected)\n",
                    g_cl->config.name, g_pf.budget, g_pf.spent);
        }
        return 1;
    }
    if (g_pf.bundle) {          /* G2: batch up; flush POSTs + pulls in bulk */
        g_pf.batch[g_pf.nbatch].hash   = it->hash;
        g_pf.batch[g_pf.nbatch].suffix = it->suffix;
        if (++g_pf.nbatch == (int) CVMFS_BUNDLE_MAX_ITEMS)
            pf_bundle_flush(p);
        return 0;
    }
    size_t n = 0;
    if (cvmfs_fetch_object(p->fx, &it->hash, it->suffix,
                           p->out, BRIX_PF_OBJCAP, &n, mono_now()) == 0)
        g_pf.spent += (long) n;
    else
        g_pf.fo = g_pf.fo0;   /* one bad object blacklists its route — restore the
                               * pristine snapshot so it can't shadow the sweep */
    return 0;   /* fetch errors never stop the sweep */
}

static void *pf_main(void *arg) {
    (void) arg;
    brix_cas_store_t own;
    brix_cas_store_t *cache;
    int crc = 0;
    if (g_cl->cache.pack != NULL) {
        /* Packed backend (G4) is a single-writer log: a second handle on the
         * same dir would interleave appends and corrupt it. Share the mount's
         * store — every pack op is serialized by its internal mutex. */
        cache = &g_cl->cache;
    } else {
        crc = g_pf.cache_dirfd >= 0
            ? brix_cas_init_at(&own, g_pf.cache_dirfd, g_pf.quota)
            : brix_cas_init(&own, g_pf.cache_dir, g_pf.quota);
        cache = &own;
    }
    unsigned char *scratch = malloc(BRIX_PF_OBJCAP);
    unsigned char *out     = malloc(BRIX_PF_OBJCAP);
    if (crc != 0 || scratch == NULL || out == NULL) {
        free(scratch); free(out);
        return NULL;                       /* prefetch unavailable, mount unaffected */
    }

    cvmfs_fetch_ctx_t fx;
    memset(&fx, 0, sizeof(fx));
    fx.fo = &g_pf.fo;
    fx.cache = cache;
    fx.transport = brixcvmfs_transport;
    fx.transport_ud = NULL;                /* handle borrowed from g_curl_pool per fetch */
    fx.store_form = CVMFS_STORE_COMPRESSED;
    fx.scratch = scratch;
    fx.scratch_cap = BRIX_PF_OBJCAP;

    for (;;) {
        pthread_mutex_lock(&g_pf.mu);
        while (g_pf.qn == 0) pthread_cond_wait(&g_pf.cv, &g_pf.mu);
        char path[1024];
        cvmfs_hash_t root = g_pf.q[g_pf.qh].root;
        snprintf(path, sizeof(path), "%s", g_pf.q[g_pf.qh].path);
        g_pf.qh = (g_pf.qh + 1) % BRIX_PF_QCAP;
        g_pf.qn--;
        pthread_mutex_unlock(&g_pf.mu);

        if (g_pf.capped) continue;         /* drain silently once the budget is hit */
        pf_walk_ud_t ud = { &fx, out };
        cvmfs_walk_subtree(&fx, &root, g_pf.tmp_dir, path, g_pf.depth,
                           pf_visit, &ud, mono_now());
        if (g_pf.bundle && g_pf.nbatch > 0)
            pf_bundle_flush(&ud);          /* tail batch of this subtree */
    }
    return NULL;
}

/* FUSE-thread side: queue `path` once. Drops silently when the queue is full
 * or the path was already prefetched — advisory readahead, never a failure. */
void pf_enqueue(const char *path) {
    if (!g_pf.enabled) return;
    uint64_t h = pf_fnv1a(path);
    for (int i = 0; i < g_pf.nseen; i++)
        if (g_pf.seen[i] == h) return;
    if (g_pf.nseen < BRIX_PF_SEENCAP) g_pf.seen[g_pf.nseen++] = h;

    pthread_mutex_lock(&g_pf.mu);
    if (g_pf.qn < BRIX_PF_QCAP) {
        int slot = (g_pf.qh + g_pf.qn) % BRIX_PF_QCAP;
        snprintf(g_pf.q[slot].path, sizeof(g_pf.q[slot].path), "%s", path);
        g_pf.q[slot].root = g_cl->pin_set ? g_cl->pin_root
                                          : g_cl->manifest.root_catalog;
        g_pf.qn++;
        pthread_cond_signal(&g_pf.cv);
    }
    pthread_mutex_unlock(&g_pf.mu);
}

/* Called once between mount and fuse_main (still single-threaded): snapshot the
 * failover set and start the worker. Failure to start just disables prefetch. */
void pf_start(int depth, long budget, const char *tmp_dir,
              const char *cache_dir, int cache_dirfd, long quota,
              int bundle) {
    g_pf.bundle = bundle;
    g_pf.depth = depth;
    g_pf.budget = budget;
    snprintf(g_pf.tmp_dir, sizeof(g_pf.tmp_dir), "%s", tmp_dir);
    snprintf(g_pf.cache_dir, sizeof(g_pf.cache_dir), "%s", cache_dir);
    g_pf.cache_dirfd = cache_dirfd >= 0 ? dup(cache_dirfd) : -1;
    g_pf.quota = quota;
    g_pf.fo = g_pf.fo0 = g_cl->fo;         /* snapshot; worker state evolves alone */
    pthread_mutex_init(&g_pf.mu, NULL);
    pthread_cond_init(&g_pf.cv, NULL);
    if (pthread_create(&g_pf.tid, NULL, pf_main, NULL) == 0) {
        pthread_detach(g_pf.tid);
        g_pf.enabled = 1;
    }
}
