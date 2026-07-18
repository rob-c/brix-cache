/*
 * brixcvmfs.c — CVMFS-brix: a hardened, read-only CVMFS FUSE driver.
 *
 * WHAT: mounts a real CVMFS repository (e.g. atlas.cern.ch) as a read-only FUSE
 *       filesystem, driven entirely by the shared ngx-free CVMFS core
 *       (shared/cvmfs) — trust chain, SQLite catalogs, content-addressed fetch
 *       with replica+proxy failover, hash-verified retry, and offline cache mode.
 * WHY:  a single small binary that is "battle-tested against bad/evil networks":
 *       every object is verified by content hash, so any mirror/proxy failure or
 *       tampered reply is retried elsewhere and never trusted unverified.
 * HOW:  FUSE 3.1 high-level ops translate straight into cvmfs_client_* calls; a
 *       libcurl transport implements the injected fetch seam (per-request connect
 *       and low-speed timeouts = the adaptive-timeout pillar), while failover and
 *       verification are owned by the shared core. Read-only: every mutating op is
 *       refused with -EROFS.
 */
#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <curl/curl.h>

#include "cvmfs/client/client.h"
#include "cvmfs/config/cvmfs_conf.h"
#include "cvmfs/walk/walk.h"
#include "net/proxy_env.h"
#include "net/cpool.h"
#include "brixcvmfs_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---- process-global mount state (one repo per process) ------------------ */
static cvmfs_client_t *g_cl;

typedef struct {
    char repo[256];
    long connect_timeout_s;
    long low_speed_time_s;
    long low_speed_bytes;
    int  max_retries;      /* per-mirror retries (CVMFS_MAX_RETRIES) */
    int  fresh_connect;    /* -o fresh: FRESH_CONNECT + FORBID_REUSE (defeat DPI) */
    int  prefer_tls;       /* -o tls: try https:// before http:// */
} brixcvmfs_transport_cfg_t;

static brixcvmfs_transport_cfg_t g_tcfg;

/* ---- libcurl transport (the injected fetch seam) ------------------------ */

typedef struct { unsigned char *buf; size_t cap, len; } curl_sink_t;

static size_t curl_write_cb(char *ptr, size_t sz, size_t nm, void *ud) {
    curl_sink_t *s = ud;
    size_t n = sz * nm;
    if (s->len + n > s->cap) return 0;         /* overflow → curl aborts */
    memcpy(s->buf + s->len, ptr, n);
    s->len += n;
    return n;
}

/* Extract scheme + host + port from a URL for env-proxy resolution. */
static void url_host(const char *url, char *sch, size_t sl, char *host, size_t hl, int *port) {
    sch[0] = host[0] = '\0'; *port = 0;
    const char *p = url;
    const char *sep = strstr(url, "://");
    if (sep) { size_t n = (size_t)(sep - url); if (n < sl) { memcpy(sch, url, n); sch[n] = '\0'; } p = sep + 3; }
    size_t n = 0;
    while (p[n] && p[n] != ':' && p[n] != '/' && n < hl - 1) { host[n] = p[n]; n++; }
    host[n] = '\0';
    *port = (p[n] == ':') ? atoi(p + n + 1) : (strcmp(sch, "https") == 0 ? 443 : 80);
}

/* Persistent easy handles, pooled through the generic brix_cpool (the SAME
 * slot/mutex/condvar engine the xrootdfs root:// and WebDAV-metadata paths use —
 * uniformity across the two FUSE drivers, phase-86). libcurl's connection cache
 * lives on the handle, so keeping handles across fetches is what keeps
 * origin/proxy connections alive (keepalive reuse = fewer handshakes for a DPI
 * middlebox to interfere with). checkout() hands a caller exclusive ownership of
 * one handle for the duration of a transfer (libcurl easy handles are NOT
 * concurrency-safe), so the foreground FUSE loop and the background prefetch
 * worker each borrow their own handle without racing. Every per-request option
 * is re-set on each call below, so no stale request state survives reuse; `-o
 * fresh` still forces a new connection per request. */
#define BRIX_CURL_POOL_SLOTS 4     /* foreground (-s serialized) + prefetch + slack */
static brix_cpool *g_curl_pool;

/* brix_cpool vtable: a slot's opaque conn memory is one CURL* easy handle. */
static int curl_slot_connect(void *conn, void *ctx, brix_status *st) {
    (void) ctx;                                  /* no shared endpoint template */
    CURL *c = curl_easy_init();
    if (c == NULL) { brix_status_set(st, XRDC_EIO, 0, "curl_easy_init failed"); return -1; }
    *(CURL **) conn = c;
    return 0;
}
static void curl_slot_close(void *conn) {
    CURL *c = *(CURL **) conn;
    if (c != NULL) { curl_easy_cleanup(c); *(CURL **) conn = NULL; }
}
static const brix_cpool_vtbl CURL_VT = { sizeof(CURL *), curl_slot_connect, curl_slot_close };

static void transport_cleanup(void) {
    if (g_curl_pool != NULL) { brix_cpool_destroy(g_curl_pool); g_curl_pool = NULL; }
}

/* One GET of `url`, RESUMING from `*got` bytes already in `out` (HTTP Range).
 * Appends new bytes and updates *got. Returns the CURLcode. If a resume request
 * comes back 200 (server ignored Range), the freshly re-sent from-0 bytes are
 * slid to the front so the buffer stays a valid prefix. */
static CURLcode http_get_range(CURL **slot, const char *proxy, const char *url,
                               unsigned char *out, size_t outcap, size_t *got) {
    if (*slot == NULL) *slot = curl_easy_init();
    CURL *c = *slot;
    if (c == NULL) return CURLE_FAILED_INIT;

    size_t      start = *got;
    curl_sink_t sink  = { out, outcap, start };   /* append after what we have */
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, g_tcfg.connect_timeout_s);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, g_tcfg.low_speed_bytes);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, g_tcfg.low_speed_time_s);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);         /* HTTP >=400 → error */
    curl_easy_setopt(c, CURLOPT_TCP_KEEPALIVE, 1L);
    /* Reused handle: set these unconditionally so a prior request's resume
     * offset / freshness flags can never leak into this one. */
    curl_easy_setopt(c, CURLOPT_RESUME_FROM_LARGE, (curl_off_t) start);
    curl_easy_setopt(c, CURLOPT_FRESH_CONNECT, g_tcfg.fresh_connect ? 1L : 0L);
    curl_easy_setopt(c, CURLOPT_FORBID_REUSE, g_tcfg.fresh_connect ? 1L : 0L);
    /* Proxy precedence: env proxy wins; else CVMFS-config proxy; else force direct. */
    char sch[8], thost[256]; int tport;
    url_host(url, sch, sizeof(sch), thost, sizeof(thost), &tport);
    brix_proxy_t px;
    if (brix_proxy_resolve(sch, thost, tport, &px)) {
        curl_easy_setopt(c, CURLOPT_PROXY, px.url);
        brix_proxy_report(&px, thost, tport);
    } else if (proxy != NULL && strcmp(proxy, "DIRECT") != 0) {
        curl_easy_setopt(c, CURLOPT_PROXY, proxy);
    } else {
        curl_easy_setopt(c, CURLOPT_PROXY, "");
    }

    CURLcode rc = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    if (start > 0 && code != 206 && sink.len > start) {
        /* Range not honoured (200): the bytes appended after `start` are actually
         * a fresh stream from offset 0 — slide them to the front. */
        size_t fresh = sink.len - start;
        memmove(out, out + start, fresh);
        *got = fresh;
    } else {
        *got = sink.len;
    }
    return rc;
}

/* Rewrite an http:// url to https:// into `buf`; returns 1 if rewritten. */
static int to_https(const char *url, char *buf, size_t n) {
    if (strncmp(url, "http://", 7) != 0) return 0;
    snprintf(buf, n, "https://%s", url + 7);
    return 1;
}

/* DPI/loss-hardened transport: RANGE-RESUME on a severed transfer (so a large
 * object survives per-chunk connection loss — the key to 10%+ loss), optional
 * TLS-first, optional fresh-connection. As long as each attempt makes progress
 * (more bytes received) we keep resuming up to a generous cap; only attempts that
 * make NO progress count against the retry budget. Across-mirror failover +
 * hash-verify are owned by the fetch layer. */
static int brixcvmfs_transport(const char *proxy, const char *host, const char *rel,
                               unsigned char *out, size_t outcap, size_t *outlen, void *ud) {
    (void) ud;                                    /* handles now come from g_curl_pool */
    brix_status st; brix_status_clear(&st);
    CURL **slot = brix_cpool_checkout(g_curl_pool, &st);  /* CURL** == the classic slot */
    if (slot == NULL) return -1;

    char httpurl[1024];
    snprintf(httpurl, sizeof(httpurl), "%s/%s", host, rel);

    int    budget  = g_tcfg.max_retries > 0 ? g_tcfg.max_retries : 6;
    int    hard_cap = 64;                 /* absolute ceiling on resume attempts */
    int    stalls  = 0;
    size_t got = 0, last = 0;
    int    ret = -1;

    for (int i = 0; i < hard_cap; i++) {
        char httpsbuf[1024];
        int  use_https = (i == 0 && g_tcfg.prefer_tls
                          && to_https(httpurl, httpsbuf, sizeof(httpsbuf)));
        const char *url = use_https ? httpsbuf : httpurl;

        CURLcode rc = http_get_range(slot, proxy, url, out, outcap, &got);
        if (rc == CURLE_OK) { *outlen = got; ret = 0; break; }

        /* hard 4xx over plain http = mirror lacks the object → fail over. A 4xx on
         * the https probe just means no TLS — fall through to http. */
        if (rc == CURLE_HTTP_RETURNED_ERROR && !use_https) break;

        /* Range-blind server: libcurl aborts a resumed request answered 200 with
         * CURLE_RANGE_ERROR before any body byte reaches the sink, so resume can
         * never progress there — throw away the partial prefix and restart the
         * whole object from 0 (the fetch layer's hash check keeps this safe). */
        if (rc == CURLE_RANGE_ERROR) { got = 0; last = 0; }

        if (got > last) { last = got; stalls = 0; }   /* progress → keep resuming */
        else if (++stalls > budget) break;            /* no progress → give up route */

        long ms = 200L << (stalls < 6 ? stalls : 6);  /* backoff on stalls only */
        struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
    }
    /* A libcurl easy handle stays healthy across transfers (it owns its own
     * connection cache and re-establishes internally), so always check it back
     * in reusable — never health-drop. */
    brix_cpool_checkin(g_curl_pool, slot, 1);
    return ret;
}

/* ---- path mapping: FUSE "/" is the catalog root "" ---------------------- */
static const char *cat_path(const char *p) { return strcmp(p, "/") == 0 ? "" : p; }

static long mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long) ts.tv_sec;
}

/* ---- seam to the cvmfs-rw union driver (brixcvmfs_internal.h) ------------ */

int brixcvmfs_rw = 0;      /* 1 = mount with the rw ops table (set pre-dispatch) */

cvmfs_client_t *brixcvmfs_client(void)             { return g_cl; }
const char     *brixcvmfs_cat_path(const char *p)  { return cat_path(p); }
long            brixcvmfs_mono_now(void)           { return mono_now(); }

/* TTL-gated refresh + pin-drift audit: when the mount is pinned and a verified
 * upstream manifest has moved past the pin, log ONE audit line per drift
 * transition (re-armed if upstream returns to the pin), keep serving the pin. */
static void brix_refresh(void) {
    static int drift_logged = 0;
    cvmfs_client_refresh(g_cl, mono_now());
    char up[48];
    if (cvmfs_client_pin_drift(g_cl, up, sizeof(up))) {
        if (!drift_logged) {
            char pin[48];
            cvmfs_hash_to_hex(&g_cl->pin_root, 0, pin, sizeof(pin));
            fprintf(stderr, "brixcvmfs: audit signal=pindrift repo=%s pinned=%s "
                    "upstream=%s serving=pinned\n", g_cl->config.name, pin, up);
            drift_logged = 1;
        }
    } else {
        drift_logged = 0;
    }
}

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
#define BRIX_PF_OBJCAP   (32u * 1024u * 1024u)

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
} brix_prefetch_t;

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
    brix_cas_store_t cache;
    int crc = g_pf.cache_dirfd >= 0
        ? brix_cas_init_at(&cache, g_pf.cache_dirfd, g_pf.quota)
        : brix_cas_init(&cache, g_pf.cache_dir, g_pf.quota);
    unsigned char *scratch = malloc(BRIX_PF_OBJCAP);
    unsigned char *out     = malloc(BRIX_PF_OBJCAP);
    if (crc != 0 || scratch == NULL || out == NULL) {
        free(scratch); free(out);
        return NULL;                       /* prefetch unavailable, mount unaffected */
    }

    cvmfs_fetch_ctx_t fx;
    memset(&fx, 0, sizeof(fx));
    fx.fo = &g_pf.fo;
    fx.cache = &cache;
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
    }
    return NULL;
}

/* FUSE-thread side: queue `path` once. Drops silently when the queue is full
 * or the path was already prefetched — advisory readahead, never a failure. */
static void pf_enqueue(const char *path) {
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
static void pf_start(int depth, long budget, const char *tmp_dir,
                     const char *cache_dir, int cache_dirfd, long quota) {
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

/* ---- FUSE ops (read-only) ---------------------------------------------- */

int brixcvmfs_op_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void) fi;
    brix_refresh();                             /* TTL-gated: no-op until due */
    cvmfs_client_reap_tick(g_cl, mono_now());   /* quota-gated: no-op until due */
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc < 0)  return -EIO;
    if (rc == 0) return -ENOENT;

    memset(st, 0, sizeof(*st));
    st->st_mode  = e.mode;
    st->st_size  = (off_t) e.size;
    st->st_mtime = (time_t) e.mtime;
    st->st_nlink = (e.flags & CVMFS_FLAG_DIR) ? 2 : e.linkcount;
    st->st_uid   = e.uid ? e.uid : getuid();
    st->st_gid   = e.gid ? e.gid : getgid();
    return 0;
}

typedef struct { void *buf; fuse_fill_dir_t filler; } readdir_ctx_t;

static void readdir_emit(const cvmfs_dirent_t *e, void *ud) {
    readdir_ctx_t *r = ud;
    if (e->name[0] != '\0')
        r->filler(r->buf, e->name, NULL, 0, 0);
}

int brixcvmfs_op_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags fl) {
    (void) off; (void) fi; (void) fl;
    brix_refresh();                           /* TTL-gated: no-op until due */
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    readdir_ctx_t r = { buf, filler };
    int n = cvmfs_client_readdir(g_cl, cat_path(path), readdir_emit, &r, mono_now());
    if (n >= 0) pf_enqueue(cat_path(path));   /* first listing = prefetch signal */
    return n < 0 ? -EIO : 0;
}

int brixcvmfs_op_open(const char *path, struct fuse_file_info *fi) {
    if ((fi->flags & O_ACCMODE) != O_RDONLY) return -EROFS;   /* read-only fs */
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc < 0)  return -EIO;
    if (rc == 0) return -ENOENT;
    if (!(e.flags & CVMFS_FLAG_FILE)) return -EISDIR;
    return 0;
}

int brixcvmfs_op_read(const char *path, char *buf, size_t size, off_t off,
                   struct fuse_file_info *fi) {
    (void) fi;
    size_t got = 0;
    int rc = cvmfs_client_read(g_cl, cat_path(path), (uint64_t) off, size,
                               (unsigned char *) buf, &got, mono_now());
    return rc == 0 ? (int) got : -EIO;
}

int brixcvmfs_op_readlink(const char *path, char *buf, size_t size) {
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc <= 0) return rc < 0 ? -EIO : -ENOENT;
    if (!(e.flags & CVMFS_FLAG_LINK)) return -EINVAL;
    snprintf(buf, size, "%s", e.symlink);
    return 0;
}

int brixcvmfs_op_statfs(const char *path, struct statvfs *sv) {
    (void) path;
    memset(sv, 0, sizeof(*sv));
    sv->f_bsize = 4096;
    sv->f_namemax = 255;
    return 0;
}

int brixcvmfs_op_getxattr(const char *path, const char *name, char *value, size_t size) {
    int n = cvmfs_client_getxattr(g_cl, cat_path(path), name, value, size, mono_now());
    if (n < 0)              return -ENODATA;    /* attribute not present */
    if (size == 0)          return n;           /* size probe */
    if ((size_t) n > size)  return -ERANGE;
    return n;
}

int brixcvmfs_op_listxattr(const char *path, char *list, size_t size) {
    int n = cvmfs_client_listxattr(g_cl, cat_path(path), list, size, mono_now());
    if (size == 0)          return n;
    if ((size_t) n > size)  return -ERANGE;
    return n;
}

/* access(2): the fs is read-only, so any W_OK is refused up front; X_OK is
 * honored against the node's mode bits (a 0644 file has no execute bit). R_OK /
 * F_OK on a world-readable RO tree always succeed. Mirrors official cvmfs. */
int brixcvmfs_op_access(const char *path, int mask) {
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc < 0)  return -EIO;
    if (rc == 0) return -ENOENT;
    if (mask & W_OK) return -EROFS;                 /* read-only filesystem */
    if ((mask & X_OK) && !(e.mode & (S_IXUSR | S_IXGRP | S_IXOTH))) return -EACCES;
    return 0;
}

/* every mutating op is refused with EROFS — a read-only filesystem returns
 * EROFS for the whole write family, not the kernel's default ENOSYS/EPERM. */
static int ro_erofs(void) { return -EROFS; }
static int op_mkdir(const char *p, mode_t m) { (void)p;(void)m; return ro_erofs(); }
static int op_unlink(const char *p) { (void)p; return ro_erofs(); }
static int op_write(const char *p, const char *b, size_t s, off_t o, struct fuse_file_info *fi)
    { (void)p;(void)b;(void)s;(void)o;(void)fi; return ro_erofs(); }
static int op_rmdir(const char *p) { (void)p; return ro_erofs(); }
static int op_rename(const char *f, const char *t, unsigned int fl)
    { (void)f;(void)t;(void)fl; return ro_erofs(); }
static int op_symlink(const char *tgt, const char *p) { (void)tgt;(void)p; return ro_erofs(); }
static int op_link(const char *f, const char *t) { (void)f;(void)t; return ro_erofs(); }
static int op_chmod(const char *p, mode_t m, struct fuse_file_info *fi)
    { (void)p;(void)m;(void)fi; return ro_erofs(); }
static int op_chown(const char *p, uid_t u, gid_t g, struct fuse_file_info *fi)
    { (void)p;(void)u;(void)g;(void)fi; return ro_erofs(); }
static int op_truncate(const char *p, off_t o, struct fuse_file_info *fi)
    { (void)p;(void)o;(void)fi; return ro_erofs(); }
static int op_utimens(const char *p, const struct timespec tv[2], struct fuse_file_info *fi)
    { (void)p;(void)tv;(void)fi; return ro_erofs(); }
static int op_setxattr(const char *p, const char *n, const char *v, size_t s, int f)
    { (void)p;(void)n;(void)v;(void)s;(void)f; return ro_erofs(); }
static int op_removexattr(const char *p, const char *n) { (void)p;(void)n; return ro_erofs(); }
static int op_mknod(const char *p, mode_t m, dev_t d) { (void)p;(void)m;(void)d; return ro_erofs(); }

static const struct fuse_operations brixcvmfs_ops = {
    .getattr  = brixcvmfs_op_getattr,
    .readdir  = brixcvmfs_op_readdir,
    .open     = brixcvmfs_op_open,
    .read     = brixcvmfs_op_read,
    .readlink = brixcvmfs_op_readlink,
    .statfs   = brixcvmfs_op_statfs,
    .getxattr  = brixcvmfs_op_getxattr,
    .listxattr = brixcvmfs_op_listxattr,
    .access   = brixcvmfs_op_access,
    .mkdir    = op_mkdir,
    .unlink   = op_unlink,
    .write    = op_write,
    .rmdir       = op_rmdir,
    .rename      = op_rename,
    .symlink     = op_symlink,
    .link        = op_link,
    .chmod       = op_chmod,
    .chown       = op_chown,
    .truncate    = op_truncate,
    .utimens     = op_utimens,
    .setxattr    = op_setxattr,
    .removexattr = op_removexattr,
    .mknod       = op_mknod,
};

/* ---- front-end --------------------------------------------------------- */

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(n > 0 ? (size_t) n : 1);
    if (b && fread(b, 1, (size_t) n, f) != (size_t) n) { free(b); b = NULL; }
    fclose(f);
    if (b) *len = (size_t) n;
    return b;
}

/* Load the repo master key(s). If `path` is a directory (the stock
 * /etc/cvmfs/keys/<domain>/ layout), concatenate every *.pub in it — CVMFS
 * rotates master keys and the whitelist is signed by one of them. */
static unsigned char *load_master_key(const char *path, size_t *len) {
    struct stat st;
    if (stat(path, &st) != 0) return NULL;
    if (!S_ISDIR(st.st_mode)) return read_file(path, len);

    DIR *d = opendir(path);
    if (d == NULL) return NULL;
    unsigned char *buf = NULL; size_t cap = 0, used = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const char *dot = strrchr(e->d_name, '.');
        if (dot == NULL || strcmp(dot, ".pub") != 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", path, e->d_name);
        size_t kl = 0;
        unsigned char *k = read_file(full, &kl);
        if (k == NULL) continue;
        if (used + kl + 1 > cap) { cap = (used + kl + 1) * 2;
            unsigned char *nb = realloc(buf, cap); if (nb == NULL) { free(k); continue; } buf = nb; }
        memcpy(buf + used, k, kl); used += kl;
        buf[used++] = '\n';
        free(k);
    }
    closedir(d);
    if (buf) *len = used;
    return buf;
}

/* Parsed brix-specific mount options (the rest of `-o` is forwarded to libfuse). */
typedef struct {
    int   clever;              /* overlay cache in <mnt>/.brixcache (default ON) */
    int   quota_mb;            /* -o quota=<MB> (0 = from config/unlimited) */
    int   fresh;               /* -o fresh: fresh connection per request */
    int   tls;                 /* -o tls: prefer https:// */
    int   retries;            /* -o retries=<N> (-1 = from config/default) */
    int   prefetch;            /* -o prefetch=<DEPTH>: subtree readahead (-1 = off) */
    long  prefetch_budget;     /* -o prefetch_budget=<BYTES> (0 = unbounded) */
    char  pin[128];            /* -o pin=<HASH>: pin the root catalog (reproducible mount) */
    char  cache_dir[512];      /* -o cache=<DIR> (implies non-clever) */
    char  writes_dir[512];     /* -o writes=<DIR> (cvmfs-rw overlay location) */
    char  fuse_extra[512];     /* passthrough -o tokens, comma-joined */
    char *flags[16]; int nflags;  /* passthrough flags (-f/-d/-h/...) */
} brix_opts_t;

static void opts_o_list(char *list, brix_opts_t *o) {
    char *save = NULL;
    for (char *t = strtok_r(list, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        if      (strcmp(t, "clever") == 0)   o->clever = 1;
        else if (strcmp(t, "noclever") == 0) o->clever = 0;
        else if (strcmp(t, "fresh") == 0)    o->fresh = 1;
        else if (strcmp(t, "tls") == 0)      o->tls = 1;
        else if (strncmp(t, "quota=", 6) == 0)   o->quota_mb = atoi(t + 6);
        else if (strncmp(t, "retries=", 8) == 0) o->retries = atoi(t + 8);
        else if (strncmp(t, "prefetch=", 9) == 0)        o->prefetch = atoi(t + 9);
        else if (strncmp(t, "prefetch_budget=", 16) == 0) o->prefetch_budget = atol(t + 16);
        else if (strncmp(t, "pin=", 4) == 0)
            snprintf(o->pin, sizeof(o->pin), "%s", t + 4);
        else if (strncmp(t, "cache=", 6) == 0)
            snprintf(o->cache_dir, sizeof(o->cache_dir), "%s", t + 6);
        else if (strncmp(t, "writes=", 7) == 0)
            snprintf(o->writes_dir, sizeof(o->writes_dir), "%s", t + 7);
        else {   /* forward to libfuse */
            size_t cur = strlen(o->fuse_extra);
            snprintf(o->fuse_extra + cur, sizeof(o->fuse_extra) - cur,
                     "%s%s", cur ? "," : "", t);
        }
    }
}

static void parse_opts(int argc, char **argv, int start, brix_opts_t *o) {
    memset(o, 0, sizeof(*o));
    o->clever = 1; o->retries = -1; o->prefetch = -1;
    char obuf[512];
    for (int i = start; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            snprintf(obuf, sizeof(obuf), "%s", argv[++i]);
            opts_o_list(obuf, o);
        } else if (strncmp(argv[i], "-o", 2) == 0 && argv[i][2] != '\0') {
            snprintf(obuf, sizeof(obuf), "%s", argv[i] + 2);
            opts_o_list(obuf, o);
        } else if (o->nflags < 16) {
            o->flags[o->nflags++] = argv[i];   /* -f / -d / -h / ... */
        }
    }
}

/* Populate the client failover set for `repo`. $BRIXCVMFS_SERVER pins a single
 * DIRECT stratum-1; otherwise apply the loaded config cascade, and if that yields
 * no hosts, synthesise the conventional cvmfs-stratum-one.<domain> fallback. */
static void brixcvmfs_build_failover(cvmfs_client_t *cl, const cvmfs_conf_t *cf,
                                     const char *repo) {
    cvmfs_failover_init(&cl->fo, 60);
    const char *env_server = getenv("BRIXCVMFS_SERVER");
    if (env_server != NULL) {
        cvmfs_failover_add_proxy(&cl->fo, "DIRECT", 0);
        cvmfs_failover_add_host(&cl->fo, env_server);
        return;
    }
    int hosts = cvmfs_conf_apply(cf, repo, &cl->config, &cl->fo);
    if (hosts == 0) {
        char s1[400];
        snprintf(s1, sizeof(s1), "http://cvmfs-stratum-one.%s/cvmfs/%s",
                 strchr(repo, '.') + 1, repo);
        cvmfs_failover_add_host(&cl->fo, s1);
    }
}

/* Seed the process-global libcurl transport config from the client config +
 * conf cascade for `repo`. `retries_override >= 0` wins over CVMFS_MAX_RETRIES. */
static void brixcvmfs_build_transport_cfg(const cvmfs_client_t *cl, const cvmfs_conf_t *cf,
                                          const char *repo, int retries_override) {
    snprintf(g_tcfg.repo, sizeof(g_tcfg.repo), "%s", repo);
    g_tcfg.connect_timeout_s = cl->config.timeout_s > 0 ? cl->config.timeout_s : 5;
    g_tcfg.low_speed_time_s  = g_tcfg.connect_timeout_s;
    g_tcfg.low_speed_bytes   = 100;
    const char *cfg_retries = cvmfs_conf_get(cf, "CVMFS_MAX_RETRIES");
    g_tcfg.max_retries = retries_override >= 0 ? retries_override
                       : (cfg_retries ? atoi(cfg_retries) : 2);
}

/* Resolve the effective cache quota in bytes: a positive `quota_override` wins;
 * otherwise fall back to CVMFS_QUOTA_LIMIT (MB) from the conf cascade; else 0. */
static long brixcvmfs_resolve_quota(const cvmfs_conf_t *cf, long quota_override) {
    if (quota_override > 0) return quota_override;
    const char *q = cvmfs_conf_get(cf, "CVMFS_QUOTA_LIMIT");   /* MB */
    if (q && atol(q) > 0) return atol(q) * 1024L * 1024L;
    return 0;
}

/* Load the repo master key: $BRIXCVMFS_PUBKEY overrides the config default path.
 * A config-derived CVMFS_KEYS_DIR/<domain>.pub that does not exist falls back to
 * the key-chain DIRECTORY itself (stock layouts rotate keys as e.g.
 * keys/cern.ch/cern-it4.cern.ch.pub with no cern.ch.pub; load_master_key
 * concatenates every *.pub and the verifier tries each). Returns the allocated
 * key blob (caller frees) + `*klen`, or NULL on read failure (message printed). */
static unsigned char *brixcvmfs_load_repo_key(const cvmfs_client_t *cl, size_t *klen) {
    const char *env_key = getenv("BRIXCVMFS_PUBKEY");
    const char *keypath = env_key ? env_key : cl->config.master_pub_path;
    unsigned char *master = load_master_key(keypath, klen);
    if (master == NULL && env_key == NULL) {
        char chain[512];
        snprintf(chain, sizeof(chain), "%s", keypath);
        char *slash = strrchr(chain, '/');
        if (slash != NULL && slash != chain) {
            *slash = '\0';
            master = load_master_key(chain, klen);
        }
    }
    if (master == NULL)
        fprintf(stderr, "brixcvmfs: cannot read master key %s\n", keypath);
    return master;
}

/* Resolve + create the scratch tmp dir for `repo` into `tmp_dir` (cap `cap`):
 * $BRIXCVMFS_TMP overrides the /tmp/brixcvmfs-<repo> default. Best-effort mkdir
 * (a truly unusable dir surfaces as a later mount failure). */
static void brixcvmfs_prepare_tmp_dir(const char *repo, char *tmp_dir, size_t cap) {
    const char *env_tmp = getenv("BRIXCVMFS_TMP");
    if (env_tmp) snprintf(tmp_dir, cap, "%s", env_tmp);
    else         snprintf(tmp_dir, cap, "/tmp/brixcvmfs-%s", repo);
    char mk[600];
    snprintf(mk, sizeof(mk), "mkdir -p '%s'", tmp_dir);
    if (system(mk) != 0) { /* mount will fail later if truly unusable */ }
}

/* Resolve + create the persistent cache dir for `repo` into `cache_dir` when NOT
 * in overlay-dirfd mode (`cache_dirfd < 0`). Precedence: explicit override →
 * $BRIXCVMFS_CACHE → /var/lib/brixcvmfs/<repo>. No-op in dirfd mode. */
static void brixcvmfs_prepare_cache_dir(const char *repo, const char *cache_dir_override,
                                        int cache_dirfd, char *cache_dir, size_t cap) {
    if (cache_dirfd >= 0) return;
    const char *env_cache = getenv("BRIXCVMFS_CACHE");
    if (cache_dir_override) snprintf(cache_dir, cap, "%s", cache_dir_override);
    else if (env_cache)     snprintf(cache_dir, cap, "%s", env_cache);
    else                    snprintf(cache_dir, cap, "/var/lib/brixcvmfs/%s", repo);
    char mk[600];
    snprintf(mk, sizeof(mk), "mkdir -p '%s'", cache_dir);
    if (system(mk) != 0) { /* mount will fail later if unusable */ }
}

/* Build failover + config and verify-mount the repo trust chain. Cache backing:
 * `cache_dirfd >= 0` = overlay dirfd mode; else `cache_dir_override` (or the
 * default/env path). quota/retries fall back to the config cascade when the
 * override is unset (<=0 quota, <0 retries). Returns a mounted client or NULL. */
static cvmfs_client_t *brixcvmfs_open(const char *repo, const char *cache_dir_override,
                                      int cache_dirfd, long quota_override, int retries_override,
                                      const char *pin_opt) {
    cvmfs_client_t *cl = calloc(1, sizeof(*cl));
    if (cl == NULL) { fprintf(stderr, "brixcvmfs: out of memory\n"); return NULL; }

    if (cvmfs_repo_config_defaults(repo, &cl->config) != 0) {
        fprintf(stderr, "brixcvmfs: '%s' is not a fully-qualified repo name\n", repo);
        free(cl); return NULL;
    }

    const char *pin = (pin_opt != NULL && pin_opt[0]) ? pin_opt : getenv("BRIXCVMFS_PIN");
    if (pin != NULL && pin[0] && cvmfs_client_pin_root(cl, pin) != 0) {
        fprintf(stderr, "brixcvmfs: bad pin '%s' (want a root-catalog hash)\n", pin);
        free(cl); return NULL;
    }

    cvmfs_conf_t cf;
    cvmfs_conf_init(&cf);
    cvmfs_conf_load_cascade(&cf, getenv("BRIXCVMFS_ETC"), repo);   /* for quota/retries */

    brixcvmfs_build_failover(cl, &cf, repo);
    brixcvmfs_build_transport_cfg(cl, &cf, repo, retries_override);
    long quota = brixcvmfs_resolve_quota(&cf, quota_override);

    size_t klen = 0;
    unsigned char *master = brixcvmfs_load_repo_key(cl, &klen);
    if (master == NULL) { free(cl); return NULL; }

    char tmp_dir[512];
    brixcvmfs_prepare_tmp_dir(repo, tmp_dir, sizeof(tmp_dir));

    char cache_dir[512] = "";
    brixcvmfs_prepare_cache_dir(repo, cache_dir_override, cache_dirfd,
                                cache_dir, sizeof(cache_dir));

    curl_global_init(CURL_GLOBAL_DEFAULT);
    /* Bring the shared curl-handle pool up before the mount fetches the root
     * catalog (eager slot-0 connect surfaces a curl_easy_init failure here). */
    brix_status pst; brix_status_clear(&pst);
    g_curl_pool = brix_cpool_create(&CURL_VT, NULL, BRIX_CURL_POOL_SLOTS, &pst);
    if (g_curl_pool == NULL) {
        fprintf(stderr, "brixcvmfs: curl handle pool init failed: %s\n", pst.msg);
        curl_global_cleanup();
        free(cl); return NULL;
    }
    int mrc = cvmfs_client_mount(cl, repo, master, klen,
                                 cache_dirfd < 0 ? cache_dir : NULL, tmp_dir,
                                 quota, cache_dirfd, brixcvmfs_transport, NULL, mono_now());
    free(master);
    if (mrc != 0) {
        fprintf(stderr, "brixcvmfs: mount of %s failed (trust/catalog error %d)\n", repo, mrc);
        transport_cleanup();
    curl_global_cleanup();
        free(cl); return NULL;
    }
    return cl;
}

/* --check: verify the trust chain + root catalog and print a summary WITHOUT
 * mounting (the stock `cvmfs_config chksetup` analog). Exit 0 = healthy. */
static int brixcvmfs_check(const char *repo) {
    cvmfs_client_t *cl = brixcvmfs_open(repo, NULL, -1, 0, -1, NULL);
    if (cl == NULL) return 1;

    long now = mono_now();
    char rev[64] = "?", root[128] = "?", host[256] = "?", proxy[64] = "?";
    int n;
    n = cvmfs_client_getxattr(cl, "/", "user.revision", rev, sizeof(rev) - 1, now);
    if (n > 0) rev[n] = 0;
    n = cvmfs_client_getxattr(cl, "/", "user.root_hash", root, sizeof(root) - 1, now);
    if (n > 0) root[n] = 0;
    n = cvmfs_client_getxattr(cl, "/", "user.host", host, sizeof(host) - 1, now);
    if (n > 0) host[n] = 0;
    n = cvmfs_client_getxattr(cl, "/", "user.proxy", proxy, sizeof(proxy) - 1, now);
    if (n > 0) proxy[n] = 0;

    cvmfs_dirent_t root_e;
    /* the catalog root entry is the empty path "" (FUSE maps "/" → "" via cat_path). */
    int root_ok = cvmfs_client_resolve(cl, "", &root_e, now) == 1
               && (root_e.flags & CVMFS_FLAG_DIR);
    int entries = cvmfs_catalog_readdir(cl->root_catalog, "", NULL, NULL);

    printf("CVMFS-brix repository check: %s\n", repo);
    printf("  trust chain .... OK (whitelist + manifest signature verified)\n");
    printf("  revision ....... %s\n", rev);
    printf("  root catalog ... %s\n", root);
    printf("  root dir ....... %s (%d entries)\n", root_ok ? "OK" : "MISSING", entries);
    printf("  active server .. %s\n", host);
    printf("  active proxy ... %s\n", proxy);
    printf("  ttl ............ %lds\n", cl->ttl);
    printf("HEALTHY\n");

    cvmfs_client_umount(cl);
    transport_cleanup();
    curl_global_cleanup();
    free(cl);
    return root_ok ? 0 : 1;
}

/* --prewarm (phase-85 F5): walk the WHOLE snapshot (the pin when
 * $BRIXCVMFS_PIN is set, else the current root) and pull every referenced CAS
 * object into the local cache, so a shared cache dir is fully warm before a
 * job wave. No mount, single-threaded: reuses the client's own fetch ctx.
 * Exit 0 = every object landed; a fetch error or a tampered catalog ⇒ 1. */
typedef struct {
    cvmfs_fetch_ctx_t *fx;
    unsigned char     *out;
    cvmfs_failover_t   fo0;   /* pristine snapshot (blacklist reset, cf. F4) */
    long               objs, bytes, errs;
} prewarm_ud_t;

static int prewarm_visit(const cvmfs_walk_item_t *it, void *ud) {
    prewarm_ud_t *p = ud;
    if (it->kind == CVMFS_WALK_CATALOG) return 0;   /* the walk itself caches it */
    size_t n = 0;
    if (cvmfs_fetch_object(p->fx, &it->hash, it->suffix,
                           p->out, BRIX_PF_OBJCAP, &n, mono_now()) == 0) {
        p->objs++;
        p->bytes += (long) n;
    } else {
        p->errs++;
        *p->fx->fo = p->fo0;  /* one bad object blacklists its route — restore
                               * so it can't shadow the rest of the sweep */
    }
    return 0;
}

static int brixcvmfs_prewarm(const char *repo) {
    cvmfs_client_t *cl = brixcvmfs_open(repo, NULL, -1, 0, -1, NULL);
    if (cl == NULL) return 1;

    prewarm_ud_t ud = { &cl->fetch, malloc(BRIX_PF_OBJCAP), cl->fo, 0, 0, 0 };
    int rc = -1;
    if (ud.out != NULL) {
        const cvmfs_hash_t *root = cl->pin_set ? &cl->pin_root
                                               : &cl->manifest.root_catalog;
        rc = cvmfs_walk_catalog(&cl->fetch, root, cl->catalog_tmp,
                                INT_MAX, prewarm_visit, &ud, mono_now());
        char hex[48];
        cvmfs_hash_to_hex(root, 0, hex, sizeof(hex));
        printf("CVMFS-brix prewarm: %s\n", repo);
        printf("  root catalog ... %s%s\n", hex, cl->pin_set ? " (pinned)" : "");
        printf("  objects ........ %ld fetched (%ld bytes)\n", ud.objs, ud.bytes);
        printf("  errors ......... %ld%s\n", ud.errs,
               rc != 0 ? " (walk aborted: catalog fetch/verify failure)" : "");
        printf("%s\n", rc == 0 && ud.errs == 0 ? "WARM" : "INCOMPLETE");
    } else {
        fprintf(stderr, "brixcvmfs: out of memory\n");
    }
    free(ud.out);

    cvmfs_client_umount(cl);
    transport_cleanup();
    curl_global_cleanup();
    free(cl);
    return rc == 0 && ud.errs == 0 ? 0 : 1;
}

/* Resolve the clever-overlay cache: unless an explicit cache (-o cache= or
 * $BRIXCVMFS_CACHE) opts out, create <mnt>/.brixcache and open a dirfd on it
 * BEFORE the FUSE mount hides it. Sets `*cache_override` (the explicit-cache
 * path, else NULL) and returns the overlay dirfd, or -1 (explicit/fallback). */
static int brixcvmfs_open_clever_cache(const char *mnt, const brix_opts_t *o,
                                       const char **cache_override) {
    *cache_override = NULL;
    int clever = o->clever;
    if (o->cache_dir[0]) { *cache_override = o->cache_dir; clever = 0; }
    else if (getenv("BRIXCVMFS_CACHE")) { clever = 0; }
    if (!clever) return -1;

    mkdir(mnt, 0755);                       /* ensure the mountpoint exists */
    char sub[600];
    snprintf(sub, sizeof(sub), "%s/.brixcache", mnt);
    if (mkdir(sub, 0755) != 0 && errno != EEXIST)
        fprintf(stderr, "brixcvmfs: warning: cannot create overlay cache %s\n", sub);
    int fd = open(sub, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        fprintf(stderr, "brixcvmfs: overlay cache unavailable, falling back\n");
    return fd;
}

/* Bind the cvmfs-rw writable overlay (<mnt>/.brixwrites or -o writes=) BEFORE
 * fuse_main hides the mountpoint — same trick as .brixcache. The rw hooks are
 * weak so a ro-only link (test builds) still works. No-op unless brixcvmfs_rw.
 * Returns 0 on success (or when not requested), else a process exit code. */
static int brixcvmfs_setup_rw_overlay(const char *mnt, const brix_opts_t *o) {
    if (!brixcvmfs_rw) return 0;
    if (brixcvmfs_setup_rw == NULL || &brixcvmfs_rw_ops == NULL) {
        fprintf(stderr, "brixcvmfs: rw overlay driver not linked in this build\n");
        return 2;
    }
    if (brixcvmfs_setup_rw(mnt, o->writes_dir) != 0) return 1;
    return 0;
}

/* Hand the mountpoint (+ passthrough flags/opts) to libfuse. Force
 * single-threaded (-s): the client shares one SQLite catalog handle + lock-free
 * failover state, so serialised FUSE dispatch is the correct, race-free choice
 * (reads are cache-served, so throughput is unaffected). Returns fuse_main's rc. */
static int brixcvmfs_run_fuse(char *arg0, const char *mnt, const brix_opts_t *o) {
    char *fargv[24]; int fargc = 0;
    fargv[fargc++] = arg0;
    fargv[fargc++] = (char *) mnt;
    fargv[fargc++] = (char *) "-s";
    /* Flag the kernel mount read-only (matches official cvmfs2) — the pure-ro
     * build only. The --rw overlay build is genuinely writable, so must not. */
    if (!brixcvmfs_rw) { fargv[fargc++] = (char *) "-o"; fargv[fargc++] = (char *) "ro"; }
    for (int i = 0; i < o->nflags && fargc < 20; i++) fargv[fargc++] = o->flags[i];
    if (o->fuse_extra[0]) { fargv[fargc++] = (char *) "-o"; fargv[fargc++] = (char *) o->fuse_extra; }

    return fuse_main(fargc, fargv,
                     brixcvmfs_rw ? &brixcvmfs_rw_ops : &brixcvmfs_ops, NULL);
}

/* Full mount bring-up: clever-cache dirfd, rw overlay, verify-mount the repo,
 * run FUSE, then tear everything down. `cache_dirfd` ownership is local to this
 * function. Returns the process exit code. */
static int brixcvmfs_mount_run(char *arg0, const char *repo, const char *mnt,
                               const brix_opts_t *o) {
    g_tcfg.fresh_connect = o->fresh;
    g_tcfg.prefer_tls    = o->tls;
    long quota = o->quota_mb > 0 ? (long) o->quota_mb * 1024L * 1024L : 0;

    const char *cache_override = NULL;
    int cache_dirfd = brixcvmfs_open_clever_cache(mnt, o, &cache_override);

    int rw_rc = brixcvmfs_setup_rw_overlay(mnt, o);
    if (rw_rc != 0) { if (cache_dirfd >= 0) close(cache_dirfd); return rw_rc; }

    cvmfs_client_t *cl = brixcvmfs_open(repo, cache_override, cache_dirfd, quota, o->retries,
                                        o->pin);
    if (cl == NULL) { if (cache_dirfd >= 0) close(cache_dirfd); return 1; }
    g_cl = cl;

    /* F4 predictive prefetch: -o prefetch=<depth> or $BRIXCVMFS_PREFETCH. */
    const char *env_pf = getenv("BRIXCVMFS_PREFETCH");
    int pf_depth = o->prefetch >= 0 ? o->prefetch : (env_pf ? atoi(env_pf) : -1);
    if (pf_depth >= 0) {
        const char *env_pb = getenv("BRIXCVMFS_PREFETCH_BUDGET");
        long pf_budget = o->prefetch_budget > 0 ? o->prefetch_budget
                       : (env_pb ? atol(env_pb) : 0);
        char pf_cache[512] = "";
        brixcvmfs_prepare_cache_dir(repo, cache_override, cache_dirfd,
                                    pf_cache, sizeof(pf_cache));
        pf_start(pf_depth, pf_budget, cl->catalog_tmp, pf_cache, cache_dirfd, quota);
    }

    int rc = brixcvmfs_run_fuse(arg0, mnt, o);

    if (brixcvmfs_rw && brixcvmfs_teardown_rw != NULL) brixcvmfs_teardown_rw();
    cvmfs_client_umount(cl);
    transport_cleanup();
    curl_global_cleanup();
    if (cache_dirfd >= 0) close(cache_dirfd);
    free(cl);
    return rc;
}

/* brixcvmfs entry — reused by the brixMount umbrella (SP-G).
 *   brixcvmfs <repo> <mountpoint> [fuse-opts]   — mount
 *   brixcvmfs --check <repo>                     — verify + summarise, no mount */
int brixcvmfs_main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--check") == 0)
        return brixcvmfs_check(argv[2]);
    if (argc >= 3 && strcmp(argv[1], "--prewarm") == 0)
        return brixcvmfs_prewarm(argv[2]);

    if (argc < 3) {
        fprintf(stderr,
            "usage: brixcvmfs <repo.fqrn> <mountpoint> [fuse-opts]\n"
            "       brixcvmfs --check <repo.fqrn>\n"
            "       brixcvmfs --prewarm <repo.fqrn>\n");
        return 2;
    }

    brix_opts_t o;
    parse_opts(argc, argv, 3, &o);
    return brixcvmfs_mount_run(argv[0], argv[1], argv[2], &o);
}

#ifndef BRIXCVMFS_NO_MAIN
int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--rw") == 0) {   /* brixcvmfs --rw <repo> <mnt> */
        if (brixcvmfs_rw_main == NULL) {
            fprintf(stderr, "brixcvmfs: rw overlay driver not linked in this build\n");
            return 2;
        }
        argv[1] = argv[0];
        return brixcvmfs_rw_main(argc - 1, argv + 1);
    }
    return brixcvmfs_main(argc, argv);
}
#endif
