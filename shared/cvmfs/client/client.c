/* client.c — CVMFS-brix client assembler. See client.h. */
#include "cvmfs/client/client.h"
#include "cvmfs/signature/whitelist.h"
#include "cvmfs/signature/verify.h"
#include "cvmfs/object/object.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CVMFS_MAX_NESTED_DEPTH 16

/* ---- raw (non-CAS) metadata fetch over failover ------------------------- */

static int raw_fetch(cvmfs_client_t *cl, const char *rel,
                     unsigned char *buf, size_t cap, size_t *len, long now) {
    for (unsigned attempt = 0; attempt < 6; attempt++) {
        cvmfs_fo_route_t route;
        if (cvmfs_failover_select(&cl->fo, now, &route) != 0) return -2;
        const char *proxy = route.proxy >= 0 ? cl->fo.proxies[route.proxy].url : NULL;
        const char *host  = cl->fo.hosts[route.host].url;

        if (cl->transport(proxy, host, rel, buf, cap, len, cl->transport_ud) == 0) {
            cvmfs_failover_record(&cl->fo, &route, 1, 1, now);
            return 0;
        }
        cvmfs_failover_record(&cl->fo, &route, 0, 0, now);
    }
    return -1;
}

/* Grow the transport landing buffer to hold `need` STORED bytes.
 *
 * Never shrinks: a mount that has already paid for a large object keeps the
 * buffer for the next one, so a read-heavy workload allocates once. Refuses
 * anything past the shared ceiling rather than trusting a size that ultimately
 * comes from catalog metadata — the catalog is signature-verified, but a bound
 * here keeps a bogus size field from turning into an unbounded allocation. */
static int scratch_ensure(cvmfs_client_t *cl, size_t need)
{
    if (need > CVMFS_OBJECT_STORED_BOUND(CVMFS_OBJECT_MAX_BYTES)) return -1;

    if (cl->scratch == NULL || cl->scratch_cap < need) {
        unsigned char *grown = realloc(cl->scratch, need);
        if (grown == NULL) return -1;
        cl->scratch     = grown;
        cl->scratch_cap = need;
    }

    /* Republish unconditionally, not just after a grow: cvmfs_client_mount()
     * memsets cl->fetch, so a re-mount that reuses an already-large buffer
     * would otherwise leave fetch.scratch NULL. */
    cl->fetch.scratch     = cl->scratch;      /* fetch borrows, does not own */
    cl->fetch.scratch_cap = cl->scratch_cap;
    return 0;
}

int cvmfs_client_scratch_reserve(cvmfs_client_t *cl, size_t plain_bytes)
{
    size_t cap = plain_bytes ? plain_bytes : (size_t) CVMFS_OBJECT_DEFAULT_BYTES;
    if (cap > (size_t) CVMFS_OBJECT_MAX_BYTES) return -1;
    return scratch_ensure(cl, CVMFS_OBJECT_STORED_BOUND(cap));
}

/* Fetch a CAS object's verified plaintext into a freshly malloc'd buffer.
 *
 * `plain_hint` is the object's plaintext size when the caller knows it (file
 * size for a whole-file object, chunk size for a 'P' chunk) and 0 when it does
 * not (catalogs). Sizing from the hint is what lets a file of ANY publisher-
 * legal size be read: both this plaintext buffer and the compressed landing
 * buffer are fitted to the object instead of to a fixed constant. */
static unsigned char *fetch_cas(cvmfs_client_t *cl, const cvmfs_hash_t *h, char suffix,
                                size_t plain_hint, size_t *outlen, long now) {
    size_t cap = plain_hint ? plain_hint : (size_t) CVMFS_OBJECT_DEFAULT_BYTES;
    if (cap > (size_t) CVMFS_OBJECT_MAX_BYTES) cap = (size_t) CVMFS_OBJECT_MAX_BYTES;

    /* The STORED form can exceed the plaintext (incompressible input deflates
     * to slightly more than it started), so the landing buffer is sized by the
     * compression bound, not by `cap`. */
    if (scratch_ensure(cl, CVMFS_OBJECT_STORED_BOUND(cap)) != 0) return NULL;

    unsigned char *buf = malloc(cap);
    if (buf == NULL) return NULL;
    if (cvmfs_fetch_object(&cl->fetch, h, suffix, buf, cap, outlen, now) != 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

/* Fetch a catalog CAS object ('C'), spill to a temp file, open it. */
static cvmfs_catalog_t *open_catalog_by_hash(cvmfs_client_t *cl, const cvmfs_hash_t *h,
                                             const char *tmp_dir, char *tmp_out,
                                             size_t tmp_out_sz, long now) {
    size_t         n = 0;
    unsigned char *db = fetch_cas(cl, h, 'C', 0 /*size unknown*/, &n, now);
    if (db == NULL) return NULL;

    snprintf(tmp_out, tmp_out_sz, "%s/brixcvmfs.cat.%d.XXXXXX", tmp_dir, (int) getpid());
    int fd = mkstemp(tmp_out);
    if (fd < 0) { free(db); return NULL; }

    int ok = 1;
    for (size_t off = 0; off < n; ) {
        ssize_t w = write(fd, db + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; ok = 0; break; }
        off += (size_t) w;
    }
    close(fd);
    free(db);
    if (!ok) { unlink(tmp_out); return NULL; }

    cvmfs_catalog_t *cat = cvmfs_catalog_open(tmp_out);
    if (cat == NULL) unlink(tmp_out);
    return cat;
}

/* ---- nested-catalog descent -------------------------------------------- */

/* Longest nested-mountpoint prefix of `path` registered in `cat`, or NULL.
 * Writes the mountpoint into `mp`/`mp_sz` and its hash into *h. When
 * `include_self` is set, `path` itself is also considered a candidate — needed
 * by readdir, whose CHILDREN of a mountpoint live in the nested catalog rooted
 * at that mountpoint; resolve (which wants the mountpoint's own dirent, held in
 * the PARENT catalog) passes 0 so it never descends into path-as-mountpoint. */
static int longest_nested_prefix(cvmfs_catalog_t *cat, const char *path,
                                 char *mp, size_t mp_sz, cvmfs_hash_t *h,
                                 int include_self) {
    int found = 0;
    /* iterate every "/a", "/a/b", ... prefix that is a directory ancestor
     * (and, when include_self, the full path) */
    size_t plen = strlen(path);
    for (size_t i = 1; i <= plen; i++) {
        int boundary = (i < plen) ? (path[i] == '/') : include_self;
        if (!boundary) continue;
        char cand[1024];
        if (i >= sizeof(cand)) break;
        memcpy(cand, path, i); cand[i] = '\0';
        cvmfs_hash_t ch; uint64_t sz;
        if (cvmfs_catalog_nested(cat, cand, &ch, &sz) == 1) {
            if (i < mp_sz) { memcpy(mp, cand, i); mp[i] = '\0'; *h = ch; found = 1; }
        }
    }
    return found;   /* mp holds the LONGEST match (last write wins as i grows) */
}

/* Resolve returning the owning catalog. *owns set if the caller must close/unlink. */
static int resolve_full(cvmfs_client_t *cl, const char *path, cvmfs_dirent_t *out,
                        cvmfs_catalog_t **cat_out, int *owns, char *tmp_out,
                        size_t tmp_out_sz, long now) {
    cvmfs_catalog_t *cat = cl->root_catalog;
    int owns_local = 0;
    char tmp[512] = {0};

    for (int depth = 0; depth < CVMFS_MAX_NESTED_DEPTH; depth++) {
        char mp[1024]; cvmfs_hash_t h;
        if (!longest_nested_prefix(cat, path, mp, sizeof(mp), &h, 0)) break;

        char ntmp[512];
        const char *td = cl->catalog_tmp[0] ? cl->catalog_tmp : "/tmp";
        cvmfs_catalog_t *ncat = open_catalog_by_hash(cl, &h, td, ntmp, sizeof(ntmp), now);
        if (ncat == NULL) break;              /* can't descend → use current cat */

        if (owns_local) { cvmfs_catalog_close(cat); if (tmp[0]) unlink(tmp); }
        cat = ncat; owns_local = 1;
        snprintf(tmp, sizeof(tmp), "%s", ntmp);

        /* the nested catalog re-registers deeper mountpoints; loop continues */
    }

    int rc = cvmfs_catalog_lookup(cat, path, out);
    *cat_out = cat; *owns = owns_local;
    if (tmp_out && owns_local) snprintf(tmp_out, tmp_out_sz, "%s", tmp);
    else if (tmp_out) tmp_out[0] = '\0';
    return rc;
}

int cvmfs_client_resolve(cvmfs_client_t *cl, const char *path, cvmfs_dirent_t *out, long now) {
    /* G1 negative-lookup short-circuit: the filter has NO false negatives, so
     * "not a member" is a guaranteed ENOENT — but only while it is bound to the
     * root catalog being served (a refresh-installed revision deactivates it). */
    if (cl->negf_set && path[0] != '\0') {
        const cvmfs_hash_t *served = cl->pin_set ? &cl->pin_root
                                                 : &cl->manifest.root_catalog;
        if (cvmfs_hash_eq(&cl->negf_root, served)
            && !cvmfs_xorf_query(&cl->negf, cvmfs_xorf_key(path)))
            return 0;
    }

    /* G6 mmap-index short-circuit: the index covers the COMPLETE namespace of
     * its bound revision, so hit AND miss are both authoritative — under the
     * same served-root guard as the filter. An internal defect (-1: corrupt
     * entry/bucket) drops the index and the catalogs answer live. */
    if (cl->pidx_set) {
        const cvmfs_hash_t *served = cl->pin_set ? &cl->pin_root
                                                 : &cl->manifest.root_catalog;
        if (cvmfs_hash_eq(&cl->pidx_root, served)) {
            int prc = cvmfs_pathidx_lookup(&cl->pidx, path, out);
            if (prc >= 0) return prc;
            cvmfs_client_pathidx_clear(cl);
        }
    }

    cvmfs_catalog_t *cat = NULL; int owns = 0; char tmp[512] = {0};
    int rc = resolve_full(cl, path, out, &cat, &owns, tmp, sizeof(tmp), now);
    if (owns) { cvmfs_catalog_close(cat); if (tmp[0]) unlink(tmp); }
    return rc;
}

/* Directory listing that follows nested-catalog transitions. A mountpoint's
 * children live in the nested catalog rooted at it, so — unlike resolve — the
 * descent must consider `path` itself a mountpoint (include_self=1). Reuses the
 * same open/close/unlink discipline as resolve_full. Returns the catalog
 * readdir count, or <0 on error. */
int cvmfs_client_readdir(cvmfs_client_t *cl, const char *path,
                         cvmfs_readdir_cb cb, void *ud, long now) {
    /* G6: a bound index lists a directory's (contiguous, sorted) children with
     * zero catalog opens. -1 = not an indexed dir or a corrupt entry — fall
     * through live; a defect will also surface (and clear) via resolve. */
    if (cl->pidx_set) {
        const cvmfs_hash_t *served = cl->pin_set ? &cl->pin_root
                                                 : &cl->manifest.root_catalog;
        if (cvmfs_hash_eq(&cl->pidx_root, served)) {
            int n = cvmfs_pathidx_readdir(&cl->pidx, path, cb, ud);
            if (n >= 0) return n;
        }
    }

    cvmfs_catalog_t *cat = cl->root_catalog;
    int owns = 0;
    char tmp[512] = {0};

    for (int depth = 0; depth < CVMFS_MAX_NESTED_DEPTH; depth++) {
        char mp[1024]; cvmfs_hash_t h;
        if (!longest_nested_prefix(cat, path, mp, sizeof(mp), &h, 1)) break;

        char ntmp[512];
        const char *td = cl->catalog_tmp[0] ? cl->catalog_tmp : "/tmp";
        cvmfs_catalog_t *ncat = open_catalog_by_hash(cl, &h, td, ntmp, sizeof(ntmp), now);
        if (ncat == NULL) break;              /* can't descend → list current cat */

        if (owns) { cvmfs_catalog_close(cat); if (tmp[0]) unlink(tmp); }
        cat = ncat; owns = 1;
        snprintf(tmp, sizeof(tmp), "%s", ntmp);
    }

    int n = cvmfs_catalog_readdir(cat, path, cb, ud);
    if (owns) { cvmfs_catalog_close(cat); if (tmp[0]) unlink(tmp); }
    return n;
}

/* ---- mount ------------------------------------------------------------- */

#define __CLIENT_C_COMPILED__
#include "client_trust.c"

/* Install a fully-verified staged manifest as the client's current one. The
 * manifest struct holds pointers into its backing buffer, so commit = copy the
 * raw bytes then re-parse against cl->manifest_buf (parse is deterministic and
 * already succeeded on these exact bytes). */
static void commit_manifest(cvmfs_client_t *cl, const unsigned char *mbuf, size_t mlen) {
    memcpy(cl->manifest_buf, mbuf, mlen);
    cl->manifest_len = mlen;
    cvmfs_manifest_parse(cl->manifest_buf, cl->manifest_len, &cl->manifest);
    cl->ttl = cl->manifest.ttl > 0 ? cl->manifest.ttl : 240;
}

/* Extract the hostname from a host URL: "http://HOST[:port]/cvmfs/repo" → HOST. */
static void host_of(const char *url, char *out, size_t n) {
    const char *p = strstr(url, "://");
    p = p ? p + 3 : url;
    size_t i = 0;
    while (p[i] && p[i] != '/' && p[i] != ':' && i < n - 1) { out[i] = p[i]; i++; }
    out[i] = '\0';
}

/* Geo-order the host list by proximity via the Stratum-1 Geo API
 * (GET api/v1.0/geo/x/<h1,h2,…> → 1-based proximity order). No-op with ≤1 host or
 * if the geo endpoint is unavailable — the configured order is kept. Makes index 0
 * the geo-closest server (sticky-preferred). */
static void geo_sort(cvmfs_client_t *cl, long now) {
    if (cl->fo.n_hosts <= 1) return;

    char   list[1024];
    size_t o = 0;
    for (size_t i = 0; i < cl->fo.n_hosts; i++) {
        char h[256];
        host_of(cl->fo.hosts[i].url, h, sizeof(h));
        int w = snprintf(list + o, sizeof(list) - o, "%s%s", i ? "," : "", h);
        if (w < 0 || (size_t) w >= sizeof(list) - o) return;
        o += (size_t) w;
    }

    char rel[1200];
    snprintf(rel, sizeof(rel), "api/v1.0/geo/x/%s", list);
    unsigned char buf[512]; size_t n = 0;
    if (raw_fetch(cl, rel, buf, sizeof(buf), &n, now) != 0) return;   /* geo down → keep order */

    int    order[CVMFS_FO_MAX_HOSTS];
    size_t cnt = cvmfs_geo_parse_order((const char *) buf, n, order, cl->fo.n_hosts);
    if (cnt == cl->fo.n_hosts)
        cvmfs_failover_reorder_hosts(&cl->fo, order, cnt);
}

int cvmfs_client_mount(cvmfs_client_t *cl, const char *repo_name,
                       const unsigned char *master_pub_pem, size_t master_pub_len,
                       const char *cache_dir, const char *tmp_dir,
                       long quota_bytes, int cache_dirfd,
                       cvmfs_transport_fn transport, void *ud, long now) {
    cl->transport = transport;
    cl->transport_ud = ud;
    snprintf(cl->config.name, sizeof(cl->config.name), "%s", repo_name);
    snprintf(cl->catalog_tmp, sizeof(cl->catalog_tmp), "%s", tmp_dir);

    if (master_pub_len > sizeof(cl->master_pub)) return -1;
    memcpy(cl->master_pub, master_pub_pem, master_pub_len);
    cl->master_pub_len = master_pub_len;

    int cache_rc;
    if (cl->cache_packed)                       /* phase-87 G4/G5 opt-in */
        cache_rc = cache_dirfd >= 0
            ? brix_cas_init_packed_at(&cl->cache, cache_dirfd, quota_bytes,
                                      cl->cache_seg_bytes, cl->cache_tiering)
            : brix_cas_init_packed(&cl->cache, cache_dir, quota_bytes,
                                   cl->cache_seg_bytes, cl->cache_tiering);
    else
        cache_rc = cache_dirfd >= 0
            ? brix_cas_init_at(&cl->cache, cache_dirfd, quota_bytes)
            : brix_cas_init(&cl->cache, cache_dir, quota_bytes);
    if (cache_rc != 0) return -1;

    memset(&cl->fetch, 0, sizeof(cl->fetch));
    cl->fetch.fo = &cl->fo;
    cl->fetch.cache = &cl->cache;
    cl->fetch.transport = transport;
    cl->fetch.transport_ud = ud;
    cl->fetch.store_form = CVMFS_STORE_COMPRESSED;
    /* Start at the default and let scratch_ensure() grow it per object. Note
     * this runs AFTER the memset of cl->fetch above, so the borrowed pointer is
     * (re)published here on every mount. */
    if (scratch_ensure(cl, CVMFS_OBJECT_STORED_BOUND(CVMFS_OBJECT_DEFAULT_BYTES)) != 0) {
        brix_cas_destroy(&cl->cache);
        return -1;
    }

    /* Retry the whole trust chain, not just transport faults: the whitelist and
     * manifest are authenticated by SIGNATURE (not content hash), so a corrupted-
     * but-complete reply (e.g. a byte-reordering DPI) passes the transport yet
     * fails parse/verify. Re-fetching gets a fresh copy — the metadata analogue of
     * the content layer's hash-verified retry. Bounded with backoff. */
    int rc = -1;
    for (unsigned attempt = 0; attempt < 6; attempt++) {
        size_t           mlen = 0;
        cvmfs_manifest_t m;
        rc = load_trust_and_catalog(cl, now, cl->manifest_stage, sizeof(cl->manifest_stage),
                                    &mlen, &m, cl->root_catalog_tmp,
                                    sizeof(cl->root_catalog_tmp), &cl->root_catalog);
        if (rc == 0) { commit_manifest(cl, cl->manifest_stage, mlen); break; }
        long ms = cvmfs_failover_backoff_ms(attempt);
        struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
    }
    if (rc != 0) return rc;

    geo_sort(cl, now);        /* order hosts by proximity: index 0 = geo-closest */

    cl->mounted_at = now;
    cl->last_refresh = now;
    cl->last_reap = now;
    return 0;
}

void cvmfs_client_reap_tick(cvmfs_client_t *cl, long now) {
    if (now < cl->last_reap + 30) return;    /* time-gate: at most every 30s */
    cl->last_reap = now;
    brix_cas_enforce_quota(&cl->cache);
}

#include "_client_part2.c"
