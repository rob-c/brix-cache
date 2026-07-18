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

/* Fetch a CAS object's verified plaintext into a freshly malloc'd buffer. */
static unsigned char *fetch_cas(cvmfs_client_t *cl, const cvmfs_hash_t *h, char suffix,
                                size_t *outlen, long now) {
    size_t cap = 16u * 1024u * 1024u;
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
    unsigned char *db = fetch_cas(cl, h, 'C', &n, now);
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
    cvmfs_catalog_t *cat = NULL; int owns = 0; char tmp[512];
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

/* Verify the trust chain (whitelist → manifest → cert) into the caller's STAGED
 * manifest buffer, then fetch + open the root catalog into a fresh temp file.
 * Installs NOTHING into cl — the caller commits (mount installs; refresh swaps)
 * only after the whole chain has verified, so a failed refresh can never leave
 * half-committed metadata (xattrs reporting a revision that is not being served,
 * or a wedge where old_root already equals the new root). Shared by mount and
 * refresh. Returns 0 with *out_cat/out_tmp/m/mlen set, or a negative code. */
static int load_trust_and_catalog(cvmfs_client_t *cl, long now,
                                  unsigned char *mbuf, size_t mbuf_cap, size_t *mlen,
                                  cvmfs_manifest_t *m,
                                  char *out_tmp, size_t out_tmp_sz,
                                  cvmfs_catalog_t **out_cat) {
    /* 1. whitelist: fetch raw, verify vs master key, check expiry. */
    unsigned char wlbuf[65536]; size_t wln = 0;
    if (raw_fetch(cl, ".cvmfswhitelist", wlbuf, sizeof(wlbuf), &wln, now) != 0) return -3;
    cvmfs_whitelist_t wl;
    if (cvmfs_whitelist_parse(wlbuf, wln, &wl) != 0) return -4;
    if (cvmfs_verify_whitelist(&wl, cl->master_pub, cl->master_pub_len) != 0) return -5;
    /* Expiry is a WALL-CLOCK judgement: the whitelist's "YYYYMMDDhhmmss" parses to
     * a UTC epoch, so it must be compared against real time — NOT `now`, which is
     * CLOCK_MONOTONIC (seconds-since-boot) and is used only for TTL/refresh gating.
     * Feeding mono here made expiry unenforceable (mono ≪ epoch, never trips). */
    if (cvmfs_whitelist_expired(&wl, (long) time(NULL))) return -6;
    /* The whitelist 'N<fqrn>' line binds this trust anchor to one repository.
     * A validly-signed whitelist minted for a different (or unnamed) repo must
     * not authorize this mount — otherwise a master-key holder for repo A could
     * have their whitelist replayed against repo B. Case-sensitive per fqrn. */
    if (wl.repo_name[0] == '\0' || strcmp(wl.repo_name, cl->config.name) != 0) return -12;

    /* 2. manifest: fetch raw into the STAGING buffer, parse. */
    if (raw_fetch(cl, ".cvmfspublished", mbuf, mbuf_cap, mlen, now) != 0) return -3;
    if (cvmfs_manifest_parse(mbuf, *mlen, m) != 0) return -7;
    /* NOTE: the manifest 'N<fqrn>' field is NOT gated against the served repo.
     * Stock CVMFS authenticates the manifest by cert-fingerprint ∈ whitelist +
     * signature body-binding, and binds repository identity through the
     * whitelist 'N' line (checked above, -12) — not the manifest's N. Real
     * publishers routinely serve one signed manifest under several fqrns (our
     * whitelist conformance harness reproduces this), so gating on manifest-N
     * here would refuse legitimate mounts. Identity is the whitelist's job. */

    /* 3. signing cert: fetch CAS object ('X'), check fingerprint ∈ whitelist. */
    size_t certn = 0;
    unsigned char *cert = fetch_cas(cl, &m->certificate, 'X', &certn, now);
    if (cert == NULL) return -8;
    char fp[64];
    int fp_ok = cvmfs_cert_fingerprint(cert, certn, fp, sizeof(fp)) == 0
             && cvmfs_whitelist_lists_fp(&wl, fp);
    int sig_ok = fp_ok && cvmfs_verify_manifest(m, cert, certn) == 0;
    free(cert);
    if (!sig_ok) return -9;

    /* 4. root catalog: fetch + open. A pinned client opens the PIN hash instead
     * of the manifest's — the CAS fetch is hash-verified, so a tampered pin
     * target is refused right here — and records whether the verified upstream
     * manifest has drifted away from the pin. */
    const cvmfs_hash_t *want = cl->pin_set ? &cl->pin_root : &m->root_catalog;
    cvmfs_catalog_t *cat = open_catalog_by_hash(cl, want,
                                                cl->catalog_tmp, out_tmp, out_tmp_sz, now);
    if (cat == NULL) return -10;
    if (cl->pin_set) {
        cl->pin_drift = !cvmfs_hash_eq(&cl->pin_root, &m->root_catalog);
        if (cl->pin_drift)
            cvmfs_hash_to_hex(&m->root_catalog, 0,
                              cl->pin_drift_hex, sizeof(cl->pin_drift_hex));
    }

    /* 5. revision consistency: the manifest 'S' must equal the root catalog's own
     * recorded revision. The catalog is content-addressed by the (now body-bound,
     * hence authentic) manifest 'C', so its 'revision' property is authenticated
     * transitively — a rollback that edits only the unsigned-looking manifest 'S'
     * without rebuilding the catalog is caught here. Tolerant of a catalog with no
     * 'revision' property (older/hand-built repos) and of a manifest that omits 'S'
     * entirely (revision defaults to 0): enforce only when BOTH sides carry a
     * revision and they disagree, so we never reject a legitimate repo that omits
     * either. Body-binding (see cvmfs_verify_manifest) already prevents an attacker
     * from stripping a signed 'S', so a revision of 0 here can only be a genuinely
     * S-less publish, which has no prior revision to roll back to. */
    /* Skipped for a pinned client: a pin to an older publish legitimately
     * disagrees with the (advanced) manifest 'S'. */
    char revbuf[32];
    if (!cl->pin_set && m->revision != 0
            && cvmfs_catalog_property(cat, "revision", revbuf, sizeof(revbuf)) == 1
            && atol(revbuf) != m->revision) {
        cvmfs_catalog_close(cat);
        return -11;
    }
    *out_cat = cat;
    return 0;
}

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

    int cache_rc = cache_dirfd >= 0
        ? brix_cas_init_at(&cl->cache, cache_dirfd, quota_bytes)
        : brix_cas_init(&cl->cache, cache_dir, quota_bytes);
    if (cache_rc != 0) return -1;

    memset(&cl->fetch, 0, sizeof(cl->fetch));
    cl->fetch.fo = &cl->fo;
    cl->fetch.cache = &cl->cache;
    cl->fetch.transport = transport;
    cl->fetch.transport_ud = ud;
    cl->fetch.store_form = CVMFS_STORE_COMPRESSED;
    cl->fetch.scratch = cl->scratch;
    cl->fetch.scratch_cap = sizeof(cl->scratch);

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

int cvmfs_client_refresh(cvmfs_client_t *cl, long now) {
    if (cl->ttl <= 0) cl->ttl = 240;
    if (now < cl->last_refresh + cl->ttl) return 0;      /* not due */

    size_t           mlen = 0;
    cvmfs_manifest_t m;
    char             ntmp[512] = {0};
    cvmfs_catalog_t *ncat = NULL;
    int rc = load_trust_and_catalog(cl, now, cl->manifest_stage, sizeof(cl->manifest_stage),
                                    &mlen, &m, ntmp, sizeof(ntmp), &ncat);
    cl->last_refresh = now;
    if (rc != 0) return -1;                              /* keep serving old */

    /* Pinned mount: the served catalog is immutable. The chain re-verified
     * (trust freshness) and drift vs upstream was recorded above; discard the
     * re-opened pin catalog and keep the manifest we mounted with, so xattrs
     * keep describing what is actually being served. */
    if (cl->pin_set) {
        cvmfs_catalog_close(ncat);
        if (ntmp[0]) unlink(ntmp);
        return 0;
    }

    /* Rollback protection: a verified-but-OLDER revision is a replay (or a
     * poisoned mirror serving stale state) — refuse it and keep serving. Only
     * enforced when both sides carry a revision, so hand-built repos without an
     * 'S' field never wedge. */
    if (m.revision > 0 && cl->manifest.revision > 0
            && m.revision < cl->manifest.revision) {
        cvmfs_catalog_close(ncat);
        if (ntmp[0]) unlink(ntmp);
        return -1;
    }

    if (cvmfs_hash_eq(&cl->manifest.root_catalog, &m.root_catalog)) {
        cvmfs_catalog_close(ncat);                       /* same revision */
        if (ntmp[0]) unlink(ntmp);
        commit_manifest(cl, cl->manifest_stage, mlen);   /* refreshed ttl/timestamp */
        return 0;
    }
    /* new revision → swap the root catalog, then commit its manifest */
    cvmfs_catalog_close(cl->root_catalog);
    if (cl->root_catalog_tmp[0]) unlink(cl->root_catalog_tmp);
    cl->root_catalog = ncat;
    snprintf(cl->root_catalog_tmp, sizeof(cl->root_catalog_tmp), "%s", ntmp);
    commit_manifest(cl, cl->manifest_stage, mlen);
    return 1;
}

void cvmfs_client_umount(cvmfs_client_t *cl) {
    if (cl->root_catalog) {
        cvmfs_catalog_close(cl->root_catalog);
        cl->root_catalog = NULL;
        if (cl->root_catalog_tmp[0]) unlink(cl->root_catalog_tmp);
    }
}

/* ---- read -------------------------------------------------------------- */

static int read_whole(cvmfs_client_t *cl, const cvmfs_dirent_t *e, uint64_t offset,
                      size_t len, unsigned char *buf, size_t *outlen, long now) {
    size_t         n = 0;
    unsigned char *data = fetch_cas(cl, &e->hash, 0, &n, now);
    if (data == NULL) return -1;
    size_t avail = offset >= n ? 0 : n - (size_t) offset;
    size_t give  = len < avail ? len : avail;
    memcpy(buf, data + offset, give);
    *outlen = give;
    free(data);
    return 0;
}

typedef struct {
    cvmfs_client_t *cl; uint64_t offset; size_t len;
    unsigned char *buf; size_t got; long now; int err;
} chunk_read_t;

static void chunk_read_cb(uint64_t coff, uint64_t csize, const cvmfs_hash_t *h, void *ud) {
    chunk_read_t *r = ud;
    if (r->err) return;
    uint64_t cend = coff + csize;
    uint64_t rend = r->offset + r->len;
    if (cend <= r->offset || coff >= rend) return;          /* no overlap */

    size_t         cn = 0;
    unsigned char *cd = fetch_cas(r->cl, h, 'P', &cn, r->now);
    if (cd == NULL) { r->err = 1; return; }

    uint64_t from = r->offset > coff ? r->offset : coff;
    uint64_t to   = rend < cend ? rend : cend;
    if (to > from && (from - coff) <= cn) {
        size_t avail = cn - (size_t)(from - coff);
        size_t give  = (size_t)(to - from);
        if (give > avail) give = avail;
        memcpy(r->buf + (from - r->offset), cd + (from - coff), give);
        r->got += give;
    }
    free(cd);
}

int cvmfs_client_read(cvmfs_client_t *cl, const char *path, uint64_t offset,
                      size_t len, unsigned char *buf, size_t *outlen, long now) {
    cvmfs_catalog_t *cat = NULL; int owns = 0; char tmp[512];
    cvmfs_dirent_t e;
    int found = resolve_full(cl, path, &e, &cat, &owns, tmp, sizeof(tmp), now);
    int rc = -1;

    if (found == 1 && (e.flags & CVMFS_FLAG_FILE)) {
        if (e.flags & CVMFS_FLAG_FILE_CHUNK) {
            chunk_read_t r; memset(&r, 0, sizeof(r));
            r.cl = cl; r.offset = offset; r.len = len; r.buf = buf; r.now = now;
            if (cvmfs_catalog_chunks(cat, path, chunk_read_cb, &r) >= 0 && !r.err) {
                *outlen = r.got; rc = 0;
            }
        } else {
            rc = read_whole(cl, &e, offset, len, buf, outlen, now);
        }
    }
    if (owns) { cvmfs_catalog_close(cat); if (tmp[0]) unlink(tmp); }
    return rc;
}

/* ---- magic xattrs ------------------------------------------------------- */

/* Copy `val` into `out` only if it fits; always return the value length (so a
 * size-probe call with outlen==0 learns the size — the getxattr protocol). */
static int put_val(char *out, size_t outlen, const char *val) {
    size_t n = strlen(val);
    if (outlen >= n) memcpy(out, val, n);
    return (int) n;
}

int cvmfs_client_getxattr(cvmfs_client_t *cl, const char *path, const char *name,
                          char *out, size_t outlen, long now) {
    char val[512];

    /* Official CVMFS exposes these under the "user.cvmfs." namespace
     * (user.cvmfs.fqrn, user.cvmfs.revision, ...). Accept that spelling by
     * folding it onto the bare "user." names we dispatch below; the bare names
     * remain valid for compatibility. */
    char nbuf[128];
    if (strncmp(name, "user.cvmfs.", 11) == 0) {
        snprintf(nbuf, sizeof(nbuf), "user.%s", name + 11);
        name = nbuf;
    }

    if (strcmp(name, "user.fqrn") == 0) {
        snprintf(val, sizeof(val), "%s", cl->config.name);
    } else if (strcmp(name, "user.revision") == 0) {
        /* Pinned: report the SERVED catalog's own revision, not the (possibly
         * advanced) manifest's; fall through when the catalog records none. */
        if (!(cl->pin_set && cl->root_catalog
                && cvmfs_catalog_property(cl->root_catalog, "revision",
                                          val, sizeof(val)) == 1))
            snprintf(val, sizeof(val), "%ld", cl->manifest.revision);
    } else if (strcmp(name, "user.root_hash") == 0) {
        /* A pinned mount serves the pin, whatever the manifest advertises. */
        cvmfs_hash_to_hex(cl->pin_set ? &cl->pin_root : &cl->manifest.root_catalog,
                          0, val, sizeof(val));
    } else if (strcmp(name, "user.host") == 0 || strcmp(name, "user.proxy") == 0) {
        cvmfs_fo_route_t r;
        if (cvmfs_failover_select(&cl->fo, now, &r) != 0) return -1;
        if (strcmp(name, "user.host") == 0)
            snprintf(val, sizeof(val), "%s", cl->fo.hosts[r.host].url);
        else
            snprintf(val, sizeof(val), "%s",
                     r.proxy >= 0 ? cl->fo.proxies[r.proxy].url : "DIRECT");
    } else if (strcmp(name, "user.hash") == 0 || strcmp(name, "user.nchunks") == 0) {
        cvmfs_catalog_t *cat = NULL; int owns = 0; char tmp[512];
        cvmfs_dirent_t e;
        int found = resolve_full(cl, path, &e, &cat, &owns, tmp, sizeof(tmp), now);
        int rc = -1;
        if (found == 1 && (e.flags & CVMFS_FLAG_FILE)) {
            if (strcmp(name, "user.hash") == 0) {
                if (e.has_hash) { cvmfs_hash_to_hex(&e.hash, 0, val, sizeof(val)); rc = 0; }
            } else {
                int n = (e.flags & CVMFS_FLAG_FILE_CHUNK)
                        ? cvmfs_catalog_chunks(cat, path, NULL, NULL) : 1;
                snprintf(val, sizeof(val), "%d", n < 0 ? 0 : n);
                rc = 0;
            }
        }
        if (owns) { cvmfs_catalog_close(cat); if (tmp[0]) unlink(tmp); }
        if (rc != 0) return -1;
    } else {
        return -1;   /* not a magic attribute we define */
    }
    return put_val(out, outlen, val);
}

int cvmfs_client_listxattr(cvmfs_client_t *cl, const char *path,
                           char *out, size_t outlen, long now) {
    /* Names applicable to EVERY node, then the file-only content attributes.
     * Official CVMFS advertises only the attributes that apply to the node, so
     * a directory (which has no whole-file hash or chunk count) must not list
     * user.hash / user.nchunks — getxattr on them would only ENODATA. */
    static const char common[]   = "user.fqrn\0user.revision\0user.root_hash\0"
                                   "user.host\0user.proxy\0";
    static const char fileonly[] = "user.hash\0user.nchunks\0";
    size_t cn = sizeof(common) - 1, fn = sizeof(fileonly) - 1;

    cvmfs_dirent_t e;
    int is_file = cvmfs_client_resolve(cl, path, &e, now) == 1
                  && (e.flags & CVMFS_FLAG_FILE);

    size_t n = cn + (is_file ? fn : 0);
    if (outlen >= n) {
        memcpy(out, common, cn);
        if (is_file) memcpy(out + cn, fileonly, fn);
    }
    return (int) n;
}

/* ---- reproducibility pin ------------------------------------------------ */

int cvmfs_client_pin_root(cvmfs_client_t *cl, const char *hex) {
    if (hex == NULL || cvmfs_hash_parse(hex, strlen(hex), &cl->pin_root) != 0)
        return -1;
    cl->pin_set = 1;
    cl->pin_drift = 0;
    cl->pin_drift_hex[0] = '\0';
    return 0;
}

int cvmfs_client_pin_drift(cvmfs_client_t *cl, char *out, size_t outlen) {
    if (!cl->pin_set || !cl->pin_drift) return 0;
    if (out != NULL && outlen > 0)
        snprintf(out, outlen, "%s", cl->pin_drift_hex);
    return 1;
}
