/* _client_part2.c — fragment 2 of client.c (auto-split).
 * Do not compile directly; it is #included by client.c. */
#ifndef _CLIENT_PART2_C_INC
#define _CLIENT_PART2_C_INC
#ifndef __CLIENT_C_COMPILED__
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

#endif /* __CLIENT_C_COMPILED__ */

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
    cvmfs_xorf_reset(&cl->negf);
    cl->negf_set = 0;
    cvmfs_client_pathidx_clear(cl);
    if (cl->root_catalog) {
        cvmfs_catalog_close(cl->root_catalog);
        cl->root_catalog = NULL;
        if (cl->root_catalog_tmp[0]) unlink(cl->root_catalog_tmp);
    }
    brix_cas_destroy(&cl->cache);

    free(cl->scratch);
    cl->scratch = NULL;
    cl->scratch_cap = 0;
    cl->fetch.scratch = NULL;
    cl->fetch.scratch_cap = 0;
}

/* ---- read -------------------------------------------------------------- */

static int read_whole(cvmfs_client_t *cl, const cvmfs_dirent_t *e, uint64_t offset,
                      size_t len, unsigned char *buf, size_t *outlen, long now) {
    size_t         n = 0;
    unsigned char *data = fetch_cas(cl, &e->hash, 0, (size_t) e->size, &n, now);
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
    unsigned char *cd = fetch_cas(r->cl, h, 'P', (size_t) csize, &cn, r->now);
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

/*
 * WHAT: Attempt an unchunked file read through the pinned mmap path index.
 * WHY:  Valid index hits avoid catalog opens while corrupt hits must fail safe.
 * HOW:  Check revision/hash/type, read CAS, and clear the index on read failure.
 */
static int read_from_index(cvmfs_client_t *cl, const char *path,
                           uint64_t offset, size_t len, unsigned char *buf,
                           size_t *outlen, long now) {
    const cvmfs_hash_t *served;
    cvmfs_dirent_t      entry;

    if (!cl->pidx_set)
        return 0;
    served = cl->pin_set ? &cl->pin_root : &cl->manifest.root_catalog;
    if (!cvmfs_hash_eq(&cl->pidx_root, served) ||
        cvmfs_pathidx_lookup(&cl->pidx, path, &entry) != 1 ||
        !(entry.flags & CVMFS_FLAG_FILE) ||
        (entry.flags & CVMFS_FLAG_FILE_CHUNK) || !entry.has_hash)
        return 0;
    if (read_whole(cl, &entry, offset, len, buf, outlen, now) == 0)
        return 1;
    cvmfs_client_pathidx_clear(cl);
    return 0;
}

/*
 * WHAT: Read a requested range from a catalog-described chunked file.
 * WHY:  Chunk maps live in the catalog and require the overlap callback path.
 * HOW:  Seed callback state, enumerate chunks, and return the accumulated bytes.
 */
static int read_chunked(cvmfs_client_t *cl, cvmfs_catalog_t *cat,
                        const char *path, uint64_t offset, size_t len,
                        unsigned char *buf, size_t *outlen, long now) {
    chunk_read_t read_state;

    memset(&read_state, 0, sizeof(read_state));
    read_state.cl = cl;
    read_state.offset = offset;
    read_state.len = len;
    read_state.buf = buf;
    read_state.now = now;
    if (cvmfs_catalog_chunks(cat, path, chunk_read_cb, &read_state) < 0 ||
        read_state.err)
        return -1;
    *outlen = read_state.got;
    return 0;
}

int cvmfs_client_read(cvmfs_client_t *cl, const char *path, uint64_t offset,
                      size_t len, unsigned char *buf, size_t *outlen, long now) {
    /* G6: an index-resolved UNCHUNKED file reads straight from CAS with the
     * index's hash — zero catalog opens (chunked files keep the catalog path;
     * their chunk tables live there). A failed index read means the entry
     * named a hash the verify-fetch could not produce (tampered index — or a
     * genuinely unfetchable object): fail SAFE, drop the whole index, take
     * the catalog path. Over-invalidating on a transient network error only
     * costs the fast path. */
    if (read_from_index(cl, path, offset, len, buf, outlen, now) == 1)
        return 0;

    cvmfs_catalog_t *cat = NULL; int owns = 0; char tmp[512] = {0};
    cvmfs_dirent_t e;
    int found = resolve_full(cl, path, &e, &cat, &owns, tmp, sizeof(tmp), now);
    int rc = -1;

    if (found == 1 && (e.flags & CVMFS_FLAG_FILE)) {
        if (e.flags & CVMFS_FLAG_FILE_CHUNK)
            rc = read_chunked(cl, cat, path, offset, len, buf, outlen, now);
        else
            rc = read_whole(cl, &e, offset, len, buf, outlen, now);
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

/*
 * WHAT: Render the revision served by the pinned or current root catalog.
 * WHY:  A pinned mount must not report an advanced manifest revision.
 * HOW:  Prefer the pinned catalog property and fall back to manifest metadata.
 */
static void attr_revision(cvmfs_client_t *cl, char *val, size_t val_len) {
    if (cl->pin_set && cl->root_catalog &&
        cvmfs_catalog_property(cl->root_catalog, "revision", val, val_len) == 1)
        return;
    snprintf(val, val_len, "%ld", cl->manifest.revision);
}

/*
 * WHAT: Render the currently selected upstream host or proxy route attribute.
 * WHY:  Both attributes depend on the same failover selection at query time.
 * HOW:  Select one route and format either host URL or proxy/DIRECT value.
 */
static int attr_route(cvmfs_client_t *cl, const char *name,
                      char *val, size_t val_len, long now) {
    cvmfs_fo_route_t route;

    if (cvmfs_failover_select(&cl->fo, now, &route) != 0)
        return -1;
    if (strcmp(name, "user.host") == 0)
        snprintf(val, val_len, "%s", cl->fo.hosts[route.host].url);
    else
        snprintf(val, val_len, "%s",
                 route.proxy >= 0 ? cl->fo.proxies[route.proxy].url : "DIRECT");
    return 0;
}

/*
 * WHAT: Render a file's content hash or number of storage chunks.
 * WHY:  These attributes require full path resolution and file-only metadata.
 * HOW:  Resolve once, render the requested value, then close owned catalogs.
 */
static int attr_content(cvmfs_client_t *cl, const char *path,
                        const char *name, char *val, size_t val_len, long now) {
    cvmfs_catalog_t *cat = NULL;
    cvmfs_dirent_t   entry;
    char             tmp[512] = {0};
    int              owns = 0;
    int              rc = -1;
    int              found;

    found = resolve_full(cl, path, &entry, &cat, &owns, tmp, sizeof(tmp), now);
    if (found == 1 && (entry.flags & CVMFS_FLAG_FILE)) {
        if (strcmp(name, "user.hash") == 0 && entry.has_hash) {
            cvmfs_hash_to_hex(&entry.hash, 0, val, val_len);
            rc = 0;
        } else if (strcmp(name, "user.nchunks") == 0) {
            int chunks = (entry.flags & CVMFS_FLAG_FILE_CHUNK)
                         ? cvmfs_catalog_chunks(cat, path, NULL, NULL) : 1;

            snprintf(val, val_len, "%d", chunks < 0 ? 0 : chunks);
            rc = 0;
        }
    }
    if (owns) {
        cvmfs_catalog_close(cat);
        if (tmp[0])
            unlink(tmp);
    }
    return rc;
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
        attr_revision(cl, val, sizeof(val));
    } else if (strcmp(name, "user.root_hash") == 0) {
        /* A pinned mount serves the pin, whatever the manifest advertises. */
        cvmfs_hash_to_hex(cl->pin_set ? &cl->pin_root : &cl->manifest.root_catalog,
                          0, val, sizeof(val));
    } else if (strcmp(name, "user.host") == 0 || strcmp(name, "user.proxy") == 0) {
        if (attr_route(cl, name, val, sizeof(val), now) != 0)
            return -1;
    } else if (strcmp(name, "user.hash") == 0 || strcmp(name, "user.nchunks") == 0) {
        if (attr_content(cl, path, name, val, sizeof(val), now) != 0)
            return -1;
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

/* ---- pre-mount cache-format knob (phase-87 G4/G5) ----------------------- */

void cvmfs_client_cache_config(cvmfs_client_t *cl, int packed, int tiering,
                               long seg_bytes) {
    cl->cache_packed = packed;
    cl->cache_tiering = tiering;
    cl->cache_seg_bytes = seg_bytes;
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
#endif /* _CLIENT_PART2_C_INC */
