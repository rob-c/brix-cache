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

int cvmfs_client_read(cvmfs_client_t *cl, const char *path, uint64_t offset,
                      size_t len, unsigned char *buf, size_t *outlen, long now) {
    /* G6: an index-resolved UNCHUNKED file reads straight from CAS with the
     * index's hash — zero catalog opens (chunked files keep the catalog path;
     * their chunk tables live there). A failed index read means the entry
     * named a hash the verify-fetch could not produce (tampered index — or a
     * genuinely unfetchable object): fail SAFE, drop the whole index, take
     * the catalog path. Over-invalidating on a transient network error only
     * costs the fast path. */
    if (cl->pidx_set) {
        const cvmfs_hash_t *served = cl->pin_set ? &cl->pin_root
                                                 : &cl->manifest.root_catalog;
        cvmfs_dirent_t ie;
        if (cvmfs_hash_eq(&cl->pidx_root, served)
            && cvmfs_pathidx_lookup(&cl->pidx, path, &ie) == 1
            && (ie.flags & CVMFS_FLAG_FILE)
            && !(ie.flags & CVMFS_FLAG_FILE_CHUNK)
            && ie.has_hash) {
            if (read_whole(cl, &ie, offset, len, buf, outlen, now) == 0)
                return 0;
            cvmfs_client_pathidx_clear(cl);
        }
    }

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
