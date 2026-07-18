/* walk.c — CVMFS content-aware core facade. See walk.h. */
#include "cvmfs/walk/walk.h"
#include "cvmfs/catalog/catalog.h"
#include "cvmfs/object/object.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CVMFS_WALK_CATALOG_CAP (16u * 1024u * 1024u)   /* matches the client's fetch_cas cap */
#define CVMFS_WALK_MAX_PATH    1024

typedef struct {
    cvmfs_fetch_ctx_t *fx;
    const char        *tmp_dir;
    cvmfs_walk_cb      cb;
    void              *ud;
    long               now;
    int                stopped;   /* callback asked to stop */
    int                err;       /* fetch/open failure — walk aborted */
} walk_ctx_t;

static void emit(walk_ctx_t *w, cvmfs_walk_kind_e kind, const cvmfs_hash_t *h,
                 char suffix, uint64_t size, const char *path) {
    if (w->stopped || w->err) return;
    cvmfs_walk_item_t it = { kind, *h, suffix, size, path };
    if (w->cb(&it, w->ud) != 0) w->stopped = 1;
}

static void walk_dir(walk_ctx_t *w, cvmfs_catalog_t *cat, const char *path, int depth);
static void open_and_walk(walk_ctx_t *w, const cvmfs_hash_t *h, const char *path, int depth);

/* per-chunk emitter for a chunked file */
typedef struct { walk_ctx_t *w; const char *path; } chunk_ud_t;

static void chunk_emit(uint64_t offset, uint64_t size, const cvmfs_hash_t *hash, void *ud) {
    (void) offset;
    chunk_ud_t *c = ud;
    emit(c->w, CVMFS_WALK_CHUNK, hash, 'P', size, c->path);
}

/* per-child handler: emit content references, recurse into directories */
typedef struct {
    walk_ctx_t      *w;
    cvmfs_catalog_t *cat;
    const char      *parent;
    int              depth;
} dir_ud_t;

static void child_visit(const cvmfs_dirent_t *e, void *ud) {
    dir_ud_t *d = ud;
    walk_ctx_t *w = d->w;
    if (w->stopped || w->err || e->name[0] == '\0') return;

    char cpath[CVMFS_WALK_MAX_PATH];
    int n = snprintf(cpath, sizeof(cpath), "%s/%s", d->parent, e->name);
    if (n < 0 || (size_t) n >= sizeof(cpath)) return;      /* over-long path: skip subtree */

    if (e->flags & CVMFS_FLAG_FILE) {
        if (e->flags & CVMFS_FLAG_FILE_CHUNK) {
            chunk_ud_t c = { w, cpath };
            cvmfs_catalog_chunks(d->cat, cpath, chunk_emit, &c);
        } else if (e->has_hash) {
            emit(w, CVMFS_WALK_FILE, &e->hash, 0, e->size, cpath);
        }
        return;
    }
    if (e->flags & CVMFS_FLAG_DIR) {
        cvmfs_hash_t nh; uint64_t nsz = 0;
        if (cvmfs_catalog_nested(d->cat, cpath, &nh, &nsz) == 1) {
            emit(w, CVMFS_WALK_CATALOG, &nh, 'C', nsz, cpath);
            if (d->depth > 0) open_and_walk(w, &nh, cpath, d->depth - 1);
            return;   /* the subtree's rows live in the nested catalog */
        }
        walk_dir(w, d->cat, cpath, d->depth);
    }
    /* symlinks carry their target inline — no CAS reference */
}

static void walk_dir(walk_ctx_t *w, cvmfs_catalog_t *cat, const char *path, int depth) {
    if (w->stopped || w->err) return;
    dir_ud_t d = { w, cat, path, depth };
    cvmfs_catalog_readdir(cat, path, child_visit, &d);
}

/* Fetch a catalog VERIFIED, spill it to a temp file under tmp_dir, open it.
 * The spill path is returned in `tmp` (unlink after close). NULL on failure. */
static cvmfs_catalog_t *open_cat(walk_ctx_t *w, const cvmfs_hash_t *h,
                                 char *tmp, size_t tmplen) {
    unsigned char *buf = malloc(CVMFS_WALK_CATALOG_CAP);
    if (buf == NULL) return NULL;
    size_t n = 0;
    if (cvmfs_fetch_object(w->fx, h, 'C', buf, CVMFS_WALK_CATALOG_CAP, &n, w->now) != 0) {
        free(buf);
        return NULL;
    }

    snprintf(tmp, tmplen, "%s/brixwalk.cat.%d.XXXXXX", w->tmp_dir, (int) getpid());
    int fd = mkstemp(tmp);
    if (fd < 0) { free(buf); return NULL; }
    int ok = 1;
    for (size_t off = 0; off < n; ) {
        ssize_t r = write(fd, buf + off, n - off);
        if (r < 0) { if (errno == EINTR) continue; ok = 0; break; }
        off += (size_t) r;
    }
    close(fd);
    free(buf);

    cvmfs_catalog_t *cat = ok ? cvmfs_catalog_open(tmp) : NULL;
    if (cat == NULL) unlink(tmp);
    return cat;
}

static void open_and_walk(walk_ctx_t *w, const cvmfs_hash_t *h, const char *path, int depth) {
    if (w->stopped || w->err) return;
    char tmp[512];
    cvmfs_catalog_t *cat = open_cat(w, h, tmp, sizeof(tmp));
    if (cat == NULL) { w->err = 1; return; }
    walk_dir(w, cat, path, depth);
    cvmfs_catalog_close(cat);
    unlink(tmp);
}

int cvmfs_walk_catalog(cvmfs_fetch_ctx_t *fx, const cvmfs_hash_t *root,
                       const char *tmp_dir, int max_depth,
                       cvmfs_walk_cb cb, void *ud, long now) {
    walk_ctx_t w = { fx, tmp_dir, cb, ud, now, 0, 0 };
    emit(&w, CVMFS_WALK_CATALOG, root, 'C', 0, "");
    open_and_walk(&w, root, "", max_depth);
    if (w.err) return -1;
    return w.stopped ? 1 : 0;
}

int cvmfs_walk_subtree(cvmfs_fetch_ctx_t *fx, const cvmfs_hash_t *root,
                       const char *tmp_dir, const char *path, int max_depth,
                       cvmfs_walk_cb cb, void *ud, long now) {
    if (path == NULL || path[0] == '\0')
        return cvmfs_walk_catalog(fx, root, tmp_dir, max_depth, cb, ud, now);

    walk_ctx_t w = { fx, tmp_dir, cb, ud, now, 0, 0 };
    char tmp[512];
    cvmfs_catalog_t *cat = open_cat(&w, root, tmp, sizeof(tmp));
    if (cat == NULL) return -1;

    /* Descend across every nested-catalog mountpoint covering `path`: scan its
     * "/"-prefixes left to right; a prefix that is a mountpoint in the CURRENT
     * catalog swaps in that nested catalog (hash-verified fetch) and the scan
     * continues with the longer prefixes. Includes `path` itself, so a subtree
     * rooted at a mountpoint walks inside its own catalog. */
    size_t plen = strlen(path);
    for (size_t i = 1; i <= plen && cat != NULL; i++) {
        if (i < plen && path[i] != '/') continue;
        char prefix[CVMFS_WALK_MAX_PATH];
        if (i >= sizeof(prefix)) { cvmfs_catalog_close(cat); unlink(tmp); return -1; }
        memcpy(prefix, path, i);
        prefix[i] = '\0';

        cvmfs_hash_t nh; uint64_t nsz = 0;
        if (cvmfs_catalog_nested(cat, prefix, &nh, &nsz) == 1) {
            cvmfs_catalog_close(cat);
            unlink(tmp);
            cat = open_cat(&w, &nh, tmp, sizeof(tmp));
        }
    }
    if (cat == NULL) return -1;

    walk_dir(&w, cat, path, max_depth);
    cvmfs_catalog_close(cat);
    unlink(tmp);
    if (w.err) return -1;
    return w.stopped ? 1 : 0;
}

int cvmfs_verify_blob(const cvmfs_hash_t *expected,
                      const unsigned char *stored, size_t stored_len,
                      unsigned char *out, size_t outcap, size_t *outlen) {
    if (!cvmfs_object_verify(stored, stored_len, expected)) return -1;
    if (cvmfs_object_inflate(stored, stored_len, out, outcap, outlen) == 0) return 0;
    /* authentic but not a zlib stream (or inflate overflow): plain-stored form */
    if (stored_len > outcap) return -3;
    memcpy(out, stored, stored_len);
    *outlen = stored_len;
    return 0;
}
