/* gc.c — the registry GC pass: live set, path helpers, root check, walk
 * (see gc.h for what the pass is and why it exists; gc_internal.h for the
 * split against gc_mark.c / gc_sweep.c).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "oci/gc_internal.h"

#include "oci/digest.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* One slot holds the widest registered hex plus its NUL. Sizing it to the
 * algorithm a store "usually" holds is how a live set quietly becomes a
 * 64-character PREFIX set, so it is sized for the grammar instead. */
#define GC_SLOT   (BRIX_OCI_HEXLEN_MAX + 1)
#define GC_CAP0   1024


int
brix_oci_gc_fmt(char *out, size_t outsz, const char *fmt, ...)
{
    va_list ap;
    int     n;

    va_start(ap, fmt);
    n = vsnprintf(out, outsz, fmt, ap);
    va_end(ap);
    return (n < 0 || (size_t) n >= outsz) ? -1 : 0;
}


const char *
brix_oci_gc_hex_alg(const char *name)
{
    brix_oci_digest_t d;

    /* Route the question through the one digest grammar rather than a second
     * hex check that would drift from it. */
    if (brix_oci_digest_parse_hex(name, strlen(name), &d) != 0) {
        return NULL;
    }
    return brix_oci_alg_name(d.alg);
}


int
brix_oci_gc_is_hex(const char *name)
{
    return brix_oci_gc_hex_alg(name) != NULL;
}


/* The slot `hex` occupies in a table of `cap` slots — its own, or the free
 * one that ends its probe. The key is a content hash already, so its last
 * bytes are as good a bucket as anything derived from them. Taking them from
 * the END of the actual string rather than a fixed offset is what keeps the
 * bucket well distributed for both widths. */
static char *
gc_slot(char *tab, size_t cap, const char *hex)
{
    unsigned long i, step = 0;
    size_t        n = strlen(hex);
    char         *s;

    i = (unsigned long) strtoul(hex + n - 8, NULL, 16);
    for (;;) {
        s = tab + (i & (cap - 1)) * GC_SLOT;
        if (s[0] == '\0' || strcmp(s, hex) == 0) {
            return s;
        }
        i += ++step;                        /* triangular probing */
    }
}


/* Grow to `cap` slots, rehashing what is already held. 0 / -1 OOM. */
static int
gc_set_grow(brix_oci_gc_set_t *s, size_t cap)
{
    char  *tab = calloc(cap, GC_SLOT);
    size_t i;

    if (tab == NULL) {
        return -1;
    }
    for (i = 0; i < s->cap; i++) {
        char *old = s->slots + i * GC_SLOT;

        if (old[0] != '\0') {
            memcpy(gc_slot(tab, cap, old), old, strlen(old) + 1);
        }
    }
    free(s->slots);
    s->slots = tab;
    s->cap = cap;
    return 0;
}


int
brix_oci_gc_set_add(brix_oci_gc_set_t *s, const char *hex)
{
    char *slot;

    /* Half full at most: probing degrades sharply past that, and a busy
     * store's blob count is exactly when this pass must stay linear. */
    if (s->n * 2 >= s->cap && gc_set_grow(s, s->cap ? s->cap * 2 : GC_CAP0)) {
        return -1;
    }
    slot = gc_slot(s->slots, s->cap, hex);
    if (slot[0] != '\0') {
        return 0;
    }
    memcpy(slot, hex, strlen(hex) + 1);
    s->n++;
    return 1;
}


int
brix_oci_gc_set_has(const brix_oci_gc_set_t *s, const char *hex)
{
    return s->cap != 0 && gc_slot(s->slots, s->cap, hex)[0] != '\0';
}


void
brix_oci_gc_set_free(brix_oci_gc_set_t *s)
{
    free(s->slots);
    s->slots = NULL;
    s->cap = 0;
    s->n = 0;
}


int
brix_oci_gc_isdir(const char *path)
{
    struct stat sb;

    /* lstat, not stat: a symlink is never followed, so a link planted in the
     * store cannot walk this pass out of the root it was pointed at. */
    return lstat(path, &sb) == 0 && S_ISDIR(sb.st_mode);
}


int
brix_oci_gc_reapable(brix_oci_gc_t *c, const char *path, off_t *size)
{
    struct stat sb;

    if (lstat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        return 0;
    }
    if (sb.st_mtime + c->grace > c->now) {
        return 0;
    }
    *size = sb.st_size;
    return 1;
}


/* A path we are not permitted to unlink is left alone and not counted: the
 * report then describes what the store actually holds, and the next pass
 * retries it once the operator has fixed the permission. */
void
brix_oci_gc_reap(brix_oci_gc_t *c, const char *path, off_t size,
                 unsigned long *counter)
{
    if (!c->dry_run && unlink(path) != 0 && errno != ENOENT) {
        return;
    }
    (*counter)++;
    c->st.bytes += (unsigned long long) size;
}


/* A store root must look like one before the pass is allowed to unlink
 * inside it. The two directories the registry always creates are cheap proof
 * that a root is not, say, "/". */
static int
gc_root_ok(const brix_oci_gc_t *c, char *err, size_t errlen)
{
    char path[PATH_MAX];

    /* blobs/ rather than blobs/sha256: the CAS grows one subdirectory per
     * algorithm on demand, so a store that has only ever held sha512 has no
     * sha256 tree — and the pair is still proof this is not `gc /`. */
    if (brix_oci_gc_fmt(path, sizeof(path), "%s/blobs", c->root) != 0
        || !brix_oci_gc_isdir(path)
        || brix_oci_gc_fmt(path, sizeof(path), "%s/repos", c->root) != 0
        || !brix_oci_gc_isdir(path))
    {
        if (err != NULL) {
            snprintf(err, errlen, "%s: not an OCI registry store (expected "
                     "blobs/ and repos/ under it)", c->root);
        }
        return 0;
    }
    return 1;
}


/* Append one path component to a repository name. -1 when the name would
 * outgrow the grammar's own bound, which is also the store's. */
static int
gc_child(char *out, size_t outsz, const char *rel, const char *name)
{
    return rel[0] == '\0'
           ? brix_oci_gc_fmt(out, outsz, "%s", name)
           : brix_oci_gc_fmt(out, outsz, "%s/%s", rel, name);
}


/* Does `dir` hold a manifest tree under ANY registered algorithm? That, not
 * the presence of one fixed subdirectory, is what makes a directory in the
 * repos/ tree a repository. `scratch` is caller-owned working space. */
static int
gc_has_manifests(const char *dir, char *scratch, size_t scratchsz)
{
    int a;

    for (a = 0; a < BRIX_OCI_ALG_COUNT; a++) {
        if (brix_oci_gc_fmt(scratch, scratchsz, "%s/manifests/%s", dir,
                            brix_oci_alg_name((brix_oci_alg_t) a)) == 0
            && brix_oci_gc_isdir(scratch))
        {
            return 1;
        }
    }
    return 0;
}


/* Walk `repos/` depth-first. A repository name carries '/', so a directory
 * can be a repository AND the parent of others ("lab" beside "lab/app");
 * both are handled, and no subdirectory is skipped by name — a repository
 * called "manifests" is legal, and skipping it would sweep its blobs. */
static int
gc_walk(brix_oci_gc_t *c, const char *rel, int depth)
{
    char           dir[PATH_MAX], sub[PATH_MAX], child[512];
    DIR           *d;
    struct dirent *e;
    int            rc = 0;

    if (depth > BRIX_OCI_GC_DEPTH_MAX
        || brix_oci_gc_fmt(dir, sizeof(dir), "%s/repos/%s", c->root, rel) != 0)
    {
        return 0;
    }
    if (rel[0] != '\0' && gc_has_manifests(dir, sub, sizeof(sub))
        && brix_oci_gc_repo(c, rel) != 0)
    {
        return -1;
    }
    d = opendir(dir);
    if (d == NULL) {
        return 0;
    }
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.'
            || gc_child(child, sizeof(child), rel, e->d_name) != 0
            || brix_oci_gc_fmt(sub, sizeof(sub), "%s/%s", dir,
                               e->d_name) != 0
            || !brix_oci_gc_isdir(sub))
        {
            continue;
        }
        rc = gc_walk(c, child, depth + 1);
    }
    closedir(d);
    return rc;
}


int
brix_oci_gc_run(brix_oci_gc_t *c, char *err, size_t errlen)
{
    int rc;

    c->now = time(NULL);
    if (!gc_root_ok(c, err, errlen)) {
        return BRIX_OCI_GC_EROOT;
    }

    /* Mark every repository before sweeping any blob: a blob judged against
     * a half-built live set is a blob deleted because the pass had not yet
     * reached the repository that names it. */
    rc = gc_walk(c, "", 0);
    if (rc == 0) {
        rc = brix_oci_gc_sweep_blobs(c);
    }
    brix_oci_gc_set_free(&c->live);
    if (rc != 0) {
        if (err != NULL) {
            snprintf(err, errlen, "%s", c->err[0] != '\0' ? c->err
                                                          : strerror(errno));
        }
        return BRIX_OCI_GC_EIO;
    }
    return BRIX_OCI_GC_OK;
}
