/* gc_mark.c — the registry GC mark phase (see gc.h): every digest the
 * manifests in one repository name enters the live set, and that
 * repository's own bookkeeping — the layer marks and referrer descriptors a
 * DELETE orphaned — is swept against what those bodies actually said.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "oci/gc_internal.h"

#include "core/compat/json_iter.h"
#include "core/compat/json_min.h"
#include "oci/digest.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


/* Whole manifest body into a NUL-terminated buffer the caller frees. */
static char *
gc_slurp(const char *path, size_t *len)
{
    struct stat sb;
    char       *buf;
    FILE       *f;
    size_t      got;

    if (lstat(path, &sb) != 0 || !S_ISREG(sb.st_mode)
        || sb.st_size > BRIX_OCI_GC_MANIFEST_MAX)
    {
        return NULL;
    }
    f = fopen(path, "r");
    if (f == NULL) {
        return NULL;
    }
    buf = malloc((size_t) sb.st_size + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    got = fread(buf, 1, (size_t) sb.st_size, f);
    fclose(f);
    buf[got] = '\0';
    *len = got;
    return buf;
}


/* One "digest": "<alg>:…" value into both sets. The sets are keyed by bare
 * hex, which stays unambiguous because no two registered algorithms share a
 * width. */
static int
gc_mark(brix_oci_gc_t *c, brix_oci_gc_set_t *repo, const char *el,
        size_t elen)
{
    brix_oci_digest_t d;
    char              s[BRIX_OCI_DIGEST_STRLEN];

    if (!brix_json_get_str(el, elen, "digest", s, sizeof(s))
        || brix_oci_digest_parse(s, strlen(s), &d) != 0)
    {
        return 0;               /* a digest we cannot read marks nothing */
    }
    return brix_oci_gc_set_add(&c->live, d.hex) < 0
           || brix_oci_gc_set_add(repo, d.hex) < 0 ? -1 : 0;
}


/* Every element of the descriptor array under `key`, if the body has one. */
static int
gc_mark_array(brix_oci_gc_t *c, brix_oci_gc_set_t *repo, const char *body,
              size_t len, const char *key)
{
    const char *arr, *el;
    size_t      an, en, cur = 0;

    if (brix_json_get_raw(body, len, key, &arr, &an) != 1) {
        return 0;
    }
    while (brix_json_arr_next(arr, an, &cur, &el, &en) == 1) {
        if (gc_mark(c, repo, el, en) != 0) {
            return -1;
        }
    }
    return 0;
}


/* Every digest one manifest names: its config blob, its layers, an index's
 * children, and the subject an artifact hangs off. The subject matters even
 * though it is a manifest and not a blob — a referrer's edge must not be the
 * only thing keeping its own subject reachable. */
static int
gc_mark_body(brix_oci_gc_t *c, brix_oci_gc_set_t *repo, const char *body,
             size_t len)
{
    static const char *const objs[] = { "config", "subject" };
    const char              *el;
    size_t                   en;
    unsigned                 i;

    for (i = 0; i < sizeof(objs) / sizeof(objs[0]); i++) {
        if (brix_json_get_raw(body, len, objs[i], &el, &en) == 1
            && gc_mark(c, repo, el, en) != 0)
        {
            return -1;
        }
    }
    return gc_mark_array(c, repo, body, len, "layers") != 0
           || gc_mark_array(c, repo, body, len, "manifests") != 0 ? -1 : 0;
}


/* Mark from every manifest body this repository holds. */
static int
gc_repo_manifests(brix_oci_gc_t *c, brix_oci_gc_set_t *repo,
                  const char *dir)
{
    char           path[PATH_MAX];
    DIR           *d = opendir(dir);
    struct dirent *e;
    int            rc = 0;

    if (d == NULL) {
        /* Vanished between the walk's stat and here: a concurrent delete,
         * and nothing to mark. Any other errno means we cannot SEE what
         * this repository references, and a sweep run on an incomplete live
         * set deletes blobs that are in use — so it is fatal, not skipped. */
        if (errno == ENOENT) {
            return 0;
        }
        snprintf(c->err, sizeof(c->err), "%.400s: %s", dir, strerror(errno));
        return -1;
    }
    while (rc == 0 && (e = readdir(d)) != NULL) {
        char  *body;
        size_t len;

        /* The sidecars (.meta, .subject) carry a suffix, so the digest
         * grammar excludes them without a second naming convention. */
        if (!brix_oci_gc_is_hex(e->d_name)
            || brix_oci_gc_fmt(path, sizeof(path), "%s/%s", dir, e->d_name) != 0)
        {
            continue;
        }
        body = gc_slurp(path, &len);
        if (body == NULL) {
            continue;
        }
        c->st.manifests++;
        rc = brix_oci_gc_set_add(&c->live, e->d_name) < 0
             || gc_mark_body(c, repo, body, len) != 0 ? -1 : 0;
        free(body);
    }
    closedir(d);
    if (rc != 0) {
        snprintf(c->err, sizeof(c->err), "out of memory marking %.400s",
                 dir);
    }
    return rc;
}


/* Drop the layer marks no manifest in this repository justifies any more —
 * what a manifest DELETE leaves behind, by design. */
static void
gc_repo_marks(brix_oci_gc_t *c, const brix_oci_gc_set_t *repo,
              const char *dir)
{
    char           path[PATH_MAX];
    DIR           *d = opendir(dir);
    struct dirent *e;
    off_t          size;

    if (d == NULL) {
        return;
    }
    while ((e = readdir(d)) != NULL) {
        if (!brix_oci_gc_is_hex(e->d_name)
            || brix_oci_gc_set_has(repo, e->d_name)
            || brix_oci_gc_fmt(path, sizeof(path), "%s/%s", dir,
                              e->d_name) != 0
            || !brix_oci_gc_reapable(c, path, &size))
        {
            continue;
        }
        brix_oci_gc_reap(c, path, size, &c->st.marks);
    }
    closedir(d);
}


/* One subject's referrer directory: descriptors whose referrer manifest is
 * gone describe an edge nothing can follow — the hole a DELETE leaves when
 * its back-pointer was never written. */
static void
gc_referrer_dir(brix_oci_gc_t *c, const char *repo_dir, const char *alg,
                const char *subj)
{
    char           dir[PATH_MAX], path[PATH_MAX], man[PATH_MAX];
    DIR           *d;
    struct dirent *e;
    off_t          size;

    if (brix_oci_gc_fmt(dir, sizeof(dir), "%s/referrers/%s/%s", repo_dir,
                       alg, subj) != 0)
    {
        return;
    }
    d = opendir(dir);
    if (d == NULL) {
        return;
    }
    while ((e = readdir(d)) != NULL) {
        const char *ralg = brix_oci_gc_hex_alg(e->d_name);
        struct stat sb;

        /* The referrer is filed under its OWN algorithm, which need not be
         * the subject's — an artifact may be sha256 while the image it
         * describes is sha512. Its width says which, so the existence probe
         * looks in exactly one place. */
        if (ralg == NULL
            || brix_oci_gc_fmt(path, sizeof(path), "%s/%s", dir,
                              e->d_name) != 0
            || brix_oci_gc_fmt(man, sizeof(man), "%s/manifests/%s/%s",
                              repo_dir, ralg, e->d_name) != 0
            || lstat(man, &sb) == 0
            || !brix_oci_gc_reapable(c, path, &size))
        {
            continue;
        }
        brix_oci_gc_reap(c, path, size, &c->st.refs);
    }
    closedir(d);
    if (!c->dry_run) {
        (void) rmdir(dir);                  /* only when it emptied */
    }
}


/* Every subject under one algorithm's referrer tree. */
static void
gc_repo_referrers_alg(brix_oci_gc_t *c, const char *repo_dir,
                      const char *alg)
{
    char           dir[PATH_MAX];
    DIR           *d;
    struct dirent *e;

    if (brix_oci_gc_fmt(dir, sizeof(dir), "%s/referrers/%s", repo_dir,
                       alg) != 0)
    {
        return;
    }
    d = opendir(dir);
    if (d == NULL) {
        return;
    }
    while ((e = readdir(d)) != NULL) {
        if (brix_oci_gc_is_hex(e->d_name)) {
            gc_referrer_dir(c, repo_dir, alg, e->d_name);
        }
    }
    closedir(d);
}


static void
gc_repo_referrers(brix_oci_gc_t *c, const char *repo_dir)
{
    int a;

    for (a = 0; a < BRIX_OCI_ALG_COUNT; a++) {
        gc_repo_referrers_alg(c, repo_dir,
                              brix_oci_alg_name((brix_oci_alg_t) a));
    }
}


int
brix_oci_gc_repo(brix_oci_gc_t *c, const char *rel)
{
    brix_oci_gc_set_t repo = { NULL, 0, 0 };
    char             dir[PATH_MAX], sub[PATH_MAX];
    int              rc, a;

    if (brix_oci_gc_fmt(dir, sizeof(dir), "%s/repos/%s", c->root, rel) != 0) {
        snprintf(c->err, sizeof(c->err), "repository path too long: %s", rel);
        return -1;
    }
    c->st.repos++;
    /* Mark under EVERY algorithm before anything is judged: a manifest this
     * pass never opened is a manifest whose blobs look unreferenced. */
    for (rc = 0, a = 0; rc == 0 && a < BRIX_OCI_ALG_COUNT; a++) {
        if (brix_oci_gc_fmt(sub, sizeof(sub), "%s/manifests/%s", dir,
                           brix_oci_alg_name((brix_oci_alg_t) a)) != 0)
        {
            snprintf(c->err, sizeof(c->err), "repository path too long: %s",
                     rel);
            rc = -1;
            break;
        }
        rc = gc_repo_manifests(c, &repo, sub);
    }
    if (rc == 0) {
        if (brix_oci_gc_fmt(sub, sizeof(sub), "%s/layers", dir) == 0) {
            gc_repo_marks(c, &repo, sub);
        }
        gc_repo_referrers(c, dir);
    }
    brix_oci_gc_set_free(&repo);
    return rc;
}

