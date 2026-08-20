/* brixcvmfs_ingest_prune.c — `brixcvmfs ingest prune` (phase-104 D8):
 * retire unreferenced digest roots. Tool surface only (G14).
 *
 *   brixcvmfs ingest prune --repo <repo_dir> [--prefix /images] [--keep N]
 *       [--keys-dir D] [--chunk-size N] [--dry-run] [--no-wait]
 *
 * Referenced = named by ANY memo file under <repo>/.brix-ingest/memo (the
 * global/conservative rule: a root stays while any tag anywhere points at
 * it). Unreferenced roots — the <repo>/.brix-ingest/roots<prefix> ledger
 * minus the referenced set — are ordered newest-first by ledger mtime;
 * --keep N spares the N newest; the rest are DELETEd in one publish under
 * the transaction lock, then their ledger entries are unlinked. Ledger
 * unlink comes after the publish, so a crash between the two leaves only a
 * re-prunable ledger entry, never a dangling published root.
 *
 * `--layout layered` images (D15.6) add a second pass: once the image roots
 * are gone, a layer root that no surviving image's `imglayers` record names
 * is unreachable too, and is retired the same way in its own publish. The
 * two passes are ordered, never merged — a layer is only provably orphaned
 * after the images that composed it have actually left the tree.
 *
 * `bci_prune_old_mark`/`bci_root_forget` are the same rule reached from the
 * other side: `ingest image --prune-old` retiring the root its tag just
 * moved off. Deleting a digest root lives here, once.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "brixcvmfs_ingest_internal.h"
#include "cvmfs/publish/publish.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    const char *repo, *keys_dir;
    char        prefix[ING_PATH_MAX];   /* normalized: no trailing '/' */
    long        chunk_size, keep;
    int         dry_run, no_wait;
} ing_prune_opts_t;

typedef struct {
    brix_oci_digest_t dig;   /* the root's digest — algorithm included: the
                                ledger is flat because hex WIDTH already
                                separates the algorithms, but the tree the
                                prune deletes from is keyed by algorithm */
    time_t mtime;
    int    victim;
} prune_root_t;

static int prune_usage(void) {
    fprintf(stderr,
        "usage: brixcvmfs ingest prune --repo <repo_dir> [--prefix /images]\n"
        "       [--keep N] [--keys-dir D] [--chunk-size N] [--dry-run]"
        " [--no-wait]\n");
    return ING_USAGE;
}

/* Normalize an optional prune prefix while retaining the root identity. */
static int prune_prefix(ing_prune_opts_t *o, const char *value) {
    size_t n = snprintf(o->prefix, sizeof(o->prefix), "%s", value);

    if (n >= sizeof(o->prefix)) return -1;
    while (n > 1 && o->prefix[n - 1] == '/') o->prefix[--n] = '\0';
    return 0;
}

/* Consume the four prune options that require a following value. */
static int prune_value_option(const char *arg, const char *value,
                              ing_prune_opts_t *o) {
    if (value == NULL) return -1;
    if (strcmp(arg, "--repo") == 0) o->repo = value;
    else if (strcmp(arg, "--keys-dir") == 0) o->keys_dir = value;
    else if (strcmp(arg, "--keep") == 0) o->keep = atol(value);
    else if (strcmp(arg, "--chunk-size") == 0) o->chunk_size = atol(value);
    else return -1;
    return 0;
}

/* Consume one prune option; *i advances when its option owns a value. */
static int prune_option(int argc, char **argv, int *i, ing_prune_opts_t *o) {
    const char *arg = argv[*i];
    const char *value = *i + 1 < argc ? argv[*i + 1] : NULL;

    if (strcmp(arg, "--dry-run") == 0) o->dry_run = 1;
    else if (strcmp(arg, "--no-wait") == 0) o->no_wait = 1;
    else if (strcmp(arg, "--prefix") == 0) {
        if (value == NULL || prune_prefix(o, value) != 0) return ING_USAGE;
        ++*i;
    } else if (prune_value_option(arg, value, o) == 0) {
        ++*i;
    } else return ING_USAGE;
    return ING_OK;
}

static int prune_parse(int argc, char **argv, ing_prune_opts_t *o) {
    memset(o, 0, sizeof(*o));
    snprintf(o->prefix, sizeof(o->prefix), "/images");
    for (int i = 1; i < argc; i++) {
        if (prune_option(argc, argv, &i, o) != ING_OK)
            return prune_usage();
    }
    return o->repo != NULL && o->keep >= 0 ? ING_OK : prune_usage();
}

static int prune_cmp(const void *a, const void *b) {
    const prune_root_t *x = a, *y = b;
    return x->mtime < y->mtime ? 1 : x->mtime > y->mtime ? -1
         : strcmp(x->dig.hex, y->dig.hex);
}

/* Roots ledger scan → unreferenced entries, newest-first. */
static int prune_collect(const ing_prune_opts_t *o, const char *roots_dir,
                         prune_root_t **out, size_t *out_n) {
    char memo_dir[ING_PATH_MAX];
    snprintf(memo_dir, sizeof(memo_dir), "%s/.brix-ingest/memo", o->repo);
    *out = NULL;
    *out_n = 0;
    DIR *d = opendir(roots_dir);
    if (d == NULL) return ING_OK;        /* nothing ever ingested here */
    struct dirent *e;
    size_t cap = 0;
    while ((e = readdir(d)) != NULL) {
        char sub[ING_PATH_MAX + 80], digest[BRIX_OCI_DIGEST_STRLEN];
        brix_oci_digest_t dig;
        struct stat st;
        /* A ledger name is a bare hex whose width names its algorithm; a
         * name that is not one is not this tool's to delete. */
        if (brix_oci_digest_parse_hex(e->d_name, strlen(e->d_name), &dig) != 0
            || snprintf(sub, sizeof(sub), "%s/%s", roots_dir, e->d_name)
                   >= (int) sizeof(sub)
            || lstat(sub, &st) != 0 || !S_ISREG(st.st_mode)
            || brix_oci_digest_format(&dig, digest, sizeof(digest)) < 0)
            continue;
        if (bci_memo_refs(memo_dir, digest, "") > 0) continue;
        if (*out_n == cap) {
            cap = cap != 0 ? cap * 2 : 8;
            prune_root_t *nv = realloc(*out, cap * sizeof(*nv));
            if (nv == NULL) {
                closedir(d);
                return bci_fail(ING_FAIL, "out of memory", NULL);
            }
            *out = nv;
        }
        prune_root_t *r = &(*out)[(*out_n)++];
        r->dig = dig;
        r->mtime = st.st_mtime;
        r->victim = 0;
    }
    closedir(d);
    qsort(*out, *out_n, sizeof(**out), prune_cmp);
    return ING_OK;
}

static int prune_publish(const ing_prune_opts_t *o, prune_root_t *v,
                         size_t nv, size_t nvictims) {
    cvmfs_changeset_t cs;
    char err[1024], path[ING_PATH_MAX + 96];
    long rev = 0;
    memset(&cs, 0, sizeof(cs));
    int rc = ING_OK;
    for (size_t i = 0; rc == ING_OK && i < nv; i++) {
        if (!v[i].victim) continue;
        cvmfs_change_t *ch = bci_cs_append(&cs);
        snprintf(path, sizeof(path), "%s/.images/%s/%s",
                 bci_pfx(o->prefix), brix_oci_alg_name(v[i].dig.alg),
                 v[i].dig.hex);
        if (ch == NULL || (ch->path = strdup(path)) == NULL)
            rc = bci_fail(ING_FAIL, "out of memory", NULL);
        else
            ch->op = CVMFS_CH_DELETE;
    }
    if (rc == ING_OK) rc = bci_lock_acquire(o->repo, o->no_wait);
    if (rc == ING_OK) {
        cvmfs_publish_opts_t po;
        memset(&po, 0, sizeof(po));
        po.repo_dir = o->repo;
        po.keys_dir = o->keys_dir;
        po.chunk_size = o->chunk_size;
        rc = cvmfs_publish_run(&po, &cs, &rev, err, sizeof(err)) == 0
             ? ING_OK : bci_fail(ING_FAIL, "publish failed", err);
        bci_lock_release(o->repo);
    }
    cvmfs_changeset_free(&cs);
    if (rc != ING_OK) return rc;
    for (size_t i = 0; i < nv; i++) {
        if (!v[i].victim) continue;
        snprintf(path, sizeof(path), "%s/.brix-ingest/roots%s/%s",
                 o->repo, bci_pfx(o->prefix), v[i].dig.hex);
        unlink(path);
        snprintf(path, sizeof(path), "%s/.brix-ingest/imglayers%s/%s",
                 o->repo, bci_pfx(o->prefix), v[i].dig.hex);
        unlink(path);                    /* layered: pass 2 reads what is left */
    }
    printf("pruned %zu root(s) under %s (revision %ld)\n",
           nvictims, o->prefix, rev);
    return ING_OK;
}

/* ---- --prune-old, for brixcvmfs_ingest_image.c ---------------------------- */

int
bci_prune_old_mark(const char *repo, const char *prefix, const char *memo_path,
                   const char *old_digest, const char *new_digest,
                   cvmfs_changeset_t *cs)
{
    char memo_dir[ING_PATH_MAX], path[ING_PATH_MAX + 96];
    brix_oci_digest_t old;
    cvmfs_change_t *ch;

    if (old_digest[0] == '\0' || strcmp(old_digest, new_digest) == 0) {
        return 0;                        /* first publish, or the tag stayed */
    }
    snprintf(memo_dir, sizeof(memo_dir), "%s/.brix-ingest/memo", repo);
    if (bci_memo_refs(memo_dir, old_digest, memo_path) > 0) {
        return 0;                        /* another tag still points at it */
    }
    if (brix_oci_digest_parse(old_digest, strlen(old_digest), &old) != 0
        || snprintf(path, sizeof(path), "%s/.images/%s/%s", bci_pfx(prefix),
                    brix_oci_alg_name(old.alg), old.hex)
               >= (int) sizeof(path))
    {
        bci_fail(ING_FAIL, "unusable previous digest", old_digest);
        return -1;
    }
    ch = bci_cs_append(cs);
    if (ch == NULL || (ch->path = strdup(path)) == NULL) {
        bci_fail(ING_FAIL, "out of memory", NULL);
        return -1;
    }
    ch->op = CVMFS_CH_DELETE;
    return 1;
}


void
bci_root_forget(const char *repo, const char *prefix, const char *digest)
{
    char path[ING_PATH_MAX + 96];
    brix_oci_digest_t d;

    if (brix_oci_digest_parse(digest, strlen(digest), &d) == 0
        && snprintf(path, sizeof(path), "%s/.brix-ingest/roots%s/%s", repo,
                    bci_pfx(prefix), d.hex) < (int) sizeof(path)) {
        unlink(path);
    }
}


/* ---- pass 2: layer roots nothing composes any more (D15.6) ---------------- */

static int prune_layers(const ing_prune_opts_t *o)
{
    cvmfs_changeset_t cs;
    char   err[1024], **hex = NULL;
    long   rev = 0;
    int    n, rc;

    memset(&cs, 0, sizeof(cs));
    n = bci_layer_orphans(o->repo, o->prefix, &cs, &hex);
    if (n < 0) {
        cvmfs_changeset_free(&cs);
        return ING_FAIL;
    }
    if (n == 0) {
        cvmfs_changeset_free(&cs);
        return ING_OK;                   /* flat repositories land here */
    }
    if (o->dry_run) {
        for (int i = 0; i < n; i++) {
            printf("would prune layer %s\n", cs.v[i].path);
        }
        cvmfs_changeset_free(&cs);
        bci_layer_release(hex, n);
        return ING_OK;
    }
    rc = bci_lock_acquire(o->repo, o->no_wait);
    if (rc == ING_OK) {
        cvmfs_publish_opts_t po;
        memset(&po, 0, sizeof(po));
        po.repo_dir = o->repo;
        po.keys_dir = o->keys_dir;
        po.chunk_size = o->chunk_size;
        rc = cvmfs_publish_run(&po, &cs, &rev, err, sizeof(err)) == 0
             ? ING_OK : bci_fail(ING_FAIL, "layer publish failed", err);
        bci_lock_release(o->repo);
    }
    cvmfs_changeset_free(&cs);
    if (rc == ING_OK) {
        bci_layer_forget(o->repo, o->prefix, hex, n);
        printf("pruned %d layer root(s) under %s (revision %ld)\n",
               n, o->prefix, rev);
    } else {
        bci_layer_release(hex, n);       /* the roots are still published */
    }
    return rc;
}


int bci_prune_main(int argc, char **argv) {
    ing_prune_opts_t o;
    int rc = prune_parse(argc, argv, &o);
    if (rc != ING_OK) return rc;
    rc = bci_prefix_check(o.prefix);
    if (rc != ING_OK) return rc;
    char roots_dir[ING_PATH_MAX];
    snprintf(roots_dir, sizeof(roots_dir), "%s/.brix-ingest/roots%s",
             o.repo, bci_pfx(o.prefix));
    prune_root_t *v = NULL;
    size_t nv = 0, nvictims = 0;
    rc = prune_collect(&o, roots_dir, &v, &nv);
    for (size_t i = 0; rc == ING_OK && i < nv; i++) {
        if (i < (size_t) o.keep) continue; /* newest-first: spare the N newest */
        v[i].victim = 1;
        nvictims++;
        if (o.dry_run)
            printf("would prune %s/.images/%s/%s\n", bci_pfx(o.prefix),
                   brix_oci_alg_name(v[i].dig.alg), v[i].dig.hex);
    }
    if (rc == ING_OK && nvictims == 0)
        printf("nothing to prune under %s\n", o.prefix);
    else if (rc == ING_OK && !o.dry_run)
        rc = prune_publish(&o, v, nv, nvictims);
    free(v);
    /* Pass 2 runs even when pass 1 found nothing: a layer can also be
     * orphaned by an image root removed some other way. */
    if (rc == ING_OK)
        rc = prune_layers(&o);
    return rc;
}
