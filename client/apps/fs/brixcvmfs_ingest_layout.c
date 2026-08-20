/* brixcvmfs_ingest_layout.c — the shape of the published namespace: the tag
 * symlink every layout ends with, and `--layout layered` (phase-104 D15.6) —
 * per-layer publish roots and the ledgers that make them reusable. Tool
 * surface only (G14).
 *
 * The flat layout publishes one merged rootfs per image, so two images off
 * one base pay for that base twice in catalog rows, in scan time and in the
 * bytes fetched to produce them (the CAS dedups the *stored* files, which is
 * why the flat layout is still the default — it costs storage nothing). What
 * it cannot dedup is the work: a rootfs has to be fetched, decompressed and
 * scanned before the store can notice it already had every file.
 *
 * Layered publishes each layer at its own content-addressed root,
 *
 *   <prefix>/.layers/<alg>/<layer-hex>/         one layer, verbatim
 *   <prefix>/.images/<alg>/<manifest-hex>/.layers   the composition, in order
 *
 * so the second image off a shared base fetches, decompresses and scans only
 * the layers that are actually new to the repository. The price is that the
 * image root is no longer a runnable rootfs: composing the layer roots is
 * the consumer's job (overlayfs lowerdirs, lowest last), which is why this
 * is a flag and not the default.
 *
 * Ledgers, all under <repo>/.brix-ingest and all advisory (they are a cache
 * of what the repository already holds; losing one costs a re-publish of
 * content that was already there, never correctness):
 *   layers<pfx>/<layer-hex>      "<prefix> <digest> <diffid|-> <rev> <utc>"
 *   imglayers<pfx>/<image-hex>   the layer hexes of that image, one per line
 * The second is what lets `ingest prune` tell an orphaned layer root from a
 * shared one, exactly as the memo files do for image roots.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "brixcvmfs_ingest_internal.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* One ledger line: prefix, digest, diff_id, revision, timestamp. */
#define LAY_LINE_MAX  (ING_PATH_MAX + 256)


/* ---- the tag symlink, shared by both layouts ------------------------------ */

int
bci_tag_symlink(const char *upper, const char *tagrel, const char *root_rel)
{
    char   lpath[ING_PATH_MAX + 8], dir[ING_PATH_MAX + 8], target[ING_PATH_MAX];
    size_t off = 0;
    char  *slash;

    if (snprintf(lpath, sizeof(lpath), "%s/%s", upper, tagrel)
            >= (int) sizeof(lpath)) {
        return bci_fail(ING_FAIL, "tag path too long", tagrel);
    }
    snprintf(dir, sizeof(dir), "%s", lpath);
    slash = strrchr(dir, '/');
    *slash = '\0';                       /* an upper path always has one */
    if (bci_mkdir_p(dir, 0755) != 0) {
        return bci_fail(ING_FAIL, "cannot create tag dir", dir);
    }
    for (const char *p = tagrel; *p != '\0'; p++) {   /* one ../ per level */
        if (*p == '/' && off + 3 < sizeof(target)) {
            memcpy(target + off, "../", 3);
            off += 3;
        }
    }
    if (off + strlen(root_rel) >= sizeof(target)) {
        return bci_fail(ING_FAIL, "tag link target too long", root_rel);
    }
    snprintf(target + off, sizeof(target) - off, "%s", root_rel);
    return symlink(target, lpath) == 0
        ? ING_OK : bci_fail(ING_FAIL, "cannot create tag symlink", lpath);
}


/* ---- layer roots and their ledgers ---------------------------------------- */

static int lay_ledger_path(char *out, size_t outlen, const char *repo,
                           const char *dir, const char *prefix,
                           const char *name)
{
    int n = snprintf(out, outlen, "%s/.brix-ingest/%s%s/%s", repo, dir,
                     bci_pfx(prefix), name);

    return n >= 0 && (size_t) n < outlen ? 0 : -1;
}


int
bci_layer_path(char *out, size_t outlen, const char *prefix,
               const brix_oci_digest_t *dig)
{
    int n = snprintf(out, outlen, "%s/.layers/%s/%s", bci_pfx(prefix),
                     brix_oci_alg_name(dig->alg), dig->hex);

    return n >= 0 && (size_t) n < outlen ? ING_OK
        : bci_fail(ING_FAIL, "layer path too long", dig->hex);
}


/* The third field of a ledger line, NUL-terminated in place; NULL when the
 * line is malformed or the field is the "-" that means "not captured". */
static char *
lay_line_diffid(char *line)
{
    char *p = strchr(line, ' ');           /* past <prefix>  */

    p = p != NULL ? strchr(p + 1, ' ') : NULL;   /* past <digest> */
    if (p == NULL) {
        return NULL;
    }
    p++;
    char *end = strchr(p, ' ');
    if (end != NULL) {
        *end = '\0';
    }
    return p[0] == '-' && p[1] == '\0' ? NULL : p;
}


int
bci_layer_known(const char *repo, const char *prefix, ing_layer_t *l)
{
    char path[ING_PATH_MAX], line[LAY_LINE_MAX], *diffid;

    l->diffid[0] = '\0';
    if (lay_ledger_path(path, sizeof(path), repo, "layers", prefix,
                        l->dig.hex) != 0
        || bci_read_line(path, line, sizeof(line)) != 0)
    {
        return 0;
    }
    diffid = lay_line_diffid(line);
    if (diffid != NULL) {
        snprintf(l->diffid, sizeof(l->diffid), "%s", diffid);
    }
    return 1;
}


int
bci_layer_stage(const char *repo, const char *prefix, const char *upper,
                const char *digest, int need_diffid, ing_layer_t *out,
                char *updir, size_t updirlen)
{
    char rel[ING_PATH_MAX];

    memset(out, 0, sizeof(*out));
    if (brix_oci_digest_parse(digest, strlen(digest), &out->dig) != 0) {
        return bci_fail(ING_FAIL, "manifest layer with an unusable digest",
                        digest);
    }
    /* A published layer whose ledger entry carries no diff_id predates
     * --verify-diffids; materializing it is the only way to obtain one, and
     * a flag that verified nothing would be worse than the cost. */
    out->reused = bci_layer_known(repo, prefix, out)
                  && (!need_diffid || out->diffid[0] != '\0');

    if (snprintf(rel, sizeof(rel), "%s/.layers/%s/%s", upper,
                 brix_oci_alg_name(out->dig.alg), out->dig.hex)
            >= (int) sizeof(rel)
        || snprintf(updir, updirlen, "%s", rel) >= (int) updirlen)
    {
        return bci_fail(ING_FAIL, "layer scratch path too long", out->dig.hex);
    }
    if (out->reused) {
        return ING_OK;                   /* nothing enters the upper tree */
    }
    return bci_mkdir_p(updir, 0755) == 0 ? ING_OK
        : bci_fail(ING_FAIL, "cannot create layer scratch", updir);
}


void
bci_layer_record(const char *repo, const char *prefix, const ing_layer_t *v,
                 int n, long rev)
{
    char path[ING_PATH_MAX], line[LAY_LINE_MAX], utc[40], digest[BRIX_OCI_DIGEST_STRLEN];

    bci_utc_now(utc, sizeof(utc));
    for (int i = 0; i < n; i++) {
        if (v[i].reused) {
            continue;                    /* the ledger entry is why it was */
        }
        if (lay_ledger_path(path, sizeof(path), repo, "layers", prefix,
                            v[i].dig.hex) != 0
            || brix_oci_digest_format(&v[i].dig, digest, sizeof(digest)) < 0)
        {
            continue;
        }
        snprintf(line, sizeof(line), "%s %s %s %ld %s\n", prefix, digest,
                 v[i].diffid[0] != '\0' ? v[i].diffid : "-", rev, utc);
        if (bci_write_atomic(path, line) != 0) {
            fprintf(stderr, "brixcvmfs ingest: warning: cannot write layer"
                    " ledger %s\n", path);
        }
    }
}


void
bci_imglayers_record(const char *repo, const char *prefix,
                     const char *img_hex, const ing_layer_t *v, int n)
{
    char  path[ING_PATH_MAX];
    char *body;
    size_t off = 0, cap = (size_t) n * (BRIX_OCI_HEXLEN_MAX + 1) + 1;

    if (lay_ledger_path(path, sizeof(path), repo, "imglayers", prefix,
                        img_hex) != 0 || (body = malloc(cap)) == NULL) {
        return;
    }
    for (int i = 0; i < n; i++) {
        off += (size_t) snprintf(body + off, cap - off, "%s\n", v[i].dig.hex);
    }
    body[off] = '\0';
    if (bci_write_atomic(path, body) != 0) {
        fprintf(stderr, "brixcvmfs ingest: warning: cannot write image layer"
                " list %s\n", path);
    }
    free(body);
}


int
bci_layers_sidecar(const char *root_abs, const char *root_rel,
                   const ing_layer_t *v, int n)
{
    char   path[ING_PATH_MAX + 16], up[ING_PATH_MAX];
    size_t off = 0;
    FILE  *f;

    /* One "../" per component of the image root, so the descriptor reads the
     * same from a Stratum-0 tree and from a client mount. */
    for (const char *p = root_rel; *p != '\0'; p++) {
        if (p[0] == '/' && p[1] != '\0') {
            off += 3;
        }
    }
    off += 3;                            /* the last component itself */
    if (off >= sizeof(up)) {
        return bci_fail(ING_FAIL, "image root too deep for a descriptor",
                        root_rel);
    }
    memset(up, 0, off + 1);
    for (size_t i = 0; i < off; i += 3) {
        memcpy(up + i, "../", 3);
    }

    if (snprintf(path, sizeof(path), "%s/.layers", root_abs)
            >= (int) sizeof(path)
        || (f = fopen(path, "w")) == NULL)
    {
        return bci_fail(ING_FAIL, "cannot write layers descriptor", root_abs);
    }
    for (int i = 0; i < n; i++) {
        fprintf(f, "%s.layers/%s/%s\n", up, brix_oci_alg_name(v[i].dig.alg),
                v[i].dig.hex);
    }
    return fclose(f) == 0 ? ING_OK
        : bci_fail(ING_FAIL, "cannot write layers descriptor", path);
}


/* ---- prune: the layer roots nothing composes any more ---------------------- */

/* Does any surviving image list this layer? The imglayers records are the
 * only place that knows, which is why prune removes an image's record only
 * after the publish that removed the image itself. */
static int
lay_referenced(const char *dir, const char *hex)
{
    char  path[ING_PATH_MAX + 160], line[BRIX_OCI_HEXLEN_MAX + 8];
    DIR  *d = opendir(dir);
    struct dirent *e;
    int   found = 0;

    if (d == NULL) {
        return 0;
    }
    while (!found && (e = readdir(d)) != NULL) {
        FILE *f;
        if (e->d_name[0] == '.'
            || snprintf(path, sizeof(path), "%s/%s", dir, e->d_name)
                   >= (int) sizeof(path)
            || (f = fopen(path, "r")) == NULL)
        {
            continue;
        }
        while (!found && fgets(line, sizeof(line), f) != NULL) {
            line[strcspn(line, "\r\n")] = '\0';
            found = strcmp(line, hex) == 0;
        }
        fclose(f);
    }
    closedir(d);
    return found;
}


int
bci_layer_orphans(const char *repo, const char *prefix, cvmfs_changeset_t *cs,
                  char ***out_hex)
{
    char  ledger[ING_PATH_MAX], imgdir[ING_PATH_MAX], path[ING_PATH_MAX];
    char **victims = NULL;
    int    n = 0;
    DIR   *d;
    struct dirent *e;

    *out_hex = NULL;
    if (lay_ledger_path(ledger, sizeof(ledger), repo, "layers", prefix, "") != 0
        || lay_ledger_path(imgdir, sizeof(imgdir), repo, "imglayers", prefix,
                           "") != 0
        || (d = opendir(ledger)) == NULL)
    {
        return 0;                        /* nothing layered was ever published */
    }
    while ((e = readdir(d)) != NULL) {
        brix_oci_digest_t dig;
        cvmfs_change_t   *ch;
        char            **grown;

        /* A ledger name is a bare hex whose width names its algorithm; a
         * name that is not one is not this tool's to delete. */
        if (brix_oci_digest_parse_hex(e->d_name, strlen(e->d_name), &dig) != 0
            || lay_referenced(imgdir, e->d_name)
            || bci_layer_path(path, sizeof(path), prefix, &dig) != ING_OK)
        {
            continue;
        }
        ch = bci_cs_append(cs);
        grown = realloc(victims, (size_t) (n + 1) * sizeof(*victims));
        if (grown != NULL) {
            victims = grown;             /* the old block is dangling now */
            victims[n] = NULL;
        }
        if (ch == NULL || grown == NULL
            || (ch->path = strdup(path)) == NULL
            || (victims[n] = strdup(e->d_name)) == NULL)
        {
            closedir(d);
            while (n-- > 0) {
                free(victims[n]);        /* the ledger stays: nothing was published */
            }
            free(victims);
            bci_fail(ING_FAIL, "out of memory", NULL);
            return -1;
        }
        ch->op = CVMFS_CH_DELETE;
        n++;
    }
    closedir(d);
    *out_hex = victims;
    return n;
}


void
bci_layer_forget(const char *repo, const char *prefix, char **hex, int n)
{
    char path[ING_PATH_MAX];

    for (int i = 0; i < n; i++) {
        if (lay_ledger_path(path, sizeof(path), repo, "layers", prefix,
                            hex[i]) == 0) {
            unlink(path);
        }
    }
    bci_layer_release(hex, n);
}


void
bci_layer_release(char **hex, int n)
{
    for (int i = 0; i < n; i++) {
        free(hex[i]);
    }
    free(hex);
}
