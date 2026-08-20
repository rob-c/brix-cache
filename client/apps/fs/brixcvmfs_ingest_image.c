/* brixcvmfs_ingest_image.c — `brixcvmfs ingest image <ref>` (phase-104 D8):
 * pull → flatten → publish, incrementally. Tool surface only (G14).
 *
 *   brixcvmfs ingest image <ref> --repo <repo_dir> [--prefix /images]
 *       [--platform os/arch] [--tag-path name:tag-dir] [--squash-owner U:G]
 *       [--strict] [--max-bytes N] [--keys-dir D] [--chunk-size N]
 *       [--insecure] [--token-file F] [--prune-old] [--force-overlap]
 *       [--verify-diffids] [--layout flat|layered] [--dry-run] [--no-wait]
 *
 * Published namespace (the DUCC-compatible flat layout, D8.2):
 *   <prefix>/.images/<alg>/<manifest-hex>/            the rootfs
 *   <prefix>/.images/<alg>/<manifest-hex>/.config.json    image config
 *   <prefix>/.images/<alg>/<manifest-hex>/.manifest.json  manifest, verbatim
 *   <prefix>/<host>/<name>:<tag>  → relative symlink → the digest root
 *
 * --layout layered (D15.6) publishes each layer at its own content-addressed
 * root instead of merging them:
 *   <prefix>/.layers/<alg>/<layer-hex>/       one layer, verbatim
 *   <prefix>/.images/<alg>/<manifest-hex>/.layers   the composition, in order
 * A published layer is never fetched, decompressed or scanned again, so the
 * second image off a shared base costs only its own top layers. The image root
 * stops being a runnable rootfs there — composing the layer roots (overlayfs
 * lowerdirs, lowest last) becomes the consumer's job — which is why this is a
 * flag and flat stays the default.
 *
 * Pipeline: resolve → memo check (<repo>/.brix-ingest/memo<flat-path>; same
 * manifest digest = no-op) → take the transaction lock → fetch layers
 * hash-on-stream → flatten (D7) into a scratch upper → sidecars + tag
 * symlink → scan + reprefix → publish → memo/ledger write. A crash
 * pre-publish leaves only scratch (reaped on the next run); the publish
 * engine's manifest-swap-last gives crash-safety for step 7 for free.
 *
 * --verify-diffids (D8.e): the layer blob digests are verified on fetch (that
 * is the transport identity); the image *config* additionally names each
 * layer's diff_id — the sha256 of the UNCOMPRESSED tar. The flattener already
 * decompresses, so capturing that hash costs no second inflate; the compare
 * happens once the config sidecar is in hand and catches a registry whose
 * manifest and config disagree about which bytes the image is made of.
 *
 * Foreign-path safety: every structural ADD outside the image's own digest
 * root carries no_clobber, so a published non-dir at <prefix>/<host>/… fails
 * the publish instead of being silently retyped (--force-overlap lifts it).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "brixcvmfs_ingest_internal.h"
#include "cvmfs/publish/publish.h"
#include "oci/flatten.h"
#include "oci/reg_client.h"
#include "core/compat/json_iter.h"
#include "core/compat/json_min.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    const char *ref_text, *repo, *keys_dir, *platform, *tag_path, *token_file;
    char        prefix[ING_PATH_MAX];   /* normalized: no trailing '/' */
    long        chunk_size;
    long long   max_bytes;
    unsigned    squash_uid, squash_gid;
    int         squash, strict, dry_run, no_wait, insecure;
    int         prune_old, force_overlap, verify_diffids, layered;
    int         require_digest;         /* refuse a ref that is not pinned */
} ing_img_opts_t;


typedef struct {
    const ing_img_opts_t *o;
    brix_oci_reg_t   reg;
    brix_oci_ref_t   ref;
    brix_oci_desc_t  desc;              /* resolved manifest */
    char             name[256];         /* effective repository name */
    brix_oci_digest_t dig;              /* desc.digest, parsed */
    const char      *hex;               /* dig.hex — the bare manifest hex */
    char             tagrel[ING_PATH_MAX];    /* "<host>/<name>:<tag>" */
    char             flat_path[ING_PATH_MAX]; /* <prefix>/<tagrel> */
    char             root_rel[BRIX_OCI_HEXLEN_MAX + 32];
                                       /* ".images/<alg>/<hex>" */
    char             root_path[ING_PATH_MAX]; /* <prefix>/<root_rel> */
    char             scratch[ING_PATH_MAX], upper[ING_PATH_MAX];
    char             root_abs[ING_PATH_MAX];  /* <upper>/<root_rel> */
    char             memo_path[ING_PATH_MAX];
    char             old_digest[BRIX_OCI_DIGEST_STRLEN];
                                       /* previous memo digest, "" = none */
    int              pruned_old;
    ing_diffid_t    *diffids;           /* --verify-diffids: one per layer */
    int              ndiffids;
    ing_layer_t     *layers;            /* --layout layered: one per layer */
    int              nlayers;
    char             layers_path[ING_PATH_MAX]; /* <prefix>/.layers */
    brix_flatten_stats_t st;
} ing_img_ctx_t;

static const char *img_pfx(const ing_img_ctx_t *c) {
    return bci_pfx(c->o->prefix);
}

static int img_path(char *out, size_t outlen, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out, outlen, fmt, ap);
    va_end(ap);
    return n >= 0 && (size_t) n < outlen
        ? ING_OK : bci_fail(ING_FAIL, "path too long", out);
}

static int img_map(int reg_rc, const char *what, const char *err) {
    int code = reg_rc == BRIX_OCI_REG_EAUTH      ? ING_AUTH
             : reg_rc == BRIX_OCI_REG_ENOTFOUND ? ING_NOTFOUND
             : reg_rc == BRIX_OCI_REG_EVERIFY   ? ING_FAIL
             : ING_TRANSPORT;
    return bci_fail(code, what, err);
}

/* ---- argv ----------------------------------------------------------------- */

static int img_usage(void) {
    fprintf(stderr,
        "usage: brixcvmfs ingest image <ref> --repo <repo_dir>"
        " [--prefix /images]\n"
        "       [--platform os/arch] [--tag-path name:tag-dir]"
        " [--squash-owner U:G]\n"
        "       [--strict] [--max-bytes N] [--keys-dir D] [--chunk-size N]\n"
        "       [--insecure] [--token-file F] [--prune-old]"
        " [--force-overlap]\n"
        "       [--verify-diffids] [--require-digest]"
        " [--layout flat|layered]\n"
        "       [--dry-run] [--no-wait]\n");
    return ING_USAGE;
}

static int img_parse_flag(ing_img_opts_t *o, const char *a) {
    if      (strcmp(a, "--strict") == 0)        o->strict = 1;
    else if (strcmp(a, "--dry-run") == 0)       o->dry_run = 1;
    else if (strcmp(a, "--no-wait") == 0)       o->no_wait = 1;
    else if (strcmp(a, "--insecure") == 0)      o->insecure = 1;
    else if (strcmp(a, "--prune-old") == 0)     o->prune_old = 1;
    else if (strcmp(a, "--force-overlap") == 0) o->force_overlap = 1;
    else if (strcmp(a, "--verify-diffids") == 0) o->verify_diffids = 1;
    else if (strcmp(a, "--require-digest") == 0) o->require_digest = 1;
    else return -1;
    return 0;
}

/* The options whose value is kept verbatim; split out so the parser that has
 * to interpret its value stays inside the complexity budget. */
static int img_parse_str(ing_img_opts_t *o, const char *a, const char *v) {
    if      (strcmp(a, "--repo") == 0)       o->repo = v;
    else if (strcmp(a, "--platform") == 0)   o->platform = v;
    else if (strcmp(a, "--tag-path") == 0)   o->tag_path = v;
    else if (strcmp(a, "--keys-dir") == 0)   o->keys_dir = v;
    else if (strcmp(a, "--token-file") == 0) o->token_file = v;
    else return -1;
    return 0;
}

static int img_parse_val(ing_img_opts_t *o, const char *a, const char *v) {
    if      (img_parse_str(o, a, v) == 0)    return 0;
    else if (strcmp(a, "--chunk-size") == 0) o->chunk_size = atol(v);
    else if (strcmp(a, "--max-bytes") == 0)  o->max_bytes = atoll(v);
    else if (strcmp(a, "--layout") == 0) {
        if (strcmp(v, "layered") != 0 && strcmp(v, "flat") != 0) return -1;
        o->layered = strcmp(v, "layered") == 0;
    }
    else if (strcmp(a, "--prefix") == 0) {
        size_t n = snprintf(o->prefix, sizeof(o->prefix), "%s", v);
        if (n >= sizeof(o->prefix)) return -1;
        while (n > 1 && o->prefix[n - 1] == '/') o->prefix[--n] = '\0';
    } else if (strcmp(a, "--squash-owner") == 0) {
        if (sscanf(v, "%u:%u", &o->squash_uid, &o->squash_gid) != 2) return -1;
        o->squash = 1;
    } else
        return -1;
    return 0;
}

static int img_parse(int argc, char **argv, ing_img_opts_t *o) {
    memset(o, 0, sizeof(*o));
    snprintf(o->prefix, sizeof(o->prefix), "/images");
    if (argc < 2 || argv[1][0] == '-') return img_usage();
    o->ref_text = argv[1];
    for (int i = 2; i < argc; i++) {
        if (img_parse_flag(o, argv[i]) == 0) continue;
        if (i + 1 < argc && img_parse_val(o, argv[i], argv[i + 1]) == 0) {
            i++;
            continue;
        }
        return img_usage();
    }
    return o->repo != NULL ? ING_OK : img_usage();
}

/* ---- step 1: resolve ------------------------------------------------------ */

/* --require-digest (App. L): the digest chain below proves the tree matches
 * the manifest we RESOLVED, never that the manifest is the one the operator
 * meant — a tag can be repointed between two runs. Only the operator knows
 * which this ingest is, so it is a flag, and it fires before the first
 * network byte. */
static int img_resolve(ing_img_ctx_t *c) {
    char err[512];
    if (brix_oci_ref_parse(c->o->ref_text, &c->ref, err, sizeof(err)) != 0)
        return bci_fail(ING_USAGE, "bad image ref", err);
    if (c->o->require_digest && !c->ref.has_digest)
        return bci_fail(ING_USAGE,
                        "--require-digest: ref is not digest-pinned "
                        "(write <name>@sha256:<hex>)", c->o->ref_text);
    int rc = brix_oci_reg_from_ref(&c->reg, &c->ref, c->o->insecure,
                                   c->name, sizeof(c->name), err, sizeof(err));
    if (rc != 0) return img_map(rc, "registry setup failed", err);
    if (c->o->token_file != NULL
        && bci_read_line(c->o->token_file, c->reg.bearer,
                         sizeof(c->reg.bearer)) != 0)
        return bci_fail(ING_USAGE, "cannot read --token-file", c->o->token_file);
    rc = brix_oci_reg_resolve(&c->reg, &c->ref, c->o->platform, &c->desc,
                              err, sizeof(err));
    if (rc != 0) return img_map(rc, "manifest resolve failed", err);
    /* The resolved descriptor names its own algorithm; the on-disk tree is
     * keyed by it, so read it out of the grammar rather than stepping over a
     * prefix whose length is only incidentally the same for both. */
    if (brix_oci_digest_parse(c->desc.digest, strlen(c->desc.digest),
                              &c->dig) != 0)
        return bci_fail(ING_FAIL, "registry returned an unusable digest",
                        c->desc.digest);
    c->hex = c->dig.hex;
    return ING_OK;
}

static int img_paths(ing_img_ctx_t *c) {
    const char *host = c->ref.host[0] != '\0' ? c->ref.host : "docker.io";
    int rc = c->o->tag_path != NULL
        ? img_path(c->tagrel, sizeof(c->tagrel), "%s", c->o->tag_path)
        : img_path(c->tagrel, sizeof(c->tagrel), "%s/%s:%s",
                   host, c->name, c->ref.tag);
    if (rc != ING_OK) return rc;
    char probe[ING_PATH_MAX + 1];       /* tagrel gets the prefix grammar */
    if (img_path(probe, sizeof(probe), "/%s", c->tagrel) != ING_OK
        || bci_prefix_check(probe) != ING_OK)
        return bci_fail(ING_USAGE, "bad tag path", c->tagrel);
    rc = img_path(c->root_rel, sizeof(c->root_rel),
                  ".images/%s/%s", brix_oci_alg_name(c->dig.alg), c->hex);
    if (rc == ING_OK)
        rc = img_path(c->root_path, sizeof(c->root_path), "%s/%s",
                      img_pfx(c), c->root_rel);
    if (rc == ING_OK)
        rc = img_path(c->flat_path, sizeof(c->flat_path), "%s/%s",
                      img_pfx(c), c->tagrel);
    if (rc == ING_OK)
        rc = img_path(c->scratch, sizeof(c->scratch),
                      "%s/.brix-ingest/scratch", c->o->repo);
    if (rc == ING_OK)
        rc = img_path(c->upper, sizeof(c->upper), "%s/upper", c->scratch);
    if (rc == ING_OK)
        rc = img_path(c->root_abs, sizeof(c->root_abs), "%s/%s",
                      c->upper, c->root_rel);
    if (rc == ING_OK)
        rc = img_path(c->layers_path, sizeof(c->layers_path), "%s/.layers",
                      img_pfx(c));
    if (rc == ING_OK)
        rc = img_path(c->memo_path, sizeof(c->memo_path),
                      "%s/.brix-ingest/memo%s", c->o->repo, c->flat_path);
    return rc;
}

/* ---- step 2: memo --------------------------------------------------------- */

/* Reads the memo (capturing the previous digest for --prune-old); 1 = the
 * published content is already this manifest — the incremental no-op. */
static int img_memo_fresh(ing_img_ctx_t *c) {
    char line[ING_PATH_MAX + 128];
    if (bci_read_line(c->memo_path, line, sizeof(line)) != 0) return 0;
    char *dig = bci_memo_digest(line);
    if (dig == NULL) return 0;
    snprintf(c->old_digest, sizeof(c->old_digest), "%s", dig);
    return strcmp(dig, c->desc.digest) == 0;
}

/* ---- steps 3+4: fetch + flatten each layer -------------------------------- */

typedef int (*img_layer_cb)(ing_img_ctx_t *c, int idx, const char *digest);

static int img_layers_foreach(ing_img_ctx_t *c, img_layer_cb cb, int *out_n) {
    const char *arr, *el;
    size_t an, en, cur = 0;
    if (brix_json_get_raw(c->desc.body, c->desc.body_len, "layers",
                          &arr, &an) != 1)
        return bci_fail(ING_FAIL, "manifest has no layers array", NULL);
    int idx = 0, st;
    while ((st = brix_json_arr_next(arr, an, &cur, &el, &en)) == 1) {
        char dig[BRIX_OCI_DIGEST_STRLEN];
        if (brix_json_get_str(el, en, "digest", dig, sizeof(dig)) != 1)
            return bci_fail(ING_FAIL, "manifest layer without digest", NULL);
        if (cb != NULL) {
            int rc = cb(c, idx, dig);
            if (rc != ING_OK) return rc;
        }
        idx++;
    }
    if (st < 0)
        return bci_fail(ING_FAIL, "malformed manifest layers array", NULL);
    if (out_n != NULL) *out_n = idx;
    return ING_OK;
}

static int img_layer_apply(ing_img_ctx_t *c, int idx, const char *digest) {
    char lpath[ING_PATH_MAX + 32], err[512], updir[ING_PATH_MAX];
    const char *upper_dir = c->root_abs;
    if (c->o->layered) {
        int st = bci_layer_stage(c->o->repo, c->o->prefix, c->upper, digest,
                                 c->o->verify_diffids, &c->layers[idx],
                                 updir, sizeof(updir));
        if (st != ING_OK) return st;
        if (c->layers[idx].reused) {
            /* --verify-diffids still has to have something to compare: the
             * ledger recorded it when the layer was first materialized. */
            snprintf(c->diffids[idx], sizeof(c->diffids[idx]), "%s",
                     c->layers[idx].diffid);
            return ING_OK;
        }
        upper_dir = updir;
    }
    snprintf(lpath, sizeof(lpath), "%s/layer.%d", c->scratch, idx);
    int fd = open(lpath, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return bci_fail(ING_FAIL, "cannot create layer temp", lpath);
    int rc = brix_oci_reg_blob_fetch(&c->reg, c->name, digest, fd,
                                     err, sizeof(err));
    if (rc != 0) {
        close(fd);
        unlink(lpath);
        return img_map(rc, "layer fetch failed", err);
    }
    brix_flatten_opts_t fo;
    memset(&fo, 0, sizeof(fo));
    fo.upper_dir = upper_dir;
    fo.strict = c->o->strict;
    fo.max_total_bytes = c->o->max_bytes;
    fo.squash = c->o->squash;
    fo.squash_uid = (uid_t) c->o->squash_uid;
    fo.squash_gid = (gid_t) c->o->squash_gid;
    if (c->diffids != NULL && idx < c->ndiffids) {
        fo.diffid_hex    = c->diffids[idx];
        fo.diffid_hexlen = sizeof(c->diffids[idx]);
    }
    rc = lseek(fd, 0, SEEK_SET) == 0
         && brix_flatten_layer(&fo, fd, &c->st, err, sizeof(err)) == 0
         ? ING_OK : bci_fail(ING_FAIL, "layer refused", err);
    close(fd);
    unlink(lpath);
    if (rc == ING_OK && c->layers != NULL && c->diffids != NULL)
        snprintf(c->layers[idx].diffid, sizeof(c->layers[idx].diffid), "%s",
                 c->diffids[idx]);
    return rc;
}

/* ---- step 5: sidecars + tag symlink --------------------------------------- */

static int img_sidecars(ing_img_ctx_t *c) {
    char dig[BRIX_OCI_DIGEST_STRLEN], path[ING_PATH_MAX + 32], err[512];
    const char *cel;
    size_t cen;
    if (brix_json_get_raw(c->desc.body, c->desc.body_len, "config",
                          &cel, &cen) != 1
        || brix_json_get_str(cel, cen, "digest", dig, sizeof(dig)) != 1)
        return bci_fail(ING_FAIL, "manifest has no config digest", NULL);
    snprintf(path, sizeof(path), "%s/.config.json", c->root_abs);
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return bci_fail(ING_FAIL, "cannot create config sidecar", path);
    int rc = brix_oci_reg_blob_fetch(&c->reg, c->name, dig, fd,
                                     err, sizeof(err));
    close(fd);
    if (rc != 0) {
        unlink(path);
        return img_map(rc, "config fetch failed", err);
    }
    snprintf(path, sizeof(path), "%s/.manifest.json", c->root_abs);
    FILE *f = fopen(path, "w");
    int ok = f != NULL
          && fwrite(c->desc.body, 1, c->desc.body_len, f) == c->desc.body_len;
    if (f != NULL) ok = fclose(f) == 0 && ok;
    if (!ok)
        return bci_fail(ING_FAIL, "cannot write manifest sidecar", path);
    return c->o->layered
        ? bci_layers_sidecar(c->root_abs, c->root_rel, c->layers, c->nlayers)
        : ING_OK;
}

/* --verify-diffids: hand the captured hashes and the config sidecar we just
 * fetched to the comparator (brixcvmfs_ingest_diffid.c). */
static int img_verify(ing_img_ctx_t *c) {
    char path[ING_PATH_MAX + 32];

    if (!c->o->verify_diffids)
        return ING_OK;
    if (img_path(path, sizeof(path), "%s/.config.json", c->root_abs) != ING_OK)
        return ING_FAIL;
    return bci_diffids_verify(path, c->diffids, c->ndiffids);
}

/* ---- steps 6+7: scan, guard, publish -------------------------------------- */

/* Structural entries (everything outside the image's own digest root) must
 * not retype foreign published content — see the header comment. */
static int img_own(const char *path, const char *root) {
    size_t n = strlen(root);
    return strncmp(path, root, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

/* The layer namespace is this tool's own too: two images sharing a base both
 * ADD the same layer root, and no_clobber there would turn a correct second
 * publish into a refusal. */
static void img_guard_structural(ing_img_ctx_t *c, cvmfs_changeset_t *cs) {
    for (size_t i = 0; i < cs->n; i++) {
        cvmfs_change_t *ch = &cs->v[i];
        if (img_own(ch->path, c->root_path)
            || (c->o->layered && img_own(ch->path, c->layers_path)))
            continue;
        if (c->o->force_overlap)
            ch->no_clobber = 0;
        else if (ch->op == CVMFS_CH_ADD_DIR || ch->op == CVMFS_CH_ADD_LINK)
            ch->no_clobber = 1;
    }
}

/* Step 8: memo + roots ledger — advisory state, so failures warn, never
 * roll back a publish that already happened. */
static void img_record(ing_img_ctx_t *c, long rev) {
    char utc[40], line[2 * ING_PATH_MAX], lpath[ING_PATH_MAX + 96];
    bci_utc_now(utc, sizeof(utc));
    snprintf(line, sizeof(line), "%s %s %ld %s\n",
             c->flat_path, c->desc.digest, rev, utc);
    if (bci_write_atomic(c->memo_path, line) != 0)
        fprintf(stderr, "brixcvmfs ingest: warning: cannot write memo %s\n",
                c->memo_path);
    snprintf(lpath, sizeof(lpath), "%s/.brix-ingest/roots%s/%s",
             c->o->repo, img_pfx(c), c->hex);
    snprintf(line, sizeof(line), "%s %s %ld %s\n",
             c->o->prefix, c->desc.digest, rev, utc);
    if (bci_write_atomic(lpath, line) != 0)
        fprintf(stderr, "brixcvmfs ingest: warning: cannot write ledger %s\n",
                lpath);
    if (c->o->layered) {
        bci_layer_record(c->o->repo, c->o->prefix, c->layers, c->nlayers, rev);
        bci_imglayers_record(c->o->repo, c->o->prefix, c->hex, c->layers,
                             c->nlayers);
    }
    if (c->pruned_old)
        bci_root_forget(c->o->repo, c->o->prefix, c->old_digest);
}

static int img_publish(ing_img_ctx_t *c, int nlayers) {
    cvmfs_changeset_t cs;
    char err[1024];
    long rev = 0;
    if (cvmfs_changeset_scan(c->upper, &cs, err, sizeof(err)) != 0)
        return bci_fail(ING_FAIL, "scratch scan failed", err);
    int rc = cvmfs_changeset_reprefix(&cs, c->o->prefix, err, sizeof(err)) == 0
             ? ING_OK : bci_fail(ING_FAIL, "prefix remap failed", err);
    if (rc == ING_OK) {
        img_guard_structural(c, &cs);
        int marked = c->o->prune_old
            ? bci_prune_old_mark(c->o->repo, c->o->prefix, c->memo_path,
                                 c->old_digest, c->desc.digest, &cs) : 0;
        rc = marked < 0 ? ING_FAIL : ING_OK;
        c->pruned_old = marked == 1;
    }
    size_t nch = cs.n;
    if (rc == ING_OK) {
        cvmfs_publish_opts_t po;
        memset(&po, 0, sizeof(po));
        po.repo_dir = c->o->repo;
        po.keys_dir = c->o->keys_dir;
        po.chunk_size = c->o->chunk_size;
        rc = cvmfs_publish_run(&po, &cs, &rev, err, sizeof(err)) == 0
             ? ING_OK : bci_fail(ING_FAIL, "publish failed", err);
    }
    cvmfs_changeset_free(&cs);
    if (rc != ING_OK) return rc;
    img_record(c, rev);
    printf("ingested %s -> %s (revision %ld, %d layers, %zu changes,"
           " %lld files, %lld bytes)%s\n",
           c->o->ref_text, c->flat_path, rev, nlayers, nch,
           (long long) c->st.files, (long long) c->st.bytes,
           c->pruned_old ? " [pruned old root]" : "");
    return ING_OK;
}

/* ---- conductor ------------------------------------------------------------ */

static int img_dry_run(ing_img_ctx_t *c) {
    int n = 0;
    int rc = img_layers_foreach(c, NULL, &n);
    if (rc != ING_OK) return rc;
    printf("dry-run: %s\n  manifest: %s (%d layers)\n"
           "  root: %s\n  tag:  %s -> %s\n",
           c->o->ref_text, c->desc.digest, n,
           c->root_path, c->flat_path, c->root_rel);
    return ING_OK;
}

/* 1 = some other tag under THIS prefix already published this manifest's
 * digest root (memos are written only after a successful publish) — a retag
 * needs no layer bytes, only the tag symlink. */
static int img_root_published(ing_img_ctx_t *c) {
    char memo_dir[ING_PATH_MAX + 32];
    snprintf(memo_dir, sizeof(memo_dir), "%s/.brix-ingest/memo%s",
             c->o->repo, img_pfx(c));
    return bci_memo_refs(memo_dir, c->desc.digest, c->memo_path) > 0;
}

/* Per-layer bookkeeping needs a slot per layer before the apply loop runs, so
 * the manifest is walked once for the count. --verify-diffids wants the
 * captured hashes; --layout layered wants the digests, and takes the diff_id
 * capture with it because the flattener decompresses anyway and a recorded
 * diff_id is what lets a REUSED layer still be verified on a later run. With
 * neither flag nothing is allocated and both stay off end to end. */
static int img_layers_alloc(ing_img_ctx_t *c) {
    int n = 0, rc;

    if (!c->o->verify_diffids && !c->o->layered)
        return ING_OK;
    rc = img_layers_foreach(c, NULL, &n);
    if (rc != ING_OK)
        return rc;
    if (n <= 0)
        return bci_fail(ING_FAIL, "manifest has no layers", NULL);
    c->diffids = calloc((size_t) n, sizeof(*c->diffids));
    if (c->diffids == NULL)
        return bci_fail(ING_FAIL, "out of memory", NULL);
    c->ndiffids = n;
    if (c->o->layered
        && (c->layers = calloc((size_t) n, sizeof(*c->layers))) == NULL)
        return bci_fail(ING_FAIL, "out of memory", NULL);
    c->nlayers = c->o->layered ? n : 0;
    return ING_OK;
}

static int img_locked(ing_img_ctx_t *c) {
    int nlayers = 0;
    if (brixcvmfs_tx_rm_tree(c->scratch) != 0)
        return bci_fail(ING_FAIL, "cannot reap stale scratch", c->scratch);
    int rc = ING_OK;
    if (img_root_published(c)) {
        /* symlink-only upper: bci_tag_symlink creates the chain */
        rc = bci_mkdir_p(c->upper, 0755) == 0
             ? ING_OK : bci_fail(ING_FAIL, "cannot create scratch tree", c->upper);
    } else {
        if (bci_mkdir_p(c->root_abs, 0755) != 0)
            return bci_fail(ING_FAIL, "cannot create scratch tree", c->root_abs);
        rc = img_layers_alloc(c);
        if (rc == ING_OK) rc = img_layers_foreach(c, img_layer_apply, &nlayers);
        if (rc == ING_OK) rc = img_sidecars(c);
        if (rc == ING_OK) rc = img_verify(c);
    }
    if (rc == ING_OK) rc = bci_tag_symlink(c->upper, c->tagrel, c->root_rel);
    if (rc == ING_OK) rc = img_publish(c, nlayers);
    if (rc == ING_OK) brixcvmfs_tx_rm_tree(c->scratch);
    /* on failure scratch stays for forensics; the next run reaps it */
    return rc;
}

int bci_image_main(int argc, char **argv) {
    ing_img_opts_t o;
    ing_img_ctx_t c;
    int rc = img_parse(argc, argv, &o);
    if (rc != ING_OK) return rc;
    rc = bci_prefix_check(o.prefix);
    if (rc != ING_OK) return rc;
    memset(&c, 0, sizeof(c));
    c.o = &o;
    rc = img_resolve(&c);
    if (rc == ING_OK) rc = img_paths(&c);
    if (rc == ING_OK && img_memo_fresh(&c)) {
        printf("up to date: %s at %s\n", c.flat_path, c.desc.digest);
    } else if (rc == ING_OK && o.dry_run) {
        rc = img_dry_run(&c);
    } else if (rc == ING_OK) {
        rc = bci_lock_acquire(o.repo, o.no_wait);
        if (rc == ING_OK) {
            rc = img_locked(&c);
            bci_lock_release(o.repo);
        }
    }
    brix_oci_desc_free(&c.desc);
    free(c.diffids);
    free(c.layers);
    return rc;
}

