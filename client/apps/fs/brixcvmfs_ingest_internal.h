/*
 * brixcvmfs_ingest_internal.h — seam of the `brixcvmfs ingest` conductor
 * (phase-104 D8/D9): the dir/image/prune verbs that turn a folder or an OCI
 * image into a Stratum-0 publish.
 *
 * WHAT: the ingest exit-code table, the small filesystem/lock helpers the
 *       ingest TUs share, and the per-verb entry points.
 * WHY:  ingest is five TUs under the file-size cap (brixcvmfs_ingest.c:
 *       dispatch + `dir` + helpers; _image.c: `image`; _prune.c: `prune`;
 *       _diffid.c: the config/diff_id comparator; _layout.c: the shape
 *       of the published namespace);
 *       the transaction-lock primitives stay owned by brixcvmfs_publish.c so
 *       `repo transaction` and `ingest` can never drift on lock discipline.
 * HOW:  pure tool surface (G14): no FUSE, no ngx, no root. Everything here
 *       is single-threaded CLI plumbing.
 */
#ifndef BRIXCVMFS_INGEST_INTERNAL_H
#define BRIXCVMFS_INGEST_INTERNAL_H

#include <stddef.h>

#include "cvmfs/publish/changeset.h"
#include "oci/digest.h"

/* Exit codes — the reg_client result codes mapped per the D5/D8 table. */
#define ING_OK        0
#define ING_USAGE     2
#define ING_AUTH      3
#define ING_NOTFOUND  4
#define ING_FAIL      5        /* verify / flatten / scan / publish refusal */
#define ING_TRANSPORT 6
#define ING_BUSY      7        /* --no-wait and the transaction lock is held */

#define ING_PATH_MAX  1024

/* ---- owned by brixcvmfs_publish.c (the phase-96 transaction plane) -------- */

int brixcvmfs_tx_lock_take(const char *lockpath);   /* O_EXCL; 0 / -1+errno */
int brixcvmfs_tx_lock_pid(const char *lockpath);    /* holder pid, 0 unknown */
int brixcvmfs_tx_lock_stale(const char *lockpath);  /* 1 = holder provably gone */
int brixcvmfs_tx_rm_tree(const char *path);         /* recursive; absent ok */

/* ---- owned by brixcvmfs_ingest.c ------------------------------------------ */

/* Print "brixcvmfs ingest: what[: detail]" to stderr and return code. */
int bci_fail(int code, const char *what, const char *detail);

int bci_mkdir_p(const char *path, unsigned mode);   /* parents included */

/* First line of `path` into buf (trimmed); 0 / -1 (absent or unreadable). */
int bci_read_line(const char *path, char *buf, size_t buflen);

/* Staged write: parents created, ".tmp" sibling + rename. 0 / -1. */
int bci_write_atomic(const char *path, const char *data);

void bci_utc_now(char *out, size_t outlen);         /* "2026-08-17T..Z" */

/* Take/release <repo>/.brixtxn/lock (creating .brixtxn). Waits for a held
 * lock unless no_wait (then ING_BUSY). ING_OK / ING_BUSY / ING_FAIL. */
int  bci_lock_acquire(const char *repo_dir, int no_wait);
void bci_lock_release(const char *repo_dir);

/* Parse-time --prefix validation (reprefix grammar over an empty set). */
int bci_prefix_check(const char *prefix);

/* Memo line "<flat-path> <digest> <rev> <utc>": NUL-terminate the digest
 * field in place and return it; NULL when malformed. */
char *bci_memo_digest(char *line);

/* Count memo files under memo_dir (recursive) whose digest field equals
 * digest, excluding the file at path skip ("" = none). */
int bci_memo_refs(const char *memo_dir, const char *digest, const char *skip);

/* "" when prefix is "/", so "%s/…" concatenation stays canonical. */
const char *bci_pfx(const char *prefix);

/* Grow-by-doubling append of a zeroed change; NULL on OOM. */
cvmfs_change_t *bci_cs_append(cvmfs_changeset_t *cs);

/* ---- owned by brixcvmfs_ingest_diffid.c ----------------------------------- */

/* One captured layer diff_id: sha256 hex + NUL. */
typedef char ing_diffid_t[BRIX_OCI_SHA256_HEXLEN + 1];

/* Compare `n` captured layer diff_ids against rootfs.diff_ids in the image
 * config at config_path (the sidecar ingest just fetched). ING_OK, or
 * ING_FAIL with the mismatching layer named on stderr. */
int bci_diffids_verify(const char *config_path, const ing_diffid_t *hex, int n);

/* ---- owned by brixcvmfs_ingest_layout.c ----------------------------------- */

/* "<upper>/<tagrel>" → a RELATIVE symlink to root_rel, its parent chain
 * created. Every layout ends the same way: the tag is a link, never a copy. */
int bci_tag_symlink(const char *upper, const char *tagrel,
                    const char *root_rel);

/* One layer of an image published under `--layout layered` (D15.6): its own
 * digest, the diff_id naming its uncompressed bytes, and whether this run
 * had to materialize it at all. A layer root is content-addressed, so an
 * image whose base is already published pays for nothing but its own top
 * layers — which is the entire point of the layout. */
typedef struct {
    brix_oci_digest_t dig;
    ing_diffid_t      diffid;    /* "" = not known */
    int               reused;    /* 1 = already published; not fetched */
} ing_layer_t;

/* "<pfx>/.layers/<alg>/<hex>" — where one layer's content is published. */
int bci_layer_path(char *out, size_t outlen, const char *prefix,
                   const brix_oci_digest_t *dig);

/* Is this layer already published under `prefix`? Fills l->diffid from the
 * ledger when it is. 1 = yes, 0 = no. */
int bci_layer_known(const char *repo, const char *prefix, ing_layer_t *l);

/* Decide whether one layer must be materialized, and where. `updir` gets
 * "<upper>/.layers/<alg>/<hex>", created when the layer has to be filled;
 * out->reused says the publish can skip the fetch entirely. need_diffid
 * forces a published layer to be materialized anyway when its ledger entry
 * predates --verify-diffids, so that flag can never silently verify nothing.
 * ING_OK / ING_FAIL. */
int bci_layer_stage(const char *repo, const char *prefix, const char *upper,
                    const char *digest, int need_diffid, ing_layer_t *out,
                    char *updir, size_t updirlen);

/* Ledger writes, advisory like the memo: a failure warns and never rolls
 * back a publish that already happened. */
void bci_layer_record(const char *repo, const char *prefix,
                      const ing_layer_t *v, int n, long rev);
void bci_imglayers_record(const char *repo, const char *prefix,
                          const char *img_hex, const ing_layer_t *v, int n);

/* The image root's `.layers` descriptor: the layer roots this image is
 * composed of, lowest first, one relative path per line. */
int bci_layers_sidecar(const char *root_abs, const char *root_rel,
                       const ing_layer_t *v, int n);

/* Layer roots under `prefix` that no surviving image's `imglayers` record
 * names. Appends one CVMFS_CH_DELETE per victim to `cs` and returns the
 * count, or -1 (message already printed). Dispose of the vector with
 * `bci_layer_forget` once the publish that removed them succeeded — it
 * unlinks their ledger entries — or with `bci_layer_release` on any path
 * where the roots are still published. */
int bci_layer_orphans(const char *repo, const char *prefix,
                      cvmfs_changeset_t *cs, char ***out_hex);
void bci_layer_forget(const char *repo, const char *prefix,
                      char **hex, int n);
void bci_layer_release(char **hex, int n);

/* ---- owned by brixcvmfs_ingest_prune.c ------------------------------------ */

/* --prune-old, which lives here because deleting a digest root is what this
 * TU is about: append a DELETE for old_digest's root under `prefix` when the
 * tag has actually moved off it (old_digest != new_digest) and no memo other
 * than memo_path still references it. 1 = marked, 0 = nothing to prune,
 * -1 = failed (message already printed). */
int bci_prune_old_mark(const char *repo, const char *prefix,
                       const char *memo_path, const char *old_digest,
                       const char *new_digest, cvmfs_changeset_t *cs);

/* Drop the roots-ledger entry of a digest root that was just deleted. */
void bci_root_forget(const char *repo, const char *prefix, const char *digest);

/* ---- verb entries --------------------------------------------------------- */

/* image/prune are weak so a dir-only standalone link (the pure-local test
 * lane) works without the registry stack; the umbrella links all three. */
int brixcvmfs_ingest_main(int argc, char **argv);   /* argv[0] = "ingest" */
int bci_image_main(int argc, char **argv)           /* brixcvmfs_ingest_image.c */
    __attribute__((weak));
int bci_prune_main(int argc, char **argv)           /* brixcvmfs_ingest_prune.c */
    __attribute__((weak));

#endif /* BRIXCVMFS_INGEST_INTERNAL_H */
