/* stargz.h — eStargz layer BUILDING (phase-104 D15.8).
 *
 * WHAT: convert an ordinary OCI layer blob (gzip/zstd/plain tar) into an
 *       eStargz blob: the same tar, reframed so that every file payload and
 *       every metadata run begins at a gzip member boundary, with a
 *       `stargz.index.json` TOC as the last tar entry and the fixed 51-byte
 *       footer that points at it.
 * WHY:  D15.7 taught this tree to READ the lazy-pull encodings; a registry
 *       that wants an off-the-shelf containerd stargz snapshotter to pull
 *       from it lazily has to SERVE them, and nothing else in the tree can
 *       produce one. The Range blob surface both `/v2/` planes already
 *       serve is the other half — see §D15 for what stays out of scope
 *       (being the snapshotter, rather than feeding one).
 * HOW:  tool surface only (G14) — no ngx, no root, single-threaded. The tar
 *       BYTES are copied through verbatim (headers, pax records, xattrs and
 *       all): only the compression framing is rewritten, so a converted
 *       layer extracts to exactly the tree its original did, minus the
 *       eStargz bookkeeping entries this format adds and flatten.c drops.
 *
 *       Conversion is not identity-preserving by design: reframing changes
 *       both the layer's compressed digest and its diff_id, so the caller
 *       MUST rewrite the image config's rootfs.diff_ids and the manifest's
 *       layer descriptors from the stats below. An eStargz layer that keeps
 *       its original's diff_id is a lie the runtime will catch.
 */
#ifndef BRIX_OCI_STARGZ_H
#define BRIX_OCI_STARGZ_H

#include <stddef.h>
#include <stdint.h>

#include "oci/digest.h"

/* The layer descriptor annotation a stargz snapshotter reads to find (and
 * verify) the TOC without fetching the blob's tail twice. */
#define BRIX_STARGZ_TOC_ANNOTATION "containerd.io/snapshot/stargz/toc.digest"

/* The tar entry the TOC lives in, and the two prefetch landmarks — the
 * archive-root names the format reserves for its own bookkeeping. Owned
 * here rather than in flatten.c because this is the TU that WRITES them;
 * the flattener drops exactly the same three (see brix_stargz_is_meta). */
#define BRIX_STARGZ_TOC_NAME       "stargz.index.json"
#define BRIX_STARGZ_LANDMARK       ".prefetch.landmark"
#define BRIX_STARGZ_NO_LANDMARK    ".no.prefetch.landmark"

/* The footer is a fixed-size gzip member so a reader can find the TOC with
 * one ranged read of the blob's tail. */
#define BRIX_STARGZ_FOOTER_LEN 51

/* What the caller needs to rewrite the manifest and config around the new
 * blob. Every digest is a full "<alg>:<hex>". */
typedef struct {
    char      blob_digest[BRIX_OCI_DIGEST_STRLEN];  /* the eStargz blob */
    char      diffid[BRIX_OCI_DIGEST_STRLEN];       /* its uncompressed tar */
    char      toc_digest[BRIX_OCI_DIGEST_STRLEN];   /* the TOC JSON bytes */
    long long blob_size;                            /* bytes written */
    int64_t   entries;                              /* TOC entries emitted */
    int64_t   dropped;      /* reserved entries dropped from the source */
} brix_stargz_stats_t;

/* Is `name` one of the format's own root-level bookkeeping entries? The
 * name must already be the archive-root component (no '/'), because these
 * three are reserved at the root ONLY — a `usr/stargz.index.json` in a
 * layer is an ordinary file and stays one. */
int brix_stargz_is_meta(const char *name);

/* Convert the layer on in_fd (positioned at its first byte; any framing
 * brix_tar_open_fd sniffs) into an eStargz blob on out_fd, filling *st.
 * A source that already carries eStargz bookkeeping entries is converted
 * cleanly: they are dropped, not duplicated. 0 / -1 with err set. */
int brix_stargz_convert(int in_fd, int out_fd, brix_stargz_stats_t *st,
                        char *err, size_t errlen);

#endif /* BRIX_OCI_STARGZ_H */
