/* flatten.h — apply one OCI layer to an overlay upper tree (phase-104 D7).
 *
 * WHAT: stream a layer archive through tar.h and materialize it into an
 *       upper directory in the repository overlay grammar: OCI ".wh."
 *       whiteouts become ".brix.wh." markers, ".wh..wh..opq" becomes the
 *       opaque marker, so cvmfs_changeset_scan() sees an ingested image
 *       exactly as it sees a hand-edited upper tree.
 * WHY:  the bridge that makes `brixcvmfs ingest image` a *front-end* to
 *       the phase-96 publish plane instead of a second publisher.
 * HOW:  every write descends from an O_DIRECTORY dirfd on upper_dir with
 *       per-component O_NOFOLLOW openat — never a joined string path — so
 *       a layer that plants a symlink in layer N and writes through it in
 *       layer N+1 hits the containment wall at the component, the
 *       changeset.c discipline in reverse. Entries whose own name spells
 *       the reserved marker grammar are refused: layers do not get to
 *       smuggle whiteouts.
 */
#ifndef BRIX_OCI_FLATTEN_H
#define BRIX_OCI_FLATTEN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    const char *upper_dir;        /* exists; empty or mid-accumulation */
    int64_t     max_total_bytes;  /* 0 = unlimited; decompression-bomb budget */
    int64_t     max_entries;      /* 0 → default 1M */
    int         strict;           /* devices/fifos fatal instead of counted */
    uid_t       squash_uid;       /* --squash-owner … */
    gid_t       squash_gid;
    int         squash;
    char       *diffid_hex;       /* NULL = no capture; else 65-byte out buffer
                                     that receives the layer's diff_id (sha256
                                     of the uncompressed tar) — free, because
                                     the reader decompresses the layer anyway */
    size_t      diffid_hexlen;
} brix_flatten_opts_t;

typedef struct {
    int64_t files, dirs, links, whiteouts, opaques, skipped_special, bytes;
    int64_t skipped_toc;          /* eStargz TOC/landmark entries dropped */
} brix_flatten_stats_t;

/* Apply one layer (manifest order; base first). 0 ok, -1 with err on refusal
 * (containment trip, marker smuggling, budget exhaustion, malformed archive).
 *
 * *st ACCUMULATES: zero it before the first layer and pass the same struct
 * for every layer of an image, so the entry/byte budgets bound the whole
 * image, not each layer separately. The upper tree is left as-is on failure:
 * callers treat the whole ingest scratch dir as disposable (D8 reaps it). */
int brix_flatten_layer(const brix_flatten_opts_t *o, int layer_fd,
                       brix_flatten_stats_t *st, char *err, size_t errlen);

#endif /* BRIX_OCI_FLATTEN_H */
