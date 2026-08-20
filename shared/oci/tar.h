/* tar.h — streaming pull-parser for OCI layer archives (phase-104 D6).
 *
 * WHAT: iterate a (possibly gzip/zstd-compressed) ustar/pax/GNU tar stream
 *       from an fd, one entry at a time, with pax and GNU-long overrides
 *       resolved before the entry is handed to the caller.
 * WHY:  tool-surface only — links into brixcvmfs/brixoci, never nginx
 *       workers (same G14 ruling as the publish engine). The flattener
 *       (flatten.h) and the ingest personality are the only callers.
 * HOW:  one 512-byte header buffer + one 64 KiB body window + decompressor
 *       state; memory is flat in archive size. brix_tar_next() refuses to
 *       advance until the current body is fully read or skipped — desync
 *       is an API-misuse error (-1), never a silent re-frame.
 */
#ifndef BRIX_OCI_TAR_H
#define BRIX_OCI_TAR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    BRIX_TAR_REG, BRIX_TAR_DIR, BRIX_TAR_SYMLINK, BRIX_TAR_HARDLINK,
    BRIX_TAR_CHR, BRIX_TAR_BLK, BRIX_TAR_FIFO
} brix_tar_type_t;

typedef struct {
    char            path[4096];      /* pax/GNU-long resolved, NUL-terminated */
    char            linkname[4096];
    brix_tar_type_t type;
    int64_t         size;
    mode_t          mode;
    int64_t         mtime;
    uid_t           uid;
    gid_t           gid;
    dev_t           rdev;
    const char     *xattr;           /* packed BLOB in the changeset.h wire
                                        format (cvmfs_xattr_pack), so layer
                                        xattrs flow to publish unchanged;
                                        NULL when the entry has none */
    size_t          xattr_len;
} brix_tar_entry_t;

typedef struct brix_tar_s brix_tar_t;

/* Sniffs the leading magic: 1f 8b → gzip, 28 b5 2f fd or a skippable-frame
 * magic (0x184D2A5x, which a zstd:chunked TOC may lead with) → zstd (refused
 * with a clear message unless built with BRIX_HAVE_ZSTD), else raw tar.
 * Concatenated gzip members and zstd frames are one stream, not a stream and
 * some trailing bytes. Takes ownership of nothing; fd stays the caller's.
 * NULL + err on failure. */
brix_tar_t *brix_tar_open_fd(int fd, char *err, size_t errlen);

/* 1 = entry produced, 0 = clean EOF (two zero blocks, or one + EOF),
 * -1 = malformed archive or body-not-consumed misuse (brix_tar_error says
 * which). The entry's pointer fields alias reader-owned storage valid until
 * the next brix_tar_next() call. */
int  brix_tar_next(brix_tar_t *t, brix_tar_entry_t *e);

/* Read up to n bytes of the current entry body; 0 at body end, -1 error. */
int  brix_tar_read(brix_tar_t *t, void *buf, size_t n);

/* Discard the rest of the current body (decompressing as needed). 0 / -1. */
int  brix_tar_skip(brix_tar_t *t);

void brix_tar_close(brix_tar_t *t);

/* Bytes of the DECOMPRESSED stream produced so far. Sampled immediately
 * after brix_tar_next() returns 1 this is the offset at which the current
 * entry's body starts — the cut point an eStargz writer has to put a gzip
 * header at (stargz.h, D15.8). The source never reads ahead into a
 * decompressed window, so the number is exact, not an estimate. */
int64_t brix_tar_stream_offset(const brix_tar_t *t);

/* Copy the whole decompressed stream to out_fd WITHOUT framing it as tar:
 * the gunzip half of this reader, exposed so a converter can rewrite a
 * layer's FRAMING while copying its tar bytes through verbatim — headers,
 * pax records and all. Must be called before the first brix_tar_next();
 * the reader is spent afterwards. 0 = clean end of stream, -1. */
int brix_tar_drain(brix_tar_t *t, int out_fd);

/* The last failure's message (valid until the next reader call). */
const char *brix_tar_error(const brix_tar_t *t);

/* ---- diff-id capture (tar_digest.c) --------------------------------------
 * The OCI config's rootfs.diff_ids are sha256 over the *uncompressed* layer
 * tars, which this reader is decompressing anyway — so capturing them costs
 * one hash pass and no second inflate. Enable before the first
 * brix_tar_next(); finish after the walk reports clean EOF (it drains the
 * bytes past the end-of-archive marker, which the diff-id covers and the
 * entry walk never reads). 0 / -1 with brix_tar_error() set.
 */
int brix_tar_digest_enable(brix_tar_t *t);
int brix_tar_digest_finish(brix_tar_t *t, char *hex, size_t hexlen);

#endif /* BRIX_OCI_TAR_H */
