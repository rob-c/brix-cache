/* dict.h — trained shared zstd dictionary codec (phase-87 G3, pure C).
 *
 * WHAT: train / identify / apply a per-repo zstd dictionary so many tiny
 *       objects share one compression context instead of resetting per file.
 * WHY:  per-chunk zlib captures no cross-file redundancy; a trained dict is
 *       2-5x better on corpora of small similar files (headers, .py, small
 *       .so).  The dict is a pure WIRE optimization: it (de)codes the STORED
 *       object bytes, so CAS identity and the verify path are untouched — a
 *       wrong or hostile dict can only fail decode (fallback), never poison
 *       verified data.
 * HOW:  thin wrappers over libzstd's ZDICT_trainFromBuffer +
 *       ZSTD_{compress,decompress}_usingDict (one-shot; objects are small by
 *       contract).  The dict's identity is the sha1 of its own bytes
 *       (self-certifying: a client that fetched a dict under id X verifies
 *       sha1(bytes) == X before ever using it).  No ngx types, no globals —
 *       shared by the nginx proxy and the standalone FUSE client.
 */
#ifndef BRIX_CVMFS_DICT_H
#define BRIX_CVMFS_DICT_H

#include <stddef.h>

/* zstd's recommended dictionary size (~110 KiB) for small-file corpora. */
#define CVMFS_DICT_TARGET_BYTES  112640u
/* Hard cap on a dict blob accepted from the wire (client) / served (proxy). */
#define CVMFS_DICT_MAX_BYTES     (1024u * 1024u)
/* Objects above this are never dict-coded — big objects don't need a dict
 * and buffering them for transcode would fight sendfile for no gain. */
#define CVMFS_DICT_MAX_OBJ       (256u * 1024u)
/* Fixed level: objects are tiny, so max-ratio compression is ~free. */
#define CVMFS_DICT_CLEVEL        19
/* Dict id = lowercase sha1 hex of the dict bytes. */
#define CVMFS_DICT_ID_HEXLEN     40u

/* Train a dictionary from `n` concatenated samples (`samples` holds them
 * back-to-back; `sizes[i]` is each length).  Writes at most `outcap` bytes
 * (use CVMFS_DICT_TARGET_BYTES).  Returns 0 and sets *outlen, or -1 when the
 * corpus is too small/degenerate for zstd to train on (caller serves no
 * dict — clients fall back, nothing breaks). */
int cvmfs_dict_train(const void *samples, const size_t *sizes, unsigned n,
                     unsigned char *out, size_t outcap, size_t *outlen);

/* Self-certifying identity: lowercase sha1 hex of the dict bytes, NUL-
 * terminated.  0 on success. */
int cvmfs_dict_id(const unsigned char *dict, size_t dictlen,
                  char hex[CVMFS_DICT_ID_HEXLEN + 1]);

/* One-shot (de)compress of a stored object with the shared dict.  A NULL/0
 * dict means dictless zstd (used by tests to prove the trained ratio).
 * Return 0 on success, -1 on any zstd error or output overflow.  Decompress
 * fails (rather than emitting garbage) when the frame was written with a
 * different trained dict — zstd checks the embedded dictID. */
int cvmfs_dict_compress(const unsigned char *dict, size_t dictlen,
                        const unsigned char *src, size_t srclen,
                        unsigned char *out, size_t outcap, size_t *outlen);
int cvmfs_dict_decompress(const unsigned char *dict, size_t dictlen,
                          const unsigned char *src, size_t srclen,
                          unsigned char *out, size_t outcap, size_t *outlen);

#endif /* BRIX_CVMFS_DICT_H */
