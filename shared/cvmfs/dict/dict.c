/* dict.c — trained shared zstd dictionary codec (phase-87 G3, pure C).
 *
 * WHAT: ZDICT training + one-shot dict (de)compression + sha1 identity.
 * WHY:  one tested implementation shared by the proxy (train + serve +
 *       transcode) and the FUSE client (verify + decode); see dict.h.
 * HOW:  contexts are created per call — G3 objects are ≤ CVMFS_DICT_MAX_OBJ
 *       by contract, so ctx reuse is noise next to the syscall + wire cost.
 */
#include "cvmfs/dict/dict.h"
#include "cvmfs/object/object.h"

#ifdef BRIX_DICT_NO_ZSTD
/* zstd-less build (server ./config sets this when libzstd is absent): every
 * entry point fails cleanly, so the dict endpoint 404s and the data path
 * serves identity — the feature simply never engages. */
int cvmfs_dict_train(const void *samples, const size_t *sizes, unsigned n,
                     unsigned char *out, size_t outcap, size_t *outlen) {
    (void) samples; (void) sizes; (void) n; (void) out; (void) outcap;
    *outlen = 0;
    return -1;
}

int cvmfs_dict_id(const unsigned char *dict, size_t dictlen,
                  char hex[CVMFS_DICT_ID_HEXLEN + 1]) {
    (void) dict; (void) dictlen; (void) hex;
    return -1;
}

int cvmfs_dict_compress(const unsigned char *dict, size_t dictlen,
                        const unsigned char *src, size_t srclen,
                        unsigned char *out, size_t outcap, size_t *outlen) {
    (void) dict; (void) dictlen; (void) src; (void) srclen;
    (void) out; (void) outcap;
    *outlen = 0;
    return -1;
}

int cvmfs_dict_decompress(const unsigned char *dict, size_t dictlen,
                          const unsigned char *src, size_t srclen,
                          unsigned char *out, size_t outcap, size_t *outlen) {
    /* the same clean failure as compress — one stub body serves both */
    return cvmfs_dict_compress(dict, dictlen, src, srclen, out, outcap, outlen);
}
#else /* !BRIX_DICT_NO_ZSTD */

#include <zstd.h>
#include <zdict.h>

int cvmfs_dict_train(const void *samples, const size_t *sizes, unsigned n,
                     unsigned char *out, size_t outcap, size_t *outlen) {
    size_t r;

    *outlen = 0;
    if (samples == NULL || sizes == NULL || n == 0 || out == NULL || outcap == 0)
        return -1;
    r = ZDICT_trainFromBuffer(out, outcap, samples, sizes, n);
    if (ZDICT_isError(r) || r == 0 || r > outcap)
        return -1;
    *outlen = r;
    return 0;
}

int cvmfs_dict_id(const unsigned char *dict, size_t dictlen,
                  char hex[CVMFS_DICT_ID_HEXLEN + 1]) {
    cvmfs_hash_t h;

    if (dict == NULL || dictlen == 0
        || cvmfs_object_hash(CVMFS_HASH_SHA1, dict, dictlen, &h) != 0
        || cvmfs_hash_to_hex(&h, 0, hex, CVMFS_DICT_ID_HEXLEN + 1) < 0)
        return -1;
    return 0;
}

/* One-shot dict (de)compression — `compressing` picks the codec direction;
 * contexts are created per call (see the file header for why). */
static int dict_xcode(int compressing, const unsigned char *dict,
                      size_t dictlen, const unsigned char *src, size_t srclen,
                      unsigned char *out, size_t outcap, size_t *outlen) {
    size_t r;

    *outlen = 0;
    if (compressing) {
        ZSTD_CCtx *c = ZSTD_createCCtx();
        if (c == NULL)
            return -1;
        r = ZSTD_compress_usingDict(c, out, outcap, src, srclen,
                                    dict, dictlen, CVMFS_DICT_CLEVEL);
        ZSTD_freeCCtx(c);
    } else {
        ZSTD_DCtx *d = ZSTD_createDCtx();
        if (d == NULL)
            return -1;
        r = ZSTD_decompress_usingDict(d, out, outcap, src, srclen,
                                      dict, dictlen);
        ZSTD_freeDCtx(d);
    }
    if (ZSTD_isError(r))
        return -1;
    *outlen = r;
    return 0;
}

int cvmfs_dict_compress(const unsigned char *dict, size_t dictlen,
                        const unsigned char *src, size_t srclen,
                        unsigned char *out, size_t outcap, size_t *outlen) {
    return dict_xcode(1, dict, dictlen, src, srclen, out, outcap, outlen);
}

int cvmfs_dict_decompress(const unsigned char *dict, size_t dictlen,
                          const unsigned char *src, size_t srclen,
                          unsigned char *out, size_t outcap, size_t *outlen) {
    return dict_xcode(0, dict, dictlen, src, srclen, out, outcap, outlen);
}

#endif /* BRIX_DICT_NO_ZSTD */
