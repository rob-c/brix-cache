/*
 * codec_bzip2.c — bzip2 backend for the codec abstraction (XROOTD_CODEC_BZIP2).
 *
 * WHAT: Streaming bzip2 (de)compression via libbz2's low-level bz_stream API.
 * WHY:  bzip2 is a legacy-but-common codec; optional (compile-gated on
 *       -DXROOTD_HAVE_BZIP2). Lowest priority of the modern set.
 * HOW:  init() arms BZ2_bzCompressInit(blockSize100k) / BZ2_bzDecompressInit();
 *       step() maps the contract onto bz_stream next_in/out + avail_in/out (unsigned int,
 *       clamped) + BZ2_bzCompress(RUN/FINISH)/BZ2_bzDecompress.
 */

#include "codec_core.h"

#if defined(XROOTD_HAVE_BZIP2)

#include <stdlib.h>
#include <limits.h>
#include <bzlib.h>

typedef struct {
    bz_stream  strm;     /* calloc-zeroed: bzalloc/bzfree NULL => libc malloc */
    int        dir;
    int        inited;
} bz_state;

static unsigned
bz_clamp(size_t n)
{
    return (n > (size_t) UINT_MAX) ? UINT_MAX : (unsigned) n;
}

static int
bzip2_init(void **state, xrootd_codec_id_t id, xrootd_codec_dir_t dir, int level)
{
    bz_state *st = calloc(1, sizeof(*st));
    int       r;

    (void) id;
    if (st == NULL) {
        return XROOTD_CODEC_ERR_MEM;
    }
    st->dir = dir;
    if (dir == XROOTD_CODEC_DIR_DECOMPRESS) {
        r = BZ2_bzDecompressInit(&st->strm, 0, 0);
    } else {
        r = BZ2_bzCompressInit(&st->strm, level, 0, 0);
    }
    if (r != BZ_OK) {
        free(st);
        return (r == BZ_MEM_ERROR) ? XROOTD_CODEC_ERR_MEM : XROOTD_CODEC_ERR_PARAM;
    }
    st->inited = 1;
    *state = st;
    return 0;
}

static xrootd_codec_rc_t
bzip2_step(void *state, const uint8_t *in, size_t in_len, size_t *in_pos,
           uint8_t *out, size_t out_size, size_t *out_pos, int finish)
{
    bz_state *st = state;
    unsigned  in_avail0, out_avail0;
    int       r;

    st->strm.next_in   = (char *) (uintptr_t) (in + *in_pos);
    st->strm.avail_in  = bz_clamp(in_len - *in_pos);
    st->strm.next_out  = (char *) (out + *out_pos);
    st->strm.avail_out = bz_clamp(out_size - *out_pos);
    in_avail0  = st->strm.avail_in;
    out_avail0 = st->strm.avail_out;

    if (st->dir == XROOTD_CODEC_DIR_DECOMPRESS) {
        r = BZ2_bzDecompress(&st->strm);
    } else {
        r = BZ2_bzCompress(&st->strm, finish ? BZ_FINISH : BZ_RUN);
    }

    *in_pos  += (size_t) (in_avail0 - st->strm.avail_in);
    *out_pos += (size_t) (out_avail0 - st->strm.avail_out);

    if (r == BZ_STREAM_END) {
        return XROOTD_CODEC_END;
    }
    if (r == BZ_OK || r == BZ_RUN_OK || r == BZ_FINISH_OK || r == BZ_FLUSH_OK) {
        return XROOTD_CODEC_OK;
    }
    if (r == BZ_MEM_ERROR) {
        return XROOTD_CODEC_ERR_MEM;
    }
    return XROOTD_CODEC_ERR_DATA;
}

static void
bzip2_end(void *state)
{
    bz_state *st = state;

    if (st == NULL) {
        return;
    }
    if (st->inited) {
        if (st->dir == XROOTD_CODEC_DIR_DECOMPRESS) {
            BZ2_bzDecompressEnd(&st->strm);
        } else {
            BZ2_bzCompressEnd(&st->strm);
        }
    }
    free(st);
}

static const xrootd_codec_backend_t bzip2_backend = {
    bzip2_init, bzip2_step, bzip2_end
};

const xrootd_codec_desc_t xrootd_codec_bzip2_desc = {
    XROOTD_CODEC_BZIP2, "bzip2", "bzip2", 1, 1, 9, 9, &bzip2_backend
};

#else

const xrootd_codec_desc_t xrootd_codec_bzip2_desc = {
    XROOTD_CODEC_BZIP2, "bzip2", "bzip2", 0, 0, 0, 0, NULL
};

#endif
