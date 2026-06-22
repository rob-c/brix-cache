/*
 * codec_lzma.c — xz/lzma backend for the codec abstraction (XROOTD_CODEC_XZ).
 *
 * WHAT: Streaming .xz (de)compression via liblzma. Compress emits the .xz
 *       container (CRC64-checked); decompress auto-detects .xz.
 * WHY:  xz/lzma is a high-ratio modern codec the user explicitly requested;
 *       optional (compile-gated on -DXROOTD_HAVE_LZMA).
 * HOW:  init() arms lzma_easy_encoder(preset) or lzma_stream_decoder(); step()
 *       maps the contract onto lzma_stream next_in/out + avail_in/out + lzma_code(RUN/FINISH).
 *       A zeroed lzma_stream equals LZMA_STREAM_INIT, so calloc suffices.
 */

#include "codec_core.h"

#if defined(XROOTD_HAVE_LZMA)

#include <stdlib.h>
#include <lzma.h>

typedef struct {
    lzma_stream  strm;     /* zero == LZMA_STREAM_INIT */
    int          dir;
    int          inited;
} lzma_state;

static int
lzma_be_init(void **state, xrootd_codec_id_t id, xrootd_codec_dir_t dir, int level)
{
    lzma_state *st = calloc(1, sizeof(*st));
    lzma_ret    r;

    (void) id;
    if (st == NULL) {
        return XROOTD_CODEC_ERR_MEM;
    }
    st->dir = dir;
    if (dir == XROOTD_CODEC_DIR_DECOMPRESS) {
        r = lzma_stream_decoder(&st->strm, UINT64_MAX, 0);
    } else {
        r = lzma_easy_encoder(&st->strm, (uint32_t) level, LZMA_CHECK_CRC64);
    }
    if (r != LZMA_OK) {
        free(st);
        return (r == LZMA_MEM_ERROR) ? XROOTD_CODEC_ERR_MEM : XROOTD_CODEC_ERR_PARAM;
    }
    st->inited = 1;
    *state = st;
    return 0;
}

static xrootd_codec_rc_t
lzma_step(void *state, const uint8_t *in, size_t in_len, size_t *in_pos,
          uint8_t *out, size_t out_size, size_t *out_pos, int finish)
{
    lzma_state *st = state;
    size_t      in_avail0, out_avail0;
    lzma_ret    r;

    st->strm.next_in   = in + *in_pos;
    st->strm.avail_in  = in_len - *in_pos;
    st->strm.next_out  = out + *out_pos;
    st->strm.avail_out = out_size - *out_pos;
    in_avail0  = st->strm.avail_in;
    out_avail0 = st->strm.avail_out;

    r = lzma_code(&st->strm, finish ? LZMA_FINISH : LZMA_RUN);

    *in_pos  += (in_avail0 - st->strm.avail_in);
    *out_pos += (out_avail0 - st->strm.avail_out);

    if (r == LZMA_STREAM_END) {
        return XROOTD_CODEC_END;
    }
    if (r == LZMA_OK) {
        return XROOTD_CODEC_OK;
    }
    if (r == LZMA_MEM_ERROR) {
        return XROOTD_CODEC_ERR_MEM;
    }
    return XROOTD_CODEC_ERR_DATA;   /* LZMA_DATA_ERROR / LZMA_FORMAT_ERROR / ... */
}

static void
lzma_be_end(void *state)
{
    lzma_state *st = state;

    if (st == NULL) {
        return;
    }
    if (st->inited) {
        lzma_end(&st->strm);
    }
    free(st);
}

static const xrootd_codec_backend_t lzma_backend = {
    lzma_be_init, lzma_step, lzma_be_end
};

const xrootd_codec_desc_t xrootd_codec_xz_desc = {
    XROOTD_CODEC_XZ, "xz", "xz", 1, 0, 9, 6, &lzma_backend
};

#else

const xrootd_codec_desc_t xrootd_codec_xz_desc = {
    XROOTD_CODEC_XZ, "xz", "xz", 0, 0, 0, 0, NULL
};

#endif
