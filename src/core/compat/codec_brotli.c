/*
 * codec_brotli.c — Brotli backend for the codec abstraction (XROOTD_CODEC_BROTLI).
 *
 * WHAT: Streaming brotli (de)compression via libbrotlienc / libbrotlidec.
 * WHY:  brotli is the standard web "br" Content-Encoding; optional (compile-gated
 *       on -DXROOTD_HAVE_BROTLI; requires both enc + dec libraries).
 * HOW:  init() creates an encoder (quality set) or decoder instance; step() maps
 *       the contract onto Brotli{Encoder,Decoder}*Stream's
 *       (&avail_in,&next_in,&avail_out,&next_out) cursor pairs.
 */

#include "codec_core.h"

#if defined(XROOTD_HAVE_BROTLI)

#include <stdlib.h>
#include <brotli/encode.h>
#include <brotli/decode.h>

typedef struct {
    BrotliEncoderState *enc;
    BrotliDecoderState *dec;
    int                 dir;
} brotli_state;

static int
brotli_init(void **state, xrootd_codec_id_t id, xrootd_codec_dir_t dir, int level)
{
    brotli_state *st = calloc(1, sizeof(*st));

    (void) id;
    if (st == NULL) {
        return XROOTD_CODEC_ERR_MEM;
    }
    st->dir = dir;
    if (dir == XROOTD_CODEC_DIR_DECOMPRESS) {
        st->dec = BrotliDecoderCreateInstance(NULL, NULL, NULL);
        if (st->dec == NULL) { free(st); return XROOTD_CODEC_ERR_MEM; }
    } else {
        st->enc = BrotliEncoderCreateInstance(NULL, NULL, NULL);
        if (st->enc == NULL) { free(st); return XROOTD_CODEC_ERR_MEM; }
        BrotliEncoderSetParameter(st->enc, BROTLI_PARAM_QUALITY,
                                  (uint32_t) level);
    }
    *state = st;
    return 0;
}

static xrootd_codec_rc_t
brotli_step(void *state, const uint8_t *in, size_t in_len, size_t *in_pos,
            uint8_t *out, size_t out_size, size_t *out_pos, int finish)
{
    brotli_state  *st = state;
    const uint8_t *nin  = in + *in_pos;
    size_t         ain  = in_len - *in_pos;
    uint8_t       *nout = out + *out_pos;
    size_t         aout = out_size - *out_pos;

    if (st->dir == XROOTD_CODEC_DIR_DECOMPRESS) {
        BrotliDecoderResult r =
            BrotliDecoderDecompressStream(st->dec, &ain, &nin, &aout, &nout, NULL);
        *in_pos  = in_len - ain;
        *out_pos = out_size - aout;
        if (r == BROTLI_DECODER_RESULT_SUCCESS) {
            return XROOTD_CODEC_END;
        }
        if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT
            || r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            return XROOTD_CODEC_OK;
        }
        return XROOTD_CODEC_ERR_DATA;
    }

    if (!BrotliEncoderCompressStream(st->enc,
            finish ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS,
            &ain, &nin, &aout, &nout, NULL)) {
        return XROOTD_CODEC_ERR_DATA;
    }
    *in_pos  = in_len - ain;
    *out_pos = out_size - aout;
    if (finish && BrotliEncoderIsFinished(st->enc)) {
        return XROOTD_CODEC_END;
    }
    return XROOTD_CODEC_OK;
}

static void
brotli_end(void *state)
{
    brotli_state *st = state;

    if (st == NULL) {
        return;
    }
    if (st->enc != NULL) { BrotliEncoderDestroyInstance(st->enc); }
    if (st->dec != NULL) { BrotliDecoderDestroyInstance(st->dec); }
    free(st);
}

static const xrootd_codec_backend_t brotli_backend = {
    brotli_init, brotli_step, brotli_end
};

const xrootd_codec_desc_t xrootd_codec_brotli_desc = {
    XROOTD_CODEC_BROTLI, "brotli", "br", 1, 0, 11, 5, &brotli_backend
};

#else

const xrootd_codec_desc_t xrootd_codec_brotli_desc = {
    XROOTD_CODEC_BROTLI, "brotli", "br", 0, 0, 0, 0, NULL
};

#endif
