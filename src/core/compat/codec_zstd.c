/*
 * codec_zstd.c — Zstandard backend for the codec abstraction (BRIX_CODEC_ZSTD).
 *
 * WHAT: Streaming zstd (de)compression via libzstd's CCtx/DCtx streaming API.
 * WHY:  zstd is a modern, fast codec widely used in HEP/WLCG + the web; optional
 *       (compile-gated on -DBRIX_HAVE_ZSTD).
 * HOW:  init() creates a CCtx (compress, level set) or DCtx (decompress); step()
 *       maps the (in,in_pos,out,out_pos,finish) contract onto ZSTD_inBuffer/
 *       ZSTD_outBuffer + ZSTD_compressStream2(e_end)/ZSTD_decompressStream.
 */

#include "codec_core.h"

#if defined(BRIX_HAVE_ZSTD)

#include <stdlib.h>
#include <zstd.h>

typedef struct {
    ZSTD_CCtx  *cctx;
    ZSTD_DCtx  *dctx;
    int         dir;
} zstd_state;

static int
zstd_init(void **state, brix_codec_id_t id, brix_codec_dir_t dir, int level)
{
    zstd_state *st = calloc(1, sizeof(*st));

    (void) id;
    if (st == NULL) {
        return BRIX_CODEC_ERR_MEM;
    }
    st->dir = dir;
    if (dir == BRIX_CODEC_DIR_DECOMPRESS) {
        st->dctx = ZSTD_createDCtx();
        if (st->dctx == NULL) {
            free(st);
            return BRIX_CODEC_ERR_MEM;
        }
    } else {
        st->cctx = ZSTD_createCCtx();
        if (st->cctx == NULL) {
            free(st);
            return BRIX_CODEC_ERR_MEM;
        }
        ZSTD_CCtx_setParameter(st->cctx, ZSTD_c_compressionLevel, level);
    }
    *state = st;
    return 0;
}

static brix_codec_rc_t
zstd_step(void *state, const uint8_t *in, size_t in_len, size_t *in_pos,
          uint8_t *out, size_t out_size, size_t *out_pos, int finish)
{
    zstd_state    *st = state;
    ZSTD_inBuffer  ib = { in, in_len, *in_pos };
    ZSTD_outBuffer ob = { out, out_size, *out_pos };
    size_t         r;

    if (st->dir == BRIX_CODEC_DIR_DECOMPRESS) {
        r = ZSTD_decompressStream(st->dctx, &ob, &ib);
        *in_pos  = ib.pos;
        *out_pos = ob.pos;
        if (ZSTD_isError(r)) {
            return BRIX_CODEC_ERR_DATA;
        }
        /* r == 0 means a frame boundary was reached (stream end). */
        return (r == 0) ? BRIX_CODEC_END : BRIX_CODEC_OK;
    }

    r = ZSTD_compressStream2(st->cctx, &ob, &ib,
                             finish ? ZSTD_e_end : ZSTD_e_continue);
    *in_pos  = ib.pos;
    *out_pos = ob.pos;
    if (ZSTD_isError(r)) {
        return BRIX_CODEC_ERR_DATA;
    }
    /* On finish, r == 0 means everything has been flushed. */
    return (finish && r == 0) ? BRIX_CODEC_END : BRIX_CODEC_OK;
}

static void
zstd_end(void *state)
{
    zstd_state *st = state;

    if (st == NULL) {
        return;
    }
    if (st->cctx != NULL) { ZSTD_freeCCtx(st->cctx); }
    if (st->dctx != NULL) { ZSTD_freeDCtx(st->dctx); }
    free(st);
}

static const brix_codec_backend_t zstd_backend = {
    zstd_init, zstd_step, zstd_end
};

const brix_codec_desc_t brix_codec_zstd_desc = {
    BRIX_CODEC_ZSTD, "zstd", "zstd", 1, 1, 19, 3, &zstd_backend
};

#else

const brix_codec_desc_t brix_codec_zstd_desc = {
    BRIX_CODEC_ZSTD, "zstd", "zstd", 0, 0, 0, 0, NULL
};

#endif
