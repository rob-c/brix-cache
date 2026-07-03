/*
 * codec_lz4.c — LZ4 backend for the codec abstraction (BRIX_CODEC_LZ4).
 *
 * WHAT: Streaming LZ4 (de)compression via liblz4's LZ4 Frame API (lz4frame.h),
 *       producing/consuming the self-describing .lz4 frame format.
 * WHY:  LZ4 is the fastest mainstream codec — useful when CPU, not bandwidth, is
 *       the bottleneck (fast links, cheap clients).  It is a deliberate extension
 *       beyond upstream XRootD (which ships only DEFLATE), compile-gated on
 *       -DBRIX_HAVE_LZ4 exactly like zstd/xz/brotli/bzip2.
 * HOW:  Decompress maps directly onto LZ4F_decompress (it already streams to any
 *       output size).  Compress is block-oriented (LZ4F_compressBegin/Update/End
 *       emit whole chunks that must fit the destination), so it uses a small
 *       internal STAGING buffer: each step feeds one input chunk through LZ4F into
 *       the stage, then drains the stage into the caller's out buffer — which lets
 *       the codec honour the step() contract for ANY out size (incl. 1-byte
 *       buffers) without assuming the caller pre-sized for compressBound.
 */

#include "codec_core.h"

#if defined(BRIX_HAVE_LZ4)

#include <stdlib.h>
#include <string.h>
#include <lz4frame.h>

#define LZ4_CHUNK  (64 * 1024)   /* input fed to LZ4F_compressUpdate per refill */

typedef struct {
    int                 dir;
    LZ4F_cctx          *cctx;     /* compress context   */
    LZ4F_dctx          *dctx;     /* decompress context */
    LZ4F_preferences_t  prefs;
    int                 begun;    /* compressBegin emitted */
    int                 ended;    /* compressEnd emitted   */
    uint8_t            *stage;    /* pending compressed output awaiting drain */
    size_t              stage_cap;
    size_t              stage_len; /* bytes valid in stage */
    size_t              stage_pos; /* bytes already drained to the caller */
} lz4_state;

static int
lz4_init(void **state, brix_codec_id_t id, brix_codec_dir_t dir, int level)
{
    lz4_state *st = calloc(1, sizeof(*st));

    (void) id;
    if (st == NULL) {
        return BRIX_CODEC_ERR_MEM;
    }
    st->dir = dir;
    if (dir == BRIX_CODEC_DIR_DECOMPRESS) {
        if (LZ4F_isError(LZ4F_createDecompressionContext(&st->dctx, LZ4F_VERSION))) {
            free(st);
            return BRIX_CODEC_ERR_MEM;
        }
    } else {
        if (LZ4F_isError(LZ4F_createCompressionContext(&st->cctx, LZ4F_VERSION))) {
            free(st);
            return BRIX_CODEC_ERR_MEM;
        }
        st->prefs.compressionLevel = level;
        /* One staging buffer big enough for the frame header + one chunk's
         * compressBound (worst case), reused for every refill incl. the footer. */
        st->stage_cap = LZ4F_compressBound(LZ4_CHUNK, &st->prefs)
                      + LZ4F_HEADER_SIZE_MAX + 64;
        st->stage = malloc(st->stage_cap);
        if (st->stage == NULL) {
            LZ4F_freeCompressionContext(st->cctx);
            free(st);
            return BRIX_CODEC_ERR_MEM;
        }
    }
    *state = st;
    return 0;
}

/* Drain staged compressed bytes into the caller's out buffer; returns 1 if the
 * stage still has bytes left (caller must call again with more out room). */
static int
lz4_drain(lz4_state *st, uint8_t *out, size_t out_size, size_t *out_pos)
{
    size_t avail = out_size - *out_pos;
    size_t have  = st->stage_len - st->stage_pos;
    size_t n     = (have < avail) ? have : avail;

    if (n > 0) {
        memcpy(out + *out_pos, st->stage + st->stage_pos, n);
        *out_pos += n;
        st->stage_pos += n;
    }
    if (st->stage_pos >= st->stage_len) {
        st->stage_len = st->stage_pos = 0;   /* fully drained */
        return 0;
    }
    return 1;
}

static brix_codec_rc_t
lz4_step(void *state, const uint8_t *in, size_t in_len, size_t *in_pos,
         uint8_t *out, size_t out_size, size_t *out_pos, int finish)
{
    lz4_state *st = state;

    if (st->dir == BRIX_CODEC_DIR_DECOMPRESS) {
        size_t  src_n = in_len - *in_pos;
        size_t  dst_n = out_size - *out_pos;
        size_t  hint  = LZ4F_decompress(st->dctx, out + *out_pos, &dst_n,
                                        in + *in_pos, &src_n, NULL);
        *in_pos  += src_n;
        *out_pos += dst_n;
        if (LZ4F_isError(hint)) {
            return BRIX_CODEC_ERR_DATA;
        }
        /* hint == 0 means a frame end was reached. */
        return (hint == 0) ? BRIX_CODEC_END : BRIX_CODEC_OK;
    }

    /* compress */    /* 1) Drain any output staged from a previous refill first. */
    if (st->stage_len > st->stage_pos) {
        if (lz4_drain(st, out, out_size, out_pos)) {
            return BRIX_CODEC_OK;          /* out full; more staged */
        }
    }
    if (*out_pos >= out_size) {
        /* No room to do useful work this call (and stage is empty). Report
         * END only once everything is flushed; otherwise ask to be called again. */
        return (st->ended) ? BRIX_CODEC_END : BRIX_CODEC_OK;
    }

    /* 2) Stage empty + out has room: emit the next frame piece. */
    {
        size_t  cap = st->stage_cap;
        size_t  produced = 0;
        size_t  r;

        if (!st->begun) {
            r = LZ4F_compressBegin(st->cctx, st->stage, cap, &st->prefs);
            if (LZ4F_isError(r)) {
                return BRIX_CODEC_ERR_INTERNAL;
            }
            produced += r;
            st->begun = 1;
        }
        if (*in_pos < in_len) {
            size_t chunk = in_len - *in_pos;
            if (chunk > LZ4_CHUNK) {
                chunk = LZ4_CHUNK;
            }
            r = LZ4F_compressUpdate(st->cctx, st->stage + produced, cap - produced,
                                    in + *in_pos, chunk, NULL);
            if (LZ4F_isError(r)) {
                return BRIX_CODEC_ERR_INTERNAL;
            }
            *in_pos  += chunk;
            produced += r;
        } else if (finish && !st->ended) {
            r = LZ4F_compressEnd(st->cctx, st->stage + produced, cap - produced, NULL);
            if (LZ4F_isError(r)) {
                return BRIX_CODEC_ERR_INTERNAL;
            }
            produced += r;
            st->ended = 1;
        }

        st->stage_len = produced;
        st->stage_pos = 0;
        (void) lz4_drain(st, out, out_size, out_pos);
    }

    /* END only when finished AND the final bytes are fully drained. */
    if (st->ended && st->stage_len == st->stage_pos) {
        return BRIX_CODEC_END;
    }
    return BRIX_CODEC_OK;
}

static void
lz4_end(void *state)
{
    lz4_state *st = state;

    if (st == NULL) {
        return;
    }
    if (st->cctx != NULL) { LZ4F_freeCompressionContext(st->cctx); }
    if (st->dctx != NULL) { LZ4F_freeDecompressionContext(st->dctx); }
    free(st->stage);
    free(st);
}

static const brix_codec_backend_t lz4_backend = {
    lz4_init, lz4_step, lz4_end
};

const brix_codec_desc_t brix_codec_lz4_desc = {
    BRIX_CODEC_LZ4, "lz4", "lz4", 1, 1, 12, 1, &lz4_backend
};

#else

const brix_codec_desc_t brix_codec_lz4_desc = {
    BRIX_CODEC_LZ4, "lz4", "lz4", 0, 0, 0, 0, NULL
};

#endif
