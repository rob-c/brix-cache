/*
 * codec_zlib.c — zlib backend for the codec abstraction: gzip + deflate.
 *
 * WHAT: Streaming (de)compression for XROOTD_CODEC_GZIP and XROOTD_CODEC_DEFLATE
 *       over a single zlib z_stream. gzip uses windowBits 15+16; deflate uses the
 *       zlib-wrapped windowBits 15 — byte-identical to the previous hand-rolled
 *       inflate path (window_bits 31 / 15 in http_body.c) so existing PUT decode
 *       behaviour is preserved exactly.
 * WHY:  zlib is the always-present codec (gzip/deflate are mandatory; the others
 *       are optional). This is also the reference backend the other codec_<name>.c
 *       files mirror.
 * HOW:  init() picks inflateInit2/deflateInit2 by direction + windowBits by id;
 *       step() translates the (in,in_pos,out,out_pos,finish) contract onto
 *       z_stream next_in/out + avail_in/out and inflate()/deflate(); end() frees it.
 */

#include "codec_core.h"

#if defined(XROOTD_HAVE_ZLIB)

#include <stdlib.h>
#include <zlib.h>

typedef struct {
    z_stream  zs;
    int       dir;        /* xrootd_codec_dir_t */
    int       inited;
} zlib_state;

static int
zlib_window_bits(xrootd_codec_id_t id)
{
    /* gzip = raw deflate + gzip header/trailer (15+16); deflate = zlib wrapper (15). */
    return (id == XROOTD_CODEC_GZIP) ? (15 + 16) : 15;
}

static int
zlib_init(void **state, xrootd_codec_id_t id, xrootd_codec_dir_t dir, int level)
{
    zlib_state *st = calloc(1, sizeof(*st));
    int         wbits = zlib_window_bits(id);
    int         zr;

    if (st == NULL) {
        return XROOTD_CODEC_ERR_MEM;
    }
    st->dir = dir;
    if (dir == XROOTD_CODEC_DIR_DECOMPRESS) {
        zr = inflateInit2(&st->zs, wbits);
    } else {
        zr = deflateInit2(&st->zs, level, Z_DEFLATED, wbits, 8,
                          Z_DEFAULT_STRATEGY);
    }
    if (zr != Z_OK) {
        free(st);
        return (zr == Z_MEM_ERROR) ? XROOTD_CODEC_ERR_MEM : XROOTD_CODEC_ERR_PARAM;
    }
    st->inited = 1;
    *state = st;
    return 0;
}

static xrootd_codec_rc_t
zlib_step(void *state, const uint8_t *in, size_t in_len, size_t *in_pos,
          uint8_t *out, size_t out_size, size_t *out_pos, int finish)
{
    zlib_state *st = state;
    uInt        in_avail0, out_avail0;
    int         zr;

    st->zs.next_in   = (Bytef *) (in + *in_pos);
    st->zs.avail_in  = (uInt) (in_len - *in_pos);
    st->zs.next_out  = (Bytef *) (out + *out_pos);
    st->zs.avail_out = (uInt) (out_size - *out_pos);
    in_avail0  = st->zs.avail_in;
    out_avail0 = st->zs.avail_out;

    if (st->dir == XROOTD_CODEC_DIR_DECOMPRESS) {
        zr = inflate(&st->zs, Z_NO_FLUSH);
    } else {
        zr = deflate(&st->zs, finish ? Z_FINISH : Z_NO_FLUSH);
    }

    *in_pos  += (size_t) (in_avail0 - st->zs.avail_in);
    *out_pos += (size_t) (out_avail0 - st->zs.avail_out);

    if (zr == Z_STREAM_END) {
        return XROOTD_CODEC_END;
    }
    if (zr == Z_OK || zr == Z_BUF_ERROR) {
        /* Z_BUF_ERROR = no progress possible without more input or output room;
         * not fatal in a streaming loop. */
        return XROOTD_CODEC_OK;
    }
    if (zr == Z_MEM_ERROR) {
        return XROOTD_CODEC_ERR_MEM;
    }
    return XROOTD_CODEC_ERR_DATA;   /* Z_DATA_ERROR / Z_NEED_DICT / Z_STREAM_ERROR */
}

static void
zlib_end(void *state)
{
    zlib_state *st = state;

    if (st == NULL) {
        return;
    }
    if (st->inited) {
        if (st->dir == XROOTD_CODEC_DIR_DECOMPRESS) {
            inflateEnd(&st->zs);
        } else {
            deflateEnd(&st->zs);
        }
    }
    free(st);
}

static const xrootd_codec_backend_t zlib_backend = {
    zlib_init, zlib_step, zlib_end
};

const xrootd_codec_desc_t xrootd_codec_gzip_desc = {
    XROOTD_CODEC_GZIP, "gzip", "gzip", 1, 1, 9, 6, &zlib_backend
};
const xrootd_codec_desc_t xrootd_codec_deflate_desc = {
    XROOTD_CODEC_DEFLATE, "deflate", "deflate", 1, 1, 9, 6, &zlib_backend
};

#else  /* !XROOTD_HAVE_ZLIB — should never happen (zlib is mandatory) */

const xrootd_codec_desc_t xrootd_codec_gzip_desc = {
    XROOTD_CODEC_GZIP, "gzip", "gzip", 0, 0, 0, 0, NULL
};
const xrootd_codec_desc_t xrootd_codec_deflate_desc = {
    XROOTD_CODEC_DEFLATE, "deflate", "deflate", 0, 0, 0, 0, NULL
};

#endif
