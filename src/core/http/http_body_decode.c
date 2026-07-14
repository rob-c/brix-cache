/*
 * http_body_decode.c - shared nginx request-body decompress-to-fd pipeline.
 *
 * WHAT: Streams a Content-Encoding codec (gzip/deflate/zstd/xz/brotli/bzip2/lz4)
 *       over an nginx request body chain, writing the decoded plaintext to a
 *       destination fd under a decompression-bomb guard. Owns the codec stream
 *       setup, the per-buffer feed loop (memory + spooled buffers), and the
 *       failed-decode HTTP-status mapping.
 *
 * WHY:  WebDAV PUT and S3 PUT may carry any supported Content-Encoding; the
 *       stored object must be the decoded bytes, streamed so a large or hostile
 *       body never lands fully in RAM or fills the disk. Split from the plain
 *       chain read/write helpers in http_body.c so each translation unit owns a
 *       single concept and stays under the file-size / complexity gates.
 *
 * HOW:  brix_http_body_decode_to_fd summarises (validates) the body, sets up one
 *       codec_ctx_t (stream + scratch buffers), hands the per-buffer feed loop to
 *       codec_decode_bufs, then frees buffers and closes the stream once on
 *       return. codec_feed drains produced output through the shared
 *       brix_http_body_pwrite_full helper (http_body_internal.h). inbuf holds the
 *       pread of each spooled buffer before it is fed. brix_http_body_inflate_to_fd
 *       is the legacy zlib-window_bits wrapper.
*/

#include "http_body.h"
#include "http_body_internal.h"
#include "core/compat/codec_core.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_pread_full (storage seam) */

#include <errno.h>

#define BRIX_INFLATE_OUT_BUFSZ  (64 * 1024)
#define BRIX_INFLATE_IN_BUFSZ   (64 * 1024)

/*
 * codec_ctx_t — file-local decode-pipeline state, threaded through the codec
 * feed / decode-bufs / setup helpers.
 *
 * WHAT: bundles everything a single request-body decode needs — the open codec
 *       stream, the log/destination it writes to, the scratch in/out buffers,
 *       the running output offset, and the first negative codec rc seen.
 * WHY:  codec_feed / codec_decode_bufs / decode_to_fd previously threaded 7–11
 *       positional parameters (stream, log, fd, path, offset, buffers, worst_rc)
 *       through every call; collapsing them into one explicitly-passed struct
 *       keeps data flow visible while dropping the per-function param counts
 *       under the gate. No hidden globals — the struct is a stack local owned by
 *       decode_to_fd and passed by pointer.
 * HOW:  s/log/dst_fd/log_path/outbuf/inbuf are set once at setup and read-only
 *       thereafter; dst_off and worst_rc are the mutable running state advanced
 *       by the feed loop. inbuf is NULL when the body has no spooled buffers.
 */
typedef struct {
    brix_codec_stream_t  *s;
    ngx_log_t            *log;
    ngx_fd_t              dst_fd;
    const char           *log_path;
    u_char               *outbuf;
    u_char               *inbuf;
    off_t                 dst_off;
    brix_codec_rc_t       worst_rc;
} codec_ctx_t;

/* Feed one input chunk through the codec stream, writing all produced output to
 * cx->dst_fd. finish!=0 marks the final input. *ended is set when the codec
 * reports end-of-stream. cx->worst_rc captures the first negative codec rc (for
 * the caller's HTTP-status mapping: ERR_BOMB -> 413, ERR_DATA -> 400). Returns
 * NGX_OK/ERROR. */
static ngx_int_t
codec_feed(codec_ctx_t *cx, const u_char *in, size_t in_len, int finish,
    int *ended)
{
    size_t  ip = 0;

    for (;;) {
        size_t             op = 0;
        brix_codec_rc_t  rc;

        rc = brix_codec_step(cx->s, (const uint8_t *) in, in_len, &ip,
                               (uint8_t *) cx->outbuf, BRIX_INFLATE_OUT_BUFSZ,
                               &op, finish);
        if (rc < 0) {
            cx->worst_rc = rc;
            ngx_log_error(NGX_LOG_ERR, cx->log, 0,
                          "brix_http_body: decode error %d for %s",
                          (int) rc, cx->log_path ? cx->log_path : "-");
            return NGX_ERROR;
        }
        if (op > 0) {
            if (brix_http_body_pwrite_full(cx->log, cx->dst_fd, cx->outbuf, op,
                                             &cx->dst_off, cx->log_path)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
        if (rc == BRIX_CODEC_END) {
            *ended = 1;
            return NGX_OK;
        }
        if (op == BRIX_INFLATE_OUT_BUFSZ) {
            continue;                 /* output buffer was full: drain more */
        }
        if (ip < in_len) {
            continue;                 /* input remains in this chunk */
        }
        return NGX_OK;                /* chunk consumed, output drained */
    }
}

/*
 * codec_decode_spooled_buf — feed one spooled (in_file) body buffer through the
 * codec stream.
 *
 * WHAT: preads buf[file_pos..file_last] in BRIX_INFLATE_IN_BUFSZ chunks into
 *       cx->inbuf and hands each chunk to codec_feed; *ended tracks whether the
 *       codec has reported end-of-stream.
 * WHY:  a spooled buffer has no in-memory payload, so it must be read from its
 *       temp fd before feeding; pulling this out of codec_decode_bufs keeps that
 *       orchestrator under the CCN gate.
 * HOW:  loop while file_off < file_last: one storage-seam pread (a short fill
 *       before file_last is a hard error, matching the old n<=0 check), then
 *       feed the got bytes (finish=0). Returns NGX_OK/ERROR.
 */
static ngx_int_t
codec_decode_spooled_buf(codec_ctx_t *cx, ngx_buf_t *b, int *ended)
{
    off_t file_off = b->file_pos;

    while (file_off < b->file_last) {
        size_t want = (size_t) (b->file_last - file_off);
        size_t got  = 0;

        if (want > BRIX_INFLATE_IN_BUFSZ) {
            want = BRIX_INFLATE_IN_BUFSZ;
        }
        /* One chunk through the storage seam; EOF before file_last (a short
         * fill) is an error, matching the old n<=0 check. */
        if (brix_vfs_pread_full(b->file->fd, cx->inbuf, want, file_off,
                                  &got) != NGX_OK || got < want)
        {
            ngx_log_error(NGX_LOG_ERR, cx->log, errno,
                          "brix_http_body: decode pread failed for %s",
                          cx->log_path ? cx->log_path : "-");
            return NGX_ERROR;
        }
        file_off += (off_t) got;
        if (codec_feed(cx, cx->inbuf, got, 0, ended) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * codec_decode_bufs — feed every request-body buffer through an open codec
 * stream, writing decompressed bytes to dst_fd, then finalise.
 *
 * In-memory buffers feed directly; spooled buffers are pread in
 * BRIX_INFLATE_IN_BUFSZ chunks into inbuf first. After the last buffer a final
 * flush (empty input, finish=1) drains any tail; if the codec never reports
 * end-of-stream the input was truncated/corrupt (ERR_DATA -> caller maps 400).
 * Flat, early-return cleanup; the stream + buffers are owned by the caller.
 */
static ngx_int_t
codec_decode_bufs(codec_ctx_t *cx, ngx_http_request_t *r)
{
    ngx_chain_t *cl;
    int          ended = 0;

    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        ngx_buf_t *b = cl->buf;

        if (b == NULL) {
            continue;
        }

        if (b->in_file) {
            if (codec_decode_spooled_buf(cx, b, &ended) != NGX_OK) {
                return NGX_ERROR;
            }

        } else if (b->pos < b->last) {
            if (codec_feed(cx, b->pos, (size_t) (b->last - b->pos), 0,
                           &ended) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    /* Final flush: signal end-of-input and drain the codec's tail. */
    if (!ended) {
        if (codec_feed(cx, (const u_char *) "", 0, 1, &ended) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    if (!ended) {
        /* All input consumed + finish, but no end-of-stream: truncated input. */
        cx->worst_rc = BRIX_CODEC_ERR_DATA;
        ngx_log_error(NGX_LOG_ERR, cx->log, 0,
                      "brix_http_body: truncated compressed body for %s",
                      cx->log_path ? cx->log_path : "-");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * brix_http_body_decode_ratio - choose the untrusted decode ratio ceiling.
 *
 * WHAT: Returns the maximum permitted output:input expansion ratio for the given
 *       Content-Encoding codec on HTTP request-body decode.
 * WHY:  The generic 1000:1 ceiling catches classic bombs for most codecs, but LZ4
 *       frames cap zero-heavy compression below that; a lower LZ4-specific limit
 *       keeps PUT bomb protection effective without changing trusted decode paths.
 * HOW:  Select the codec-specific constant for LZ4, otherwise use the shared
 *       default consumed by the central codec guard.
 */
static uint32_t
brix_http_body_decode_ratio(brix_codec_id_t codec)
{
    if (codec == BRIX_CODEC_LZ4) {
        return BRIX_DECODE_LZ4_MAX_RATIO;
    }
    return BRIX_DECODE_MAX_RATIO;
}

/*
 * codec_ctx_setup — open the codec stream and its scratch buffers into *cx.
 *
 * WHAT: opens a decompress stream for `codec` (bomb-guarded by max_output +
 *       codec ratio), allocates cx->outbuf and — only when the body has spooled
 *       buffers — cx->inbuf, and fills the read-only fields of *cx.
 * WHY:  isolating the multi-resource acquisition (with its own failure ladder)
 *       from the decode orchestrator keeps that function flat and under the CCN
 *       gate; on any failure this helper frees whatever it already took, so the
 *       caller never partial-owns resources.
 * HOW:  cx must arrive with s/log/dst_fd/log_path/outbuf/inbuf pre-set by the
 *       caller (dst_off/worst_rc zero-init). On open failure -> UNSUPPORTED_
 *       MEDIA_TYPE; on alloc failure -> INTERNAL_SERVER_ERROR, freeing the
 *       stream (and outbuf) first. Returns NGX_OK with cx fully populated, else
 *       NGX_ERROR with *http_status_out set.
 */
static ngx_int_t
codec_ctx_setup(codec_ctx_t *cx, brix_codec_id_t codec, uint64_t max_output,
    int need_inbuf, ngx_int_t *http_status_out)
{
    brix_codec_guard_t  guard;

    ngx_memzero(&guard, sizeof(guard));
    guard.out_cap   = max_output;          /* 0 = unbounded */
    guard.max_ratio = brix_http_body_decode_ratio(codec);

    cx->s = brix_codec_open(codec, BRIX_CODEC_DIR_DECOMPRESS, -1, &guard);
    if (cx->s == NULL) {
        if (http_status_out) {
            *http_status_out = NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }
        ngx_log_error(NGX_LOG_ERR, cx->log, 0,
                      "brix_http_body: codec %d unavailable for %s",
                      (int) codec, cx->log_path ? cx->log_path : "-");
        return NGX_ERROR;
    }

    cx->outbuf = ngx_alloc(BRIX_INFLATE_OUT_BUFSZ, cx->log);
    if (cx->outbuf == NULL) {
        brix_codec_close(cx->s);
        if (http_status_out) { *http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR; }
        return NGX_ERROR;
    }
    if (need_inbuf) {
        cx->inbuf = ngx_alloc(BRIX_INFLATE_IN_BUFSZ, cx->log);
        if (cx->inbuf == NULL) {
            ngx_free(cx->outbuf);
            brix_codec_close(cx->s);
            if (http_status_out) { *http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR; }
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/*
 * codec_decode_http_status — map a failed decode's worst codec rc onto an HTTP
 * status. ERR_BOMB -> 413, ERR_DATA -> 400, anything else -> 500. Kept as a pure
 * lookup so the orchestrator stays branch-light.
 */
static ngx_int_t
codec_decode_http_status(brix_codec_rc_t worst_rc)
{
    if (worst_rc == BRIX_CODEC_ERR_BOMB) {
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;   /* 413 */
    }
    if (worst_rc == BRIX_CODEC_ERR_DATA) {
        return NGX_HTTP_BAD_REQUEST;                /* 400 */
    }
    return NGX_HTTP_INTERNAL_SERVER_ERROR;          /* 500 */
}

/*
 * brix_http_body_decode_to_fd - decompress the request body to dst_fd.
 *
 * WHAT: streams the Content-Encoding-selected codec over the request body chain,
 *       writing plaintext to dst_fd. Bounds output via the bomb guard (out_cap =
 *       max_output, ratio default) so a hostile highly-compressible upload cannot
 *       exhaust disk; on any failure sets *http_status_out (413 bomb / 400 bad
 *       data / 500 I-O) and returns NGX_ERROR. On success returns NGX_OK.
 * HOW:  summarise (validate) the body, set up one codec_ctx_t (stream + scratch
 *       buffers via codec_ctx_setup), hand the per-buffer feed loop to
 *       codec_decode_bufs, then free buffers + close the stream once on return.
 */
ngx_int_t
brix_http_body_decode_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, brix_codec_id_t codec, uint64_t max_output,
    brix_http_body_summary_t *summary_out, ngx_int_t *http_status_out)
{
    codec_ctx_t                 cx;
    ngx_int_t                   rc;
    brix_http_body_summary_t  summary;

    if (summary_out == NULL) {
        summary_out = &summary;
    }
    if (brix_http_body_summary(r, summary_out) != NGX_OK) {
        if (http_status_out) { *http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR; }
        return NGX_ERROR;
    }
    if (r == NULL || r->request_body == NULL
        || r->request_body->bufs == NULL)
    {
        return NGX_OK;
    }

    ngx_memzero(&cx, sizeof(cx));
    cx.log      = r->connection->log;
    cx.dst_fd   = dst_fd;
    cx.log_path = log_path;
    cx.worst_rc = BRIX_CODEC_OK;

    if (codec_ctx_setup(&cx, codec, max_output, summary_out->has_spooled,
                        http_status_out) != NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = codec_decode_bufs(&cx, r);

    ngx_free(cx.inbuf);
    ngx_free(cx.outbuf);
    brix_codec_close(cx.s);

    if (rc != NGX_OK && http_status_out) {
        *http_status_out = codec_decode_http_status(cx.worst_rc);
    }
    return rc;
}

/*
 * brix_http_body_inflate_to_fd - compatibility wrapper (zlib window_bits).
 *
 * Maps the legacy window_bits selector (15+16 = gzip, 15 = deflate) onto the
 * codec abstraction and delegates to brix_http_body_decode_to_fd with no output
 * cap. Retained so existing callers keep working; new code should call
 * brix_http_body_decode_to_fd directly with a codec id + bomb cap.
 */
ngx_int_t
brix_http_body_inflate_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, int window_bits,
    brix_http_body_summary_t *summary_out)
{
    brix_codec_id_t codec = (window_bits >= 16)
                              ? BRIX_CODEC_GZIP : BRIX_CODEC_DEFLATE;

    return brix_http_body_decode_to_fd(r, dst_fd, log_path, codec, 0,
                                         summary_out, NULL);
}
