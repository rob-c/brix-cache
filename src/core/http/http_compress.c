/*
 * http_compress.c — outbound (GET) response compression (see http_compress.h).
 *
 * Negotiation picks the best AVAILABLE codec named in Accept-Encoding by a fixed
 * preference (zstd > br > gzip > xz > deflate > bzip2 > lz4), skipping ranges, HEAD,
 * tiny files, and already-compressed content types. The compressed sender forces
 * chunked output (compressed length is unknown up front) and streams the file
 * through the shared codec abstraction into the nginx output filter.
 */

#include "http_compress.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_pread_full (storage seam) */
#include "http_file_response.h"

#include <unistd.h>

#define BRIX_COMPRESS_CHUNK  (64 * 1024)

/* Outbound codec preference, best first. Only available ones are considered. */
static const brix_codec_id_t brix_compress_pref[] = {
    BRIX_CODEC_ZSTD, BRIX_CODEC_BROTLI, BRIX_CODEC_GZIP,
    BRIX_CODEC_XZ, BRIX_CODEC_DEFLATE, BRIX_CODEC_BZIP2,
    BRIX_CODEC_LZ4   /* fastest but weakest ratio: last resort */
};

/* Content types that are already compressed — never re-compress these. */
static int
content_type_incompressible(ngx_http_request_t *r)
{
    static const char *deny[] = {
        "application/gzip", "application/zstd", "application/x-xz",
        "application/x-bzip2", "application/zip", "application/x-7z-compressed",
        "application/x-br", "application/x-brotli",   /* already brotli-encoded */
        "application/x-rar-compressed", "application/x-zstd",
        "image/", "video/", "audio/", "application/octet-stream-compressed",
    };
    ngx_str_t *ct = &r->headers_out.content_type;
    size_t     i;

    if (ct->len == 0 || ct->data == NULL) {
        return 0;                       /* unknown type: allow compression */
    }
    for (i = 0; i < sizeof(deny) / sizeof(deny[0]); i++) {
        size_t dl = ngx_strlen(deny[i]);
        if (ct->len >= dl && ngx_strncasecmp(ct->data, (u_char *) deny[i], dl) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * WHAT: decide whether the ";q=..." parameter starting at `semi` explicitly
 *       disables the coding (an exactly-zero q-value).
 * WHY:  RFC 7231 5.3.1 lets a client veto a coding with "q=0" in any of its
 *       zero spellings ("q=0", "q=0.", "q=0.0", "q=0.00", "q=0.000"); a nonzero
 *       fractional digit (q=0.x) still accepts. Pulled out of the segment scan so
 *       the caller stays a flat name-match with no nested q-parser.
 * HOW:  find "q=0" within [semi, seg_end); a match is a real veto UNLESS it is
 *       followed by ".<digits>" containing a non-'0' digit (which makes q>0).
 */
static int
accept_encoding_q_is_zero(const u_char *semi, const u_char *seg_end)
{
    const u_char *q = ngx_strlcasestrn((u_char *) semi, (u_char *) seg_end,
        (u_char *) "q=0", 3 - 1);
    const u_char *after;

    if (q == NULL) {
        return 0;                       /* no explicit q=0 => not vetoed */
    }
    after = q + 3;                      /* first char past "q=0" */
    if (after < seg_end && *after == '.') {
        const u_char *d = after + 1;
        /* scan the fractional digits; any non-'0' => q>0 => accepted */
        while (d < seg_end && *d >= '0' && *d <= '9') {
            if (*d != '0') { return 0; }
            d++;
        }
    }
    return 1;                           /* q=0 / q=0. / q=0.0[00] => vetoed */
}

/*
 * WHAT: test whether a single Accept-Encoding list member [seg, seg_end) names
 *       `token` (len `tlen`) as an acceptable coding.
 * WHY:  isolates the per-member name comparison + q-value veto from the list
 *       iteration so neither carries the other's branching.
 * HOW:  the coding name runs up to ';' (its q-value) or the member end, trimmed
 *       of trailing OWS; a case-insensitive length-exact match that is not
 *       vetoed by an explicit q=0 means the coding is acceptable.
 */
static int
accept_encoding_segment_has(const u_char *seg, const u_char *seg_end,
    const char *token, size_t tlen)
{
    const u_char *semi = ngx_strlchr((u_char *) seg, (u_char *) seg_end, ';');
    const u_char *name_end = semi ? semi : seg_end;

    while (name_end > seg && (name_end[-1] == ' ' || name_end[-1] == '\t')) {
        name_end--;
    }
    if ((size_t) (name_end - seg) != tlen
        || ngx_strncasecmp((u_char *) seg, (u_char *) token, tlen) != 0)
    {
        return 0;
    }
    if (semi != NULL && accept_encoding_q_is_zero(semi, seg_end)) {
        return 0;
    }
    return 1;
}

/* Is `token` (len) present as an acceptable coding in the Accept-Encoding value
 * (case-insensitive, ignoring an explicit ";q=0")? */
static int
accept_encoding_has(const u_char *ae, size_t ae_len, const char *token)
{
    size_t        tlen = ngx_strlen(token);
    const u_char *p = ae, *end = ae + ae_len;

    while (p < end) {
        const u_char *comma, *seg_end;

        /* skip inter-member OWS — RFC 7230 permits SP and HTAB around list members */
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) { p++; }
        comma = ngx_strlchr((u_char *) p, (u_char *) end, ',');
        seg_end = comma ? comma : end;
        if (accept_encoding_segment_has(p, seg_end, token, tlen)) {
            return 1;
        }
        p = seg_end;
    }
    return 0;
}

brix_codec_id_t
brix_http_compress_negotiate(ngx_http_request_t *r, off_t file_size,
    ngx_flag_t is_range)
{
    ngx_table_elt_t *ae;
    size_t           i;

    if (is_range || r->header_only || file_size < BRIX_COMPRESS_MIN_SIZE) {
        return BRIX_CODEC_IDENTITY;
    }
    ae = r->headers_in.accept_encoding;
    if (ae == NULL || ae->value.len == 0) {
        return BRIX_CODEC_IDENTITY;
    }
    if (content_type_incompressible(r)) {
        return BRIX_CODEC_IDENTITY;
    }
    for (i = 0; i < sizeof(brix_compress_pref) / sizeof(brix_compress_pref[0]);
         i++)
    {
        brix_codec_id_t          id = brix_compress_pref[i];
        const brix_codec_desc_t *d  = brix_codec_by_id(id);
        if (d != NULL && d->available
            && accept_encoding_has(ae->value.data, ae->value.len, d->http_token))
        {
            return id;
        }
    }
    return BRIX_CODEC_IDENTITY;
}

/*
 * WHAT: Request-owned cursor, codec and two fixed-size buffers for a send.
 * WHY: Socket backpressure is not a codec failure. Preserve partially consumed
 *      input and pending output without retaining caller stack storage or
 *      allocating one more buffer for every chunk of a slow reader's file.
 * HOW: A request cleanup owns fd/codec; its data also locates the write handler's
 *      cursor without borrowing any protocol module's request-context slot.
 */
typedef struct {
    ngx_http_request_t  *r;
    ngx_fd_t             fd;
    off_t                size;
    off_t                off;
    brix_codec_stream_t *stream;
    u_char              *inbuf;
    ngx_buf_t           *output;
    size_t               fill;
    size_t               ip;
    int                  finish;
    int                  ended;
    off_t                bytes;
    brix_http_compress_done_fn done;
    void                *data;
} compress_send_t;

/* WHAT: Release owned native resources once, including abandoned requests.
 * WHY: Neither a disconnected reader nor a failed output filter may leak an fd
 *      or codec. HOW: Disarm each resource after release; pool storage remains. */
static void
compress_cleanup(void *data)
{
    compress_send_t *st = data;

    if (st->stream != NULL) {
        brix_codec_close(st->stream);
        st->stream = NULL;
    }
    if (st->fd != NGX_INVALID_FILE) {
        ngx_close_file(st->fd);
        st->fd = NGX_INVALID_FILE;
    }
}

/* WHAT: Find this request's send cursor, or NULL. WHY: Keep the shared sender
 * independent of protocol contexts. HOW: Match our own cleanup identity. */
static compress_send_t *
compress_state(ngx_http_request_t *r)
{
    ngx_http_cleanup_t *cln;

    for (cln = r->cleanup; cln != NULL; cln = cln->next) {
        if (cln->handler == compress_cleanup) {
            return cln->data;
        }
    }
    return NULL;
}

/* WHAT: Queue the current memory buffer, marking only codec END as response EOF.
 * WHY: Cleartext and TLS both send generated bytes, never a file-backed buffer.
 * HOW: Reuse only after all downstream filters have drained the previous bytes. */
static ngx_int_t
compress_emit(compress_send_t *st, size_t len)
{
    ngx_buf_t   *b = st->output;
    ngx_chain_t  out;

    b->pos = b->start;
    b->last = b->start + len;
    b->temporary = 1;
    b->memory = 1;
    b->flush = 1;
    b->last_buf = st->ended && st->r == st->r->main;
    b->last_in_chain = st->ended;
    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(st->r, &out);
}

/*
 * WHAT: emit the response headers for a compressed body — 200 + ETag/Last-Modified,
 *       forced chunked, Content-Encoding + Vary.
 * WHY:  keeps all header mutation (and its allocation failure paths) out of the
 *       streaming orchestrator so that reads as a flat init-then-stream sequence.
 * HOW:  set the file headers, drop Content-Length (unknown => chunked), then push
 *       the Content-Encoding (desc->http_token) and Vary list elements.
 */
static ngx_int_t
compress_set_headers(ngx_http_request_t *r, const brix_codec_desc_t *desc,
    off_t size, time_t mtime, unsigned etag_flags)
{
    ngx_table_elt_t *ce, *vary;

    if (brix_http_set_file_headers(r, mtime, size, size, NULL, etag_flags,
                                     0, 0, size > 0 ? size - 1 : 0) != NGX_OK)
    {
        return NGX_ERROR;
    }
    r->headers_out.content_length_n = -1;        /* unknown -> chunked */
    if (r->headers_out.content_length != NULL) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ce = ngx_list_push(&r->headers_out.headers);
    vary = ngx_list_push(&r->headers_out.headers);
    if (ce == NULL || vary == NULL) {
        return NGX_ERROR;
    }
    ce->hash = 1;
    ngx_str_set(&ce->key, "Content-Encoding");
    ce->value.data = (u_char *) desc->http_token;
    ce->value.len  = ngx_strlen(desc->http_token);
    vary->hash = 1;
    ngx_str_set(&vary->key, "Vary");
    ngx_str_set(&vary->value, "Accept-Encoding");
    return NGX_OK;
}

/* WHAT: Whether downstream filters still own output. WHY: A codec buffer may
 * not be overwritten merely because a filter returned NGX_OK. HOW: Inspect the
 * buffer cursor and both nginx buffering masks (including TLS output). */
static int
compress_pending(const compress_send_t *st)
{
    return st->output->pos != st->output->last
           || st->r->buffered || st->r->connection->buffered;
}

/* WHAT: Read the next bounded storage chunk; reject premature EOF.
 * WHY: Do not leak bytes appended past the stat'd representation or bless a
 * truncated file as a complete compressed object. HOW: Read through the VFS
 * seam, limiting each read to the original remaining size. */
static ngx_int_t
compress_read_chunk(compress_send_t *st)
{
    off_t  remaining = st->size - st->off;
    size_t want = remaining > BRIX_COMPRESS_CHUNK
                  ? BRIX_COMPRESS_CHUNK : (size_t) remaining;
    size_t got = 0;

    if (brix_vfs_pread_full(st->fd, st->inbuf, want, st->off, &got) != NGX_OK
        || got != want)
    {
        return NGX_ERROR;
    }
    st->off += (off_t) got;
    st->fill = got;
    st->ip = 0;
    st->finish = st->off == st->size;
    return NGX_OK;
}

/* WHAT: Advance the codec once, emitting only initialized output bytes.
 * WHY: Preserve partial input across backpressure and refuse a stuck codec.
 * HOW: Keep its cursor in request storage, count produced bytes and mark EOF
 * only when the codec reports END, not just when it consumed the final input. */
static ngx_int_t
compress_codec_step(compress_send_t *st)
{
    size_t          op = 0, before = st->ip;
    brix_codec_rc_t  rc;

    rc = brix_codec_step(st->stream, st->inbuf, st->fill, &st->ip,
        st->output->start, BRIX_COMPRESS_CHUNK, &op, st->finish);
    if (rc < 0 || (rc != BRIX_CODEC_END && op == 0 && before == st->ip)) {
        return NGX_ERROR;
    }
    st->bytes += (off_t) op;
    st->ended = rc == BRIX_CODEC_END;
    if (op > 0 || st->ended) {
        return compress_emit(st, op);
    }
    return NGX_OK;
}

/* WHAT: Pump until complete, backpressured, or failed. WHY: Bound live output
 * memory independently of file size and reader speed. HOW: Drain the one pending
 * buffer before reading/encoding another; NGX_AGAIN preserves all cursors. */
static ngx_int_t
compress_stream_body(compress_send_t *st)
{
    ngx_int_t rc;

    for (;;) {
        if (compress_pending(st)) {
            rc = ngx_http_output_filter(st->r, NULL);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }
            if (rc == NGX_AGAIN || compress_pending(st)) {
                return NGX_AGAIN;
            }
        }
        if (st->ended) {
            return NGX_OK;
        }
        if (st->ip == st->fill && !st->finish
            && compress_read_chunk(st) != NGX_OK)
        {
            return NGX_ERROR;
        }
        rc = compress_codec_step(st);
        if (rc != NGX_OK) {
            return rc;
        }
    }
}

/* WHAT: Rearm native write readiness and the configured send timeout.
 * WHY: Slow readers must neither truncate a response nor keep a worker spinning.
 * HOW: Respect an output filter's existing rate-limit delay/timer. */
static ngx_int_t
compress_arm_write(ngx_http_request_t *r)
{
    ngx_event_t              *wev = r->connection->write;
    ngx_http_core_loc_conf_t *cf;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (ngx_handle_write_event(wev, cf->send_lowat) != NGX_OK) {
        return NGX_ERROR;
    }
    if (!wev->ready && !wev->delayed) {
        ngx_add_timer(wev, cf->send_timeout);
    }
    return NGX_OK;
}

/* WHAT: Complete or resume a parked compressed response on the event loop.
 * WHY: NGX_AGAIN means the socket will become writable, not a fatal send error.
 * HOW: Resume the request-owned pump; one completion balances its held request
 * reference, while request cleanup also covers disconnect/error finalization. */
static void
compress_write_handler(ngx_http_request_t *r)
{
    compress_send_t  *st = compress_state(r);
    ngx_event_t      *wev = r->connection->write;
    ngx_int_t         rc;

    if (st == NULL) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }
    if (wev->timedout && !wev->delayed) {
        r->connection->timedout = 1;
        rc = NGX_HTTP_REQUEST_TIME_OUT;
    } else {
        if (wev->timedout) {
            wev->timedout = 0;
            wev->delayed = 0;
        }
        if (wev->delayed) {
            return;
        }
        rc = compress_stream_body(st);
    }
    if (rc == NGX_AGAIN && compress_arm_write(r) == NGX_OK) {
        return;
    }
    if (rc == NGX_AGAIN) {
        rc = NGX_ERROR;
    }
    compress_cleanup(st);
    r->write_event_handler = ngx_http_request_empty_handler;
    if (st->done != NULL) {
        st->done(r, st->data, st->bytes, rc);
    }
    ngx_http_finalize_request(r, rc);
}

/* WHAT: Create a request-owned sender and its cleanup. WHY: Never retain the
 * caller's stack across asynchronous output. HOW: Allocate just two 64KiB
 * buffers; once the cleanup is armed it owns the fd on every return path. */
static compress_send_t *
compress_create(ngx_http_request_t *r, ngx_fd_t fd, off_t size,
    brix_codec_id_t codec)
{
    ngx_http_cleanup_t *cln = ngx_http_cleanup_add(r, sizeof(compress_send_t));
    compress_send_t    *st;

    if (cln == NULL) {
        ngx_close_file(fd);
        return NULL;
    }
    st = cln->data;
    ngx_memzero(st, sizeof(*st));
    st->r = r;
    st->fd = fd;
    st->size = size;
    cln->handler = compress_cleanup;
    st->stream = brix_codec_open(codec, BRIX_CODEC_DIR_COMPRESS, -1, NULL);
    st->inbuf = ngx_palloc(r->pool, BRIX_COMPRESS_CHUNK);
    st->output = ngx_create_temp_buf(r->pool, BRIX_COMPRESS_CHUNK);
    if (st->stream == NULL || st->inbuf == NULL || st->output == NULL) {
        compress_cleanup(st);
        return NULL;
    }
    return st;
}

ngx_int_t
brix_http_send_file_compressed(ngx_http_request_t *r, ngx_fd_t send_fd,
    const char *fs_path, off_t size, brix_codec_id_t codec, time_t mtime,
    unsigned etag_flags, off_t *bytes_in_out,
    brix_http_compress_done_fn done, void *data)
{
    const brix_codec_desc_t *desc = brix_codec_by_id(codec);
    compress_send_t         *st;
    ngx_int_t                rc;

    (void) fs_path;
    if (desc == NULL || !desc->available || size < 0) {
        ngx_close_file(send_fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Headers: 200 + ETag/Last-Modified, then force chunked + Content-Encoding. */
    if (compress_set_headers(r, desc, size, mtime, etag_flags) != NGX_OK) {
        ngx_close_file(send_fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    st = compress_create(r, send_fd, size, codec);
    if (st == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    st->done = done;
    st->data = data;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        compress_cleanup(st);
        return rc;
    }
    rc = compress_stream_body(st);
    if (rc == NGX_AGAIN) {
        if (compress_arm_write(r) != NGX_OK) {
            compress_cleanup(st);
            return NGX_ERROR;
        }
        r->write_event_handler = compress_write_handler;
        r->main->count++;
        return NGX_DONE;
    }
    if (bytes_in_out != NULL) {
        *bytes_in_out = st->bytes;
    }
    compress_cleanup(st);
    return rc;
}
