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

/* Push one memory buffer of [data,len) to the output filter; last marks EOF. */
static ngx_int_t
compress_emit(ngx_http_request_t *r, const u_char *data, size_t len, int last)
{
    ngx_buf_t   *b;
    ngx_chain_t  out;

    b = ngx_create_temp_buf(r->pool, len > 0 ? len : 1);
    if (b == NULL) {
        return NGX_ERROR;
    }
    if (len > 0) {
        ngx_memcpy(b->pos, data, len);
        b->last = b->pos + len;
    } else {
        b->last = b->pos;
    }
    b->memory   = 0;
    b->temporary = 1;
    b->flush    = 1;
    b->last_buf = last ? 1 : 0;
    b->last_in_chain = 1;
    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

/*
 * WHAT: file-local state for one compressed send — the fd/codec/buffers plus the
 *       running input offset and the caller's compressed-byte counter.
 * WHY:  lets the read/drain steps be split out as small helpers that take one
 *       `*st` instead of re-threading the eight send parameters (the extern
 *       signature stays frozen; this is the internal bundle only).
 * HOW:  zero-initialised by the orchestrator; `off` advances as chunks are read,
 *       `bytes_in_out` (nullable) accumulates emitted compressed bytes.
 */
typedef struct {
    ngx_http_request_t  *r;
    ngx_fd_t             fd;
    off_t                size;
    off_t                off;
    brix_codec_stream_t *stream;
    u_char              *inbuf;
    u_char              *outbuf;
    off_t               *bytes_in_out;
} compress_send_t;

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

/*
 * WHAT: drain the codec for the chunk currently in `st->inbuf` ([0,fill)), pushing
 *       every compressed output buffer to the filter; `finish` flushes at EOF.
 * WHY:  the inner compress/emit loop is the densest branching in the sender; as a
 *       named helper it is independently reviewable and the outer loop stays flat.
 * HOW:  step the codec until the chunk is consumed (or END at finish); emit each
 *       non-empty output; accumulate emitted bytes. Sets `*ended` on codec END.
 *       Returns NGX_OK on progress, NGX_ERROR on a codec/emit failure.
 */
static ngx_int_t
compress_drain_chunk(compress_send_t *st, size_t fill, int finish, int *ended)
{
    size_t ip = 0;

    for (;;) {
        size_t          op  = 0;
        brix_codec_rc_t crc;

        crc = brix_codec_step(st->stream, st->inbuf, fill, &ip, st->outbuf,
                                BRIX_COMPRESS_CHUNK, &op, finish);
        if (crc < 0) {
            return NGX_ERROR;
        }
        if (st->bytes_in_out) { *st->bytes_in_out += (off_t) op; }
        if (crc == BRIX_CODEC_END) {
            *ended = 1;
            return compress_emit(st->r, st->outbuf, op, 1);
        }
        if (op > 0 && compress_emit(st->r, st->outbuf, op, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        if (op == BRIX_COMPRESS_CHUNK) { continue; }   /* drain more */
        if (ip < fill) { continue; }
        return NGX_OK;                   /* chunk consumed; read next */
    }
}

/*
 * WHAT: read one storage chunk into `st->inbuf` and drain it through the codec.
 * WHY:  one read+drain iteration as a helper turns the send loop into a flat
 *       `while (!done) { step; }` with no nested read/compress branching.
 * HOW:  pread a full chunk via the storage seam (EINTR/short-read handled by the
 *       primitive); a short fill means EOF; advance `off` and drain. Sets `*done`
 *       when the codec signals END. Returns NGX_OK / NGX_ERROR.
 */
static ngx_int_t
compress_stream_step(compress_send_t *st, int *done)
{
    size_t got = 0;
    size_t fill;
    int    finish;

    if (brix_vfs_pread_full(st->fd, st->inbuf, BRIX_COMPRESS_CHUNK, st->off,
                              &got) != NGX_OK)
    {
        return NGX_ERROR;
    }
    fill = got;
    if (got > 0) { st->off += (off_t) got; }
    finish = (st->off >= st->size) || (got == 0);
    return compress_drain_chunk(st, fill, finish, done);
}

/*
 * WHAT: run the read -> codec -> output-filter stream until the codec ends or an
 *       error occurs (headers already sent, buffers/stream already open).
 * WHY:  separates the loop driver from the one-time setup so each is short.
 * HOW:  iterate compress_stream_step until it flags done or returns NGX_ERROR.
 */
static ngx_int_t
compress_stream_body(compress_send_t *st)
{
    int done = 0;

    while (!done) {
        if (compress_stream_step(st, &done) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

ngx_int_t
brix_http_send_file_compressed(ngx_http_request_t *r, ngx_fd_t send_fd,
    const char *fs_path, off_t size, brix_codec_id_t codec, time_t mtime,
    unsigned etag_flags, off_t *bytes_in_out)
{
    const brix_codec_desc_t *desc = brix_codec_by_id(codec);
    compress_send_t          st = {0};
    ngx_int_t                rc;

    (void) fs_path;
    if (desc == NULL || !desc->available) {
        ngx_close_file(send_fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Headers: 200 + ETag/Last-Modified, then force chunked + Content-Encoding. */
    if (compress_set_headers(r, desc, size, mtime, etag_flags) != NGX_OK) {
        ngx_close_file(send_fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    st.r            = r;
    st.fd           = send_fd;
    st.size         = size;
    st.bytes_in_out = bytes_in_out;
    st.stream = brix_codec_open(codec, BRIX_CODEC_DIR_COMPRESS, -1, NULL);
    st.inbuf  = ngx_palloc(r->pool, BRIX_COMPRESS_CHUNK);
    st.outbuf = ngx_palloc(r->pool, BRIX_COMPRESS_CHUNK);
    if (st.stream == NULL || st.inbuf == NULL || st.outbuf == NULL) {
        if (st.stream) { brix_codec_close(st.stream); }
        ngx_close_file(send_fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_send_header(r) == NGX_ERROR) {
        brix_codec_close(st.stream);
        ngx_close_file(send_fd);
        return NGX_ERROR;
    }

    rc = compress_stream_body(&st);

    brix_codec_close(st.stream);
    ngx_close_file(send_fd);
    return rc;
}
