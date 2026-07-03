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

/* Is `token` (len) present as an acceptable coding in the Accept-Encoding value
 * (case-insensitive, ignoring an explicit ";q=0")? */
static int
accept_encoding_has(const u_char *ae, size_t ae_len, const char *token)
{
    size_t tlen = ngx_strlen(token);
    const u_char *p = ae, *end = ae + ae_len;

    while (p < end) {
        const u_char *comma, *semi, *tok_end;
        size_t        seg_len;

        /* skip inter-member OWS — RFC 7230 permits SP and HTAB around list members */
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) { p++; }
        comma = ngx_strlchr((u_char *) p, (u_char *) end, ',');
        tok_end = comma ? comma : end;
        seg_len = (size_t) (tok_end - p);
        /* token name is up to ';' (q-value) or whitespace */
        semi = ngx_strlchr((u_char *) p, (u_char *) tok_end, ';');
        {
            const u_char *name_end = semi ? semi : tok_end;
            while (name_end > p && (name_end[-1] == ' ' || name_end[-1] == '\t')) {
                name_end--;
            }
            if ((size_t) (name_end - p) == tlen
                && ngx_strncasecmp((u_char *) p, (u_char *) token, tlen) == 0)
            {
                /* reject explicit q=0 in any of its exactly-zero spellings:
                 * "q=0", "q=0.", "q=0.0", "q=0.00", "q=0.000" (RFC 7231 5.3.1).
                 * Accept only a q-value with a NONZERO fractional digit (q=0.x). */
                if (semi != NULL) {
                    const u_char *q = ngx_strlcasestrn((u_char *) semi,
                        (u_char *) tok_end, (u_char *) "q=0", 3 - 1);
                    if (q != NULL) {
                        const u_char *after = q + 3;     /* first char past "q=0" */
                        int nonzero = 0;
                        if (after < tok_end && *after == '.') {
                            const u_char *d = after + 1;
                            /* scan the fractional digits; any non-'0' => q>0 */
                            while (d < tok_end && *d >= '0' && *d <= '9') {
                                if (*d != '0') { nonzero = 1; break; }
                                d++;
                            }
                        }
                        if (!nonzero) {           /* q=0 / q=0. / q=0.0[00] => reject */
                            p = tok_end;
                            (void) seg_len;
                            continue;
                        }
                    }
                }
                return 1;
            }
        }
        p = tok_end;
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

ngx_int_t
brix_http_send_file_compressed(ngx_http_request_t *r, ngx_fd_t send_fd,
    const char *fs_path, off_t size, brix_codec_id_t codec, time_t mtime,
    unsigned etag_flags, off_t *bytes_in_out)
{
    const brix_codec_desc_t *desc = brix_codec_by_id(codec);
    brix_codec_stream_t     *s;
    ngx_table_elt_t           *ce, *vary;
    u_char                    *inbuf, *outbuf;
    off_t                      off = 0;
    ngx_int_t                  rc;
    int                        done = 0;

    (void) fs_path;
    if (desc == NULL || !desc->available) {
        ngx_close_file(send_fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Headers: 200 + ETag/Last-Modified, then force chunked + Content-Encoding. */
    if (brix_http_set_file_headers(r, mtime, size, size, NULL, etag_flags,
                                     0, 0, size > 0 ? size - 1 : 0) != NGX_OK)
    {
        ngx_close_file(send_fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.content_length_n = -1;        /* unknown -> chunked */
    if (r->headers_out.content_length != NULL) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ce = ngx_list_push(&r->headers_out.headers);
    vary = ngx_list_push(&r->headers_out.headers);
    if (ce == NULL || vary == NULL) {
        ngx_close_file(send_fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ce->hash = 1;
    ngx_str_set(&ce->key, "Content-Encoding");
    ce->value.data = (u_char *) desc->http_token;
    ce->value.len  = ngx_strlen(desc->http_token);
    vary->hash = 1;
    ngx_str_set(&vary->key, "Vary");
    ngx_str_set(&vary->value, "Accept-Encoding");

    s = brix_codec_open(codec, BRIX_CODEC_DIR_COMPRESS, -1, NULL);
    inbuf  = ngx_palloc(r->pool, BRIX_COMPRESS_CHUNK);
    outbuf = ngx_palloc(r->pool, BRIX_COMPRESS_CHUNK);
    if (s == NULL || inbuf == NULL || outbuf == NULL) {
        if (s) { brix_codec_close(s); }
        ngx_close_file(send_fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_send_header(r) == NGX_ERROR) {
        brix_codec_close(s);
        ngx_close_file(send_fd);
        return NGX_ERROR;
    }

    rc = NGX_OK;
    while (!done) {
        size_t  ip = 0, fill = 0;
        size_t  got = 0;
        int     finish;

        /* One full chunk through the storage seam (EINTR/short-read handled by
         * the primitive); a short fill means EOF and ends the stream. */
        if (brix_vfs_pread_full(send_fd, inbuf, BRIX_COMPRESS_CHUNK, off,
                                  &got) != NGX_OK)
        {
            rc = NGX_ERROR; break;
        }
        if (got > 0) { off += (off_t) got; fill = got; }
        finish = (off >= size) || (got == 0);

        for (;;) {
            size_t            op = 0;
            brix_codec_rc_t crc;

            crc = brix_codec_step(s, inbuf, fill, &ip, outbuf,
                                    BRIX_COMPRESS_CHUNK, &op, finish);
            if (crc < 0) { rc = NGX_ERROR; done = 1; break; }
            if (bytes_in_out) { *bytes_in_out += (off_t) op; }
            if (crc == BRIX_CODEC_END) {
                if (compress_emit(r, outbuf, op, 1) != NGX_OK) { rc = NGX_ERROR; }
                done = 1;
                break;
            }
            if (op > 0) {
                if (compress_emit(r, outbuf, op, 0) != NGX_OK) {
                    rc = NGX_ERROR; done = 1; break;
                }
            }
            if (op == BRIX_COMPRESS_CHUNK) { continue; }   /* drain more */
            if (ip < fill) { continue; }
            break;                       /* chunk consumed; read next */
        }
    }

    brix_codec_close(s);
    ngx_close_file(send_fd);
    return rc;
}
