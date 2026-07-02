/*
 * aws_chunked.c — AWS streaming (aws-chunked) request-body decoder (phase-43 W0).
 *
 * See aws_chunked.h for the wire format and rationale.  This is a streaming
 * state machine: it pulls the request-body chain buffer-by-buffer (spooled
 * buffers are read in 64 KiB windows) so a large upload never lands fully in
 * RAM, and pwrites only decoded payload bytes to the destination fd.
 */

#include "aws_chunked.h"
#include "fs/vfs/vfs.h"   /* xrootd_vfs_pread_full / pwrite_full (storage seam) */
#include "s3.h"
#include "core/http/http_headers.h"
#include "core/compat/crypto.h"
#include "core/compat/hex.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* S3_CHUNK_READ_WINDOW is defined in aws_chunked.h (shared with the offload). */
#define S3_CHUNK_MAX_LINE      512          /* size line / trailer line cap */
#define S3_CHUNK_EXT_MAX       128          /* chunk-signature extension cap */

/* SHA-256 of the empty string — the constant payload-hash slot in the
 * AWS4-HMAC-SHA256-PAYLOAD string-to-sign. */
static const char S3_EMPTY_SHA256_HEX[] =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/* Chunk framing parser states. */
typedef enum {
    ST_SIZE = 0,    /* reading hex chunk size            */
    ST_EXT,         /* skipping ;chunk-signature=... ext */
    ST_SIZE_LF,     /* expecting LF after size CR        */
    ST_DATA,        /* copying payload bytes             */
    ST_DATA_CR,     /* expecting CR after payload        */
    ST_DATA_LF,     /* expecting LF after payload CR     */
    ST_TRAILER,     /* reading trailer lines             */
    ST_DONE,        /* terminal blank line consumed      */
    ST_ERROR
} s3_chunk_state_t;

typedef struct {
    s3_chunk_state_t  state;
    ngx_fd_t          fd;
    const char       *log_path;
    ngx_log_t        *log;

    uint64_t          cur_size;       /* size accumulator                  */
    int               size_digits;    /* saw at least one hex digit        */
    uint64_t          chunk_remaining;/* payload bytes left in this chunk  */
    uint64_t          total_decoded;  /* running decoded byte count        */
    uint64_t          expected;       /* x-amz-decoded-content-length      */
    off_t             write_off;      /* next pwrite offset                */

    char              line[S3_CHUNK_MAX_LINE];
    size_t            line_len;

    s3_chunk_trailer_t *trailer;
    int               http_status;    /* set when state -> ST_ERROR        */

    /* W6a: per-chunk SigV4 verification (verify != 0). */
    int               verify;
    const s3_chunk_verify_t *vctx;    /* signing key, scope, amz_date       */
    void             *sha;            /* streaming SHA-256 of current chunk  */
    char              prev_sig[65];   /* previous chunk signature (seed 1st) */
    char              ext[S3_CHUNK_EXT_MAX]; /* current chunk header ext     */
    size_t            ext_len;
} s3_chunk_ctx_t;

static void s3_chunk_fail(s3_chunk_ctx_t *c, int status);

/* Constant-time equality for two equal-length hex strings. */
static int
s3_ct_eq(const char *a, const char *b, size_t n)
{
    unsigned char d = 0;
    size_t        i;
    for (i = 0; i < n; i++) {
        d |= (unsigned char) (a[i] ^ b[i]);
    }
    return d == 0;
}

/* Extract the 64-hex chunk-signature from an accumulated chunk-extension
 * ("chunk-signature=<64hex>").  Returns 1 + writes out[65] on success. */
static int
s3_chunk_ext_signature(const char *ext, size_t len, char out[65])
{
    static const char key[] = "chunk-signature=";
    const size_t      keyn = sizeof(key) - 1;
    size_t            i, j;

    for (i = 0; i + keyn <= len; i++) {
        if (ngx_strncasecmp((u_char *) ext + i, (u_char *) key, keyn) != 0) {
            continue;
        }
        if (len - i - keyn < 64) {
            return 0;
        }
        for (j = 0; j < 64; j++) {
            char ch = ext[i + keyn + j];
            int  hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')
                       || (ch >= 'A' && ch <= 'F');
            if (!hex) {
                return 0;
            }
            out[j] = ch;
        }
        out[64] = '\0';
        return 1;
    }
    return 0;
}

/*
 * Verify the just-completed chunk's signature.  `c->sha` is finalised over the
 * chunk's payload, the AWS4-HMAC-SHA256-PAYLOAD string-to-sign is built with the
 * rolling previous signature, and the HMAC is constant-time compared with the
 * client-provided chunk-signature.  Returns 0 on match (and advances prev_sig);
 * on mismatch/error sets ST_ERROR with the right status and returns -1.
 */
static int
s3_chunk_verify(s3_chunk_ctx_t *c)
{
    char    provided[65];
    u_char  chunk_hash[32];
    char    chunk_hash_hex[65];
    u_char  mac[32];
    char    computed[65];
    u_char  sts[64 + sizeof(c->vctx->amz_date) + sizeof(c->vctx->scope) + 256];
    u_char *p;

    if (!s3_chunk_ext_signature(c->ext, c->ext_len, provided)) {
        s3_chunk_fail(c, NGX_HTTP_FORBIDDEN);
        return -1;
    }
    if (!xrootd_sha256_stream_final(c->sha, chunk_hash)) {
        s3_chunk_fail(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return -1;
    }
    xrootd_hex_encode(chunk_hash, 32, chunk_hash_hex);

    p = ngx_snprintf(sts, sizeof(sts),
                     "AWS4-HMAC-SHA256-PAYLOAD\n%s\n%s\n%s\n%s\n%s",
                     c->vctx->amz_date, c->vctx->scope, c->prev_sig,
                     S3_EMPTY_SHA256_HEX, chunk_hash_hex);

    if (!xrootd_hmac_sha256(c->vctx->signing_key, 32, sts,
                            (size_t) (p - sts), mac)) {
        s3_chunk_fail(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return -1;
    }
    xrootd_hex_encode(mac, 32, computed);

    if (!s3_ct_eq(computed, provided, 64)) {
        s3_chunk_fail(c, NGX_HTTP_FORBIDDEN);   /* SignatureDoesNotMatch */
        return -1;
    }

    ngx_memcpy(c->prev_sig, provided, 65);      /* roll forward */
    return 0;
}

static int
s3_hexdigit(unsigned char c, unsigned *out)
{
    if (c >= '0' && c <= '9') { *out = c - '0'; return 1; }
    if (c >= 'a' && c <= 'f') { *out = c - 'a' + 10; return 1; }
    if (c >= 'A' && c <= 'F') { *out = c - 'A' + 10; return 1; }
    return 0;
}

static void
s3_chunk_fail(s3_chunk_ctx_t *c, int status)
{
    c->state = ST_ERROR;
    c->http_status = status;
}

/* Write decoded payload, enforcing the declared decoded length as an upper
 * bound so a malformed stream cannot overrun. */
static int
s3_chunk_emit(s3_chunk_ctx_t *c, const u_char *p, size_t n)
{
    if (c->total_decoded + n > c->expected) {
        s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST);   /* more data than declared */
        return -1;
    }
    /* Write the decoded chunk through the storage seam (handles EINTR/short
     * writes); a failure fails the whole upload. */
    if (xrootd_vfs_pwrite_full(c->fd, p, n, c->write_off) != NGX_OK) {
        s3_chunk_fail(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return -1;
    }
    c->write_off     += (off_t) n;
    c->total_decoded += (uint64_t) n;
    return 0;
}

/* Parse a completed trailer line "name:value" and capture an x-amz-checksum-*. */
static void
s3_chunk_trailer_line(s3_chunk_ctx_t *c)
{
    static const char pfx[] = "x-amz-checksum-";
    const size_t      pfxn = sizeof(pfx) - 1;
    char             *colon;
    size_t            namelen, i;

    if (c->trailer == NULL || c->line_len <= pfxn) {
        return;
    }
    if (ngx_strncasecmp((u_char *) c->line, (u_char *) pfx, pfxn) != 0) {
        return;
    }
    colon = memchr(c->line, ':', c->line_len);
    if (colon == NULL) {
        return;
    }
    namelen = (size_t) (colon - c->line);
    if (namelen <= pfxn || (namelen - pfxn) >= sizeof(c->trailer->algo_token)) {
        return;
    }

    for (i = 0; i < namelen - pfxn; i++) {
        c->trailer->algo_token[i] = (char) ngx_tolower(c->line[pfxn + i]);
    }
    c->trailer->algo_token[namelen - pfxn] = '\0';

    {
        size_t vlen = c->line_len - namelen - 1;          /* after ':' */
        char  *v    = colon + 1;
        while (vlen > 0 && (*v == ' ' || *v == '\t')) { v++; vlen--; }
        if (vlen >= sizeof(c->trailer->value)) {
            vlen = sizeof(c->trailer->value) - 1;
        }
        ngx_memcpy(c->trailer->value, v, vlen);
        c->trailer->value[vlen] = '\0';
    }
}

/* Feed one contiguous span through the state machine. Returns -1 on error. */
static int
s3_chunk_feed(s3_chunk_ctx_t *c, const u_char *p, const u_char *end)
{
    while (p < end && c->state != ST_DONE && c->state != ST_ERROR) {
        u_char ch = *p;

        switch (c->state) {

        case ST_SIZE: {
            unsigned v;
            if (s3_hexdigit(ch, &v)) {
                if (c->cur_size > (UINT64_MAX >> 4)) {
                    s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST);
                    return -1;
                }
                c->cur_size = (c->cur_size << 4) | v;
                c->size_digits = 1;
                p++;
            } else if (ch == ';') {
                c->state = ST_EXT; p++;
            } else if (ch == '\r') {
                if (!c->size_digits) { s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST); return -1; }
                c->state = ST_SIZE_LF; p++;
            } else {
                s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST); return -1;
            }
            break;
        }

        case ST_EXT:
            /* Capture the chunk-signature extension (W6a verify) or, when
             * verification is off, skip it to CR (legacy behaviour). */
            if (ch == '\r') {
                c->state = ST_SIZE_LF;
            } else if (c->verify && c->ext_len < sizeof(c->ext)) {
                c->ext[c->ext_len++] = (char) ch;
            }
            p++;
            break;

        case ST_SIZE_LF:
            if (ch != '\n') { s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST); return -1; }
            p++;
            c->chunk_remaining = c->cur_size;
            if (c->cur_size == 0) {
                /* Terminating 0-chunk: its signature covers the empty payload. */
                if (c->verify && s3_chunk_verify(c) != 0) { return -1; }
                c->state = ST_TRAILER;       /* last chunk */
                c->line_len = 0;
            } else {
                c->state = ST_DATA;
            }
            c->cur_size = 0;
            c->size_digits = 0;
            break;

        case ST_DATA: {
            size_t avail = (size_t) (end - p);
            size_t take  = (c->chunk_remaining < avail) ? (size_t) c->chunk_remaining
                                                        : avail;
            if (take > 0) {
                if (c->verify
                    && !xrootd_sha256_stream_update(c->sha, p, take))
                {
                    s3_chunk_fail(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return -1;
                }
                if (s3_chunk_emit(c, p, take) != 0) { return -1; }
                p += take;
                c->chunk_remaining -= take;
            }
            if (c->chunk_remaining == 0) {
                /* All payload of this chunk is hashed — verify its signature. */
                if (c->verify && s3_chunk_verify(c) != 0) { return -1; }
                c->state = ST_DATA_CR;
            }
            break;
        }

        case ST_DATA_CR:
            if (ch != '\r') { s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST); return -1; }
            c->state = ST_DATA_LF; p++;
            break;

        case ST_DATA_LF:
            if (ch != '\n') { s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST); return -1; }
            c->state = ST_SIZE; c->ext_len = 0; p++;   /* reset ext for next hdr */
            break;

        case ST_TRAILER:
            if (ch == '\n') {
                /* Strip a trailing CR, then process the completed line. */
                if (c->line_len > 0 && c->line[c->line_len - 1] == '\r') {
                    c->line_len--;
                }
                if (c->line_len == 0) {
                    c->state = ST_DONE;     /* blank line terminates */
                } else {
                    s3_chunk_trailer_line(c);
                    c->line_len = 0;
                }
                p++;
            } else {
                if (c->line_len < sizeof(c->line)) {
                    c->line[c->line_len++] = (char) ch;
                }
                p++;   /* overlong trailer lines are truncated, not fatal */
            }
            break;

        default:
            p++;
            break;
        }
    }
    return (c->state == ST_ERROR) ? -1 : 0;
}

int
s3_body_is_aws_chunked(ngx_http_request_t *r)
{
    ngx_table_elt_t *h;

    h = xrootd_http_find_header(r, "x-amz-content-sha256",
                                sizeof("x-amz-content-sha256") - 1);
    if (h != NULL && h->value.len >= sizeof("STREAMING-") - 1
        && ngx_strncmp(h->value.data, (u_char *) "STREAMING-",
                       sizeof("STREAMING-") - 1) == 0)
    {
        return 1;
    }

    h = xrootd_http_find_header(r, "Content-Encoding",
                                sizeof("Content-Encoding") - 1);
    if (h != NULL && h->value.len >= sizeof("aws-chunked") - 1) {
        /* aws-chunked may appear alone or combined (e.g. "aws-chunked,gzip"). */
        size_t i, n = h->value.len - (sizeof("aws-chunked") - 1);
        for (i = 0; i <= n; i++) {
            if (ngx_strncasecmp(h->value.data + i, (u_char *) "aws-chunked",
                                sizeof("aws-chunked") - 1) == 0)
            {
                return 1;
            }
        }
    }
    return 0;
}

int
s3_aws_chunked_has_inner_coding(ngx_http_request_t *r)
{
    ngx_table_elt_t *h = xrootd_http_find_header(r, "Content-Encoding",
                                                 sizeof("Content-Encoding") - 1);
    const u_char    *p, *end;

    if (h == NULL || h->value.len == 0) {
        return 0;
    }
    p   = h->value.data;
    end = p + h->value.len;

    /* Walk comma-separated content-codings; any token that is neither
     * "aws-chunked" nor "identity" (nor empty) is an inner content-coding the
     * streaming path cannot decode. */
    while (p < end) {
        const u_char *tok, *tend;
        size_t        len;

        while (p < end && (*p == ' ' || *p == ',' || *p == '\t')) { p++; }
        tok = p;
        while (p < end && *p != ',') { p++; }
        tend = p;
        while (tend > tok && (tend[-1] == ' ' || tend[-1] == '\t')) { tend--; }
        len = (size_t) (tend - tok);
        if (len == 0) {
            continue;
        }
        if (len == sizeof("aws-chunked") - 1
            && ngx_strncasecmp((u_char *) tok, (u_char *) "aws-chunked", len) == 0) {
            continue;
        }
        if (len == sizeof("identity") - 1
            && ngx_strncasecmp((u_char *) tok, (u_char *) "identity", len) == 0) {
            continue;
        }
        return 1;   /* a real inner content-coding (gzip/zstd/...) is present */
    }
    return 0;
}

/* Feed one request-body buffer (memory or spooled) into the decoder. */
static int
s3_chunk_feed_buf(s3_chunk_ctx_t *c, ngx_buf_t *b, u_char *window)
{
    if (ngx_buf_in_memory(b)) {
        return s3_chunk_feed(c, b->pos, b->last);
    }

    if (b->in_file) {
        off_t off = b->file_pos;

        while (off < b->file_last && c->state != ST_DONE
               && c->state != ST_ERROR)
        {
            off_t  want = b->file_last - off;
            size_t got  = 0;
            if (want > S3_CHUNK_READ_WINDOW) {
                want = S3_CHUNK_READ_WINDOW;
            }
            /* One window through the storage seam (EINTR/short-read handled). */
            if (xrootd_vfs_pread_full(b->file->fd, window, (size_t) want, off,
                                      &got) != NGX_OK)
            {
                s3_chunk_fail(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return -1;
            }
            if (got == 0) {
                break;
            }
            if (s3_chunk_feed(c, window, window + got) != 0) {
                return -1;
            }
            off += (off_t) got;
        }
    }
    return (c->state == ST_ERROR) ? -1 : 0;
}

ngx_int_t
s3_aws_chunked_decode_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, uint64_t decoded_len_expected,
    s3_chunk_trailer_t *trailer, int *http_status_out, u_char *window,
    const s3_chunk_verify_t *verify)
{
    s3_chunk_ctx_t  c;
    ngx_chain_t    *cl;
    ngx_int_t       rc = NGX_OK;

    ngx_memzero(&c, sizeof(c));
    c.state     = ST_SIZE;
    c.fd        = dst_fd;
    c.log_path  = log_path;
    c.log       = r->connection->log;
    c.expected  = decoded_len_expected;
    c.trailer   = trailer;
    if (trailer != NULL) {
        trailer->algo_token[0] = '\0';
        trailer->value[0] = '\0';
    }

    /* W6a: arm per-chunk verification; the seed signature is the first chunk's
     * previous-signature.  The streaming SHA-256 handle hashes each chunk's
     * payload (works on the worker thread — per-ctx, no shared state). */
    if (verify != NULL && verify->enabled) {
        c.verify = 1;
        c.vctx   = verify;
        ngx_cpystrn((u_char *) c.prev_sig, (u_char *) verify->seed_signature,
                    sizeof(c.prev_sig));
        c.sha = xrootd_sha256_stream_new();
        if (c.sha == NULL) {
            *http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_ERROR;
        }
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        /* An empty streamed body is only valid when 0 bytes were declared. */
        if (decoded_len_expected != 0) {
            *http_status_out = NGX_HTTP_BAD_REQUEST;
            rc = NGX_ERROR;
        }
        xrootd_sha256_stream_free(c.sha);   /* NULL-safe when verify off */
        return rc;
    }

    /* The caller may pass a pre-allocated scratch window (the offload path does,
     * so the worker thread never touches r->pool); otherwise allocate one. */
    if (window == NULL) {
        window = ngx_palloc(r->pool, S3_CHUNK_READ_WINDOW);
        if (window == NULL) {
            *http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR;
            xrootd_sha256_stream_free(c.sha);
            return NGX_ERROR;
        }
    }

    for (cl = r->request_body->bufs; cl != NULL && rc == NGX_OK; cl = cl->next) {
        if (s3_chunk_feed_buf(&c, cl->buf, window) != 0) {
            *http_status_out = c.http_status;
            rc = NGX_ERROR;
        }
    }

    /* The stream must have reached the terminating blank line and produced
     * exactly the declared number of decoded bytes. */
    if (rc == NGX_OK
        && (c.state != ST_DONE || c.total_decoded != decoded_len_expected))
    {
        *http_status_out = NGX_HTTP_BAD_REQUEST;
        rc = NGX_ERROR;
    }

    xrootd_sha256_stream_free(c.sha);
    return rc;
}
