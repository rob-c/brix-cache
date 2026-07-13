/*
 * aws_chunked.c — AWS streaming (aws-chunked) request-body decoder (phase-43 W0).
 *
 * See aws_chunked.h for the wire format and rationale.  This is a streaming
 * state machine: it pulls the request-body chain buffer-by-buffer (spooled
 * buffers are read in 64 KiB windows) so a large upload never lands fully in
 * RAM, and pwrites only decoded payload bytes to the destination fd.
 */

#include "aws_chunked.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_pread_full / pwrite_full (storage seam) */
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
    if (!brix_sha256_stream_final(c->sha, chunk_hash)) {
        s3_chunk_fail(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return -1;
    }
    brix_hex_encode(chunk_hash, 32, chunk_hash_hex);

    p = ngx_snprintf(sts, sizeof(sts),
                     "AWS4-HMAC-SHA256-PAYLOAD\n%s\n%s\n%s\n%s\n%s",
                     c->vctx->amz_date, c->vctx->scope, c->prev_sig,
                     S3_EMPTY_SHA256_HEX, chunk_hash_hex);

    if (!brix_hmac_sha256(c->vctx->signing_key, 32, sts,
                            (size_t) (p - sts), mac)) {
        s3_chunk_fail(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return -1;
    }
    brix_hex_encode(mac, 32, computed);

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
    if (brix_vfs_pwrite_full(c->fd, p, n, c->write_off) != NGX_OK) {
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

/*
 * Per-state step outcome.  A state handler consumes zero or more bytes from the
 * span (advancing *pp) and reports whether the caller should keep looping or
 * stop: STEP_CONT keeps the feed loop running, STEP_ERROR aborts (the handler
 * has already called s3_chunk_fail with the right status).
 */
typedef enum {
    STEP_CONT = 0,
    STEP_ERROR
} s3_chunk_step_t;

/*
 * WHAT: handle one byte in ST_SIZE (hex chunk-size line).
 * WHY:  isolates the size-accumulator/overflow/terminator logic from the feed
 *       loop so each transition is independently reviewable.
 * HOW:  a hex digit shifts it into cur_size (guarding UINT64 overflow); ';'
 *       opens the extension; CR (after >=1 digit) moves to the LF wait; anything
 *       else is a malformed size line.  Advances *pp by exactly one byte.
 */
static s3_chunk_step_t
chunk_scan_size_line(s3_chunk_ctx_t *c, u_char ch, const u_char **pp)
{
    unsigned v;

    if (s3_hexdigit(ch, &v)) {
        if (c->cur_size > (UINT64_MAX >> 4)) {
            s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST);
            return STEP_ERROR;
        }
        c->cur_size = (c->cur_size << 4) | v;
        c->size_digits = 1;
        (*pp)++;
        return STEP_CONT;
    }
    if (ch == ';') {
        c->state = ST_EXT;
        (*pp)++;
        return STEP_CONT;
    }
    if (ch == '\r') {
        if (!c->size_digits) {
            s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST);
            return STEP_ERROR;
        }
        c->state = ST_SIZE_LF;
        (*pp)++;
        return STEP_CONT;
    }
    s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST);
    return STEP_ERROR;
}

/*
 * WHAT: handle one byte in ST_EXT (the ";chunk-signature=..." extension).
 * WHY:  keeps the verify-capture-vs-skip decision in one place.
 * HOW:  CR ends the extension (move to LF wait); otherwise, when verification is
 *       on and the buffer has room, append to c->ext; when off, drop the byte.
 *       Always advances *pp by one byte.
 */
static s3_chunk_step_t
chunk_scan_ext_sig(s3_chunk_ctx_t *c, u_char ch, const u_char **pp)
{
    if (ch == '\r') {
        c->state = ST_SIZE_LF;
    } else if (c->verify && c->ext_len < sizeof(c->ext)) {
        c->ext[c->ext_len++] = (char) ch;
    }
    (*pp)++;
    return STEP_CONT;
}

/*
 * WHAT: handle one byte in ST_SIZE_LF (the LF closing the size/ext line).
 * WHY:  the LF is where a chunk header completes, so this is where a 0-chunk
 *       (terminator) branches to the trailer and a non-zero chunk arms payload.
 * HOW:  requires LF; latches chunk_remaining from the parsed size; a zero size
 *       is the terminating chunk (verify its empty-payload signature, go to
 *       trailer); a non-zero size moves to ST_DATA.  Resets the size accumulator.
 */
static s3_chunk_step_t
chunk_scan_size_lf(s3_chunk_ctx_t *c, u_char ch, const u_char **pp)
{
    if (ch != '\n') {
        s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST);
        return STEP_ERROR;
    }
    (*pp)++;
    c->chunk_remaining = c->cur_size;
    if (c->cur_size == 0) {
        /* Terminating 0-chunk: its signature covers the empty payload. */
        if (c->verify && s3_chunk_verify(c) != 0) {
            return STEP_ERROR;
        }
        c->state = ST_TRAILER;       /* last chunk */
        c->line_len = 0;
    } else {
        c->state = ST_DATA;
    }
    c->cur_size = 0;
    c->size_digits = 0;
    return STEP_CONT;
}

/*
 * WHAT: consume payload bytes in ST_DATA for the current chunk.
 * WHY:  the only bulk-copy state — takes as many bytes as are both available and
 *       still owed, streaming them into the SHA (when verifying) and the fd.
 * HOW:  copies min(remaining, available); on chunk exhaustion verifies the
 *       chunk's rolling signature and moves to ST_DATA_CR.  Advances *pp past the
 *       bytes it consumed.
 */
static s3_chunk_step_t
chunk_consume_data(s3_chunk_ctx_t *c, const u_char **pp, const u_char *end)
{
    const u_char *p     = *pp;
    size_t        avail = (size_t) (end - p);
    size_t        take  = (c->chunk_remaining < avail) ? (size_t) c->chunk_remaining
                                                       : avail;

    if (take > 0) {
        if (c->verify && !brix_sha256_stream_update(c->sha, p, take)) {
            s3_chunk_fail(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return STEP_ERROR;
        }
        if (s3_chunk_emit(c, p, take) != 0) {
            return STEP_ERROR;
        }
        p += take;
        c->chunk_remaining -= take;
    }
    if (c->chunk_remaining == 0) {
        /* All payload of this chunk is hashed — verify its signature. */
        if (c->verify && s3_chunk_verify(c) != 0) {
            return STEP_ERROR;
        }
        c->state = ST_DATA_CR;
    }
    *pp = p;
    return STEP_CONT;
}

/*
 * WHAT: handle the CRLF that follows a chunk's payload (ST_DATA_CR/ST_DATA_LF).
 * WHY:  both states are single-byte terminator checks; folding them keeps the
 *       feed loop's dispatch flat without a per-byte helper each.
 * HOW:  ST_DATA_CR requires CR then moves to ST_DATA_LF; ST_DATA_LF requires LF
 *       then returns to ST_SIZE, resetting the extension buffer for the next
 *       header.  Advances *pp by one byte on success.
 */
static s3_chunk_step_t
chunk_scan_data_crlf(s3_chunk_ctx_t *c, u_char ch, const u_char **pp)
{
    if (c->state == ST_DATA_CR) {
        if (ch != '\r') {
            s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST);
            return STEP_ERROR;
        }
        c->state = ST_DATA_LF;
        (*pp)++;
        return STEP_CONT;
    }
    /* ST_DATA_LF */
    if (ch != '\n') {
        s3_chunk_fail(c, NGX_HTTP_BAD_REQUEST);
        return STEP_ERROR;
    }
    c->state = ST_SIZE;
    c->ext_len = 0;                  /* reset ext for next hdr */
    (*pp)++;
    return STEP_CONT;
}

/*
 * WHAT: handle one byte in ST_TRAILER (post-payload trailer lines).
 * WHY:  the terminating blank line and per-line accumulation/truncation policy
 *       live in one place, matching the size/data scanners.
 * HOW:  LF completes a line (strip a trailing CR): an empty line terminates the
 *       stream (ST_DONE), otherwise the completed line is parsed for an
 *       x-amz-checksum-* trailer; non-LF bytes accumulate into c->line and are
 *       truncated (not fatal) past the buffer.  Advances *pp by one byte.
 */
static s3_chunk_step_t
chunk_scan_trailer(s3_chunk_ctx_t *c, u_char ch, const u_char **pp)
{
    if (ch == '\n') {
        /* Strip a trailing CR, then process the completed line. */
        if (c->line_len > 0 && c->line[c->line_len - 1] == '\r') {
            c->line_len--;
        }
        if (c->line_len == 0) {
            c->state = ST_DONE;      /* blank line terminates */
        } else {
            s3_chunk_trailer_line(c);
            c->line_len = 0;
        }
        (*pp)++;
        return STEP_CONT;
    }
    if (c->line_len < sizeof(c->line)) {
        c->line[c->line_len++] = (char) ch;
    }
    (*pp)++;                         /* overlong trailer lines are truncated */
    return STEP_CONT;
}

/*
 * WHAT: dispatch one byte to the handler for the current state.
 * WHY:  turns the feed loop's switch ladder into a flat call, so the loop stays
 *       trivial and each state is decomposed into its own scanner.
 * HOW:  routes by c->state; ST_DATA passes end (it is the only bulk-consumer).
 *       An unknown state simply skips the byte (mirrors the former default).
 */
static s3_chunk_step_t
chunk_feed_step(s3_chunk_ctx_t *c, const u_char **pp, const u_char *end)
{
    u_char ch = **pp;

    switch (c->state) {
    case ST_SIZE:
        return chunk_scan_size_line(c, ch, pp);
    case ST_EXT:
        return chunk_scan_ext_sig(c, ch, pp);
    case ST_SIZE_LF:
        return chunk_scan_size_lf(c, ch, pp);
    case ST_DATA:
        return chunk_consume_data(c, pp, end);
    case ST_DATA_CR:
    case ST_DATA_LF:
        return chunk_scan_data_crlf(c, ch, pp);
    case ST_TRAILER:
        return chunk_scan_trailer(c, ch, pp);
    default:
        (*pp)++;
        return STEP_CONT;
    }
}

/* Feed one contiguous span through the state machine. Returns -1 on error. */
static int
s3_chunk_feed(s3_chunk_ctx_t *c, const u_char *p, const u_char *end)
{
    while (p < end && c->state != ST_DONE && c->state != ST_ERROR) {
        if (chunk_feed_step(c, &p, end) == STEP_ERROR) {
            return -1;
        }
    }
    return (c->state == ST_ERROR) ? -1 : 0;
}

int
s3_body_is_aws_chunked(ngx_http_request_t *r)
{
    ngx_table_elt_t *h;

    h = brix_http_find_header(r, "x-amz-content-sha256",
                                sizeof("x-amz-content-sha256") - 1);
    if (h != NULL && h->value.len >= sizeof("STREAMING-") - 1
        && ngx_strncmp(h->value.data, (u_char *) "STREAMING-",
                       sizeof("STREAMING-") - 1) == 0)
    {
        return 1;
    }

    h = brix_http_find_header(r, "Content-Encoding",
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

/*
 * WHAT: peel the next comma-separated content-coding token off [*pp, end).
 * WHY:  isolates the whitespace/comma tokenisation from the classify loop so the
 *       walker reads as "get token -> classify token".
 * HOW:  skips leading spaces/tabs/commas, spans up to the next comma, trims
 *       trailing whitespace, and reports the trimmed token via tok/len out-params.
 *       Advances *pp past the token (and its comma on the next call).  Returns 1
 *       while a token was produced, 0 at end of the header value.
 */
static int
inner_coding_next_token(const u_char **pp, const u_char *end,
    const u_char **tok, size_t *len)
{
    const u_char *p = *pp;
    const u_char *tend;

    if (p >= end) {
        return 0;
    }
    while (p < end && (*p == ' ' || *p == ',' || *p == '\t')) { p++; }
    *tok = p;
    while (p < end && *p != ',') { p++; }
    tend = p;
    while (tend > *tok && (tend[-1] == ' ' || tend[-1] == '\t')) { tend--; }
    *len = (size_t) (tend - *tok);
    *pp  = p;
    return 1;
}

/* Whether a content-coding token is one the streaming path can pass through
 * (empty, "aws-chunked", or "identity") rather than a real inner coding. */
static int
inner_coding_is_passthrough(const u_char *tok, size_t len)
{
    if (len == 0) {
        return 1;
    }
    if (len == sizeof("aws-chunked") - 1
        && ngx_strncasecmp((u_char *) tok, (u_char *) "aws-chunked", len) == 0) {
        return 1;
    }
    if (len == sizeof("identity") - 1
        && ngx_strncasecmp((u_char *) tok, (u_char *) "identity", len) == 0) {
        return 1;
    }
    return 0;
}

int
s3_aws_chunked_has_inner_coding(ngx_http_request_t *r)
{
    ngx_table_elt_t *h = brix_http_find_header(r, "Content-Encoding",
                                                 sizeof("Content-Encoding") - 1);
    const u_char    *p, *end, *tok;
    size_t           len;

    if (h == NULL || h->value.len == 0) {
        return 0;
    }
    p   = h->value.data;
    end = p + h->value.len;

    /* Walk comma-separated content-codings; any token that is neither
     * "aws-chunked" nor "identity" (nor empty) is an inner content-coding the
     * streaming path cannot decode. */
    while (inner_coding_next_token(&p, end, &tok, &len)) {
        if (!inner_coding_is_passthrough(tok, len)) {
            return 1;   /* a real inner content-coding (gzip/zstd/...) present */
        }
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
            if (brix_vfs_pread_full(b->file->fd, window, (size_t) want, off,
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

/*
 * Decode inputs, bundled so the setup/drain helpers take one struct instead of
 * the frozen extern's eight loose arguments (the public entry point keeps its
 * signature — this is the file-local shape it fans out into).
 */
typedef struct {
    ngx_http_request_t      *r;
    ngx_fd_t                 dst_fd;
    const char              *log_path;
    uint64_t                 decoded_len_expected;
    s3_chunk_trailer_t      *trailer;
    int                     *http_status_out;
    u_char                  *window;
    const s3_chunk_verify_t *verify;
} s3_chunk_dec_t;

/*
 * WHAT: initialise the decoder context and, when requested, arm verification.
 * WHY:  separates one-time setup (state seed, trailer clear, SHA handle) from the
 *       feed loop, keeping the orchestrator flat.
 * HOW:  zero-inits c, seeds the framing state, clears the trailer out-params, and
 *       — when verify is enabled — copies the seed signature and allocates the
 *       streaming SHA-256 handle.  Returns NGX_OK, or NGX_ERROR (with
 *       *http_status_out set) if the SHA handle cannot be allocated.
 */
static ngx_int_t
s3_chunk_dec_init(const s3_chunk_dec_t *d, s3_chunk_ctx_t *c)
{
    ngx_memzero(c, sizeof(*c));
    c->state    = ST_SIZE;
    c->fd       = d->dst_fd;
    c->log_path = d->log_path;
    c->log      = d->r->connection->log;
    c->expected = d->decoded_len_expected;
    c->trailer  = d->trailer;
    if (d->trailer != NULL) {
        d->trailer->algo_token[0] = '\0';
        d->trailer->value[0] = '\0';
    }

    /* W6a: arm per-chunk verification; the seed signature is the first chunk's
     * previous-signature.  The streaming SHA-256 handle hashes each chunk's
     * payload (works on the worker thread — per-ctx, no shared state). */
    if (d->verify != NULL && d->verify->enabled) {
        c->verify = 1;
        c->vctx   = d->verify;
        ngx_cpystrn((u_char *) c->prev_sig, (u_char *) d->verify->seed_signature,
                    sizeof(c->prev_sig));
        c->sha = brix_sha256_stream_new();
        if (c->sha == NULL) {
            *d->http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/*
 * WHAT: ensure a scratch read-window exists for the spooled-buffer path.
 * WHY:  the offload path pre-allocates one so the worker thread never touches
 *       r->pool; the inline path allocates lazily here.
 * HOW:  returns the caller-supplied window if non-NULL, otherwise allocates one
 *       from r->pool; on allocation failure sets *http_status_out and returns
 *       NULL.
 */
static u_char *
s3_chunk_dec_window(const s3_chunk_dec_t *d)
{
    u_char *window;

    if (d->window != NULL) {
        return d->window;
    }
    window = ngx_palloc(d->r->pool, S3_CHUNK_READ_WINDOW);
    if (window == NULL) {
        *d->http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return window;
}

/*
 * WHAT: drive every request-body buffer through the state machine.
 * WHY:  isolates the buffer-chain drain (and its per-buffer error surfacing) from
 *       setup/finalisation.
 * HOW:  feeds each chain buffer through s3_chunk_feed_buf; on the first failure
 *       publishes c->http_status and returns NGX_ERROR, else NGX_OK.
 */
static ngx_int_t
s3_chunk_dec_drain(const s3_chunk_dec_t *d, s3_chunk_ctx_t *c, u_char *window)
{
    ngx_chain_t *cl;

    for (cl = d->r->request_body->bufs; cl != NULL; cl = cl->next) {
        if (s3_chunk_feed_buf(c, cl->buf, window) != 0) {
            *d->http_status_out = c->http_status;
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/*
 * WHAT: run the decode once the context is armed (body present).
 * WHY:  the non-empty-body case — window acquisition, drain, and the
 *       terminated/length postcondition — as one linear helper.
 * HOW:  acquires the window, drains the buffer chain, then requires the stream to
 *       have reached ST_DONE with exactly the declared byte count.  Returns
 *       NGX_OK or NGX_ERROR with *http_status_out set.
 */
static ngx_int_t
s3_chunk_dec_run(const s3_chunk_dec_t *d, s3_chunk_ctx_t *c)
{
    u_char    *window = s3_chunk_dec_window(d);
    ngx_int_t  rc;

    if (window == NULL) {
        return NGX_ERROR;
    }

    rc = s3_chunk_dec_drain(d, c, window);
    if (rc != NGX_OK) {
        return rc;
    }

    /* The stream must have reached the terminating blank line and produced
     * exactly the declared number of decoded bytes. */
    if (c->state != ST_DONE || c->total_decoded != d->decoded_len_expected) {
        *d->http_status_out = NGX_HTTP_BAD_REQUEST;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
s3_aws_chunked_decode_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, uint64_t decoded_len_expected,
    s3_chunk_trailer_t *trailer, int *http_status_out, u_char *window,
    const s3_chunk_verify_t *verify)
{
    s3_chunk_dec_t d = {
        .r                    = r,
        .dst_fd               = dst_fd,
        .log_path             = log_path,
        .decoded_len_expected = decoded_len_expected,
        .trailer              = trailer,
        .http_status_out      = http_status_out,
        .window               = window,
        .verify               = verify,
    };
    s3_chunk_ctx_t c;
    ngx_int_t      rc;

    if (s3_chunk_dec_init(&d, &c) != NGX_OK) {
        return NGX_ERROR;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        /* An empty streamed body is only valid when 0 bytes were declared. */
        rc = NGX_OK;
        if (decoded_len_expected != 0) {
            *http_status_out = NGX_HTTP_BAD_REQUEST;
            rc = NGX_ERROR;
        }
    } else {
        rc = s3_chunk_dec_run(&d, &c);
    }

    brix_sha256_stream_free(c.sha);   /* NULL-safe when verify off */
    return rc;
}
