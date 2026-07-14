/*
 * aws_chunked_parse.c — AWS streaming (aws-chunked) framing state machine and
 * per-chunk SigV4 signature verification (phase-79 file-size split of
 * aws_chunked.c).
 *
 * WHAT: Owns the byte-level chunk framing parser — the per-state scanners
 *       (size line, extension, CRLF terminators, payload, trailer), the
 *       decoded-payload writer, the trailer-line capture, and the security-
 *       relevant per-chunk signature check (constant-time compare of each
 *       chunk-signature against the rolling AWS4-HMAC-SHA256-PAYLOAD chain).
 *       s3_chunk_feed() drives one contiguous span; s3_chunk_fail() latches the
 *       error state. Both are the only symbols exported to the orchestrator.
 * WHY:  This is the correctness- and security-critical half of the decoder;
 *       keeping the whole framing/verification chain in one focused file (under
 *       the 500-line cap) makes the per-chunk signature chain, chunk parsing,
 *       and trailer handling reviewable in isolation from the buffer-chain
 *       orchestration in aws_chunked.c.
 * HOW:  The feed loop (s3_chunk_feed) dispatches one byte at a time to the
 *       per-state scanner via chunk_feed_step; each scanner advances the cursor
 *       and reports STEP_CONT/STEP_ERROR. Payload bytes stream through the
 *       streaming SHA-256 (when verifying) and the storage seam; on each chunk
 *       boundary s3_chunk_verify() finalises the hash, rebuilds the string-to-
 *       sign with the previous signature, and constant-time-compares the HMAC.
 *
 * See aws_chunked.h for the wire format and rationale.
 */

#include "aws_chunked.h"
#include "aws_chunked_internal.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_pwrite_full (storage seam) */
#include "s3.h"
#include "core/http/http_headers.h"
#include "core/compat/crypto.h"
#include "core/compat/hex.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* SHA-256 of the empty string — the constant payload-hash slot in the
 * AWS4-HMAC-SHA256-PAYLOAD string-to-sign. */
static const char S3_EMPTY_SHA256_HEX[] =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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

void
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
int
s3_chunk_feed(s3_chunk_ctx_t *c, const u_char *p, const u_char *end)
{
    while (p < end && c->state != ST_DONE && c->state != ST_ERROR) {
        if (chunk_feed_step(c, &p, end) == STEP_ERROR) {
            return -1;
        }
    }
    return (c->state == ST_ERROR) ? -1 : 0;
}
