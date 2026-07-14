/*
 * aws_chunked_internal.h — declarations shared across the aws-chunked
 * request-body decoder files after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the framing-parser context (s3_chunk_ctx_t), its parser
 *       state enum (s3_chunk_state_t), the two line/extension caps, and the
 *       exactly-two functions that call across the decoder's translation units:
 *       s3_chunk_fail() (the state-machine failure primitive) and s3_chunk_feed()
 *       (feed one contiguous span through the machine). Everything else stays
 *       file-local (static).
 * WHY:  aws_chunked.c (801 lines) split into three focused files under the
 *       500-line cap: aws_chunked.c (decode orchestrator: context setup,
 *       buffer-chain drain, public entry point), aws_chunked_parse.c (the
 *       security-relevant byte-level framing state machine + per-chunk SigV4
 *       signature verification), and aws_chunked_encoding.c (Content-Encoding /
 *       x-amz-content-sha256 detection and inner-coding classification). The
 *       orchestrator and the parser share one context struct and the two
 *       cross-called entry points below; nothing else crosses a file boundary.
 * HOW:  aws_chunked.c and aws_chunked_parse.c include this header; the two
 *       declared symbols are non-static and carry no linkage beyond the decoder
 *       translation units. aws_chunked_encoding.c needs none of this and does
 *       not include it.
 *
 * Requires: aws_chunked.h (s3_chunk_trailer_t, s3_chunk_verify_t, ngx request
 *           and integer types) is included here.
 */
#ifndef NGX_HTTP_S3_AWS_CHUNKED_INTERNAL_H
#define NGX_HTTP_S3_AWS_CHUNKED_INTERNAL_H

#include "aws_chunked.h"

/* S3_CHUNK_READ_WINDOW is defined in aws_chunked.h (shared with the offload). */
#define S3_CHUNK_MAX_LINE      512          /* size line / trailer line cap */
#define S3_CHUNK_EXT_MAX       128          /* chunk-signature extension cap */

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

/*
 * s3_chunk_fail — latch the state machine into ST_ERROR with an HTTP status.
 * Defined in aws_chunked_parse.c; called from the decode orchestrator
 * (aws_chunked.c) when a spooled-buffer read fails, and throughout the parser.
 */
void s3_chunk_fail(s3_chunk_ctx_t *c, int status);

/*
 * s3_chunk_feed — feed one contiguous span [p, end) through the framing state
 * machine. Returns 0 when the span is consumed without error (stream may still
 * be mid-chunk), -1 once the machine has entered ST_ERROR. Defined in
 * aws_chunked_parse.c; called from the orchestrator's per-buffer drain.
 */
int s3_chunk_feed(s3_chunk_ctx_t *c, const u_char *p, const u_char *end);

#endif /* NGX_HTTP_S3_AWS_CHUNKED_INTERNAL_H */
