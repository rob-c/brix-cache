/*
 * aws_chunked.h — AWS streaming (aws-chunked) request-body decoder (phase-43 W0).
 *
 * AWS SDKs upload with an application-layer chunk framing carried INSIDE the HTTP
 * body (signalled by x-amz-content-sha256: STREAMING-*), distinct from HTTP
 * Transfer-Encoding: chunked (which nginx strips).  Each chunk is:
 *
 *   <hex-size>[;chunk-signature=<64hex>]\r\n  <size bytes payload>  \r\n
 *
 * terminated by a 0-size chunk optionally followed by trailer headers (e.g.
 * x-amz-checksum-crc32:<base64>) and a blank line.  Without decoding, this
 * framing would be stored verbatim — corrupting every object from a default
 * modern aws-cli/boto3 client.  This module decodes the payload to a file
 * descriptor, enforces x-amz-decoded-content-length, and captures a trailer
 * checksum for verification.
 */

#ifndef NGX_HTTP_S3_AWS_CHUNKED_H
#define NGX_HTTP_S3_AWS_CHUNKED_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* A trailer checksum captured during decode (empty algo_token ⇒ none seen). */
typedef struct {
    char algo_token[16];   /* "crc32" / "crc32c" / "sha1" / "sha256" / "crc64nvme" */
    char value[64];        /* base64 wire value from the trailer line             */
} s3_chunk_trailer_t;

/*
 * W6a: per-chunk SigV4 signature-verification context.  When `enabled`, the
 * decoder verifies each chunk's `chunk-signature=` against
 *   HMAC(signing_key, "AWS4-HMAC-SHA256-PAYLOAD\n<amz_date>\n<scope>\n
 *                      <prev-sig>\n<sha256("")>\n<sha256(chunk-data)>")
 * rolling prev-sig from the seed (request Authorization) signature, and rejects
 * a mismatch with 403.  All fields come from the SigV4 auth already performed.
 */
typedef struct {
    int    enabled;
    u_char signing_key[32];
    char   seed_signature[65];   /* hex, the request's Authorization signature */
    char   amz_date[32];         /* YYYYMMDDTHHMMSSZ                           */
    char   scope[96];            /* YYYYMMDD/region/s3/aws4_request            */
} s3_chunk_verify_t;

/*
 * s3_body_is_aws_chunked — 1 if the request body uses aws-chunked framing.
 * Detected via x-amz-content-sha256: STREAMING-* (authoritative) or a
 * Content-Encoding that includes the aws-chunked token.
 */
int s3_body_is_aws_chunked(ngx_http_request_t *r);

/*
 * s3_aws_chunked_has_inner_coding — 1 if the request's Content-Encoding names a
 * content-coding OTHER than aws-chunked/identity (e.g. "aws-chunked,gzip").
 *
 * The streaming de-chunker strips only the chunk framing, so an inner-compressed
 * payload would be committed still compressed.  Callers reject such uploads (400)
 * rather than store undecoded bytes — the same invariant the non-chunked PUT path
 * enforces.  Returns 0 for plain aws-chunked (no inner coding).
 */
int s3_aws_chunked_has_inner_coding(ngx_http_request_t *r);

/* Scratch window the decoder reads spooled buffers through (phase-46 W1b: the
 * offload path pre-allocates one so the worker thread never touches r->pool). */
#define S3_CHUNK_READ_WINDOW   (64 * 1024)

/*
 * s3_aws_chunked_decode_to_fd — decode the framed request body to dst_fd.
 *
 * Iterates the nginx request-body chain (memory + spooled buffers), runs the
 * chunk state machine, and pwrites only payload bytes to dst_fd.  Enforces that
 * the total decoded length equals decoded_len_expected.  Any trailer checksum
 * (x-amz-checksum-*) is recorded in *trailer.
 *
 * `window` is a caller-provided S3_CHUNK_READ_WINDOW-byte scratch buffer; pass
 * NULL to have it allocated from r->pool (only safe on the event-loop thread).
 *
 * `verify` (may be NULL or .enabled=0) requests per-chunk SigV4 verification; a
 * signature mismatch fails the decode with *http_status_out = 403.
 *
 * Returns NGX_OK on success; on failure returns NGX_ERROR and sets
 * *http_status_out to the HTTP status to surface (400 malformed/short, 403
 * signature mismatch, 500 I/O).
 */
ngx_int_t s3_aws_chunked_decode_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, uint64_t decoded_len_expected,
    s3_chunk_trailer_t *trailer, int *http_status_out, u_char *window,
    const s3_chunk_verify_t *verify);

#endif /* NGX_HTTP_S3_AWS_CHUNKED_H */
