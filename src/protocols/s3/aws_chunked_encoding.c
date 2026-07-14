/*
 * aws_chunked_encoding.c — aws-chunked request classification via request
 * headers (phase-79 file-size split of aws_chunked.c).
 *
 * WHAT: Owns the two header-inspection predicates the S3 PUT path consults
 *       before decoding: s3_body_is_aws_chunked() (does the body use the
 *       aws-chunked application-layer framing?) and s3_aws_chunked_has_inner_
 *       coding() (does Content-Encoding name a real inner coding the streaming
 *       de-chunker cannot strip, e.g. "aws-chunked,gzip"?), plus their private
 *       content-coding tokeniser/classifier helpers.
 * WHY:  This is pure header classification with no shared state with the framing
 *       state machine — splitting it out keeps both the parser (aws_chunked_
 *       parse.c) and the orchestrator (aws_chunked.c) under the 500-line cap and
 *       lets the detection logic be reviewed independently of decode.
 * HOW:  Both predicates walk request headers via brix_http_find_header and, for
 *       Content-Encoding, tokenise the comma-separated content-codings and
 *       classify each token as passthrough (empty/aws-chunked/identity) or a
 *       real inner coding.
 *
 * See aws_chunked.h for the wire format and rationale.
 */

#include "aws_chunked.h"
#include "core/http/http_headers.h"

#include <string.h>

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
