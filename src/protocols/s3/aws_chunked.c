/*
 * aws_chunked.c — AWS streaming (aws-chunked) request-body decode orchestrator
 * (phase-43 W0; phase-79 file-size split).
 *
 * See aws_chunked.h for the wire format and rationale.  This file owns the
 * decode orchestration: it sets up the framing context, drives the nginx
 * request-body chain buffer-by-buffer (spooled buffers are read in 64 KiB
 * windows) so a large upload never lands fully in RAM, and enforces the
 * declared decoded length and terminated-stream postcondition.  The byte-level
 * framing state machine and per-chunk signature verification live in the
 * sibling aws_chunked_parse.c (via s3_chunk_feed / s3_chunk_fail); the
 * header-classification predicates live in aws_chunked_encoding.c.
 */

#include "aws_chunked.h"
#include "aws_chunked_internal.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_pread_full (storage seam) */
#include "s3.h"
#include "core/http/http_headers.h"
#include "core/compat/crypto.h"
#include "core/compat/hex.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

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
