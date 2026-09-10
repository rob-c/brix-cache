/*
 * file_serve_memory.c — memory-backed body send for a backend with no single
 * sendfile fd.
 *
 * Split verbatim out of file_serve.c (which had grown past the 600-line
 * contract); the bodies are unchanged apart from the pre-header first read
 * documented on brix_serve_memory_backed.  INVARIANT 2: this path is
 * memory-backed (b->memory = 1) end to end and is never mixed with the
 * sendfile path that lives in file_serve.c.
 */

#include "file_serve.h"
#include "core/compat/error_mapping.h"    /* brix_http_map_errno */
#include "fs/backend/sd.h"                /* BRIX_SD_ADV_WILLNEED */
#include "file_serve_internal.h"

#include <errno.h>

/* brix_serve_memory_backed — stream [start, start+len) of `fh` to the client by
 * reading through the storage driver into pool buffers and pushing them through
 * nginx's output filter. Used when the backend exposes no single sendfile fd —
 * an object/block backend (e.g. pblock) whose bytes span multiple block files,
 * which brix_http_send_file_range (a single in_file buffer) cannot serve. The
 * bytes still flow proto -> VFS -> driver, just memory-backed instead of
 * zero-copy. The driver preads run on the event loop; a thread-pool/AIO streaming
 * variant for very large objects is a follow-up. Returns the output-filter rc or
 * NGX_ERROR. The caller still owns closing `fh`. */
#define BRIX_SERVE_MEM_CHUNK  (256 * 1024)

/* Read-ahead for the memory-backed loop: after each chunk, hint the next
 * WINDOW bytes off the read cursor via the driver's read_advise slot
 * (WILLNEED) — on a slice partial-cache handle that queues a background block
 * fill ahead of the foreground preads. The driver keeps a per-handle rolling
 * frontier, so the repeated per-chunk hints cost one bitmap peek and
 * speculation stays a continuous runway bounded by ITS prefetch window (and
 * the object size) — the hint is deliberately NOT clamped to the request
 * range, so a client walking a file in sequential range GETs gets successor
 * blocks warmed beyond each request. Ignored entirely unless
 * brix_cache_prefetch is on. Requests below ADV_MIN never speculate — a small
 * metadata GET must not amplify origin traffic. The first hint fires only
 * after the first chunk completes, so the block the foreground is filling
 * right now is present and gets skipped, never fetched twice. */
#define BRIX_SERVE_MEM_ADV_WINDOW     (8 * 1024 * 1024)
#define BRIX_SERVE_MEM_ADV_MIN        (1024 * 1024)

/* Close the response body with a bare last_buf (HEAD or an empty range). */
static ngx_int_t
brix_serve_send_empty_body(ngx_http_request_t *r)
{
    ngx_buf_t   *b = ngx_calloc_buf(r->pool);
    ngx_chain_t  out;

    if (b == NULL) {
        return NGX_ERROR;
    }
    b->last_buf = 1;
    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

/*
 * brix_serve_mem_prime — the first driver pread, taken before any header.
 *
 * WHAT: allocate one chunk and read it at `start`, reporting the driver's own
 *   count and errno to the caller.
 * WHY: separated so the pre-header read and the in-loop reads stay one
 *   statement each in the streaming body, and so the allocation failure is
 *   distinguishable from a backend refusal (ENOMEM vs the driver's errno).
 * HOW: pool-allocate `want`, hand the buffer back through `out`, return the
 *   pread result verbatim (-1 with errno set, 0 for an origin that delivered
 *   nothing, else the byte count).
 */
static ssize_t
brix_serve_mem_prime(ngx_http_request_t *r, brix_vfs_file_t *fh, off_t start,
    size_t want, u_char **out)
{
    u_char *buf = ngx_palloc(r->pool, want);

    if (buf == NULL) {
        errno = ENOMEM;
        return -1;
    }
    *out = buf;

    return brix_vfs_file_pread(fh, buf, want, start);
}

/* Bytes to move in the next memory-backed chunk. */
static size_t
brix_serve_mem_want(off_t len, off_t done)
{
    off_t want = len - done;

    return (want > BRIX_SERVE_MEM_CHUNK) ? (size_t) BRIX_SERVE_MEM_CHUNK
                                         : (size_t) want;
}

/*
 * brix_serve_mem_status — terminal HTTP status for a driver read that failed
 * before any byte reached the wire.
 *
 * WHAT: map the errno left by brix_vfs_file_pread to the status the client
 *   gets instead of a bare connection close.
 * WHY: the shared errno table owns the security-load-bearing classes
 *   (ENOENT 404, EACCES/EPERM/EXDEV/ELOOP 403) and must keep owning them here
 *   — a driver read must never turn a confinement rejection into a 5xx.  Its
 *   "no idea" answer is 500, but this path is reached only for a backend with
 *   no single sendfile fd, i.e. an object/remote origin reached through the
 *   driver, so an unclassified delivery failure is a gateway failure (502),
 *   matching every other origin-failure site in the tree.
 * HOW: run the shared table, promote its 500 default to 502, leave the rest.
 */
static ngx_int_t
brix_serve_mem_status(int err)
{
    ngx_int_t status = brix_http_map_errno(err);

    return (status == NGX_HTTP_INTERNAL_SERVER_ERROR) ? NGX_HTTP_BAD_GATEWAY
                                                      : status;
}

/* Push one already-read chunk through the output filter. */
static ngx_int_t
brix_serve_mem_emit(ngx_http_request_t *r, u_char *buf, ssize_t n, int last)
{
    ngx_buf_t   *b = ngx_calloc_buf(r->pool);
    ngx_chain_t  out;

    if (b == NULL) {
        return NGX_ERROR;
    }
    b->pos      = buf;
    b->last     = buf + n;
    b->memory   = 1;
    b->flush    = 1;
    b->last_buf = last;
    out.buf  = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

/* One chunk already read but not yet pushed through the output filter — how
 * the pre-header first read is handed to the streaming loop. */
typedef struct {
    u_char  *buf;   /* NULL once consumed */
    ssize_t  n;
} brix_serve_mem_chunk_t;

/*
 * brix_serve_mem_stream — push [start, start+len) through the output filter.
 *
 * WHAT: emit `first` (the chunk the caller already read), then read and emit
 *   the remainder chunk by chunk, hinting the read-ahead window after each.
 * WHY: split from brix_serve_memory_backed so the pre-header contract (which
 *   owns the only failure that still has a status line available) and the
 *   on-the-wire streaming (where NGX_ERROR is the only report left) are two
 *   readable bodies instead of one over-branched one.
 * HOW: `first->buf` is consumed on the opening iteration and nulled; every
 *   later iteration allocates and preads its own.  A failure here is always
 *   post-header: NGX_ERROR for a driver error, NGX_OK for a short EOF, the
 *   filter's own rc otherwise.
 */
static ngx_int_t
brix_serve_mem_stream(ngx_http_request_t *r, brix_vfs_file_t *fh, off_t start,
    off_t len, brix_serve_mem_chunk_t *first)
{
    off_t done = 0;

    while (done < len) {
        size_t    want = brix_serve_mem_want(len, done);
        ngx_int_t rc;

        if (first->buf == NULL) {
            first->buf = ngx_palloc(r->pool, want);
            if (first->buf == NULL) {
                return NGX_ERROR;
            }
            first->n = brix_vfs_file_pread(fh, first->buf, want, start + done);
            if (first->n <= 0) {
                /* error / short EOF — the header is already gone, so the
                 * only report available is the connection itself. */
                return first->n < 0 ? NGX_ERROR : NGX_OK;
            }
        }

        rc = brix_serve_mem_emit(r, first->buf, first->n,
                                 (done + first->n >= len) ? 1 : 0);
        if (rc == NGX_ERROR || rc > NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        done += first->n;
        first->buf = NULL;

        if (len >= BRIX_SERVE_MEM_ADV_MIN) {
            (void) brix_vfs_file_read_advise(fh, start + done,
                                             BRIX_SERVE_MEM_ADV_WINDOW,
                                             BRIX_SD_ADV_WILLNEED);
        }
    }

    return NGX_OK;
}

ngx_int_t
brix_serve_memory_backed(ngx_http_request_t *r, brix_vfs_file_t *fh,
    off_t start, off_t len)
{
    brix_serve_mem_chunk_t first = { NULL, 0 };
    ngx_int_t              hrc;

    /* The FIRST driver pread runs BEFORE the header is sent.  For every
     * backend that lands here the bytes come from an object/remote origin,
     * and that first read is the first moment the origin is asked for them —
     * so it is where an origin refusal surfaces.  Sending the header first
     * left no way to report one: nginx had a 200 buffered and unflushed, the
     * NGX_ERROR return closed the connection, and the client saw an empty
     * reply with no status code at all.  Read first and the failure still has
     * a status line to travel in.  Once a byte HAS been flushed the old
     * behaviour is the only one available and is kept in the stream helper. */
    if (!r->header_only && len > 0) {
        errno = 0;
        first.n = brix_serve_mem_prime(r, fh, start,
                                       brix_serve_mem_want(len, 0),
                                       &first.buf);
        if (first.n <= 0) {
            /* n == 0 is an origin that answered the read with no bytes at
             * all; it is a delivery failure, not an EOF (the range was
             * clamped to the statted size before we got here). */
            return brix_serve_mem_status(first.n < 0 ? errno : EIO);
        }
    }

    /* The response headers were set (set_file_headers) but not yet sent — the
     * sendfile path sends them inside send_file_range; do the same here. */
    hrc = ngx_http_send_header(r);
    if (hrc == NGX_ERROR || hrc > NGX_OK) {
        return hrc;
    }

    if (r->header_only || len <= 0) {
        return brix_serve_send_empty_body(r);
    }

    return brix_serve_mem_stream(r, fh, start, len, &first);
}
